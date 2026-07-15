import re
from typing import Any, Dict, List

from core.apr.common import (
    clip_text,
    constructor_initializer_names,
    dedup_keep_order,
    extract_symbols_from_code,
    node_text,
    parse_tree,
    split_top_level_commas,
    walk_nodes,
)

from .support import MAX_PROJECT_HEADERS, _matching_brace_end, _strip_comments

def _available_symbol_inventory(
    *,
    target_symbols: dict,
    same_file_helpers: List[dict],
    same_file_declarations: List[dict],
    header_context: List[dict],
    usage_examples: List[dict],
) -> Dict[str, List[str]]:
    aggregate = {
        "calls": list(target_symbols.get("calls") or []),
        "types": list(target_symbols.get("types") or []),
        "fields": list(target_symbols.get("fields") or []),
        "macro_like": list(target_symbols.get("macro_like") or []),
        "identifiers": list(target_symbols.get("identifiers") or []),
    }
    snippets = []
    for item in same_file_helpers[:12] + same_file_declarations[:20] + usage_examples[:8]:
        for key in ("text", "snippet", "declaration"):
            if item.get(key):
                snippets.append(str(item.get(key)))
    for header in header_context[:6]:
        for item in header.get("api_surface") or []:
            if item.get("text"):
                snippets.append(str(item.get("text")))
    for snippet in snippets:
        symbols = extract_symbols_from_code(snippet[:2500], "cpp")
        for key in aggregate:
            aggregate[key].extend(symbols.get(key) or [])
    return {
        key: dedup_keep_order([str(item) for item in values if item])[:80]
        for key, values in aggregate.items()
    }

def _visible_api_inventory(
    *,
    target_symbols: dict,
    symbol_inventory: dict,
    same_file_helpers: List[dict],
    same_file_declarations: List[dict],
    header_context: List[dict],
    usage_examples: List[dict],
    member_field_inventory: List[dict],
    constructor_initializer_whitelist: dict,
) -> Dict[str, List[str]]:
    functions = list(symbol_inventory.get("calls") or [])
    macros = list(symbol_inventory.get("macro_like") or [])
    types = list(symbol_inventory.get("types") or [])
    member_fields = list(symbol_inventory.get("fields") or [])
    identifiers = list(symbol_inventory.get("identifiers") or [])

    snippets = []
    for item in same_file_helpers[:16] + same_file_declarations[:24] + usage_examples[:10]:
        snippets.append(str(item.get("text") or item.get("snippet") or ""))
        kind = str(item.get("kind") or "")
        if kind.startswith("function_definition:"):
            functions.append(kind.split(":", 1)[1])
    for header in header_context[:10]:
        for item in header.get("api_surface") or []:
            snippets.append(str(item.get("text") or ""))
            kind = str(item.get("kind") or "")
            if kind.startswith("function_definition:"):
                functions.append(kind.split(":", 1)[1])

    for snippet in snippets:
        api = _api_names_from_snippet(snippet)
        functions.extend(api["functions"])
        macros.extend(api["macros"])
        types.extend(api["types"])
        extracted = extract_symbols_from_code(snippet[:2500], "cpp")
        functions.extend(extracted.get("calls") or [])
        macros.extend(extracted.get("macro_like") or [])
        types.extend(extracted.get("types") or [])
        member_fields.extend(extracted.get("fields") or [])
        identifiers.extend(extracted.get("identifiers") or [])

    for entry in member_field_inventory:
        member_fields.extend(entry.get("fields") or [])
        functions.extend(entry.get("methods") or [])
        types.append(entry.get("class") or "")
    member_fields.extend(constructor_initializer_whitelist.get("allowed_initializers") or [])

    return {
        "functions": dedup_keep_order(functions)[:120],
        "macros": dedup_keep_order(macros)[:120],
        "types": dedup_keep_order(types)[:100],
        "member_fields": dedup_keep_order(member_fields)[:120],
        "identifiers": dedup_keep_order(list(target_symbols.get("identifiers") or []) + identifiers)[:120],
        "source_policy": [
            "Names here are visible in the target, same-file declarations/helpers, resolved headers, usage examples, or enclosing class inventory.",
            "FixAgent should not introduce calls/macros/types/member fields outside this inventory unless they are standard C/C++ language/library surface.",
        ],
    }

def _augment_visible_api_inventory(
    inventory: Dict[str, Any],
    contract_engine: Dict[str, Any],
) -> Dict[str, Any]:
    out = dict(inventory or {})
    api_inventory = contract_engine.get("api_contract_inventory") or {}
    macro_inventory = contract_engine.get("macro_contract_inventory") or {}
    type_inventory = contract_engine.get("type_contract_inventory") or {}
    functions = list(out.get("functions") or [])
    macros = list(out.get("macros") or [])
    types = list(out.get("types") or [])
    for sig in api_inventory.get("function_signatures") or []:
        functions.append(sig.get("name") or "")
    for macro in macro_inventory.get("macro_definitions") or []:
        macros.append(macro.get("name") or "")
    for group in macro_inventory.get("enum_constant_groups") or []:
        macros.extend(group.get("constants") or [])
    for group in macro_inventory.get("bitmask_flag_groups") or []:
        macros.extend(group.get("allowed_constants") or [])
    for typ in type_inventory.get("type_definitions") or []:
        types.append(typ.get("name") or "")
        types.append(typ.get("alias") or "")
    out["functions"] = dedup_keep_order([item for item in functions if item])[:140]
    out["macros"] = dedup_keep_order([item for item in macros if item])[:160]
    out["types"] = dedup_keep_order([item for item in types if item])[:120]
    policy = list(out.get("source_policy") or [])
    policy.append(
        "Contract engine augments visible symbols with sibling macro/enum constants and signatures found in resolved source/header evidence."
    )
    out["source_policy"] = dedup_keep_order(policy)[:4]
    return out


def _scope_aware_symbol_contract(
    *,
    target_unit: str,
    target_symbols: dict,
    visible_api_inventory: Dict[str, Any],
    contract_engine: Dict[str, Any],
    member_field_inventory: List[dict],
) -> Dict[str, Any]:
    existing_calls = dedup_keep_order([str(item) for item in (target_symbols.get("calls") or []) if item])
    existing_macros = dedup_keep_order([str(item) for item in (target_symbols.get("macro_like") or []) if item])
    existing_types = dedup_keep_order([str(item) for item in (target_symbols.get("types") or []) if item])
    existing_fields = dedup_keep_order([str(item) for item in (target_symbols.get("fields") or []) if item])
    visible_functions = dedup_keep_order([str(item) for item in (visible_api_inventory.get("functions") or []) if item])
    visible_macros = dedup_keep_order(
        [str(item) for item in (visible_api_inventory.get("macros") or visible_api_inventory.get("macros_or_enum_constants") or []) if item]
    )
    visible_types = dedup_keep_order([str(item) for item in (visible_api_inventory.get("types") or []) if item])
    visible_fields = dedup_keep_order([str(item) for item in (visible_api_inventory.get("member_fields") or []) if item])

    local_methods = []
    class_fields = {}
    class_methods = {}
    for entry in member_field_inventory or []:
        cls = entry.get("class") or "<unknown>"
        class_fields[cls] = dedup_keep_order(entry.get("fields") or [])
        class_methods[cls] = dedup_keep_order(entry.get("methods") or [])
        local_methods.extend(entry.get("methods") or [])

    signatures = (contract_engine.get("api_contract_inventory") or {}).get("function_signatures") or []
    signature_names = dedup_keep_order([item.get("name") for item in signatures if item.get("name")])
    # "Visible" can be broad; "introducible" is intentionally stricter.
    introducible_functions = dedup_keep_order(
        existing_calls
        + [name for name in visible_functions if name in existing_calls]
        + [name for name in local_methods if name in existing_calls]
    )
    introducible_macros = dedup_keep_order(existing_macros + [name for name in visible_macros if name in existing_macros])
    introducible_types = dedup_keep_order(existing_types + [name for name in visible_types if name in existing_types])

    target_text = target_unit or ""
    member_call_receivers = _member_call_receivers(target_text)
    risky_unqualified = [
        name for name in signature_names
        if name not in existing_calls and name not in local_methods and name not in {"static_cast", "sizeof"}
    ][:40]
    return {
        "existing_calls": existing_calls[:80],
        "existing_macros_or_enum_constants": existing_macros[:80],
        "existing_types": existing_types[:80],
        "existing_member_fields": existing_fields[:80],
        "visible_functions": visible_functions[:120],
        "visible_macros_or_enum_constants": visible_macros[:120],
        "visible_types": visible_types[:100],
        "visible_member_fields": visible_fields[:120],
        "introducible_functions": introducible_functions[:80],
        "introducible_macros_or_enum_constants": introducible_macros[:80],
        "introducible_types": introducible_types[:80],
        "class_member_contracts": [
            {
                "class": cls,
                "fields": fields[:80],
                "methods": (class_methods.get(cls) or [])[:80],
            }
            for cls, fields in list(class_fields.items())[:12]
        ],
        "member_call_receivers": member_call_receivers[:80],
        "risky_unqualified_helpers": risky_unqualified,
        "symbol_introduction_policy": [
            "Existing target calls/macros/types are safe to preserve or adjust locally.",
            "Introducing a new unqualified helper is unsafe unless it appears in introducible_functions or required_related_evidence with an exact callable form.",
            "Introducing a new member call requires the method to appear under the receiver/type member contract.",
            "A name that appears only in visible_functions is evidence, not permission to call it.",
        ],
    }


def _member_call_receivers(text: str) -> List[dict]:
    out = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*(\.|->)\s*([A-Za-z_]\w*)\s*\(", text or ""):
        out.append({"receiver": match.group(1), "operator": match.group(2), "method": match.group(3)})
    return out

def _api_names_from_snippet(text: str) -> Dict[str, List[str]]:
    text = str(text or "")
    functions = []
    macros = []
    types = []
    for match in re.finditer(r"^\s*#\s*define\s+([A-Z_][A-Z0-9_]*)\b", text, re.MULTILINE):
        macros.append(match.group(1))
    for match in re.finditer(
        r"\b(?:class|struct|enum)\s+([A-Za-z_]\w*)|\btypedef\b[^;{]*\b([A-Za-z_]\w*)\s*;",
        text,
    ):
        types.extend([item for item in match.groups() if item])
    function_re = re.compile(
        r"(?:^|[;\n}])\s*(?:template\s*<[^;{}]+>\s*)?"
        r"(?:[A-Za-z_][\w:<>,~*&\s]+\s+)?([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:;|\{)",
        re.MULTILINE,
    )
    for match in function_re.finditer(text):
        name = match.group(1)
        if name not in {"if", "for", "while", "switch", "return"}:
            functions.append(name)
    return {
        "functions": dedup_keep_order(functions),
        "macros": dedup_keep_order(macros),
        "types": dedup_keep_order(types),
    }

def _member_field_inventory(
    *,
    source_code: str,
    source_label: str,
    language: str,
    target_start: int,
    target_func_name: str,
    headers: List[dict],
) -> List[dict]:
    entries = _class_inventory_from_source(
        source_code,
        language=language,
        source_label=source_label,
        target_start=target_start,
    )
    for header in headers[:MAX_PROJECT_HEADERS]:
        entries.extend(
            _class_inventory_from_source(
                header.get("text") or "",
                language=header.get("language") or language,
                source_label=header.get("relpath") or header.get("include") or "<header>",
                target_start=-1,
            )
        )
    target_class = _target_class_hint(target_func_name)
    ranked = []
    for entry in entries:
        relation = entry.get("relation") or ""
        score = 0
        if relation == "enclosing_target":
            score += 100
        if target_class and entry.get("class") == target_class:
            score += 50
        if entry.get("fields"):
            score += 5
        ranked.append((score, entry))
    ranked.sort(key=lambda item: (-item[0], item[1].get("source", ""), item[1].get("class", "")))
    out = []
    seen = set()
    for _, entry in ranked:
        key = (entry.get("source"), entry.get("class"), tuple(entry.get("fields") or []))
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
        if len(out) >= 16:
            break
    return out

def _class_inventory_from_source(
    source: str,
    *,
    language: str,
    source_label: str,
    target_start: int = -1,
) -> List[dict]:
    entries = _class_inventory_ast(
        source,
        language=language,
        source_label=source_label,
        target_start=target_start,
    )
    if entries:
        return entries
    return _class_inventory_regex(
        source,
        source_label=source_label,
        target_start=target_start,
    )

def _class_inventory_ast(
    source: str,
    *,
    language: str,
    source_label: str,
    target_start: int,
) -> List[dict]:
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return []
    entries = []
    for node in walk_nodes(tree.root_node):
        if node.type not in {"class_specifier", "struct_specifier"}:
            continue
        name_node = node.child_by_field_name("name")
        class_name = node_text(name_node, source_bytes).strip() if name_node else ""
        body = node.child_by_field_name("body")
        body_text = node_text(body, source_bytes) if body else node_text(node, source_bytes)
        fields = _field_names_from_class_body(body_text)
        methods = _method_names_from_class_body(body_text)
        relation = "enclosing_target" if target_start >= 0 and node.start_byte <= target_start <= node.end_byte else "visible_class_or_struct"
        if class_name or fields or methods:
            entries.append(
                {
                    "class": class_name,
                    "kind": "class_or_struct",
                    "source": source_label,
                    "relation": relation,
                    "fields": fields[:80],
                    "methods": methods[:80],
                    "evidence": clip_text(body_text, 1200),
                }
            )
    return entries

def _class_inventory_regex(
    source: str,
    *,
    source_label: str,
    target_start: int,
) -> List[dict]:
    entries = []
    pattern = re.compile(r"\b(class|struct)\s+([A-Za-z_]\w*)[^{;]*\{", re.S)
    for match in pattern.finditer(source or ""):
        body_start = match.end()
        body_end = _matching_brace_end(source, body_start - 1)
        if body_end <= body_start:
            continue
        body = source[body_start:body_end]
        fields = _field_names_from_class_body(body)
        methods = _method_names_from_class_body(body)
        if not fields and not methods:
            continue
        relation = "enclosing_target" if target_start >= 0 and match.start() <= target_start <= body_end else "visible_class_or_struct"
        entries.append(
            {
                "class": match.group(2),
                "kind": match.group(1),
                "source": source_label,
                "relation": relation,
                "fields": fields[:80],
                "methods": methods[:80],
                "evidence": clip_text(body, 1200),
            }
        )
        if len(entries) >= 40:
            break
    return entries

def _field_names_from_class_body(body: str) -> List[str]:
    fields = []
    cleaned = _strip_comments(body)
    for raw in cleaned.split(";"):
        line = " ".join(part.strip() for part in raw.splitlines() if part.strip())
        if not line:
            continue
        if re.search(r"\b(public|private|protected)\s*:\s*$", line):
            continue
        if re.search(r"\b(using|typedef|friend|static_assert|return|if|for|while|switch)\b", line):
            continue
        if "(" in line and not re.search(r"\bstd::function\s*<", line):
            continue
        line = re.sub(r"=.*$", "", line).strip()
        for part in split_top_level_commas(line):
            part = part.strip()
            match = re.search(r"(?:^|[\s*&:,])([A-Za-z_]\w*)\s*(?:\[[^\]]*\])?$", part)
            if match:
                fields.append(match.group(1))
    return dedup_keep_order(fields)

def _method_names_from_class_body(body: str) -> List[str]:
    methods = []
    for match in re.finditer(r"\b([A-Za-z_]\w*)\s*\([^;{}]*\)\s*(?:const\s*)?(?:;|\{)", body or ""):
        name = match.group(1)
        if name not in {"if", "for", "while", "switch"}:
            methods.append(name)
    return dedup_keep_order(methods)

def _constructor_initializer_whitelist(
    *,
    target_unit: str,
    target_func_name: str,
    member_field_inventory: List[dict],
) -> dict:
    existing = constructor_initializer_names(target_unit)
    class_hint = _target_class_hint(target_func_name)
    fields = []
    evidence = []
    for entry in member_field_inventory:
        if entry.get("relation") == "enclosing_target" or (
            class_hint and entry.get("class") == class_hint
        ):
            fields.extend(entry.get("fields") or [])
            evidence.append(
                {
                    "class": entry.get("class"),
                    "source": entry.get("source"),
                    "fields": (entry.get("fields") or [])[:30],
                    "relation": entry.get("relation"),
                }
            )
    if not fields:
        for entry in member_field_inventory[:4]:
            fields.extend(entry.get("fields") or [])
    return {
        "target_is_constructor_like": bool(existing),
        "target_class_hint": class_hint,
        "existing_initializers": existing,
        "allowed_initializers": dedup_keep_order(existing + fields)[:120],
        "policy": "Constructor initializer entries may only use existing class fields visible in member_field_inventory.",
        "evidence": evidence[:6],
    }

def _target_class_hint(target_func_name: str) -> str:
    parts = [part for part in str(target_func_name or "").split("::") if part]
    if len(parts) >= 2:
        return parts[-2]
    return ""
