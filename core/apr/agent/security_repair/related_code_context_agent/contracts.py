import re
from typing import Any, Dict, List, Set

from core.apr.common import clip_text, dedup_keep_order, split_top_level_commas

from .support import (
    MAX_API_CONTRACTS,
    MAX_CONTRACT_GROUPS,
    MAX_MACRO_CONTRACTS,
    MAX_PROJECT_HEADERS,
    MAX_TYPE_CONTRACTS,
    _constant_family_key,
    _strip_comments,
    _symbol_relevance,
)

def _api_macro_type_contract_engine(
    *,
    source_code: str,
    source_label: str,
    language: str,
    headers: List[dict],
    target_unit: str,
    target_symbols: dict,
    usage_examples: List[dict],
    target_references: List[dict],
    member_field_inventory: List[dict],
    constructor_initializer_whitelist: dict,
) -> Dict[str, Any]:
    sources = [
        {
            "source": source_label,
            "kind": "target_source_file",
            "language": language,
            "text": source_code or "",
        }
    ]
    for header in headers[:MAX_PROJECT_HEADERS]:
        sources.append(
            {
                "source": header.get("relpath") or header.get("include") or "<header>",
                "kind": "resolved_project_header",
                "language": header.get("language") or language,
                "text": header.get("text") or "",
            }
        )

    target_calls = set(str(item) for item in (target_symbols.get("calls") or []) if item)
    target_macros = set(str(item) for item in (target_symbols.get("macro_like") or []) if item)
    target_types = set(str(item) for item in (target_symbols.get("types") or []) if item)
    target_fields = set(str(item) for item in (target_symbols.get("fields") or []) if item)
    bitmask_expressions = _target_bitmask_expressions(target_unit)
    for expr in bitmask_expressions:
        target_macros.update(expr.get("constants") or [])

    function_contracts: List[dict] = []
    macro_definitions: List[dict] = []
    enum_groups: List[dict] = []
    type_definitions: List[dict] = []
    for source in sources:
        text = source.get("text") or ""
        label = source.get("source") or ""
        function_contracts.extend(
            _extract_function_contracts(
                text,
                source_label=label,
                target_calls=target_calls,
            )
        )
        macro_definitions.extend(
            _extract_macro_definitions(
                text,
                source_label=label,
            )
        )
        enum_groups.extend(
            _extract_enum_constant_groups(
                text,
                source_label=label,
            )
        )
        type_definitions.extend(
            _extract_type_contracts(
                text,
                source_label=label,
                target_types=target_types,
            )
        )

    function_contracts = _rank_function_contracts(
        function_contracts,
        target_calls=target_calls,
        usage_examples=usage_examples,
        target_references=target_references,
    )
    macro_inventory = _build_macro_contract_inventory(
        macro_definitions=macro_definitions,
        enum_groups=enum_groups,
        target_macros=target_macros,
        bitmask_expressions=bitmask_expressions,
    )
    type_inventory = _build_type_contract_inventory(
        type_definitions=type_definitions,
        enum_groups=enum_groups,
        target_types=target_types,
        target_fields=target_fields,
        member_field_inventory=member_field_inventory,
        constructor_initializer_whitelist=constructor_initializer_whitelist,
    )
    api_inventory = {
        "function_signatures": function_contracts[:MAX_API_CONTRACTS],
        "function_like_macros": [
            item
            for item in macro_inventory.get("macro_definitions", [])
            if item.get("function_like")
        ][:20],
        "api_use_policy": [
            "Only introduce or change calls whose signature appears in function_signatures or as an existing target call.",
            "Preserve argument count/type shape unless the signature inventory proves the replacement API.",
            "When a call is already present in the target, prefer changing arguments or nearby predicates before switching callees.",
        ],
    }
    return {
        "api_contract_inventory": api_inventory,
        "macro_contract_inventory": macro_inventory,
        "type_contract_inventory": type_inventory,
        "contract_brief": _contract_brief(
            api_inventory=api_inventory,
            macro_inventory=macro_inventory,
            type_inventory=type_inventory,
        ),
    }

def _extract_function_contracts(
    source: str,
    *,
    source_label: str,
    target_calls: Set[str],
) -> List[dict]:
    contracts = []
    seen = set()
    cleaned = _strip_comments(source or "")
    signature_re = re.compile(
        r"(?m)^\s*(?P<prefix>(?:(?:static|extern|inline|constexpr|virtual|friend|explicit)\s+)*)"
        r"(?P<ret>[A-Za-z_~][\w:<>,\s\*&~]*?)\s+"
        r"(?P<name>[A-Za-z_]\w*)\s*"
        r"\((?P<params>[^;{}]{0,900})\)\s*(?P<const>const\s*)?(?P<term>;|\{)"
    )
    for match in signature_re.finditer(cleaned):
        name = match.group("name")
        if name in {"if", "for", "while", "switch", "return", "sizeof"}:
            continue
        relevance = _symbol_relevance(name, target_calls)
        if relevance <= 0 and len(contracts) >= MAX_API_CONTRACTS:
            continue
        params = split_top_level_commas(match.group("params") or "")
        signature = " ".join(match.group(0).split())
        key = (source_label, name, signature)
        if key in seen:
            continue
        seen.add(key)
        contracts.append(
            {
                "name": name,
                "source": source_label,
                "kind": "definition" if match.group("term") == "{" else "declaration",
                "signature": clip_text(signature.rstrip("{").rstrip(";"), 420),
                "return_type": " ".join((match.group("ret") or "").split()),
                "parameters": [clip_text(param.strip(), 160) for param in params if param.strip()][:12],
                "parameter_count": len([param for param in params if param.strip() and param.strip() != "void"]),
                "relevance": relevance,
            }
        )
        if len(contracts) >= MAX_API_CONTRACTS * 2:
            break
    return contracts

def _rank_function_contracts(
    contracts: List[dict],
    *,
    target_calls: Set[str],
    usage_examples: List[dict],
    target_references: List[dict],
) -> List[dict]:
    usage_text = "\n".join(
        str(item.get("snippet") or "")
        for item in (usage_examples or []) + (target_references or [])
    )
    ranked = []
    for contract in contracts:
        score = int(contract.get("relevance") or 0)
        name = str(contract.get("name") or "")
        if name in target_calls:
            score += 30
        if name and re.search(r"\b" + re.escape(name) + r"\s*\(", usage_text):
            score += 10
        if contract.get("kind") == "declaration":
            score += 2
        ranked.append((score, contract))
    ranked.sort(key=lambda item: (-item[0], item[1].get("source", ""), item[1].get("name", "")))
    out = []
    seen = set()
    for score, contract in ranked:
        key = (contract.get("name"), contract.get("signature"))
        if key in seen:
            continue
        seen.add(key)
        contract = dict(contract)
        contract["score"] = score
        out.append(contract)
        if len(out) >= MAX_API_CONTRACTS:
            break
    return out

def _extract_macro_definitions(source: str, *, source_label: str) -> List[dict]:
    macros = []
    macro_re = re.compile(
        r"(?m)^\s*#\s*define\s+(?P<name>[A-Za-z_]\w*)(?P<params>\s*\([^)]*\))?\s*(?P<value>.*)$"
    )
    for match in macro_re.finditer(source or ""):
        name = match.group("name")
        params_raw = (match.group("params") or "").strip()
        params = []
        if params_raw.startswith("("):
            params = [item.strip() for item in split_top_level_commas(params_raw[1:-1]) if item.strip()]
        macros.append(
            {
                "name": name,
                "source": source_label,
                "kind": "function_like_macro" if params_raw else "object_like_macro",
                "function_like": bool(params_raw),
                "parameters": params[:12],
                "value": clip_text((match.group("value") or "").strip(), 260),
                "family": _constant_family_key(name),
            }
        )
        if len(macros) >= MAX_MACRO_CONTRACTS * 3:
            break
    return macros

def _extract_enum_constant_groups(source: str, *, source_label: str) -> List[dict]:
    groups = []
    cleaned = _strip_comments(source or "")
    enum_re = re.compile(
        r"\b(?:typedef\s+)?enum(?:\s+(?P<tag>[A-Za-z_]\w*))?\s*\{(?P<body>.*?)\}\s*(?P<alias>[A-Za-z_]\w*)?\s*;",
        re.S,
    )
    for match in enum_re.finditer(cleaned):
        body = match.group("body") or ""
        constants = []
        values = {}
        for part in split_top_level_commas(body):
            part = part.strip()
            if not part:
                continue
            const_match = re.match(r"([A-Za-z_]\w*)\s*(?:=\s*(.*))?$", part, re.S)
            if not const_match:
                continue
            name = const_match.group(1)
            constants.append(name)
            if const_match.group(2):
                values[name] = clip_text(" ".join(const_match.group(2).split()), 160)
        if not constants:
            continue
        group_name = match.group("tag") or match.group("alias") or _constant_family_key(constants[0])
        groups.append(
            {
                "name": group_name,
                "source": source_label,
                "constants": dedup_keep_order(constants)[:120],
                "values": values,
                "family_keys": dedup_keep_order([_constant_family_key(name) for name in constants if name])[:12],
                "evidence": clip_text(match.group(0), 1200),
            }
        )
        if len(groups) >= MAX_CONTRACT_GROUPS * 3:
            break
    return groups

def _extract_type_contracts(
    source: str,
    *,
    source_label: str,
    target_types: Set[str],
) -> List[dict]:
    contracts = []
    cleaned = _strip_comments(source or "")
    typedef_re = re.compile(
        r"(?ms)\btypedef\s+(?P<body>[^;{}]*(?:\{.*?\}\s*)?)(?P<alias>[A-Za-z_]\w*)\s*;"
    )
    for match in typedef_re.finditer(cleaned):
        alias = match.group("alias")
        body = " ".join((match.group("body") or "").split())
        contracts.append(
            {
                "name": alias,
                "alias": alias,
                "source": source_label,
                "kind": "typedef",
                "definition": clip_text(f"typedef {body} {alias};", 600),
                "relevance": _symbol_relevance(alias, target_types),
            }
        )
        if len(contracts) >= MAX_TYPE_CONTRACTS * 2:
            break
    spec_re = re.compile(r"\b(?P<kind>struct|enum|class)\s+(?P<name>[A-Za-z_]\w*)")
    for match in spec_re.finditer(cleaned):
        name = match.group("name")
        contracts.append(
            {
                "name": name,
                "alias": "",
                "source": source_label,
                "kind": match.group("kind"),
                "definition": clip_text(match.group(0), 220),
                "relevance": _symbol_relevance(name, target_types),
            }
        )
        if len(contracts) >= MAX_TYPE_CONTRACTS * 3:
            break
    out = []
    seen = set()
    for item in sorted(contracts, key=lambda entry: (-int(entry.get("relevance") or 0), entry.get("source", ""), entry.get("name", ""))):
        key = (item.get("source"), item.get("kind"), item.get("name"), item.get("definition"))
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= MAX_TYPE_CONTRACTS:
            break
    return out

def _build_macro_contract_inventory(
    *,
    macro_definitions: List[dict],
    enum_groups: List[dict],
    target_macros: Set[str],
    bitmask_expressions: List[dict],
) -> Dict[str, Any]:
    constant_entries = []
    for macro in macro_definitions:
        if macro.get("function_like"):
            continue
        constant_entries.append(
            {
                "name": macro.get("name"),
                "source": macro.get("source"),
                "kind": "macro",
                "value": macro.get("value"),
                "family": macro.get("family") or _constant_family_key(macro.get("name") or ""),
            }
        )
    for group in enum_groups:
        for constant in group.get("constants") or []:
            constant_entries.append(
                {
                    "name": constant,
                    "source": group.get("source"),
                    "kind": "enum_constant",
                    "enum": group.get("name"),
                    "value": (group.get("values") or {}).get(constant, ""),
                    "family": _constant_family_key(constant),
                }
            )
    relevant_constants = _relevant_constant_entries(
        constant_entries,
        target_macros=target_macros,
    )
    enum_constant_groups = _relevant_enum_groups(
        enum_groups,
        target_macros=target_macros,
    )
    bitmask_groups = _bitmask_flag_groups(
        bitmask_expressions=bitmask_expressions,
        constant_entries=constant_entries,
        target_macros=target_macros,
    )
    relevant_macro_defs = [
        macro
        for macro in macro_definitions
        if macro.get("name") in {entry.get("name") for entry in relevant_constants}
        or macro.get("name") in target_macros
        or macro.get("function_like")
        and _symbol_relevance(str(macro.get("name") or ""), target_macros) > 0
    ][:MAX_MACRO_CONTRACTS]
    return {
        "target_macro_constants": dedup_keep_order(list(target_macros))[:80],
        "target_bitmask_expressions": bitmask_expressions[:12],
        "macro_definitions": relevant_macro_defs,
        "enum_constant_groups": enum_constant_groups[:MAX_CONTRACT_GROUPS],
        "bitmask_flag_groups": bitmask_groups[:MAX_CONTRACT_GROUPS],
        "constant_family_policy": [
            "For flag/enum repairs, prefer constants from the same bitmask_flag_group or enum_constant_group.",
            "Do not invent macro/enum names outside this inventory.",
            "Preserve required existing flags unless failure evidence specifically identifies that flag as wrong.",
        ],
    }

def _build_type_contract_inventory(
    *,
    type_definitions: List[dict],
    enum_groups: List[dict],
    target_types: Set[str],
    target_fields: Set[str],
    member_field_inventory: List[dict],
    constructor_initializer_whitelist: dict,
) -> Dict[str, Any]:
    field_sources = []
    for entry in member_field_inventory:
        overlap = sorted(set(entry.get("fields") or []) & target_fields)
        field_sources.append(
            {
                "class": entry.get("class"),
                "source": entry.get("source"),
                "relation": entry.get("relation"),
                "fields": (entry.get("fields") or [])[:50],
                "target_field_overlap": overlap,
            }
        )
    enum_type_defs = [
        {
            "name": group.get("name"),
            "source": group.get("source"),
            "kind": "enum_constant_group",
            "constants": (group.get("constants") or [])[:80],
            "relevance": max(_symbol_relevance(str(group.get("name") or ""), target_types), 1 if set(group.get("constants") or []) & target_types else 0),
        }
        for group in enum_groups[:MAX_CONTRACT_GROUPS]
    ]
    combined = type_definitions + enum_type_defs
    combined.sort(key=lambda item: (-int(item.get("relevance") or 0), item.get("source", ""), item.get("name", "")))
    return {
        "target_types": dedup_keep_order(list(target_types))[:60],
        "type_definitions": combined[:MAX_TYPE_CONTRACTS],
        "member_field_contracts": field_sources[:12],
        "constructor_initializer_contract": constructor_initializer_whitelist,
        "type_use_policy": [
            "Do not add member fields or initializer names outside member_field_contracts/constructor_initializer_contract.",
            "Prefer existing target types and visible typedefs; avoid broad type rewrites in a function-level patch.",
        ],
    }

def _contract_brief(
    *,
    api_inventory: Dict[str, Any],
    macro_inventory: Dict[str, Any],
    type_inventory: Dict[str, Any],
) -> Dict[str, Any]:
    high_priority_groups = []
    for group in macro_inventory.get("bitmask_flag_groups") or []:
        high_priority_groups.append(
            {
                "kind": "bitmask_flag_group",
                "expression": group.get("expression"),
                "required_existing_constants": group.get("required_existing_constants") or [],
                "allowed_constants": (group.get("allowed_constants") or [])[:24],
                "policy": group.get("policy"),
            }
        )
    for group in macro_inventory.get("enum_constant_groups") or []:
        high_priority_groups.append(
            {
                "kind": "enum_constant_group",
                "name": group.get("name"),
                "constants": (group.get("constants") or [])[:24],
                "source": group.get("source"),
            }
        )
    return {
        "allowed_functions": [
            item.get("name")
            for item in (api_inventory.get("function_signatures") or [])[:30]
            if item.get("name")
        ],
        "allowed_macros_or_enum_constants": dedup_keep_order(
            list(macro_inventory.get("target_macro_constants") or [])
            + [
                name
                for group in macro_inventory.get("bitmask_flag_groups") or []
                for name in (group.get("allowed_constants") or [])
            ]
            + [
                name
                for group in macro_inventory.get("enum_constant_groups") or []
                for name in (group.get("constants") or [])
            ]
        )[:80],
        "allowed_types": [
            item.get("name")
            for item in (type_inventory.get("type_definitions") or [])[:30]
            if item.get("name")
        ],
        "high_priority_contract_groups": high_priority_groups[:8],
        "contract_policy": [
            "Use this brief to verify new symbols before editing.",
            "Macro/enum substitutions should come from high_priority_contract_groups.",
            "Function-call changes must match api_contract_inventory signatures.",
        ],
    }

def _target_bitmask_expressions(target_unit: str) -> List[dict]:
    expressions = []
    for idx, line in enumerate((target_unit or "").splitlines(), start=1):
        if "|" not in line:
            continue
        constants = re.findall(r"\b[A-Z_][A-Z0-9_]{2,}\b", line)
        if len(constants) < 2:
            continue
        expressions.append(
            {
                "line_offset": idx,
                "expression": clip_text(line.strip(), 300),
                "constants": dedup_keep_order(constants)[:24],
            }
        )
        if len(expressions) >= 16:
            break
    return expressions

def _relevant_constant_entries(
    entries: List[dict],
    *,
    target_macros: Set[str],
) -> List[dict]:
    families = {_constant_family_key(name) for name in target_macros if name}
    out = []
    seen = set()
    for entry in entries:
        name = str(entry.get("name") or "")
        family = entry.get("family") or _constant_family_key(name)
        if name not in target_macros and family not in families:
            continue
        key = (entry.get("kind"), entry.get("source"), name, entry.get("value"))
        if key in seen:
            continue
        seen.add(key)
        out.append(entry)
        if len(out) >= MAX_MACRO_CONTRACTS:
            break
    return out

def _relevant_enum_groups(
    enum_groups: List[dict],
    *,
    target_macros: Set[str],
) -> List[dict]:
    families = {_constant_family_key(name) for name in target_macros if name}
    out = []
    for group in enum_groups:
        constants = group.get("constants") or []
        group_families = set(group.get("family_keys") or [])
        if not (set(constants) & target_macros or group_families & families):
            continue
        out.append(
            {
                "name": group.get("name"),
                "source": group.get("source"),
                "constants": constants[:120],
                "values": group.get("values") or {},
                "family_keys": group.get("family_keys") or [],
                "evidence": clip_text(group.get("evidence"), 900),
            }
        )
        if len(out) >= MAX_CONTRACT_GROUPS:
            break
    return out

def _bitmask_flag_groups(
    *,
    bitmask_expressions: List[dict],
    constant_entries: List[dict],
    target_macros: Set[str],
) -> List[dict]:
    by_family: Dict[str, List[dict]] = {}
    for entry in constant_entries:
        family = entry.get("family") or _constant_family_key(entry.get("name") or "")
        if not family:
            continue
        by_family.setdefault(family, []).append(entry)
    groups = []
    for expr in bitmask_expressions:
        constants = expr.get("constants") or []
        families = dedup_keep_order([_constant_family_key(name) for name in constants if name])
        allowed = []
        evidence = []
        for family in families:
            for entry in by_family.get(family, []):
                allowed.append(entry.get("name") or "")
                evidence.append(
                    {
                        "name": entry.get("name"),
                        "source": entry.get("source"),
                        "kind": entry.get("kind"),
                        "value": entry.get("value"),
                    }
                )
        groups.append(
            {
                "expression": expr.get("expression"),
                "required_existing_constants": constants,
                "allowed_constants": dedup_keep_order(constants + allowed)[:80],
                "family_keys": families,
                "evidence": evidence[:24],
                "policy": "A patch may swap/add/remove at most the specific flag needed, using allowed_constants from the same family.",
            }
        )
    if not groups and target_macros:
        families = dedup_keep_order([_constant_family_key(name) for name in target_macros if name])
        for family in families[:MAX_CONTRACT_GROUPS]:
            allowed = [entry.get("name") or "" for entry in by_family.get(family, [])]
            if not allowed:
                continue
            groups.append(
                {
                    "expression": "",
                    "required_existing_constants": [name for name in target_macros if _constant_family_key(name) == family],
                    "allowed_constants": dedup_keep_order(allowed)[:80],
                    "family_keys": [family],
                    "evidence": by_family.get(family, [])[:24],
                    "policy": "Use constants from this family for local macro/enum substitutions.",
                }
            )
    return groups[:MAX_CONTRACT_GROUPS]
