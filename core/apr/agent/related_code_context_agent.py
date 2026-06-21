import os
import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_related_code_context_artifact
from core.apr.config import APR_MAX_LOCAL_HEADER_CONTEXT_CHARS, APR_MAX_SOURCE_CHARS
from core.apr.agent.context_common import (
    call_name_from_node,
    clip_text,
    contains_symbol,
    dedup_keep_order,
    extract_symbols_from_code,
    function_name_from_declarator,
    include_records_from_source,
    iter_candidate_project_files,
    node_text,
    parse_tree,
    relpath,
    source_byte_range_to_char_range,
    source_language_from_path,
    source_root,
    walk_nodes,
)


MAX_RECURSIVE_HEADER_DEPTH = 2
MAX_PROJECT_HEADERS = 16
MAX_HEADER_SURFACE_ITEMS = 24
MAX_SOURCE_SURFACE_ITEMS = 40
MAX_USAGE_EXAMPLES = 8
MAX_USAGE_SEARCH_FILES = 80
MAX_DECLARATION_CHARS = 1600
MAX_USAGE_CHARS = 1400
MAX_SOURCE_EXCERPT_CHARS = APR_MAX_SOURCE_CHARS


def collect_related_code_context(
    *,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    context_root: Optional[str],
    target_code_context: dict,
) -> Dict[str, Any]:
    language = source_language_from_path(source_path)
    root = source_root(source_path, context_root)
    source_label = relpath(source_path, root)
    target_unit = (
        (target_code_context.get("target_envelope") or {}).get("replacement_unit")
        or func_code
        or ""
    )
    symbols = extract_symbols_from_code(target_unit, language)
    symbol_set = {
        str(item)
        for key in ("calls", "types", "fields", "identifiers", "macro_like")
        for item in (symbols.get(key) or [])
        if item
    }

    headers, unresolved_headers = _collect_project_headers(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
    )
    include_inventory = _build_include_inventory(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        headers=headers,
        unresolved=unresolved_headers,
    )
    source_excerpt = trim_source_for_context(source_code, start_idx, end_idx)
    source_api_surface = _surface_items_from_source(
        source=source_code,
        language=language,
        source_label=source_label,
        symbols=symbol_set,
        target_start=start_idx,
        target_end=end_idx,
        max_items=MAX_SOURCE_SURFACE_ITEMS,
    )
    same_file_helpers = [
        item for item in source_api_surface
        if str(item.get("kind") or "").startswith("function_definition:")
    ]
    same_file_declarations = [
        item for item in source_api_surface
        if not str(item.get("kind") or "").startswith("function_definition:")
    ]
    header_context = _build_project_header_context(headers, symbol_set)
    usage_examples = _build_call_references(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        call_names=set(symbols.get("calls") or []),
        start_idx=start_idx,
        end_idx=end_idx,
    )
    target_references = _build_call_references(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        call_names={func_name} if func_name else set(),
        start_idx=start_idx,
        end_idx=end_idx,
    )
    external_contracts = _infer_external_contracts(
        target_code=target_unit,
        same_file_helpers=same_file_helpers,
        usage_examples=usage_examples,
        target_references=target_references,
    )
    project_idioms = _project_idioms(
        source_api_surface=source_api_surface,
        header_context=header_context,
        usage_examples=usage_examples,
    )
    ranked_context = _rank_context(
        same_file_helpers=same_file_helpers,
        same_file_declarations=same_file_declarations,
        header_context=header_context,
        usage_examples=usage_examples,
        target_references=target_references,
        external_contracts=external_contracts,
    )
    uncertainties = []
    if include_inventory["unresolved_project_includes"]:
        uncertainties.append(
            "some project includes could not be resolved: "
            + ", ".join(include_inventory["unresolved_project_includes"])
        )
    if len(headers) >= MAX_PROJECT_HEADERS:
        uncertainties.append(f"project header traversal stopped at {MAX_PROJECT_HEADERS} headers")

    return {
        "related_code_map": {
            "target_source_excerpt": source_excerpt,
            "include_inventory": include_inventory,
            "same_file_helpers": same_file_helpers,
            "same_file_declarations": same_file_declarations,
            "header_context": header_context,
            "cross_file_usage_examples": usage_examples,
            "caller_context": target_references,
        },
        "external_behavioral_contracts": external_contracts,
        "project_idioms": project_idioms,
        "ranked_context": ranked_context,
        "uncertainties": uncertainties,
    }


def run_related_code_context_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    context_root: Optional[str],
    target_code_context: dict,
) -> Tuple[dict, dict]:
    context = collect_related_code_context(
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        source_code=source_code,
        source_path=source_path,
        start_idx=start_idx,
        end_idx=end_idx,
        context_root=context_root,
        target_code_context=target_code_context,
    )
    artifact = write_related_code_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        related_code_context=context,
    )
    return context, artifact


def trim_source_for_context(source_code: str, start_idx: int, end_idx: int) -> str:
    start_char, end_char = source_byte_range_to_char_range(source_code, start_idx, end_idx)
    if len(source_code) <= MAX_SOURCE_EXCERPT_CHARS or start_char < 0 or end_char < 0:
        return source_code
    head_budget = min(6000, MAX_SOURCE_EXCERPT_CHARS // 4)
    remaining = MAX_SOURCE_EXCERPT_CHARS - head_budget
    neighborhood = max(2000, remaining // 2)
    head = source_code[:head_budget]
    func_lo = max(head_budget, start_char - neighborhood)
    func_hi = min(len(source_code), end_char + neighborhood)
    parts = [head]
    if func_lo > head_budget:
        parts.append("\n\n/* ... [source truncated - prelude shown above] ... */\n\n")
    parts.append(source_code[func_lo:func_hi])
    if func_hi < len(source_code):
        parts.append("\n\n/* ... [source truncated - tail omitted] ... */\n")
    return "".join(parts)


def _resolve_project_include(include_name: str, including_dir: str, root: str) -> str:
    candidates = [os.path.normpath(os.path.join(including_dir, include_name))]
    root_candidate = os.path.normpath(os.path.join(root, include_name))
    if root_candidate not in candidates:
        candidates.append(root_candidate)
    for candidate in candidates:
        try:
            inside_root = os.path.commonpath([root, candidate]) == root
        except ValueError:
            inside_root = False
        if inside_root and os.path.isfile(candidate):
            return candidate
    basename = os.path.basename(include_name)
    matches = []
    for dirpath, dirs, files in os.walk(root):
        dirs[:] = [d for d in dirs if d not in {".git", "build", "cmake-build-debug"}]
        if basename in files:
            matches.append(os.path.join(dirpath, basename))
            if len(matches) > 1:
                break
    return matches[0] if len(matches) == 1 else ""


def _collect_project_headers(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
) -> Tuple[List[dict], List[str]]:
    queue = []
    unresolved = []
    seen_paths = set()
    headers = []
    source_origin = relpath(source_path, source_root)
    for record in include_records_from_source(source_code, language, source_origin):
        if record["kind"] == "project":
            queue.append((record["name"], os.path.dirname(source_path), 0, source_origin))

    while queue and len(headers) < MAX_PROJECT_HEADERS:
        include_name, including_dir, depth, included_from = queue.pop(0)
        header_path = _resolve_project_include(include_name, including_dir, source_root)
        if not header_path:
            unresolved.append(include_name)
            continue
        if header_path in seen_paths:
            continue
        seen_paths.add(header_path)
        try:
            with open(header_path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            unresolved.append(include_name)
            continue
        rel = relpath(header_path, source_root)
        header_language = source_language_from_path(header_path)
        headers.append(
            {
                "include": include_name,
                "path": header_path,
                "relpath": rel,
                "depth": depth,
                "included_from": included_from,
                "text": text,
                "language": header_language,
            }
        )
        if depth >= MAX_RECURSIVE_HEADER_DEPTH:
            continue
        for record in include_records_from_source(text, header_language, rel):
            if record["kind"] == "project":
                queue.append((record["name"], os.path.dirname(header_path), depth + 1, rel))
    return headers, dedup_keep_order(unresolved)


def _build_include_inventory(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
    headers: List[dict],
    unresolved: List[str],
) -> dict:
    system = []
    project = []
    source_origin = relpath(source_path, source_root)
    for record in include_records_from_source(source_code, language, source_origin):
        if record["kind"] == "system":
            system.append(record["name"])
        elif record["kind"] == "project":
            project.append(record["name"])
    for header in headers:
        for record in include_records_from_source(header["text"], header["language"], header["relpath"]):
            if record["kind"] == "system":
                system.append(record["name"])
            elif record["kind"] == "project":
                project.append(record["name"])
    return {
        "system_includes": dedup_keep_order(system),
        "project_includes": dedup_keep_order(project),
        "resolved_project_headers": dedup_keep_order([h["relpath"] for h in headers]),
        "unresolved_project_includes": dedup_keep_order(unresolved),
    }


def _surface_items_from_source(
    *,
    source: str,
    language: str,
    source_label: str,
    symbols: set,
    target_start: int = -1,
    target_end: int = -1,
    max_items: int,
) -> List[dict]:
    items = []
    seen = set()
    tree, source_bytes = parse_tree(source, language)
    interesting = {
        "declaration",
        "type_definition",
        "struct_specifier",
        "enum_specifier",
        "preproc_def",
        "preproc_function_def",
        "function_declaration",
        "function_definition",
    }
    if tree is not None and source_bytes is not None:
        for node in walk_nodes(tree.root_node):
            if node.type not in interesting:
                continue
            if target_start >= 0 and node.start_byte >= target_start and node.end_byte <= target_end:
                continue
            text = node_text(node, source_bytes).strip()
            if not contains_symbol(text, symbols):
                continue
            label = node.type
            if node.type == "function_definition":
                declarator = node.child_by_field_name("declarator")
                name = function_name_from_declarator(declarator, source_bytes) if declarator else ""
                if name and name not in symbols:
                    continue
                label = f"function_definition:{name or '<unknown>'}"
            key = (source_label, label, text[:200])
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "source": source_label,
                    "kind": label,
                    "text": clip_text(text, MAX_DECLARATION_CHARS),
                }
            )
            if len(items) >= max_items:
                return items
        return items

    declaration_re = re.compile(
        r'^\s*(?:#\s*define\b.*|typedef\b.*|(?:struct|enum)\b.*|[A-Za-z_][\w\s\*]*\b[A-Za-z_]\w*\s*\([^;{}]*\)\s*;)',
        re.MULTILINE,
    )
    for match in declaration_re.finditer(source):
        text = match.group(0).strip()
        if not contains_symbol(text, symbols):
            continue
        key = (source_label, text)
        if key in seen:
            continue
        seen.add(key)
        items.append({"source": source_label, "kind": "regex_declaration", "text": text})
        if len(items) >= max_items:
            break
    return items


def _build_project_header_context(headers: List[dict], symbols: set) -> List[dict]:
    out = []
    total_chars = 0
    for header in headers:
        if total_chars >= APR_MAX_LOCAL_HEADER_CONTEXT_CHARS:
            out.append({"note": "project header context truncated"})
            break
        surface = _surface_items_from_source(
            source=header["text"],
            language=header["language"],
            source_label=header["relpath"],
            symbols=symbols,
            max_items=MAX_HEADER_SURFACE_ITEMS,
        )
        payload = {
            "header": header["relpath"],
            "include": header["include"],
            "depth": header["depth"],
            "included_from": header["included_from"],
            "api_surface": [],
        }
        for item in surface:
            item_size = len(str(item))
            if total_chars + len(str(payload)) + item_size > APR_MAX_LOCAL_HEADER_CONTEXT_CHARS:
                payload["api_surface_truncated"] = True
                break
            payload["api_surface"].append(item)
        if not payload["api_surface"]:
            excerpt = clip_text(header["text"], 900)
            if total_chars + len(str(payload)) + len(excerpt) <= APR_MAX_LOCAL_HEADER_CONTEXT_CHARS:
                payload["excerpt_when_no_symbol_match"] = excerpt
            else:
                payload["note"] = "header omitted because context budget is exhausted"
        total_chars += len(str(payload))
        out.append(payload)
    return out


def _usage_examples_from_source(
    *,
    source: str,
    source_path: str,
    source_root: str,
    language: str,
    call_names: set,
    target_start: int = -1,
    target_end: int = -1,
    limit: int,
) -> List[dict]:
    examples = []
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return examples
    for node in walk_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        if target_start >= 0 and node.start_byte >= target_start and node.end_byte <= target_end:
            continue
        text = node_text(node, source_bytes)
        declarator = node.child_by_field_name("declarator")
        function_name = function_name_from_declarator(declarator, source_bytes) if declarator else ""
        used_calls = sorted(
            name
            for name in call_names
            if name != function_name and re.search(r'\b' + re.escape(name) + r'\s*\(', text)
        )
        if not used_calls:
            continue
        examples.append(
            {
                "source": relpath(source_path, source_root),
                "function": function_name or "<unknown>",
                "calls": used_calls,
                "snippet": _snippet_from_function_for_calls(text, set(used_calls)),
            }
        )
        if len(examples) >= limit:
            break
    return examples


def _snippet_from_function_for_calls(function_text: str, call_names: set) -> str:
    lines = function_text.splitlines()
    selected = []
    for idx, line in enumerate(lines):
        if any(re.search(r'\b' + re.escape(name) + r'\s*\(', line) for name in call_names):
            start = max(0, idx - 2)
            end = min(len(lines), idx + 3)
            if selected and selected[-1] != "...":
                selected.append("...")
            selected.extend(lines[start:end])
    if not selected:
        return clip_text(function_text, MAX_USAGE_CHARS)
    return clip_text("\n".join(selected), MAX_USAGE_CHARS)


def _build_call_references(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
    call_names: set,
    start_idx: int,
    end_idx: int,
) -> List[dict]:
    if not call_names:
        return []
    examples = _usage_examples_from_source(
        source=source_code,
        source_path=source_path,
        source_root=source_root,
        language=language,
        call_names=call_names,
        target_start=start_idx,
        target_end=end_idx,
        limit=MAX_USAGE_EXAMPLES,
    )
    if len(examples) >= MAX_USAGE_EXAMPLES:
        return examples
    for path in iter_candidate_project_files(source_root, source_path, MAX_USAGE_SEARCH_FILES):
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if not any(name in text for name in call_names):
            continue
        examples.extend(
            _usage_examples_from_source(
                source=text,
                source_path=path,
                source_root=source_root,
                language=source_language_from_path(path),
                call_names=call_names,
                limit=MAX_USAGE_EXAMPLES - len(examples),
            )
        )
        if len(examples) >= MAX_USAGE_EXAMPLES:
            break
    return examples[:MAX_USAGE_EXAMPLES]


def _infer_external_contracts(
    *,
    target_code: str,
    same_file_helpers: List[dict],
    usage_examples: List[dict],
    target_references: List[dict],
) -> List[dict]:
    contracts = []
    target_lc = target_code.lower()
    for helper in same_file_helpers:
        text = str(helper.get("text") or "")
        name = str(helper.get("kind") or "").split(":", 1)[-1]
        if not name or name == "<unknown>":
            continue
        evidence = []
        if re.search(r"if\s*\(\s*!\s*\w+\s*\)\s*\{\s*return\b", text, re.S) or re.search(r"if\s*\(\s*!\s*\w+\s*\)\s*return\b", text):
            evidence.append("helper has an early return on NULL-like argument")
        if re.search(r"assert\s*\(\s*!\s*\w+\s*\|\|", text):
            evidence.append("helper assertion explicitly allows NULL-like argument")
        if evidence:
            contracts.append(
                {
                    "symbol": name,
                    "kind": "nullable_argument_tolerated",
                    "contract": f"{name} appears to handle NULL-like inputs; do not skip the call only because an argument may be NULL.",
                    "evidence": evidence + [clip_text(text, 900)],
                }
            )
        if re.search(r"\b(free|unlink|remove|apply|switch|insert|addchild)\w*\b", name.lower() + " " + text.lower()):
            contracts.append(
                {
                    "symbol": name,
                    "kind": "state_or_ownership_helper",
                    "contract": f"Preserve the established call order around {name}; these helpers mutate state/ownership.",
                    "evidence": [clip_text(text, 900)],
                }
            )
    for example in usage_examples + target_references:
        snippet = str(example.get("snippet") or "")
        calls = example.get("calls") or []
        for call in calls:
            call_re = re.escape(str(call))
            if re.search(rf"\b(if|while)\s*\([^)]*\b{call_re}\s*\(", snippet) or re.search(rf"\b(ret|rc|err)\s*=\s*{call_re}\s*\(", snippet):
                contracts.append(
                    {
                        "symbol": call,
                        "kind": "return_value_checked_in_usage",
                        "contract": f"Existing usage checks or stores the return value of {call}; preserve its error-handling convention.",
                        "evidence": [clip_text(snippet, 900)],
                    }
                )
    if any(word in target_lc for word in ("unlink", "apply", "remove_aug", "lys_node_switch")):
        contracts.append(
            {
                "symbol": "target_state_flow",
                "kind": "state_transition_order",
                "contract": "Target function performs ordered state transitions; avoid inserting new apply/remove/unlink calls before proving the order from callers/helpers.",
                "evidence": [
                    line.strip()
                    for line in target_code.splitlines()
                    if re.search(r"\b(unlink|apply|remove|switch|addchild)\w*\s*\(", line)
                ][:10],
            }
        )
    return _dedup_contracts(contracts)[:20]


def _project_idioms(
    *,
    source_api_surface: List[dict],
    header_context: List[dict],
    usage_examples: List[dict],
) -> List[dict]:
    texts = []
    for item in source_api_surface[:20]:
        texts.append(str(item.get("text") or ""))
    for header in header_context[:8]:
        for item in header.get("api_surface") or []:
            texts.append(str(item.get("text") or ""))
    for example in usage_examples:
        texts.append(str(example.get("snippet") or ""))
    joined = "\n".join(texts)
    idioms = []
    patterns = {
        "goto_cleanup": r"\bgoto\s+(cleanup|error)\b",
        "ly_check_macros": r"\bLY_CHECK_[A-Z_]+\b",
        "fmt_error_handler": r"\b(on_error|FMT_THROW|format_error)\b",
        "assertion_contracts": r"\bassert\s*\(",
        "manual_memory_cleanup": r"\b(free|delete|ly_set_free|lyd_free|lys_free)\s*\(",
    }
    for name, pattern in patterns.items():
        matches = re.findall(pattern, joined)
        if matches:
            idioms.append(
                {
                    "kind": name,
                    "summary": f"Project context repeatedly uses {name.replace('_', ' ')}.",
                    "evidence_count": len(matches),
                }
            )
    return idioms


def _rank_context(
    *,
    same_file_helpers: List[dict],
    same_file_declarations: List[dict],
    header_context: List[dict],
    usage_examples: List[dict],
    target_references: List[dict],
    external_contracts: List[dict],
) -> dict:
    must_read = []
    for item in external_contracts[:8]:
        must_read.append({"type": "external_contract", "summary": item.get("contract"), "symbol": item.get("symbol")})
    for item in target_references[:5]:
        must_read.append({"type": "caller_context", "source": item.get("source"), "function": item.get("function")})
    likely = []
    for item in same_file_helpers[:8]:
        likely.append({"type": "same_file_helper", "kind": item.get("kind"), "source": item.get("source")})
    for item in usage_examples[:6]:
        likely.append({"type": "usage_example", "source": item.get("source"), "function": item.get("function"), "calls": item.get("calls")})
    background = []
    for item in same_file_declarations[:10]:
        background.append({"type": "same_file_declaration", "kind": item.get("kind"), "source": item.get("source")})
    for header in header_context[:8]:
        background.append({"type": "header_context", "header": header.get("header"), "items": len(header.get("api_surface") or [])})
    return {
        "must_read": must_read[:12],
        "likely_relevant": likely[:14],
        "background_only": background[:16],
    }


def _dedup_contracts(contracts: List[dict]) -> List[dict]:
    out = []
    seen = set()
    for contract in contracts:
        key = (contract.get("symbol"), contract.get("kind"), contract.get("contract"))
        if key in seen:
            continue
        seen.add(key)
        out.append(contract)
    return out
