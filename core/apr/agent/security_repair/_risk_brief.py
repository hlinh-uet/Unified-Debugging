import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.program_analysis import analyze_target_operations


MAX_TEXT = 360
MAX_RISKS = 12
MAX_UNSAFE_PATHS = 8
_GUARD_SYMBOL_RE = re.compile(r"(?:check|test|bound|valid|verify|ensure|assert|guard|limit|avail|remain)", re.IGNORECASE)
_INPUT_READ_SYMBOL_RE = re.compile(r"(?:extract|get|read|fetch|load|decode|parse|consume)", re.IGNORECASE)
_OUTPUT_SYMBOL_RE = re.compile(r"(?:print|format|log|warn|error|dump|emit|printf|puts|message)", re.IGNORECASE)
_OWNERSHIP_SYMBOL_RE = re.compile(r"(?:free|delete|destroy|destruct|release|dtor|refcount|retain|owner|cleanup)", re.IGNORECASE)
_ALLOCATION_SYMBOL_RE = re.compile(r"(?:alloc|malloc|calloc|realloc|new)", re.IGNORECASE)
_POINTER_SYMBOL_RE = re.compile(r"(?:^|_)(?:ptr|buf|buffer|data|base|dst|src|cursor|pos|p|ep|end)(?:_|$)", re.IGNORECASE)
_SIZE_SYMBOL_RE = re.compile(r"(?:^|_)(?:len|length|size|count|off|offset|remaining|remain|avail|capacity|cap|limit|end|max|need)(?:_|$)", re.IGNORECASE)
_CAPACITY_SYMBOL_RE = re.compile(r"(?:^|_)(?:capacity|cap|sizeof|size|limit|max|end|avail|remaining|remain)(?:_|$)", re.IGNORECASE)
_REMAINING_SYMBOL_RE = re.compile(r"(?:^|_)(?:remaining|remain|avail|left|end|limit)(?:_|$)", re.IGNORECASE)
_CONSUMED_SYMBOL_RE = re.compile(r"(?:^|_)(?:off|offset|pos|idx|index|cursor|consumed|used|advance|ptr|p)(?:_|$)", re.IGNORECASE)
_NEEDED_SYMBOL_RE = re.compile(r"(?:^|_)(?:len|length|size|count|need|needed|nread|copy|read|write)(?:_|$)", re.IGNORECASE)
_BOUND_OPERATOR_RE = re.compile(r"(?:<=|>=|<|>|==|!=|\bsizeof\b|\bARRAY_SIZE\b|\bMIN\b|\bMAX\b|\bend\b|\blimit\b)", re.IGNORECASE)
_C_KEYWORDS = {
    "auto", "break", "case", "char", "const", "continue", "default", "do", "double",
    "else", "enum", "extern", "float", "for", "goto", "if", "inline", "int", "long",
    "register", "return", "short", "signed", "sizeof", "static", "struct", "switch",
    "typedef", "union", "unsigned", "void", "volatile", "while",
}


def build_security_risk_brief(
    *,
    func_name: str,
    func_code: str,
    replacement_target: Dict[str, Any],
    failed_tests_context: str,
    related_code_context: Optional[Dict[str, Any]] = None,
    repair_objective: Optional[Dict[str, Any]] = None,
    source_path: str = "",
    source_root: str = "",
    language: str = "",
) -> Dict[str, Any]:
    objective = dict(repair_objective or {})
    failure_contract = _failure_contract(failed_tests_context, objective)
    operation_analysis = analyze_target_operations(
        func_code=func_code,
        replacement_target=replacement_target or {},
        related_code_context=related_code_context or {},
        source_path=source_path,
        source_root=source_root,
        function_name=func_name,
        language=language,
    )
    project_terms = _project_context_terms(related_code_context or {}, func_code)
    operation_risks = _risk_candidates_from_operations(operation_analysis.operations or [], project_terms)
    if operation_risks:
        operation_risks = _enrich_risks_with_source_guards(
            operation_risks,
            func_code=func_code,
            replacement_target=replacement_target,
            project_terms=project_terms,
        )
        source_risks = []
    else:
        source_risks = _risk_candidates_from_source(func_code, replacement_target, project_terms)
    risky_operations = _risk_brief_operations(
        source_risks,
        operation_risks,
        failure_contract=failure_contract,
        project_terms=project_terms,
    )
    unsafe_paths = _unsafe_paths_from_risks(
        risky_operations,
        func_code=func_code,
        replacement_target=replacement_target,
        project_terms=project_terms,
    )
    return {
        "analysis_engine": {
            "name": "security_repair_constraints_risk_brief",
            "version": 4,
            "strategy": "concrete_risk_operations_from_program_analysis_with_source_fallback",
            "role": "Internal RepairConstraints helper; emits unsafe_paths centered on sink/state/guards/cleanup.",
            "operation_provider": operation_analysis.engine or {},
        },
        "target": {
            "function": func_name,
            "source_file": _source_file(replacement_target, source_path),
            "replacement_range": ((replacement_target or {}).get("replacement_envelope") or {}).get("replacement_range") or {},
        },
        "security_failure_contract": failure_contract,
        "related_context_hints": _related_context_hints(related_code_context or {}, project_terms),
        "unsafe_paths": unsafe_paths[:MAX_UNSAFE_PATHS],
        "path_summary": _path_summary(unsafe_paths, failure_contract),
        "risk_operations": risky_operations[:MAX_RISKS],
        # Compatibility alias for older prompts/consumers. Prefer risk_operations/unsafe_paths.
        "risky_operations": risky_operations[:MAX_RISKS],
        "risk_summary": _risk_summary(risky_operations, failure_contract),
        "wrong_fix_risks": _wrong_fix_risks(
            risky_operations,
            related_code_context or {},
            failure_contract,
            project_terms,
        ),
        "constraints": _risk_constraints(related_code_context or {}, failure_contract, project_terms),
        "downstream_context_requests": _context_requests(unsafe_paths, failure_contract),
        "risk_policy": [
            "Use risk_operations for concrete operation facts, then unsafe_paths for sink/state/guard/cleanup evidence.",
            "Each unsafe_path ties a sink to observed state, guards, cleanup obligations, and a patch-site hint.",
            "Choose edits that make the evidence-matched unsafe_path fail closed before the sink while preserving valid paths.",
            "Avoid wrong_fix_risks even if a candidate patch compiles or changes output.",
        ],
        "uncertainties": list(operation_analysis.uncertainties or [])[:6] + _path_uncertainties(unsafe_paths),
    }


def _project_context_terms(context: Dict[str, Any], func_code: str) -> Dict[str, List[str]]:
    symbols: List[str] = []
    _collect_identifier_strings(context, symbols)
    symbols.extend(re.findall(r"\b[A-Za-z_]\w*\b", func_code or ""))
    api_symbols = _dedup([item for item in symbols if _is_probable_api_symbol(item)])
    return {
        "guard_symbols": _semantic_symbols(api_symbols, _GUARD_SYMBOL_RE),
        "extract_symbols": _semantic_symbols(api_symbols, _INPUT_READ_SYMBOL_RE),
        "output_symbols": _semantic_symbols(api_symbols, _OUTPUT_SYMBOL_RE),
        "ownership_symbols": _semantic_symbols(api_symbols, _OWNERSHIP_SYMBOL_RE),
        "allocation_symbols": _semantic_symbols(api_symbols, _ALLOCATION_SYMBOL_RE),
    }


def _collect_identifier_strings(value: Any, out: List[str], depth: int = 0) -> None:
    if value is None or depth > 6:
        return
    if isinstance(value, dict):
        for item in value.values():
            _collect_identifier_strings(item, out, depth + 1)
        return
    if isinstance(value, (list, tuple, set)):
        for item in value:
            _collect_identifier_strings(item, out, depth + 1)
        return
    if isinstance(value, str):
        out.extend(re.findall(r"\b[A-Za-z_]\w*\b", value))


def _is_probable_api_symbol(value: Any) -> bool:
    text = str(value or "").strip()
    if not re.match(r"^[A-Za-z_]\w*$", text):
        return False
    if text.lower() in _C_KEYWORDS:
        return False
    if len(text) <= 2:
        return False
    return "_" in text or any(char.isupper() for char in text)


def _semantic_symbols(symbols: List[str], pattern: re.Pattern) -> List[str]:
    return _dedup([item for item in symbols or [] if pattern.search(item)])[:40]


def _compact_project_terms(project_terms: Dict[str, List[str]]) -> Dict[str, List[str]]:
    return {
        "guard_symbols": _first(project_terms.get("guard_symbols"), 12),
        "extract_symbols": _first(project_terms.get("extract_symbols"), 12),
        "output_symbols": _first(project_terms.get("output_symbols"), 12),
        "ownership_symbols": _first(project_terms.get("ownership_symbols"), 12),
        "allocation_symbols": _first(project_terms.get("allocation_symbols"), 12),
    }


def _project_operation_symbols(project_terms: Dict[str, List[str]]) -> List[str]:
    return _dedup([
        *(project_terms.get("guard_symbols") or []),
        *(project_terms.get("extract_symbols") or []),
        *(project_terms.get("output_symbols") or []),
        *(project_terms.get("ownership_symbols") or []),
        *(project_terms.get("allocation_symbols") or []),
    ])


def _symbol_regex(symbols: Optional[List[str]]) -> Optional[re.Pattern]:
    names = [item for item in _dedup(symbols or []) if re.match(r"^[A-Za-z_]\w*$", str(item))]
    if not names:
        return None
    names = sorted(names, key=len, reverse=True)[:80]
    return re.compile(r"\b(?:" + "|".join(re.escape(item) for item in names) + r")\b")


def _line_calls_any_symbol(line: str, symbols: Optional[List[str]]) -> bool:
    pattern = _symbol_regex(symbols)
    if not pattern:
        return False
    return bool(pattern.search(str(line or "")))


def _failure_contract(text: str, objective: Dict[str, Any]) -> Dict[str, Any]:
    lower = str(text or "").lower()
    categories = [str(item) for item in objective.get("failure_categories") or [] if item]
    oracle = (
        objective.get("validation_oracle")
        or objective.get("oracle_subkind")
        or _first_match(
            lower,
            [
                ("AddressSanitizer", "asan"),
                ("short/truncated input", "short packet|truncated|malformed"),
                ("language-specific test failure", "phpt|failed test summary"),
                ("test harness failure", "test failed|tests failed"),
            ],
        )
    )
    return {
        "route": "security_repair",
        "categories": _dedup(categories)[:8],
        "oracle_kind": oracle,
        "signals": _signal_lines(text),
        "repair_goal": objective.get("repair_goal") or "Eliminate the unsafe runtime path with a minimal semantics-preserving edit.",
    }


def _risk_candidates_from_source(
    func_code: str,
    replacement_target: Dict[str, Any],
    project_terms: Dict[str, List[str]],
) -> List[dict]:
    start_line = _replacement_start_line(replacement_target)
    lines = (func_code or "").splitlines()
    risks = []
    patterns = [
        ("buffer_or_memory_call", re.compile(r"\b(memcpy|memmove|memcmp|memset|strcpy|strncpy|read|write)\s*\(")),
        ("allocation_or_size_call", re.compile(r"\b(malloc|calloc|realloc)\s*\(")),
        ("free_or_lifetime_transition", re.compile(r"\b(free|delete|destroy|destruct|release)\s*\(")),
        ("array_access", re.compile(r"\b[A-Za-z_]\w*\s*\[[^\]]+\]")),
        ("pointer_or_member_deref", re.compile(r"(?:->|\*\s*[A-Za-z_]\w*)")),
        ("pointer_or_offset_advance", re.compile(r"(\+\+|--|\+=|-=|=\s*[^;]*(?:\+|-)\s*(?:len|length|size|count|off|offset|alen|tlen|tlv|ptr|p)\b)")),
        ("length_controlled_loop", re.compile(r"\b(for|while)\s*\([^)]*(?:len|length|size|count|off|offset|alen|tlen|tlv|remaining)[^)]*\)")),
    ]
    extract_pattern = _symbol_regex(project_terms.get("extract_symbols"))
    if extract_pattern:
        patterns.insert(1, ("project_bounds_or_extract_operation", extract_pattern))
    allocation_pattern = _symbol_regex(project_terms.get("allocation_symbols"))
    if allocation_pattern:
        patterns.insert(1, ("allocation_or_size_call", allocation_pattern))
    ownership_pattern = _symbol_regex(project_terms.get("ownership_symbols"))
    if ownership_pattern:
        patterns.insert(2, ("free_or_lifetime_transition", ownership_pattern))
    for idx, line in enumerate(lines, start=start_line):
        stripped = line.strip()
        if not stripped or stripped.startswith(("/*", "*", "//")):
            continue
        if _skip_declarative_risk_line(stripped, project_terms) or _is_bounds_guard_only(stripped, project_terms):
            continue
        for kind, pattern in patterns:
            if not pattern.search(stripped):
                continue
            risks.append(
                _risk_record(
                    kind=kind,
                    line=idx,
                    code=stripped,
                    provider="source_regex",
                    symbols=_symbols_from_line(stripped),
                    guard_context=_guard_context(lines, idx - start_line, project_terms, start_line=start_line),
                )
            )
            break
    return risks


def _skip_declarative_risk_line(line: str, project_terms: Dict[str, List[str]]) -> bool:
    text = str(line or "").strip()
    if re.search(r"\)\s*\{\s*$", text):
        return True
    if not text.endswith(";"):
        return False
    if _line_calls_any_symbol(text, _project_operation_symbols(project_terms)):
        return False
    if re.search(r"\b(memcpy|memmove|memcmp|strcpy|strncpy|read|write)\s*(?:\(|$)", text):
        return False
    if re.search(r"\b(?:const|register|static|struct|enum|union|unsigned|signed|u_int|uint\d+_t|int|char|size_t|time_t|bool|void)\b", text):
        return True
    return False


def _is_bounds_guard_only(line: str, project_terms: Dict[str, List[str]]) -> bool:
    text = str(line or "")
    if not _line_calls_any_symbol(text, project_terms.get("guard_symbols")):
        return False
    has_sink = (
        _line_calls_any_symbol(text, project_terms.get("extract_symbols"))
        or re.search(r"\b(memcpy|memmove|memcmp|memset|strcpy|strncpy|read|write)\s*\(", text)
    )
    return not bool(has_sink)


def _risk_candidates_from_operations(operations: List[dict], project_terms: Dict[str, List[str]]) -> List[dict]:
    out = []
    for op in operations or []:
        code = str(op.get("code") or "").strip()
        if not code:
            continue
        if _skip_declarative_risk_line(code, project_terms) or _is_bounds_guard_only(code, project_terms):
            continue
        kind = ""
        if re.search(r"\b(memcpy|memmove|memcmp|read|write)\s*\(", code):
            kind = "buffer_or_memory_call"
        elif _line_calls_any_symbol(code, project_terms.get("allocation_symbols")):
            kind = "allocation_or_size_call"
        elif re.search(r"\b(free|delete|destroy|destruct|release)\s*\(", code) or _line_calls_any_symbol(code, project_terms.get("ownership_symbols")):
            kind = "free_or_lifetime_transition"
        elif _line_calls_any_symbol(code, project_terms.get("extract_symbols")):
            kind = "project_bounds_or_extract_operation"
        elif re.search(r"\[[^\]]+\]|->|\*\s*[A-Za-z_]\w*", code):
            kind = "pointer_index_or_deref"
        if not kind:
            continue
        symbols = op.get("symbols") if isinstance(op.get("symbols"), dict) else {}
        flat_symbols = []
        for key in ("calls", "macro_like", "fields", "identifiers", "types"):
            flat_symbols.extend(str(item) for item in symbols.get(key) or [] if item)
        out.append(
            _risk_record(
                kind=kind,
                line=op.get("line"),
                code=code,
                provider=op.get("provider") or "program_analysis",
                symbols=flat_symbols,
                guard_context=_operation_guard_context(op),
            )
        )
    return out


def _enrich_risks_with_source_guards(
    risks: List[dict],
    *,
    func_code: str,
    replacement_target: Dict[str, Any],
    project_terms: Dict[str, List[str]],
) -> List[dict]:
    start_line = _replacement_start_line(replacement_target)
    lines = (func_code or "").splitlines()
    enriched = []
    for risk in risks or []:
        item = dict(risk)
        line = _safe_int(item.get("line"))
        if line:
            local_index = max(0, line - start_line)
            item["existing_guards"] = _merge_guard_context(
                item.get("existing_guards") or [],
                _guard_context(lines, local_index, project_terms, start_line=start_line),
            )
        enriched.append(item)
    return enriched


def _risk_record(*, kind: str, line: Any, code: str, provider: str, symbols: List[str], guard_context: List[Any]) -> dict:
    values = _risk_values(code, symbols)
    return {
        "id": "",
        "kind": kind,
        "line": _safe_int(line),
        "sink_code": _clip(code, 260),
        "provider": provider,
        "input_controlled_values": values,
        "operation_summary": _operation_summary(kind, code, provider),
        "operand_roles": _operand_roles(kind, code, values),
        "boundary_facts": _boundary_facts(kind, code, values),
        "existing_guards": _compact_guard_context(guard_context),
        "guard_gap": _guard_gap(kind, guard_context, values),
        "missing_property": _missing_property(kind),
        "dominance_requirement": _dominance_requirement(kind),
        "suggested_patch_operator": _patch_operator(kind),
        "repair_intent": _repair_intent(kind),
        "required_related_context": _required_related_context(kind, symbols),
        "confidence": "medium",
        "score": 0,
    }


def _risk_brief_operations(
    source_risks: List[dict],
    operation_risks: List[dict],
    *,
    failure_contract: Dict[str, Any],
    project_terms: Dict[str, List[str]],
) -> List[dict]:
    merged = {}
    for risk in [*source_risks, *operation_risks]:
        key = (risk.get("line"), risk.get("kind"), _risk_code_key(risk.get("sink_code")))
        if key in merged:
            merged[key]["provider"] = "source_regex+program_analysis"
            merged[key]["input_controlled_values"] = _dedup([
                *merged[key].get("input_controlled_values", []),
                *risk.get("input_controlled_values", []),
            ])[:10]
            merged[key]["existing_guards"] = _merge_guard_context(
                merged[key].get("existing_guards") or [],
                risk.get("existing_guards") or [],
            )
            continue
        merged[key] = dict(risk)
    operations = list(merged.values())
    operations.sort(key=lambda item: (int(item.get("line") or 10**9), str(item.get("kind") or "")))
    for idx, risk in enumerate(operations, start=1):
        risk["id"] = f"risk_op_{idx}"
        risk.pop("score", None)
        risk["role"] = "hazard_evidence_not_edit_location"
        risk["why_risky"] = _why_risky(risk, failure_contract)
        risk["wrong_fix_trap"] = _wrong_fix_trap(risk, project_terms)
        risk["safe_repair_expectation"] = _safe_repair_expectation(risk)
    return operations


def _operation_summary(kind: str, code: str, provider: str) -> Dict[str, Any]:
    call_name, args = _call_shape(code)
    return {
        "sink_kind": kind,
        "call_name": call_name,
        "arguments": _first(args, 6),
        "provider": provider,
        "is_memory_sink": kind in {"buffer_or_memory_call", "array_access", "pointer_index_or_deref", "pointer_or_member_deref"},
        "is_length_or_capacity_flow": kind in {"allocation_or_size_call", "pointer_or_offset_advance", "length_controlled_loop"},
        "is_lifetime_flow": kind == "free_or_lifetime_transition",
    }


def _operand_roles(kind: str, code: str, values: List[str]) -> Dict[str, List[str]]:
    call_name, args = _call_shape(code)
    pointer_symbols = [item for item in values if _POINTER_SYMBOL_RE.search(item)]
    size_symbols = [item for item in values if _SIZE_SYMBOL_RE.search(item)]
    roles: Dict[str, List[str]] = {
        "pointer_like": _first(pointer_symbols, 8),
        "size_like": _first(size_symbols, 8),
        "capacity_like": _first([item for item in values if _CAPACITY_SYMBOL_RE.search(item)], 8),
        "remaining_like": _first([item for item in values if _REMAINING_SYMBOL_RE.search(item)], 8),
        "needed_like": _first([item for item in values if _NEEDED_SYMBOL_RE.search(item)], 8),
    }
    if call_name in {"memcpy", "memmove", "memcmp", "memset"}:
        roles["memory_call_arguments"] = _first(args, 4)
        if len(args) >= 1:
            roles["destination"] = [args[0]]
        if len(args) >= 2:
            roles["source"] = [args[1]]
        if len(args) >= 3:
            roles["byte_count"] = [args[2]]
    elif call_name in {"read", "write"}:
        roles["io_call_arguments"] = _first(args, 4)
        if len(args) >= 3:
            roles["byte_count"] = [args[2]]
    elif kind in {"array_access", "pointer_index_or_deref"}:
        roles["index_or_member_terms"] = _first(_symbols_from_line(code), 8)
    return {key: value for key, value in roles.items() if value}


def _boundary_facts(kind: str, code: str, values: List[str]) -> Dict[str, Any]:
    text = str(code or "")
    return {
        "requires_pre_guard": kind != "free_or_lifetime_transition",
        "requires_capacity_proof": kind in {"buffer_or_memory_call", "array_access", "allocation_or_size_call"},
        "requires_pointer_validity": kind in {"buffer_or_memory_call", "pointer_index_or_deref", "pointer_or_member_deref", "array_access"},
        "requires_lifetime_preservation": kind == "free_or_lifetime_transition",
        "has_inline_bound_expression": bool(_BOUND_OPERATOR_RE.search(text)),
        "mentions_size_or_remaining_symbol": bool(values and any(_SIZE_SYMBOL_RE.search(item) for item in values)),
    }


def _guard_gap(kind: str, guards: List[Any], values: List[str]) -> Dict[str, Any]:
    normalized = [_normalize_guard_context(item) for item in guards or []]
    guard_text = "\n".join(str(item.get("code") or "") for item in normalized)
    mentions_value = any(
        value and re.search(r"\b" + re.escape(str(value)) + r"\b", guard_text)
        for value in _first(values, 8)
    )
    has_bounds_guard = bool(_BOUND_OPERATOR_RE.search(guard_text))
    has_null_guard = bool(re.search(r"(?:!\s*[A-Za-z_]\w+|[A-Za-z_]\w+\s*(?:==|!=)\s*NULL|nullptr|0)", guard_text))
    return {
        "has_existing_guard": bool(normalized),
        "guard_mentions_sink_values": mentions_value,
        "guard_has_bounds_operator": has_bounds_guard,
        "guard_has_null_or_lifetime_check": has_null_guard,
        "missing_guard_property": _missing_property(kind),
    }


def _repair_intent(kind: str) -> Dict[str, Any]:
    return {
        "operator": _patch_operator(kind),
        "primary_goal": _missing_property(kind),
        "must_dominate_sink": kind != "free_or_lifetime_transition",
        "valid_path_rule": _valid_path_preservation({"kind": kind}),
    }


def _unsafe_paths_from_risks(
    risks: List[dict],
    *,
    func_code: str,
    replacement_target: Dict[str, Any],
    project_terms: Dict[str, List[str]],
) -> List[dict]:
    lines = (func_code or "").splitlines()
    start_line = _replacement_start_line(replacement_target)
    paths = []
    for idx, risk in enumerate(risks or [], start=1):
        line = _safe_int(risk.get("line"))
        local_index = max(0, line - start_line)
        path = {
            "id": f"unsafe_path_{idx}",
            "source_risk_id": risk.get("id"),
            "sink": {
                "kind": risk.get("kind"),
                "line": line,
                "code": risk.get("sink_code"),
                "symbols": _first(risk.get("input_controlled_values"), 10),
                "provider": risk.get("provider"),
            },
            "data_state_before_sink": _data_state_before_sink(risk),
            "existing_guards": _guard_facts(
                risk.get("existing_guards") or [],
                sink_line=line,
                missing_property=risk.get("missing_property"),
                sink_symbols=risk.get("input_controlled_values") or [],
            ),
            "cleanup_obligations": _cleanup_obligations_near(
                lines,
                local_index=local_index,
                start_line=start_line,
                project_terms=project_terms,
            ),
            "recommended_patch_site": _recommended_patch_site(risk),
            "fail_closed_expectation": _fail_closed_expectation(risk, lines, local_index),
            "valid_path_preservation": _valid_path_preservation(risk),
            "wrong_fix_trap": risk.get("wrong_fix_trap"),
            "confidence": risk.get("confidence") or "medium",
        }
        paths.append(path)
    return paths[:MAX_UNSAFE_PATHS]


def _data_state_before_sink(risk: Dict[str, Any]) -> Dict[str, Any]:
    kind = str(risk.get("kind") or "")
    values = [str(item) for item in risk.get("input_controlled_values") or [] if item]
    code = str(risk.get("sink_code") or "")
    pointer_terms = [
        value for value in values
        if _POINTER_SYMBOL_RE.search(value)
    ]
    size_terms = [
        value for value in values
        if _SIZE_SYMBOL_RE.search(value)
    ]
    typed_facts = _typed_buffer_facts(values, code)
    pointer_state = []
    size_state = []
    capacity_facts = []
    if kind in {"pointer_index_or_deref", "pointer_or_member_deref", "array_access"}:
        pointer_state.append("pointer/object/index is consumed at the sink")
        if pointer_terms:
            pointer_state.append("pointer-like values involved: " + ", ".join(_dedup(pointer_terms)[:5]))
    if kind in {"buffer_or_memory_call", "allocation_or_size_call", "length_controlled_loop", "pointer_or_offset_advance"}:
        size_state.append("length/offset/capacity arithmetic feeds the sink")
    if size_terms:
        size_state.append("size-like values involved: " + ", ".join(_dedup(size_terms)[:6]))
    if re.search(r"\b(memcpy|memmove|memcmp|memset|strcpy|strncpy|read|write)\s*\(", code):
        capacity_facts.append("memory-call source availability and destination capacity must be proven before call")
    if re.search(r"\b(?:end|remaining|avail|capacity|cap)\w*\b", code, re.IGNORECASE):
        capacity_facts.append("target code exposes remaining/end/capacity-like terms near the sink")
    if typed_facts.get("capacity_symbols") or typed_facts.get("remaining_symbols"):
        capacity_facts.append(
            "typed capacity/remaining symbols: "
            + ", ".join(_first(typed_facts.get("capacity_symbols") + typed_facts.get("remaining_symbols"), 6))
        )
    if typed_facts.get("needed_symbols"):
        size_state.append("needed/consumed size symbols: " + ", ".join(_first(typed_facts.get("needed_symbols"), 6)))
    if not pointer_state:
        pointer_state.append("pointer validity is unknown before this sink")
    if not size_state:
        size_state.append("available byte/object count is unknown before this sink")
    if not capacity_facts:
        capacity_facts.append("physical buffer capacity is not proven by the detected guard facts")
    return {
        "pointer_state": pointer_state[:5],
        "size_state": size_state[:5],
        "buffer_capacity_facts": capacity_facts[:5],
        "typed_buffer_facts": typed_facts,
    }


def _typed_buffer_facts(values: List[str], code: str) -> Dict[str, List[str]]:
    identifiers = _dedup([
        *values,
        *re.findall(r"\b[A-Za-z_]\w*\b", code or ""),
    ])
    return {
        "pointer_symbols": _first([item for item in identifiers if _POINTER_SYMBOL_RE.search(item)], 8),
        "capacity_symbols": _first([item for item in identifiers if _CAPACITY_SYMBOL_RE.search(item)], 8),
        "remaining_symbols": _first([item for item in identifiers if _REMAINING_SYMBOL_RE.search(item)], 8),
        "consumed_symbols": _first([item for item in identifiers if _CONSUMED_SYMBOL_RE.search(item)], 8),
        "needed_symbols": _first([item for item in identifiers if _NEEDED_SYMBOL_RE.search(item)], 8),
    }


def _guard_facts(guards: List[Any], *, sink_line: int, missing_property: str, sink_symbols: List[str]) -> List[dict]:
    out = []
    for idx, guard in enumerate(guards or [], start=1):
        fact = _normalize_guard_context(guard)
        code = str(fact.get("code") or "").strip()
        if not code:
            continue
        line = _safe_int(fact.get("line")) or None
        covers = _guard_covers_sink(code, missing_property, sink_symbols)
        out.append(
            {
                "id": f"guard_{idx}",
                "line": line,
                "code": _clip(code, 220),
                "source": fact.get("source") or "nearby_guard",
                "dominates_sink": _dominates_sink(line, sink_line),
                "covers_sink": covers,
                "missing": "" if covers else _clip(missing_property, 220),
            }
        )
    if not out:
        out.append(
            {
                "id": "guard_missing",
                "line": None,
                "code": "",
                "source": "none",
                "dominates_sink": False,
                "covers_sink": False,
                "missing": _clip(missing_property or "no dominating guard was detected before the sink", 220),
            }
        )
    return out[:5]


def _cleanup_obligations_near(
    lines: List[str],
    *,
    local_index: int,
    start_line: int,
    project_terms: Dict[str, List[str]],
) -> List[dict]:
    out = []
    label_blocks = _cleanup_label_blocks(lines, project_terms, start_line=start_line)
    window_start = max(0, local_index - 10)
    window = lines[window_start:min(len(lines), local_index + 12)]
    for offset, line in enumerate(window, start=window_start):
        stripped = line.strip()
        if not stripped:
            continue
        goto_match = re.search(r"\bgoto\s+([A-Za-z_]\w*)\s*;", stripped)
        if goto_match:
            label = goto_match.group(1)
            block = label_blocks.get(label) or {}
            cleanup_call = _clip(stripped, 220)
            evidence = "nearby goto-based fail-closed path"
            resource = "error_path"
            if block:
                cleanup_call = _clip(stripped + " -> " + (block.get("summary") or ""), 260)
                evidence = "goto resolves to local cleanup/error label"
                resource = block.get("resource") or resource
            out.append(
                {
                    "resource": resource,
                    "required_on_fail_closed": True,
                    "cleanup_call": cleanup_call,
                    "evidence": evidence,
                    "label": label,
                    "label_line": block.get("line"),
                }
            )
        elif _is_cleanup_call(stripped, project_terms):
            out.append(
                {
                    "resource": _clip(_cleanup_resource_hint(stripped), 80),
                    "required_on_fail_closed": True,
                    "cleanup_call": _clip(stripped, 220),
                    "evidence": "nearby cleanup/release call in target function",
                    "line": start_line + offset,
                }
            )
    if not out:
        out.append(
            {
                "resource": "unknown",
                "required_on_fail_closed": "unknown",
                "cleanup_call": "",
                "evidence": "no nearby cleanup call detected; preserve existing error path if adding early return",
            }
        )
    return out[:5]


def _cleanup_label_blocks(lines: List[str], project_terms: Dict[str, List[str]], *, start_line: int) -> Dict[str, dict]:
    out: Dict[str, dict] = {}
    label_re = re.compile(r"^\s*([A-Za-z_]\w*)\s*:\s*(?:/\*.*\*/)?\s*$")
    for index, line in enumerate(lines or []):
        match = label_re.match(line or "")
        if not match:
            continue
        label = match.group(1)
        block_lines = []
        cleanup_calls = []
        for next_index in range(index + 1, min(len(lines), index + 18)):
            stripped = (lines[next_index] or "").strip()
            if not stripped:
                continue
            if label_re.match(stripped):
                break
            block_lines.append(stripped)
            if _is_cleanup_call(stripped, project_terms):
                cleanup_calls.append(stripped)
            if re.search(r"\b(?:return|goto)\b", stripped):
                break
        if not block_lines:
            continue
        summary = label + ": " + " ".join(block_lines[:5])
        out[label] = {
            "label": label,
            "line": start_line + index,
            "cleanup_calls": [_clip(item, 180) for item in cleanup_calls[:4]],
            "resource": _clip(_cleanup_resource_hint(cleanup_calls[0]), 80) if cleanup_calls else "error_path",
            "summary": _clip(summary, 260),
        }
    return out


def _is_cleanup_call(line: str, project_terms: Dict[str, List[str]]) -> bool:
    return _line_calls_any_symbol(line, project_terms.get("ownership_symbols")) or bool(
        re.search(
            r"\b(free|delete|destroy|destruct|release|cleanup|close)\w*\s*\(",
            line or "",
            re.IGNORECASE,
        )
    )


def _cleanup_resource_hint(code: str) -> str:
    match = re.search(r"\b[A-Za-z_]\w*\s*\(([^)]{0,120})\)", code or "")
    if not match:
        return "resource"
    args = [part.strip() for part in match.group(1).split(",") if part.strip()]
    return args[0] if args else "resource"


def _recommended_patch_site(risk: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "line": risk.get("line"),
        "kind": _patch_operator(risk.get("kind")),
        "before_sink": True,
        "dominance_requirement": risk.get("dominance_requirement"),
        "required_property": risk.get("missing_property"),
        "operator": risk.get("suggested_patch_operator"),
    }


def _fail_closed_expectation(risk: Dict[str, Any], lines: List[str], local_index: int) -> str:
    window = "\n".join(lines[max(0, local_index - 8):min(len(lines), local_index + 8)])
    goto_labels = re.findall(r"\bgoto\s+([A-Za-z_]\w*)\s*;", window)
    if goto_labels:
        return "reject malformed input by following existing goto/error path: " + ", ".join(_dedup(goto_labels)[:3])
    if re.search(r"\breturn\s+[-A-Za-z_0-9]+\s*;", window):
        return "reject malformed input using the existing local error-return convention"
    if risk.get("kind") == "free_or_lifetime_transition":
        return "fail closed without duplicating or skipping ownership/release transitions"
    return "reject only malformed input before the sink and do not consume/advance data first"


def _valid_path_preservation(risk: Dict[str, Any]) -> str:
    kind = risk.get("kind")
    if kind in {"pointer_or_offset_advance", "length_controlled_loop"}:
        return "valid inputs with sufficient remaining length must keep the same pointer/offset progression"
    if kind == "buffer_or_memory_call":
        return "valid inputs with proven source/destination bounds must keep the same copy/read/write behavior"
    if kind == "free_or_lifetime_transition":
        return "valid ownership/lifetime path must release or transfer each resource exactly once"
    return "valid inputs that satisfy the required guard must continue through the original behavior"


def _risk_code_key(value: Any) -> str:
    text = re.sub(r"\s+", " ", str(value or "").strip())
    return text.rstrip(";")


def _context_requests(paths: List[dict], failure_contract: Dict[str, Any]) -> List[dict]:
    out = []
    for path in paths[:6]:
        sink = path.get("sink") or {}
        patch_site = path.get("recommended_patch_site") or {}
        out.append(
            {
                "unsafe_path_id": path.get("id"),
                "kind": sink.get("kind"),
                "line": sink.get("line"),
                "request": patch_site.get("required_property") or "retrieve project-local guard/fail-closed convention for this sink",
                "symbols": sink.get("symbols") or [],
            }
        )
    if "bounds_or_size" in set(failure_contract.get("categories") or []):
        out.append({"kind": "project_idiom", "request": "retrieve bounds-check and fail-closed macros/helpers used near this parser"})
    if "lifetime_or_ownership" in set(failure_contract.get("categories") or []):
        out.append({"kind": "project_idiom", "request": "retrieve ownership/refcount/destructor conventions for visible project-local symbols"})
    return out[:8]


def _path_summary(paths: List[dict], failure_contract: Dict[str, Any]) -> dict:
    kinds: Dict[str, int] = {}
    operators: Dict[str, int] = {}
    for path in paths or []:
        sink = path.get("sink") or {}
        patch_site = path.get("recommended_patch_site") or {}
        kind = str(sink.get("kind") or "unknown")
        operator = str(patch_site.get("operator") or patch_site.get("kind") or "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
        operators[operator] = operators.get(operator, 0) + 1
    return {
        "unsafe_path_count": len(paths or []),
        "sink_kinds": kinds,
        "patch_operators": operators,
        "failure_categories": failure_contract.get("categories") or [],
        "interpretation": "unsafe path facts; select one path and make its sink unreachable on malformed input",
    }


def _related_context_hints(context: Dict[str, Any], project_terms: Dict[str, List[str]]) -> Dict[str, Any]:
    scope = context.get("scope_aware_symbol_contract") or {}
    contract = context.get("contract_brief") or {}
    ranked = context.get("ranked_context") or {}
    return {
        "introducible_functions": _first(scope.get("introducible_functions"), 12),
        "introducible_macros_or_enum_constants": _first(
            scope.get("introducible_macros_or_enum_constants"),
            16,
        ),
        "introducible_types": _first(scope.get("introducible_types"), 10),
        "risky_unqualified_helpers": _first(scope.get("risky_unqualified_helpers"), 10),
        "high_priority_contract_groups": [
            {
                "kind": item.get("kind"),
                "summary": item.get("policy") or item.get("name") or item.get("expression"),
                "allowed_constants": _first(item.get("allowed_constants") or item.get("constants"), 10),
            }
            for item in _first(contract.get("high_priority_contract_groups"), 6)
            if isinstance(item, dict)
        ],
        "must_read_context": [
            {
                "type": item.get("type"),
                "kind": item.get("kind"),
                "symbol": item.get("symbol"),
                "summary": item.get("summary"),
            }
            for item in _first(ranked.get("must_read"), 6)
            if isinstance(item, dict)
        ],
        "observed_security_idioms": _compact_project_terms(project_terms),
    }


def _risk_summary(risks: List[dict], failure_contract: Dict[str, Any]) -> dict:
    kinds: Dict[str, int] = {}
    for risk in risks or []:
        kind = str(risk.get("kind") or "unknown")
        kinds[kind] = kinds.get(kind, 0) + 1
    return {
        "risk_count": len(risks or []),
        "risk_kinds": kinds,
        "failure_categories": failure_contract.get("categories") or [],
        "interpretation": "compatibility hazard list; prefer unsafe_paths for repair planning",
    }


def _wrong_fix_risks(
    risks: List[dict],
    related_code_context: Dict[str, Any],
    failure_contract: Dict[str, Any],
    project_terms: Dict[str, List[str]],
) -> List[dict]:
    out = []
    output_symbols = _first(project_terms.get("output_symbols"), 8)
    if output_symbols:
        out.append(
            {
                "kind": "output_only_patch",
                "warning": "Changing only observed output/formatting helpers does not fix an unsafe access.",
                "avoid_when": "the failing oracle is bounds, crash, short input, sanitizer, or malformed input",
                "observed_symbols": output_symbols,
            }
        )
    guard_symbols = _first(project_terms.get("guard_symbols"), 8)
    if guard_symbols:
        out.append(
            {
                "kind": "observed_guard_idiom_misuse",
                "warning": "When adding observed guard/check helpers, follow existing call shapes and fail-closed behavior from related context.",
                "avoid_when": "the patch invents new argument forms or moves validation after consumption",
                "observed_symbols": guard_symbols,
            }
        )
    out.append(
        {
            "kind": "broad_rewrite",
            "warning": "Do not reformat or rewrite a long parser/printer function; make the smallest guard or length-flow change that preserves valid-input behavior.",
            "avoid_when": "target replacement unit is large or has many existing validation guards",
        }
    )
    if any(risk.get("kind") == "free_or_lifetime_transition" for risk in risks or []):
        out.append(
            {
                "kind": "cleanup_order_change",
                "warning": "Do not skip, duplicate, or reorder cleanup/release calls unless the ownership contract proves it.",
                "avoid_when": "the failure involves lifetime, refcount, destructor, or cleanup paths",
            }
        )
    scope = (related_code_context or {}).get("scope_aware_symbol_contract") or {}
    risky_helpers = _first(scope.get("risky_unqualified_helpers"), 8)
    if risky_helpers:
        out.append(
            {
                "kind": "invented_helper_call",
                "warning": "Do not introduce helpers that are only visible but not introducible.",
                "examples": risky_helpers,
            }
        )
    return out[:8]


def _risk_constraints(
    related_code_context: Dict[str, Any],
    failure_contract: Dict[str, Any],
    project_terms: Dict[str, List[str]],
) -> List[str]:
    constraints = [
        "Unsafe path brief records sink/state/guard/cleanup facts; FixAgent must select the path supported by failure evidence.",
        "Preserve valid-input output and existing fail-closed/error conventions.",
        "Avoid output-only, logging-only, formatting-only, or broad rewrite patches for memory-safety failures.",
    ]
    guard_symbols = _first(project_terms.get("guard_symbols"), 8)
    if guard_symbols:
        constraints.append(
            "Use observed guard/check idioms exactly as shown in related context: "
            + ", ".join(guard_symbols)
        )
    if "bounds_or_size" in set((failure_contract or {}).get("categories") or []):
        constraints.append("Bounds fixes must validate available packet bytes before dereference, extraction, memcpy/memmove, or pointer advancement.")
    contract = (related_code_context or {}).get("contract_brief") or {}
    for item in _first(contract.get("contract_policy"), 3):
        constraints.append(str(item))
    return _dedup(constraints)[:10]


def _why_risky(risk: Dict[str, Any], failure_contract: Dict[str, Any]) -> str:
    kind = risk.get("kind")
    base = _missing_property(kind)
    categories = ", ".join(str(item) for item in (failure_contract or {}).get("categories") or [])
    if categories:
        return f"{base}; relevant to failure categories: {categories}"
    return base


def _wrong_fix_trap(risk: Dict[str, Any], project_terms: Dict[str, List[str]]) -> str:
    kind = risk.get("kind")
    code = str(risk.get("sink_code") or "")
    if _line_calls_any_symbol(code, project_terms.get("output_symbols")):
        return "Do not fix by changing only printed text or formatting."
    if kind == "project_bounds_or_extract_operation":
        return "Do not invent guard/extraction helper usage; follow observed project-local idioms."
    if kind in {"pointer_or_offset_advance", "length_controlled_loop"}:
        return "Do not advance pointer/offset first and check later."
    if kind == "buffer_or_memory_call":
        return "Do not change copied output size without proving source and destination bounds."
    return "Do not treat this hazard as proof that the exact line is the edit location."


def _safe_repair_expectation(risk: Dict[str, Any]) -> str:
    kind = risk.get("kind")
    if kind == "project_bounds_or_extract_operation":
        return "Follow nearby guard/extraction and fail-closed conventions exactly."
    if kind in {"pointer_or_offset_advance", "length_controlled_loop"}:
        return "Guard remaining bytes/length before consuming or advancing."
    if kind == "buffer_or_memory_call":
        return "Ensure source availability and destination capacity before the memory call."
    if kind == "free_or_lifetime_transition":
        return "Preserve ownership/refcount transitions and cleanup ordering."
    return "Add the smallest fail-closed guard that preserves valid-path behavior."


def _missing_property(kind: str) -> str:
    return {
        "array_access": "index and container bounds are established before access",
        "pointer_index_or_deref": "pointer validity and available object/packet bytes are established before use",
        "pointer_or_member_deref": "pointer validity, lifetime, and available bytes are established before dereference",
        "buffer_or_memory_call": "source/destination sizes and available bytes are checked before the memory call",
        "allocation_or_size_call": "allocation size arithmetic cannot overflow and matches the consumed input size",
        "free_or_lifetime_transition": "object/resource ownership is transferred or released exactly once",
        "project_bounds_or_extract_operation": "input extraction follows project-local bounds-check and error convention",
        "pointer_or_offset_advance": "pointer/offset advances only after bounds validation and remaining-size accounting",
        "length_controlled_loop": "loop consumption cannot exceed remaining bytes and terminates on malformed lengths",
        "error_or_cleanup_transition": "invalid input fails closed without skipping required cleanup",
        "parse_or_validation_operation": "validation rejects malformed input before unsafe consumption",
    }.get(kind, "unsafe operation is guarded before it executes")


def _dominance_requirement(kind: str) -> str:
    if kind == "free_or_lifetime_transition":
        return "ownership/refcount state must be validated before release, overwrite, or destructor path"
    if kind in {"error_or_cleanup_transition", "parse_or_validation_operation"}:
        return "error/truncation branch must dominate the unsafe continuation on malformed input"
    return "new or strengthened guard must execute before the risky sink on the failing path"


def _patch_operator(kind: str) -> str:
    if kind == "free_or_lifetime_transition":
        return "lifetime_or_refcount_fix"
    if kind == "allocation_or_size_call":
        return "fix_allocation_size_arithmetic"
    if kind in {"pointer_or_offset_advance", "length_controlled_loop"}:
        return "fix_length_or_remaining_size_flow"
    if kind in {"error_or_cleanup_transition", "parse_or_validation_operation"}:
        return "refine_fail_closed_branch"
    return "add_or_strengthen_dominating_guard"


def _required_related_context(kind: str, symbols: List[str]) -> str:
    if kind == "project_bounds_or_extract_operation":
        return "bounds-check, extraction, and fail-closed idioms for observed project-local helpers"
    if kind == "free_or_lifetime_transition":
        return "ownership/refcount/destructor contracts for visible project-local symbols"
    if kind == "allocation_or_size_call":
        return "safe allocation helpers and size arithmetic conventions"
    if symbols:
        return "contracts or usage examples for " + ", ".join(_dedup(symbols)[:5])
    return "project-local guard, cleanup, and error conventions near the target function"


def _risk_values(code: str, symbols: List[str]) -> List[str]:
    candidates = []
    candidates.extend(symbols or [])
    candidates.extend(re.findall(r"\b(?:len|length|size|count|off|offset|alen|tlen|tlv|remaining|ptr|end|p|ep)\w*\b", code or "", re.IGNORECASE))
    return _dedup(candidates)[:10]


def _call_shape(code: str) -> Tuple[str, List[str]]:
    match = re.search(r"\b([A-Za-z_]\w*)\s*\((.*)\)", str(code or ""))
    if not match:
        return "", []
    call_name = match.group(1)
    args = _split_call_args(match.group(2))
    return call_name, args


def _split_call_args(text: str) -> List[str]:
    args = []
    cur = []
    depth = 0
    for char in str(text or ""):
        if char == "," and depth == 0:
            arg = "".join(cur).strip()
            if arg:
                args.append(_clip(arg, 120))
            cur = []
            continue
        cur.append(char)
        if char in "([{":
            depth += 1
        elif char in ")]}" and depth > 0:
            depth -= 1
    arg = "".join(cur).strip()
    if arg:
        args.append(_clip(arg, 120))
    return args[:8]


def _operation_guard_context(operation: Dict[str, Any]) -> List[dict]:
    out = []
    for item in operation.get("control_ancestors") or []:
        if not isinstance(item, dict) or not item.get("code"):
            continue
        out.append(
            {
                "kind": item.get("kind") or "control_ancestor",
                "line": _safe_int(item.get("line")) or None,
                "code": _clip(item.get("code"), 220),
                "source": "control_ancestor",
            }
        )
    return out[:6]


def _compact_guard_context(guards: List[Any]) -> List[dict]:
    out = []
    for guard in guards or []:
        fact = _normalize_guard_context(guard)
        if not fact.get("code"):
            continue
        out.append(fact)
    return out[:6]


def _merge_guard_context(left: List[Any], right: List[Any]) -> List[dict]:
    out = []
    seen = set()
    for guard in [*(left or []), *(right or [])]:
        fact = _normalize_guard_context(guard)
        code = str(fact.get("code") or "")
        if not code:
            continue
        key = (fact.get("line"), code)
        if key in seen:
            continue
        seen.add(key)
        out.append(fact)
    return out[:6]


def _normalize_guard_context(guard: Any) -> dict:
    if isinstance(guard, dict):
        return {
            "kind": guard.get("kind") or "guard",
            "line": _safe_int(guard.get("line")) or None,
            "code": _clip(guard.get("code"), 220),
            "source": guard.get("source") or "program_analysis",
        }
    return {
        "kind": "guard",
        "line": None,
        "code": _clip(guard, 220),
        "source": "legacy_string",
    }


def _guard_context(lines: List[str], index: int, project_terms: Dict[str, List[str]], *, start_line: int) -> List[dict]:
    out = []
    window_start = max(0, index - 4)
    for local_line, line in enumerate(lines[window_start:index + 1], start=window_start):
        stripped = line.strip()
        if re.search(r"\b(if|assert|goto\s+\w+|return)\b", stripped) or _line_calls_any_symbol(stripped, project_terms.get("guard_symbols")):
            out.append(
                {
                    "kind": "nearby_guard",
                    "line": start_line + local_line,
                    "code": _clip(stripped, 220),
                    "source": "source_nearby",
                }
            )
    return out[-4:]


def _dominates_sink(guard_line: Optional[int], sink_line: int) -> Any:
    if not sink_line:
        return "unknown"
    if guard_line is None:
        return "unknown"
    return bool(guard_line <= sink_line)


def _guard_covers_sink(code: str, missing_property: str, sink_symbols: List[str]) -> bool:
    text = str(code or "")
    lower_missing = str(missing_property or "").lower()
    mentions_sink_symbol = any(
        symbol and re.search(r"\b" + re.escape(str(symbol)) + r"\b", text)
        for symbol in _first(sink_symbols, 8)
    )
    has_bound_operator = bool(_BOUND_OPERATOR_RE.search(text))
    has_pointer_guard = bool(re.search(r"(?:!\s*[A-Za-z_]\w+|[A-Za-z_]\w+\s*(?:==|!=)\s*NULL|nullptr|0)", text))
    if any(word in lower_missing for word in ("source", "destination", "available", "bytes", "bounds", "size", "allocation", "loop")):
        return mentions_sink_symbol and has_bound_operator
    if any(word in lower_missing for word in ("pointer", "lifetime", "ownership", "resource")):
        return mentions_sink_symbol and (has_pointer_guard or has_bound_operator)
    return mentions_sink_symbol and (has_bound_operator or has_pointer_guard)


def _signal_lines(text: str) -> List[str]:
    signal = re.compile(r"asan|ubsan|fail|failed|crash|segmentation|overflow|underflow|truncated|short packet|double-free|use-after-free|expected|actual", re.IGNORECASE)
    out = []
    for line in str(text or "").splitlines():
        stripped = line.strip()
        if stripped and signal.search(stripped):
            out.append(_clip(stripped, 240))
        if len(out) >= 12:
            break
    return out


def _risk_uncertainties(risks: List[dict]) -> List[str]:
    if not risks:
        return ["no_risky_operations_detected_by_heuristics"]
    return ["risk_brief_is_unordered; FixAgent must inspect failure evidence and full target unit"]


def _path_uncertainties(paths: List[dict]) -> List[str]:
    if not paths:
        return ["no_unsafe_paths_detected_by_heuristics"]
    notes = ["unsafe_paths_are_static_facts; FixAgent must verify path against failure evidence and full target unit"]
    if any((path.get("cleanup_obligations") or [{}])[0].get("resource") == "unknown" for path in paths or []):
        notes.append("some unsafe_paths have unknown cleanup obligations; preserve existing error path when failing closed")
    return notes[:4]


def _source_file(replacement_target: Dict[str, Any], source_path: str) -> str:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    identity = (replacement_target or {}).get("replacement_identity") or {}
    return str(envelope.get("source_file") or envelope.get("source_path") or identity.get("source_path") or source_path or "")


def _replacement_start_line(replacement_target: Dict[str, Any]) -> int:
    try:
        return int((((replacement_target or {}).get("replacement_envelope") or {}).get("replacement_range") or {}).get("start_line") or 1)
    except Exception:
        return 1


def _symbols_from_line(line: str) -> List[str]:
    return _dedup(re.findall(r"\b[A-Za-z_]\w*\b", line or ""))[:12]


def _first_match(text: str, pairs: List[Tuple[str, str]]) -> str:
    for label, pattern in pairs:
        if re.search(pattern, text or "", re.IGNORECASE):
            return label
    return ""


def _safe_int(value: Any) -> int:
    try:
        return int(value)
    except Exception:
        return 0


def _dedup(values: List[Any]) -> List[str]:
    out = []
    seen = set()
    for value in values or []:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _first(value: Any, limit: int) -> List[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value[:limit]
    if isinstance(value, tuple):
        return list(value[:limit])
    return [value]


def _clip(value: Any, max_chars: int = MAX_TEXT) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"
