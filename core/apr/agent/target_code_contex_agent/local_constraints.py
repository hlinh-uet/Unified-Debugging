import re
from typing import Any, Dict, List, Optional

from core.apr.agent.context_common import (
    clip_text,
    constructor_initializer_names,
    dedup_keep_order,
    line_number_for_byte,
)

from .support import (
    _compact_dependency,
    _compact_region,
    _compact_statement,
    _has_any_signal,
    _looks_error_sentinel_return,
    _looks_success_default_return,
    _nearest_preceding_branch,
    _signature_range,
    MAX_REPAIR_SITES,
)
from .failure_localization import _backward_dependencies, _forward_impacts

# Stage 5: suy ra invariant, contract cục bộ và edit scope từ target-local evidence.
def infer_local_contracts(
    *,
    target_spec: Dict[str, Any],
    function_ir: Dict[str, Any],
    failure_localization: Dict[str, Any],
    source_code: str,
) -> Dict[str, Any]:
    replacement_unit = target_spec.get("replacement_unit") or ""
    statements = function_ir.get("statement_inventory") or []
    analysis = function_ir.get("analysis") or {}
    failure_contract = failure_localization.get("failure_contract") or {}
    ranked_repair_sites = failure_localization.get("ranked_repair_sites") or []
    advanced_intra_function_analysis = _advanced_intra_function_analysis(
        replacement_unit=replacement_unit,
        func_name=(target_spec.get("target_envelope") or {}).get("resolved_function_name") or "",
        statements=statements,
        analysis=analysis,
        failure_contract=failure_contract,
        ranked_repair_sites=ranked_repair_sites,
    )
    semantic_repair_contracts = _semantic_repair_contracts(
        replacement_unit=replacement_unit,
        statements=statements,
        failure_contract=failure_contract,
        advanced_analysis=advanced_intra_function_analysis,
    )
    semantic_invariants = _semantic_invariants(
        statements=statements,
        analysis=analysis,
        failure_contract=failure_contract,
        ranked_repair_sites=ranked_repair_sites,
        advanced_analysis=advanced_intra_function_analysis,
        semantic_repair_contracts=semantic_repair_contracts,
    )
    local_contracts = _local_behavioral_contracts(
        replacement_unit,
        statements,
        analysis=analysis,
        ranked_repair_sites=ranked_repair_sites,
        advanced_analysis=advanced_intra_function_analysis,
    )
    edit_scope = _edit_scope(
        replacement_unit=replacement_unit,
        replacement_start=int(target_spec.get("replacement_start") or 0),
        replacement_end=int(target_spec.get("replacement_end") or 0),
        source_code=source_code,
        ranked_repair_sites=ranked_repair_sites,
    )
    return {
        "advanced_intra_function_analysis": advanced_intra_function_analysis,
        "semantic_repair_contracts": semantic_repair_contracts,
        "semantic_invariants": semantic_invariants,
        "local_behavioral_contracts": local_contracts,
        "edit_scope": edit_scope,
        "local_constraints": {
            "advanced_intra_function_analysis": advanced_intra_function_analysis,
            "semantic_repair_contracts": semantic_repair_contracts,
            "semantic_invariants": semantic_invariants,
            "local_behavioral_contracts": local_contracts,
            "edit_scope": edit_scope,
        },
    }

# Bổ sung slice nâng cao cho numeric range, tail processing, duration và member initializer.
def _advanced_intra_function_analysis(
    *,
    replacement_unit: str,
    func_name: str,
    statements: List[dict],
    analysis: Dict[str, Any],
    failure_contract: Dict[str, Any],
    ranked_repair_sites: List[dict],
) -> Dict[str, Any]:
    profile_terms = set(str(item).lower() for item in (failure_contract.get("high_value_terms") or []))
    categories = set(failure_contract.get("categories") or [])
    numeric_needed = bool(
        profile_terms & {"digit", "carry", "overflow", "rounding", "precision", "num_digits"}
        or any(_has_any_signal(statement, {"numeric_value_flow"}) for statement in statements)
        and "output_or_return_mismatch" in categories
    )
    tail_needed = bool(
        profile_terms & {"remaining", "leftover", "num_chars_left", "transcode", "size"}
        or "bounds_or_size" in categories
    )
    chrono_needed = bool(
        profile_terms & {"negative", "duration", "seconds", "milliseconds", "to_unsigned"}
        or "duration" in replacement_unit.lower()
        or "chrono" in replacement_unit.lower()
    )

    numeric_slices = _advanced_signal_slices(
        statements=statements,
        signal="numeric_value_flow",
        term_pattern=r"\b(digit|digits|num_digits|carry|overflow|round|rounding|precision|numerator|denominator|divmod|to_unsigned)\b",
        reason="numeric digit/carry/range flow that can corrupt observable numeric output",
    ) if numeric_needed else []
    tail_slices = _advanced_signal_slices(
        statements=statements,
        signal="tail_or_leftover_processing",
        term_pattern=r"\b(leftover|remaining|num_chars_left|chars_left|bytes_left|left|tail|memcpy|memmove|transcode|decode|encode|utf|size\s*\(\s*\))\b",
        reason="tail/leftover processing that can truncate valid data",
    ) if tail_needed else []
    chrono_slices = _advanced_signal_slices(
        statements=statements,
        signal="chrono_duration_flow",
        term_pattern=r"\b(duration|seconds|milliseconds|chrono|count|negative|to_unsigned)\b",
        reason="chrono duration/sign conversion flow",
    ) if chrono_needed else []
    constructor_usage = _constructor_member_usage(
        replacement_unit=replacement_unit,
        func_name=func_name,
    )

    inferred_invariants = []
    if numeric_slices:
        inferred_invariants.append(
            {
                "kind": "numeric_digit_range",
                "strength": "medium",
                "summary": "Digit-like values written as characters should stay in the valid digit range or be immediately normalized by carry propagation.",
                "evidence": [_compact_advanced_slice(item) for item in numeric_slices[:3]],
            }
        )
    if tail_slices:
        inferred_invariants.append(
            {
                "kind": "tail_data_consumption",
                "strength": "medium",
                "summary": "Remaining/tail input bytes should be consumed according to the same decoder/transcode contract as the main loop, not silently dropped.",
                "evidence": [_compact_advanced_slice(item) for item in tail_slices[:3]],
            }
        )
    if chrono_slices:
        inferred_invariants.append(
            {
                "kind": "duration_sign_and_unit_consistency",
                "strength": "medium",
                "summary": "Duration count, seconds, and sub-second fields should preserve a consistent sign/unit convention before unsigned conversion or formatting.",
                "evidence": [_compact_advanced_slice(item) for item in chrono_slices[:3]],
            }
        )
    if constructor_usage.get("initializer_names"):
        inferred_invariants.append(
            {
                "kind": "constructor_member_initializer_shape",
                "strength": "hard",
                "summary": "Constructor initializer list should only initialize existing class fields and should not invent new member state.",
                "evidence": [constructor_usage],
            }
        )

    return {
        "numeric_range_slices": numeric_slices[:6],
        "tail_processing_slices": tail_slices[:6],
        "chrono_duration_slices": chrono_slices[:6],
        "class_member_usage": constructor_usage,
        "inferred_invariants": inferred_invariants[:8],
        "ranked_site_overlap": _advanced_site_overlap(
            ranked_repair_sites=ranked_repair_sites,
            advanced_slices=numeric_slices + tail_slices + chrono_slices,
        ),
        "analysis_notes": [
            "Advanced slices are deterministic hints; they should refine, not replace, failure_slices and ranked_repair_sites.",
            "Use these slices to avoid plausible local edits that violate numeric range, tail consumption, or member initializer invariants.",
        ],
    }

# Tạo slice quanh các statement có signal nâng cao và truy vết dependency hai chiều.
def _advanced_signal_slices(
    *,
    statements: List[dict],
    signal: str,
    term_pattern: str,
    reason: str,
) -> List[dict]:
    selected = []
    pattern = re.compile(term_pattern, re.IGNORECASE)
    for statement in statements:
        text = str(statement.get("text") or "")
        if signal not in (statement.get("signals") or []) and not pattern.search(text):
            continue
        variables = _signal_slice_variables(statement, pattern)
        selected.append(
            {
                "seed_statement": _compact_statement(statement, include_facts=True),
                "reason": reason,
                "relevant_variables": variables[:12],
                "backward_dependencies": [
                    _compact_dependency(item)
                    for item in _backward_dependencies(statement, statements, variables)[:5]
                ],
                "forward_impacts": [
                    _compact_dependency(item)
                    for item in _forward_impacts(statement, statements, variables)[:5]
                ],
            }
        )
        if len(selected) >= 8:
            break
    return selected

# Chọn biến/call liên quan nhất để mở rộng một advanced slice.
def _signal_slice_variables(statement: dict, pattern) -> List[str]:
    variables = []
    for value in (statement.get("reads") or []) + (statement.get("writes") or []) + (statement.get("calls") or []):
        text = str(value or "")
        if pattern.search(text):
            variables.append(text)
    if not variables:
        variables = (statement.get("reads") or []) + (statement.get("writes") or [])
    return dedup_keep_order(variables)[:12]

# Trích thông tin constructor initializer và member access để tránh sinh field không tồn tại.
def _constructor_member_usage(
    *,
    replacement_unit: str,
    func_name: str,
) -> Dict[str, Any]:
    initializers = constructor_initializer_names(replacement_unit)
    member_accesses = dedup_keep_order(
        re.findall(r"(?:this\s*->|[A-Za-z_]\w*\s*(?:->|\.))\s*([A-Za-z_]\w*)", replacement_unit or "")
    )
    return {
        "function_name": func_name,
        "constructor_like": bool(initializers),
        "initializer_names": initializers,
        "member_accesses": member_accesses[:80],
        "policy": "Do not add initializer/member names that are not visible in RelatedCodeContext member_field_inventory.",
    }

# Rút gọn advanced slice thành evidence ngắn cho invariant.
def _compact_advanced_slice(item: dict) -> dict:
    seed = item.get("seed_statement") or {}
    return {
        "line": seed.get("line"),
        "statement": seed.get("text"),
        "relevant_variables": item.get("relevant_variables") or [],
        "reason": item.get("reason"),
    }

# Kiểm tra advanced slice có trùng với ranked repair site hay không.
def _advanced_site_overlap(
    *,
    ranked_repair_sites: List[dict],
    advanced_slices: List[dict],
) -> List[dict]:
    overlaps = []
    for site in ranked_repair_sites[:MAX_REPAIR_SITES]:
        line_range = site.get("line_range") or []
        if len(line_range) != 2:
            continue
        start, end = line_range
        for advanced in advanced_slices[:12]:
            seed = advanced.get("seed_statement") or {}
            line = seed.get("line")
            if isinstance(line, int) and start <= line <= end:
                overlaps.append(
                    {
                        "repair_site_id": site.get("id"),
                        "advanced_statement_line": line,
                        "reason": advanced.get("reason"),
                    }
                )
                break
    return overlaps[:12]

# Tạo các contract repair-level có cấu trúc để planner không chỉ nhìn atom rời rạc.
def _semantic_repair_contracts(
    *,
    replacement_unit: str,
    statements: List[dict],
    failure_contract: Dict[str, Any],
    advanced_analysis: Dict[str, Any],
) -> List[dict]:
    text = replacement_unit or ""
    lower = text.lower()
    failure_text = " ".join(
        str(item)
        for key in ("expected_behavior", "observed_behavior", "failure_literals", "high_value_terms")
        for item in (failure_contract.get(key) or [])
    ).lower()
    categories = set(failure_contract.get("categories") or [])
    contracts: List[dict] = []

    if _looks_sign_numeric_alignment_case(lower, failure_text, categories):
        contracts.append(
            {
                "kind": "numeric_alignment_sign_emission",
                "strength": "hard",
                "repair_focus": "sign emission in ALIGN_NUMERIC/output iterator path",
                "summary": (
                    "For numeric alignment, a computed sign must be emitted exactly once before padding; "
                    "do not only widen the sign predicate if the failure is missing '+'/'-' output."
                ),
                "preferred_edit_patterns": [
                    "Adjust the numeric-alignment sign emission path around reserve/write_padded/double_writer.",
                    "Preserve existing SIGN_FLAG/PLUS_FLAG semantics unless evidence proves the predicate is wrong.",
                ],
                "forbidden_edit_patterns": [
                    "Do not invent sibling flags such as SPACE_FLAG unless present in related symbol inventory.",
                    "Do not call container methods on buffers unless RelatedCodeContext proves the method exists for that concrete type.",
                ],
                "evidence": _statements_matching(
                    statements,
                    [r"\bSIGN_FLAG\b", r"\bPLUS_FLAG\b", r"\bALIGN_NUMERIC\b", r"\breserve\s*\(", r"\bwrite_padded\s*\("],
                )[:8],
            }
        )

    if _looks_iterator_advancement_case(lower, failure_text, categories):
        contracts.append(
            {
                "kind": "output_iterator_postcondition",
                "strength": "hard",
                "repair_focus": "returned/output iterator advancement",
                "summary": (
                    "The returned/output iterator must point exactly after the produced output; preserve calls that update "
                    "formatting state unless the failure evidence proves that call is wrong."
                ),
                "preferred_edit_patterns": [
                    "Repair advancement/state propagation near ctx.out(), advance_to, visit, write, or formatter output paths.",
                    "Keep dynamic width/precision handling calls unless they are the proven defect.",
                ],
                "forbidden_edit_patterns": [
                    "Do not remove handle_dynamic_spec calls merely to change iterator position.",
                    "Do not change return ctx.out()/advance_to semantics without evidence of the new iterator postcondition.",
                ],
                "evidence": _statements_matching(
                    statements,
                    [r"\bctx\.out\s*\(", r"\badvance_to\s*\(", r"\bvisit\s*\(", r"\bhandle_dynamic_spec\b", r"\breturn\b.*\bout\s*\("],
                )[:10],
            }
        )

    if _looks_error_propagation_case(lower, failure_text, categories):
        contracts.append(
            {
                "kind": "error_propagation_contract",
                "strength": "hard",
                "repair_focus": "missing error/exception propagation",
                "summary": (
                    "Missing-name/error cases should follow the local error propagation convention; do not invent an "
                    "unqualified helper or abort path if the function returns a sentinel used by callers."
                ),
                "preferred_edit_patterns": [
                    "Preserve existing sentinel returns when callers translate them to exceptions.",
                    "Use an existing local error handler only when it is already visible in target or RelatedCodeContext.",
                ],
                "forbidden_edit_patterns": [
                    "Do not introduce unqualified assert_fail/format_error/FMT_THROW without exact visible evidence.",
                    "Do not replace caller-mediated error propagation with abort/assert behavior unless that is the local convention.",
                ],
                "evidence": _statements_matching(
                    statements,
                    [r"\breturn\s+-?1\b", r"\breturn\s+\{\s*\}", r"\bon_error\s*\(", r"\bformat_error\b", r"\bassert_fail\b"],
                )[:10],
            }
        )

    preserve_calls = _preserve_call_contracts(statements, failure_text)
    if preserve_calls:
        contracts.append(
            {
                "kind": "preserve_critical_call_sequence",
                "strength": "medium",
                "repair_focus": "call sequence preservation",
                "summary": "Existing state/formatting calls that establish local contracts should not be deleted as a repair shortcut.",
                "preferred_edit_patterns": [
                    "Change arguments or adjacent state only when the call contract remains satisfied.",
                    "Prefer adding a narrow guard/value adjustment over deleting a critical formatting/state call.",
                ],
                "forbidden_edit_patterns": [
                    "Do not delete precision/width/state propagation calls unless failure evidence names that call as the defect.",
                ],
                "evidence": preserve_calls[:10],
            }
        )

    for invariant in (advanced_analysis or {}).get("inferred_invariants") or []:
        if invariant.get("kind") in {"constructor_member_initializer_shape", "tail_data_consumption"}:
            contracts.append(
                {
                    "kind": f"advanced_{invariant.get('kind')}",
                    "strength": invariant.get("strength") or "medium",
                    "repair_focus": invariant.get("kind"),
                    "summary": invariant.get("summary"),
                    "preferred_edit_patterns": [],
                    "forbidden_edit_patterns": [],
                    "evidence": invariant.get("evidence") or [],
                }
            )
    return contracts[:10]


def _looks_sign_numeric_alignment_case(lower: str, failure_text: str, categories: set) -> bool:
    has_sign_path = "sign" in lower and ("align_numeric" in lower or "write_padded" in lower)
    sign_failure = any(term in failure_text for term in ("+42", "leading", "sign", "numeric alignment", "plus"))
    return has_sign_path and (sign_failure or "output_or_return_mismatch" in categories)


def _looks_iterator_advancement_case(lower: str, failure_text: str, categories: set) -> bool:
    has_iterator_path = any(term in lower for term in ("ctx.out", "advance_to", "output_range", "iterator", "visit("))
    iterator_failure = any(term in failure_text for term in ("iterator", "buf +", "pointer", "end", "address"))
    return has_iterator_path and (iterator_failure or "output_or_return_mismatch" in categories)


def _looks_error_propagation_case(lower: str, failure_text: str, categories: set) -> bool:
    has_error_path = any(term in lower for term in ("return -1", "return {}", "format_error", "on_error", "assert_fail"))
    expected_error = any(term in failure_text for term in ("format_error", "exception", "throw", "argument not found", "missing"))
    return has_error_path and (expected_error or "missing_expected_error" in categories)


def _statements_matching(statements: List[dict], patterns: List[str]) -> List[dict]:
    compiled = [re.compile(pattern, re.IGNORECASE) for pattern in patterns]
    out = []
    for statement in statements:
        text = str(statement.get("text") or "")
        if any(pattern.search(text) for pattern in compiled):
            out.append(_compact_statement(statement, include_facts=True))
    return out


def _preserve_call_contracts(statements: List[dict], failure_text: str) -> List[dict]:
    critical = []
    patterns = [
        r"\bhandle_dynamic_spec\s*<",
        r"\badvance_to\s*\(",
        r"\bvisit\s*\(",
        r"\bwrite_padded\s*\(",
        r"\bwrite\s*\(",
        r"\breturn\b.*\bout\s*\(",
    ]
    for statement in _statements_matching(statements, patterns):
        text = str(statement.get("text") or "")
        if "handle_dynamic_spec" in text and "precision" in text and "precision" in failure_text:
            strength = "hard"
        elif any(term in text for term in ("advance_to", "ctx.out", "return")):
            strength = "hard"
        else:
            strength = "medium"
        statement = dict(statement)
        statement["preserve_strength"] = strength
        critical.append(statement)
    return critical

# Khai phá invariant cục bộ mà patch cần giữ khi sửa target function.
def _semantic_invariants(
    *,
    statements: List[dict],
    analysis: Dict[str, Any],
    failure_contract: Dict[str, Any],
    ranked_repair_sites: List[dict],
    advanced_analysis: Optional[Dict[str, Any]] = None,
    semantic_repair_contracts: Optional[List[dict]] = None,
) -> List[dict]:
    invariants = [
        {
            "kind": "signature_scope_invariant",
            "summary": "The repair must preserve the target replacement unit signature and enclosing/template scope.",
            "strength": "hard",
            "evidence": [],
        }
    ]

    guarded_accesses = (analysis.get("control_flow_summary") or {}).get("guarded_accesses") or []
    for access in guarded_accesses[:12]:
        invariants.append(
            {
                "kind": "guarded_memory_access",
                "summary": "Pointer/index/buffer access should be dominated by an equivalent or stricter guard.",
                "strength": "hard" if "crash_or_memory_safety" in (failure_contract.get("categories") or []) else "medium",
                "evidence": [access],
            }
        )

    for error_statement in [
        statement for statement in statements if _has_any_signal(statement, {"error_or_cleanup_path"})
    ][:12]:
        guard = _nearest_preceding_branch(error_statement, statements)
        invariants.append(
            {
                "kind": "guarded_error_path",
                "summary": "Do not remove error/exception behavior outright; adjust the predicate if valid inputs reach it incorrectly.",
                "strength": "hard",
                "evidence": [
                    _compact_statement(guard, include_facts=True) if guard else {},
                    _compact_statement(error_statement, include_facts=True),
                ],
            }
        )

    output_sequence = [
        _compact_statement(statement)
        for statement in statements
        if _has_any_signal(statement, {"output_call", "return"})
    ][:20]
    if output_sequence:
        invariants.append(
            {
                "kind": "observable_output_order",
                "summary": "Preserve observable output/return order unless failure_contract says the observable value/order is wrong.",
                "strength": "medium",
                "evidence": output_sequence,
            }
        )

    state_sequence = [
        _compact_statement(statement)
        for statement in statements
        if _has_any_signal(statement, {"state_or_ownership_call"})
    ][:20]
    if state_sequence:
        invariants.append(
            {
                "kind": "state_or_ownership_order",
                "summary": "Preserve state/ownership operation order except at a repair site that directly explains the state failure.",
                "strength": "hard" if "state_or_contract" in (failure_contract.get("categories") or []) else "medium",
                "evidence": state_sequence,
            }
        )

    cleanup_sequence = (analysis.get("control_flow_summary") or {}).get("cleanup_labels_and_gotos") or []
    if cleanup_sequence:
        invariants.append(
            {
                "kind": "cleanup_path_shape",
                "summary": "Preserve existing cleanup labels and goto-based resource handling shape.",
                "strength": "hard",
                "evidence": cleanup_sequence,
            }
        )

    if any(site.get("scope_kind") == "case" for site in ranked_repair_sites):
        invariants.append(
            {
                "kind": "switch_case_isolation",
                "summary": "Prefer case-local edits; do not change sibling cases unless the slice crosses those cases.",
                "strength": "medium",
                "evidence": [
                    {
                        "site": site.get("id"),
                        "line_range": site.get("line_range"),
                        "statement": (site.get("primary_statement") or {}).get("text"),
                    }
                    for site in ranked_repair_sites
                    if site.get("scope_kind") == "case"
                ][:8],
            }
        )
    for invariant in (advanced_analysis or {}).get("inferred_invariants") or []:
        invariants.append(invariant)
    for contract in semantic_repair_contracts or []:
        invariants.append(
            {
                "kind": contract.get("kind"),
                "summary": contract.get("summary"),
                "strength": contract.get("strength") or "medium",
                "evidence": contract.get("evidence") or [],
            }
        )
    return invariants[:40]

# Suy ra contract hành vi cục bộ từ return, cleanup, state, guard và output order.
def _local_behavioral_contracts(
    func_code: str,
    statements: List[dict],
    *,
    analysis: Optional[Dict[str, Any]] = None,
    ranked_repair_sites: Optional[List[dict]] = None,
    advanced_analysis: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    analysis = analysis or {}
    advanced_analysis = advanced_analysis or {}
    contracts = []
    returns = [
        statement.get("text")
        for statement in statements
        if "return" in (statement.get("signals") or [])
    ]
    if returns:
        contracts.append(
            {
                "kind": "return_convention",
                "summary": "Preserve the target function's existing return-value convention and success/error split.",
                "evidence": returns[:8],
            }
        )
    if re.search(r"\bcleanup\s*:", func_code) or re.search(r"\berror\s*:", func_code) or re.search(r"\bfail\s*:", func_code):
        contracts.append(
            {
                "kind": "cleanup_convention",
                "summary": "Preserve cleanup/error labels and existing goto-based resource handling.",
                "evidence": [
                    line.strip()
                    for line in func_code.splitlines()
                    if re.search(r"\b(cleanup|error|fail|out)\s*:|\bgoto\s+(cleanup|error|fail|out)\b", line)
                ][:12],
            }
        )
    state_lines = [
        statement.get("text")
        for statement in statements
        if "state_or_ownership_call" in (statement.get("signals") or [])
    ]
    if state_lines:
        contracts.append(
            {
                "kind": "state_or_ownership_order",
                "summary": "Do not reorder state/ownership operations unless a ranked repair site specifically supports that move.",
                "evidence": state_lines[:10],
            }
        )
    guarded_accesses = (analysis.get("control_flow_summary") or {}).get("guarded_accesses") or []
    if guarded_accesses:
        contracts.append(
            {
                "kind": "bounds_or_null_guard_contract",
                "summary": "Pointer, index, and buffer operations must remain protected by the enclosing guards or by a stricter local guard.",
                "evidence": guarded_accesses[:10],
            }
        )
    output_lines = [
        statement.get("text")
        for statement in statements
        if "output_call" in (statement.get("signals") or [])
    ]
    if output_lines:
        contracts.append(
            {
                "kind": "output_order_contract",
                "summary": "Preserve the order of existing output/diagnostic calls unless the failure evidence is specifically an output-order bug.",
                "evidence": output_lines[:10],
            }
        )
    for invariant in advanced_analysis.get("inferred_invariants") or []:
        contracts.append(
            {
                "kind": invariant.get("kind"),
                "summary": invariant.get("summary"),
                "evidence": invariant.get("evidence") or [],
            }
        )
    if ranked_repair_sites:
        contracts.append(
            {
                "kind": "repair_scope_contract",
                "summary": "Prefer edits inside ranked_repair_sites; treat unrelated branches and helper calls as frozen by default.",
                "evidence": [
                    {
                        "site": site.get("id"),
                        "line_range": site.get("line_range"),
                        "edit_intent": site.get("edit_intent"),
                    }
                    for site in ranked_repair_sites[:MAX_REPAIR_SITES]
                ],
            }
        )
    if re.search(r"\b(assert|LY_CHECK|LOG|FMT_THROW|on_error)\b", func_code):
        contracts.append(
            {
                "kind": "project_error_idiom",
                "summary": "Prefer existing project error macros/handlers already used by this function.",
                "evidence": [
                    line.strip()
                    for line in func_code.splitlines()
                    if re.search(r"\b(assert|LY_CHECK|LOG|FMT_THROW|on_error)\b", line)
                ][:10],
            }
        )
    return contracts

# Mô tả vùng được phép sửa và vùng frozen-by-default trong replacement unit.
def _edit_scope(
    *,
    replacement_unit: str,
    replacement_start: int,
    replacement_end: int,
    source_code: str,
    ranked_repair_sites: List[dict],
) -> Dict[str, Any]:
    preferred = []
    for site in ranked_repair_sites:
        line_range = site.get("line_range") or []
        byte_range = site.get("byte_range") or []
        preferred.append(
            {
                "repair_site_id": site.get("id"),
                "line_range": line_range,
                "byte_range": byte_range,
                "scope_kind": site.get("scope_kind"),
                "edit_intent": site.get("edit_intent"),
            }
        )
    signature_range = _signature_range(
        replacement_unit=replacement_unit,
        replacement_start=replacement_start,
        source_code=source_code,
    )
    return {
        "replacement_unit_range": {
            "start_byte": replacement_start,
            "end_byte": replacement_end,
            "start_line": line_number_for_byte(source_code, replacement_start),
            "end_line": line_number_for_byte(source_code, replacement_end),
        },
        "preferred_allowed_ranges": preferred[:MAX_REPAIR_SITES],
        "frozen_by_default": [
            {
                "kind": "signature_and_enclosing_prefix",
                "line_range": signature_range.get("line_range"),
                "byte_range": signature_range.get("byte_range"),
                "rule": "Do not change signature, template prefix, class/namespace wrapper, or storage qualifiers unless required by target_envelope.",
            },
            {
                "kind": "unranked_code",
                "rule": "Treat code outside preferred_allowed_ranges as frozen unless a failure slice dependency explicitly justifies the edit.",
            },
        ],
        "scope_policy": "Patch should be inside the target replacement unit and preferably inside ranked repair-site ranges.",
    }
