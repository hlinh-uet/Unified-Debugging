import re
from typing import Any, Dict, List, Optional, Set, Tuple

from core.apr.agent.context_common import clip_text, dedup_keep_order

from .support import (
    _compact_dependency,
    _compact_region,
    _compact_statement,
    _dedup_edges,
    _fallback_control_edges,
    _has_any_signal,
    _identifiers_from_text,
    _line_ref,
    _limit_mapping,
    _looks_error_sentinel_return,
    _looks_size_like,
    _looks_success_default_return,
    MAX_FAILURE_SLICES,
    MAX_REPAIR_SITES,
    MAX_STATEMENTS,
    MAX_STRUCTURAL_REGIONS,
)

# Stage 3: nối FailContext với code bằng failure contract, PDG nhẹ, slices và repair sites.
def build_failure_localization(
    *,
    function_ir: Dict[str, Any],
    failed_tests_context: str,
    repair_objective: Dict[str, Any],
) -> Dict[str, Any]:
    symbols = function_ir.get("target_symbols") or {}
    statements = function_ir.get("statement_inventory") or []
    structural_regions = function_ir.get("structural_regions") or []
    failure_contract = _failure_contract(
        failed_tests_context=failed_tests_context,
        symbols=symbols,
        repair_objective=repair_objective,
    )
    dependence_graph = _program_dependence_graph(
        statements=statements,
        structural_regions=structural_regions,
    )
    failure_slices = _build_failure_slices(
        statements=statements,
        structural_regions=structural_regions,
        failed_tests_context=failed_tests_context,
        symbols=symbols,
        repair_objective=repair_objective,
    )
    ranked_repair_sites = _rank_repair_sites(
        failure_slices=failure_slices,
        statements=statements,
        structural_regions=structural_regions,
    )
    failure_links = _failure_links_from_repair_sites(ranked_repair_sites)
    if not failure_links:
        failure_links = _rank_failure_code_links(
            statements=statements,
            failed_tests_context=failed_tests_context,
            symbols=symbols,
            repair_objective=repair_objective,
        )

    return {
        "failure_contract": failure_contract,
        "program_dependence_graph": dependence_graph,
        "failure_slices": failure_slices,
        "ranked_repair_sites": ranked_repair_sites,
        "failure_code_links": failure_links,
        "failure_localization": {
            "failure_contract": failure_contract,
            "program_dependence_graph": dependence_graph,
            "failure_slices": failure_slices,
            "ranked_repair_sites": ranked_repair_sites,
            "failure_code_links": failure_links,
        },
    }

# Biến FailContext và repair objective thành contract cục bộ cho bước localization.
def _failure_contract(
    *,
    failed_tests_context: str,
    symbols: dict,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    profile = _failure_profile(
        failed_tests_context,
        symbols,
        repair_objective=repair_objective,
    )
    text = str(failed_tests_context or "")
    expected = _extract_failure_snippets(
        text,
        labels=("expected result", "expected", "failure_contract", "should", "must"),
    )
    observed = _extract_failure_snippets(
        text,
        labels=("observed result", "actual", "observed", "thrown", "crash", "exception"),
    )
    literals = _extract_failure_literals(text)
    return {
        "categories": profile.get("categories") or [],
        "symbolic_terms": profile.get("terms") or [],
        "high_value_terms": profile.get("high_value_terms") or [],
        "line_numbers": profile.get("line_numbers") or [],
        "expected_behavior": expected[:8],
        "observed_behavior": observed[:8],
        "failure_literals": literals[:16],
        "oracle_kind": _oracle_kind(profile),
        "repair_bias": _repair_bias(profile),
        "route": profile.get("route", ""),
        "repair_goal": profile.get("repair_goal", ""),
        "notes": [
            "This contract is extracted from FailContext and should guide repair intent, not replace validation.",
            "Prefer satisfying expected_behavior while preserving existing valid-path semantics.",
        ],
    }

# Dựng program dependence graph nhẹ trong phạm vi function từ def-use/control/observable edges.
def _program_dependence_graph(
    *,
    statements: List[dict],
    structural_regions: List[dict],
) -> Dict[str, Any]:
    nodes = [
        _compact_statement(statement, include_facts=True)
        for statement in statements[:MAX_STATEMENTS]
    ]
    data_edges = []
    last_defs: Dict[str, dict] = {}
    for statement in statements:
        for var in statement.get("reads") or []:
            source = last_defs.get(var)
            if source and source.get("id") != statement.get("id"):
                data_edges.append(
                    {
                        "from": source.get("id"),
                        "to": statement.get("id"),
                        "kind": "def_use",
                        "symbol": var,
                    }
                )
        for var in statement.get("writes") or []:
            last_defs[var] = statement
        if len(data_edges) >= 180:
            break

    control_edges = []
    for statement in statements:
        for region in statement.get("enclosing_regions") or []:
            region_id = region.get("id")
            if region_id:
                control_edges.append(
                    {
                        "from": region_id,
                        "to": statement.get("id"),
                        "kind": "control_dependency",
                        "condition": region.get("condition", ""),
                    }
                )
    control_edges.extend(_fallback_control_edges(statements))

    observable_edges = []
    observables = [
        statement
        for statement in statements
        if _has_any_signal(
            statement,
            {"return", "output_call", "error_or_cleanup_path", "state_or_ownership_call"},
        )
    ]
    for statement in statements:
        vars_ = set((statement.get("reads") or []) + (statement.get("writes") or []))
        if not vars_ and not _has_any_signal(statement, {"branch_or_loop", "guard_or_predicate"}):
            continue
        for observable in observables:
            if (observable.get("line") or 0) <= (statement.get("line") or 0):
                continue
            obs_vars = set((observable.get("reads") or []) + (observable.get("writes") or []))
            if vars_ & obs_vars or _has_any_signal(statement, {"branch_or_loop", "guard_or_predicate"}):
                observable_edges.append(
                    {
                        "from": statement.get("id"),
                        "to": observable.get("id"),
                        "kind": "observable_impact",
                        "shared_symbols": sorted(vars_ & obs_vars)[:8],
                    }
                )
                break
        if len(observable_edges) >= 120:
            break

    return {
        "nodes": nodes,
        "regions": [_compact_region(region) for region in structural_regions[:MAX_STRUCTURAL_REGIONS]],
        "data_edges": data_edges[:180],
        "control_edges": _dedup_edges(control_edges)[:180],
        "observable_edges": _dedup_edges(observable_edges)[:120],
        "entry_statement": nodes[0] if nodes else {},
        "exit_statements": [
            _compact_statement(statement)
            for statement in statements
            if _has_any_signal(statement, {"return", "error_or_cleanup_path"})
        ][:20],
    }

# Chấm điểm statement theo failure profile rồi tạo backward/forward/control slice quanh seed.
def _build_failure_slices(
    *,
    statements: List[dict],
    structural_regions: List[dict],
    failed_tests_context: str,
    symbols: dict,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    if not statements:
        return []
    profile = _failure_profile(failed_tests_context, symbols, repair_objective=repair_objective)
    scored = []
    for statement in statements:
        score, reasons = _score_statement_for_failure(statement, profile)
        if score > 0:
            scored.append((score, reasons, statement))

    if not scored:
        for statement in statements:
            if _has_any_signal(statement, {"pointer_deref", "index_or_array_access", "buffer_or_io_call", "return", "state_or_ownership_call"}):
                scored.append((1, ["high-impact statement in target function"], statement))

    scored.sort(key=lambda item: (-item[0], item[2].get("line") or 10**9))
    region_by_id = {region.get("id"): region for region in structural_regions}
    slices = []
    for score, reasons, seed in scored[:MAX_FAILURE_SLICES]:
        variables = _slice_variables(seed, profile)
        backward = _backward_dependencies(seed, statements, variables)
        forward = _forward_impacts(seed, statements, variables)
        controls = [
            region_by_id.get(region.get("id"), region)
            for region in seed.get("enclosing_regions") or []
            if region.get("id")
        ]
        slices.append(
            {
                "id": f"FS{len(slices) + 1}",
                "seed_statement": _compact_statement(seed, include_facts=True),
                "score": score,
                "confidence": "high" if score >= 10 else "medium" if score >= 5 else "low",
                "failure_categories": profile.get("categories") or [],
                "relevant_variables": variables[:12],
                "localization_reason": "; ".join(reasons[:6]),
                "backward_dependencies": [_compact_dependency(item) for item in backward[:8]],
                "forward_impacts": [_compact_dependency(item) for item in forward[:8]],
                "control_dependencies": [_compact_region(item) for item in controls[:8] if item],
            }
        )
    return slices

# Chuyển failure slices thành các vùng sửa ưu tiên với intent và allowed operations.
def _rank_repair_sites(
    *,
    failure_slices: List[dict],
    statements: List[dict],
    structural_regions: List[dict],
) -> List[dict]:
    if not failure_slices:
        return []
    statement_by_id = {statement.get("id"): statement for statement in statements}
    region_by_id = {region.get("id"): region for region in structural_regions}
    sites = []
    for failure_slice in failure_slices:
        seed_ref = failure_slice.get("seed_statement") or {}
        seed = statement_by_id.get(seed_ref.get("id"))
        if not seed:
            continue
        allowed_range = _allowed_repair_range(
            seed,
            region_by_id,
            failure_slice=failure_slice,
            statement_by_id=statement_by_id,
        )
        intent = _repair_intent(seed, failure_slice)
        site = {
            "id": f"RS{len(sites) + 1}",
            "failure_slice_id": failure_slice.get("id"),
            "rank": len(sites) + 1,
            "confidence": failure_slice.get("confidence", "low"),
            "score": failure_slice.get("score", 0),
            "line_range": [allowed_range.get("line_start"), allowed_range.get("line_end")],
            "byte_range": [allowed_range.get("start_byte"), allowed_range.get("end_byte")],
            "scope_kind": allowed_range.get("kind"),
            "primary_statement": seed_ref,
            "edit_intent": intent,
            "allowed_operations": _allowed_operations_for_intent(intent),
            "evidence": {
                "reason": failure_slice.get("localization_reason", ""),
                "relevant_variables": failure_slice.get("relevant_variables") or [],
                "backward_dependencies": failure_slice.get("backward_dependencies") or [],
                "forward_impacts": failure_slice.get("forward_impacts") or [],
                "control_dependencies": failure_slice.get("control_dependencies") or [],
            },
        }
        sites.append(site)
        if len(sites) >= MAX_REPAIR_SITES:
            break
    return sites

# Tạo failure-code links trực tiếp từ các repair site đã rank.
def _failure_links_from_repair_sites(repair_sites: List[dict]) -> List[dict]:
    links = []
    for site in repair_sites:
        primary = site.get("primary_statement") or {}
        links.append(
            {
                "line": primary.get("line"),
                "kind": primary.get("kind"),
                "statement": primary.get("text"),
                "score": site.get("score", 0),
                "reason": (site.get("evidence") or {}).get("reason", ""),
                "confidence": site.get("confidence", "low"),
                "repair_site_id": site.get("id"),
                "edit_intent": site.get("edit_intent"),
                "allowed_line_range": site.get("line_range"),
            }
        )
    return links

# Fallback rank statement liên quan lỗi khi chưa có repair site đủ tốt.
def _rank_failure_code_links(
    *,
    statements: List[dict],
    failed_tests_context: str,
    symbols: dict,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> List[dict]:
    profile = _failure_profile(failed_tests_context, symbols, repair_objective=repair_objective)
    ranked = []
    for statement in statements:
        score, reasons = _score_statement_for_failure(statement, profile)
        if score > 0:
            ranked.append(
                {
                    "line": statement.get("line"),
                    "kind": statement.get("kind"),
                    "statement": statement.get("text"),
                    "score": score,
                    "reason": "; ".join(reasons[:4]),
                    "confidence": "high" if score >= 10 else "medium" if score >= 5 else "low",
                }
            )
    ranked.sort(key=lambda item: (-item["score"], item.get("line") or 10**9))
    return ranked[:MAX_REPAIR_SITES]

# Phân loại failure context thành categories, route terms và line hints để scoring.
def _failure_profile(
    failed_tests_context: str,
    symbols: dict,
    *,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    repair_objective = repair_objective or {}
    failure = str(failed_tests_context or "")
    failure_lc = failure.lower()
    route = str(repair_objective.get("route") or "").strip()
    bug_kind = str(repair_objective.get("bug_kind") or "").strip()
    categories = []
    security_oracle = route == "security_repair" or bug_kind == "vulnerability"
    correctness_oracle = route == "correctness_repair" or bug_kind == "general_bug"
    if re.search(r"\b(segmentation|segfault|crash|asan|ubsan|null|nullptr|heap-buffer|stack-buffer|oob|out[- ]of[- ]bounds)\b", failure_lc):
        categories.append("crash_or_memory_safety")
    if re.search(r"\b(overflow|underflow|bounds?|length|size|truncated|buffer|read|write)\b", failure_lc):
        categories.append("bounds_or_size")
    if re.search(r"\b(expected|actual|mismatch|diff|stdout|stderr|output|format|printed|return value)\b", failure_lc):
        categories.append("output_or_return_mismatch")
    if re.search(r"\b(schema|state|flag|internal error|assert|not found|invalid|cleanup|resource|leak)\b", failure_lc):
        categories.append("state_or_contract")
    if (
        re.search(r"\b(expect(ed|s)?|should|required|required to)\b.{0,120}\b(throw|exception|error)\b", failure_lc)
        or re.search(r"\b(no exception|throws nothing|without raising|not throw|no error)\b", failure_lc)
    ):
        categories.append("missing_expected_error")
    if re.search(
        r"\b(compile[_ -]?failed|compilation failed|compiler error|syntax error|"
        r"duplicate symbol|undefined reference)\b|"
        r"\berror:\s*['`A-Za-z_].*(not declared|undeclared|undefined|duplicate|expected)\b",
        failure_lc,
    ):
        categories.append("compile_or_parse")
    objective_categories = [
        str(item)
        for item in repair_objective.get("failure_categories") or []
        if item
    ]
    categories = dedup_keep_order(objective_categories + categories)
    if security_oracle and "crash_or_memory_safety" not in categories:
        categories.append("crash_or_memory_safety")
    if security_oracle and "bounds_or_size" not in categories:
        categories.append("bounds_or_size")
    if correctness_oracle and not security_oracle:
        categories = [
            category for category in categories
            if category not in {"crash_or_memory_safety"}
        ]
        if "bounds_or_size" in categories and not re.search(
            r"\b(overflow|underflow|length|size|truncated|precision|digit|carry)\b",
            failure_lc,
        ):
            categories = [category for category in categories if category != "bounds_or_size"]
        if "output_or_return_mismatch" in categories and "compile_or_parse" in categories:
            categories = [category for category in categories if category != "compile_or_parse"]
    terms = _failure_terms(failure_lc, symbols)
    high_value_terms = _high_value_failure_terms(failure_lc, repair_objective)
    line_numbers = _failure_line_numbers(failure)
    return {
        "raw": failure,
        "terms": terms,
        "high_value_terms": high_value_terms,
        "route": route,
        "bug_kind": bug_kind,
        "repair_goal": repair_objective.get("repair_goal", ""),
        "categories": dedup_keep_order(categories),
        "line_numbers": line_numbers,
    }

# Chấm điểm statement theo mức khớp với failure profile và route security/correctness.
def _score_statement_for_failure(statement: dict, profile: Dict[str, Any]) -> Tuple[int, List[str]]:
    text = str(statement.get("text") or "")
    text_lc = text.lower()
    route = str(profile.get("route") or "")
    correctness_route = route == "correctness_repair"
    security_route = route == "security_repair"
    score = 0
    reasons = []
    statement_terms = set()
    for key in ("reads", "writes", "calls", "literals"):
        statement_terms.update(str(item).lower() for item in statement.get(key) or [])
    high_value_terms = set(str(item).lower() for item in profile.get("high_value_terms") or [])
    for term in profile.get("terms") or []:
        term_lc = term.lower()
        if not term_lc or len(term_lc) < 3:
            continue
        if _term_matches_statement(term_lc, text_lc, statement_terms):
            delta = 7 if term_lc in high_value_terms else 2 if correctness_route else 4
            score += delta
            reasons.append(f"matches failure/symbol term '{term}'")
    for term_lc in high_value_terms:
        if len(term_lc) < 3:
            continue
        if _term_matches_statement(term_lc, text_lc, statement_terms):
            score += 5
            reasons.append(f"matches high-value route term '{term_lc}'")
    line = statement.get("line")
    for failure_line in profile.get("line_numbers") or []:
        if isinstance(line, int) and abs(line - failure_line) <= 2:
            score += 7 if line == failure_line else 4
            reasons.append(f"near failure-reported line {failure_line}")
            break

    signals = set(statement.get("signals") or [])
    categories = set(profile.get("categories") or [])
    if "crash_or_memory_safety" in categories:
        if "pointer_deref" in signals:
            score += 6
            reasons.append("memory-safety failure and statement dereferences a pointer")
        if "index_or_array_access" in signals or "buffer_or_io_call" in signals:
            score += 6
            reasons.append("memory-safety failure and statement indexes or touches a buffer")
        if "guard_or_predicate" in signals:
            score += 2
            reasons.append("memory-safety failure and statement is a guard/predicate")
    if "bounds_or_size" in categories:
        if "index_or_array_access" in signals or "buffer_or_io_call" in signals:
            delta = 6 if security_route else 1
            score += delta
            reasons.append("bounds/size failure and statement handles indexing/buffer I/O")
        if any(_looks_size_like(var) for var in (statement.get("reads") or []) + (statement.get("writes") or [])):
            score += 3 if security_route else 1
            reasons.append("statement touches length/size-like variables")
        if correctness_route and "tail_or_leftover_processing" in signals:
            score += 8
            reasons.append("correctness bounds/size failure and statement handles leftover/tail data")
    if "output_or_return_mismatch" in categories:
        if "return" in signals:
            score += 6 if correctness_route else 5
            reasons.append("output/return mismatch and statement returns a value")
        if "output_call" in signals:
            score += 7 if correctness_route else 6
            reasons.append("output mismatch and statement emits output")
        if correctness_route and _has_any_signal(statement, {"branch_or_loop", "guard_or_predicate"}) and high_value_terms:
            if any(_term_matches_statement(term, text_lc, statement_terms) for term in high_value_terms):
                score += 5
                reasons.append("correctness route and predicate/dispatch touches high-value failure term")
        if correctness_route and "numeric_value_flow" in signals and (
            high_value_terms & {"digit", "carry", "overflow", "rounding", "precision", "num_digits"}
            or re.search(r"\b(digit|carry|overflow|round|precision)\b", text_lc)
        ):
            score += 8
            reasons.append("correctness numeric output mismatch and statement participates in digit/carry/range flow")
        if correctness_route and "tail_or_leftover_processing" in signals and (
            high_value_terms & {"remaining", "leftover", "num_chars_left", "transcode", "size"}
        ):
            score += 8
            reasons.append("correctness truncation/output mismatch and statement processes remaining data")
        if correctness_route and "chrono_duration_flow" in signals and (
            high_value_terms & {"negative", "duration", "seconds", "milliseconds", "to_unsigned"}
        ):
            score += 7
            reasons.append("correctness duration failure and statement participates in duration/sign conversion")
    if "state_or_contract" in categories:
        if "state_or_ownership_call" in signals:
            score += 5
            reasons.append("state/contract failure and statement mutates state/ownership")
        if "error_or_cleanup_path" in signals:
            score += 4
            reasons.append("state/contract failure and statement is on error/cleanup path")
    if "missing_expected_error" in categories:
        if "error_or_cleanup_path" in signals:
            score += 7
            reasons.append("expected error/exception but statement is an error path")
        if "return" in signals and _looks_error_sentinel_return(text):
            score += 9
            reasons.append("expected error/exception and statement returns an error/sentinel value")
        if "return" in signals and _looks_success_default_return(text):
            score += 8
            reasons.append("expected error/exception but statement returns a success/default value")
        if re.search(r"\b(has_|is_|valid|invalid|found|named|args?|name)\w*\b", text_lc):
            score += 4
            reasons.append("expected error/exception and statement checks validation/lookup state")
    if "compile_or_parse" in categories and not correctness_route and _has_any_signal(statement, {"macro_call", "branch_or_loop"}):
        score += 2
        reasons.append("compile/parse failure and statement uses syntax-sensitive construct")
    if statement.get("enclosing_conditions") and _has_any_signal(statement, {"pointer_deref", "index_or_array_access", "buffer_or_io_call"}):
        score += 1 if security_route else 0
        reasons.append("dangerous operation is control-dependent on guard(s)")
    span = max(0, int(statement.get("end_line") or statement.get("line") or 0) - int(statement.get("line") or 0))
    if correctness_route and span >= 20 and not any(
        _term_matches_statement(term, text_lc, statement_terms) for term in high_value_terms
    ):
        score -= min(8, 2 + span // 12)
        reasons.append("correctness route downranks broad branch without high-value oracle terms")
    return score, dedup_keep_order(reasons)

# Trích các term có giá trị từ FailContext và symbol trong target function.
def _failure_terms(failure: str, symbols: dict) -> List[str]:
    terms = []
    stop_words = {
        "expected",
        "actual",
        "failure",
        "failed",
        "error",
        "test",
        "tests",
        "line",
        "file",
        "true",
        "false",
        "null",
        "none",
        "with",
        "from",
        "that",
        "this",
        "the",
        "and",
        "but",
        "for",
        "into",
        "leading",
        "reported",
        "stated",
        "concrete",
        "metadata",
        "summary",
        "evidence",
        "result",
        "results",
        "google",
        "assertion",
        "input",
        "source",
        "excerpt",
        "cpp",
        "shown",
        "which",
        "does",
        "required",
        "contain",
        "contains",
        "wrong",
        "text",
        "string",
        "formatted",
        "observed",
        "reported",
        "asserted",
        "expects",
        "expected",
        "actual_output",
        "failure_actual",
        "failure_expected",
        "failure_summary",
        "test_evidence",
        "observed_vs_expected",
        "return",
    }
    for key in ("calls", "fields", "identifiers", "macro_like"):
        for value in symbols.get(key) or []:
            text = str(value or "").strip()
            if len(text) >= 3 and re.search(r"\b" + re.escape(text.lower()) + r"\b", failure):
                terms.append(text)
    for quoted in re.findall(r'"([^"\n]{3,80})"|\'([^\'\n]{3,80})\'', failure):
        for item in quoted:
            if item:
                terms.extend(re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", item))
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", failure):
        if token.lower() not in stop_words:
            terms.append(token)
    return dedup_keep_order(terms)[:36]

# Rút ra các term ưu tiên cao theo từng pattern lỗi như format, overflow, tail, duration.
def _high_value_failure_terms(failure: str, repair_objective: Dict[str, Any]) -> List[str]:
    terms = []
    objective_text = " ".join(
        str(repair_objective.get(key) or "")
        for key in ("repair_goal", "validation_oracle", "oracle_subkind", "route")
    ).lower()
    text = f"{failure}\n{objective_text}"
    if re.search(r"\b(sign|plus|leading \+|'\+'|\"\+|:\s*[^\"`]*\+|sign_flag|plus_flag)\b", text):
        terms.extend(["sign", "flag", "plus_flag", "sign_flag"])
    if re.search(r"\b(space|align|alignment|numeric alignment)\b", text):
        terms.extend(["align", "alignment"])
    if re.search(r"\b(format|formatted|formatter|precision|fixed|round|rounding|decimal)\b", text):
        terms.extend(["format", "precision", "fixed", "rounding", "decimal"])
    if re.search(r"\b(overflow|carry|digit|large double|integer part|corrupt|b446)\b", text):
        terms.extend(["overflow", "carry", "digit", "result", "num_digits"])
    if re.search(r"\b(truncated|truncate|remaining|leftover|chars?_left|bytes?_left|utf|utf8|utf16|transcode|decode|encode)\b", text):
        terms.extend(["remaining", "leftover", "num_chars_left", "memcpy", "transcode", "size"])
    if re.search(r"\b(negative duration|duration|chrono|seconds|milliseconds|to_unsigned|d\.count|count\(\))\b", text):
        terms.extend(["negative", "duration", "count", "seconds", "milliseconds", "to_unsigned"])
    if re.search(r"\b(minus flag|zero flag|left align|right align|printf|%c)\b", text):
        terms.extend(["align", "left", "right", "zero", "minus", "width"])
    if re.search(r"\b(throw|exception|format_error|throws nothing|no exception)\b", text):
        terms.extend(["throw", "exception", "format_error", "error"])
    if re.search(r"\b(null|nullptr|segfault|asan|oob|out[- ]of[- ]bounds|use-after-free)\b", text):
        terms.extend(["null", "bounds", "size", "length", "guard"])
    return dedup_keep_order(terms)[:18]

# Kiểm tra term failure có thật sự xuất hiện trong statement hoặc fact của statement không.
def _term_matches_statement(term_lc: str, text_lc: str, statement_terms: Set[str]) -> bool:
    if term_lc in statement_terms:
        return True
    if not re.match(r"^[a-z_][a-z0-9_]*$", term_lc):
        return term_lc in text_lc
    return bool(re.search(r"\b" + re.escape(term_lc) + r"\b", text_lc))

# Trích line number từ log/test output để boost statement gần dòng lỗi.
def _failure_line_numbers(failure: str) -> List[int]:
    values = []
    patterns = [
        r"\bline\s+(\d{1,6})\b",
        r"\bline:(\d{1,6})\b",
        r":(\d{1,6})(?::\d{1,4})?\b",
    ]
    for pattern in patterns:
        for match in re.finditer(pattern, failure, flags=re.IGNORECASE):
            try:
                line = int(match.group(1))
            except Exception:
                continue
            if 0 < line < 1_000_000:
                values.append(line)
    out = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        out.append(value)
        seen.add(value)
    return out[:12]

# Chọn biến/call từ seed statement để truy dependency trong failure slice.
def _slice_variables(seed: dict, profile: Dict[str, Any]) -> List[str]:
    terms = set(str(term).lower() for term in profile.get("terms") or [])
    vars_in_seed = dedup_keep_order((seed.get("reads") or []) + (seed.get("writes") or []))
    relevant = [var for var in vars_in_seed if var.lower() in terms]
    if not relevant:
        relevant = vars_in_seed
    if not relevant and seed.get("calls"):
        relevant = seed.get("calls") or []
    return relevant[:12]

# Truy ngược các definition/predicate/control guard ảnh hưởng đến seed statement.
def _backward_dependencies(seed: dict, statements: List[dict], variables: List[str]) -> List[dict]:
    seed_line = seed.get("line") or 10**9
    if _has_any_signal(seed, {"error_or_cleanup_path"}):
        for statement in reversed(statements):
            line = statement.get("line") or 0
            if line >= seed_line or statement.get("id") == seed.get("id"):
                continue
            if statement.get("kind") in {"if_statement", "switch_statement"} and seed_line - line <= 8:
                return [{**statement, "dependency_kind": "nearest_error_guard"}]
    if not variables:
        return []
    var_set = set(variables)
    deps = []
    for statement in reversed(statements):
        line = statement.get("line") or 0
        if line >= seed_line or statement.get("id") == seed.get("id"):
            continue
        writes = set(statement.get("writes") or [])
        reads = set(statement.get("reads") or [])
        condition_vars = set()
        for condition in statement.get("enclosing_conditions") or []:
            condition_vars.update(_identifiers_from_text(condition))
        if writes & var_set:
            deps.append({**statement, "dependency_kind": "definition"})
        elif reads & var_set and _has_any_signal(statement, {"guard_or_predicate", "branch_or_loop"}):
            deps.append({**statement, "dependency_kind": "predicate"})
        elif condition_vars & var_set:
            deps.append({**statement, "dependency_kind": "control_guard"})
        if len(deps) >= 10:
            break
    return list(reversed(deps))

# Truy xuôi các use/redefinition/observable effect bị ảnh hưởng bởi seed statement.
def _forward_impacts(seed: dict, statements: List[dict], variables: List[str]) -> List[dict]:
    if not variables:
        return []
    var_set = set(variables)
    seed_line = seed.get("line") or 0
    impacts = []
    for statement in statements:
        line = statement.get("line") or 0
        if line <= seed_line or statement.get("id") == seed.get("id"):
            continue
        reads = set(statement.get("reads") or [])
        writes = set(statement.get("writes") or [])
        if reads & var_set:
            impacts.append({**statement, "dependency_kind": "later_use"})
        elif writes & var_set:
            impacts.append({**statement, "dependency_kind": "later_redefinition"})
        elif _has_any_signal(statement, {"return", "output_call", "state_or_ownership_call", "error_or_cleanup_path"}):
            impacts.append({**statement, "dependency_kind": "observable_effect"})
        if len(impacts) >= 10:
            break
    return impacts

# Xác định range sửa hợp lý quanh seed statement hoặc region điều khiển nó.
def _allowed_repair_range(
    seed: dict,
    region_by_id: Dict[str, dict],
    *,
    failure_slice: Optional[dict] = None,
    statement_by_id: Optional[Dict[str, dict]] = None,
) -> dict:
    statement_by_id = statement_by_id or {}
    if _has_any_signal(seed, {"error_or_cleanup_path"}):
        for dep in (failure_slice or {}).get("backward_dependencies") or []:
            if dep.get("dependency_kind") not in {"nearest_error_guard", "predicate", "control_guard"}:
                continue
            dep_stmt = statement_by_id.get(dep.get("id")) or dep
            start_byte = dep_stmt.get("start_byte", dep.get("start_byte"))
            end_byte = seed.get("end_byte")
            return {
                "kind": "guarded_error_region",
                "line_start": dep_stmt.get("line") or dep.get("line"),
                "line_end": seed.get("end_line") or seed.get("line"),
                "start_byte": start_byte,
                "end_byte": end_byte,
            }
    enclosing = seed.get("enclosing_regions") or []
    for region_ref in reversed(enclosing):
        region = region_by_id.get(region_ref.get("id"))
        if not region:
            continue
        line_start = region.get("line_start") or 0
        line_end = region.get("line_end") or line_start
        if line_end - line_start <= 80:
            return {
                "kind": region.get("kind"),
                "line_start": line_start,
                "line_end": line_end,
                "start_byte": region.get("start_byte"),
                "end_byte": region.get("end_byte"),
            }
    return {
        "kind": "statement",
        "line_start": seed.get("line"),
        "line_end": seed.get("end_line") or seed.get("line"),
        "start_byte": seed.get("start_byte"),
        "end_byte": seed.get("end_byte"),
    }

# Suy ra intent sửa từ signal của seed statement và loại failure.
def _repair_intent(seed: dict, failure_slice: dict) -> str:
    signals = set(seed.get("signals") or [])
    categories = set(failure_slice.get("failure_categories") or [])
    if "missing_expected_error" in categories and "return" in signals:
        return "restore_error_sentinel_or_error_path"
    if "branch_or_loop" in signals or seed.get("kind") in {"if_statement", "switch_statement", "case_statement"}:
        return "adjust_predicate_or_dispatch"
    if "error_or_cleanup_path" in signals and "output_or_return_mismatch" in categories:
        return "adjust_error_condition_or_predicate"
    if signals & {"state_or_ownership_call", "error_or_cleanup_path"} and not signals & {"index_or_array_access", "buffer_or_io_call"}:
        return "repair_state_cleanup_or_error_path"
    if signals & {"pointer_deref", "index_or_array_access", "buffer_or_io_call"}:
        return "add_or_tighten_guard_before_dangerous_operation"
    if "output_or_return_mismatch" in categories and signals & {"return", "output_call"}:
        return "preserve_or_correct_observable_output"
    if signals & {"state_or_ownership_call", "error_or_cleanup_path"}:
        return "repair_state_cleanup_or_error_path"
    if seed.get("writes"):
        return "correct_local_assignment_or_value_flow"
    return "minimal_local_expression_fix"

# Liệt kê thao tác sửa được phép cho từng repair intent.
def _allowed_operations_for_intent(intent: str) -> List[str]:
    mapping = {
        "adjust_predicate_or_dispatch": [
            "change the nearest condition/case predicate",
            "add a missing branch-local guard",
            "avoid restructuring unrelated cases",
        ],
        "add_or_tighten_guard_before_dangerous_operation": [
            "add or tighten null/bounds/length guard",
            "preserve success-path side effects and output order",
            "use existing error/cleanup convention for rejected paths",
        ],
        "preserve_or_correct_observable_output": [
            "change only the value/order needed for the observed output",
            "preserve existing diagnostic/output calls unless directly implicated",
        ],
        "repair_state_cleanup_or_error_path": [
            "move/add state update only within the ranked local region",
            "preserve cleanup labels and ownership-release order",
        ],
        "adjust_error_condition_or_predicate": [
            "adjust the nearest predicate that leads to the error/exception path",
            "preserve the error call for truly invalid inputs",
            "do not suppress the error unconditionally",
        ],
        "restore_error_sentinel_or_error_path": [
            "restore the target function's existing error/sentinel return convention",
            "prefer an existing local sentinel/error value over inventing a new exception/API",
            "preserve valid lookup/success returns",
        ],
        "correct_local_assignment_or_value_flow": [
            "change local assignment/expression",
            "preserve callers, helper APIs, and unrelated state operations",
        ],
        "minimal_local_expression_fix": [
            "make the smallest expression-level change supported by the slice",
        ],
    }
    return mapping.get(intent, mapping["minimal_local_expression_fix"])

# Trích snippet expected/observed từ FailContext theo nhãn gần đúng.
def _extract_failure_snippets(text: str, labels: Tuple[str, ...]) -> List[str]:
    snippets = []
    lines = [line.strip(" -*\t") for line in str(text or "").splitlines()]
    for idx, line in enumerate(lines):
        if not line:
            continue
        line_lc = line.lower()
        if any(label in line_lc for label in labels):
            snippets.append(clip_text(line, 360))
            if idx + 1 < len(lines) and lines[idx + 1].strip():
                snippets.append(clip_text(lines[idx + 1].strip(" -*\t"), 360))
    return dedup_keep_order(snippets)

# Trích literal trong failure output để đối chiếu với atom/statement.
def _extract_failure_literals(text: str) -> List[str]:
    literals = []
    for pattern in (r'"((?:\\.|[^"\\]){1,160})"', r'`([^`\n]{1,160})`', r"\*\"([^\n\"]{1,160})\"\*"):
        literals.extend(match.group(1) for match in re.finditer(pattern, str(text or "")))
    return dedup_keep_order(literals)

# Quy đổi categories/route thành loại oracle chính cho repair contract.
def _oracle_kind(profile: Dict[str, Any]) -> str:
    categories = set(profile.get("categories") or [])
    route = str(profile.get("route") or "")
    if route == "security_repair":
        return "crash_or_sanitizer_oracle" if "crash_or_memory_safety" in categories else "security_oracle"
    if route == "correctness_repair" and "output_or_return_mismatch" in categories:
        return "observable_output_or_return_oracle"
    if "compile_or_parse" in categories:
        return "compile_or_parse_oracle"
    if "crash_or_memory_safety" in categories:
        return "crash_or_sanitizer_oracle"
    if "output_or_return_mismatch" in categories:
        return "observable_output_or_return_oracle"
    if "state_or_contract" in categories:
        return "state_or_contract_oracle"
    return "unknown_or_mixed_oracle"

# Sinh bias sửa theo route và loại failure để FixAgent không chọn sai mục tiêu.
def _repair_bias(profile: Dict[str, Any]) -> List[str]:
    categories = set(profile.get("categories") or [])
    route = str(profile.get("route") or "")
    bias = []
    if route == "security_repair":
        bias.append("Security route: prioritize unsafe pointer/index/allocation sinks and their nearest guards.")
    if route == "correctness_repair":
        bias.append("Correctness route: prioritize expected/actual output, return, exception, formatting, and numeric semantics.")
    if route != "correctness_repair" and ("crash_or_memory_safety" in categories or "bounds_or_size" in categories):
        bias.append("Prefer local guards that preserve valid-path side effects.")
    if "output_or_return_mismatch" in categories:
        bias.append("Preserve expected observable output/return semantics; do not convert valid paths into errors.")
    if "state_or_contract" in categories:
        bias.append("Repair state transitions or predicates without broad ownership/order rewrites.")
    if "compile_or_parse" in categories:
        bias.append("Prefer syntactically minimal edits inside the replacement envelope.")
    return bias or ["Prefer the smallest local semantic change supported by the failure slice."]
