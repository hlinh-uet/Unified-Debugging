import json
import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_repair_objective_artifact


SECURITY_ROUTE = "security_repair"
CORRECTNESS_ROUTE = "correctness_repair"
HYBRID_ROUTE = "hybrid_repair"


def classify_repair_objective(
    *,
    bug,
    bug_id: str,
    dataset: str,
    failed_tests_context: str,
) -> Dict[str, Any]:
    """Classify the APR objective before code-context collection.

    This is intentionally deterministic. Metadata is treated as a prior, while
    failure oracle text decides what the current validation is asking the patch
    to satisfy.
    """
    raw_meta = getattr(bug, "raw", None) if bug is not None else None
    tests = getattr(bug, "tests", []) if bug is not None else []
    metadata_label, metadata_evidence = _metadata_bug_label(
        dataset=dataset,
        bug_id=bug_id,
        raw_meta=raw_meta,
    )
    oracle = _oracle_features(
        failed_tests_context=failed_tests_context,
        tests=tests,
    )
    scores = _score_objective(metadata_label, oracle)
    bug_kind, route, confidence = _choose_route(
        metadata_label=metadata_label,
        scores=scores,
        oracle=oracle,
    )
    repair_goal = _repair_goal(route=route, bug_kind=bug_kind, oracle=oracle)
    preferred, forbidden = _route_operators(route, oracle)
    categories = _failure_categories(route=route, oracle=oracle)

    return {
        "classifier": {
            "name": "repair_objective_classifier_agent",
            "version": 1,
            "strategy": "metadata_oracle_weighted_deterministic_classifier",
        },
        "bug_id": bug_id,
        "dataset": dataset,
        "bug_kind": bug_kind,
        "metadata_label": metadata_label,
        "validation_oracle": oracle.get("oracle_kind"),
        "oracle_subkind": oracle.get("oracle_subkind"),
        "route": route,
        "confidence": confidence,
        "scores": scores,
        "repair_goal": repair_goal,
        "failure_categories": categories,
        "preferred_patch_operators": preferred,
        "forbidden_patch_operators": forbidden,
        "route_policy": _route_policy(route),
        "target_context_policy": _target_context_policy(route),
        "fix_policy": _fix_policy(route),
        "evidence": {
            "metadata": metadata_evidence,
            "oracle": oracle.get("evidence") or [],
        },
        "notes": _notes(metadata_label, route, oracle),
    }


def run_repair_objective_classifier_agent(
    *,
    bug,
    bug_id: str,
    dataset: str,
    failed_tests_context: str,
) -> Tuple[dict, dict]:
    objective = classify_repair_objective(
        bug=bug,
        bug_id=bug_id,
        dataset=dataset,
        failed_tests_context=failed_tests_context,
    )
    artifact = write_repair_objective_artifact(
        bug_id=bug_id,
        attempt_index=0,
        qualified_name="test_fail_context",
        candidate_relpath="",
        repair_objective=objective,
    )
    return objective, artifact


def _metadata_bug_label(
    *,
    dataset: str,
    bug_id: str,
    raw_meta: Any,
) -> Tuple[str, List[str]]:
    evidence = []
    text = _flatten_metadata_text(raw_meta)
    text_lc = f"{dataset} {bug_id} {text}".lower()

    explicit_general = re.search(
        r"\b(general[_ -]?bug|correctness|regression|unit[_ -]?test|non[_ -]?security)\b",
        text_lc,
    )
    explicit_security = re.search(
        r"\b(cve|cwe|vuln|vulnerability|security|asan|ubsan|sanitizer|"
        r"heap-buffer-overflow|stack-buffer-overflow|use-after-free|oob)\b",
        text_lc,
    )

    if isinstance(raw_meta, dict):
        for key in ("bug_type", "bug_kind", "type", "category", "label", "is_vulnerability"):
            if key in raw_meta:
                evidence.append(f"metadata {key}={raw_meta.get(key)!r}")
        for key in ("cve", "cve_id", "cwe", "cwe_id", "security"):
            if raw_meta.get(key):
                evidence.append(f"metadata {key}={raw_meta.get(key)!r}")

    if explicit_security and not explicit_general:
        evidence.append(f"metadata/security keyword: {explicit_security.group(0)}")
        return "vulnerability", evidence
    if explicit_general and not explicit_security:
        evidence.append(f"metadata/general keyword: {explicit_general.group(0)}")
        return "general_bug", evidence

    ds_lc = (dataset or "").strip().lower()
    if ds_lc in {"fmt", "codeflaws"}:
        evidence.append(f"dataset prior: {dataset} is treated as general correctness")
        return "general_bug", evidence
    if "vul" in ds_lc or "cve" in ds_lc:
        evidence.append(f"dataset prior: {dataset} suggests vulnerability")
        return "vulnerability", evidence

    return "unknown", evidence


def _oracle_features(*, failed_tests_context: str, tests: Any) -> Dict[str, Any]:
    text = str(failed_tests_context or "")
    test_text = json.dumps(tests, ensure_ascii=False, default=str)[:30000]
    combined = f"{text}\n{test_text}"
    lower = combined.lower()
    evidence: List[str] = []

    security_patterns = [
        (r"\baddresssanitizer\b|\bmemorysanitizer\b|\bundefinedbehaviorsanitizer\b", "sanitizer_report"),
        (r"\bheap-buffer-overflow\b|\bstack-buffer-overflow\b|\bglobal-buffer-overflow\b", "buffer_overflow"),
        (r"\buse-after-free\b|\bdouble[- ]free\b|\binvalid free\b", "lifetime_violation"),
        (r"\bsegmentation fault\b|\bsegfault\b|\bsigsegv\b|\bsigbus\b|\bcrash\b", "crash"),
        (r"\bnull pointer\b|\bnull deref|\bnullptr\b", "null_deref"),
        (r"\bout[- ]of[- ]bounds\b|\boob\b|\bbuffer overrun\b", "out_of_bounds"),
        (r"\bruntime error:.*\b(load|store|index|overflow)\b", "ubsan_runtime_error"),
    ]
    correctness_patterns = [
        (r"\bexpected\b.*\bactual\b|\bactual\b.*\bexpected\b", "expected_actual_mismatch"),
        (r"\bexpect_(eq|streq|true|false|ne)\b|\bassert_(eq|streq|true|false|ne)\b", "unit_assertion"),
        (r"\bwrong\b.*\b(output|string|return|value)\b|\bmismatch\b", "semantic_mismatch"),
        (r"\bformat\b|\bformatted\b|\bprecision\b|\brounding\b|\bsign flag\b|\bleading [+-]\b", "format_or_numeric_output"),
        (r"\bthrows nothing\b|\bno exception\b|\bexpected\b.{0,120}\bthrow", "exception_mismatch"),
        (r"\bstdout\b|\bstderr\b|\bprinted\b|\breturn value\b", "observable_output"),
    ]
    compile_patterns = [
        (r"\bcompile[_ -]?failed\b|\bcompilation failed\b|\bcompiler error\b", "compile_failed"),
        (r"\berror:\s*['`A-Za-z_].*(not declared|undeclared|undefined|duplicate|expected)", "compiler_diagnostic"),
        (r"\bundefined reference\b|\bsyntax error\b", "link_or_syntax_error"),
    ]

    security_hits = _pattern_hits(lower, security_patterns)
    correctness_hits = _pattern_hits(lower, correctness_patterns)
    compile_hits = _pattern_hits(lower, compile_patterns)
    for hit in security_hits[:5]:
        evidence.append(f"security oracle signal: {hit}")
    for hit in correctness_hits[:5]:
        evidence.append(f"correctness oracle signal: {hit}")
    for hit in compile_hits[:5]:
        evidence.append(f"compile oracle signal: {hit}")

    oracle_kind = "unknown_or_mixed"
    oracle_subkind = ""
    if compile_hits and not security_hits and not correctness_hits:
        oracle_kind = "compile_or_parse_error"
        oracle_subkind = compile_hits[0]
    elif security_hits and len(security_hits) >= len(correctness_hits):
        oracle_kind = "security_runtime_failure"
        oracle_subkind = security_hits[0]
    elif correctness_hits:
        oracle_kind = "correctness_failure"
        oracle_subkind = correctness_hits[0]
    elif security_hits:
        oracle_kind = "security_runtime_failure"
        oracle_subkind = security_hits[0]

    return {
        "oracle_kind": oracle_kind,
        "oracle_subkind": oracle_subkind,
        "security_hits": security_hits,
        "correctness_hits": correctness_hits,
        "compile_hits": compile_hits,
        "has_expected_actual": bool(re.search(r"\bexpected\b|\bactual\b", lower)),
        "has_sanitizer": bool(security_hits and any("sanitizer" in hit for hit in security_hits)),
        "has_crash": bool(security_hits and any(hit in {"crash", "null_deref"} for hit in security_hits)),
        "evidence": evidence,
    }


def _score_objective(metadata_label: str, oracle: Dict[str, Any]) -> Dict[str, int]:
    security = 0
    correctness = 0
    build = 0

    if metadata_label == "vulnerability":
        security += 50
    elif metadata_label == "general_bug":
        correctness += 35

    security += 45 * len(oracle.get("security_hits") or [])
    correctness += 35 * len(oracle.get("correctness_hits") or [])
    build += 45 * len(oracle.get("compile_hits") or [])

    if oracle.get("has_sanitizer"):
        security += 50
    if oracle.get("has_crash"):
        security += 35
    if oracle.get("has_expected_actual"):
        correctness += 30

    if oracle.get("oracle_kind") == "compile_or_parse_error":
        build += 60
    return {
        "security": security,
        "correctness": correctness,
        "build": build,
    }


def _choose_route(
    *,
    metadata_label: str,
    scores: Dict[str, int],
    oracle: Dict[str, Any],
) -> Tuple[str, str, str]:
    security = scores.get("security", 0)
    correctness = scores.get("correctness", 0)
    build = scores.get("build", 0)

    if build >= 90 and build > max(security, correctness) + 20:
        return "general_bug", CORRECTNESS_ROUTE, "high"

    if metadata_label == "vulnerability":
        confidence = "high" if security >= correctness else "medium"
        return "vulnerability", SECURITY_ROUTE, confidence
    if metadata_label == "general_bug":
        confidence = "high" if correctness >= security else "medium"
        return "general_bug", CORRECTNESS_ROUTE, confidence

    if security >= correctness + 35:
        return "vulnerability", SECURITY_ROUTE, "high"
    if correctness >= security + 20:
        return "general_bug", CORRECTNESS_ROUTE, "high" if correctness >= security + 45 else "medium"

    if oracle.get("oracle_kind") == "security_runtime_failure":
        return "vulnerability", SECURITY_ROUTE, "medium"
    if oracle.get("oracle_kind") == "correctness_failure":
        return "general_bug", CORRECTNESS_ROUTE, "medium"
    return "ambiguous", HYBRID_ROUTE, "low"


def _failure_categories(*, route: str, oracle: Dict[str, Any]) -> List[str]:
    categories = []
    if route in {SECURITY_ROUTE, HYBRID_ROUTE} and oracle.get("security_hits"):
        categories.append("crash_or_memory_safety")
    if route == SECURITY_ROUTE and any(
        hit in {"buffer_overflow", "out_of_bounds", "ubsan_runtime_error"}
        for hit in oracle.get("security_hits") or []
    ):
        categories.append("bounds_or_size")
    if route in {CORRECTNESS_ROUTE, HYBRID_ROUTE} and oracle.get("correctness_hits"):
        categories.append("output_or_return_mismatch")
    if "exception_mismatch" in (oracle.get("correctness_hits") or []):
        categories.append("missing_expected_error")
    if oracle.get("compile_hits"):
        categories.append("compile_or_parse")
    return _dedup(categories)


def _repair_goal(*, route: str, bug_kind: str, oracle: Dict[str, Any]) -> str:
    subkind = oracle.get("oracle_subkind") or oracle.get("oracle_kind") or "unknown"
    if route == SECURITY_ROUTE:
        return (
            "Eliminate the unsafe runtime behavior while preserving valid-path semantics; "
            f"primary oracle signal: {subkind}."
        )
    if route == CORRECTNESS_ROUTE:
        return (
            "Make the observable behavior match expected output/return/exception semantics; "
            f"primary oracle signal: {subkind}."
        )
    return (
        f"Resolve mixed {bug_kind} evidence conservatively: satisfy the validation oracle "
        "without hiding possible safety regressions."
    )


def _route_operators(route: str, oracle: Dict[str, Any]) -> Tuple[List[str], List[str]]:
    if route == SECURITY_ROUTE:
        return (
            [
                "add_or_tighten_null_bounds_guard",
                "repair_length_or_allocation_size",
                "preserve_cleanup_error_path",
                "fail_closed_for_invalid_input",
            ],
            [
                "output_only_cosmetic_change",
                "suppress_crash_without_guarding_sink",
                "remove_error_handling_unconditionally",
            ],
        )
    if route == CORRECTNESS_ROUTE:
        return (
            [
                "correct_branch_dispatch_or_predicate",
                "correct_output_return_or_exception_value",
                "repair_numeric_rounding_or_carry",
                "reuse_existing_api_symbol_or_flag",
            ],
            [
                "invent_unseen_api_macro_or_error_code",
                "turn_valid_input_into_error_return",
                "broad_defensive_guard_unrelated_to_oracle",
                "rewrite_unrelated_memory_buffer_mechanics",
            ],
        )
    return (
        [
            "minimal_semantic_local_edit",
            "guard_only_the_ranked_unsafe_sink_if_present",
            "preserve_observable_oracle_behavior",
        ],
        [
            "broad_refactor",
            "signature_or_wrapper_change",
            "unconditional_error_suppression",
        ],
    )


def _route_policy(route: str) -> List[str]:
    if route == SECURITY_ROUTE:
        return [
            "Rank unsafe memory/pointer/index/allocation sinks above formatting-only output code.",
            "Prefer local validation/guard/cleanup changes that eliminate the unsafe path.",
            "Do not accept a patch that merely changes output while leaving the unsafe sink reachable.",
        ]
    if route == CORRECTNESS_ROUTE:
        return [
            "Rank code that controls expected/actual output, return, exception, numeric, or formatting semantics.",
            "Treat buffer/pointer words as correctness evidence only when the oracle is observable output.",
            "Do not add broad defensive guards or error returns for valid-input tests.",
        ]
    return [
        "Keep both safety and observable-oracle evidence visible.",
        "Prefer the smallest local edit that satisfies the current validation without weakening safety checks.",
    ]


def _target_context_policy(route: str) -> List[str]:
    if route == SECURITY_ROUTE:
        return [
            "Boost dangerous sinks, missing guards, tainted size/index flow, and cleanup/error paths.",
            "Downrank pure output formatting statements unless they dominate the unsafe sink.",
        ]
    if route == CORRECTNESS_ROUTE:
        return [
            "Boost statements matching expected/actual literals, flags, returns, format specifiers, rounding, and dispatch predicates.",
            "Downrank large generic buffer branches unless the failure slice proves they affect the observable oracle.",
        ]
    return ["Use route-specific evidence when available and mark ambiguous slices explicitly."]


def _fix_policy(route: str) -> List[str]:
    if route == SECURITY_ROUTE:
        return [
            "Patch must remove or guard the unsafe runtime behavior.",
            "Fail closed only for invalid/malformed input paths supported by evidence.",
            "Preserve valid-path observable behavior unless safety evidence requires a local guard.",
        ]
    if route == CORRECTNESS_ROUTE:
        return [
            "Patch must satisfy expected-vs-actual behavior directly.",
            "Use only APIs/macros/types visible in target or related context.",
            "Avoid defensive rewrites that bypass the valid behavior under test.",
        ]
    return ["Prefer a small evidence-backed patch and avoid broad rewrites."]


def _notes(metadata_label: str, route: str, oracle: Dict[str, Any]) -> List[str]:
    notes = []
    if metadata_label == "vulnerability" and route != SECURITY_ROUTE:
        notes.append("Metadata suggests vulnerability, but current oracle is not clearly memory-safety; route was softened.")
    if metadata_label == "general_bug" and route == SECURITY_ROUTE:
        notes.append("Metadata suggests general bug, but sanitizer/crash oracle overrode it.")
    if oracle.get("compile_hits") and route == CORRECTNESS_ROUTE:
        notes.append("Compile signals are treated as validation feedback, not as the primary bug kind, unless no semantic oracle exists.")
    return notes


def _pattern_hits(text: str, patterns: List[Tuple[str, str]]) -> List[str]:
    hits = []
    for pattern, name in patterns:
        if re.search(pattern, text, flags=re.IGNORECASE | re.DOTALL):
            hits.append(name)
    return _dedup(hits)


def _flatten_metadata_text(value: Any, *, depth: int = 0) -> str:
    if depth > 4:
        return ""
    if value is None:
        return ""
    if isinstance(value, dict):
        parts = []
        for key, item in value.items():
            parts.append(str(key))
            parts.append(_flatten_metadata_text(item, depth=depth + 1))
        return " ".join(parts)
    if isinstance(value, (list, tuple, set)):
        return " ".join(_flatten_metadata_text(item, depth=depth + 1) for item in list(value)[:80])
    return str(value)


def _dedup(values: List[str]) -> List[str]:
    out = []
    seen = set()
    for value in values:
        if value in seen:
            continue
        out.append(value)
        seen.add(value)
    return out
