"""Input/output-guided ranking over freshly collected ordered runtime traces."""

from __future__ import annotations

import os
import re
import math
from collections import defaultdict, deque
from typing import Any, Dict, Iterable, List, Tuple

from core.apr.common import (
    node_text,
    parse_tree,
    source_language_from_path,
    walk_nodes,
)
from .keys import (
    _extract_class_from_key,
    _extract_file_from_key,
    _sort_scores,
)
from .semantic import extract_io_semantics, semantic_tokens
from .scenario import build_scenario_analysis
from .trace_plan import build_trace_plan
from .investigation import load_or_build_source_evidence
from .probes import (
    merge_targeted_runtime_observations,
    resolve_probe_evidence,
)
from .artifacts import atomic_write_json
from .runtime import collect_targeted_probe_runtime_evidence


CAUSAL_FL_VERSION = 8
MAX_PERSISTED_CANDIDATES = 100

_CALL_NODE_TYPES = {"call_expression"}
_CONTROL_WORDS = {
    "if", "for", "while", "switch", "return", "sizeof", "alignof",
    "decltype", "static_cast", "dynamic_cast", "reinterpret_cast",
    "const_cast", "catch",
}
_TEST_ASSERTION_PREFIXES = (
    "assert", "expect_", "assert_", "check_", "require", "verify",
)
_GENERIC_FAILURE_SYMBOLS = {
    "abort", "actual", "error", "exception", "expected", "fail", "failed",
    "failure", "fatal", "fault", "overflow", "sanitizer", "segmentation",
    "signal", "summary", "timeout", "underflow", "warning",
}
_STACK_PATTERNS = (
    # ASan/UBSan: #0 0x... in ns::fn(args) /path/file.cc:12
    re.compile(
        r"^\s*#(?P<index>\d+)\s+(?:0x[0-9a-fA-F]+\s+)?in\s+"
        r"(?P<function>[~A-Za-z_][^\s]*?)"
        r"(?:\s+(?P<path>(?:[A-Za-z]:)?[/\\][^:\n]+):(?P<line>\d+))?\s*$"
    ),
    # GDB: #0 ns::fn (...) at /path/file.cc:12
    re.compile(
        r"^\s*#(?P<index>\d+)\s+"
        r"(?P<function>[~A-Za-z_][^\s(]*)(?:\s*\([^)]*\))?"
        r"\s+(?:at|from)\s+(?P<path>[^:\n]+)(?::(?P<line>\d+))?"
    ),
)


def calculate_causal_hierarchy_scores(
    *,
    bug: Any,
    runtime_evidence: Dict[str, Any],
    llm_provider: str = None,
    llm_rerank: bool = True,
    artifact_dir: str = "",
    targeted_probes: bool = True,
) -> Tuple[Dict[str, float], Dict[str, float], Dict[str, float], Dict[str, Any]]:
    """Run scenario-first, input-aware causal-tier fault localization."""
    evidence = collect_failure_evidence(
        bug,
        runtime_evidence=runtime_evidence,
    )
    scenario_analysis = build_scenario_analysis(evidence)
    if artifact_dir:
        atomic_write_json(
            os.path.join(artifact_dir, "scenario_analysis.json"),
            scenario_analysis,
        )
    first_scenario = (
        scenario_analysis.get("first_failing_scenario") or {}
    )
    ranking_evidence = _evidence_for_first_scenario(
        evidence,
        first_scenario=first_scenario,
    )
    runtime_functions = runtime_evidence.get("functions") or {}
    producer_distances = _producer_graph_distances(
        runtime_functions=runtime_functions,
        dynamic_edges=runtime_evidence.get("dynamic_edges") or [],
        evidence=ranking_evidence,
    )
    regression_count = max(
        1, len(runtime_evidence.get("regression_test_ids") or [])
    )
    producer_slices, slicing_audit = _dynamic_producer_slices(
        runtime_evidence=runtime_evidence,
        evidence=ranking_evidence,
        regression_count=regression_count,
        selected_scenario=first_scenario,
    )
    invocation_keys = sorted({
        str(key)
        for invocation in slicing_audit.get("invocations") or []
        for key in invocation.get("member_keys") or []
        if str(key)
    })
    source_evidence = load_or_build_source_evidence(
        bug=bug,
        runtime_evidence=runtime_evidence,
        scenario=first_scenario,
        invocation_keys=invocation_keys,
        artifact_dir=artifact_dir,
    )
    trace_plan = build_trace_plan(
        scenario_analysis=scenario_analysis,
        runtime_evidence=runtime_evidence,
        use_llm=llm_rerank,
        provider=llm_provider,
        artifact_dir=artifact_dir,
        source_evidence=source_evidence,
        invocation_keys=invocation_keys,
    )
    probe_evidence = resolve_probe_evidence(
        trace_plan=trace_plan,
        source_evidence=source_evidence,
        runtime_evidence=runtime_evidence,
        invocation_keys=invocation_keys,
        artifact_dir=artifact_dir,
    )
    targeted_runtime = {}
    if (
        targeted_probes
        and llm_rerank
        and probe_evidence.get("targeted_probes")
    ):
        targeted_runtime = collect_targeted_probe_runtime_evidence(
            bug,
            probe_plan=probe_evidence,
            artifact_dir=artifact_dir,
        )
        probe_evidence = merge_targeted_runtime_observations(
            probe_evidence=probe_evidence,
            targeted_runtime=targeted_runtime,
        )
        if artifact_dir:
            written = atomic_write_json(
                os.path.join(
                    artifact_dir, "causal_probe_evidence.json"
                ),
                probe_evidence,
            )
            if written:
                probe_evidence["artifact"] = written
    semantic_affinities, semantic_audit = _semantic_io_affinities(
        runtime_functions=runtime_functions,
        evidence=ranking_evidence,
    )
    function_scores, candidate_features, tier_audit = (
        _rank_scenario_causal_tiers(
            runtime_functions=runtime_functions,
            producer_slices=producer_slices,
            slicing_audit=slicing_audit,
            producer_distances=producer_distances,
            semantic_affinities=semantic_affinities,
            trace_plan=trace_plan,
            evidence=ranking_evidence,
            source_evidence=source_evidence,
            probe_evidence=probe_evidence,
        )
    )
    file_scores = _aggregate_parent_scores(
        function_scores, key_func=_extract_file_from_key
    )
    class_scores = _aggregate_parent_scores(
        function_scores, key_func=_extract_class_from_key
    )
    evidence["ranking"] = {
        "formula": "evidence_driven_lexicographic_causal_proofs_v8",
        "weight_policy": "no_fitted_coefficients",
        "dynamic_producer_slicing_used": bool(
            slicing_audit.get("available")
        ),
        "coverage_metadata_used": False,
        "runtime_scope": "fresh_ordered_trace_of_regression_failed_tests",
        "candidate_count": len(function_scores),
        "persisted_candidate_limit": MAX_PERSISTED_CANDIDATES,
        "candidate_features": {
            key: candidate_features[key]
            for key in list(function_scores)[:MAX_PERSISTED_CANDIDATES]
        },
    }
    evidence["scenario_analysis"] = scenario_analysis
    evidence["trace_plan"] = trace_plan
    evidence["causal_tiers"] = tier_audit
    evidence["dynamic_producer_slicing"] = slicing_audit
    evidence["semantic_io_analysis"] = semantic_audit
    evidence["source_investigation"] = source_evidence
    evidence["probe_evidence"] = probe_evidence
    evidence["targeted_probe_runtime"] = targeted_runtime
    evidence["llm_reranking"] = {
        "enabled": bool(llm_rerank),
        "applied": bool((trace_plan.get("llm") or {}).get("applied")),
        "role": "input-aware trace planning, not direct ranking",
        "diagnostics": (trace_plan.get("llm") or {}).get(
            "diagnostics"
        ) or [],
    }
    evidence["runtime_trace"] = _compact_runtime_evidence(runtime_evidence)
    return (
        function_scores,
        _sort_scores(file_scores),
        _sort_scores(class_scores),
        evidence,
    )


def collect_failure_evidence(
    bug: Any,
    *,
    runtime_evidence: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Extract test-code and failure-output seeds without using ground truth."""
    diagnostics: List[str] = []
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    context = _build_test_source_contexts(bug, raw)
    context_by_id = {
        str(item.get("test_id") or ""): item
        for item in context.get("tests") or []
        if isinstance(item, dict)
    }
    runtime_by_id = {
        str(item.get("test_id") or ""): item
        for item in (runtime_evidence or {}).get("tests") or []
        if isinstance(item, dict)
    }
    tests = []
    all_stack_frames = []
    all_near_calls = set()
    all_test_calls = set()
    all_producer_calls = set()
    all_output_symbols = set()
    all_active_trace_keys = set()
    all_semantic_tokens = set()
    all_exception_trace_keys = set()

    for record in getattr(bug, "tests", None) or []:
        if not _is_regression_failure(record):
            continue
        test_id = str(record.get("test_id") or "")
        focused = context_by_id.get(test_id) or {}
        runtime_test = runtime_by_id.get(test_id) or {}
        failure_text = str(runtime_test.get("fresh_output") or "")
        if not failure_text:
            failure_text = "\n".join(
                str(value or "")
                for value in (
                    record.get("fail_reason"),
                    record.get("actual_output"),
                )
                if value
            )
        observations = _failure_observations(failure_text)
        observation = observations[0]
        source_path, source_text, source_start_line = _resolve_test_source(
            raw=raw,
            test_id=test_id,
            focused=focused,
            observation=observation,
        )
        reported_line = int(observation.get("reported_line") or 0)
        language = source_language_from_path(source_path)
        test_calls, parser = _extract_call_names(source_text, language)
        near_sources = [
            _near_failure_source(
                source_text,
                source_start_line=source_start_line,
                reported_line=int(item.get("reported_line") or 0),
            )
            for item in observations
        ]
        near_source = "\n".join(
            dict.fromkeys(value for value in near_sources if value)
        )
        near_calls, near_parser = _extract_call_names(near_source, language)
        stack_frames = _extract_stack_frames(failure_text)
        output_symbols = _extract_output_symbols(failure_text)
        test_calls = sorted(_useful_call_names(test_calls))
        near_calls = sorted(_useful_call_names(near_calls))

        all_stack_frames.extend(stack_frames)
        all_near_calls.update(near_calls)
        all_test_calls.update(test_calls)
        all_output_symbols.update(output_symbols)
        active_trace_keys = [
            str(item.get("key") or "")
            for item in runtime_test.get("active_stack") or []
            if str(item.get("key") or "")
        ]
        all_active_trace_keys.update(active_trace_keys)
        exception_events = [
            item
            for item in runtime_test.get("exception_events") or []
            if isinstance(item, dict)
        ]
        all_exception_trace_keys.update(
            str(
                item.get("throw_site_key")
                or item.get("key")
                or ""
            )
            for item in exception_events
            if str(
                item.get("throw_site_key")
                or item.get("key")
                or ""
            )
        )
        observed_output = _extract_expected_actual(failure_text)
        producer_call_sites = []
        for observation_index, item in enumerate(observations):
            contract = item.get("observed_output") or {}
            producer_call_sites.extend(_extract_producer_call_sites(
                source=source_text,
                source_start_line=source_start_line,
                reported_line=int(item.get("reported_line") or 0),
                output_expressions=contract.get("expressions") or [],
                language=language,
                observation_index=observation_index,
                source_path=source_path,
            ))
        for site in producer_call_sites:
            all_producer_calls.update(site.get("calls") or [])
        io_semantics = extract_io_semantics(
            raw=raw,
            test_id=test_id,
            source_path=source_path,
            source=source_text,
            source_start_line=source_start_line,
            focused=focused,
            observations=observations,
            producer_sites=producer_call_sites,
            runtime_evidence=runtime_evidence or {},
        )
        all_semantic_tokens.update(io_semantics.get("tokens") or [])
        test_diagnostics = []
        if not source_text:
            test_diagnostics.append("test_source_unavailable")
        if parser != "tree_sitter":
            test_diagnostics.append(f"test_call_parser:{parser}")
        if near_source and near_parser != "tree_sitter":
            test_diagnostics.append(f"near_failure_call_parser:{near_parser}")
        tests.append({
            "test_id": test_id,
            "failure_mode": str(observation.get("failure_mode") or "unknown"),
            "failure_source_path": str(
                observation.get("reported_source_path") or ""
            ),
            "failure_line": reported_line,
            "failure_observations": observations,
            "resolved_test_source_path": source_path,
            "focused_test_source": source_text,
            "focused_test_start_line": source_start_line,
            "test_call_symbols": test_calls[:80],
            "near_failure_call_symbols": near_calls[:40],
            "stack_frames": stack_frames[:24],
            "active_trace_keys": active_trace_keys[:40],
            "exception_events": exception_events[:40],
            "output_symbols": sorted(output_symbols)[:40],
            "observed_output": observed_output,
            "input_literals": _extract_input_literals(near_source or source_text),
            "producer_call_sites": producer_call_sites,
            "io_semantics": io_semantics,
            "runtime_output_artifact": runtime_test.get("output_artifact", ""),
            "runtime_trace_artifact": runtime_test.get("trace_artifact", ""),
            "diagnostics": test_diagnostics,
        })

    return {
        "version": CAUSAL_FL_VERSION,
        "engine": "scenario_first_input_aware_causal_trace",
        "ground_truth_used": False,
        "tests": tests,
        "failure_seeds": {
            "near_failure_call_symbols": sorted(all_near_calls),
            "test_call_symbols": sorted(all_test_calls),
            "producer_call_symbols": sorted(all_producer_calls),
            "stack_frames": _unique_dicts(all_stack_frames)[:64],
            "output_symbols": sorted(all_output_symbols),
            "active_trace_keys": sorted(all_active_trace_keys),
            "semantic_io_tokens": sorted(all_semantic_tokens),
            "exception_trace_keys": sorted(all_exception_trace_keys),
        },
        "diagnostics": diagnostics,
    }


def _evidence_for_first_scenario(
    evidence: Dict[str, Any],
    *,
    first_scenario: Dict[str, Any],
) -> Dict[str, Any]:
    """Scope seeds to the first failed assertion instead of the whole test."""
    test_id = str(first_scenario.get("test_id") or "")
    observation_index = int(
        first_scenario.get("observation_index") or 0
    )
    selected_tests = []
    for test in evidence.get("tests") or []:
        if test_id and str(test.get("test_id") or "") != test_id:
            continue
        item = dict(test)
        selected_sites = [
            site
            for site in test.get("producer_call_sites") or []
            if int(site.get("observation_index") or 0)
            == observation_index
        ]
        if selected_sites:
            nearest = min(
                int(site.get("distance_to_failure") or 0)
                for site in selected_sites
            )
            selected_sites = [
                site for site in selected_sites
                if int(site.get("distance_to_failure") or 0) == nearest
            ]
        item["producer_call_sites"] = selected_sites
        observations = test.get("failure_observations") or []
        item["failure_observations"] = (
            [observations[observation_index]]
            if observation_index < len(observations)
            else []
        )
        selected_tests.append(item)
    producer_calls = [
        str(value)
        for value in first_scenario.get("producer_calls") or []
        if str(value)
    ]
    seeds = dict(evidence.get("failure_seeds") or {})
    if producer_calls:
        seeds["producer_call_symbols"] = producer_calls
        seeds["near_failure_call_symbols"] = producer_calls
    if selected_tests:
        test = selected_tests[0]
        seeds["test_call_symbols"] = test.get("test_call_symbols") or []
        seeds["stack_frames"] = test.get("stack_frames") or []
        seeds["active_trace_keys"] = test.get("active_trace_keys") or []
        seeds["output_symbols"] = test.get("output_symbols") or []
        seeds["semantic_io_tokens"] = (
            (test.get("io_semantics") or {}).get("tokens") or []
        )
    return {
        **evidence,
        "tests": selected_tests,
        "failure_seeds": seeds,
        "scope": {
            "test_id": test_id,
            "observation_index": observation_index,
            "scenario_id": first_scenario.get("scenario_id"),
        },
    }


def _rank_scenario_causal_tiers(
    *,
    runtime_functions: Dict[str, Dict[str, Any]],
    producer_slices: Dict[str, Dict[str, Any]],
    slicing_audit: Dict[str, Any],
    producer_distances: Dict[str, int],
    semantic_affinities: Dict[str, Dict[str, Any]],
    trace_plan: Dict[str, Any],
    evidence: Dict[str, Any],
    source_evidence: Dict[str, Any],
    probe_evidence: Dict[str, Any] | None = None,
) -> Tuple[Dict[str, float], Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Order executed functions by causal tiers without fitted coefficients."""
    invocations = slicing_audit.get("invocations") or []
    member_keys = {
        str(key)
        for invocation in invocations
        for key in invocation.get("member_keys") or []
        if str(key)
    }
    roots = {
        str(invocation.get("root") or "")
        for invocation in invocations
        if str(invocation.get("root") or "")
    }
    boundaries = [
        record
        for invocation in invocations
        for record in invocation.get("boundary_records") or []
        if isinstance(record, dict)
    ]
    boundary_by_function = defaultdict(list)
    for record in boundaries:
        key = str(record.get("function") or "")
        if key:
            boundary_by_function[key].append(record)
    confirmed_bad = {
        key
        for key, records in boundary_by_function.items()
        if any(
            record.get("causal_status") == "first_bad_transformation"
            for record in records
        )
    }
    trace_anchors = {
        str(value)
        for value in trace_plan.get("trace_anchors") or []
        if str(value) in runtime_functions
    }
    plan_terms = set(semantic_tokens(
        trace_plan.get("trace_terms") or []
    ))
    observed_probe_functions = defaultdict(int)
    for request in (probe_evidence or {}).get("requests") or []:
        if (
            request.get("status") == "observed"
            and request.get("kind") in {
                "argument",
                "return_value",
                "branch_outcome",
                "output_write",
                "call_result",
            }
        ):
            function = str(request.get("function") or "")
            if function:
                observed_probe_functions[function] += len(
                    request.get("observations") or []
                )
    supported_hypotheses = {}
    for hypothesis_index, hypothesis in enumerate(
        trace_plan.get("hypotheses") or []
    ):
        if not isinstance(hypothesis, dict):
            continue
        support = hypothesis.get("support") or {}
        candidate = str(
            hypothesis.get("candidate_function")
            or support.get("candidate_function")
            or ""
        )
        if (
            candidate in runtime_functions
            and support.get("status") == "source_runtime_supported"
        ):
            chain = [
                str(value)
                for value in hypothesis.get("causal_chain") or []
                if str(value)
            ] or [candidate]
            observed_count = sum(
                observed_probe_functions.get(function, 0)
                for function in chain
            )
            supported_hypotheses.setdefault(candidate, {
                "hypothesis_index": hypothesis_index,
                "runtime_probe_observation_count": observed_count,
            })
    dossiers = (source_evidence or {}).get("dossiers") or {}
    exception_trace_keys = set(
        (evidence.get("failure_seeds") or {}).get(
            "exception_trace_keys"
        )
        or []
    )
    records = []
    features = {}
    for function_key, runtime in runtime_functions.items():
        direct_seed, direct_reasons = _candidate_failure_seed(
            function_key, evidence
        )
        tokens = set(semantic_tokens([
            function_key,
            str(runtime.get("function") or ""),
            str(runtime.get("source_path") or ""),
        ]))
        plan_matches = sorted(tokens & plan_terms)
        semantic_matches = (
            (semantic_affinities.get(function_key) or {}).get("matches")
            or []
        )
        dossier = dossiers.get(function_key) or {}
        source_contract_matches = (
            dossier.get("contract_token_matches") or []
        )
        source_behavior_boundary = bool(
            dossier.get("returns")
            or dossier.get("conditions")
            or dossier.get("assignments")
            or dossier.get("throws")
        )
        function_boundaries = boundary_by_function.get(function_key) or []
        last_exit = max(
            [
                int(item.get("exit_event") or -1)
                for item in function_boundaries
            ]
            or [-1]
        )
        producer_distance = producer_distances.get(function_key)
        active = bool(runtime.get("active_at_failure_count"))
        if function_key in confirmed_bad:
            tier = 0
            tier_reason = "observed_first_bad_boundary_transformation"
        elif function_key in supported_hypotheses:
            tier = 1
            tier_reason = "source_runtime_supported_causal_hypothesis"
        elif function_key in exception_trace_keys:
            tier = 2
            tier_reason = "observed_exception_throw_boundary"
        elif (
            function_key in member_keys
            and source_contract_matches
            and source_behavior_boundary
        ):
            tier = 3
            tier_reason = "source_semantic_boundary_matches_failure_contract"
        elif function_key in trace_anchors and function_key in member_keys:
            tier = 4
            tier_reason = "trace_plan_anchor_in_failing_invocation"
        elif plan_matches and function_key in member_keys:
            tier = 5
            tier_reason = "input_output_trace_term_in_failing_invocation"
        elif (
            function_key in roots
            or (direct_seed and function_key in member_keys)
        ):
            tier = 6
            tier_reason = "direct_asserted_output_producer_boundary"
        elif function_key in member_keys:
            tier = 7
            tier_reason = "member_of_first_failing_producer_invocation"
        elif producer_distance is not None:
            tier = 8
            tier_reason = "dynamic_producer_graph_path"
        elif active:
            tier = 9
            tier_reason = "active_failure_stack"
        else:
            tier = 10
            tier_reason = "executed_outside_selected_causal_region"
        distance_order = (
            int(producer_distance)
            if producer_distance is not None
            else len(runtime_functions) + 1
        )
        reverse_distance = (
            int(runtime.get("best_reverse_distance"))
            if runtime.get("best_reverse_distance") is not None
            else len(runtime_functions) + 1
        )
        hypothesis_record = supported_hypotheses.get(
            function_key
        ) or {}
        hypothesis_order = int(
            hypothesis_record.get(
                "hypothesis_index", len(runtime_functions) + 1
            )
        )
        hypothesis_probe_count = int(
            hypothesis_record.get(
                "runtime_probe_observation_count", 0
            )
        )
        slice_depth = float(
            (producer_slices.get(function_key) or {}).get("depth") or 0.0
        )
        sort_key = (
            tier,
            -hypothesis_probe_count,
            hypothesis_order,
            -len(source_contract_matches),
            -int(source_behavior_boundary),
            -slice_depth,
            distance_order,
            -last_exit,
            reverse_distance,
            function_key,
        )
        records.append((sort_key, function_key))
        features[function_key] = {
            "causal_tier": tier,
            "tier_reason": tier_reason,
            "trace_plan_anchor": function_key in trace_anchors,
            "trace_plan_term_matches": plan_matches,
            "semantic_io_matches": semantic_matches,
            "source_contract_matches": source_contract_matches,
            "source_behavior_boundary": source_behavior_boundary,
            "source_evidence_available": bool(
                dossier.get("source_available")
            ),
            "causal_hypothesis_supported": (
                function_key in supported_hypotheses
            ),
            "hypothesis_runtime_probe_observation_count": (
                hypothesis_probe_count
            ),
            "producer_cone_membership": function_key in member_keys,
            "producer_cone_roots": (
                (producer_slices.get(function_key) or {}).get("roots")
                or []
            ),
            "producer_distance": producer_distance,
            "boundary_observation_count": len(function_boundaries),
            "last_boundary_exit_event": last_exit,
            "boundary_data_status": (
                "observed"
                if function_key in confirmed_bad
                else (
                    "control_only"
                    if function_boundaries
                    else "not_in_selected_invocation"
                )
            ),
            "direct_seed_reasons": direct_reasons,
        }
    records.sort(key=lambda item: item[0])
    count = len(records)
    scores = {}
    for ordinal, (_, function_key) in enumerate(records, 1):
        # Scores encode ordinal only; causal tier and tie-break are explicit.
        score = float(count - ordinal + 1)
        scores[function_key] = score
        features[function_key]["ordinal_rank"] = ordinal
        features[function_key]["final_score"] = score
    return scores, features, {
        "policy": "lexicographic_causal_tiers_no_fitted_weights",
        "tier_definitions": {
            "0": "observed first bad boundary transformation",
            "1": "source/runtime-supported causal hypothesis",
            "2": "observed exception throw boundary",
            "3": "source semantic boundary matches failure contract",
            "4": "trace-plan anchor in first failing invocation",
            "5": "input/output trace-term match in invocation",
            "6": "direct asserted-output producer boundary",
            "7": "other invocation member",
            "8": "dynamic producer graph path",
            "9": "active failure stack",
            "10": "other executed function",
        },
        "first_bad_transformation_confirmed": bool(confirmed_bad),
        "boundary_data_available": bool(confirmed_bad),
        "boundary_data_gap": (
            ""
            if confirmed_bad
            else (
                "function enter/exit is available, but arguments, return "
                "values and output-reaching writes are not instrumented"
            )
        ),
        "selected_invocation_count": len(invocations),
        "selected_member_count": len(member_keys),
        "trace_anchor_count": len(trace_anchors),
        "supported_hypothesis_count": len(supported_hypotheses),
        "source_dossier_count": len(dossiers),
    }


def _candidate_failure_seed(
    function_key: str, evidence: Dict[str, Any]
) -> Tuple[float, List[str]]:
    file_key = _extract_file_from_key(function_key)
    qualified, leaf = _function_identity(function_key)
    seeds = evidence.get("failure_seeds") or {}
    stack_frames = seeds.get("stack_frames") or []
    near_calls = seeds.get("near_failure_call_symbols") or []
    producer_calls = seeds.get("producer_call_symbols") or []
    test_calls = seeds.get("test_call_symbols") or []
    output_symbols = seeds.get("output_symbols") or []
    active_trace_keys = set(seeds.get("active_trace_keys") or [])
    score = 0.0
    reasons = []

    if function_key in active_trace_keys:
        score = 1.0
        reasons.append("ordered_trace_active_stack_match")

    for frame in stack_frames:
        frame_function = str(frame.get("function") or "")
        frame_file = os.path.basename(str(frame.get("path") or ""))
        if _symbol_matches(qualified, leaf, frame_function):
            score = 1.0
            reasons.append("runtime_stack_function_match")
        elif frame_file and frame_file == file_key:
            score = 1.0
            reasons.append("runtime_stack_file_match")

    if any(_symbol_matches(qualified, leaf, value) for value in producer_calls):
        score = 1.0
        reasons.append("asserted_output_producer_call_match")
    elif any(_symbol_matches(qualified, leaf, value) for value in near_calls):
        score = 1.0
        reasons.append("near_failure_test_call_match")
    elif any(_symbol_matches(qualified, leaf, value) for value in test_calls):
        score = 1.0
        reasons.append("failing_test_call_match")

    if any(_symbol_matches(qualified, leaf, value) for value in output_symbols):
        score = 1.0
        reasons.append("failure_output_symbol_match")
    return score, list(dict.fromkeys(reasons))


def _semantic_io_affinities(
    *,
    runtime_functions: Dict[str, Dict[str, Any]],
    evidence: Dict[str, Any],
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Return binary exact-token overlap with no fitted threshold or weight."""
    evidence_tokens = list(dict.fromkeys(
        str(value)
        for value in (
            (evidence.get("failure_seeds") or {}).get(
                "semantic_io_tokens"
            )
            or []
        )
        if str(value)
    ))
    candidate_tokens = {}
    for key, runtime in runtime_functions.items():
        candidate_tokens[key] = semantic_tokens([
            key,
            str(runtime.get("function") or ""),
            str(runtime.get("source_path") or ""),
        ])
    matched_tokens = {}
    for key, tokens in candidate_tokens.items():
        matches = [
            token
            for token in evidence_tokens
            if any(_semantic_token_match(token, item) for item in tokens)
        ]
        matched_tokens[key] = matches
    scores = {
        key: {
            "score": 1.0 if matched_tokens[key] else 0.0,
            "matches": matched_tokens[key][:24],
        }
        for key in runtime_functions
    }
    semantic_tests = [
        test.get("io_semantics") or {}
        for test in evidence.get("tests") or []
        if isinstance(test, dict)
    ]
    return scores, {
        "tokens": evidence_tokens,
        "matched_tokens": sorted(set(
            token
            for matches in matched_tokens.values()
            for token in matches
        )),
        "compiler_semantics_available": any(
            bool(item.get("available")) for item in semantic_tests
        ),
        "providers": list(dict.fromkeys(
            str(item.get("provider") or "")
            for item in semantic_tests
            if str(item.get("provider") or "")
        )),
        "diagnostics": list(dict.fromkeys(
            str(value)
            for item in semantic_tests
            for value in item.get("diagnostics") or []
            if str(value)
        )),
        "scoring": "binary exact-token overlap; no threshold or fitted weight",
    }


def _semantic_token_match(left: str, right: str) -> bool:
    left = str(left or "").lower()
    right = str(right or "").lower()
    if not left or not right:
        return False
    return left == right


def _producer_graph_distances(
    *,
    runtime_functions: Dict[str, Dict[str, Any]],
    dynamic_edges: List[Dict[str, Any]],
    evidence: Dict[str, Any],
) -> Dict[str, int]:
    seeds = evidence.get("failure_seeds") or {}
    observed_calls = [
        *(seeds.get("producer_call_symbols") or []),
        *(seeds.get("near_failure_call_symbols") or []),
        *(seeds.get("test_call_symbols") or []),
    ]
    roots = {
        key
        for key in runtime_functions
        if any(
            _symbol_matches(*_function_identity(key), observed)
            for observed in observed_calls
        )
    }
    graph = defaultdict(set)
    for edge in dynamic_edges:
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if caller and callee:
            graph[caller].add(callee)
    distances = {}
    queue = deque((root, 0) for root in roots)
    while queue:
        key, distance = queue.popleft()
        if key in distances and distances[key] <= distance:
            continue
        distances[key] = distance
        for child in graph.get(key, ()):
            queue.append((child, distance + 1))
    return distances


def _dynamic_producer_slices(
    *,
    runtime_evidence: Dict[str, Any],
    evidence: Dict[str, Any],
    regression_count: int,
    selected_scenario: Dict[str, Any] = None,
) -> Tuple[Dict[str, Dict[str, Any]], Dict[str, Any]]:
    """Slice the concrete invocation that produced the asserted expression."""
    runtime_by_id = {
        str(item.get("test_id") or ""): item
        for item in runtime_evidence.get("tests") or []
        if isinstance(item, dict)
    }
    features: Dict[str, Dict[str, Any]] = {}
    invocations = []
    diagnostics = []
    for test in evidence.get("tests") or []:
        test_id = str(test.get("test_id") or "")
        selected_test_id = str(
            (selected_scenario or {}).get("test_id") or ""
        )
        if selected_test_id and test_id != selected_test_id:
            continue
        runtime_test = runtime_by_id.get(test_id) or {}
        events = runtime_test.get("events") or []
        if not events:
            diagnostics.append(f"{test_id}:ordered_events_unavailable")
            continue
        marker_id = str(
            (selected_scenario or {}).get("source_marker_id") or ""
        )
        window_start, window_end = _scenario_event_window(
            events, marker_id=marker_id
        )
        if window_start or window_end < len(events):
            diagnostics.append(
                f"{test_id}:scenario_marker_window_used:"
                f"{window_start}:{window_end}"
            )
        scoped_events = events[window_start:window_end]
        sites_by_observation = defaultdict(list)
        for site in test.get("producer_call_sites") or []:
            selected_observation = (
                (selected_scenario or {}).get("observation_index")
            )
            if (
                selected_observation is not None
                and int(site.get("observation_index") or 0)
                != int(selected_observation)
            ):
                continue
            sites_by_observation[
                int(site.get("observation_index") or 0)
            ].append(site)
        if not sites_by_observation:
            sites_by_observation[0] = []
        selected_ranges = set()
        event_end_before = len(scoped_events)
        for observation_index, producer_sites in sorted(
            sites_by_observation.items(), reverse=True
        ):
            selection = _select_producer_invocation(
                events=scoped_events[:event_end_before],
                producer_sites=producer_sites,
                fallback_calls=(
                    test.get("near_failure_call_symbols")
                    or test.get("test_call_symbols")
                    or []
                ),
                test_source_path=str(
                    test.get("resolved_test_source_path") or ""
                ),
            )
            if (
                not selection
                and int(runtime_test.get("trace_event_count") or 0)
                > len(events)
                and producer_sites
            ):
                graph_invocation = _aggregate_graph_producer_invocation(
                    runtime_test=runtime_test,
                    producer_sites=producer_sites,
                    test_id=test_id,
                    observation_index=observation_index,
                )
                if graph_invocation:
                    for key in graph_invocation["member_keys"]:
                        record = features.setdefault(key, {
                            "test_ids": set(),
                            "roots": set(),
                            "max_depth_score": 0.0,
                            "max_span_score": 0.0,
                        })
                        record["test_ids"].add(test_id)
                        record["roots"].update(
                            graph_invocation["root_keys"]
                        )
                    invocations.append(graph_invocation)
                    diagnostics.append(
                        f"{test_id}:observation_{observation_index}:"
                        "full_events_unavailable_used_aggregate_graph"
                    )
                    continue
            if not selection:
                diagnostics.append(
                    f"{test_id}:observation_{observation_index}:"
                    "producer_invocation_not_found"
                )
                continue
            start, end, selected_site = selection
            start += window_start
            end += window_start
            if (start, end) in selected_ranges:
                continue
            selected_ranges.add((start, end))
            observation_start = selected_site.get("observation_event_start")
            event_end_before = min(
                start - window_start,
                (
                    int(observation_start)
                    if observation_start is not None
                    else start - window_start
                ),
            )
            invocation = events[start:end + 1]
            root = invocation[0]
            root_depth = int(root.get("depth") or 0)
            max_relative_depth = max(
                [
                    max(0, int(item.get("depth") or 0) - root_depth)
                    for item in invocation
                    if item.get("event") == "enter"
                ]
                or [1]
            )
            spans = _invocation_spans(invocation)
            root_span = max(1, end - start)
            per_function_depth = defaultdict(int)
            members = set()
            for item in invocation:
                if item.get("event") != "enter":
                    continue
                key = str(item.get("key") or "")
                if not key:
                    continue
                members.add(key)
                per_function_depth[key] = max(
                    per_function_depth[key],
                    max(0, int(item.get("depth") or 0) - root_depth),
                )
            for key in members:
                depth_score = min(
                    1.0,
                    per_function_depth[key] / max(1, max_relative_depth),
                )
                span_score = min(
                    1.0,
                    math.log1p(spans.get(key, 0)) / math.log1p(root_span),
                )
                record = features.setdefault(key, {
                    "test_ids": set(),
                    "roots": set(),
                    "max_depth_score": 0.0,
                    "max_span_score": 0.0,
                })
                record["test_ids"].add(test_id)
                record["roots"].add(str(root.get("key") or ""))
                record["max_depth_score"] = max(
                    record["max_depth_score"], depth_score
                )
                record["max_span_score"] = max(
                    record["max_span_score"], span_score
                )
            invocations.append({
                "test_id": test_id,
                "observation_index": observation_index,
                "root": root.get("key"),
                "event_start": start,
                "event_end": end,
                "event_count": len(invocation),
                "invocation_id": str(
                    root.get("invocation_id") or ""
                ),
                "parent_invocation_id": str(
                    root.get("parent_invocation_id") or ""
                ),
                "callsite_id": str(root.get("callsite_id") or ""),
                "call_source_path": root.get("call_source_path") or "",
                "call_source_line": int(root.get("call_source_line") or 0),
                "producer_site": selected_site,
                "member_count": len(members),
                "member_keys": sorted(members),
                "boundary_records": _invocation_boundary_records(
                    invocation
                ),
            })

    normalized = {}
    for key, record in features.items():
        support = min(
            1.0, len(record["test_ids"]) / max(1, regression_count)
        )
        normalized[key] = {
            "score": support,
            "membership": support,
            "depth": float(record["max_depth_score"]),
            "span": float(record["max_span_score"]),
            "test_ids": sorted(record["test_ids"]),
            "roots": sorted(record["roots"]),
        }
    return normalized, {
        "available": bool(invocations),
        "invocations": invocations,
        "diagnostics": diagnostics,
    }


def _aggregate_graph_producer_invocation(
    *,
    runtime_test: Dict[str, Any],
    producer_sites: List[Dict[str, Any]],
    test_id: str,
    observation_index: int,
) -> Dict[str, Any]:
    """Conservative fallback when an old cache retained only the trace tail."""
    functions = runtime_test.get("functions") or {}
    calls = [
        str(value)
        for site in producer_sites
        for value in site.get("calls") or []
        if str(value)
    ]
    roots = {
        key
        for key in functions
        if any(
            _symbol_matches(*_function_identity(key), call)
            for call in calls
        )
    }
    if not roots:
        return {}
    graph = defaultdict(set)
    for edge in runtime_test.get("dynamic_edges") or []:
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if caller and callee:
            graph[caller].add(callee)
    members = set()
    queue = deque(roots)
    while queue:
        key = queue.popleft()
        if key in members:
            continue
        members.add(key)
        queue.extend(graph.get(key, ()))
    selected_site = min(
        producer_sites,
        key=lambda site: int(site.get("distance_to_failure") or 0),
    )
    return {
        "test_id": test_id,
        "observation_index": observation_index,
        "root": sorted(roots)[0],
        "root_keys": sorted(roots),
        "event_start": None,
        "event_end": None,
        "event_count": 0,
        "producer_site": selected_site,
        "member_count": len(members),
        "member_keys": sorted(members),
        "boundary_records": [],
        "selection_mode": "aggregate_dynamic_graph_fallback",
        "precision": "conservative; invocation identity unavailable",
    }


def _select_producer_invocation(
    *,
    events: List[Dict[str, Any]],
    producer_sites: List[Dict[str, Any]],
    fallback_calls: List[str],
    test_source_path: str,
) -> Tuple[int, int, Dict[str, Any]] | None:
    site_anchors = {}
    site_has_symbol_event = {}
    for site_index, site in enumerate(producer_sites):
        calls = site.get("calls") or []
        anchors = []
        has_symbol_event = False
        for event_index, event in enumerate(events):
            if event.get("event") != "enter":
                continue
            qualified, leaf = _function_identity(str(event.get("key") or ""))
            symbol_match = any(
                _symbol_matches(qualified, leaf, call) for call in calls
            )
            if symbol_match:
                has_symbol_event = True
            line_delta = _site_line_delta(event, site)
            if (
                line_delta is not None
                and line_delta == 0
                and _same_source_file(
                    str(event.get("call_source_path") or ""),
                    test_source_path,
                )
            ):
                anchors.append(event_index)
        site_anchors[site_index] = anchors
        site_has_symbol_event[site_index] = has_symbol_event

    candidates = []
    for index, event in enumerate(events):
        if event.get("event") != "enter":
            continue
        qualified, leaf = _function_identity(str(event.get("key") or ""))
        call_line = int(event.get("call_source_line") or 0)
        call_path = str(event.get("call_source_path") or "")
        for site_index, site in enumerate(producer_sites):
            calls = site.get("calls") or []
            primary_calls = site.get("primary_calls") or calls[:1]
            symbol_match = any(
                _symbol_matches(qualified, leaf, call) for call in calls
            )
            primary_match = any(
                _symbol_matches(qualified, leaf, call)
                for call in primary_calls
            )
            line_delta = _site_line_delta(event, site)
            line_match = line_delta == 0
            path_match = _same_source_file(call_path, test_source_path)
            if not symbol_match and site_has_symbol_event.get(site_index):
                continue
            if not symbol_match and not (line_match and path_match):
                continue
            anchors = site_anchors.get(site_index) or []
            if anchors and index < max(anchors):
                continue
            preceding_anchors = [
                anchor
                for anchor in anchors
                if anchor < index
            ]
            # Lexicographic structural priority: no fitted coefficients.
            priority = (
                str(site.get("role") or "") == "asserted_expression",
                primary_match,
                symbol_match,
                line_match and path_match,
                path_match,
                -(
                    int(line_delta)
                    if line_delta is not None
                    else float("inf")
                ),
                -int(event.get("depth") or 0),
            )
            observation_start = (
                max(preceding_anchors)
                if preceding_anchors
                else (index if index in anchors else None)
            )
            candidates.append((priority, index, site, observation_start))
    if not candidates:
        for index, event in enumerate(events):
            if event.get("event") != "enter":
                continue
            qualified, leaf = _function_identity(str(event.get("key") or ""))
            if any(
                _symbol_matches(qualified, leaf, call)
                for call in fallback_calls
            ):
                candidates.append((
                    (False, False, True, False, False, 0, 0),
                    index,
                    {},
                    None,
                ))
    if not candidates:
        return None
    _, start, site, observation_start = max(
        candidates, key=lambda item: (item[0], item[1])
    )
    site = dict(site)
    if observation_start is not None:
        site["observation_event_start"] = int(observation_start)
    root = events[start]
    root_invocation_id = str(root.get("invocation_id") or "")
    end = len(events) - 1
    for index in range(start + 1, len(events)):
        item = events[index]
        if (
            item.get("event") == "exit"
            and (
                (
                    root_invocation_id
                    and str(item.get("invocation_id") or "")
                    == root_invocation_id
                )
                or (
                    not root_invocation_id
                    and item.get("pid") == root.get("pid")
                    and item.get("tid") == root.get("tid")
                    and item.get("depth") == root.get("depth")
                    and item.get("key") == root.get("key")
                )
            )
        ):
            end = index
            break
    return start, end, site


def _scenario_event_window(
    events: List[Dict[str, Any]], *, marker_id: str
) -> Tuple[int, int]:
    """Return events produced by one explicitly instrumented assertion."""
    if not marker_id:
        return 0, len(events)
    matches = [
        index
        for index, event in enumerate(events)
        if event.get("event") == "marker"
        and event.get("marker_kind") == "scenario_begin"
        and str(event.get("marker_id") or "") == marker_id
    ]
    if not matches:
        return 0, len(events)
    start_marker = matches[-1]
    end = next(
        (
            index
            for index in range(start_marker + 1, len(events))
            if events[index].get("event") == "marker"
            and events[index].get("marker_kind") == "scenario_begin"
        ),
        len(events),
    )
    return start_marker + 1, end


def _site_line_delta(
    event: Dict[str, Any], site: Dict[str, Any]
) -> int | None:
    call_line = int(event.get("call_source_line") or 0)
    site_line = int(site.get("line") or 0)
    site_end_line = int(site.get("end_line") or site_line)
    if not call_line or not site_line:
        return None
    if site_line <= call_line <= site_end_line:
        return 0
    return min(
        abs(call_line - site_line),
        abs(call_line - site_end_line),
    )


def _invocation_spans(events: List[Dict[str, Any]]) -> Dict[str, int]:
    open_entries = {}
    spans = defaultdict(int)
    for index, item in enumerate(events):
        slot = (item.get("pid"), item.get("tid"), item.get("depth"))
        if item.get("event") == "enter":
            open_entries[slot] = (str(item.get("key") or ""), index)
            continue
        opened = open_entries.pop(slot, None)
        if opened and opened[0] == str(item.get("key") or ""):
            spans[opened[0]] = max(spans[opened[0]], index - opened[1])
    for key, index in open_entries.values():
        spans[key] = max(spans[key], len(events) - 1 - index)
    return dict(spans)


def _invocation_boundary_records(
    events: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    """Record control boundaries and explicitly mark unavailable data values."""
    open_entries = {}
    stack_by_thread = defaultdict(dict)
    records = []
    for index, item in enumerate(events):
        pid = item.get("pid")
        tid = item.get("tid")
        depth = int(item.get("depth") or 0)
        key = str(item.get("key") or "")
        slot = (pid, tid, depth)
        thread_stack = stack_by_thread[(pid, tid)]
        if item.get("event") == "enter":
            parent = str(thread_stack.get(depth - 1) or "")
            thread_stack[depth] = key
            for stale_depth in [
                value for value in thread_stack if value > depth
            ]:
                thread_stack.pop(stale_depth, None)
            open_entries[slot] = {
                "function": key,
                "caller": parent,
                "enter_event": index,
                "depth": depth,
                "call_source_path": item.get("call_source_path") or "",
                "call_source_line": int(
                    item.get("call_source_line") or 0
                ),
            }
            continue
        opened = open_entries.pop(slot, None)
        if not opened or opened["function"] != key:
            continue
        records.append({
            **opened,
            "exit_event": index,
            "event_span": index - int(opened["enter_event"]),
            "arguments": {"status": "not_instrumented"},
            "return_value": {"status": "not_instrumented"},
            "output_writes": {"status": "not_instrumented"},
            "causal_status": "control_boundary_only",
        })
        thread_stack.pop(depth, None)
    records.sort(key=lambda item: int(item["enter_event"]))
    return records[:400]


def _same_source_file(left: str, right: str) -> bool:
    if not left or not right:
        return False
    left = str(left).replace("\\", "/")
    right = str(right).replace("\\", "/")
    return (
        os.path.basename(left) == os.path.basename(right)
        or left.endswith("/" + right.lstrip("/"))
        or right.endswith("/" + left.lstrip("/"))
    )


def _aggregate_parent_scores(
    function_scores: Dict[str, float], *, key_func
) -> Dict[str, float]:
    grouped = defaultdict(list)
    for function_key, score in function_scores.items():
        parent = key_func(function_key)
        if parent:
            grouped[parent].append(float(score))
    return {
        key: max(values)
        for key, values in grouped.items()
    }


def _compact_runtime_evidence(value: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "schema": value.get("schema"),
        "engine": value.get("engine"),
        "fresh_execution": bool(value.get("fresh_execution")),
        "regression_test_ids": value.get("regression_test_ids") or [],
        "function_count": len(value.get("functions") or {}),
        "dynamic_edge_count": len(value.get("dynamic_edges") or []),
        "compile": value.get("compile") or {},
        "tests": [
            {
                "test_id": item.get("test_id"),
                "returncode": item.get("returncode"),
                "failed_as_expected": item.get("failed_as_expected"),
                "raw_trace_event_count": item.get("raw_trace_event_count"),
                "trace_event_count": item.get("trace_event_count"),
                "trace_truncated": item.get("trace_truncated"),
                "persisted_event_count": item.get("persisted_event_count"),
                "events_tail_truncated": item.get("events_tail_truncated"),
                "output_artifact": item.get("output_artifact"),
                "trace_artifact": item.get("trace_artifact"),
                "active_stack": item.get("active_stack") or [],
                "diagnostics": item.get("diagnostics") or [],
            }
            for item in value.get("tests") or []
        ],
        "diagnostics": value.get("diagnostics") or [],
    }


def _build_test_source_contexts(bug: Any, raw: Dict[str, Any]) -> Dict[str, Any]:
    """Resolve failing test definitions without consulting coverage metadata."""
    root = os.path.realpath(
        str(raw.get("buggy_tree_dir") or raw.get("source_repo_dir") or "")
    )
    paths = []
    for value in raw.get("test_files") or []:
        candidate = (
            str(value)
            if os.path.isabs(str(value))
            else os.path.join(root, str(value))
        )
        path = os.path.realpath(candidate)
        if root and _within(path, root) and os.path.isfile(path):
            paths.append(path)

    tests = []
    for record in getattr(bug, "tests", None) or []:
        if not _is_regression_failure(record):
            continue
        test_id = str(record.get("test_id") or "")
        test_qualifier = test_id.split("::")[-1]
        expected_identifiers = [
            value for value in re.split(r"[./]", test_qualifier) if value
        ][-2:]
        matches = []
        for path in paths:
            language = source_language_from_path(path)
            try:
                source = open(
                    path, "r", encoding="utf-8", errors="replace"
                ).read()
            except OSError:
                continue
            tree, source_bytes = parse_tree(source, language)
            if tree is None or source_bytes is None:
                continue
            for node in walk_nodes(tree.root_node):
                if node.type != "function_definition":
                    continue
                declarator = node.child_by_field_name("declarator")
                if declarator is None:
                    continue
                identifiers = {
                    node_text(child, source_bytes)
                    for child in walk_nodes(declarator)
                    if child.type in {
                        "identifier", "field_identifier", "type_identifier",
                    }
                }
                if (
                    expected_identifiers
                    and all(value in identifiers for value in expected_identifiers)
                ):
                    matches.append((path, node, source_bytes))
        focused = {"test_id": test_id}
        if len(matches) == 1:
            path, node, source_bytes = matches[0]
            focused.update({
                "test_source_path": path,
                "test_source_range": {
                    "start_byte": int(node.start_byte),
                    "end_byte": int(node.end_byte),
                    "start_line": int(node.start_point[0]) + 1,
                    "end_line": int(node.end_point[0]) + 1,
                },
                "test_source": node_text(node, source_bytes),
            })
        tests.append(focused)
    return {"tests": tests}


def _failure_observations(text: str) -> List[Dict[str, Any]]:
    """Extract every distinct failure location and its local output contract."""
    text = str(text or "")
    locations = list(re.finditer(
        r"(?P<path>(?:[A-Za-z]:)?[^:\n]*?\."
        r"(?:c|cc|cpp|cxx|h|hh|hpp|hxx)):(?P<line>\d+)",
        text,
        re.IGNORECASE,
    ))
    mode = _failure_mode(text)
    observations = []
    for index, location in enumerate(locations):
        path = str(location.group("path")).strip()
        line = int(location.group("line"))
        block_end = (
            locations[index + 1].start()
            if index + 1 < len(locations)
            else len(text)
        )
        block = text[location.start():block_end]
        observations.append({
            "failure_mode": _failure_mode(block, default=mode),
            "reported_source_path": path,
            "reported_line": line,
            "observed_output": _extract_expected_actual(block),
        })
    if observations:
        return observations[:24]
    return [{
        "failure_mode": mode,
        "reported_source_path": "",
        "reported_line": 0,
        "observed_output": _extract_expected_actual(text),
    }]


def _failure_observation(text: str) -> Dict[str, Any]:
    """Backward-compatible primary observation."""
    return _failure_observations(text)[0]


def _failure_mode(text: str, default: str = "nonzero_exit") -> str:
    lowered = str(text or "").lower()
    if "sanitizer" in lowered:
        return "sanitizer"
    elif "segmentation" in lowered or "signal" in lowered:
        return "crash"
    elif "assert" in lowered or "expected" in lowered:
        return "assertion"
    elif "timeout" in lowered:
        return "timeout"
    return default


def _resolve_test_source(
    *,
    raw: Dict[str, Any],
    test_id: str,
    focused: Dict[str, Any],
    observation: Dict[str, Any],
) -> Tuple[str, str, int]:
    del test_id
    focused_path = str(focused.get("test_source_path") or "")
    focused_range = focused.get("test_source_range") or {}
    path = _existing_source_path(focused_path, raw)
    if path:
        source, start = _read_source_range(path, focused_range)
        if source:
            return path, source, start

    reported_path = str(observation.get("reported_source_path") or "")
    path = _existing_source_path(reported_path, raw)
    if not path:
        return "", str(focused.get("test_source") or ""), int(
            focused_range.get("start_line") or 1
        )
    reported_line = int(observation.get("reported_line") or 0)
    source, start = _read_line_window(path, reported_line, radius=80)
    return path, source, start


def _existing_source_path(value: str, raw: Dict[str, Any]) -> str:
    if value and os.path.isfile(value):
        return os.path.realpath(value)
    buggy_root = os.path.realpath(str(raw.get("buggy_tree_dir") or ""))
    container_root = str(raw.get("container_repo_dir") or "").rstrip("/")
    normalized = str(value or "").replace("\\", "/")
    if buggy_root and container_root and normalized.startswith(container_root + "/"):
        candidate = os.path.realpath(
            os.path.join(buggy_root, normalized[len(container_root) + 1:])
        )
        if _within(candidate, buggy_root) and os.path.isfile(candidate):
            return candidate
    if buggy_root and normalized and not normalized.startswith("/"):
        candidate = os.path.realpath(os.path.join(buggy_root, normalized))
        if _within(candidate, buggy_root) and os.path.isfile(candidate):
            return candidate
    return ""


def _read_source_range(path: str, source_range: Dict[str, Any]) -> Tuple[str, int]:
    try:
        source = open(path, "r", encoding="utf-8", errors="replace").read()
    except OSError:
        return "", 1
    start_byte = int(source_range.get("start_byte") or -1)
    end_byte = int(source_range.get("end_byte") or -1)
    if 0 <= start_byte < end_byte <= len(source.encode("utf-8")):
        raw = source.encode("utf-8")
        return (
            raw[start_byte:end_byte].decode("utf-8", errors="replace"),
            int(source_range.get("start_line") or 1),
        )
    start_line = int(source_range.get("start_line") or 1)
    end_line = int(source_range.get("end_line") or 0)
    if end_line >= start_line:
        lines = source.splitlines()
        return "\n".join(lines[start_line - 1:end_line]), start_line
    return source, 1


def _read_line_window(path: str, line: int, radius: int) -> Tuple[str, int]:
    try:
        lines = open(path, "r", encoding="utf-8", errors="replace").read().splitlines()
    except OSError:
        return "", 1
    if line <= 0:
        return "\n".join(lines[: 2 * radius + 1]), 1
    start = max(1, line - radius)
    end = min(len(lines), line + radius)
    return "\n".join(lines[start - 1:end]), start


def _near_failure_source(
    source: str, *, source_start_line: int, reported_line: int
) -> str:
    if not source or reported_line <= 0:
        return ""
    lines = source.splitlines()
    local = reported_line - max(1, source_start_line)
    if local < 0 or local >= len(lines):
        return ""
    # The producer of an asserted value is normally immediately before the
    # assertion. Include a small forward tail for multi-line assertions.
    return "\n".join(lines[max(0, local - 16):min(len(lines), local + 5)])


def _extract_producer_call_sites(
    *,
    source: str,
    source_start_line: int,
    reported_line: int,
    output_expressions: List[str],
    language: str,
    observation_index: int = 0,
    source_path: str = "",
) -> List[Dict[str, Any]]:
    """Find test statements that can define/mutate the asserted output."""
    if not source:
        return []
    identifiers = set()
    for expression in output_expressions:
        identifiers.update(
            re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", expression)
        )
    lines = source.splitlines()
    failure_local = (
        reported_line - max(1, source_start_line)
        if reported_line > 0
        else len(lines) - 1
    )
    start = max(0, failure_local - 32)
    end = min(len(lines), failure_local + 2)
    sites = []

    # Parse the complete assertion statement. This is essential for a GTest
    # assertion whose producer call is on a continuation line.
    asserted_statement = _statement_containing_line(
        source, language=language, local_line=failure_local
    )
    expression_calls = []
    for expression in output_expressions:
        calls, _ = _extract_call_names(expression, language)
        expression_calls.extend(_ordered_useful_call_names(calls))
    if asserted_statement:
        statement, statement_start, statement_end = asserted_statement
        raw_calls, _ = _extract_call_names(statement, language)
        useful_calls = _ordered_useful_call_names(raw_calls)
        for call in raw_calls:
            macro = _canonical_symbol(call)
            if macro and macro.isupper():
                useful_calls.extend(
                    _macro_body_calls(
                        source_path, macro=macro, language=language
                    )
                )
        useful_calls = list(dict.fromkeys(useful_calls + expression_calls))
        if useful_calls:
            absolute_start = max(1, source_start_line) + statement_start
            absolute_end = max(1, source_start_line) + statement_end
            sites.append({
                "line": absolute_start,
                "end_line": absolute_end,
                "calls": useful_calls,
                "primary_calls": useful_calls[:1],
                "output_expression_matches": sorted(identifiers),
                "role": "asserted_expression",
                "observation_index": observation_index,
                "source": statement.strip()[:1000],
                "distance_to_failure": 0,
            })
    elif expression_calls:
        sites.append({
            "line": reported_line,
            "end_line": reported_line,
            "calls": list(dict.fromkeys(expression_calls)),
            "primary_calls": list(dict.fromkeys(expression_calls))[:1],
            "output_expression_matches": sorted(identifiers),
            "role": "asserted_expression",
            "observation_index": observation_index,
            "source": " | ".join(output_expressions)[:1000],
            "distance_to_failure": 0,
        })

    for local_line in range(start, end):
        text = lines[local_line]
        calls, _ = _extract_call_names(text, language)
        calls = _ordered_useful_call_names(calls)
        if not calls:
            continue
        expression_matches = sorted(
            identifier
            for identifier in identifiers
            if re.search(rf"\b{re.escape(identifier)}\b", text)
        )
        absolute_line = max(1, source_start_line) + local_line
        if any(
            item["role"] == "asserted_expression"
            and item["line"] <= absolute_line <= item["end_line"]
            for item in sites
        ):
            continue
        if identifiers and not expression_matches:
            continue
        sites.append({
            "line": absolute_line,
            "end_line": absolute_line,
            "calls": calls,
            "primary_calls": calls[:1],
            "output_expression_matches": expression_matches,
            "role": "producer",
            "observation_index": observation_index,
            "source": text.strip()[:500],
            "distance_to_failure": (
                max(0, reported_line - absolute_line)
                if reported_line
                else max(0, end - local_line)
            ),
        })
    sites.sort(
        key=lambda item: (
            item["role"] != "asserted_expression",
            item["distance_to_failure"],
            -len(item["output_expression_matches"]),
        )
    )
    return sites[:16]


def _macro_body_calls(
    source_path: str, *, macro: str, language: str
) -> List[str]:
    """Resolve calls hidden by a local multiline assertion wrapper macro."""
    if not source_path or not macro:
        return []
    try:
        lines = open(
            source_path, "r", encoding="utf-8", errors="replace"
        ).read().splitlines()
    except OSError:
        return []
    pattern = re.compile(
        rf"^\s*#\s*define\s+{re.escape(macro)}(?:\s|\()"
    )
    for index, line in enumerate(lines):
        if not pattern.search(line):
            continue
        body = [line]
        while body[-1].rstrip().endswith("\\") and index + len(body) < len(lines):
            body.append(lines[index + len(body)])
        if len(body) > 1:
            body_source = "\n".join(body[1:])
        else:
            body_source = pattern.sub("", body[0], count=1)
            body_source = re.sub(r"^\([^)]*\)\s*", "", body_source)
        calls, _ = _extract_call_names(
            body_source.replace("\\", ""), language
        )
        return _ordered_useful_call_names(calls)
    return []


def _statement_containing_line(
    source: str, *, language: str, local_line: int
) -> Tuple[str, int, int] | None:
    if not source or local_line < 0:
        return None
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return None
    candidates = []
    for node in walk_nodes(tree.root_node):
        if node.type not in {
            "expression_statement", "declaration", "return_statement",
        }:
            continue
        start = int(node.start_point[0])
        end = int(node.end_point[0])
        if start <= local_line <= end:
            candidates.append((end - start, int(node.end_byte - node.start_byte), node))
    if not candidates:
        return None
    node = min(candidates, key=lambda item: (item[0], item[1]))[2]
    return (
        node_text(node, source_bytes),
        int(node.start_point[0]),
        int(node.end_point[0]),
    )


def _extract_call_names(source: str, language: str) -> Tuple[List[str], str]:
    if not source:
        return [], "unavailable"
    tree, source_bytes = parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        names = []
        for node in walk_nodes(tree.root_node):
            if node.type not in _CALL_NODE_TYPES:
                continue
            function = node.child_by_field_name("function")
            if function is None:
                continue
            value = node_text(function, source_bytes).strip()
            if value:
                names.append(value)
        return names, "tree_sitter"

    # C++ grammar is optional in this repository. Keep a diagnosed lexical
    # fallback so missing grammar never disables FL.
    names = re.findall(
        r"(?<![A-Za-z0-9_])"
        r"([~A-Za-z_][A-Za-z0-9_:~]*(?:\s*<[^;{}()]{1,120}>)?)\s*\(",
        source,
    )
    return names, "lexical_fallback"


def _extract_stack_frames(text: str) -> List[Dict[str, Any]]:
    frames = []
    for line in str(text or "").splitlines():
        for pattern in _STACK_PATTERNS:
            match = pattern.search(line)
            if not match:
                continue
            data = match.groupdict()
            frames.append({
                "index": int(data.get("index") or len(frames)),
                "function": str(data.get("function") or ""),
                "path": str(data.get("path") or ""),
                "line": int(data.get("line") or 0),
            })
            break
    return _unique_dicts(frames)


def _extract_output_symbols(text: str) -> List[str]:
    symbols = set()
    for frame in _extract_stack_frames(text):
        value = str(frame.get("function") or "")
        if value:
            symbols.add(value)
    for line in str(text or "").splitlines():
        if not re.search(
            r"error|failure|assert|sanitizer|segmentation|summary|fatal",
            line,
            re.IGNORECASE,
        ):
            continue
        for value in re.findall(
            r"\b(?:[A-Za-z_][A-Za-z0-9_]*::)+[~A-Za-z_][A-Za-z0-9_~]*\b",
            line,
        ):
            symbols.add(value)
        for value in re.findall(
            r"\b[~A-Za-z_][A-Za-z0-9_~]{3,}\s*(?=\()", line
        ):
            symbols.add(value.strip())
    return sorted(
        value for value in symbols
        if _canonical_symbol(value).rsplit("::", 1)[-1].lower()
        not in _GENERIC_FAILURE_SYMBOLS
    )


def _extract_expected_actual(text: str) -> Dict[str, Any]:
    """Keep a compact, structured assertion/failure contract."""
    expected = []
    actual = []
    expressions = []
    signal = []
    pending = ""
    raw_lines = str(text or "").splitlines()
    equality = _extract_gtest_equality_contract(raw_lines)
    expected.extend(equality["expected"])
    actual.extend(equality["actual"])
    expressions.extend(equality["expressions"])
    last_value_label = ""
    for raw_line in raw_lines:
        line = raw_line.strip()
        if not line:
            continue
        if re.match(
            r"expected\s+(?:equality|inequality|near|double equality)\b",
            line,
            re.IGNORECASE,
        ):
            continue
        exception = re.search(
            r'(?:c\+\+\s+)?exception\s+with\s+description\s+"(.*)"'
            r"\s+thrown\b",
            line,
            re.IGNORECASE,
        )
        if exception:
            actual.append(exception.group(1))
        match = re.search(
            r"\b(expected|actual|which is|value of)\s*:?\s*(.*)$",
            line,
            re.IGNORECASE,
        )
        if match:
            label = match.group(1).lower()
            value = match.group(2).strip()
            if label == "expected":
                expected.append(value)
                pending = "" if value else "expected"
                last_value_label = "expected"
            elif label == "value of":
                expressions.append(value)
                pending = ""
                last_value_label = "actual"
            elif label == "which is":
                (expected if last_value_label == "expected" else actual).append(
                    value
                )
                pending = ""
            else:
                actual.append(value)
                pending = "" if value else "actual"
                last_value_label = "actual"
            continue
        if pending and len(line) <= 500:
            (expected if pending == "expected" else actual).append(line)
            pending = ""
        if re.search(
            r"assert|error|fail|fatal|sanitizer|segmentation|signal|exception",
            line,
            re.IGNORECASE,
        ):
            signal.append(line)
    return {
        "expected": list(dict.fromkeys(value for value in expected if value))[:12],
        "actual": list(dict.fromkeys(value for value in actual if value))[:12],
        "expressions": list(
            dict.fromkeys(value for value in expressions if value)
        )[:12],
        "failure_signals": list(dict.fromkeys(signal))[:20],
    }


def _extract_gtest_equality_contract(
    raw_lines: List[str],
) -> Dict[str, List[str]]:
    """Parse GTest's unlabeled two-expression equality diagnostic."""
    expected = []
    actual = []
    expressions = []
    for index, raw_line in enumerate(raw_lines):
        if not re.match(
            r"\s*expected\s+(?:equality|inequality|near|double equality)\b",
            raw_line,
            re.IGNORECASE,
        ):
            continue
        payload = []
        for candidate in raw_lines[index + 1:]:
            stripped = candidate.strip()
            if not stripped:
                continue
            if re.search(r":\d+:\s+Failure\s*$", stripped):
                break
            if stripped.startswith("["):
                break
            payload.append(stripped)
            if len(payload) >= 3:
                break
        if len(payload) < 2:
            continue
        actual_expression = payload[0]
        expressions.append(actual_expression)
        which = re.match(r"which is:\s*(.*)$", payload[1], re.IGNORECASE)
        if which:
            actual.append(which.group(1).strip())
            if len(payload) >= 3:
                expected.append(payload[2])
        else:
            actual.append(actual_expression)
            expected.append(payload[1])
    return {
        "expected": expected,
        "actual": actual,
        "expressions": expressions,
    }


def _extract_input_literals(source: str) -> List[str]:
    """Extract bounded literal inputs from the focused failing-test source."""
    values = []
    pattern = re.compile(
        r"""(?x)
        "(?:\\.|[^"\\])*"
        |'(?:\\.|[^'\\])*'
        |(?<![A-Za-z0-9_])[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)
        """
    )
    for match in pattern.finditer(str(source or "")):
        value = match.group(0)
        if value not in values:
            values.append(value)
        if len(values) >= 40:
            break
    return values


def _is_regression_failure(record: Dict[str, Any]) -> bool:
    before = str(record.get("outcome") or "").upper()
    after = str(record.get("outcome_fixed") or "").upper()
    return before in {"FAIL", "FAILED"} and after in {"PASS", "PASSED"}


def _useful_call_names(values: Iterable[str]) -> set:
    return set(_ordered_useful_call_names(values))


def _ordered_useful_call_names(values: Iterable[str]) -> List[str]:
    out = []
    for value in values:
        canonical = _canonical_symbol(value)
        leaf = canonical.rsplit("::", 1)[-1]
        if (
            not canonical
            or leaf.lower() in _CONTROL_WORDS
            or leaf.lower() in _GENERIC_FAILURE_SYMBOLS
            or leaf.isupper()
            or leaf.lower().startswith(_TEST_ASSERTION_PREFIXES)
        ):
            continue
        if canonical not in out:
            out.append(canonical)
    return out


def _function_identity(function_key: str) -> Tuple[str, str]:
    match = re.search(r"(?<!:):(?!:)", str(function_key or ""))
    value = function_key[match.end():] if match else str(function_key or "")
    canonical = _canonical_symbol(value)
    return canonical, canonical.rsplit("::", 1)[-1]


def _canonical_symbol(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r"\([^()]*\)\s*$", "", value)
    value = re.sub(r"\s*<[^;{}()]{1,120}>\s*$", "", value)
    value = re.sub(r"\s+", "", value)
    return value.lstrip("&*")


def _symbol_matches(qualified: str, leaf: str, observed: str) -> bool:
    observed = _canonical_symbol(observed)
    if not observed or not leaf:
        return False
    observed_leaf = observed.rsplit("::", 1)[-1]
    if (
        len(leaf) < 3
        or len(observed_leaf) < 3
        or observed_leaf.lower() in _GENERIC_FAILURE_SYMBOLS
    ):
        return False
    normalized_observed = re.sub(r"::v\d+(?=::)", "", observed)
    normalized_qualified = re.sub(r"::v\d+(?=::)", "", qualified)
    qualified_match = (
        normalized_observed == normalized_qualified
        or normalized_observed.endswith("::" + normalized_qualified)
        or normalized_qualified.endswith("::" + normalized_observed)
    )
    constructor_match = (
        normalized_qualified
        == normalized_observed + "::" + observed_leaf
    )
    if "::" in normalized_observed:
        return qualified_match or constructor_match
    return qualified_match or constructor_match or observed_leaf == leaf


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _unique_dicts(values: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out = []
    for value in values:
        key = tuple(sorted((str(k), str(v)) for k, v in value.items()))
        if key in seen:
            continue
        seen.add(key)
        out.append(value)
    return out
