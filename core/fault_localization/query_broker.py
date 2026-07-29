"""One census-time broker for all FL runtime investigation questions."""

from __future__ import annotations

import os
from collections import Counter
from typing import Any, Dict

from core.failure_context import build_regression_fail_context

from .artifacts import atomic_write_json
from .causal import collect_failure_evidence
from .investigation import load_or_build_source_evidence
from .probes import resolve_probe_evidence
from .scenario import build_scenario_analysis
from .trace_plan import build_trace_plan


QUERY_BROKER_SCHEMA = "unified_debugging.investigation_query_broker.v1"


def build_investigation_query_broker(
    *,
    bug: Any,
    census_by_test: Dict[str, Dict[str, Any]],
    refined_scopes: Dict[str, Dict[str, Any]],
    artifact_dir: str,
    use_llm: bool,
    provider: str = None,
) -> Dict[str, Any]:
    """Plan deterministic and LLM-guided probes before the sole probe build."""
    census_runtime = _aggregate_census_runtime(census_by_test)
    fail_context = build_regression_fail_context(
        bug,
        runtime_evidence=census_runtime,
    )
    try:
        failure_evidence = collect_failure_evidence(
            bug,
            runtime_evidence=census_runtime,
            fail_context=fail_context,
        )
        scenario_analysis = build_scenario_analysis(failure_evidence)
        scenario = (
            scenario_analysis.get("first_failing_scenario") or {}
        )
        invocation_keys = sorted({
            str(value)
            for scope in refined_scopes.values()
            for value in (
                scope.get("path_function_keys")
                or scope.get("detailed_function_keys")
                or []
            )
            if str(value)
        })
        source_evidence = load_or_build_source_evidence(
            bug=bug,
            runtime_evidence=census_runtime,
            scenario=scenario,
            invocation_keys=invocation_keys,
            artifact_dir=artifact_dir,
        )
        trace_plan = build_trace_plan(
            scenario_analysis=scenario_analysis,
            runtime_evidence=census_runtime,
            use_llm=use_llm,
            provider=provider,
            artifact_dir=artifact_dir,
            source_evidence=source_evidence,
            invocation_keys=invocation_keys,
        )
        pre_execution_probe_evidence = resolve_probe_evidence(
            trace_plan=trace_plan,
            source_evidence=source_evidence,
            runtime_evidence={
                **census_runtime,
                "trace_scope": {"tests": refined_scopes},
            },
            invocation_keys=invocation_keys,
            artifact_dir="",
        )
        planned_probes = [
            dict(item)
            for item in (
                pre_execution_probe_evidence.get(
                    "runtime_probe_requests"
                )
                or []
            )
            if isinstance(item, dict)
        ]
        result = {
            "schema": QUERY_BROKER_SCHEMA,
            "version": 1,
            "status": (
                "planned"
                if planned_probes
                else "planned_without_runtime_probes"
            ),
            "phase": "post_census_pre_detailed_execution",
            "fail_context_id": fail_context.get("context_id", ""),
            "scenario_id": (
                scenario.get("scenario_id")
                or scenario.get("scenario_fingerprint")
                or ""
            ),
            "trace_plan": trace_plan,
            "planned_probes": planned_probes,
            "planned_probe_count": len(planned_probes),
            "execution_policy": {
                "probe_build_pass_limit": 1,
                "post_ranking_runtime_passes": 0,
                "overflow_recovery": "probe_only_single_pass",
                "missing_evidence_policy": "unknown_never_negative",
            },
            "source_evidence_identity": source_evidence.get(
                "identity", ""
            ),
            "diagnostics": [],
        }
    except Exception as exc:
        result = {
            "schema": QUERY_BROKER_SCHEMA,
            "version": 1,
            "status": "planning_failed",
            "phase": "post_census_pre_detailed_execution",
            "fail_context_id": fail_context.get("context_id", ""),
            "trace_plan": {},
            "planned_probes": [],
            "planned_probe_count": 0,
            "execution_policy": {
                "probe_build_pass_limit": 1,
                "post_ranking_runtime_passes": 0,
                "missing_evidence_policy": "unknown_never_negative",
            },
            "diagnostics": [
                f"investigation_query_planning_failed:"
                f"{type(exc).__name__}"
            ],
        }
    if artifact_dir:
        path = atomic_write_json(
            os.path.join(
                artifact_dir, "investigation_query_broker.json"
            ),
            result,
        )
        if path:
            result["artifact"] = path
    return result


def merge_broker_probes_into_scopes(
    *,
    refined_scopes: Dict[str, Dict[str, Any]],
    census_by_test: Dict[str, Dict[str, Any]],
    broker: Dict[str, Any],
    max_probes_per_test: int,
    sample_limit: int,
) -> Dict[str, Any]:
    """Merge broker branch questions into existing bounded slice probes."""
    planned = [
        item
        for item in broker.get("planned_probes") or []
        if isinstance(item, dict)
    ]
    installed_candidates = set()
    dropped = []
    for test_id, scope in refined_scopes.items():
        census_functions = (
            (census_by_test.get(test_id) or {}).get("functions") or {}
        )
        existing = [
            dict(item)
            for item in scope.get("slice_probes") or []
            if isinstance(item, dict)
        ]
        identities = {
            _probe_site_identity(item)
            for item in existing
        }
        budget = max(
            0,
            int(scope.get("slice_probe_event_reserve") or 0),
        )
        estimated = sum(
            max(1, int(item.get("estimated_event_count") or 1))
            for item in existing
        )
        for raw_probe in planned:
            function = str(raw_probe.get("function") or "")
            if function not in census_functions:
                continue
            identity = _probe_site_identity(raw_probe)
            if identity in identities:
                installed_candidates.add(
                    str(raw_probe.get("probe_id") or "")
                )
                continue
            execution_count = max(
                1,
                int(
                    (census_functions.get(function) or {}).get(
                        "coverage_enter_count"
                    )
                    or (census_functions.get(function) or {}).get(
                        "enter_count"
                    )
                    or 1
                ),
            )
            cost = min(execution_count, max(1, int(sample_limit)))
            if (
                len(existing) >= max(1, int(max_probes_per_test))
                or estimated + cost > budget
            ):
                dropped.append({
                    "test_id": test_id,
                    "probe_id": raw_probe.get("probe_id"),
                    "reason": "shared_probe_budget_exhausted",
                })
                continue
            probe = {
                **raw_probe,
                "execution_count": execution_count,
                "estimated_event_count": cost,
                "origin": "shared_investigation_query_broker",
            }
            existing.append(probe)
            identities.add(identity)
            estimated += cost
            installed_candidates.add(
                str(raw_probe.get("probe_id") or "")
            )
        scope["slice_probes"] = existing
        scope["slice_probe_count"] = len(existing)
        scope["estimated_probe_event_count"] = estimated
        scope["estimated_total_event_count"] = (
            int(scope.get("estimated_detailed_event_count") or 0)
            + estimated
        )
        scope["slice_probe_limit_per_id"] = (
            max(1, budget // max(1, len(existing)))
            if existing and budget
            else 0
        )
    broker["eligible_probe_ids"] = sorted(
        value for value in installed_candidates if value
    )
    broker["budget_dropped_probes"] = dropped
    broker["budget_dropped_probe_count"] = len(dropped)
    return broker


def _aggregate_census_runtime(
    census_by_test: Dict[str, Dict[str, Any]],
) -> Dict[str, Any]:
    functions: Dict[str, Dict[str, Any]] = {}
    edges = Counter()
    tests = []
    for test_id, test in census_by_test.items():
        tests.append(test)
        for key, raw in (test.get("functions") or {}).items():
            if not isinstance(raw, dict):
                continue
            record = functions.setdefault(str(key), {
                **raw,
                "test_ids": [],
                "enter_count": 0,
                "coverage_enter_count": 0,
            })
            record["test_ids"].append(str(test_id))
            record["enter_count"] += int(raw.get("enter_count") or 0)
            record["coverage_enter_count"] += int(
                raw.get("coverage_enter_count") or 0
            )
        for edge in test.get("dynamic_edges") or []:
            caller = str(edge.get("caller") or "")
            callee = str(edge.get("callee") or "")
            if caller and callee:
                edges[(caller, callee)] += int(
                    edge.get("count") or 1
                )
    for record in functions.values():
        record["test_ids"] = sorted(set(record["test_ids"]))
    return {
        "schema": "unified_debugging.census_runtime.v1",
        "fresh_execution": True,
        "regression_test_ids": sorted(census_by_test),
        "tests": tests,
        "functions": functions,
        "dynamic_edges": [
            {"caller": caller, "callee": callee, "count": count}
            for (caller, callee), count in edges.most_common()
        ],
    }


def _probe_site_identity(probe: Dict[str, Any]) -> tuple:
    return (
        str(probe.get("function") or ""),
        str(probe.get("kind") or ""),
        int(probe.get("line") or 0),
        str(probe.get("expression") or ""),
    )
