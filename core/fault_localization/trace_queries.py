"""Question-driven runtime evidence contracts for fault localization.

The runtime collector still owns execution and instrumentation.  This module
keeps the policy explicit: a trace run answers concrete questions and missing
evidence is never silently treated as negative evidence.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Set


TRACE_QUERY_PLAN_SCHEMA = "unified_debugging.trace_query_plan.v1"
TRACE_QUERY_EVIDENCE_SCHEMA = "unified_debugging.trace_query_evidence.v1"

_BOUNDARY_KINDS = {
    "argument",
    "return_value",
    "output_write",
    "branch_outcome",
    "call_result",
}


def build_trace_query_plan(
    *,
    test_id: str,
    fail_context: Dict[str, Any],
    trace_scope: Dict[str, Any],
    installed_probe_ids: Optional[Iterable[str]] = None,
) -> Dict[str, Any]:
    """Build small evidence requests from one failure and its census slice."""
    installed = {
        str(value)
        for value in (installed_probe_ids or [])
        if str(value)
    }
    failure_test = next(
        (
            item
            for item in (fail_context or {}).get("tests") or []
            if isinstance(item, dict)
            and str(item.get("test_id") or "") == str(test_id or "")
        ),
        {},
    )
    scenario_id = str(trace_scope.get("scenario_id") or "")
    context_id = str((fail_context or {}).get("context_id") or "")
    requests: List[Dict[str, Any]] = []

    path_keys = [
        str(value)
        for value in trace_scope.get("path_function_keys") or []
        if str(value)
    ]
    roots = [
        str(value)
        for value in trace_scope.get("producer_root_keys") or []
        if str(value)
    ]
    sinks = [
        str(value)
        for value in trace_scope.get("output_error_sink_keys") or []
        if str(value)
    ]
    requests.append({
        "request_id": _stable_id(
            "trace_query",
            {
                "test_id": test_id,
                "scenario_id": scenario_id,
                "kind": "producer_to_sink_control_path",
                "roots": roots,
                "sinks": sinks,
            },
        ),
        "question": (
            "Which freshly executed producer-to-sink control paths can carry "
            "the failing test observation?"
        ),
        "kind": "producer_to_sink_control_path",
        "collection": "aggregate_census",
        "producer_root_keys": roots,
        "sink_keys": sinks,
        "function_keys": path_keys,
        "status": "pending",
    })

    for probe in trace_scope.get("slice_probes") or []:
        if not isinstance(probe, dict):
            continue
        probe_id = str(probe.get("probe_id") or "")
        kind = str(probe.get("kind") or "")
        if not probe_id or kind not in _BOUNDARY_KINDS:
            continue
        requests.append({
            "request_id": _stable_id(
                "trace_query",
                {
                    "test_id": test_id,
                    "scenario_id": scenario_id,
                    "probe_id": probe_id,
                },
            ),
            "question": _probe_question(
                kind=kind,
                function=str(probe.get("function") or ""),
                expression=str(probe.get("expression") or ""),
            ),
            "kind": kind,
            "collection": "source_probe",
            "probe_id": probe_id,
            "function": str(probe.get("function") or ""),
            "source_path": str(probe.get("source_path") or ""),
            "line": int(probe.get("line") or 0),
            "expression": str(probe.get("expression") or ""),
            "evidence_semantics": (
                "scalar_value"
                if kind == "branch_outcome"
                else "boundary_occurrence"
            ),
            "expected_execution_count": int(
                probe.get("execution_count") or 0
            ),
            "sample_limit": int(
                trace_scope.get("slice_probe_limit_per_id") or 0
            ),
            "installed": probe_id in installed,
            "status": "pending" if probe_id in installed else "not_instrumented",
        })

    plan_identity = {
        "test_id": str(test_id or ""),
        "context_id": context_id,
        "scenario_id": scenario_id,
        "requests": [
            {
                "request_id": item["request_id"],
                "kind": item["kind"],
                "probe_id": item.get("probe_id", ""),
            }
            for item in requests
        ],
    }
    return {
        "schema": TRACE_QUERY_PLAN_SCHEMA,
        "version": 1,
        "plan_id": _stable_id("trace_plan", plan_identity),
        "test_id": str(test_id or ""),
        "scenario_id": scenario_id,
        "fail_context_id": context_id,
        "failure_observation": (
            failure_test.get("failure_observation") or {}
        ),
        "execution_policy": {
            "strategy": "aggregate_census_then_targeted_questions",
            "global_event_limit_escalation": False,
            "overflow_recovery": "probe_only_single_pass",
            "missing_evidence_policy": "unknown_never_negative",
        },
        "requests": requests,
    }


def evaluate_trace_query_plan(
    *,
    plan: Dict[str, Any],
    primary_result: Dict[str, Any],
    recovery_result: Optional[Dict[str, Any]] = None,
    primary_signature_match: Optional[bool] = None,
    recovery_signature_match: Optional[bool] = None,
) -> Dict[str, Any]:
    """Resolve query states without converting truncation into absence."""
    recovery = recovery_result if isinstance(recovery_result, dict) else {}
    primary_overflow = bool(primary_result.get("trace_truncated"))
    primary_probe_collection = _primary_probe_collection_available(
        primary_result
    )
    recovery_used = bool(recovery)
    recovery_overflow = bool(recovery.get("trace_truncated")) if recovery_used else False

    primary_observed = observed_probe_ids(primary_result)
    recovery_observed = (
        observed_probe_ids(recovery)
        if recovery_used and recovery_signature_match is not False
        else set()
    )
    observed = primary_observed | recovery_observed
    scalar_values = _scalar_values(primary_result)
    if recovery_used and recovery_signature_match is not False:
        for probe_id, values in _scalar_values(recovery).items():
            scalar_values.setdefault(probe_id, []).extend(values)

    resolved = []
    for raw_request in plan.get("requests") or []:
        request = dict(raw_request)
        if request.get("collection") == "aggregate_census":
            functions = request.get("function_keys") or []
            roots = request.get("producer_root_keys") or []
            if functions and roots:
                request["status"] = "observed"
                request["answer"] = {
                    "path_function_keys": functions,
                    "producer_root_keys": roots,
                    "sink_keys": request.get("sink_keys") or [],
                }
            else:
                request["status"] = "unknown_scope_unresolved"
            resolved.append(request)
            continue

        probe_id = str(request.get("probe_id") or "")
        if not request.get("installed"):
            request["status"] = "unknown_not_instrumented"
        elif primary_signature_match is False:
            request["status"] = "signature_mismatch"
        elif probe_id in observed:
            observed_status = (
                "observed"
                if request.get("evidence_semantics") == "scalar_value"
                else "observed_boundary"
            )
            expected_count = int(
                request.get("expected_execution_count") or 0
            )
            sample_limit = int(request.get("sample_limit") or 0)
            sampled = bool(
                expected_count
                and sample_limit
                and expected_count > sample_limit
            )
            request["status"] = (
                observed_status + "_sampled"
                if sampled
                else observed_status
            )
            request["sampling_complete"] = not sampled
            request["observations"] = scalar_values.get(probe_id) or []
        elif recovery_used and recovery_signature_match is False:
            request["status"] = "signature_mismatch"
        elif recovery_used and recovery_overflow:
            request["status"] = "incomplete_overflow"
        elif recovery_used:
            request["status"] = "observed_absent"
        elif primary_overflow:
            request["status"] = "incomplete_overflow"
        elif not primary_probe_collection:
            request["status"] = "unknown_not_collected"
        else:
            request["status"] = "observed_absent"
        resolved.append(request)

    status_counts: Dict[str, int] = {}
    for request in resolved:
        status = str(request.get("status") or "unknown")
        status_counts[status] = status_counts.get(status, 0) + 1
    incomplete = sum(
        count
        for status, count in status_counts.items()
        if status.startswith("unknown")
        or status in {"incomplete_overflow", "signature_mismatch"}
        or status.endswith("_sampled")
    )
    return {
        "schema": TRACE_QUERY_EVIDENCE_SCHEMA,
        "version": 1,
        "plan_id": plan.get("plan_id"),
        "test_id": plan.get("test_id"),
        "fail_context_id": plan.get("fail_context_id"),
        "status": "complete" if incomplete == 0 else "partial",
        "status_counts": status_counts,
        "primary_trace_overflow": primary_overflow,
        "primary_probe_collection_available": primary_probe_collection,
        "probe_recovery_used": recovery_used,
        "recovery_trace_overflow": recovery_overflow,
        "primary_signature_match": primary_signature_match,
        "recovery_signature_match": recovery_signature_match,
        "requests": resolved,
        "next_queries": _next_queries(resolved),
        "diagnostics": _query_diagnostics(
            primary_overflow=primary_overflow,
            recovery_used=recovery_used,
            recovery_overflow=recovery_overflow,
            primary_signature_match=primary_signature_match,
            recovery_signature_match=recovery_signature_match,
        ),
    }


def should_run_probe_recovery(
    plan: Dict[str, Any],
    primary_result: Dict[str, Any],
    *,
    primary_signature_match: Optional[bool],
) -> bool:
    """Recover missing probe answers, never by increasing the global E/X cap."""
    if primary_signature_match is False:
        return False
    pending_probe_ids = {
        str(item.get("probe_id") or "")
        for item in plan.get("requests") or []
        if item.get("collection") == "source_probe"
        and item.get("installed")
        and str(item.get("probe_id") or "")
    }
    missing = pending_probe_ids - observed_probe_ids(primary_result)
    if not missing:
        return False
    return bool(
        primary_result.get("trace_truncated")
        or not _primary_probe_collection_available(primary_result)
    )


def observed_probe_ids(runtime_result: Dict[str, Any]) -> Set[str]:
    observed = {
        str(item.get("probe_id") or "")
        for item in runtime_result.get("value_observations") or []
        if str(item.get("probe_id") or "")
    }
    observed.update(
        str(item.get("marker_id") or "")
        for item in runtime_result.get("slice_boundary_observations") or []
        if str(item.get("marker_id") or "")
    )
    return observed


def _primary_probe_collection_available(
    runtime_result: Dict[str, Any],
) -> bool:
    strategy = str(
        runtime_result.get("trace_collection_strategy") or ""
    )
    return (
        strategy != "census_only_detailed_scope_unavailable"
        and not bool(runtime_result.get("coverage_only"))
    )


def _scalar_values(runtime_result: Dict[str, Any]) -> Dict[str, List[Dict[str, Any]]]:
    values: Dict[str, List[Dict[str, Any]]] = {}
    for item in runtime_result.get("value_observations") or []:
        probe_id = str(item.get("probe_id") or "")
        if probe_id:
            values.setdefault(probe_id, []).append(item)
    return values


def _probe_question(*, kind: str, function: str, expression: str) -> str:
    subject = expression or function or "the selected boundary"
    if kind == "argument":
        return f"Did the failing execution enter {function} at {subject}?"
    if kind == "return_value":
        return f"Did the failing execution reach the return boundary {subject}?"
    if kind == "output_write":
        return f"Did the failing execution reach the write boundary {subject}?"
    if kind == "branch_outcome":
        return f"What scalar branch outcome was observed for {subject}?"
    return f"What runtime evidence was observed for {subject}?"


def _query_diagnostics(
    *,
    primary_overflow: bool,
    recovery_used: bool,
    recovery_overflow: bool,
    primary_signature_match: Optional[bool],
    recovery_signature_match: Optional[bool],
) -> List[str]:
    diagnostics = []
    if primary_overflow:
        diagnostics.append("ordered_trace_overflow")
    if recovery_used:
        diagnostics.append("probe_only_overflow_recovery_used")
    if recovery_overflow:
        diagnostics.append("probe_only_recovery_incomplete")
    if primary_signature_match is False:
        diagnostics.append("primary_failure_signature_mismatch")
    if recovery_signature_match is False:
        diagnostics.append("recovery_failure_signature_mismatch")
    return diagnostics


def _next_queries(requests: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    sampled = [
        str(item.get("request_id") or "")
        for item in requests
        if str(item.get("status") or "").endswith("_sampled")
        and str(item.get("request_id") or "")
    ]
    overflowed = [
        str(item.get("request_id") or "")
        for item in requests
        if item.get("status") == "incomplete_overflow"
        and str(item.get("request_id") or "")
    ]
    follow_ups = []
    if overflowed:
        follow_ups.append({
            "strategy": "probe_only_recovery",
            "request_ids": overflowed,
        })
    if sampled:
        follow_ups.append({
            "strategy": "invocation_window_refinement",
            "request_ids": sampled,
            "reason": (
                "per-probe sampling cannot prove absence in later hot-loop "
                "iterations"
            ),
        })
    return follow_ups


def _stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        default=str,
        separators=(",", ":"),
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()[:16]}"
