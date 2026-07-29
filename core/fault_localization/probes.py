"""Evidence broker for source/runtime probe requests produced by FL planning."""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, Iterable, List

from .artifacts import atomic_write_json


PROBE_SCHEMA = "unified_debugging.causal_probe_evidence.v1"
_RUNTIME_VALUE_KINDS = {
    "argument",
    "return_value",
    "branch_outcome",
    "output_write",
    "call_result",
}


def resolve_probe_evidence(
    *,
    trace_plan: Dict[str, Any],
    source_evidence: Dict[str, Any],
    runtime_evidence: Dict[str, Any],
    invocation_keys: Iterable[str],
    artifact_dir: str = "",
) -> Dict[str, Any]:
    """Resolve every requested information need without inventing values.

    Function-control and exception facts can be answered from the current
    trace. Value/branch/write needs are source-resolved and emitted as targeted
    instrumentation requests when the trace does not contain those values.
    """
    dossiers = (source_evidence or {}).get("dossiers") or {}
    members = {str(value) for value in invocation_keys if str(value)}
    executed = set(runtime_evidence.get("functions") or {})
    trace_scope_tests = (
        (runtime_evidence.get("trace_scope") or {}).get("tests")
        or {}
    )
    if isinstance(trace_scope_tests, dict):
        trace_scope_iterable = trace_scope_tests.values()
    elif isinstance(trace_scope_tests, list):
        trace_scope_iterable = trace_scope_tests
    else:
        trace_scope_iterable = ()
    slice_probes_by_id = {
        str(probe.get("probe_id") or ""): probe
        for scope in trace_scope_iterable
        if isinstance(scope, dict)
        for probe in scope.get("slice_probes") or []
        if str(probe.get("probe_id") or "")
    }
    slice_observations_by_id: Dict[str, List[Dict[str, Any]]] = {}
    for observation in [
        *(runtime_evidence.get("value_observations") or []),
        *(runtime_evidence.get("slice_boundary_observations") or []),
    ]:
        probe_id = str(
            observation.get("probe_id")
            or observation.get("marker_id")
            or ""
        )
        if probe_id in slice_probes_by_id:
            slice_observations_by_id.setdefault(
                probe_id, []
            ).append(observation)
    trace_query_status_by_probe_id: Dict[str, str] = {}
    trace_query_tests = (
        (runtime_evidence.get("trace_queries") or {}).get("tests") or {}
    )
    if isinstance(trace_query_tests, dict):
        trace_query_iterable = trace_query_tests.values()
    elif isinstance(trace_query_tests, list):
        trace_query_iterable = trace_query_tests
    else:
        trace_query_iterable = ()
    for query_plan in trace_query_iterable:
        if not isinstance(query_plan, dict):
            continue
        for request in (
            (query_plan.get("evidence") or {}).get("requests") or []
        ):
            probe_id = str(request.get("probe_id") or "")
            status = str(request.get("status") or "")
            if probe_id and status:
                trace_query_status_by_probe_id[probe_id] = status
    exception_by_key: Dict[str, List[Dict[str, Any]]] = {}
    for event in runtime_evidence.get("exception_events") or []:
        key = str(
            event.get("throw_site_key") or event.get("key") or ""
        )
        if key:
            exception_by_key.setdefault(key, []).append(event)
    requests = []
    seen = set()
    planned_needs = [
        item
        for item in trace_plan.get("information_needs") or []
        if isinstance(item, dict)
    ]
    for hypothesis in trace_plan.get("hypotheses") or []:
        if not isinstance(hypothesis, dict):
            continue
        if (
            (hypothesis.get("support") or {}).get("status")
            != "source_runtime_supported"
        ):
            continue
        for function in hypothesis.get("causal_chain") or [
            hypothesis.get("candidate_function")
        ]:
            dossier = dossiers.get(str(function or "")) or {}
            for condition in dossier.get("conditions") or []:
                planned_needs.append({
                    "kind": "branch_outcome",
                    "function": str(function or ""),
                    "expression": condition.get("expression"),
                    "predicted_relation": (
                        "observe the concrete path on the failing execution"
                    ),
                    "origin": "supported_causal_chain",
                })
    planned_runtime_probes = []
    for need in planned_needs:
        if not isinstance(need, dict):
            continue
        function = str(need.get("function") or "")
        kind = str(need.get("kind") or "")
        expression = str(need.get("expression") or "")
        identity = (function, kind, expression)
        if identity in seen:
            continue
        seen.add(identity)
        dossier = dossiers.get(function) or {}
        record = {
            "function": function,
            "kind": kind,
            "expression": expression,
            "predicted_relation": str(
                need.get("predicted_relation") or ""
            ),
            "function_executed": function in executed,
            "in_selected_invocation": function in members,
            "source_available": bool(dossier.get("source_available")),
            "status": "unresolved",
            "observations": [],
            "diagnostics": [],
        }
        if function not in executed:
            record["diagnostics"].append("function_not_executed")
        elif not dossier.get("source_available"):
            record["diagnostics"].append("source_definition_unavailable")
        elif kind == "source_definition":
            record["status"] = "observed"
            record["observations"].append({
                "source_path": dossier.get("source_path"),
                "source_line": dossier.get("source_line"),
                "signature": dossier.get("signature"),
                "source_digest": dossier.get("source_digest"),
            })
        elif kind == "exception":
            events = exception_by_key.get(function) or []
            record["status"] = "observed" if events else "observed_absent"
            record["observations"] = events[:20]
        elif kind in _RUNTIME_VALUE_KINDS:
            static_matches = _static_probe_sites(
                dossier=dossier,
                kind=kind,
                expression=expression,
            )
            record["static_probe_sites"] = static_matches
            matching_slice_ids = [
                probe_id
                for probe_id, probe in slice_probes_by_id.items()
                if str(probe.get("function") or "") == function
                and str(probe.get("kind") or "") == kind
                and (
                    not expression
                    or str(probe.get("expression") or "") == expression
                )
            ]
            concrete_slice_observations = [
                observation
                for probe_id in matching_slice_ids
                for observation in (
                    slice_observations_by_id.get(probe_id) or []
                )
            ]
            if concrete_slice_observations:
                base_status = (
                    "observed"
                    if kind == "branch_outcome"
                    else "observed_boundary"
                )
                query_statuses = sorted({
                    trace_query_status_by_probe_id.get(probe_id, "")
                    for probe_id in matching_slice_ids
                    if trace_query_status_by_probe_id.get(probe_id, "")
                })
                sampled = any(
                    status.endswith("_sampled")
                    for status in query_statuses
                )
                record["status"] = (
                    base_status + "_sampled"
                    if sampled
                    else base_status
                )
                record["observations"] = (
                    concrete_slice_observations[:40]
                )
                record["probe_ids"] = matching_slice_ids
                record["trace_query_statuses"] = query_statuses
                if sampled:
                    record["diagnostics"].append(
                        "hot_probe_sample_is_partial_evidence"
                    )
                requests.append(record)
                continue
            if static_matches:
                record["status"] = "targeted_runtime_probe_required"
                if kind == "branch_outcome":
                    for site in static_matches:
                        probe_id = _probe_identity(
                            function=function,
                            kind=kind,
                            line=int(site.get("line") or 0),
                            expression=str(
                                site.get("expression") or ""
                            ),
                        )
                        planned_runtime_probes.append({
                            "probe_id": probe_id,
                            "function": function,
                            "kind": kind,
                            "source_path": dossier.get("source_path"),
                            "line": int(site.get("line") or 0),
                            "expression": str(
                                site.get("expression") or ""
                            ),
                        })
            else:
                record["status"] = "source_expression_unresolved"
        else:
            record["diagnostics"].append("unsupported_probe_kind")
        requests.append(record)
    runtime_probe_requests = list({
        item["probe_id"]: item for item in planned_runtime_probes
    }.values())
    result = {
        "schema": PROBE_SCHEMA,
        "scenario_id": trace_plan.get("first_failing_scenario_id"),
        "source_marker_id": trace_plan.get("source_marker_id"),
        "requests": requests,
        "observed_count": sum(
            item.get("status") in {
                "observed",
                "observed_absent",
                "observed_boundary",
            }
            for item in requests
        ),
        "partial_observed_count": sum(
            str(item.get("status") or "").endswith("_sampled")
            for item in requests
        ),
        "runtime_probe_request_count": sum(
            item.get("status") == "targeted_runtime_probe_required"
            for item in requests
        ),
        "runtime_probe_requests": runtime_probe_requests,
        "ground_truth_used": False,
    }
    if artifact_dir:
        path = atomic_write_json(
            os.path.join(artifact_dir, "causal_probe_evidence.json"),
            result,
        )
        if path:
            result["artifact"] = path
    return result


def _static_probe_sites(
    *,
    dossier: Dict[str, Any],
    kind: str,
    expression: str,
) -> List[Dict[str, Any]]:
    if kind == "return_value":
        records = dossier.get("returns") or []
    elif kind == "branch_outcome":
        records = dossier.get("conditions") or []
    elif kind == "output_write":
        records = dossier.get("assignments") or []
    elif kind == "call_result":
        records = dossier.get("calls") or []
    elif kind == "argument":
        return [{
            "line": dossier.get("source_line"),
            "expression": dossier.get("signature"),
        }] if dossier.get("signature") else []
    else:
        records = []
    requested_tokens = _tokens(expression)
    if not requested_tokens:
        return list(records)[:12]
    matched = [
        item
        for item in records
        if requested_tokens & _tokens(item.get("expression"))
    ]
    return (matched or list(records))[:12]


def _tokens(value: Any) -> set:
    import re

    return {
        item.lower()
        for item in re.findall(
            r"[A-Za-z_][A-Za-z0-9_]*", str(value or "")
        )
        if len(item) >= 2
    }


def _probe_identity(
    *, function: str, kind: str, line: int, expression: str
) -> str:
    value = "\0".join((
        str(function or ""),
        str(kind or ""),
        str(int(line or 0)),
        str(expression or ""),
    ))
    return "probe_" + hashlib.sha256(
        value.encode("utf-8")
    ).hexdigest()[:20]
