"""Input/Expected/Actual contradiction analysis and LLM-guided trace plans."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
from collections import Counter
from typing import Any, Dict, List

from core.apr.agent.correctness_repair.models import (
    parse_json_object_with_recovery,
)
from core.apr.llm import call_llm

from .artifacts import atomic_write_json, read_json, safe_artifact_component
from .investigation import (
    compact_source_evidence,
    hypothesis_support,
)
from .semantic import semantic_tokens
from .scenario import scenario_analysis_identity


TRACE_PLAN_SYSTEM_PROMPT = (
    "You are an evidence investigator for C/C++ fault localization. Reconstruct "
    "a causal chain from the concrete test input through executed source code "
    "to the Expected/Actual contradiction. Use source definitions, dynamic "
    "call edges and runtime invocation membership together; names alone are "
    "not evidence. Select only exact supplied function keys. State what value, "
    "branch, write, call result or exception must be observed to confirm each "
    "hypothesis. Do not propose a patch, use benchmark knowledge, ground truth, "
    "or a final numeric ranking. Return strict JSON without markdown."
)
TRACE_PLAN_SCHEMA = "unified_debugging.fl_investigation_plan.v3"


def build_trace_plan(
    *,
    scenario_analysis: Dict[str, Any],
    runtime_evidence: Dict[str, Any],
    use_llm: bool,
    provider: str = None,
    artifact_dir: str = "",
    source_evidence: Dict[str, Any] | None = None,
    invocation_keys: List[str] | None = None,
) -> Dict[str, Any]:
    scenario = scenario_analysis.get("first_failing_scenario") or {}
    contradiction = analyze_contradiction(scenario)
    inventory = _runtime_inventory(runtime_evidence)
    source_evidence = source_evidence or {}
    invocation_keys = [
        str(value)
        for value in invocation_keys or []
        if str(value) in inventory
    ]
    scenario_identity = scenario_analysis_identity(scenario_analysis)
    plan_identity = _plan_identity(
        scenario_identity=scenario_identity,
        source_evidence_identity=str(
            source_evidence.get("identity") or ""
        ),
        runtime_evidence=runtime_evidence,
    )
    deterministic = {
        "schema": TRACE_PLAN_SCHEMA,
        "version": 3,
        "identity": plan_identity,
        "scenario_identity": scenario_identity,
        "status": "generated" if scenario else "unavailable",
        "mode": "deterministic",
        "first_failing_scenario_id": scenario.get("scenario_id"),
        "source_marker_id": scenario.get("source_marker_id"),
        "contradiction": contradiction,
        "trace_terms": semantic_tokens([
            *(contradiction.get("expected") or []),
            *(contradiction.get("actual") or []),
        ]),
        "values_to_trace": _values_to_trace(scenario),
        "trace_anchors": _exact_producer_anchors(
            scenario.get("producer_calls") or [],
            allowed=list(inventory),
        ),
        "boundary_requirements": [
            "function arguments at entry",
            "return value at exit",
            "writes reaching the asserted Actual value",
        ],
        "hypotheses": [],
        "information_needs": [],
        "source_evidence_identity": str(
            source_evidence.get("identity") or ""
        ),
        "investigation": {
            "executed_candidate_count": len(inventory),
            "selected_invocation_member_count": len(invocation_keys),
            "source_dossier_count": len(
                source_evidence.get("dossiers") or {}
            ),
            "ground_truth_used": False,
        },
        "llm": {
            "enabled": bool(use_llm),
            "applied": False,
            "provider": provider or "default",
            "diagnostics": [],
        },
    }
    cached_plan = _load_cached_llm_plan(
        artifact_dir=artifact_dir,
        plan_identity=plan_identity,
        allowed_functions=set(inventory),
    )
    if use_llm and cached_plan:
        return cached_plan
    if not use_llm or not scenario:
        _write_trace_plan_artifact(
            artifact_dir=artifact_dir,
            plan=deterministic,
            prompt={},
            response="",
        )
        return deterministic

    prompt_payload = {
        "task": "build_source_and_runtime_supported_causal_hypotheses",
        "plan_identity": plan_identity,
        "first_failing_scenario": scenario,
        "deterministic_contradiction": contradiction,
        "source_dossiers": compact_source_evidence(source_evidence),
        "selected_invocation_functions": invocation_keys,
        "dynamic_edges": (runtime_evidence.get("dynamic_edges") or [])[:400],
        "exception_events": (
            runtime_evidence.get("exception_events") or []
        )[:80],
        "constraints": {
            "ground_truth_available": False,
            "allowed_trace_anchors": list(inventory),
            "allowed_hypothesis_functions": list(inventory),
            "causal_chain_must_follow_dynamic_edges": True,
            "hypothesis_requires_source_evidence": True,
            "must_not_propose_patch": True,
            "must_not_rank_final_faults": True,
        },
        "output_schema": {
            "contradiction_summary": "input-aware explanation",
            "violated_invariants": ["property contradicted by Actual"],
            "preserved_invariants": ["property still correct"],
            "hypotheses": [{
                "candidate_function": "exact allowed function key",
                "causal_chain": ["exact allowed function keys in runtime order"],
                "source_observation": "specific control/data behavior in supplied source",
                "explains_actual": "how the behavior yields Actual",
                "information_needs": [{
                    "kind": (
                        "argument | return_value | branch_outcome | "
                        "output_write | exception | call_result | "
                        "source_definition"
                    ),
                    "function": "exact allowed function key",
                    "expression": "value or condition to observe",
                    "predicted_relation": "observation that confirms hypothesis",
                }],
            }],
            "values_to_trace": ["runtime value at an exact function boundary"],
            "trace_terms": ["semantic operation/type term"],
            "trace_anchors": ["exact allowed function key"],
        },
    }
    prompt = json.dumps(
        prompt_payload, ensure_ascii=False, separators=(",", ":")
    )
    try:
        response = call_llm(
            prompt,
            provider=provider,
            system_prompt=TRACE_PLAN_SYSTEM_PROMPT,
        ) or ""
    except Exception as exc:
        response = ""
        error = f"fl_trace_plan_llm_failed:{type(exc).__name__}"
    else:
        error = ""
    parsed, parse_error = parse_json_object_with_recovery(response)
    error = error or parse_error
    if error or not parsed:
        deterministic["llm"]["diagnostics"].append(
            error or "fl_trace_plan_llm_empty"
        )
        _write_trace_plan_artifact(
            artifact_dir=artifact_dir,
            plan=deterministic,
            prompt=prompt_payload,
            response=response,
        )
        return deterministic

    allowed = set(inventory)
    raw_hypotheses = [
        item
        for item in parsed.get("hypotheses") or []
        if isinstance(item, dict)
    ]
    hypotheses = []
    for item in raw_hypotheses:
        support = hypothesis_support(
            hypothesis=item,
            source_evidence=source_evidence,
            invocation_keys=invocation_keys,
            dynamic_edges=runtime_evidence.get("dynamic_edges") or [],
        )
        candidate = support.get("candidate_function")
        if not candidate or candidate not in allowed:
            continue
        hypotheses.append({
            **item,
            "candidate_function": candidate,
            "support": support,
        })
    anchors = [
        str(value)
        for value in parsed.get("trace_anchors") or []
        if str(value) in allowed
    ]
    anchors.extend(
        str(item.get("candidate_function") or "")
        for item in hypotheses
        if (item.get("support") or {}).get("status")
        == "source_runtime_supported"
    )
    information_needs = [
        need
        for hypothesis in hypotheses
        for need in (
            (hypothesis.get("support") or {}).get(
                "valid_information_needs"
            )
            or []
        )
    ]
    deterministic.update({
        "mode": "llm_guided",
        "trace_terms": list(dict.fromkeys([
            *deterministic["trace_terms"],
            *(
                str(value)
                for value in parsed.get("trace_terms") or []
                if str(value)
            ),
        ]))[:120],
        "values_to_trace": list(dict.fromkeys([
            *deterministic["values_to_trace"],
            *(
                str(value)
                for value in parsed.get("values_to_trace") or []
                if str(value)
            ),
        ]))[:80],
        "trace_anchors": list(dict.fromkeys([
            *deterministic["trace_anchors"],
            *anchors,
        ]))[:80],
        "hypotheses": hypotheses[:24],
        "information_needs": information_needs[:80],
        "llm_analysis": {
            "contradiction_summary": parsed.get("contradiction_summary"),
            "violated_invariants": parsed.get("violated_invariants") or [],
            "preserved_invariants": parsed.get("preserved_invariants") or [],
        },
    })
    deterministic["llm"].update({
        "applied": True,
        "diagnostics": [],
    })
    _write_trace_plan_artifact(
        artifact_dir=artifact_dir,
        plan=deterministic,
        prompt=prompt_payload,
        response=response,
    )
    return deterministic


def _load_cached_llm_plan(
    *,
    artifact_dir: str,
    plan_identity: str,
    allowed_functions: set,
) -> Dict[str, Any]:
    """Reuse a completed LLM plan when resuming FL from runtime cache."""
    if not artifact_dir or not plan_identity:
        return {}
    path = _trace_plan_path(
        artifact_dir=artifact_dir,
        plan_identity=plan_identity,
    )
    artifact = read_json(path)
    if not isinstance(artifact, dict):
        return {}
    if artifact.get("schema") != TRACE_PLAN_SCHEMA:
        return {}
    plan = artifact.get("plan") or {}
    if (
        not isinstance(plan, dict)
        or plan.get("mode") != "llm_guided"
        or str(plan.get("identity") or "") != plan_identity
        or not bool((plan.get("llm") or {}).get("applied"))
    ):
        return {}
    anchors = {
        str(value) for value in plan.get("trace_anchors") or [] if str(value)
    }
    if not anchors.issubset(allowed_functions):
        return {}
    plan = dict(plan)
    plan["artifact"] = path
    plan["llm"] = {
        **(plan.get("llm") or {}),
        "cache_hit": True,
    }
    return plan


def analyze_contradiction(scenario: Dict[str, Any]) -> Dict[str, Any]:
    observed = scenario.get("observed_output") or {}
    expected = [str(value) for value in observed.get("expected") or []]
    actual = [str(value) for value in observed.get("actual") or []]
    expected_text = expected[0] if expected else ""
    actual_text = actual[0] if actual else ""
    matcher = difflib.SequenceMatcher(
        a=expected_text,
        b=actual_text,
        autojunk=False,
    )
    edits = [
        {
            "operation": tag,
            "expected_span": [i1, i2],
            "actual_span": [j1, j2],
            "expected_fragment": expected_text[i1:i2],
            "actual_fragment": actual_text[j1:j2],
        }
        for tag, i1, i2, j1, j2 in matcher.get_opcodes()
        if tag != "equal"
    ]
    prefix_length = _common_prefix_length(expected_text, actual_text)
    suffix_length = _common_suffix_length(
        expected_text[prefix_length:],
        actual_text[prefix_length:],
    )
    return {
        "input_literals": scenario.get("input_literals") or [],
        "assertion_source": scenario.get("source") or "",
        "producer_calls": scenario.get("producer_calls") or [],
        "expected": expected,
        "actual": actual,
        "expected_length": len(expected_text),
        "actual_length": len(actual_text),
        "length_delta": len(actual_text) - len(expected_text),
        "common_prefix_length": prefix_length,
        "common_suffix_length": suffix_length,
        "edit_script": edits[:40],
        "same_character_multiset": (
            Counter(expected_text) == Counter(actual_text)
            if expected_text or actual_text
            else None
        ),
    }


def _runtime_inventory(
    runtime_evidence: Dict[str, Any]
) -> Dict[str, Dict[str, Any]]:
    functions = runtime_evidence.get("functions") or {}
    return {
        str(key): value
        for key, value in functions.items()
        if str(key) and isinstance(value, dict)
    }


def _exact_producer_anchors(
    producer_calls: List[str], *, allowed: List[str]
) -> List[str]:
    call_leaves = {
        str(value).rsplit("::", 1)[-1]
        for value in producer_calls
        if str(value)
    }
    return [
        key
        for key in allowed
        if key.rsplit("::", 1)[-1] in call_leaves
    ][:40]


def _values_to_trace(scenario: Dict[str, Any]) -> List[str]:
    values = []
    for value in [
        scenario.get("actual_expression"),
        *(scenario.get("arguments") or []),
        *(scenario.get("input_literals") or []),
    ]:
        value = str(value or "").strip()
        if value and value not in values:
            values.append(value)
    return values[:80]


def _common_prefix_length(left: str, right: str) -> int:
    count = 0
    for a, b in zip(left, right):
        if a != b:
            break
        count += 1
    return count


def _common_suffix_length(left: str, right: str) -> int:
    count = 0
    for a, b in zip(reversed(left), reversed(right)):
        if a != b:
            break
        count += 1
    return count


def _write_trace_plan_artifact(
    *,
    artifact_dir: str,
    plan: Dict[str, Any],
    prompt: Dict[str, Any],
    response: str,
) -> str:
    if not artifact_dir:
        return ""
    plan_identity = str(plan.get("identity") or "")
    if not plan_identity:
        return ""
    payload = {
        "schema": TRACE_PLAN_SCHEMA,
        "identity": plan_identity,
        "plan": plan,
        "prompt": prompt,
        "response": response,
    }
    path = _trace_plan_path(
        artifact_dir=artifact_dir,
        plan_identity=plan_identity,
    )
    written = atomic_write_json(path, payload)
    if not written:
        return ""
    # The non-versioned pointer is for humans and compatibility only. Cache
    # reads use the immutable identity-specific artifact above.
    atomic_write_json(
        os.path.join(artifact_dir, "fl_trace_plan.json"),
        payload,
    )
    plan["artifact"] = written
    return written


def _plan_identity(
    *,
    scenario_identity: Dict[str, Any],
    source_evidence_identity: str,
    runtime_evidence: Dict[str, Any],
) -> str:
    cache_identity = runtime_evidence.get("cache_identity") or {}
    value = {
        "version": 3,
        "scenario": scenario_identity,
        "source_evidence_identity": str(
            source_evidence_identity or ""
        ),
        "runtime_schema": str(runtime_evidence.get("schema") or ""),
        "runtime_cache_identity": cache_identity,
        "regression_test_ids": sorted(
            str(item)
            for item in runtime_evidence.get("regression_test_ids") or []
            if str(item)
        ),
    }
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _trace_plan_path(*, artifact_dir: str, plan_identity: str) -> str:
    slug = safe_artifact_component(str(plan_identity or ""))[:64]
    return os.path.join(
        artifact_dir,
        "trace_plans",
        f"{slug}.json",
    )
