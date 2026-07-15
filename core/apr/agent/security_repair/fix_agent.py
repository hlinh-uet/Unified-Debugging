import json
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm
from core.apr.agent.security_repair._unsafe_path_schema import (
    compact_unsafe_path,
)


SECURITY_FIX_SYSTEM_PROMPT = (
    "You are a professional C/C++ vulnerability repair agent. Return ONLY the raw fixed C/C++ code. "
    "Use the security repair constraints as source-of-truth for unsafe sinks, trust boundaries, "
    "symbols, and edit boundaries. No markdown, no explanation, no backticks."
)


def build_security_fix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: str,
    repair_objective_json: str,
    repair_brief_json: str,
) -> str:
    return f"""SECURITY REPAIR TASK
Bug ID: {bug_id}
Repair only the target C/C++ replacement unit below. This route is for a vulnerability or unsafe runtime bug:
the patch must remove or guard the unsafe memory, pointer, bounds, allocation, lifetime, or cleanup behavior.

TARGET REPLACEMENT UNIT TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET REPLACEMENT UNIT
{func_code}
END TARGET REPLACEMENT UNIT

FAILURE EVIDENCE
Use this evidence to identify the unsafe behavior and the triggering path.
{failed_tests_context}

SECURITY OBJECTIVE
BEGIN REPAIR OBJECTIVE JSON
{repair_objective_json}
END REPAIR OBJECTIVE JSON

REPAIR BRIEF
This is the compact constraints brief synthesized from failure evidence and RelatedCodeContext.
It provides unsafe_paths as an evidence list centered on sink/state/guards/cleanup plus project contracts.
Use repair_decision_context, risk_operations, unsafe_path_selection_policy, and unsafe_path_decision_aids
to choose the unsafe_path best supported
by FAILURE EVIDENCE, then implement the minimal security edit
that satisfies repair_constraints and related contracts.
BEGIN REPAIR BRIEF JSON
{repair_brief_json}
END REPAIR BRIEF JSON

SECURITY POLICY
1. Treat REPAIR BRIEF repair_constraints.unsafe_paths[] as evidence candidates, not a ranked list or preselected target.
   Choose one relevant entry only after matching it against FAILURE EVIDENCE, full target code, unsafe_path_selection_policy,
   unsafe_path_decision_aids, and repair_decision_context.operation_evidence. Its sink is the unsafe operation to block:
   pointer dereference, array/index access, memcpy/memmove/read/write, allocation size, integer size flow,
   free/lifetime operation, or cleanup/error transition.
2. This is a security_repair route: do not convert it into output-only correctness tuning
   while an unsafe path remains reachable.
3. Do not assume unsafe_paths[0] is correct. Reject any candidate path whose sink kind, symbols, guard gap,
   cleanup requirement, or fail-closed behavior does not explain the observed failure.
4. Patch at or before the chosen unsafe_path.recommended_patch_site so the new or strengthened guard dominates
   the chosen unsafe_path.sink before the unsafe behavior executes.
5. Use the matching risk_operation.operation_summary, operand_roles, boundary_facts, guard_gap, and repair_intent
   to decide the exact guard/size/lifetime condition; do not invent that condition from scratch.
6. Use the chosen unsafe_path.data_state_before_sink, existing_guards, cleanup_obligations, fail_closed_expectation,
   valid_path_preservation, and typed_buffer_facts as the concrete repair contract.
7. Use REPAIR BRIEF repair_constraints.security_constraints, repair_decision_context, unsafe_path_selection_policy,
   unsafe_path_decision_aids, risk_operations, unsafe_paths, preserve_constraints, allowed_edit_operations,
   forbidden_edit_operations, and validation_focus.
8. Preserve valid-path behavior and existing cleanup/resource conventions. Fail closed only for invalid or malformed
   inputs supported by failure/source evidence.
9. Use REPAIR BRIEF allowed_symbol_surface and repair_constraints.required_related_evidence before adding or changing any validation
   helper, macro, enum constant, error code, type, field, or cleanup call.
10. Do not introduce a visible-but-not-automatically-introducible helper unless required_related_evidence proves the exact callable form.
11. Do not produce an output-only, cosmetic, formatting-only, or logging-only patch while the unsafe sink remains reachable.
12. Do not delete error handling or cleanup unconditionally. New fail-closed returns/gotos must satisfy the chosen unsafe_path.cleanup_obligations.
13. Preserve REPAIR BRIEF repair_constraints.hard_constraints and preserve_constraints, avoid
    forbidden_edit_operations, and keep the patch minimal inside the shown replacement unit.

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ replacement unit for {func_name}.
2. Preserve the existing signature, template context, coding style, macros, and helper APIs unless REPAIR BRIEF explicitly permits otherwise.
3. Do not add includes, new global helpers, main functions, unrelated refactors, wrappers, namespaces, classes, or changes outside the target replacement unit.
4. Do not call or rely on an API, macro, type, helper, ownership convention, or error-handling convention unless it appears in REPAIR BRIEF allowed_symbol_surface or repair_constraints.required_related_evidence.
5. Do not introduce member fields or constructor initializer entries outside REPAIR BRIEF allowed_symbol_surface.member_fields.
6. Return raw source only: no markdown, no explanation, no code fences, no backticks.

FIXED REPLACEMENT UNIT
"""


def build_security_fix_agent_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
    repair_constraints: Optional[Dict[str, Any]] = None,
) -> str:
    objective = _security_objective(
        repair_objective=repair_objective,
        repair_constraints=repair_constraints,
    )
    repair_objective_json = json.dumps(
        _compact_repair_objective(objective),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    repair_brief_json = json.dumps(
        _compact_repair_constraints_for_fix(repair_constraints or {}),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    return build_security_fix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        failed_tests_context=_clip(failed_tests_context, 3200),
        repair_objective_json=repair_objective_json,
        repair_brief_json=repair_brief_json,
    )


def run_security_fix_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
    repair_constraints: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], dict]:
    prompt = build_security_fix_agent_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
        repair_constraints=repair_constraints,
    )
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=SECURITY_FIX_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name="security_fix_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "security_fix_agent_no_response",
    )
    return response, artifact


def _security_objective(
    *,
    repair_objective: Optional[Dict[str, Any]],
    repair_constraints: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    objective = dict(
        repair_objective
        or _repair_objective_from_repair_constraints(repair_constraints or {})
        or {}
    )
    objective["route"] = "security_repair"
    objective.setdefault("bug_kind", "vulnerability")
    objective.setdefault("repair_goal", "Eliminate the vulnerability with the smallest semantics-preserving edit.")
    return objective


def _repair_objective_from_repair_constraints(constraints_context: Dict[str, Any]) -> Dict[str, Any]:
    objective = (constraints_context or {}).get("repair_objective") or {}
    if not isinstance(objective, dict) or not objective.get("route"):
        objective = (constraints_context or {}).get("classifier_directive") or {}
    if not isinstance(objective, dict):
        return {}
    route = str(objective.get("route") or "").strip()
    if not route:
        return {}
    return {
        "route": route,
        "bug_kind": objective.get("bug_kind"),
        "repair_goal": objective.get("repair_goal"),
        "failure_categories": objective.get("failure_categories") or [],
        "validation_oracle": objective.get("validation_oracle"),
        "confidence": objective.get("confidence"),
    }


def _compact_repair_constraints_for_fix(constraints_context: Dict[str, Any]) -> Dict[str, Any]:
    """Compact the full repair constraints into a focused brief for Fix Agent.

    Removes duplicate keys that inflate the prompt without adding information:
    - classifier_directive (duplicate of repair_objective)
    - planner_profile (duplicate of repair_objective)
    - unsafe_path_context (duplicate of repair_constraints.unsafe_paths)
    - repair_plan (duplicate of repair_constraints; only selection steps kept)
    - analysis_engine (internal metadata, not needed by LLM)
    - debug_summary (debugging aid, not needed by LLM)
    """
    if not isinstance(constraints_context, dict) or not constraints_context:
        return {}
    suggestion = constraints_context
    repair_constraints = suggestion.get("repair_constraints") or {}
    # Extract only the non-duplicate selection steps from repair_plan.
    repair_plan_raw = suggestion.get("repair_plan") or {}
    repair_plan_summary = {}
    if isinstance(repair_plan_raw, dict):
        steps = repair_plan_raw.get("steps") or []
        repair_intent = repair_plan_raw.get("repair_intent") or ""
        if steps or repair_intent:
            repair_plan_summary = {
                "repair_intent": _clip(repair_intent, 520),
                "steps": [_clip(item, 360) for item in _first(steps, 9)],
            }
    result = {
        "repair_objective": _compact_repair_objective(suggestion.get("repair_objective") or {}),
        "replacement_target": {
            "function_name": (suggestion.get("replacement_target") or {}).get("function_name"),
            "source_file": (suggestion.get("replacement_target") or {}).get("source_file"),
            "replacement_range": (suggestion.get("replacement_target") or {}).get("replacement_range") or {},
            "replacement_includes_prefix": (suggestion.get("replacement_target") or {}).get("replacement_includes_prefix"),
            "output_rules": [
                _clip(item, 260)
                for item in _first((suggestion.get("replacement_target") or {}).get("output_rules"), 6)
            ],
        },
        "failure_summary": _compact_failure_summary(suggestion.get("failure_summary") or {}),
        "repair_constraints": _compact_repair_constraints(repair_constraints),
        "allowed_symbol_surface": _compact_allowed_symbol_surface(
            suggestion.get("allowed_symbol_surface") or {}
        ),
        "context_policy": [_clip(item, 260) for item in _first(suggestion.get("context_policy"), 4)],
    }
    if repair_plan_summary:
        result["repair_plan_summary"] = repair_plan_summary
    return result


def _compact_repair_objective(objective: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(objective, dict):
        return {}
    evidence = objective.get("evidence") or {}
    return {
        "bug_kind": objective.get("bug_kind"),
        "metadata_label": objective.get("metadata_label"),
        "validation_oracle": objective.get("validation_oracle"),
        "oracle_subkind": objective.get("oracle_subkind"),
        "route": "security_repair",
        "confidence": objective.get("confidence"),
        "repair_goal": _clip(objective.get("repair_goal"), 260),
        "failure_categories": _first(objective.get("failure_categories"), 8),
        "fix_policy": [_clip(item, 180) for item in _first(objective.get("fix_policy"), 4)],
        "route_policy": [_clip(item, 180) for item in _first(objective.get("route_policy"), 4)],
        "evidence": {
            "metadata": [_clip(item, 180) for item in _first(evidence.get("metadata"), 3)],
            "oracle": [_clip(item, 180) for item in _first(evidence.get("oracle"), 4)],
        },
    }


def _compact_failure_summary(summary: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "categories": _first(summary.get("categories"), 8),
        "oracle_kind": summary.get("oracle_kind"),
        "expected_behavior": [_clip(item, 260) for item in _first(summary.get("expected_behavior"), 3)],
        "observed_behavior": [_clip(item, 260) for item in _first(summary.get("observed_behavior"), 3)],
        "failure_literals": [_clip(item, 120) for item in _first(summary.get("failure_literals"), 8)],
        "repair_bias": [_clip(item, 220) for item in _first(summary.get("repair_bias"), 4)],
    }


def _compact_repair_constraints(constraints: Dict[str, Any]) -> Dict[str, Any]:
    """Compact repair_constraints, removing duplicate sub-structures.

    Removed keys (duplicates already present elsewhere or in unsafe_paths):
    - risk_plan (duplicates unsafe_paths + risk_operations)
    - related_contracts_to_preserve (duplicates preserve_constraints)
    - confidence_notes (low-value metadata)

    unsafe_paths limited to top 3 (by confidence) to reduce context size.
    unsafe_path_decision_aids limited to top 3.
    risk_operations limited to top 4.
    """
    if not isinstance(constraints, dict):
        return {}
    failing = constraints.get("failing_behavior") or {}
    # Select top 3 unsafe_paths, preferring higher confidence
    raw_paths = _first(constraints.get("unsafe_paths"), 12)
    ranked_paths = sorted(
        [p for p in raw_paths if isinstance(p, dict)],
        key=lambda p: ({"high": 0, "medium": 1, "low": 2}.get(str(p.get("confidence", "medium")).lower(), 1)),
    )
    top_paths = ranked_paths[:3] if ranked_paths else raw_paths[:3]
    return {
        "target_function": constraints.get("target_function"),
        "route": "security_repair",
        "objective": _clip(constraints.get("objective"), 320),
        "patch_shape": [_clip(item, 260) for item in _first(constraints.get("patch_shape"), 4)],
        "failing_behavior": {
            "categories": _first(failing.get("categories"), 8),
            "oracle_kind": failing.get("oracle_kind"),
            "expected_behavior": [_clip(item, 260) for item in _first(failing.get("expected_behavior"), 3)],
            "observed_behavior": [_clip(item, 260) for item in _first(failing.get("observed_behavior"), 3)],
            "failure_literals": [_clip(item, 120) for item in _first(failing.get("failure_literals"), 8)],
        },
        "hard_constraints": [_clip(item, 320) for item in _first(constraints.get("hard_constraints"), 10)],
        "preserve_constraints": [_clip(item, 320) for item in _first(constraints.get("preserve_constraints"), 10)],
        "security_constraints": [_clip(item, 320) for item in _first(constraints.get("security_constraints"), 8)],
        "repair_decision_context": _compact_repair_decision_context(constraints.get("repair_decision_context") or {}),
        "unsafe_path_selection_policy": _compact_any(constraints.get("unsafe_path_selection_policy") or {}, 900),
        "unsafe_paths": [compact_unsafe_path(item) for item in top_paths],
        "unsafe_path_decision_aids": [
            _compact_unsafe_path_decision_aid(item)
            for item in _first(constraints.get("unsafe_path_decision_aids"), 3)
            if isinstance(item, dict)
        ],
        "risk_operations": [
            _compact_any(item, 520)
            for item in _first(constraints.get("risk_operations"), 4)
            if isinstance(item, dict)
        ],
        "wrong_fix_risks": [_compact_any(item, 360) for item in _first(constraints.get("wrong_fix_risks"), 6)],
        "allowed_edit_operations": [_clip(item, 300) for item in _first(constraints.get("allowed_edit_operations"), 12)],
        "forbidden_edit_operations": [_clip(item, 300) for item in _first(constraints.get("forbidden_edit_operations"), 14)],
        "required_related_evidence": [_compact_any(item, 360) for item in _first(constraints.get("required_related_evidence"), 8)],
        "validation_focus": [_clip(item, 320) for item in _first(constraints.get("validation_focus"), 8)],
    }


def _compact_repair_decision_context(context: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    return {
        "role": context.get("role"),
        "fix_agent_should": [_clip(item, 220) for item in _first(context.get("fix_agent_should"), 4)],
        "fix_agent_should_not": [_clip(item, 220) for item in _first(context.get("fix_agent_should_not"), 4)],
        "selection_policy": _compact_any(context.get("selection_policy") or {}, 520),
        "operation_evidence": [
            _compact_any(item, 520)
            for item in _first(context.get("operation_evidence"), 4)
            if isinstance(item, dict)
        ],
        "path_decision_aids": [
            _compact_unsafe_path_decision_aid(item)
            for item in _first(context.get("path_decision_aids"), 4)
            if isinstance(item, dict)
        ],
        "failure_terms": _first(context.get("failure_terms"), 20),
    }


def _compact_repair_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(plan, dict):
        return {}
    constraints = plan.get("constraints") or {}
    failing = plan.get("failing_behavior") or {}
    return {
        "target_function": plan.get("target_function"),
        "route": "security_repair",
        "objective": _clip(plan.get("objective"), 320),
        "planner_focus": plan.get("planner_focus"),
        "patch_shape": [_clip(item, 260) for item in _first(plan.get("patch_shape"), 4)],
        "semantic_contracts": [_compact_any(item, 520) for item in _first(plan.get("semantic_contracts"), 6)],
        "failing_behavior": {
            "categories": _first(failing.get("categories"), 8),
            "oracle_kind": failing.get("oracle_kind"),
            "expected_behavior": [_clip(item, 260) for item in _first(failing.get("expected_behavior"), 3)],
            "observed_behavior": [_clip(item, 260) for item in _first(failing.get("observed_behavior"), 3)],
        },
        "repair_intent": _clip(plan.get("repair_intent"), 520),
        "steps": [_clip(item, 360) for item in _first(plan.get("steps"), 9)],
        "constraints": {
            "must_preserve": [_clip(item, 320) for item in _first(constraints.get("must_preserve"), 10)],
            "forbidden_changes": [_clip(item, 320) for item in _first(constraints.get("forbidden_changes"), 10)],
            "symbol_introduction_policy": [_clip(item, 260) for item in _first(constraints.get("symbol_introduction_policy"), 4)],
            "risky_unqualified_helpers": _first(constraints.get("risky_unqualified_helpers"), 20),
            "required_related_evidence": [_compact_any(item, 360) for item in _first(constraints.get("required_related_evidence"), 6)],
        },
        "plan_safety_checks": [_clip(item, 320) for item in _first(plan.get("plan_safety_checks"), 10)],
        "unsafe_path_selection_policy": _compact_any(plan.get("unsafe_path_selection_policy") or {}, 900),
        "unsafe_paths": [
            compact_unsafe_path(item)
            for item in _first(plan.get("unsafe_paths"), 6)
        ],
        "unsafe_path_decision_aids": [
            _compact_unsafe_path_decision_aid(item)
            for item in _first(plan.get("unsafe_path_decision_aids"), 6)
            if isinstance(item, dict)
        ],
        "evidence_refs": [_compact_any(item, 320) for item in _first(plan.get("evidence_refs"), 6)],
        "confidence": plan.get("confidence"),
    }


def _compact_risk_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(plan, dict):
        return {}
    return {
        "source": plan.get("source"),
        "path_summary": _compact_any(plan.get("path_summary") or {}, 420),
        "risk_summary": _compact_any(plan.get("risk_summary") or {}, 420),
        "security_failure_contract": _compact_any(plan.get("security_failure_contract") or {}, 520),
        "unsafe_paths": [
            compact_unsafe_path(item)
            for item in _first(plan.get("unsafe_paths"), 6)
        ],
        # Compatibility hazard context; prefer unsafe_paths.
        "risk_operations": [
            {
                "id": risk.get("id"),
                "kind": risk.get("kind"),
                "line": risk.get("line"),
                "sink_code": _clip(risk.get("sink_code"), 260),
                "input_controlled_values": _first(risk.get("input_controlled_values"), 8),
                "operation_summary": _compact_any(risk.get("operation_summary") or {}, 220),
                "operand_roles": _compact_any(risk.get("operand_roles") or {}, 260),
                "boundary_facts": _compact_any(risk.get("boundary_facts") or {}, 220),
                "existing_guards": [_compact_guard_context(item) for item in _first(risk.get("existing_guards"), 3)],
                "guard_gap": _compact_any(risk.get("guard_gap") or {}, 260),
                "missing_property": _clip(risk.get("missing_property"), 220),
                "dominance_requirement": _clip(risk.get("dominance_requirement"), 220),
                "suggested_patch_operator": risk.get("suggested_patch_operator"),
                "repair_intent": _compact_any(risk.get("repair_intent") or {}, 220),
                "required_related_context": _clip(risk.get("required_related_context"), 220),
                "role": risk.get("role"),
                "why_risky": _clip(risk.get("why_risky"), 220),
                "wrong_fix_trap": _clip(risk.get("wrong_fix_trap"), 220),
                "safe_repair_expectation": _clip(risk.get("safe_repair_expectation"), 220),
                "confidence": risk.get("confidence"),
            }
            for risk in _first(plan.get("risk_operations") or plan.get("risky_operations") or plan.get("ranked_risks"), 8)
            if isinstance(risk, dict)
        ],
        # Compatibility hazard context; prefer risk_operations.
        "risky_operations": [
            _compact_any(item, 360)
            for item in _first(plan.get("risky_operations") or plan.get("ranked_risks") or plan.get("risk_operations"), 6)
            if isinstance(item, dict)
        ],
        "wrong_fix_risks": [_compact_any(item, 300) for item in _first(plan.get("wrong_fix_risks"), 6)],
        "constraints": [_clip(item, 260) for item in _first(plan.get("constraints"), 8)],
        "downstream_context_requests": [_compact_any(item, 300) for item in _first(plan.get("downstream_context_requests"), 6)],
        "policy": [_clip(item, 220) for item in _first(plan.get("policy"), 4)],
    }


def _compact_unsafe_path_decision_aid(aid: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(aid, dict) or not aid:
        return {}
    return {
        "id": aid.get("id"),
        "unsafe_path_id": aid.get("unsafe_path_id"),
        "sink": _compact_any(aid.get("sink") or {}, 320),
        "selection_signals": _compact_any(aid.get("selection_signals") or {}, 360),
        "patch_feasibility": _compact_any(aid.get("patch_feasibility") or {}, 360),
        "symbol_facts": _compact_any(aid.get("symbol_facts") or {}, 360),
        "guard_evidence": [_compact_any(item, 260) for item in _first(aid.get("guard_evidence"), 4)],
        "fail_closed_action": _clip(aid.get("fail_closed_action"), 260),
        "cleanup_preservation": [_compact_any(item, 260) for item in _first(aid.get("cleanup_preservation"), 4)],
        "valid_path_preservation": _clip(aid.get("valid_path_preservation"), 260),
        "wrong_fix_trap": _clip(aid.get("wrong_fix_trap"), 220),
        "failure_categories": _first(aid.get("failure_categories"), 8),
        "confidence": aid.get("confidence"),
    }


def _compact_guard_context(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return {
            "kind": item.get("kind"),
            "line": item.get("line"),
            "code": _clip(item.get("code"), 180),
            "source": item.get("source"),
        }
    return {"code": _clip(item, 180)}


def _compact_risk_operations_context(context: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    return {
        "analysis_engine": _compact_analysis_engine(context.get("analysis_engine") or {}),
        "path_summary": _compact_any(context.get("path_summary") or {}, 420),
        "risk_summary": _compact_any(context.get("risk_summary") or {}, 420),
        "security_failure_contract": _compact_any(context.get("security_failure_contract") or {}, 520),
        "unsafe_paths": [
            compact_unsafe_path(item)
            for item in _first(context.get("unsafe_paths"), 6)
        ],
        "risk_operations": [
            _compact_any(item, 420)
            for item in _first(context.get("risk_operations") or context.get("risky_operations") or context.get("ranked_risks"), 6)
        ],
        # Compatibility hazard context; prefer risk_operations/unsafe_paths.
        "risky_operations": [
            _compact_any(item, 420)
            for item in _first(context.get("risky_operations") or context.get("ranked_risks") or context.get("risk_operations"), 6)
        ],
        "wrong_fix_risks": [_compact_any(item, 300) for item in _first(context.get("wrong_fix_risks"), 6)],
        "constraints": [_clip(item, 260) for item in _first(context.get("constraints"), 6)],
    }


def _compact_allowed_symbol_surface(surface: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "functions": _first(surface.get("functions"), 30),
        "macros_or_enum_constants": _first(surface.get("macros_or_enum_constants"), 50),
        "types": _first(surface.get("types"), 30),
        "member_fields": _first(surface.get("member_fields"), 40),
        "visible_but_not_automatically_introducible": _compact_any(
            surface.get("visible_but_not_automatically_introducible") or {},
            260,
        ),
        "scope_policy": [_clip(item, 220) for item in _first(surface.get("scope_policy"), 4)],
    }


def _compact_planner_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(profile, dict):
        return {}
    return {
        "route": "security_repair",
        "planning_focus": profile.get("planning_focus"),
        "repair_goal": _clip(profile.get("repair_goal"), 260),
        "patch_shape": [_clip(item, 220) for item in _first(profile.get("patch_shape"), 4)],
        "step_priorities": [_clip(item, 220) for item in _first(profile.get("step_priorities"), 4)],
        "must_preserve": [_clip(item, 220) for item in _first(profile.get("must_preserve"), 4)],
        "forbidden_changes": [_clip(item, 220) for item in _first(profile.get("forbidden_changes"), 5)],
    }


def _compact_analysis_engine(engine: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "name": engine.get("name"),
        "version": engine.get("version"),
        "available": engine.get("available"),
        "strategy": engine.get("strategy"),
        "parser": _compact_any(engine.get("parser") or {}, 160),
    }


def _compact_classifier_directive(directive: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(directive, dict):
        return {}
    return {
        "authority": directive.get("authority"),
        "route": "security_repair",
        "bug_kind": directive.get("bug_kind"),
        "confidence": directive.get("confidence"),
        "validation_oracle": directive.get("validation_oracle"),
        "oracle_subkind": directive.get("oracle_subkind"),
        "repair_goal": _clip(directive.get("repair_goal"), 260),
        "failure_categories": _first(directive.get("failure_categories"), 8),
        "fix_policy": [_clip(item, 180) for item in _first(directive.get("fix_policy"), 4)],
        "route_policy": [_clip(item, 180) for item in _first(directive.get("route_policy"), 4)],
        "heuristic_boundary": _clip(directive.get("heuristic_boundary"), 260),
    }


def _compact_any(value: Any, max_chars: int) -> Any:
    if isinstance(value, dict):
        out = {}
        for idx, (key, item) in enumerate(value.items()):
            if idx >= 8:
                out["..."] = "truncated"
                break
            out[key] = _compact_any(item, max_chars)
        return out
    if isinstance(value, list):
        return [_compact_any(item, max_chars) for item in value[:6]]
    if isinstance(value, str):
        return _clip(value, max_chars)
    return value


def _first(value: Any, limit: int) -> List[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value[:limit]
    if isinstance(value, tuple):
        return list(value[:limit])
    return [value]


def _clip(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"
