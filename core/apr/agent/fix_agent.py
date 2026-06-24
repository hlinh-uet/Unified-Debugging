import json
from typing import Any, Dict, List, Optional, Tuple

from core.apr.agent.correctness_repair.fix_prompt import build_correctness_fix_prompt
from core.apr.agent.security_repair.fix_prompt import build_security_fix_prompt
from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


FIX_SYSTEM_PROMPT = (
    "You are a professional C/C++ repair agent. Return ONLY the raw fixed C/C++ code. "
    "Use the repair brief as source-of-truth. "
    "No markdown, no explanation, no backticks."
)


def build_fix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
    repair_suggestion: Optional[Dict[str, Any]] = None,
) -> str:
    repair_objective = (
        repair_objective
        or _repair_objective_from_repair_suggestion(repair_suggestion or {})
    )
    route = str(repair_objective.get("route") or "").strip()
    repair_objective_json = json.dumps(
        _compact_repair_objective(repair_objective),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    repair_brief_json = json.dumps(
        _compact_repair_suggestion_for_fix(repair_suggestion or {}),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    failure_context_excerpt = _clip(failed_tests_context, 3200)
    if route == "security_repair":
        return build_security_fix_prompt(
            bug_id=bug_id,
            func_name=func_name,
            cand_label=cand_label,
            func_code=func_code,
            failed_tests_context=failure_context_excerpt,
            repair_objective_json=repair_objective_json,
            repair_brief_json=repair_brief_json,
        )
    if route == "correctness_repair":
        return build_correctness_fix_prompt(
            bug_id=bug_id,
            func_name=func_name,
            cand_label=cand_label,
            func_code=func_code,
            failed_tests_context=failure_context_excerpt,
            repair_objective_json=repair_objective_json,
            repair_brief_json=repair_brief_json,
        )
    return _build_hybrid_fix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        failed_tests_context=failure_context_excerpt,
        repair_objective_json=repair_objective_json,
        repair_brief_json=repair_brief_json,
    )


def _build_hybrid_fix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: str,
    repair_objective_json: str,
    repair_brief_json: str,
) -> str:
    return f"""REPAIR TASK
Bug ID: {bug_id}
Repair only the target C/C++ function below. The defect may be a vulnerability or a general correctness bug.
The target replacement unit is the only code that will be replaced by your answer.

TARGET REPLACEMENT UNIT TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET REPLACEMENT UNIT
{func_code}
END TARGET REPLACEMENT UNIT

FAILURE EVIDENCE
Use this metadata evidence to understand the observed failure. It may be incomplete.
{failed_tests_context}

REPAIR OBJECTIVE ROUTE
This classifier decides whether the patch should be security-oriented or correctness-oriented.
Follow this route unless direct source/validation evidence contradicts it.
BEGIN REPAIR OBJECTIVE JSON
{repair_objective_json}
END REPAIR OBJECTIVE JSON

REPAIR BRIEF
This is the single compact repair plan synthesized from FailContext, TargetCodeContext, and
RelatedCodeContext. Treat it as the source of truth for localization, contracts, allowed symbols,
must-preserve constraints, and forbidden changes.
REPAIR BRIEF classifier_directive is the route authority. Interpret heuristic edit locations and
repair_plan.steps only inside classifier_directive.repair_goal, fix_policy, route_policy, and
planner_profile.patch_shape.
BEGIN REPAIR BRIEF JSON
{repair_brief_json}
END REPAIR BRIEF JSON

CONTEXT USE POLICY
1. First identify the concrete failing behavior from FAILURE EVIDENCE.
2. Follow REPAIR OBJECTIVE ROUTE and REPAIR BRIEF classifier_directive route_policy/fix_policy to avoid using
   a vulnerability-style repair for a general correctness bug or a correctness-only patch for a vulnerability.
3. Obey REPAIR BRIEF target_contract.output_contract before all other output-format guidance.
4. Treat REPAIR BRIEF failure_summary.expected_behavior and observed_behavior as the repair oracle summary.
5. Follow REPAIR BRIEF planner_profile plus repair_plan.semantic_contracts, primary_edit_location,
   repair_intent, and steps as the patch plan.
6. Preserve REPAIR BRIEF repair_plan.constraints.must_preserve and avoid constraints.forbidden_changes.
7. Verify every API, macro, enum constant, type, helper, ownership rule, and caller expectation against
   REPAIR BRIEF allowed_symbol_surface and repair_plan.constraints.required_related_evidence.
8. Run REPAIR BRIEF repair_plan.plan_safety_checks mentally before output; do not emit a patch that violates them.
9. Prefer existing same-file helpers, macros, and idioms over inventing new logic.
10. Produce the smallest safe repair supported by the repair brief.
11. Do not copy unrelated helper bodies or examples into the target replacement unit.
12. Preserve the expected behavior stated in FAILURE EVIDENCE. If the test expects valid input to succeed,
   do not turn that path into a validation/error return only to avoid a crash.
13. For crash/null-deref fixes, prefer the smallest guard/fallback/continue/cleanup adjustment that keeps the
   original success semantics. Add a new error return only when the failure evidence expects an error.
14. Avoid formatting churn and broad rewrites; changing unrelated lines increases regression risk.
15. Do not add template prefixes, return types, namespaces, classes, wrappers, includes, or helper functions unless
    REPAIR BRIEF target_contract says the replacement unit includes that exact surrounding construct.
16. Treat REPAIR BRIEF repair_plan.allowed_edit_scope as the default edit region. Change code outside those ranges only
    when the primary/alternate edit location explicitly justifies it.
17. If route is correctness_repair, satisfy expected-vs-actual behavior directly; do not add broad defensive guards,
    error returns, or unrelated buffer rewrites for valid-input tests.
18. If route is security_repair, the patch must guard/remove the unsafe sink; do not only alter observable output.

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ replacement unit for {func_name}.
2. Preserve the existing signature, template context, coding style, macros, and helper APIs unless REPAIR BRIEF explicitly permits otherwise.
3. Keep the patch minimal and localized to the shown replacement unit.
4. Do not add includes, new global helpers, main functions, unrelated refactors, or changes outside the target function.
5. Do not call or rely on an API, macro, type, helper, ownership convention, or error-handling convention unless it appears in REPAIR BRIEF allowed_symbol_surface or repair_plan.constraints.required_related_evidence.
6. Do not introduce member fields or constructor initializer entries outside REPAIR BRIEF allowed_symbol_surface.member_fields.
7. Do not include explanations, preface text, markdown, code fences, or backticks.

FIXED REPLACEMENT UNIT
"""


def _repair_objective_from_repair_suggestion(suggestion: Dict[str, Any]) -> Dict[str, Any]:
    objective = (suggestion or {}).get("repair_objective") or {}
    if not isinstance(objective, dict) or not objective.get("route"):
        objective = (suggestion or {}).get("classifier_directive") or {}
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


def _compact_repair_suggestion_for_fix(suggestion: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(suggestion, dict) or not suggestion:
        return {}
    repair_plan = _repair_plan_from_suggestion(suggestion)
    return {
        "analysis_engine": _compact_analysis_engine(suggestion.get("analysis_engine") or {}),
        "repair_objective": _compact_repair_objective(suggestion.get("repair_objective") or {}),
        "classifier_directive": _compact_classifier_directive(suggestion.get("classifier_directive") or {}),
        "planner_profile": _compact_planner_profile(suggestion.get("planner_profile") or {}),
        "target_contract": {
            "function_name": (suggestion.get("target_contract") or {}).get("function_name"),
            "source_file": (suggestion.get("target_contract") or {}).get("source_file"),
            "replacement_range": (suggestion.get("target_contract") or {}).get("replacement_range") or {},
            "replacement_includes_prefix": (suggestion.get("target_contract") or {}).get("replacement_includes_prefix"),
            "output_contract": [
                _clip(item, 260)
                for item in _first((suggestion.get("target_contract") or {}).get("output_contract"), 6)
            ],
            "notes": _first((suggestion.get("target_contract") or {}).get("notes"), 4),
        },
        "failure_summary": {
            "categories": _first((suggestion.get("failure_summary") or {}).get("categories"), 8),
            "oracle_kind": (suggestion.get("failure_summary") or {}).get("oracle_kind"),
            "expected_behavior": [
                _clip(item, 260)
                for item in _first((suggestion.get("failure_summary") or {}).get("expected_behavior"), 3)
            ],
            "observed_behavior": [
                _clip(item, 260)
                for item in _first((suggestion.get("failure_summary") or {}).get("observed_behavior"), 3)
            ],
            "failure_literals": [
                _clip(item, 120)
                for item in _first((suggestion.get("failure_summary") or {}).get("failure_literals"), 8)
            ],
            "repair_bias": [
                _clip(item, 220)
                for item in _first((suggestion.get("failure_summary") or {}).get("repair_bias"), 4)
            ],
        },
        "repair_plan": _compact_repair_plan(repair_plan),
        "allowed_symbol_surface": {
            "functions": _first((suggestion.get("allowed_symbol_surface") or {}).get("functions"), 30),
            "macros_or_enum_constants": _first((suggestion.get("allowed_symbol_surface") or {}).get("macros_or_enum_constants"), 50),
            "types": _first((suggestion.get("allowed_symbol_surface") or {}).get("types"), 30),
            "member_fields": _first((suggestion.get("allowed_symbol_surface") or {}).get("member_fields"), 40),
            "visible_but_not_automatically_introducible": _compact_any(
                (suggestion.get("allowed_symbol_surface") or {}).get("visible_but_not_automatically_introducible") or {},
                260,
            ),
            "scope_policy": [
                _clip(item, 220)
                for item in _first((suggestion.get("allowed_symbol_surface") or {}).get("scope_policy"), 4)
            ],
        },
        "context_policy": [_clip(item, 260) for item in _first(suggestion.get("context_policy"), 4)],
        "debug_summary": {
            "failed_tests_excerpt": _clip((suggestion.get("debug_summary") or {}).get("failed_tests_excerpt"), 1200),
            "target_engine": (suggestion.get("debug_summary") or {}).get("target_engine"),
            "related_engine": (suggestion.get("debug_summary") or {}).get("related_engine"),
        },
    }


def _repair_plan_from_suggestion(suggestion: Dict[str, Any]) -> Dict[str, Any]:
    plan = suggestion.get("repair_plan") or {}
    if isinstance(plan, dict) and plan:
        return plan
    return {}


def _compact_repair_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(plan, dict):
        return {}
    constraints = plan.get("constraints") or {}
    failing = plan.get("failing_behavior") or {}
    return {
        "target_function": plan.get("target_function"),
        "route": plan.get("route"),
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
        "primary_edit_location": _compact_any(plan.get("primary_edit_location") or {}, 700),
        "fallback_edit_locations": [_compact_any(item, 420) for item in _first(plan.get("fallback_edit_locations"), 4)],
        "allowed_edit_scope": [_compact_any(item, 260) for item in _first(plan.get("allowed_edit_scope"), 4)],
        "steps": [_clip(item, 360) for item in _first(plan.get("steps"), 9)],
        "constraints": {
            "must_preserve": [_clip(item, 320) for item in _first(constraints.get("must_preserve"), 10)],
            "forbidden_changes": [_clip(item, 320) for item in _first(constraints.get("forbidden_changes"), 10)],
            "symbol_introduction_policy": [
                _clip(item, 260)
                for item in _first(constraints.get("symbol_introduction_policy"), 4)
            ],
            "risky_unqualified_helpers": _first(constraints.get("risky_unqualified_helpers"), 20),
            "required_related_evidence": [
                _compact_any(item, 360)
                for item in _first(constraints.get("required_related_evidence"), 6)
            ],
        },
        "plan_safety_checks": [_clip(item, 320) for item in _first(plan.get("plan_safety_checks"), 10)],
        "evidence_refs": [_compact_any(item, 320) for item in _first(plan.get("evidence_refs"), 6)],
        "confidence": plan.get("confidence"),
    }


def _compact_planner_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(profile, dict):
        return {}
    return {
        "route": profile.get("route"),
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


def _compact_repair_objective(objective: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(objective, dict):
        return {}
    evidence = objective.get("evidence") or {}
    return {
        "bug_kind": objective.get("bug_kind"),
        "metadata_label": objective.get("metadata_label"),
        "validation_oracle": objective.get("validation_oracle"),
        "oracle_subkind": objective.get("oracle_subkind"),
        "route": objective.get("route"),
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


def _compact_classifier_directive(directive: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(directive, dict):
        return {}
    return {
        "authority": directive.get("authority"),
        "route": directive.get("route"),
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


def run_fix_agent(
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
    repair_suggestion: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], dict]:
    prompt = build_fix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
        repair_suggestion=repair_suggestion,
    )
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=FIX_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name="fix_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "fix_agent_no_response",
    )
    return response, artifact
