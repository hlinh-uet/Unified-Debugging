import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_repair_constraints_artifact
from core.apr.agent.security_repair._risk_brief import build_security_risk_brief
from core.apr.agent.security_repair._unsafe_path_schema import (
    compact_unsafe_path,
    compact_unsafe_paths,
)


MAX_TEXT = 420


def repair_planning_profile(repair_objective: Dict[str, Any], failure_contract: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "route": "security_repair",
        "planning_focus": "unsafe_runtime_path",
        "repair_goal": (repair_objective or {}).get("repair_goal") or (failure_contract or {}).get("repair_goal"),
        "patch_shape": [
            "Repair the nearest unsafe pointer/index/allocation/lifetime/cleanup behavior or the guard/size flow that feeds it.",
            "Fail closed only for invalid or malformed input paths supported by evidence.",
            "Preserve valid-path behavior and existing cleanup/resource conventions.",
        ],
        "step_priorities": [
            "Identify the unsafe sink or unsafe transition on the failing path.",
            "Use unsafe_paths as sink/state/guard/cleanup facts, then choose the path supported by failure evidence.",
            "Patch the nearest guard, bounds/length calculation, allocation size, lifetime transition, or cleanup/error path.",
            "Verify the unsafe path is no longer reachable while valid paths keep their original semantics.",
        ],
        "must_preserve": [
            "Valid-path observable behavior and resource cleanup conventions must remain intact.",
            "Existing ownership, lifetime, and error-path conventions must not be weakened.",
        ],
        "forbidden_changes": [
            "Do not produce output-only, logging-only, formatting-only, or cosmetic patches while the unsafe path remains reachable.",
            "Do not delete cleanup/error handling unconditionally.",
            "Do not invent unseen validation helpers, macros, enum constants, types, fields, or error codes.",
        ],
    }


def target_guardrails(repair_objective: Dict[str, Any]) -> List[str]:
    rules = [
        "Security route: the patch must guard or remove the unsafe memory/pointer/index/allocation/lifetime behavior.",
        "Do not accept output-only, logging-only, or formatting-only changes that leave the unsafe sink reachable.",
        "Prefer the nearest guard, size/index calculation, allocation-size fix, lifetime fix, or cleanup/error-path refinement.",
    ]
    rules.extend(str(item) for item in (repair_objective or {}).get("target_context_policy") or [])
    return rules


def related_behavioral_contracts(repair_objective: Dict[str, Any]) -> List[dict]:
    return [
        {
            "symbol": "repair_route",
            "kind": "security_repair_route",
            "contract": "Prioritize unsafe pointer/index/allocation/lifetime sinks and existing validation/cleanup conventions.",
            "evidence": (repair_objective or {}).get("route_policy") or [],
        },
        {
            "symbol": "repair_route",
            "kind": "security_forbidden_patch_shape",
            "contract": "Do not satisfy validation by changing only output text while leaving a memory-safety sink reachable.",
            "evidence": (repair_objective or {}).get("forbidden_patch_operators") or [],
        },
    ]


def build_security_repair_constraints(
    *,
    func_name: str,
    func_code: str,
    replacement_target: Dict[str, Any],
    related_code_context: Dict[str, Any],
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
    risk_operations_context: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    objective = _security_objective(repair_objective)
    failure_summary = _failure_summary(
        failed_tests_context=failed_tests_context,
        repair_objective=objective,
    )
    route_directive = _route_directive(objective, failure_summary)
    plan_profile = repair_planning_profile(objective, failure_summary)
    related_evidence = _required_related_evidence(related_code_context)
    if not (
        isinstance(risk_operations_context, dict)
        and (
            risk_operations_context.get("unsafe_paths")
            or risk_operations_context.get("risk_operations")
            or risk_operations_context.get("risky_operations")
            or risk_operations_context.get("ranked_risks")
        )
    ):
        risk_operations_context = build_security_risk_brief(
            func_name=func_name,
            func_code=func_code,
            replacement_target=replacement_target,
            failed_tests_context=failed_tests_context,
            related_code_context=related_code_context,
            repair_objective=objective,
        )
    constraints = _security_constraint_payload(
        func_name=func_name,
        func_code=func_code,
        route_directive=route_directive,
        failure_summary=failure_summary,
        plan_profile=plan_profile,
        replacement_target=replacement_target,
        related_code_context=related_code_context,
        related_evidence=related_evidence,
        repair_objective=objective,
        risk_operations_context=risk_operations_context,
    )
    contract_brief = related_code_context.get("contract_brief") or {}
    scope_contract = related_code_context.get("scope_aware_symbol_contract") or {}
    envelope = replacement_target.get("replacement_envelope") or {}
    return {
        "analysis_engine": {
            "name": "security_repair_constraints_agent",
            "version": 1,
            "route": "security_repair",
            "strategy": "security_failure_plus_related_context_constraints_no_target_localization",
            "role": "Synthesize vulnerability repair constraints without choosing a primary edit location.",
        },
        "repair_objective": _compact_repair_objective(objective, failure_summary),
        "classifier_directive": route_directive,
        "planner_profile": _compact_plan_profile(plan_profile),
        "replacement_target": {
            "function_name": envelope.get("resolved_function_name") or envelope.get("function_name") or func_name,
            "source_file": envelope.get("source_file"),
            "replacement_range": envelope.get("replacement_range") or {},
            "replacement_includes_prefix": envelope.get("replacement_includes_prefix"),
            "output_rules": _first(_security_output_rules(replacement_target), 6),
            "notes": _first(envelope.get("notes"), 4),
        },
        "failure_summary": failure_summary,
        "unsafe_path_context": _compact_risk_operations_context(risk_operations_context),
        # Compatibility key for older pipeline state. Prefer unsafe_path_context.
        "risk_operations_context": _compact_risk_operations_context(risk_operations_context),
        "repair_constraints": constraints,
        "repair_plan": _repair_plan_alias(constraints),
        "allowed_symbol_surface": {
            "functions": _first(
                contract_brief.get("introducible_functions") or contract_brief.get("allowed_functions"),
                30,
            ),
            "macros_or_enum_constants": _first(
                contract_brief.get("introducible_macros_or_enum_constants")
                or contract_brief.get("allowed_macros_or_enum_constants"),
                50,
            ),
            "types": _first(contract_brief.get("introducible_types") or contract_brief.get("allowed_types"), 30),
            "member_fields": _first((related_code_context.get("visible_api_inventory") or {}).get("member_fields"), 40),
            "visible_but_not_automatically_introducible": {
                "functions": _first(scope_contract.get("risky_unqualified_helpers"), 30),
            },
            "scope_policy": _first(scope_contract.get("symbol_introduction_policy"), 4),
        },
        "context_policy": [
            "The default security objective is the route authority; unsafe_paths refine sink/state/guard/cleanup facts.",
            "RelatedCodeContext is the authority for introducible APIs, macros, enum constants, types, fields, and project idioms.",
            "FixAgent must inspect the full target replacement unit, select one relevant unsafe_path, and choose the minimal security edit.",
            "Do not only alter observable output while an unsafe sink remains reachable.",
        ],
        "debug_summary": {
            "failed_tests_excerpt": _clip(failed_tests_context, 900),
            "unsafe_path_engine": ((risk_operations_context or {}).get("analysis_engine") or {}).get("name"),
            "related_engine": (related_code_context.get("analysis_engine") or {}).get("name"),
        },
    }


def run_security_repair_constraints_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    func_name: str,
    func_code: str,
    replacement_target: Dict[str, Any],
    related_code_context: Dict[str, Any],
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
    risk_operations_context: Optional[Dict[str, Any]] = None,
) -> Tuple[dict, dict]:
    constraints = build_security_repair_constraints(
        func_name=func_name,
        func_code=func_code,
        replacement_target=replacement_target,
        related_code_context=related_code_context,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
        risk_operations_context=risk_operations_context,
    )
    artifact = write_repair_constraints_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        repair_constraints=constraints,
        step_name="security_repair_constraints_agent",
    )
    return constraints, artifact


def _security_constraint_payload(
    *,
    func_name: str,
    func_code: str,
    route_directive: Dict[str, Any],
    failure_summary: Dict[str, Any],
    plan_profile: Dict[str, Any],
    replacement_target: Dict[str, Any],
    related_code_context: Dict[str, Any],
    related_evidence: List[dict],
    repair_objective: Dict[str, Any],
    risk_operations_context: Optional[Dict[str, Any]],
) -> Dict[str, Any]:
    risk_plan = _risk_plan_payload(risk_operations_context, func_code, replacement_target)
    selection_policy = _unsafe_path_selection_policy(failure_summary)
    decision_aids = _unsafe_path_decision_aids_from_paths(
        risk_plan.get("unsafe_paths") or [],
        failure_summary,
    )
    repair_decision_context = _repair_decision_context(
        risk_plan=risk_plan,
        selection_policy=selection_policy,
        decision_aids=decision_aids,
        failure_summary=failure_summary,
    )
    return {
        "target_function": func_name,
        "route": "security_repair",
        "objective": _clip(route_directive.get("repair_goal"), 320),
        "planner_focus": plan_profile.get("planning_focus"),
        "patch_shape": [_clip(item, 260) for item in _first(plan_profile.get("patch_shape"), 4)],
        "failing_behavior": {
            "categories": _first(failure_summary.get("categories"), 8),
            "oracle_kind": failure_summary.get("oracle_kind"),
            "expected_behavior": [_clip(item, 260) for item in _first(failure_summary.get("expected_behavior"), 3)],
            "observed_behavior": [_clip(item, 260) for item in _first(failure_summary.get("observed_behavior"), 3)],
            "failure_literals": [_clip(item, 120) for item in _first(failure_summary.get("failure_literals"), 8)],
        },
        "hard_constraints": _hard_constraints(replacement_target),
        "preserve_constraints": _preserve_constraints(
            related_code_context=related_code_context,
            plan_profile=plan_profile,
            repair_objective=repair_objective,
        ),
        "security_constraints": _security_constraints(),
        "risk_plan": risk_plan,
        "repair_decision_context": repair_decision_context,
        "unsafe_path_selection_policy": selection_policy,
        "unsafe_paths": risk_plan.get("unsafe_paths") or [],
        "unsafe_path_decision_aids": decision_aids,
        "risk_operations": risk_plan.get("risk_operations") or risk_plan.get("risky_operations") or risk_plan.get("ranked_risks") or [],
        "wrong_fix_risks": risk_plan.get("wrong_fix_risks") or [],
        "allowed_edit_operations": _allowed_edit_operations(repair_objective),
        "forbidden_edit_operations": _forbidden_edit_operations(
            related_code_context=related_code_context,
            repair_objective=repair_objective,
            plan_profile=plan_profile,
        ),
        "symbol_introduction_policy": _first(
            (related_code_context.get("scope_aware_symbol_contract") or {}).get("symbol_introduction_policy"),
            4,
        ),
        "required_related_evidence": related_evidence,
        "related_contracts_to_preserve": _related_contracts_to_preserve(related_code_context),
        "validation_focus": _validation_focus(),
        "confidence_notes": _confidence_notes(failure_summary, related_evidence),
    }


def _security_objective(repair_objective: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    objective = dict(repair_objective or {})
    objective["route"] = "security_repair"
    objective.setdefault("bug_kind", "vulnerability")
    objective.setdefault("repair_goal", "Eliminate the vulnerability with the smallest semantics-preserving edit.")
    return objective


def _failure_summary(
    *,
    failed_tests_context: str,
    repair_objective: Dict[str, Any],
) -> Dict[str, Any]:
    text = str(failed_tests_context or "")
    categories = [str(item) for item in repair_objective.get("failure_categories") or [] if item]
    return {
        "categories": _dedup(categories)[:8],
        "oracle_kind": repair_objective.get("validation_oracle"),
        "route": "security_repair",
        "repair_goal": repair_objective.get("repair_goal"),
        "expected_behavior": _extract_failure_snippets(text, ("expected result", "expected", "should", "must")),
        "observed_behavior": _extract_failure_snippets(text, ("observed result", "actual", "observed", "thrown", "crash", "exception")),
        "failure_literals": _extract_failure_literals(text),
        "repair_bias": _first(repair_objective.get("fix_policy"), 4),
    }


def _hard_constraints(replacement_target: Dict[str, Any]) -> List[str]:
    out = [
        "Preserve the target replacement unit signature, resolved function name, storage qualifiers, template/enclosing scope, and return type.",
        "Return exactly one raw C/C++ replacement unit; no markdown, prose, code fences, includes, wrappers, or test code.",
        "Do not add global helpers, includes, namespaces, classes, main functions, or changes outside the target replacement unit.",
        "Do not invent APIs, macros, enum constants, types, fields, helpers, error codes, or constructor initializers outside RelatedCodeContext inventories.",
    ]
    out.extend(_security_output_rules(replacement_target))
    return _dedup(out)[:10]


def _security_output_rules(replacement_target: Dict[str, Any]) -> List[str]:
    envelope = replacement_target.get("replacement_envelope") or {}
    replacement_range = envelope.get("replacement_range") or {}
    original_range = envelope.get("original_function_range") or {}
    rules = [
        "Output raw source only: no markdown, prose, XML, or code fences.",
        "The output replaces replacement_target.replacement_envelope.replacement_range exactly.",
        "Preserve the resolved function name, signature, return type, and enclosing scope while eliminating the unsafe behavior.",
    ]
    if envelope.get("replacement_includes_prefix") or replacement_range.get("start_byte") != original_range.get("start_byte"):
        rules.append("Preserve the template/declaration prefix included in replacement_target.replacement_envelope.replacement_unit.")
    else:
        language = str(envelope.get("language") or "").lower()
        unit = str(envelope.get("replacement_unit") or "")
        if language in {"cpp", "c++"} and "template" not in unit[:200]:
            rules.append("Do not add an external template prefix unless it already exists in the replacement unit.")
    return rules


def _preserve_constraints(
    *,
    related_code_context: Dict[str, Any],
    plan_profile: Dict[str, Any],
    repair_objective: Dict[str, Any],
) -> List[str]:
    out = []
    for item in _first(plan_profile.get("must_preserve"), 4):
        out.append(str(item))
    for item in _first(repair_objective.get("route_policy"), 4):
        out.append(str(item))
    for item in _first((related_code_context.get("visible_api_inventory") or {}).get("source_policy"), 3):
        out.append(str(item))
    for item in _first((related_code_context.get("contract_brief") or {}).get("contract_policy"), 4):
        out.append(str(item))
    for item in _first((related_code_context.get("type_contract_inventory") or {}).get("type_use_policy"), 3):
        out.append(str(item))
    return _dedup(out)[:12]


def _allowed_edit_operations(repair_objective: Dict[str, Any]) -> List[str]:
    base = [
        "add or strengthen a guard before an unsafe read/write/dereference/index/allocation operation",
        "move an existing check before the risky use when that preserves valid-path behavior",
        "repair length/offset/remaining-size arithmetic that feeds a risky operation",
        "use existing project-local truncation/error macros or cleanup conventions from RelatedCodeContext",
        "refine an error/cleanup branch only when malformed input should fail closed",
    ]
    base.extend(str(item) for item in _first(repair_objective.get("preferred_patch_operators"), 6))
    return _dedup(base)[:12]


def _forbidden_edit_operations(
    *,
    related_code_context: Dict[str, Any],
    repair_objective: Dict[str, Any],
    plan_profile: Dict[str, Any],
) -> List[str]:
    out = [
        "do not hard-code the failing test input or expected output",
        "do not perform broad rewrites, unrelated refactors, or formatting-only churn",
        "do not introduce identifiers absent from allowed_symbol_surface or required_related_evidence",
        "do not change API arity, type layout, enum/macro names, or member fields without exact RelatedCodeContext evidence",
        "do not add only a generic top-level length guard if a nested sink remains reachable",
        "do not silence parser output or skip parsing without following project truncation/error convention",
        "do not advance pointers, offsets, or length counters before validating available bytes",
        "do not produce output-only, logging-only, or cosmetic patches while the unsafe path remains reachable",
    ]
    out.extend(str(item) for item in _first(plan_profile.get("forbidden_changes"), 6))
    out.extend(
        f"Default route forbids patch operator: {item}."
        for item in _first(repair_objective.get("forbidden_patch_operators"), 6)
    )
    for helper in _first((related_code_context.get("scope_aware_symbol_contract") or {}).get("risky_unqualified_helpers"), 8):
        out.append(f"do not introduce unqualified helper `{helper}` unless exact callable scope is proven by required_related_evidence")
    return _dedup(out)[:16]


def _security_constraints() -> List[str]:
    return [
        "Treat unsafe_paths[] as an evidence list, not as a preselected repair target.",
        "Choose an unsafe_paths[] entry only when it matches failure evidence, full target code, and unsafe_path_selection_policy.",
        "The patch must make the chosen path's sink unreachable on malformed input.",
        "The patch must prevent the unsafe read/write/dereference/index/allocation/lifetime operation before it executes.",
        "Any new guard must dominate the chosen unsafe path sink on the failing path.",
        "Length, offset, remaining-size, and allocation arithmetic must avoid overflow, underflow, and signedness surprises.",
        "Pointer or offset advancement must happen only after bounds validation.",
        "Malformed input should fail closed using existing project-local error/truncation conventions.",
        "New fail-closed returns or gotos must satisfy cleanup_obligations for the chosen unsafe path.",
        "Valid-path behavior and cleanup/resource conventions must remain intact.",
    ]


def _risk_plan_payload(
    risk_operations_context: Optional[Dict[str, Any]],
    func_code: str,
    replacement_target: Dict[str, Any],
) -> Dict[str, Any]:
    if isinstance(risk_operations_context, dict) and (
        risk_operations_context.get("unsafe_paths")
        or risk_operations_context.get("risk_operations")
        or risk_operations_context.get("risky_operations")
        or risk_operations_context.get("ranked_risks")
    ):
        risky_operations = risk_operations_context.get("risky_operations") or risk_operations_context.get("ranked_risks") or []
        risk_operations = risk_operations_context.get("risk_operations") or risky_operations
        unsafe_paths = risk_operations_context.get("unsafe_paths") or []
        return {
            "source": "security_repair_constraints_unsafe_path_brief",
            "path_summary": risk_operations_context.get("path_summary") or {},
            "risk_summary": risk_operations_context.get("risk_summary") or {},
            "security_failure_contract": risk_operations_context.get("security_failure_contract") or {},
            "unsafe_paths": compact_unsafe_paths(unsafe_paths, limit=8, max_text=MAX_TEXT),
            "risk_operations": [_compact_risk(item) for item in _first(risk_operations, 12)],
            # Compatibility alias for old consumers.
            "risky_operations": [_compact_risk(item) for item in _first(risky_operations, 12)],
            "wrong_fix_risks": [
                _compact_related_item(item)
                for item in _first(risk_operations_context.get("wrong_fix_risks"), 8)
            ],
            "constraints": [
                _clip(item, 320)
                for item in _first(risk_operations_context.get("constraints"), 10)
            ],
            "downstream_context_requests": [
                _compact_related_item(item)
                for item in _first(risk_operations_context.get("downstream_context_requests"), 8)
            ],
            "policy": _first(risk_operations_context.get("risk_policy"), 6),
        }
    return {
        "source": "no_risk_operations_context",
        "path_summary": {
            "unsafe_path_count": 0,
            "interpretation": "unsafe path brief unavailable; do not infer hazards from repair constraints fallback",
        },
        "risk_summary": {"risk_count": 0},
        "unsafe_paths": [],
        "risk_operations": [],
        "risky_operations": [],
        "downstream_context_requests": [],
        "policy": ["Unsafe path brief should be generated inside repair constraints from fail context and RelatedCodeContext."],
    }


def _compact_risk(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {"summary": _clip(item, MAX_TEXT)}
    return {
        "id": item.get("id"),
        "kind": item.get("kind"),
        "line": item.get("line"),
        "sink_code": _clip(item.get("sink_code") or item.get("code"), 260),
        "input_controlled_values": _first(item.get("input_controlled_values"), 10),
        "operation_summary": _compact_any(item.get("operation_summary") or {}, 360),
        "operand_roles": _compact_any(item.get("operand_roles") or {}, 420),
        "boundary_facts": _compact_any(item.get("boundary_facts") or {}, 360),
        "existing_guards": [_compact_guard_context(value) for value in _first(item.get("existing_guards"), 4)],
        "guard_gap": _compact_any(item.get("guard_gap") or {}, 360),
        "missing_property": _clip(item.get("missing_property") or item.get("required_property"), 260),
        "dominance_requirement": _clip(item.get("dominance_requirement"), 260),
        "suggested_patch_operator": item.get("suggested_patch_operator"),
        "repair_intent": _compact_any(item.get("repair_intent") or {}, 360),
        "required_related_context": _clip(item.get("required_related_context"), 260),
        "role": item.get("role"),
        "why_risky": _clip(item.get("why_risky"), 260),
        "wrong_fix_trap": _clip(item.get("wrong_fix_trap"), 260),
        "safe_repair_expectation": _clip(item.get("safe_repair_expectation"), 260),
        "confidence": item.get("confidence"),
    }


def _compact_risk_operations_context(context: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not isinstance(context, dict):
        return {}
    return {
        "analysis_engine": context.get("analysis_engine") or {},
        "path_summary": context.get("path_summary") or {},
        "risk_summary": context.get("risk_summary") or {},
        "security_failure_contract": context.get("security_failure_contract") or {},
        "unsafe_paths": [
            compact_unsafe_path(item, max_text=MAX_TEXT)
            for item in _first(context.get("unsafe_paths"), 6)
        ],
        "risk_operations": [
            _compact_risk(item)
            for item in _first(context.get("risk_operations") or context.get("risky_operations") or context.get("ranked_risks"), 8)
        ],
        "risky_operations": [
            _compact_risk(item)
            for item in _first(context.get("risky_operations") or context.get("ranked_risks"), 8)
        ],
        "wrong_fix_risks": [
            _compact_related_item(item)
            for item in _first(context.get("wrong_fix_risks"), 6)
        ],
        "constraints": [_clip(item, 260) for item in _first(context.get("constraints"), 8)],
    }


def _repair_decision_context(
    *,
    risk_plan: Dict[str, Any],
    selection_policy: Dict[str, Any],
    decision_aids: List[dict],
    failure_summary: Dict[str, Any],
) -> Dict[str, Any]:
    operations = [
        item for item in _first(risk_plan.get("risk_operations") or risk_plan.get("risky_operations"), 8)
        if isinstance(item, dict)
    ]
    return {
        "role": "pre_fix_triage_context_no_preselected_path",
        "fix_agent_should": [
            "match failure evidence to one unsafe_path and its linked risk_operation before editing",
            "use operation_summary, operand_roles, boundary_facts, and guard_gap to understand what must be guarded",
            "prefer existing project guard/fail-closed idioms over invented helpers or new types",
            "emit a minimal source change only after the chosen operation contract is satisfied",
        ],
        "fix_agent_should_not": [
            "treat unsafe_paths order as ranking",
            "repair a generic risky-looking line that does not explain the failing oracle",
            "invent types, headers, helpers, macros, enum constants, fields, or error codes outside allowed_symbol_surface",
            "change output text or valid-path behavior while the unsafe runtime path remains reachable",
        ],
        "selection_policy": selection_policy,
        "operation_evidence": [
            {
                "id": operation.get("id"),
                "kind": operation.get("kind"),
                "line": operation.get("line"),
                "sink_code": _clip(operation.get("sink_code"), 220),
                "operation_summary": _compact_any(operation.get("operation_summary") or {}, 300),
                "operand_roles": _compact_any(operation.get("operand_roles") or {}, 360),
                "boundary_facts": _compact_any(operation.get("boundary_facts") or {}, 260),
                "guard_gap": _compact_any(operation.get("guard_gap") or {}, 320),
                "repair_intent": _compact_any(operation.get("repair_intent") or {}, 260),
                "wrong_fix_trap": _clip(operation.get("wrong_fix_trap"), 220),
            }
            for operation in operations
        ],
        "path_decision_aids": _first(decision_aids, 6),
        "failure_terms": _failure_terms(failure_summary),
    }


def _validation_focus() -> List[str]:
    return [
        "Verify the patch chose an unsafe_paths[] entry supported by failure evidence, not merely the first listed path.",
        "Verify the chosen unsafe_paths[] sink is no longer reachable on the malformed failing path.",
        "Verify any new guard dominates the chosen sink before pointer/index/buffer use or pointer/offset advancement.",
        "Verify new fail-closed control flow satisfies cleanup_obligations.",
        "Verify malformed input follows existing error/truncation conventions.",
        "Verify valid inputs still produce the original successful behavior.",
    ]


def _repair_plan_alias(constraints: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "target_function": constraints.get("target_function"),
        "route": constraints.get("route"),
        "objective": constraints.get("objective"),
        "planner_focus": constraints.get("planner_focus"),
        "patch_shape": constraints.get("patch_shape") or [],
        "failing_behavior": constraints.get("failing_behavior") or {},
        "repair_intent": "Choose the minimal vulnerability repair inside the provided target function that satisfies repair_constraints.",
        "steps": [
            "Inspect unsafe_paths[] as evidence, not as an ordered list or preselected repair target.",
            "Use unsafe_path_selection_policy and unsafe_path_decision_aids to choose a path supported by FAILURE EVIDENCE and the full target function.",
            "Reject paths whose sink kind, symbols, guard gap, or fail-closed behavior do not explain the observed failure.",
            "Patch at or before the chosen path's recommended_patch_site so the guard/check dominates the chosen sink.",
            "Use the chosen path's data_state_before_sink, existing_guards, cleanup_obligations, and valid_path_preservation as the repair contract.",
        ],
        "constraints": {
            "must_preserve": (constraints.get("hard_constraints") or []) + (constraints.get("preserve_constraints") or []),
            "forbidden_changes": constraints.get("forbidden_edit_operations") or [],
            "symbol_introduction_policy": constraints.get("symbol_introduction_policy") or [],
            "required_related_evidence": constraints.get("required_related_evidence") or [],
        },
        "plan_safety_checks": constraints.get("validation_focus") or [],
        "repair_decision_context": constraints.get("repair_decision_context") or {},
        "unsafe_path_selection_policy": constraints.get("unsafe_path_selection_policy") or {},
        "unsafe_paths": constraints.get("unsafe_paths") or [],
        "unsafe_path_decision_aids": constraints.get("unsafe_path_decision_aids") or [],
        "evidence_refs": constraints.get("required_related_evidence") or [],
        "confidence": "medium",
    }


def _unsafe_path_selection_policy(failure_summary: Dict[str, Any]) -> Dict[str, Any]:
    categories = _first((failure_summary or {}).get("categories"), 8)
    return {
        "role": "criteria_only_no_preselected_path",
        "unsafe_paths_are": "static evidence candidates, not a ranked repair plan",
        "must_choose_path_by": [
            "failure evidence names or signals mention the same operation, symbol family, malformed-input behavior, sanitizer class, or failing test area",
            "the candidate sink is reachable in the shown target function before the observed crash/fail-closed boundary",
            "the candidate has a concrete missing guard, size, pointer, lifetime, or cleanup property that explains the failure",
            "the repair can use identifiers, macros, error paths, and cleanup conventions already visible or allowed by RelatedCodeContext",
        ],
        "reject_path_when": [
            "it is merely the first unsafe_paths[] entry but has no specific match to failure evidence",
            "its sink kind cannot explain the observed crash, sanitizer signal, or malformed-input failure",
            "fixing it would require inventing a helper, type, macro, enum, field, include, or error code outside allowed_symbol_surface",
            "it would change valid-path output or broad control flow instead of closing only malformed input",
        ],
        "tie_breakers": [
            "prefer paths whose symbols appear in failure evidence or high-priority related context",
            "prefer paths with a nearby project-local guard or fail-closed idiom that can be strengthened",
            "prefer paths with known cleanup_obligations over paths whose cleanup state is unknown",
            "prefer the smallest edit that dominates the sink without moving pointer/offset consumption earlier",
        ],
        "failure_categories": categories,
    }


def _unsafe_path_decision_aids_from_paths(paths: List[dict], failure_summary: Dict[str, Any]) -> List[dict]:
    out = []
    failure_categories = _first((failure_summary or {}).get("categories"), 8)
    failure_terms = _failure_terms(failure_summary)
    for idx, path in enumerate(_first(paths, 6), start=1):
        if not isinstance(path, dict):
            continue
        sink = path.get("sink") or {}
        patch_site = path.get("recommended_patch_site") or {}
        state = path.get("data_state_before_sink") or {}
        typed_facts = state.get("typed_buffer_facts") or {}
        sink_symbols = _first(sink.get("symbols"), 8)
        symbol_hits = _symbol_hits_in_failure(sink_symbols, failure_terms)
        existing_guards = [guard for guard in _first(path.get("existing_guards"), 4) if isinstance(guard, dict)]
        cleanup = [item for item in _first(path.get("cleanup_obligations"), 4) if isinstance(item, dict)]
        out.append(
            {
                "id": f"unsafe_path_decision_{idx}",
                "unsafe_path_id": path.get("id"),
                "sink": {
                    "kind": sink.get("kind"),
                    "line": sink.get("line"),
                    "code": _clip(sink.get("code"), 220),
                    "symbols": sink_symbols,
                },
                "selection_signals": {
                    "symbol_hits_in_failure_evidence": symbol_hits,
                    "sink_kind_matches_failure_categories": _sink_kind_matches_failure_categories(sink.get("kind"), failure_categories),
                    "has_dominating_guard": any(guard.get("dominates_sink") is True for guard in existing_guards),
                    "has_uncovered_guard_gap": any(not guard.get("covers_sink") for guard in existing_guards),
                    "cleanup_state": _cleanup_state(cleanup),
                },
                "patch_feasibility": {
                    "operator_hint": patch_site.get("operator") or patch_site.get("kind"),
                    "line": patch_site.get("line"),
                    "before_sink": patch_site.get("before_sink"),
                    "dominance_requirement": _clip(patch_site.get("dominance_requirement"), 220),
                    "required_property": _clip(patch_site.get("required_property"), 260),
                },
                "symbol_facts": {
                    "pointer_symbols": _first(typed_facts.get("pointer_symbols"), 8),
                    "capacity_symbols": _first(typed_facts.get("capacity_symbols"), 8),
                    "remaining_symbols": _first(typed_facts.get("remaining_symbols"), 8),
                    "consumed_symbols": _first(typed_facts.get("consumed_symbols"), 8),
                    "needed_symbols": _first(typed_facts.get("needed_symbols"), 8),
                },
                "guard_evidence": [
                    {
                        "line": guard.get("line"),
                        "code": _clip(guard.get("code"), 180),
                        "dominates_sink": guard.get("dominates_sink"),
                        "covers_sink": guard.get("covers_sink"),
                        "missing": _clip(guard.get("missing"), 180),
                    }
                    for guard in existing_guards
                ],
                "fail_closed_action": _clip(path.get("fail_closed_expectation"), 260),
                "cleanup_preservation": [
                    {
                        "resource": obligation.get("resource"),
                        "required_on_fail_closed": obligation.get("required_on_fail_closed"),
                        "cleanup_call": _clip(obligation.get("cleanup_call"), 180),
                        "label": obligation.get("label"),
                        "label_line": obligation.get("label_line"),
                    }
                    for obligation in cleanup
                ],
                "valid_path_preservation": _clip(path.get("valid_path_preservation"), 260),
                "wrong_fix_trap": _clip(path.get("wrong_fix_trap"), 220),
                "failure_categories": failure_categories,
                "confidence": path.get("confidence") or "medium",
            }
        )
    return out


def _failure_terms(failure_summary: Dict[str, Any]) -> List[str]:
    values = []
    for key in ("expected_behavior", "observed_behavior", "failure_literals", "categories"):
        values.extend(str(item) for item in _first((failure_summary or {}).get(key), 20))
    return _dedup(re.findall(r"\b[A-Za-z_]\w*\b", " ".join(values)))[:80]


def _symbol_hits_in_failure(symbols: List[Any], failure_terms: List[str]) -> List[str]:
    terms = {str(item).lower() for item in failure_terms or []}
    hits = []
    for symbol in symbols or []:
        text = str(symbol or "").strip()
        if text and text.lower() in terms:
            hits.append(text)
    return _dedup(hits)[:8]


def _sink_kind_matches_failure_categories(kind: Any, categories: List[str]) -> bool:
    text = " ".join(str(item).lower() for item in categories or [])
    kind_text = str(kind or "").lower()
    if any(token in text for token in ("bounds", "length", "size", "runtime", "memory", "overflow", "oob", "sanitizer")):
        return kind_text in {
            "array_access",
            "pointer_index_or_deref",
            "pointer_or_member_deref",
            "buffer_or_memory_call",
            "allocation_or_size_call",
            "project_bounds_or_extract_operation",
            "pointer_or_offset_advance",
            "length_controlled_loop",
        }
    if any(token in text for token in ("lifetime", "ownership", "double", "free", "use_after")):
        return kind_text == "free_or_lifetime_transition"
    return False


def _cleanup_state(cleanup: List[dict]) -> str:
    if not cleanup:
        return "unknown"
    if any(item.get("required_on_fail_closed") is True for item in cleanup):
        return "known_fail_closed_or_cleanup_path"
    if any(item.get("resource") == "unknown" for item in cleanup):
        return "unknown"
    return "observed_cleanup_context"


def _route_directive(objective: Dict[str, Any], failure_summary: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "authority": "default_project_route_is_primary",
        "route": "security_repair",
        "bug_kind": objective.get("bug_kind"),
        "confidence": objective.get("confidence") or "medium",
        "validation_oracle": objective.get("validation_oracle") or failure_summary.get("oracle_kind"),
        "oracle_subkind": objective.get("oracle_subkind"),
        "repair_goal": _clip(objective.get("repair_goal") or failure_summary.get("repair_goal"), 320),
        "failure_categories": _first(objective.get("failure_categories") or failure_summary.get("categories"), 8),
        "fix_policy": [_clip(item, 200) for item in _first(objective.get("fix_policy"), 4)],
        "route_policy": [_clip(item, 200) for item in _first(objective.get("route_policy"), 4)],
        "heuristic_boundary": (
            "No TargetCodeContext localization is used. Choose the edit location from full target code, "
            "failure evidence, RelatedCodeContext contracts, and constraints only."
        ),
    }


def _required_related_evidence(context: Dict[str, Any]) -> List[dict]:
    ranked = context.get("ranked_context") or {}
    out = []
    for item in _first(ranked.get("must_read"), 8):
        out.append(_compact_related_item(item))
    if not out:
        for item in _first(ranked.get("likely_relevant"), 5):
            out.append(_compact_related_item(item))
    return out[:8]


def _related_contracts_to_preserve(context: Dict[str, Any]) -> List[dict]:
    out = []
    for group in _first((context.get("contract_brief") or {}).get("high_priority_contract_groups"), 5):
        out.append(_compact_related_item(group))
    for item in _first(context.get("external_behavioral_contracts"), 5):
        out.append(_compact_related_item(item))
    return out[:8]


def _compact_related_item(item: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(item, dict):
        return {"summary": _clip(item, MAX_TEXT)}
    return {
        "type": item.get("type"),
        "kind": item.get("kind"),
        "symbol": item.get("symbol"),
        "source": item.get("source"),
        "function": item.get("function"),
        "summary": _clip(item.get("summary") or item.get("request"), MAX_TEXT),
        "warning": _clip(item.get("warning"), MAX_TEXT),
        "avoid_when": _clip(item.get("avoid_when"), MAX_TEXT),
        "examples": _first(item.get("examples"), 8),
        "signature": _clip(item.get("signature"), MAX_TEXT),
        "risk_id": item.get("risk_id"),
        "line": item.get("line"),
        "symbols": _first(item.get("symbols"), 8),
        "allowed_constants": _first(item.get("allowed_constants"), 12),
    }


def _compact_guard_context(item: Any) -> Dict[str, Any]:
    if isinstance(item, dict):
        return {
            "kind": item.get("kind"),
            "line": item.get("line"),
            "code": _clip(item.get("code"), 220),
            "source": item.get("source"),
        }
    return {"code": _clip(item, 220)}


def _compact_any(value: Any, max_chars: int) -> Any:
    if isinstance(value, dict):
        return {
            str(key): _compact_any(item, max_chars)
            for key, item in value.items()
            if item not in (None, "", [], {})
        }
    if isinstance(value, list):
        return [_compact_any(item, max_chars) for item in value[:8]]
    if isinstance(value, tuple):
        return [_compact_any(item, max_chars) for item in list(value[:8])]
    if isinstance(value, (bool, int, float)):
        return value
    return _clip(value, max_chars)


def _compact_repair_objective(objective: Dict[str, Any], failure_summary: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bug_kind": objective.get("bug_kind"),
        "metadata_label": objective.get("metadata_label"),
        "validation_oracle": objective.get("validation_oracle") or failure_summary.get("oracle_kind"),
        "oracle_subkind": objective.get("oracle_subkind"),
        "route": "security_repair",
        "confidence": objective.get("confidence"),
        "repair_goal": _clip(objective.get("repair_goal") or failure_summary.get("repair_goal"), 260),
        "failure_categories": _first(objective.get("failure_categories") or failure_summary.get("categories"), 8),
        "fix_policy": [_clip(item, 180) for item in _first(objective.get("fix_policy"), 4)],
        "route_policy": [_clip(item, 180) for item in _first(objective.get("route_policy"), 4)],
        "preferred_patch_operators": _first(objective.get("preferred_patch_operators"), 6),
        "forbidden_patch_operators": _first(objective.get("forbidden_patch_operators"), 6),
    }


def _compact_plan_profile(profile: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "route": profile.get("route"),
        "planning_focus": profile.get("planning_focus"),
        "repair_goal": _clip(profile.get("repair_goal"), 260),
        "patch_shape": [_clip(item, 220) for item in _first(profile.get("patch_shape"), 4)],
        "step_priorities": [_clip(item, 220) for item in _first(profile.get("step_priorities"), 4)],
        "must_preserve": [_clip(item, 220) for item in _first(profile.get("must_preserve"), 4)],
        "forbidden_changes": [_clip(item, 220) for item in _first(profile.get("forbidden_changes"), 5)],
    }


def _confidence_notes(failure_summary: Dict[str, Any], related_evidence: List[dict]) -> List[str]:
    notes = []
    if not failure_summary.get("expected_behavior") and not failure_summary.get("observed_behavior"):
        notes.append("Failure evidence has weak expected/observed snippets; FixAgent must infer cautiously from full context.")
    if not related_evidence:
        notes.append("RelatedCodeContext did not provide strong must-read evidence; avoid introducing new symbols.")
    notes.append("No target-localizer primary edit location is provided by design.")
    return notes


def _extract_failure_snippets(text: str, labels: tuple) -> List[str]:
    snippets = []
    lines = [line.strip() for line in (text or "").splitlines() if line.strip()]
    for idx, line in enumerate(lines):
        lower = line.lower()
        if not any(label in lower for label in labels):
            continue
        snippets.append(_clip(line, 360))
        if idx + 1 < len(lines) and len(snippets) < 8:
            snippets.append(_clip(lines[idx + 1], 360))
    return _dedup(snippets)[:8]


def _extract_failure_literals(text: str) -> List[str]:
    literals = []
    for quoted in re.findall(r'"([^"\n]{1,120})"|\'([^\'\n]{1,120})\'', text or ""):
        for item in quoted:
            if item:
                literals.append(item)
    return _dedup(literals)[:16]


def _first(value: Any, limit: int) -> List[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value[:limit]
    if isinstance(value, tuple):
        return list(value[:limit])
    return [value]


def _dedup(values: List[Any]) -> List[str]:
    out = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


def _clip(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"
