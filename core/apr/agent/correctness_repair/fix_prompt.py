def build_correctness_fix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: str,
    repair_objective_json: str,
    repair_brief_json: str,
) -> str:
    return f"""CORRECTNESS REPAIR TASK
Bug ID: {bug_id}
Repair only the target C/C++ replacement unit below. This route is for a general correctness bug:
the patch must make observable behavior match the expected output, return value, exception, or state.

TARGET REPLACEMENT UNIT TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET REPLACEMENT UNIT
{func_code}
END TARGET REPLACEMENT UNIT

FAILURE EVIDENCE
Use this metadata evidence to identify the concrete expected-vs-actual behavior.
{failed_tests_context}

CORRECTNESS OBJECTIVE
BEGIN REPAIR OBJECTIVE JSON
{repair_objective_json}
END REPAIR OBJECTIVE JSON

REPAIR BRIEF
This is the single compact repair plan synthesized from failure evidence, target localization,
and related contracts. Treat it as the source of truth for edit location, allowed symbols,
must-preserve constraints, and forbidden changes.
REPAIR BRIEF classifier_directive is the route authority. Interpret heuristic edit locations and
repair_plan.steps only inside classifier_directive.repair_goal, fix_policy, route_policy, and
planner_profile.patch_shape.
BEGIN REPAIR BRIEF JSON
{repair_brief_json}
END REPAIR BRIEF JSON

CORRECTNESS POLICY
1. First state internally the exact expected behavior and observed behavior from FAILURE EVIDENCE.
2. Treat REPAIR BRIEF classifier_directive as the primary repair objective; do not convert this
   correctness route into a vulnerability-style guard unless the classifier/failure evidence requires it.
3. Patch the value-flow, predicate, dispatch, numeric/rounding, formatting, iterator-progress, or state transition
   that directly explains the expected-vs-actual mismatch.
4. Follow REPAIR BRIEF planner_profile plus repair_plan.semantic_contracts, repair_intent,
   primary_edit_location, steps, and plan_safety_checks.
   Use fallback_edit_locations only when the primary location cannot satisfy the failure contract.
5. Preserve REPAIR BRIEF target_contract.output_contract plus repair_plan.constraints.must_preserve and forbidden_changes.
6. Use REPAIR BRIEF allowed_symbol_surface and repair_plan.constraints.required_related_evidence before adding or changing any API,
   macro, enum constant, type, field, or helper.
7. Do not introduce a visible-but-not-automatically-introducible helper unless required_related_evidence proves the exact callable form.
8. Reuse existing project idioms. For low-level output iterator or reserve/write paths, preserve iterator advancement
   and buffer contracts shown by the repair brief.
9. Do not add broad defensive guards, error returns, or exception paths for valid-input tests unless the failure
   evidence explicitly expects an error.
10. Do not rewrite unrelated memory/buffer mechanics, ownership flow, formatting style, or helper-call sequences unless
   the repair brief proves that exact mechanics causes the observable mismatch.
11. Keep the patch minimal and localized to the ranked repair-site evidence.

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ replacement unit for {func_name}.
2. Preserve the existing signature, template context, coding style, macros, and helper APIs unless REPAIR BRIEF explicitly permits otherwise.
3. Do not add includes, new global helpers, main functions, unrelated refactors, wrappers, namespaces, classes, or changes outside the target replacement unit.
4. Do not call or rely on an API, macro, type, helper, ownership convention, or error-handling convention unless it appears in REPAIR BRIEF allowed_symbol_surface or repair_plan.constraints.required_related_evidence.
5. Do not introduce member fields or constructor initializer entries outside REPAIR BRIEF allowed_symbol_surface.member_fields.
6. Return raw source only: no markdown, no explanation, no code fences, no backticks.

FIXED REPLACEMENT UNIT
"""
