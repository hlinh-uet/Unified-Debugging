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
This is the single compact repair plan synthesized from failure evidence, target localization,
and related contracts. Treat it as the source of truth for unsafe sink/guard evidence,
allowed symbols, must-preserve constraints, and forbidden changes.
REPAIR BRIEF classifier_directive is the route authority. Interpret heuristic edit locations and
repair_plan.steps only inside classifier_directive.repair_goal, fix_policy, route_policy, and
planner_profile.patch_shape.
BEGIN REPAIR BRIEF JSON
{repair_brief_json}
END REPAIR BRIEF JSON

SECURITY POLICY
1. Identify the unsafe sink first: pointer dereference, array/index access, memcpy/memmove/read/write, allocation size,
   integer size flow, free/lifetime operation, or cleanup/error transition.
2. Treat REPAIR BRIEF classifier_directive as the primary repair objective; do not convert this
   security route into output-only correctness tuning while an unsafe path remains reachable.
3. Patch the nearest guard, bounds/length calculation, allocation size, lifetime transition, or cleanup/error path that
   prevents the unsafe behavior.
4. Follow REPAIR BRIEF planner_profile plus repair_plan.semantic_contracts, repair_intent,
   primary_edit_location, steps, and plan_safety_checks.
   Use fallback_edit_locations only when the primary location cannot guard or feed the unsafe sink.
5. Preserve valid-path behavior and existing cleanup/resource conventions. Fail closed only for invalid or malformed
   inputs supported by failure/source evidence.
6. Use REPAIR BRIEF allowed_symbol_surface and repair_plan.constraints.required_related_evidence before adding or changing any validation
   helper, macro, enum constant, error code, type, field, or cleanup call.
7. Do not introduce a visible-but-not-automatically-introducible helper unless required_related_evidence proves the exact callable form.
8. Do not produce an output-only, cosmetic, formatting-only, or logging-only patch while the unsafe sink remains reachable.
9. Do not delete error handling or cleanup unconditionally. Refine predicates/guards so valid and invalid paths stay distinct.
10. Preserve REPAIR BRIEF repair_plan.constraints.must_preserve, avoid constraints.forbidden_changes,
   and keep the patch minimal and localized to the ranked unsafe-sink or guard evidence.

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ replacement unit for {func_name}.
2. Preserve the existing signature, template context, coding style, macros, and helper APIs unless REPAIR BRIEF explicitly permits otherwise.
3. Do not add includes, new global helpers, main functions, unrelated refactors, wrappers, namespaces, classes, or changes outside the target replacement unit.
4. Do not call or rely on an API, macro, type, helper, ownership convention, or error-handling convention unless it appears in REPAIR BRIEF allowed_symbol_surface or repair_plan.constraints.required_related_evidence.
5. Do not introduce member fields or constructor initializer entries outside REPAIR BRIEF allowed_symbol_surface.member_fields.
6. Return raw source only: no markdown, no explanation, no code fences, no backticks.

FIXED REPLACEMENT UNIT
"""
