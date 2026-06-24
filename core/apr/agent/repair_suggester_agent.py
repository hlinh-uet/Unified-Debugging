from typing import Any, Dict, List, Optional, Tuple

from core.apr.agent.correctness_repair.profile import (
    repair_planning_profile as correctness_repair_planning_profile,
)
from core.apr.agent.security_repair.profile import (
    repair_planning_profile as security_repair_planning_profile,
)
from core.apr.artifacts import write_repair_suggestion_artifact


MAX_TEXT = 420


def build_repair_suggestion(
    *,
    func_name: str,
    target_code_context: Dict[str, Any],
    related_code_context: Dict[str, Any],
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    """Build the compact repair plan that FixAgent should use to write the patch."""
    repair_objective = repair_objective or {}
    failure_contract = target_code_context.get("failure_contract") or {}
    classifier_directive = _classifier_directive(repair_objective, failure_contract)
    route = str(classifier_directive.get("route") or "").strip()
    plan_profile = _route_plan_profile(
        route=route,
        repair_objective=repair_objective,
        failure_contract=failure_contract,
    )
    primary_atom = _first_dict(target_code_context.get("ranked_repair_atoms"))
    primary_site = _first_dict(target_code_context.get("ranked_repair_sites"))
    alternatives = _alternate_locations(
        target_code_context.get("ranked_repair_atoms") or [],
        target_code_context.get("ranked_repair_sites") or [],
    )
    primary_location = _primary_edit_location(primary_atom, primary_site)
    related_evidence = _required_related_evidence(related_code_context)
    contract_brief = related_code_context.get("contract_brief") or {}
    scope_contract = related_code_context.get("scope_aware_symbol_contract") or {}
    envelope = target_code_context.get("target_envelope") or {}
    edit_scope = target_code_context.get("edit_scope") or {}
    repair_plan = _build_repair_plan(
        func_name=func_name,
        route=route,
        classifier_directive=classifier_directive,
        failure_contract=failure_contract,
        primary_atom=primary_atom,
        primary_site=primary_site,
        primary_location=primary_location,
        alternatives=alternatives,
        plan_profile=plan_profile,
        edit_scope=edit_scope,
        related_evidence=related_evidence,
        target_code_context=target_code_context,
        related_code_context=related_code_context,
        repair_objective=repair_objective,
    )
    suggestion = {
        "analysis_engine": {
            "name": "repair_suggester_agent",
            "version": 4,
            "strategy": "classifier_directive_repair_plan_synthesis",
            "role": "Convert classifier objective, target localization, and related contracts into one compact repair plan.",
        },
        "repair_objective": _compact_repair_objective(repair_objective, failure_contract),
        "classifier_directive": classifier_directive,
        "planner_profile": _compact_plan_profile(plan_profile),
        "target_contract": {
            "function_name": envelope.get("resolved_function_name") or envelope.get("function_name") or func_name,
            "source_file": envelope.get("source_file"),
            "replacement_range": envelope.get("replacement_range") or {},
            "replacement_includes_prefix": envelope.get("replacement_includes_prefix"),
            "output_contract": _first(envelope.get("output_contract"), 6),
            "notes": _first(envelope.get("notes"), 4),
        },
        "failure_summary": {
            "categories": _first(failure_contract.get("categories"), 8),
            "oracle_kind": failure_contract.get("oracle_kind"),
            "expected_behavior": [_clip(item, 260) for item in _first(failure_contract.get("expected_behavior"), 3)],
            "observed_behavior": [_clip(item, 260) for item in _first(failure_contract.get("observed_behavior"), 3)],
            "failure_literals": [_clip(item, 120) for item in _first(failure_contract.get("failure_literals"), 8)],
            "repair_bias": [_clip(item, 220) for item in _first(failure_contract.get("repair_bias"), 4)],
        },
        "repair_plan": repair_plan,
        "allowed_symbol_surface": {
            "functions": _first(contract_brief.get("introducible_functions") or contract_brief.get("allowed_functions"), 30),
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
            "RepairObjectiveClassifier is the route authority; Target/Related heuristics may rank evidence but must not change the repair objective.",
            "FixAgent should follow repair_plan and planner_profile as the only patch-planning brief.",
            "TargetCodeContext is evidence for location/slice only; RelatedCodeContext is evidence for API/macro/type validity only.",
            "If the primary edit location conflicts with failure evidence, use fallback_edit_locations but keep the same plan constraints.",
        ],
        "debug_summary": {
            "failed_tests_excerpt": _clip(failed_tests_context, 900),
            "target_engine": (target_code_context.get("analysis_engine") or {}).get("name"),
            "related_engine": (related_code_context.get("analysis_engine") or {}).get("name"),
        },
    }
    return suggestion


def _build_repair_plan(
    *,
    func_name: str,
    route: str,
    classifier_directive: Dict[str, Any],
    failure_contract: Dict[str, Any],
    primary_atom: Dict[str, Any],
    primary_site: Dict[str, Any],
    primary_location: Dict[str, Any],
    alternatives: List[dict],
    plan_profile: Dict[str, Any],
    edit_scope: Dict[str, Any],
    related_evidence: List[dict],
    target_code_context: Dict[str, Any],
    related_code_context: Dict[str, Any],
    repair_objective: Dict[str, Any],
) -> Dict[str, Any]:
    semantic_contracts = _compact_semantic_contracts(target_code_context.get("semantic_repair_contracts") or [])
    scope_contract = related_code_context.get("scope_aware_symbol_contract") or {}
    return {
        "target_function": func_name,
        "route": route or "unknown",
        "objective": _clip(classifier_directive.get("repair_goal"), 320),
        "planner_focus": plan_profile.get("planning_focus") or "minimal_semantic_repair",
        "patch_shape": [_clip(item, 260) for item in _first(plan_profile.get("patch_shape"), 4)],
        "semantic_contracts": semantic_contracts,
        "failing_behavior": {
            "categories": _first(failure_contract.get("categories"), 8),
            "oracle_kind": failure_contract.get("oracle_kind"),
            "expected_behavior": [_clip(item, 260) for item in _first(failure_contract.get("expected_behavior"), 3)],
            "observed_behavior": [_clip(item, 260) for item in _first(failure_contract.get("observed_behavior"), 3)],
        },
        "repair_intent": _repair_intent(
            route=route,
            failure_contract=failure_contract,
            primary_atom=primary_atom,
            primary_site=primary_site,
            plan_profile=plan_profile,
        ),
        "primary_edit_location": primary_location,
        "fallback_edit_locations": alternatives,
        "allowed_edit_scope": _first(edit_scope.get("preferred_allowed_ranges"), 4),
        "steps": _plan_steps(
            route=route,
            plan_profile=plan_profile,
            semantic_contracts=semantic_contracts,
            primary_atom=primary_atom,
            primary_site=primary_site,
            failure_contract=failure_contract,
            related_code_context=related_code_context,
            repair_objective=repair_objective,
        ),
        "constraints": {
            "must_preserve": _must_preserve(
                target_code_context=target_code_context,
                related_code_context=related_code_context,
                repair_objective=repair_objective,
                plan_profile=plan_profile,
            ),
            "forbidden_changes": _forbidden_changes(
                route=route,
                primary_atom=primary_atom,
                related_code_context=related_code_context,
                repair_objective=repair_objective,
                plan_profile=plan_profile,
            ),
            "symbol_introduction_policy": _first(scope_contract.get("symbol_introduction_policy"), 4),
            "risky_unqualified_helpers": _first(scope_contract.get("risky_unqualified_helpers"), 20),
            "required_related_evidence": related_evidence,
        },
        "plan_safety_checks": _plan_safety_checks(
            semantic_contracts=semantic_contracts,
            scope_contract=scope_contract,
            primary_atom=primary_atom,
        ),
        "evidence_refs": _evidence_refs(
            primary_atom=primary_atom,
            primary_site=primary_site,
            target_code_context=target_code_context,
            related_evidence=related_evidence,
        ),
        "confidence": _decision_confidence(primary_atom, primary_site),
    }


def run_repair_suggester_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    func_name: str,
    target_code_context: Dict[str, Any],
    related_code_context: Dict[str, Any],
    failed_tests_context: str,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Tuple[dict, dict]:
    suggestion = build_repair_suggestion(
        func_name=func_name,
        target_code_context=target_code_context,
        related_code_context=related_code_context,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
    )
    artifact = write_repair_suggestion_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        repair_suggestion=suggestion,
    )
    return suggestion, artifact


def _primary_edit_location(atom: Dict[str, Any], site: Dict[str, Any]) -> Dict[str, Any]:
    if atom:
        return {
            "source": "target_ranked_repair_atom",
            "id": atom.get("id"),
            "kind": atom.get("kind"),
            "line_range": atom.get("line_range"),
            "byte_range": atom.get("byte_range"),
            "text": _clip(atom.get("text"), MAX_TEXT),
            "operator_hint": atom.get("operator_hint"),
            "parent_statement": _compact_statement(atom.get("parent_statement") or {}),
            "repair_site_id": atom.get("repair_site_id"),
            "failure_slice_id": atom.get("failure_slice_id"),
            "evidence": _first(((atom.get("evidence") or {}).get("reasons") or []), 5),
        }
    if site:
        return {
            "source": "target_ranked_repair_site",
            "id": site.get("id"),
            "kind": site.get("scope_kind"),
            "line_range": site.get("line_range"),
            "byte_range": site.get("byte_range"),
            "edit_intent": site.get("edit_intent"),
            "parent_statement": _compact_statement(site.get("primary_statement") or {}),
            "failure_slice_id": site.get("failure_slice_id"),
            "evidence": _clip((site.get("evidence") or {}).get("reason"), MAX_TEXT),
        }
    return {"source": "none", "note": "No ranked repair atom or site was available."}


def _alternate_locations(atoms: List[dict], sites: List[dict]) -> List[dict]:
    out = []
    for atom in atoms[1:4]:
        out.append(
            {
                "source": "target_ranked_repair_atom",
                "id": atom.get("id"),
                "kind": atom.get("kind"),
                "line_range": atom.get("line_range"),
                "text": _clip(atom.get("text"), 220),
                "operator_hint": atom.get("operator_hint"),
            }
        )
    for site in sites[:3]:
        site_id = site.get("id")
        if any(item.get("repair_site_id") == site_id or item.get("id") == site_id for item in out):
            continue
        out.append(
            {
                "source": "target_ranked_repair_site",
                "id": site_id,
                "kind": site.get("scope_kind"),
                "line_range": site.get("line_range"),
                "edit_intent": site.get("edit_intent"),
                "statement": _clip((site.get("primary_statement") or {}).get("text"), 220),
            }
        )
    return out[:5]


def _plan_steps(
    *,
    route: str,
    plan_profile: Dict[str, Any],
    semantic_contracts: List[dict],
    primary_atom: Dict[str, Any],
    primary_site: Dict[str, Any],
    failure_contract: Dict[str, Any],
    related_code_context: Dict[str, Any],
    repair_objective: Dict[str, Any],
) -> List[str]:
    steps = []
    repair_goal = _clip(repair_objective.get("repair_goal"), 260)
    if repair_goal:
        steps.append(f"Keep the classifier repair goal as the patch objective: {repair_goal}")
    for contract in semantic_contracts[:4]:
        focus = contract.get("repair_focus") or contract.get("kind")
        summary = contract.get("summary")
        if focus and summary:
            steps.append(f"Honor semantic contract `{focus}`: {_clip(summary, 260)}")
    for item in _first(plan_profile.get("step_priorities"), 4):
        steps.append(str(item))
    preferred_ops = _first(repair_objective.get("preferred_patch_operators"), 4)
    if preferred_ops:
        steps.append(
            "Choose one of these classifier-approved patch operator families when possible: "
            + ", ".join(str(item) for item in preferred_ops)
            + "."
        )
    expected = "; ".join(str(item) for item in _first(failure_contract.get("expected_behavior"), 2))
    observed = "; ".join(str(item) for item in _first(failure_contract.get("observed_behavior"), 2))
    if expected or observed:
        steps.append(
            "Patch the code path that directly explains the failure contract"
            + (f": expected [{_clip(expected, 220)}]" if expected else "")
            + (f"; observed [{_clip(observed, 220)}]" if observed else "")
            + "."
        )
    if primary_atom:
        steps.append(
            "Use the primary edit location first: repair atom "
            f"{primary_atom.get('id')} ({primary_atom.get('kind')}) at lines {primary_atom.get('line_range')}; "
            f"treat `{primary_atom.get('operator_hint') or 'minimal_local_edit'}` as an edit-shape hint, not a code patch."
        )
        if primary_atom.get("kind") == "macro_or_enum_constant":
            steps.append(
                "If the primary atom is a macro/enum constant, preserve the existing constant unless a replacement "
                "appears explicitly in allowed_symbol_surface.macros_or_enum_constants or required_related_evidence; "
                "prefer editing the surrounding predicate/value-flow over inventing a sibling flag."
            )
    elif primary_site:
        steps.append(
            "Use the primary edit location first: repair site "
            f"{primary_site.get('id')} at lines {primary_site.get('line_range')}; "
            f"intent `{primary_site.get('edit_intent') or 'minimal_local_edit'}`."
        )
    contract_groups = ((related_code_context.get("contract_brief") or {}).get("high_priority_contract_groups") or [])[:2]
    for group in contract_groups:
        allowed = group.get("allowed_constants") or group.get("constants") or []
        if allowed:
            steps.append(
                "If changing macro/enum/flag values, choose only from the related contract group "
                f"{group.get('kind')}: {', '.join(str(item) for item in allowed[:10])}."
            )
            break
    return _dedup(steps)[:8] or ["Make the smallest local semantic edit supported by target localization and related contracts."]


def _repair_intent(
    *,
    route: str,
    failure_contract: Dict[str, Any],
    primary_atom: Dict[str, Any],
    primary_site: Dict[str, Any],
    plan_profile: Dict[str, Any],
) -> str:
    hypothesis = _root_cause_hypothesis(
        route=route,
        failure_contract=failure_contract,
        primary_atom=primary_atom,
        primary_site=primary_site,
    )
    shape = " ".join(str(item) for item in _first(plan_profile.get("patch_shape"), 2))
    if shape:
        return _clip(f"{hypothesis} Patch intent: {shape}", 520)
    return _clip(f"{hypothesis} Patch intent: minimal semantic repair constrained by the classifier route.", 520)


def _must_preserve(
    *,
    target_code_context: Dict[str, Any],
    related_code_context: Dict[str, Any],
    repair_objective: Dict[str, Any],
    plan_profile: Dict[str, Any],
) -> List[str]:
    envelope = target_code_context.get("target_envelope") or {}
    out = [
        "Preserve the target replacement unit signature, resolved function name, template/enclosing scope, and output contract.",
        "Keep edits inside the target replacement unit and preferably inside the primary/alternate edit location ranges.",
    ]
    for item in _first(envelope.get("output_contract"), 3):
        out.append(str(item))
    for contract in _first(target_code_context.get("local_behavioral_contracts"), 5):
        summary = contract.get("summary")
        if summary:
            out.append(str(summary))
    for invariant in _first(target_code_context.get("semantic_invariants"), 5):
        summary = invariant.get("summary")
        if summary:
            out.append(str(summary))
    for item in _first((related_code_context.get("visible_api_inventory") or {}).get("source_policy"), 2):
        out.append(str(item))
    for item in _first(((related_code_context.get("contract_brief") or {}).get("contract_policy") or []), 3):
        out.append(str(item))
    for item in _first(plan_profile.get("must_preserve"), 4):
        out.append(str(item))
    for item in _first(repair_objective.get("route_policy"), 3):
        out.append(str(item))
    for contract in _first(target_code_context.get("semantic_repair_contracts"), 6):
        if contract.get("summary"):
            out.append(str(contract.get("summary")))
    return _dedup(out)[:12]


def _forbidden_changes(
    *,
    route: str,
    primary_atom: Dict[str, Any],
    related_code_context: Dict[str, Any],
    repair_objective: Dict[str, Any],
    plan_profile: Dict[str, Any],
) -> List[str]:
    out = [
        "Do not change function signature, return type, storage qualifiers, template prefix, namespace/class wrapper, or visibility.",
        "Do not add includes, global helpers, main/test code, unrelated refactors, or formatting-only churn.",
        "Do not introduce functions, macros, enum constants, types, member fields, or constructor initializers outside the visible related inventories.",
        "Do not introduce any identifier absent from allowed_symbol_surface or required_related_evidence.",
        "Do not copy unrelated helper bodies or caller examples into the target replacement unit.",
    ]
    for item in _first(plan_profile.get("forbidden_changes"), 5):
        out.append(str(item))
    for contract in _first((related_code_context.get("scope_aware_symbol_contract") or {}).get("symbol_introduction_policy"), 4):
        out.append(str(contract))
    for contract in _first((related_code_context.get("scope_aware_symbol_contract") or {}).get("risky_unqualified_helpers"), 8):
        out.append(f"Do not introduce unqualified helper `{contract}` unless required_related_evidence proves exact callable scope.")
    if primary_atom:
        for item in _first(primary_atom.get("forbidden_operations"), 4):
            out.append(str(item))
    for item in _first(repair_objective.get("forbidden_patch_operators"), 4):
        out.append(f"Classifier forbids patch operator: {item}.")
    member_policy = (((related_code_context.get("type_contract_inventory") or {}).get("type_use_policy")) or [])
    for item in _first(member_policy, 2):
        out.append(str(item))
    return _dedup(out)[:12]


def _required_related_evidence(context: Dict[str, Any]) -> List[dict]:
    ranked = context.get("ranked_context") or {}
    out = []
    for item in _first(ranked.get("must_read"), 8):
        out.append(_compact_related_item(item))
    if not out:
        for item in _first(ranked.get("likely_relevant"), 5):
            out.append(_compact_related_item(item))
    return out[:8]


def _evidence_refs(
    *,
    primary_atom: Dict[str, Any],
    primary_site: Dict[str, Any],
    target_code_context: Dict[str, Any],
    related_evidence: List[dict],
) -> List[dict]:
    refs = []
    if primary_atom:
        refs.append({"type": "target_atom", "id": primary_atom.get("id"), "line_range": primary_atom.get("line_range")})
    if primary_site:
        refs.append({"type": "target_site", "id": primary_site.get("id"), "line_range": primary_site.get("line_range")})
    for failure_slice in _first(target_code_context.get("failure_slices"), 2):
        seed = failure_slice.get("seed_statement") or {}
        refs.append({"type": "failure_slice", "id": failure_slice.get("id"), "seed_line": seed.get("line"), "reason": _clip(failure_slice.get("localization_reason"), 220)})
    for item in related_evidence[:3]:
        refs.append({"type": "related_evidence", "summary": _clip(item.get("summary") or item.get("signature") or item.get("source"), 220)})
    return refs[:8]


def _root_cause_hypothesis(
    *,
    route: str,
    failure_contract: Dict[str, Any],
    primary_atom: Dict[str, Any],
    primary_site: Dict[str, Any],
) -> str:
    categories = ", ".join(str(item) for item in _first(failure_contract.get("categories"), 4)) or "unknown failure category"
    location = primary_atom.get("text") if primary_atom else (primary_site.get("primary_statement") or {}).get("text")
    route_text = route or "unknown route"
    if location:
        return _clip(f"{route_text} failure ({categories}) is most likely controlled by `{location}`.", 520)
    return _clip(f"{route_text} failure ({categories}) has no precise atom; use the highest ranked local slice/site.", 520)


def _decision_confidence(atom: Dict[str, Any], site: Dict[str, Any]) -> str:
    values = [str(atom.get("confidence") or ""), str(site.get("confidence") or "")]
    if "high" in values:
        return "high"
    if "medium" in values:
        return "medium"
    return "low"


def _compact_repair_objective(objective: Dict[str, Any], failure_contract: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "bug_kind": objective.get("bug_kind"),
        "route": objective.get("route") or failure_contract.get("route"),
        "validation_oracle": objective.get("validation_oracle") or failure_contract.get("oracle_kind"),
        "confidence": objective.get("confidence"),
        "repair_goal": _clip(objective.get("repair_goal") or failure_contract.get("repair_goal"), 320),
        "failure_categories": _first(objective.get("failure_categories") or failure_contract.get("categories"), 8),
        "fix_policy": [_clip(item, 180) for item in _first(objective.get("fix_policy"), 4)],
        "route_policy": [_clip(item, 180) for item in _first(objective.get("route_policy"), 4)],
        "preferred_patch_operators": _first(objective.get("preferred_patch_operators"), 6),
        "forbidden_patch_operators": _first(objective.get("forbidden_patch_operators"), 6),
    }


def _compact_semantic_contracts(contracts: List[dict]) -> List[dict]:
    out = []
    for contract in contracts[:8]:
        out.append(
            {
                "kind": contract.get("kind"),
                "strength": contract.get("strength"),
                "repair_focus": contract.get("repair_focus"),
                "summary": _clip(contract.get("summary"), 360),
                "preferred_edit_patterns": [
                    _clip(item, 240)
                    for item in _first(contract.get("preferred_edit_patterns"), 4)
                ],
                "forbidden_edit_patterns": [
                    _clip(item, 240)
                    for item in _first(contract.get("forbidden_edit_patterns"), 4)
                ],
                "evidence": [_compact_any(item, 260) for item in _first(contract.get("evidence"), 4)],
            }
        )
    return out


def _plan_safety_checks(
    *,
    semantic_contracts: List[dict],
    scope_contract: Dict[str, Any],
    primary_atom: Dict[str, Any],
) -> List[str]:
    checks = [
        "Before output, verify no new identifier is absent from allowed_symbol_surface or required_related_evidence.",
        "If adding/changing a call, verify the callable form and arity against scope-aware related contracts.",
        "If adding/changing a member call, verify the receiver/type owns that method or field.",
    ]
    for contract in semantic_contracts[:6]:
        for item in _first(contract.get("forbidden_edit_patterns"), 2):
            checks.append(str(item))
    risky = scope_contract.get("risky_unqualified_helpers") or []
    if risky:
        checks.append(
            "Do not introduce these visible-but-not-introducible helpers without exact callable evidence: "
            + ", ".join(str(item) for item in risky[:12])
            + "."
        )
    if primary_atom.get("kind") == "macro_or_enum_constant":
        checks.append("A macro/enum replacement must appear in allowed_symbol_surface.macros_or_enum_constants.")
    return _dedup(checks)[:10]


def _route_plan_profile(
    *,
    route: str,
    repair_objective: Dict[str, Any],
    failure_contract: Dict[str, Any],
) -> Dict[str, Any]:
    if route == "security_repair":
        return security_repair_planning_profile(repair_objective, failure_contract)
    if route == "correctness_repair":
        return correctness_repair_planning_profile(repair_objective, failure_contract)
    return {
        "route": route or "unknown",
        "planning_focus": "ambiguous_minimal_semantic_repair",
        "repair_goal": repair_objective.get("repair_goal") or failure_contract.get("repair_goal"),
        "patch_shape": [
            "Use the classifier route when available and make the smallest evidence-backed semantic edit.",
            "Preserve both observable behavior and safety constraints unless the failure oracle requires a local change.",
        ],
        "step_priorities": [
            "Identify whether the failing oracle is primarily safety, correctness, or build behavior.",
            "Patch only the ranked local code path that explains that oracle.",
            "Avoid broad refactors, signature changes, and invented APIs.",
        ],
        "must_preserve": [
            "Preserve the target function signature, replacement-unit boundaries, and visible API contracts.",
        ],
        "forbidden_changes": [
            "Do not perform broad rewrites or route-specific repairs unsupported by classifier/failure evidence.",
        ],
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


def _classifier_directive(objective: Dict[str, Any], failure_contract: Dict[str, Any]) -> Dict[str, Any]:
    route = str(objective.get("route") or failure_contract.get("route") or "unknown").strip()
    confidence = objective.get("confidence") or "unknown"
    authority = (
        "classifier_route_is_primary"
        if confidence in {"high", "medium"}
        else "ambiguous_route_use_failure_evidence_but_do_not_ignore_classifier"
    )
    return {
        "authority": authority,
        "route": route,
        "bug_kind": objective.get("bug_kind"),
        "confidence": confidence,
        "validation_oracle": objective.get("validation_oracle") or failure_contract.get("oracle_kind"),
        "oracle_subkind": objective.get("oracle_subkind"),
        "repair_goal": _clip(objective.get("repair_goal") or failure_contract.get("repair_goal"), 320),
        "failure_categories": _first(objective.get("failure_categories") or failure_contract.get("categories"), 8),
        "fix_policy": [_clip(item, 200) for item in _first(objective.get("fix_policy"), 4)],
        "route_policy": [_clip(item, 200) for item in _first(objective.get("route_policy"), 4)],
        "heuristic_boundary": (
            "Use TargetCodeContext/RelatedCodeContext to choose edit atoms, slices, and allowed symbols; "
            "do not let their heuristic repair hints override this route, goal, or fix policy."
        ),
    }


def _compact_statement(statement: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": statement.get("id"),
        "line": statement.get("line"),
        "end_line": statement.get("end_line"),
        "kind": statement.get("kind"),
        "text": _clip(statement.get("text"), MAX_TEXT),
        "signals": _first(statement.get("signals"), 8),
    }


def _compact_related_item(item: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "type": item.get("type"),
        "kind": item.get("kind"),
        "symbol": item.get("symbol"),
        "source": item.get("source"),
        "function": item.get("function"),
        "summary": _clip(item.get("summary"), MAX_TEXT),
        "signature": _clip(item.get("signature"), MAX_TEXT),
        "allowed_constants": _first(item.get("allowed_constants"), 12),
    }


def _first_dict(values: Any) -> Dict[str, Any]:
    if isinstance(values, list):
        for item in values:
            if isinstance(item, dict):
                return item
    return {}


def _first(values: Any, limit: int) -> List[Any]:
    if not values:
        return []
    if isinstance(values, list):
        return values[:limit]
    if isinstance(values, tuple):
        return list(values[:limit])
    return [values]


def _dedup(values: List[str]) -> List[str]:
    out = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        seen.add(text)
        out.append(text)
    return out


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


def _clip(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"
