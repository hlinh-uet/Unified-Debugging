"""Causal reasoning with at most one hypothesis-driven CPG expansion."""

from __future__ import annotations

import json
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm

from .semantic_queries import (
    BEHAVIOR_RELATIONS,
    normalize_information_needs,
)
from .models import clip, parse_json_object_with_recovery, unique_dicts


CAUSAL_SYSTEM_PROMPT = (
    "You are a C/C++ causal correctness-repair reasoner. Explain the failing behavior using only "
    "the exact target and cited source-backed evidence. CPG evidence may be unavailable; exact "
    "Tree-sitter target evidence is valid. Return one strict JSON object, without markdown."
)


def diagnose(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    state: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], str]:
    prompt = _diagnosis_prompt(state)
    response = call_llm(prompt, provider=llm_provider, system_prompt=CAUSAL_SYSTEM_PROMPT)
    parsed, parse_error = parse_json_object_with_recovery(response)
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name=f"correctness_causal_diagnosis_round_{int(state.get('planning_round') or 1):02d}",
        prompt=prompt,
        response=response or "",
        status="generated" if response and not parse_error else "failed",
        error=parse_error or ("" if response else "causal_diagnosis_no_response"),
    )
    if parse_error or not response:
        return [], [], artifact, parse_error or "causal_diagnosis_no_response"
    hypotheses, error = _normalize_hypotheses(
        parsed.get("hypotheses"),
        evidence=_planning_evidence_catalog(state),
    )
    if error:
        return [], [], artifact, error
    raw_needs = parsed.get("information_needs") or []
    if not isinstance(raw_needs, list):
        return hypotheses, [], artifact, (
            "optional_follow_up_rejected:information_needs_not_array"
        )
    if raw_needs:
        needs, needs_error = normalize_information_needs(
            raw_needs,
            target_inventory=state.get("target_inventory") or {},
            max_needs=6,
            allowed_hypothesis_ids=[item["id"] for item in hypotheses],
        )
        if not needs:
            return hypotheses, [], artifact, (
                f"optional_follow_up_rejected:{needs_error or 'diagnosis_information_needs_invalid'}"
            )
    else:
        needs, needs_error = [], ""
    return hypotheses, needs, artifact, needs_error


def adjudicate_and_plan(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    state: Dict[str, Any],
    max_plans: int,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], str]:
    prompt = _adjudication_prompt(state, max_plans=max_plans)
    response = call_llm(prompt, provider=llm_provider, system_prompt=CAUSAL_SYSTEM_PROMPT)
    parsed, parse_error = parse_json_object_with_recovery(response)
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name=f"correctness_hypothesis_adjudication_round_{int(state.get('planning_round') or 1):02d}",
        prompt=prompt,
        response=response or "",
        status="generated" if response and not parse_error else "failed",
        error=parse_error or ("" if response else "hypothesis_adjudication_no_response"),
    )
    if parse_error or not response:
        error = parse_error or "hypothesis_adjudication_no_response"
        return [], [_validation_fallback_plan(state, response, error)], artifact, error
    hypotheses, error = _normalize_hypotheses(
        parsed.get("hypotheses"),
        evidence=_planning_evidence_catalog(state),
    )
    if error:
        return [], [_validation_fallback_plan(state, response, error)], artifact, error
    plans, error = _materialize_plans(
        parsed.get("plans"),
        hypotheses=hypotheses,
        evidence=_planning_evidence_catalog(state),
        max_plans=max_plans,
    )
    if error or not plans:
        fallback_error = error or "no_plans_generated"
        return hypotheses, [_validation_fallback_plan(state, response, fallback_error)], artifact, fallback_error
    return hypotheses, plans, artifact, error


def _validation_fallback_plan(
    state: Dict[str, Any], response: Optional[str], reason: str
) -> Dict[str, Any]:
    """Keep patch synthesis reachable when the planning contract is malformed."""
    hypotheses = [
        item for item in state.get("hypothesis_ledger") or [] if isinstance(item, dict)
    ]
    selected = hypotheses[0] if hypotheses else {}
    evidence = _planning_evidence_catalog(state)[:16]
    target = state.get("target_contract") or {}
    output_contract = state.get("output_contract") or {}
    raw_guidance = clip(response, 4000) if response else ""
    return {
        "id": "plan_validation_fallback",
        "hypothesis_id": selected.get("id"),
        "source_hypothesis_id": selected.get("id"),
        "hypothesis": selected.get("mechanism") or (
            "The structured planning contract was unavailable; derive the smallest target-local "
            "repair from the failure contract and source-backed evidence."
        ),
        "target_unit_id": target.get("target_id"),
        "edit_intent": (
            "Synthesize the smallest target-local candidate supported by the failure context and "
            "available causal evidence, then let compile and tests decide validity."
        ),
        "structured_edits": [{
            "operation": "derive_minimal_target_local_repair",
            "source_anchor": target.get("resolved_name") or target.get("requested_name"),
            "replacement_intent": raw_guidance or (
                "Use the causal hypothesis, failure contract, and cited evidence as direct repair guidance."
            ),
        }],
        "required_evidence_ids": [item.get("id") for item in evidence if item.get("id")],
        "grounded_evidence_cards": evidence,
        "must_preserve": list(output_contract.get("must_preserve") or [])[:12],
        "why_this_may_fix": (
            "Planning-format failures are not correctness evidence; the generated candidate will be "
            "accepted only by the normal compile and test validation path."
        ),
        "risk": "validation_required",
        "confidence": "low",
        "fallback_reason": reason,
    }


def _planning_evidence_catalog(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Accept every mechanically source-backed ID exposed in the capsule."""
    facts = [
        {
            **dict(item),
            "evidence_domain": item.get("evidence_domain") or "static_program_semantics",
            "epistemic_status": item.get("epistemic_status") or "static_source_fact",
            "runtime_observed": bool(item.get("runtime_observed")),
        }
        for item in state.get("evidence_facts") or []
        if isinstance(item, dict)
    ]
    by_id = {str(item.get("id")): item for item in facts if item.get("id")}
    context = (state.get("behavior_state") or {}).get("context") or {}
    aliases: List[Dict[str, Any]] = []

    def alias(alias_id: Any, evidence_id: Any) -> None:
        alias_id = str(alias_id or "")
        canonical = by_id.get(str(evidence_id or ""))
        if not alias_id or not canonical:
            return
        aliases.append({**canonical, "id": alias_id, "canonical_evidence_id": canonical.get("id")})

    for call in context.get("calls") or []:
        if isinstance(call, dict):
            alias(call.get("id"), call.get("evidence_id"))
    for contract in context.get("callee_contracts") or []:
        if isinstance(contract, dict):
            alias(contract.get("id"), contract.get("evidence_id"))

    target = state.get("target_contract") or {}
    for entity in (state.get("target_inventory") or {}).get("entities") or []:
        if not isinstance(entity, dict) or not entity.get("id"):
            continue
        aliases.append({
            "id": entity.get("id"),
            "kind": f"target_ast_{entity.get('kind') or 'entity'}",
            "symbol": next(iter(entity.get("symbols") or []), ""),
            "symbols": entity.get("symbols") or [],
            "source_file": target.get("source_file"),
            "source_path": target.get("source_path"),
            "source_range": entity.get("source_range") or {},
            "source_excerpt": entity.get("source_excerpt"),
            "semantic_summary": "source-backed target AST entity",
            "semantic_details": {"node_type": entity.get("node_type")},
            "evidence_domain": "static_program_semantics",
            "epistemic_status": "static_source_fact",
            "runtime_observed": False,
        })
    return unique_dicts([*facts, *aliases])


def _diagnosis_prompt(state: Dict[str, Any]) -> str:
    payload = _prompt_state(state)
    relations = ", ".join(sorted(BEHAVIOR_RELATIONS))
    return """CAUSAL DIAGNOSIS

The fault-localized target is exact. The initial Behavior Context is deliberately narrow: exact target
source plus only variable definitions, effects, target calls, and exact callee contracts retained by
the target's backward REACHING_DEF slice. Callee contracts contain relevant parameters, guarded
returns, external writes, and reaching definitions rather than full method bodies. When Joern is unavailable or empty, use the exact
Tree-sitter target entities as source-backed evidence. Compiler-generated variables and eager overload, sibling,
caller, unrelated callee/local, type, and deep-dataflow expansions are excluded. Cite the evidence/entity IDs attached to calls,
variables, contracts, and any follow-up expansions. Trace possible source-level effects through definitions, writes,
result use, overwrite/order, control, alias, and callee effects visible in TARGET. Return two to four distinct causal
hypotheses whenever the evidence exposes more than one effect path. Include a lower-confidence
counter-hypothesis on a different effect path instead of collapsing immediately to one edit; never
create syntactic variants of one mechanism or fabricate supporting evidence.

Treat FAILURE CONTRACT as the oracle, using this evidence order:
1. proof_obligation and a high-confidence failing_assertion selected from the runner-reported source line;
2. failure_observation, which is observed runner output and is not automatically an expected/actual source operand;
3. test_dependency_slice, which explains local test setup and data dependencies but is not runtime proof;
4. test_source_excerpt only as a fallback.
For a medium-confidence only-assertion selection, state that uncertainty. If proof_obligation is
resolve_assertion_oracle, do not choose one candidate assertion or invent expected behavior. For a signal
without a source location, do not infer a crash site from source order; only the signal itself is observed.
Every predicted_failure_path must connect target behavior to the explicit proof_obligation.

All Joern, CPG, Tree-sitter, reaching-definition, control-flow, call-graph, and callee-contract
retrieval is STATIC PROGRAM SEMANTICS. It can establish that a definition, branch, return, write,
or data-flow path exists and may execute under a condition. It does not establish that the branch
was taken, that a callee returned a particular value, or that a variable held a concrete value in
the failing execution. Only failure_observation and actual validation/test outcomes are runtime
observations. Use conditional language for static paths. A runtime-specific claim supported only by
static evidence must remain a low/medium-confidence hypothesis with the runtime fact listed in
missing_facts.

A hypothesis with unresolved critical facts must not claim high confidence. TESTED REPAIRS are negative
or positive causal evidence: when a faithfully attempted mechanism leaves the same failure and observable
output unchanged, explore a different causal path unless new evidence contradicts that result.
Do not propose a patch yet. information_needs are handled only by static CPG/source retrieval.
Do not request exact values, executed branches, or observed return values for the failing run through
information_needs; keep those as missing_facts requiring runtime instrumentation. An unresolved callee is not a contract: if a
critical proof obligation needs its overload, sibling usage, caller, type/constant definition, or deep
dataflow, request that additional semantic query bound to the closest visible source entity.
A declaration containing a call or a target-wide anchor is acceptable when no more specific visible
entity is available; the deterministic query normalizer will rebind it only when there is one unique
source-backed match. Never fabricate an entity ID. Otherwise return an empty information_needs array.

Allowed relation names:
""" + relations + """

Every additional need must reference a hypothesis and a source-bound subject entity.
Return exactly:
{
  "hypotheses": [{
    "id": "h1", "mechanism": "...", "predicted_failure_path": "...",
    "supporting_evidence_ids": ["..."], "contradicting_evidence_ids": [],
    "missing_facts": ["..."], "confidence": "low|medium|high",
    "epistemic_status": "static_path_hypothesis|runtime_observed|mixed|uncertain"
  }],
  "information_needs": [{
    "id": "need_h1_2", "hypothesis_id": "h1", "subject_entity_id": "entity:...",
    "relation": "CALLER_RESULT_USE", "question": "one exact semantic question",
    "symbols": ["subject_bound_symbol"], "required_for": "proof obligation",
    "priority": "critical"
  }]
}

REPAIR STATE
""" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def _adjudication_prompt(state: Dict[str, Any], *, max_plans: int) -> str:
    payload = _prompt_state(state)
    target_id = str((state.get("target_contract") or {}).get("target_id") or "")
    return f"""HYPOTHESIS ADJUDICATION AND PATCH PORTFOLIO

Adjudicate the existing hypotheses using the cited source-backed evidence and tested-repair outcomes.
Produce at most {max_plans} minimal plans, one per distinct viable causal mechanism; do not spend portfolio
slots on syntactic variants of the same mechanism. Rank untested mechanisms before a mechanism whose
faithful prior patch left the same failure unchanged, unless new cited evidence reverses that conclusion.
Do not invent APIs, types, macros, fields, or constants absent from the target/evidence.
Each supported plan must say how its target-local edit satisfies the FAILURE CONTRACT proof_obligation.
Do not convert an uncertain assertion candidate or crash candidate site into an observed fact.
Static source evidence may justify a possible mechanism or preservation condition, but it cannot prove
that a value, return, or branch occurred in the failing execution. Plans relying on such an unobserved
runtime link must retain that uncertainty in risk/confidence.

All plans must use target_unit_id exactly "{target_id}". A structured edit describes intent and an exact
source anchor copied from TARGET; it is advisory to PatchSynthesizer, not a hard-coded patch template.
Return exactly:
{{
  "hypotheses": [{{
    "id": "h1", "mechanism": "...", "predicted_failure_path": "...",
    "supporting_evidence_ids": ["..."], "contradicting_evidence_ids": [],
    "missing_facts": [], "confidence": "low|medium|high", "status": "supported|rejected|uncertain",
    "epistemic_status": "static_path_hypothesis|runtime_observed|mixed|uncertain"
  }}],
  "plans": [{{
    "id": "plan_1", "hypothesis_id": "h1", "target_unit_id": "{target_id}",
    "edit_intent": "...", "structured_edits": [{{
      "operation": "semantic edit description", "source_anchor": "exact target text", "replacement_intent": "..."
    }}],
    "required_evidence_ids": ["..."], "must_preserve": ["..."],
    "why_this_may_fix": "behavior -> mechanism -> edit", "risk": "low|medium|high",
    "confidence": "low|medium|high"
  }}]
}}

REPAIR STATE
""" + json.dumps(payload, ensure_ascii=False, separators=(",", ":"), default=str)


def _prompt_state(state: Dict[str, Any]) -> Dict[str, Any]:
    target = state.get("target_contract") or {}
    behavior_context = (state.get("behavior_state") or {}).get("context") or {}
    return {
        "state_id": state.get("state_id"),
        "target": {
            "target_id": target.get("target_id"),
            "resolved_name": target.get("resolved_name"),
            "signature": target.get("signature"),
            "source_path": target.get("source_path"),
            "source_range": target.get("source_range"),
            "source_hash": target.get("source_hash"),
            "visible_symbols": (target.get("visible_symbols") or [])[:96],
        },
        "failure_contract": state.get("failure_contract") or {},
        "target_inventory": _prompt_inventory(
            state.get("target_inventory") or {}, behavior_context=behavior_context
        ),
        "behavior_context": _compact_behavior_context(behavior_context),
        "follow_up_query_state": {
            "information_needs": (state.get("behavior_state") or {}).get("information_needs") or [],
        },
        "tested_repairs": _compact_tested_repairs(state),
        "prior_hypotheses": list(
            _compact_prior_hypotheses(
                (state.get("prior_repair_state") or {}).get("hypothesis_ledger") or []
            )
        ),
        "prior_plans": _compact_prior_plans(
            (state.get("prior_repair_state") or {}).get("plans") or []
        ),
        "hypotheses": state.get("hypothesis_ledger") or [],
        "warnings": (state.get("warnings") or [])[-12:],
        "errors": (state.get("errors") or [])[-12:],
    }


def _compact_tested_repairs(state: Dict[str, Any]) -> List[Dict[str, Any]]:
    records = [
        *list((state.get("prior_repair_state") or {}).get("validation_history") or []),
        *list(state.get("validation_history") or []),
    ]
    out = []
    seen = set()
    for raw in records[-12:]:
        if not isinstance(raw, dict):
            continue
        outcome = raw.get("outcome") if isinstance(raw.get("outcome"), dict) else raw
        item = {
            "kind": raw.get("kind") or "validation_outcome",
            "evidence_domain": "runtime_validation_observation",
            "runtime_observed": True,
            "round": raw.get("round"),
            "hypothesis_id": raw.get("hypothesis_id"),
            "hypothesis": clip(raw.get("hypothesis"), 900),
            "plan_id": raw.get("plan_id"),
            "edit_intent": clip(raw.get("edit_intent"), 900),
            "patch_diff": clip(raw.get("patch_diff"), 3000),
            "category": outcome.get("category"),
            "transition": outcome.get("transition"),
            "initial_failed_tests": (outcome.get("initial_failed_tests") or [])[:32],
            "post_failed_tests": (outcome.get("post_failed_tests") or [])[:32],
            "fixed_tests": (outcome.get("fixed_tests") or [])[:32],
            "regressed_tests": (outcome.get("regressed_tests") or [])[:32],
            "validation_error": clip(outcome.get("validation_error"), 800),
        }
        marker = json.dumps(item, sort_keys=True, ensure_ascii=True, default=str)
        if marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out[-4:]


def _compact_prior_hypotheses(values: Any) -> List[Dict[str, Any]]:
    return [
        {
            "id": item.get("id"),
            "mechanism": clip(item.get("mechanism"), 900),
            "predicted_failure_path": clip(item.get("predicted_failure_path"), 900),
            "supporting_evidence_ids": (item.get("supporting_evidence_ids") or [])[:16],
            "confidence": item.get("confidence"),
            "status": item.get("status"),
            "epistemic_status": item.get("epistemic_status"),
        }
        for item in values[:4]
        if isinstance(item, dict)
    ]


def _compact_prior_plans(values: Any) -> List[Dict[str, Any]]:
    return [
        {
            "id": item.get("id"),
            "source_hypothesis_id": item.get("source_hypothesis_id"),
            "hypothesis": clip(item.get("hypothesis"), 900),
            "edit_intent": clip(item.get("edit_intent"), 900),
            "required_evidence_ids": (item.get("required_evidence_ids") or [])[:16],
        }
        for item in values[:3]
        if isinstance(item, dict)
    ]


def _prompt_inventory(
    inventory: Dict[str, Any], *, behavior_context: Dict[str, Any]
) -> Dict[str, Any]:
    """Keep query anchors but omit target snippets already present in BehaviorContext."""
    del behavior_context
    # Call and variable subjects are embedded directly in their compact contracts.
    # The root remains the generic anchor for target-wide control/return questions.
    allowed_kinds = {"target_function"}
    entities = []
    for item in inventory.get("entities") or []:
        if not isinstance(item, dict) or item.get("kind") not in allowed_kinds:
            continue
        item_range = item.get("source_range") or {}
        entities.append({
            "id": item.get("id"),
            "kind": item.get("kind"),
            "node_type": item.get("node_type"),
            "source_lines": {
                "start": item_range.get("start_line"),
                "end": item_range.get("end_line"),
            },
            "symbols": (item.get("symbols") or [])[:8],
        })
    return {
        "inventory_id": inventory.get("inventory_id"),
        "target_id": inventory.get("target_id"),
        "source_hash": inventory.get("source_hash"),
        "entities": entities,
    }


def _compact_behavior_context(context: Dict[str, Any]) -> Dict[str, Any]:
    """Remove audit indexes and repeated control text from the LLM-facing capsule."""
    variables = []
    for item in list(context.get("variables") or [])[:12]:
        if not isinstance(item, dict):
            continue
        variables.append({
            "symbol": item.get("symbol"),
            "subject_entity_id": item.get("subject_entity_id"),
            "type": item.get("type"),
            "origin": item.get("origin"),
            "declarations": [
                {
                    "entity_id": declaration.get("entity_id"),
                    "kind": declaration.get("kind"),
                    "source": clip(declaration.get("source"), 500),
                    "source_lines": {
                        "start": (declaration.get("source_range") or {}).get("start_line"),
                        "end": (declaration.get("source_range") or {}).get("end_line"),
                    },
                }
                for declaration in item.get("declarations") or []
                if isinstance(declaration, dict)
            ],
            "declaration_evidence_ids": item.get("declaration_evidence_ids") or [],
            "writes": [
                {
                    "evidence_id": value.get("evidence_id"),
                    "expression": clip(value.get("expression"), 500),
                    "epistemic_status": value.get("epistemic_status") or "static_assignment_site",
                    "runtime_observed": bool(value.get("runtime_observed")),
                }
                for value in list(item.get("writes") or [])[:4]
                if isinstance(value, dict)
            ],
            "call_uses": [
                {
                    "evidence_id": value.get("evidence_id"),
                    "call": clip(value.get("call"), 500),
                }
                for value in list(item.get("call_uses") or [])[:4]
                if isinstance(value, dict)
            ],
            "related_source_symbols": list(item.get("related_source_symbols") or [])[:8],
            "status": item.get("status"),
        })
    calls = []
    for item in list(context.get("calls") or [])[:8]:
        if not isinstance(item, dict):
            continue
        calls.append({
            "id": item.get("id"),
            "subject_entity_id": item.get("subject_entity_id"),
            "evidence_id": item.get("evidence_id"),
            "symbol": item.get("symbol"),
            "resolved_full_name": item.get("resolved_full_name"),
            "signature": item.get("signature"),
            "result_type": item.get("result_type"),
            "semantic_symbol_id": item.get("semantic_symbol_id"),
            "definition": item.get("definition") or {},
            "arguments": item.get("arguments") or [],
            "argument_mapping": (item.get("argument_mapping") or [])[:16],
            "dataflow": _compact_dependencies(item.get("dataflow")),
            "callee_contract_ids": item.get("callee_contract_ids") or [],
            "status": item.get("status"),
            "execution_status": item.get("execution_status") or "not_runtime_observed",
        })
    contracts = []
    for item in list(context.get("callee_contracts") or [])[:5]:
        if not isinstance(item, dict):
            continue
        contracts.append({
            "id": item.get("id"),
            "evidence_id": item.get("evidence_id"),
            "symbol": item.get("symbol"),
            "full_name": item.get("full_name"),
            "signature": item.get("signature"),
            "definition_ref": item.get("definition_ref"),
            "parameters": item.get("parameters") or [],
            "returns": item.get("returns") or [],
            "assignments": [
                {
                    "line": value.get("line"),
                    "symbol": value.get("symbol"),
                    "expression": clip(value.get("assignment"), 500),
                }
                for value in item.get("assignments") or []
                if isinstance(value, dict)
            ],
            "side_effect_analysis": item.get("side_effect_analysis"),
            "epistemic_status": item.get("epistemic_status") or "static_function_contract",
            "runtime_observed": bool(item.get("runtime_observed")),
        })
    retained_region_ids = set()
    for expansion in context.get("expansions") or []:
        for evidence in (expansion.get("evidence") or []) if isinstance(expansion, dict) else []:
            ref = evidence.get("source_ref") or {}
            if ref.get("scope") == "related" and ref.get("region_id"):
                retained_region_ids.add(str(ref["region_id"]))
    return {
        "version": context.get("version"),
        "evidence_semantics": context.get("evidence_semantics") or {
            "domain": "static_program_semantics",
            "runtime_observed": False,
            "does_not_support": [
                "executed branch",
                "concrete failing-run value",
                "observed callee return",
            ],
        },
        "target": context.get("target") or {},
        "program_slice": {
            key: (context.get("program_slice") or {}).get(key)
            for key in (
                "provider", "criterion", "direction", "retained_node_count",
                "retrieval_scope", "indexed_node_count", "view_node_count",
                "excluded_from_view_count", "view_limit", "view_kind_counts",
                "source_lines", "symbols", "call_symbols",
            )
            if (context.get("program_slice") or {}).get(key) not in (None, [], {})
        },
        "source_regions": [
            {**item, "source": clip(item.get("source"), 1600)}
            for item in context.get("source_regions") or []
            if isinstance(item, dict) and str(item.get("id") or "") in retained_region_ids
        ],
        "variables": variables,
        "calls": calls,
        "effects": [
            {
                "evidence_id": item.get("evidence_id"),
                "subject_entity_id": item.get("subject_entity_id"),
                "kind": item.get("kind"),
                "symbol": item.get("symbol"),
                "expression": clip(item.get("expression"), 500),
                "dataflow": _compact_dependencies(item.get("dataflow")),
                "epistemic_status": item.get("epistemic_status") or "static_possible_effect",
                "runtime_observed": bool(item.get("runtime_observed")),
            }
            for item in list(context.get("effects") or [])[:16]
            if isinstance(item, dict)
            and item.get("kind") in {
                "target_assignment", "target_update", "target_return", "target_control"
            }
        ],
        "callee_contracts": contracts,
        "expansions": context.get("expansions") or [],
        "unresolved_relations": context.get("unresolved_relations") or [],
    }


def _compact_dependencies(values: Any) -> List[Dict[str, Any]]:
    out = []
    for item in values or []:
        if not isinstance(item, dict):
            continue
        out.append({
            "kind": item.get("kind"),
            "symbol": item.get("symbol"),
            "line": item.get("line"),
            "code": clip(
                item.get("code"),
                280 if item.get("kind") == "semantic_dataflow_path" else 420,
            ),
        })
        if len(out) >= 4:
            break
    return out


def _normalize_hypotheses(
    value: Any, *, evidence: Optional[List[Dict[str, Any]]] = None
) -> Tuple[List[Dict[str, Any]], str]:
    if not isinstance(value, list) or not value:
        return [], "hypotheses_missing"
    evidence_by_id = {
        str(item.get("id")): item
        for item in evidence or []
        if isinstance(item, dict) and item.get("id")
    }
    out = []
    for raw in value[:4]:
        if not isinstance(raw, dict):
            return [], "hypothesis_not_object"
        hypothesis_id = str(raw.get("id") or "")
        mechanism = str(raw.get("mechanism") or "").strip()
        if not hypothesis_id or not mechanism:
            return [], "hypothesis_contract_incomplete"
        supporting_ids = _strings(raw.get("supporting_evidence_ids"), 16)
        supporting_domains = list(dict.fromkeys(
            str((evidence_by_id.get(evidence_id) or {}).get("evidence_domain") or "")
            for evidence_id in supporting_ids
            if evidence_id in evidence_by_id
        ))
        runtime_support = any(
            bool((evidence_by_id.get(evidence_id) or {}).get("runtime_observed"))
            for evidence_id in supporting_ids
        )
        static_support_only = bool(supporting_ids) and not runtime_support
        confidence = str(raw.get("confidence") or "low").lower()
        if confidence not in {"low", "medium", "high"}:
            confidence = "low"
        epistemic_status = str(raw.get("epistemic_status") or "uncertain")
        confidence_adjustment = ""
        if static_support_only:
            epistemic_status = "static_path_hypothesis"
            if confidence == "high":
                confidence = "medium"
                confidence_adjustment = "high_downgraded_static_support_only"
        elif not runtime_support:
            if epistemic_status in {"runtime_observed", "mixed"}:
                epistemic_status = "uncertain"
            if confidence == "high":
                confidence = "medium"
                confidence_adjustment = "high_downgraded_no_runtime_evidence"
        out.append({
            "id": hypothesis_id,
            "mechanism": clip(mechanism, 900),
            "predicted_failure_path": clip(raw.get("predicted_failure_path"), 900),
            "supporting_evidence_ids": supporting_ids,
            "contradicting_evidence_ids": _strings(raw.get("contradicting_evidence_ids"), 16),
            "missing_facts": _strings(raw.get("missing_facts"), 8),
            "confidence": confidence,
            "status": str(raw.get("status") or "candidate"),
            "epistemic_status": epistemic_status,
            "supporting_evidence_domains": supporting_domains,
            "runtime_support_present": runtime_support,
            "confidence_adjustment": confidence_adjustment,
        })
    return unique_dicts(out), ""


def _materialize_plans(
    value: Any,
    *,
    hypotheses: List[Dict[str, Any]],
    evidence: List[Dict[str, Any]],
    max_plans: int,
) -> Tuple[List[Dict[str, Any]], str]:
    """Attach available evidence without validating or rejecting plan semantics."""
    if not isinstance(value, list):
        return [], "plans_not_array"
    evidence_by_id = {str(item.get("id")): item for item in evidence if item.get("id")}
    plans = []
    for raw in value[:max_plans]:
        if not isinstance(raw, dict):
            continue
        hypothesis_id = str(raw.get("hypothesis_id") or raw.get("source_hypothesis_id") or "")
        evidence_ids = _strings(raw.get("required_evidence_ids"), 16)
        plan = dict(raw)
        plan["source_hypothesis_id"] = hypothesis_id
        plan["hypothesis"] = next(
            (item.get("mechanism") for item in hypotheses if item.get("id") == hypothesis_id),
            raw.get("hypothesis") or "",
        )
        plan["grounded_evidence_cards"] = [
            evidence_by_id[item] for item in evidence_ids if item in evidence_by_id
        ]
        plans.append(plan)
    if not plans:
        return [], "no_plans_generated"
    return plans, ""


def _strings(value: Any, limit: int) -> List[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, list):
        return []
    return list(dict.fromkeys(str(item) for item in value if str(item).strip()))[:limit]
