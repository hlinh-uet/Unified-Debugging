"""Target-anchored behavior inquiry and causal semantic-search controller."""

from __future__ import annotations

from typing import Any, Dict, Optional, Tuple

from core.apr.artifacts import write_related_code_context_artifact, write_repair_suggestions_artifact

from .behavior_analysis import analyze_target_behavior, merge_expansion_context
from .causal_reasoner import adjudicate_and_plan, diagnose
from .evidence_broker import execute_behavior_queries, merge_information_needs
from core.failure_context import build_failure_contract
from .models import ARCHITECTURE, STATE_VERSION, new_repair_state, unique_dicts
from .source_model import build_target_contract
from .target_inventory import build_target_inventory


def run_correctness_repair_planning(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    func_code: str,
    source_root: str,
    source_path: str,
    failed_tests_context: Dict[str, Any],
    replacement_target: Optional[Dict[str, Any]] = None,
    repair_objective: Optional[Dict[str, Any]] = None,
    output_contract: Optional[Dict[str, Any]] = None,
    max_plans: int = 3,
    prior_repair_state: Optional[Dict[str, Any]] = None,
    planning_round: int = 1,
    compilation_context: Optional[Dict[str, Any]] = None,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    del cand_label
    target, target_errors = build_target_contract(
        func_code=func_code,
        replacement_target=replacement_target or {},
        source_path=source_path,
        func_name=func_name,
    )
    failure = build_failure_contract(failed_tests_context or {})
    if target_errors:
        return _failed_result(
            bug_id=bug_id,
            attempt_index=attempt_index,
            qualified_name=qualified_name,
            candidate_relpath=candidate_relpath,
            error=";".join(target_errors),
            target=target,
            failure=failure,
            inventory={},
            stage="target_anchor",
        )
    inventory, inventory_errors = build_target_inventory(target)
    if inventory_errors:
        return _failed_result(
            bug_id=bug_id,
            attempt_index=attempt_index,
            qualified_name=qualified_name,
            candidate_relpath=candidate_relpath,
            error=";".join(inventory_errors),
            target=target,
            failure=failure,
            inventory=inventory,
            stage="target_inventory",
        )

    state = new_repair_state(
        target_contract=target,
        failure_contract=failure,
        target_inventory=inventory,
    )
    state["planning_round"] = max(1, int(planning_round or 1))
    state["compilation_context"] = (
        compilation_context
        or (prior_repair_state or {}).get("compilation_context")
        or {}
    )
    state["repair_objective"] = repair_objective or {}
    state["output_contract"] = output_contract or {}
    state["warnings"].extend(target.get("diagnostics") or [])
    state["warnings"].extend(inventory.get("diagnostics") or [])
    state["warnings"].extend(state["compilation_context"].get("diagnostics") or [])
    compatible_prior = _compatible_prior_state(prior_repair_state or {}, target)
    if compatible_prior:
        state["prior_repair_state"] = _compact_prior_state(compatible_prior)
        state["evidence_facts"] = unique_dicts(
            list(compatible_prior.get("evidence_facts") or [])[:32]
        )
        state["validation_history"] = list(
            compatible_prior.get("validation_history") or []
        )[-6:]
    validation_feedback = failure.get("validation_feedback") or {}
    if validation_feedback:
        state["validation_history"].append(validation_feedback)

    behavior_analysis, facts, query_round, query_errors = analyze_target_behavior(
        target_contract=target,
        target_inventory=inventory,
        source_root=source_root,
        compilation_context=state["compilation_context"],
    )
    state["behavior_state"]["context"] = behavior_analysis
    state["behavior_state"]["query_rounds"].append(query_round)
    state["evidence_facts"] = unique_dicts([*state["evidence_facts"], *facts])
    state["warnings"].extend(query_errors)
    semantic_artifact = _write_semantic_workspace_artifact(
        state=state,
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
    )
    hypotheses, clarification_needs, diagnosis_artifact, diagnosis_error = diagnose(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        state=state,
    )
    state["hypothesis_ledger"] = hypotheses
    if diagnosis_error:
        if diagnosis_error.startswith("optional_follow_up_rejected:"):
            state["behavior_state"]["diagnostics"].append(diagnosis_error)
        else:
            state["warnings"].append(diagnosis_error)

    if clarification_needs:
        clarified_needs, clarification_facts, second_round, second_errors = execute_behavior_queries(
            information_needs=clarification_needs,
            target_contract=target,
            target_inventory=inventory,
            source_root=source_root,
            round_index=2,
            semantic_context=(state["behavior_state"].get("context") or {}).get("semantic_context") or {},
            compilation_context=state.get("compilation_context") or {},
        )
        state["behavior_state"]["information_needs"] = merge_information_needs(
            state["behavior_state"]["information_needs"], clarified_needs
        )
        state["behavior_state"]["context"] = merge_expansion_context(
            state["behavior_state"].get("context") or {},
            facts=clarification_facts,
            information_needs=clarified_needs,
        )
        state["behavior_state"]["query_rounds"].append(second_round)
        state["evidence_facts"] = unique_dicts([*state["evidence_facts"], *clarification_facts])
        state["warnings"].extend(second_errors)
        semantic_artifact = _write_semantic_workspace_artifact(
            state=state,
            bug_id=bug_id,
            attempt_index=attempt_index,
            qualified_name=qualified_name,
            candidate_relpath=candidate_relpath,
        )

    final_hypotheses, plans, adjudication_artifact, plan_error = adjudicate_and_plan(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        state=state,
        max_plans=max_plans,
    )
    state["hypothesis_ledger"] = final_hypotheses or hypotheses
    state["plans"] = plans
    if plan_error:
        state["warnings"].append(plan_error)
    state["status"] = "patch_portfolio_ready" if plans else "no_patch_portfolio"
    return _write_result(
        state=state,
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        related_artifact=semantic_artifact,
        llm_artifacts=[diagnosis_artifact, adjudication_artifact],
    )


def _write_semantic_workspace_artifact(
    *,
    state: Dict[str, Any],
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
) -> Dict[str, Any]:
    workspace = {
        "architecture": ARCHITECTURE,
        "target_inventory": state.get("target_inventory") or {},
        "compilation_context": state.get("compilation_context") or {},
        "behavior_state": state.get("behavior_state") or {},
        "evidence_store": {
            "fact_count": len(state.get("evidence_facts") or []),
            "evidence_ids": [item.get("id") for item in state.get("evidence_facts") or []],
        },
        "query_policy": {
            "initial_search_domain": "exact_target_syntax_ir_and_compiler_semantic_deltas",
            "follow_up_search_domain": "budgeted_compiler_declarations_then_joern_on_demand",
            "evidence_domain": "static_program_semantics",
            "runtime_observed": False,
            "runtime_evidence_policy": (
                "Tree-sitter and optional Joern queries never answer failing-run value, branch, or return questions"
            ),
            "execution": "tree_sitter_query_then_clang_frontend_then_hypothesis_driven_expansion",
            "initial_projection": [
                "budgeted_balanced_view_over_full_target_syntax_index",
                "compiler_resolved_variable_types",
                "compiler_resolved_direct_call_identities",
            ],
            "syntax_index_policy": (
                "retain_all_target_records_for_retrieval_and expose only the budgeted view to the LLM"
            ),
            "lazy_only": [
                "overload_candidates", "sibling_usages", "callers",
                "type_or_constant_definitions", "deep_dataflow",
            ],
            "semantic_retrieval_budget": {
                "max_compiler_queries": 3,
                "max_source_regions": 5,
                "max_total_source_chars": 2400,
                "max_source_chars_per_region": 800,
            },
            "source_index": "tree_sitter_query_pack_plus_clang_compilation_database",
            "static_semantic_bundle": True,
        },
        "warnings": state.get("warnings") or [],
        "errors": state.get("errors") or [],
    }
    has_source_evidence = bool(state.get("evidence_facts"))
    return write_related_code_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        related_code_context=workspace,
        step_name=f"correctness_behavior_analysis_round_{int(state.get('planning_round') or 1):02d}",
        status="generated" if has_source_evidence else "failed",
        error="" if has_source_evidence else "behavior_semantic_workspace_incomplete",
    )


def _compatible_prior_state(
    prior: Dict[str, Any], target: Dict[str, Any]
) -> Dict[str, Any]:
    if not isinstance(prior, dict):
        return {}
    if str(prior.get("state_version") or "") != str(STATE_VERSION):
        return {}
    prior_target = prior.get("target_contract") or {}
    if (
        str(prior_target.get("target_id") or "") != str(target.get("target_id") or "")
        or str(prior_target.get("source_hash") or "") != str(target.get("source_hash") or "")
    ):
        return {}
    return prior


def _compact_prior_state(prior: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "state_id": prior.get("state_id"),
        "status": prior.get("status"),
        "hypothesis_ledger": list(prior.get("hypothesis_ledger") or [])[:4],
        "information_needs": list(
            ((prior.get("behavior_state") or {}).get("information_needs") or [])
        )[:12],
        "evidence_facts": [
            {
                **item,
                "source_excerpt": str(item.get("source_excerpt") or "")[:1200],
            }
            for item in list(prior.get("evidence_facts") or [])[:16]
            if isinstance(item, dict)
        ],
        "plans": list(prior.get("plans") or [])[:3],
        "validation_history": list(prior.get("validation_history") or [])[-6:],
        "compilation_context": prior.get("compilation_context") or {},
        "warnings": list(prior.get("warnings") or [])[-8:],
        "errors": list(prior.get("errors") or [])[-8:],
    }


def _write_result(
    *,
    state: Dict[str, Any],
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    related_artifact: Dict[str, Any],
    llm_artifacts: list,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    plans = state.get("plans") or []
    result = {
        "architecture": ARCHITECTURE,
        "plans": plans,
        "repair_state": state,
        "failure_contract": state.get("failure_contract") or {},
        "target_inventory": state.get("target_inventory") or {},
        "behavior_state": state.get("behavior_state") or {},
        "hypothesis_ledger": state.get("hypothesis_ledger") or [],
        "retrieved_evidence_ids": [item.get("id") for item in state.get("evidence_facts") or []],
        "related_evidence_records": state.get("evidence_facts") or [],
        "related_context_artifact": related_artifact,
        "llm_artifacts": llm_artifacts,
        "warnings": state.get("warnings") or [],
        "errors": state.get("errors") or [],
        "planning_stop_reason": "patch_portfolio_ready" if plans else state.get("status"),
    }
    error = "" if plans else ";".join(
        str(item) for item in result["errors"][-8:]
    ) or "no_patch_portfolio"
    artifact = write_repair_suggestions_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        repair_suggestions=result,
        step_name=(
            f"correctness_cpg_behavior_causal_search_controller_round_"
            f"{int(state.get('planning_round') or 1):02d}"
        ),
        status="generated" if plans else "failed",
        error=error,
    )
    return result, artifact


def _failed_result(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    error: str,
    target: Dict[str, Any],
    failure: Dict[str, Any],
    inventory: Dict[str, Any],
    stage: str,
) -> Tuple[Dict[str, Any], Dict[str, Any]]:
    state = {
        "state_version": STATE_VERSION,
        "architecture": ARCHITECTURE,
        "status": f"{stage}_failed",
        "target_contract": target,
        "failure_contract": failure,
        "target_inventory": inventory,
        "behavior_state": {
            "context": {},
            "information_needs": [],
            "query_rounds": [],
            "diagnostics": [],
        },
        "hypothesis_ledger": [],
        "evidence_facts": [],
        "plans": [],
        "validation_history": [],
        "warnings": [],
        "errors": [error],
    }
    return _write_result(
        state=state,
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        related_artifact={},
        llm_artifacts=[],
    )
