"""Patch synthesis for one grounded causal plan."""

from __future__ import annotations

import json
from typing import Any, Dict, Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm

from .failure_contract import build_failure_contract
from .models import clip


PATCH_SYSTEM_PROMPT = (
    "You are a C/C++ patch synthesizer. Implement exactly one grounded causal plan inside the exact "
    "replacement unit. Return only the complete raw replacement unit, without markdown or explanation."
)


def build_correctness_fix_agent_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: Any,
    repair_objective: Optional[Dict[str, Any]] = None,
    repair_context: Optional[Dict[str, Any]] = None,
    output_contract: Optional[Dict[str, Any]] = None,
    repair_plan: Optional[Dict[str, Any]] = None,
) -> str:
    del repair_objective
    context = repair_context or {}
    state = context.get("repair_state") if isinstance(context.get("repair_state"), dict) else {}
    failure = state.get("failure_contract") or context.get("failure_contract")
    if not isinstance(failure, dict):
        failure = build_failure_contract(failed_tests_context if isinstance(failed_tests_context, dict) else {})
    plan = _compact_selected_repair_plan(repair_plan or {})
    evidence = plan.pop("grounded_evidence", [])
    payload = {
        "bug_id": bug_id,
        "target": {
            "function": func_name,
            "source_file": cand_label,
            "target_unit_id": (repair_plan or {}).get("target_unit_id"),
            "source_hash": (state.get("target_contract") or {}).get("source_hash"),
        },
        "failure_contract": failure,
        "selected_hypothesis": plan.get("hypothesis"),
        "selected_plan": plan,
        "cited_source_evidence": evidence,
        "output_contract": _compact_output_contract(output_contract or {}),
    }
    return f"""PATCH SYNTHESIS

Implement the selected plan, not a new diagnosis. Use only symbols and APIs present in TARGET or
CITED SOURCE EVIDENCE. Preserve the signature and all behavior listed in must_preserve.
The output must be one complete replacement unit. Do not add includes or declarations outside it.

REPAIR INPUT
{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}

EXACT TARGET REPLACEMENT UNIT
----- BEGIN TARGET -----
{func_code}
----- END TARGET -----

RAW FIXED REPLACEMENT UNIT
"""


def run_correctness_fix_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    func_code: str,
    failed_tests_context: Any,
    repair_objective: Optional[Dict[str, Any]] = None,
    repair_context: Optional[Dict[str, Any]] = None,
    output_contract: Optional[Dict[str, Any]] = None,
    repair_plan: Optional[Dict[str, Any]] = None,
) -> Tuple[Optional[str], dict]:
    prompt = build_correctness_fix_agent_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
        repair_context=repair_context,
        output_contract=output_contract,
        repair_plan=repair_plan,
    )
    response = call_llm(prompt, provider=llm_provider, system_prompt=PATCH_SYSTEM_PROMPT)
    plan_suffix = _safe_step_suffix((repair_plan or {}).get("id"))
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name=f"correctness_patch_synthesizer{plan_suffix}",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "patch_synthesizer_no_response",
    )
    return response, artifact


def _compact_selected_repair_plan(plan: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(plan, dict):
        return {}
    evidence = []
    for fact in plan.get("grounded_evidence_cards") or []:
        if not isinstance(fact, dict):
            continue
        evidence.append({
            "id": fact.get("id"),
            "kind": fact.get("kind"),
            "relation": fact.get("relation"),
            "symbol": fact.get("symbol"),
            "source_file": fact.get("source_file"),
            "source_range": fact.get("source_range"),
            "source_excerpt": clip(fact.get("source_excerpt"), 1800),
            "semantic_summary": clip(fact.get("semantic_summary"), 500),
            "semantic_details": fact.get("semantic_details") or {},
        })
    return {
        "id": plan.get("id"),
        "source_hypothesis_id": plan.get("source_hypothesis_id"),
        "hypothesis": clip(plan.get("hypothesis"), 900),
        "target_unit_id": plan.get("target_unit_id"),
        "edit_intent": clip(plan.get("edit_intent"), 900),
        "structured_edits": (plan.get("structured_edits") or [])[:8],
        "required_evidence_ids": (plan.get("required_evidence_ids") or [])[:16],
        "must_preserve": (plan.get("must_preserve") or [])[:12],
        "why_this_may_fix": clip(plan.get("why_this_may_fix"), 900),
        "risk": plan.get("risk"),
        "confidence": plan.get("confidence"),
        "grounded_evidence": evidence,
    }


def _compact_output_contract(contract: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "editable_scope": clip(contract.get("editable_scope"), 400),
        "return_format": clip(contract.get("return_format"), 300),
        "must_preserve": (contract.get("must_preserve") or [])[:10],
        "must_not": (contract.get("must_not") or [])[:10],
        "repair_scope": contract.get("repair_scope") or {},
    }


def _safe_step_suffix(value: Any) -> str:
    chars = [ch if ch.isalnum() or ch in "._-" else "_" for ch in str(value or "")]
    value = "".join(chars).strip("._-")
    return f"_{value[:40]}" if value else ""
