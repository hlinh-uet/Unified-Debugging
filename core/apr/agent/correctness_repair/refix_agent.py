"""Patch re-synthesis after typed validation feedback."""

from __future__ import annotations

import difflib
import json
from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm

from .feedback import classify_validation_feedback
from .models import clip


REFIX_SYSTEM_PROMPT = (
    "You are a C/C++ patch synthesizer refining one source-bound repair candidate. Return only the "
    "complete raw replacement unit. Do not return markdown or explanation."
)


def build_refix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    original_function: str,
    previous_patched_function: str,
    validation_details: dict,
    prior_context: dict,
) -> str:
    feedback = classify_validation_feedback(validation_details)
    validation_context = (prior_context or {}).get("validation_context") or {}
    plan = validation_context.get("repair_plan") or {}
    delta = "\n".join(difflib.unified_diff(
        (original_function or "").splitlines(),
        (previous_patched_function or "").splitlines(),
        fromfile="original", tofile="previous_patch", lineterm="", n=3,
    ))
    payload = {
        "bug_id": bug_id,
        "target": {"function": func_name, "source_file": cand_label},
        "validation_feedback": feedback,
        "selected_plan": {
            "id": plan.get("id"),
            "source_hypothesis_id": plan.get("source_hypothesis_id"),
            "hypothesis": clip(plan.get("hypothesis"), 900),
            "edit_intent": clip(plan.get("edit_intent"), 900),
            "structured_edits": (plan.get("structured_edits") or [])[:8],
            "must_preserve": (plan.get("must_preserve") or [])[:12],
        },
        "patch_delta": clip(delta, 5000),
    }
    return f"""PATCH RE-SYNTHESIS

The selected plan is the plan that produced PREVIOUS FAILED REPLACEMENT UNIT. Preserve that plan lineage
for this ReFix pass: refine its implementation and do not silently switch to another portfolio plan.
Use the typed validation transition as feedback:
- refine_edit: preserve the causal mechanism and repair only materialization/type/API details.
- revise_preservation_constraints: retain the fixed behavior and remove the regression.
- rediagnose_mechanism: the previous implementation did not support the selected mechanism; produce a more
  faithful implementation of the same selected plan using the original unit, failed patch, and test feedback.
- repair_source_binding_or_patch_shape: repair only completeness/source shape; do not infer test behavior.

INPUT
{json.dumps(payload, ensure_ascii=False, indent=2, default=str)}

ORIGINAL EXACT REPLACEMENT UNIT
{original_function}

PREVIOUS FAILED REPLACEMENT UNIT
{previous_patched_function}

RAW REFINED REPLACEMENT UNIT
"""


def run_correctness_refix_agent(
    *,
    bug_id: str,
    attempt_index: int,
    refix_round: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    original_function: str,
    previous_patched_function: str,
    validation_details: dict,
    prior_context: Optional[dict] = None,
) -> Tuple[Optional[str], dict]:
    prompt = build_refix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        original_function=original_function,
        previous_patched_function=previous_patched_function,
        validation_details=validation_details,
        prior_context=prior_context or {},
    )
    response = call_llm(prompt, provider=llm_provider, system_prompt=REFIX_SYSTEM_PROMPT)
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name=f"correctness_patch_resynthesizer_round_{refix_round:02d}",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "patch_resynthesizer_no_response",
    )
    artifact["refix_round"] = refix_round
    return response, artifact
