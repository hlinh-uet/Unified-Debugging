import difflib
import json
from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


PATCH_VALIDATION_SYSTEM_PROMPT = (
    "You are a C/C++ patch validation critic. Analyze why a generated patch failed validation. "
    "Do not write patched code. Return ONLY compact JSON."
)


def build_patch_validation_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    original_function: str,
    patched_function: str,
    validation_details: dict,
    prior_context: dict,
) -> str:
    validation_json = json.dumps(
        _compact_validation_details(validation_details),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    prior_context_json = json.dumps(
        _compact_prior_context(prior_context),
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    patch_delta = _patch_delta_summary(original_function, patched_function)
    return f"""PATCH VALIDATION TASK
Bug ID: {bug_id}
Analyze the failed FixAgent patch for this C/C++ function. Do not produce code.

TARGET
Function name: {func_name}
Source file: {cand_label}

ORIGINAL FUNCTION BEFORE PATCH
BEGIN ORIGINAL FUNCTION
{original_function}
END ORIGINAL FUNCTION

FIXAGENT PATCHED FUNCTION THAT FAILED
BEGIN PATCHED FUNCTION
{patched_function}
END PATCHED FUNCTION

PATCH DELTA
BEGIN PATCH DELTA
{patch_delta}
END PATCH DELTA

VALIDATION DETAILS
BEGIN VALIDATION JSON
{validation_json}
END VALIDATION JSON

PRIOR FAILURE/CODE CONTEXT
BEGIN PRIOR CONTEXT JSON
{prior_context_json}
END PRIOR CONTEXT JSON

CRITIC RULES
- Do not invent new APIs, helpers, error codes, tests, or behavior.
- Ground every claim in validation details, prior context, original function, or patch delta.
- The goal is to help ReFix improve the failed patch, not solve from scratch.
- Identify whether the patch likely fixed the original failure, introduced regressions, was no-op,
  malformed, wrong-target, overbroad, or violated the failure contract.
- If the original failure expects valid input to succeed, explicitly forbid turning that path into
  a new error return unless validation evidence requires it.
- Prefer "keep/revert/refine" guidance over a new from-scratch patch strategy.

OUTPUT JSON SCHEMA
Return exactly one JSON object with these keys:
{{
  "patch_outcome": "no_op | malformed | compile_error | wrong_target | introduced_regression | still_failing_original | partial_fix_with_regression | unknown",
  "fixed_original_failure": true,
  "likely_patch_issue": "short grounded explanation",
  "evidence": ["short evidence bullets"],
  "keep_from_fix_patch": ["patch elements likely useful to preserve"],
  "change_in_refix": ["specific patch elements to refine, remove, or revert"],
  "forbidden_changes": ["changes ReFix must avoid"],
  "must_preserve": ["behavior/contracts that must remain true"],
  "confidence": "low | medium | high"
}}
"""


def run_patch_validation_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    original_function: str,
    patched_function: str,
    validation_details: dict,
    prior_context: dict,
) -> Tuple[str, dict]:
    prompt = build_patch_validation_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        original_function=original_function,
        patched_function=patched_function,
        validation_details=validation_details,
        prior_context=prior_context,
    )
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=PATCH_VALIDATION_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name="patch_validation_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "patch_validation_agent_no_response",
    )
    return response or "", artifact


def _patch_delta_summary(original_function: str, patched_function: str) -> str:
    diff_lines = list(
        difflib.unified_diff(
            (original_function or "").splitlines(),
            (patched_function or "").splitlines(),
            fromfile="original",
            tofile="fixagent_patch",
            lineterm="",
            n=3,
        )
    )
    if not diff_lines:
        return "No textual delta was detected between original and FixAgent patch."
    text = "\n".join(diff_lines)
    return text[:7000] + ("\n...<patch delta truncated>" if len(text) > 7000 else "")


def _compact_validation_details(details: dict) -> dict:
    details = details or {}
    out = {
        "validation_error": details.get("validation_error", ""),
        "post_failed_tests": details.get("post_failed_tests", []),
        "full_post_failed_tests": details.get("full_post_failed_tests", []),
    }
    tail = str(details.get("validation_log_tail") or "")
    if tail:
        out["validation_log_tail"] = tail[-5000:]
    for key in (
        "phase_a_suite_ok",
        "phase_a_base_commit",
        "phase_a_buggy_overlay_commit",
        "phase_a_buggy_overlay_files",
    ):
        if key in details:
            out[key] = details.get(key)
    return out


def _compact_prior_context(prior_context: dict) -> dict:
    prior_context = prior_context or {}
    keys = (
        "function",
        "status",
        "validation_error",
        "repair_target_relpath",
        "fail_context_agent_artifact_response_excerpt",
        "fix_agent_artifact_response_excerpt",
    )
    return {key: prior_context.get(key) for key in keys if prior_context.get(key)}
