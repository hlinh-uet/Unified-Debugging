import json
from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


REFIX_SYSTEM_PROMPT = (
    "You are a professional C/C++ patch refinement agent. Return ONLY the raw fixed C/C++ code. "
    "No markdown, no explanation, no backticks."
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
    focused_feedback = _focused_validation_feedback(validation_details, prior_context)
    diagnosis_hints = _build_patch_diagnosis_hints(
        focused_feedback=focused_feedback,
        previous_patched_function=previous_patched_function,
    )
    compact_validation = _compact_validation_details(validation_details)
    validation_json = json.dumps(
        compact_validation,
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    prior_context_json = json.dumps(
        prior_context or {},
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    return f"""REFIX TASK
Bug ID: {bug_id}
The previous APR patch was generated for the right repair target but did not validate.
Refine the previous patch into a better patch. Do not restart from an unrelated solution.

TARGET
Function name: {func_name}
Source file: {cand_label}

ORIGINAL FUNCTION BEFORE APR
BEGIN ORIGINAL FUNCTION
{original_function}
END ORIGINAL FUNCTION

PREVIOUS PATCHED FUNCTION THAT FAILED VALIDATION
BEGIN PREVIOUS PATCHED FUNCTION
{previous_patched_function}
END PREVIOUS PATCHED FUNCTION

FOCUSED FAILURE SIGNAL
This is the most important evidence. The previous patch must be corrected to satisfy this behavior.
BEGIN FOCUSED FAILURE SIGNAL
{focused_feedback}
END FOCUSED FAILURE SIGNAL

PATCH DIAGNOSIS HINTS
These are deterministic hints derived from the failed patch and failure signal. Follow them when applicable.
BEGIN PATCH DIAGNOSIS HINTS
{diagnosis_hints}
END PATCH DIAGNOSIS HINTS

VALIDATION FEEDBACK FROM PREVIOUS PATCH
Use this as the strongest signal. Pay attention to compile errors, failing test names, validation_error,
and validation_log_tail. If the feedback is incomplete, make the smallest defensible correction.
This JSON is intentionally compacted to avoid distracting passed-test noise.
BEGIN COMPACT VALIDATION FEEDBACK JSON
{validation_json}
END COMPACT VALIDATION FEEDBACK JSON

PRIOR APR CONTEXT
This contains saved metadata from the original APR attempt. It may include retrieval/fix/fail-context artifact
paths and previous status. Treat it as debugging context, not as source code truth.
BEGIN PRIOR APR CONTEXT JSON
{prior_context_json}
END PRIOR APR CONTEXT JSON

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ definition of function {func_name}.
2. Preserve the existing function signature.
3. Keep the change minimal relative to the previous patched function.
4. Do not add includes, new global helpers, main functions, unrelated refactors, or changes outside this function.
5. Do not return markdown, explanations, code fences, or backticks.
6. If the previous patch changed behavior in the wrong direction, revert only that wrong part and keep useful parts.

REFINED FIXED FUNCTION
"""


def _focused_validation_feedback(validation_details: dict, prior_context: dict) -> str:
    parts = []
    details = validation_details or {}
    for key in (
        "validation_error",
        "post_failed_tests",
        "full_post_failed_tests",
    ):
        value = details.get(key)
        if value:
            parts.append(f"{key}: {value}")

    tail = str(details.get("validation_log_tail") or "").strip()
    if tail:
        fail_lines = [
            line for line in tail.splitlines()
            if "__UD_FAIL__" in line or "FAIL" in line or "Expected" in line or "expected" in line
        ]
        if fail_lines:
            parts.append("validation_log_failure_lines:\n" + "\n".join(fail_lines[-30:]))
        else:
            parts.append("validation_log_tail:\n" + tail[-3000:])

    for key, value in (prior_context or {}).items():
        if not key.endswith("_response_excerpt"):
            continue
        text = str(value or "").strip()
        if not text:
            continue
        lower = text.lower()
        if "failure_summary" in lower or "expected" in lower or "observed" in lower:
            parts.append(f"{key}:\n{text[:5000]}")

    return "\n\n".join(parts) if parts else "No focused failure signal was available."


def _build_patch_diagnosis_hints(
    *,
    focused_feedback: str,
    previous_patched_function: str,
) -> str:
    hints = []
    feedback_lc = (focused_feedback or "").lower()
    patch_lc = (previous_patched_function or "").lower()

    sign_required = (
        'expected": "-' in feedback_lc
        or 'expected**: the string "-' in feedback_lc
        or "preserving the sign" in feedback_lc
        or "preserve the sign" in feedback_lc
    )
    abs_like_patch = (
        "abs_" in patch_lc
        or "std::abs" in patch_lc
        or " -d" in patch_lc
        or "= -d" in patch_lc
        or "-abs" in patch_lc
    )
    emits_minus = (
        "'-'" in patch_lc
        or '"-"' in patch_lc
        or "minus" in patch_lc
    )
    has_output_iterator = "out" in patch_lc

    if sign_required:
        hints.append(
            "The failure requires preserving a negative sign in formatted output "
            '(example expected output contains "-").'
        )
        if abs_like_patch and not emits_minus:
            hints.append(
                "The previous patch appears to convert a negative value to its absolute magnitude "
                "without emitting/preserving the '-' sign. That is insufficient."
            )
        if has_output_iterator:
            hints.append(
                "If this function owns an output iterator named out, a likely minimal repair is to "
                "emit '-' to out before formatting the absolute magnitude."
            )
        hints.append(
            "Do not repair this by only changing numeric conversion helpers or by only taking abs(); "
            "the output must still contain the negative sign."
        )

    if not hints:
        hints.append("No deterministic diagnosis hint was inferred beyond the focused failure signal.")
    return "\n".join(f"- {hint}" for hint in hints)


def _compact_validation_details(validation_details: dict) -> dict:
    details = validation_details or {}
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


def run_refix_agent(
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
    prior_context: dict,
) -> Tuple[Optional[str], dict]:
    prompt = build_refix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        original_function=original_function,
        previous_patched_function=previous_patched_function,
        validation_details=validation_details,
        prior_context=prior_context,
    )
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=REFIX_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name=f"refix_agent_round_{refix_round:02d}",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "refix_agent_no_response",
    )
    artifact["refix_round"] = refix_round
    return response, artifact
