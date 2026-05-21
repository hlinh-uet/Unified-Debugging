from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


FIX_SYSTEM_PROMPT = (
    "You are a professional C/C++ repair agent. Return ONLY the raw fixed C/C++ code. "
    "No markdown, no explanation, no backticks."
)


def build_fix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    retrieval_context: str,
    failed_tests_context: str,
) -> str:
    return f"""REPAIR TASK
Bug ID: {bug_id}
Repair only the target C/C++ function below. The defect may be a vulnerability or a general correctness bug.
The target function is the only code that will be replaced by your answer.

TARGET FUNCTION TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET FUNCTION
{func_code}
END TARGET FUNCTION

FAILURE EVIDENCE
Use this metadata evidence to understand the observed failure. It may be incomplete.
{failed_tests_context}

RETRIEVAL CONTEXT
Use this agent-produced context summary for relevant includes, declarations, local headers, helper functions, target references, coding idioms, risky operations, constraints, and uncertainties.
BEGIN RETRIEVAL CONTEXT
{retrieval_context.strip()}
END RETRIEVAL CONTEXT

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ definition of function {func_name}.
2. Preserve the existing function signature, coding style, macros, and helper APIs unless the bug fix strictly requires otherwise.
3. Keep the patch minimal and localized to function {func_name}.
4. Do not add includes, new global helpers, main functions, unrelated refactors, or changes outside the target function.
5. Do not include explanations, preface text, markdown, code fences, or backticks.

FIXED FUNCTION
"""


def run_fix_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    func_code: str,
    retrieval_context: str,
    failed_tests_context: str,
) -> Tuple[Optional[str], dict]:
    prompt = build_fix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        retrieval_context=retrieval_context,
        failed_tests_context=failed_tests_context,
    )
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=FIX_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name="fix_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "fix_agent_no_response",
    )
    return response, artifact
