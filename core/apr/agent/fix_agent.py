import json
from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


FIX_SYSTEM_PROMPT = (
    "You are a professional C/C++ repair agent. Return ONLY the raw fixed C/C++ code. "
    "Use the failure evidence and deterministic code evidence pack as source-of-truth. "
    "No markdown, no explanation, no backticks."
)


def build_fix_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    repair_evidence_pack: dict,
    failed_tests_context: str,
) -> str:
    repair_evidence_json = json.dumps(
        repair_evidence_pack or {},
        ensure_ascii=False,
        indent=2,
        default=str,
    )
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

REPAIR EVIDENCE PACK
Use this deterministic code evidence as the source-of-truth for available APIs, helper signatures, macros, types, declarations, source-file context, project-header declarations, usage examples, and caller contracts.
BEGIN REPAIR EVIDENCE PACK JSON
{repair_evidence_json}
END REPAIR EVIDENCE PACK JSON

CONTEXT USE POLICY
1. First identify the concrete failing behavior from FAILURE EVIDENCE.
2. Use REPAIR EVIDENCE PACK to verify relevant APIs, macros, types, helpers, ownership rules, and caller expectations.
3. Verify every API, macro, type, helper, ownership rule, and caller expectation against TARGET FUNCTION or REPAIR EVIDENCE PACK.
4. Prefer existing same-file helpers, macros, and idioms over inventing new logic.
5. Produce the smallest safe repair supported by the target function and evidence pack.
6. Do not copy unrelated helper bodies or examples into the target function.
7. Preserve the expected behavior stated in FAILURE EVIDENCE. If the test expects valid input to succeed,
   do not turn that path into a validation/error return only to avoid a crash.
8. For crash/null-deref fixes, prefer the smallest guard/fallback/continue/cleanup adjustment that keeps the
   original success semantics. Add a new error return only when the failure evidence expects an error.
9. Avoid formatting churn and broad rewrites; changing unrelated lines increases regression risk.

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ definition of function {func_name}.
2. Preserve the existing function signature, coding style, macros, and helper APIs unless the bug fix strictly requires otherwise.
3. Keep the patch minimal and localized to function {func_name}.
4. Do not add includes, new global helpers, main functions, unrelated refactors, or changes outside the target function.
5. Do not call or rely on an API, macro, type, helper, ownership convention, or error-handling convention unless it appears in the target function, repair evidence pack, or is clearly provided by an included standard/system header shown in the evidence.
6. Do not include explanations, preface text, markdown, code fences, or backticks.

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
    repair_evidence_pack: dict,
    failed_tests_context: str,
) -> Tuple[Optional[str], dict]:
    prompt = build_fix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        repair_evidence_pack=repair_evidence_pack,
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
