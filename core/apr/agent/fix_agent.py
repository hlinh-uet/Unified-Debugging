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
    target_code_context: dict,
    related_code_context: dict,
    failed_tests_context: str,
) -> str:
    target_context_json = json.dumps(
        target_code_context or {},
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    related_context_json = json.dumps(
        related_code_context or {},
        ensure_ascii=False,
        indent=2,
        default=str,
    )
    return f"""REPAIR TASK
Bug ID: {bug_id}
Repair only the target C/C++ function below. The defect may be a vulnerability or a general correctness bug.
The target replacement unit is the only code that will be replaced by your answer.

TARGET REPLACEMENT UNIT TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET REPLACEMENT UNIT
{func_code}
END TARGET REPLACEMENT UNIT

FAILURE EVIDENCE
Use this metadata evidence to understand the observed failure. It may be incomplete.
{failed_tests_context}

TARGET CODE CONTEXT
This deterministic context describes the exact replacement range, enclosing/template/scope constraints,
failure-to-code links, local contracts, and local repair guardrails. Treat it as the strongest source of
truth for what your answer may contain.
BEGIN TARGET CODE CONTEXT JSON
{target_context_json}
END TARGET CODE CONTEXT JSON

RELATED CODE CONTEXT
This deterministic context contains relevant same-file helpers, callee/caller context, headers, tests,
usage examples, external helper/API contracts, project idioms, and ranked context. Use it to avoid
inventing APIs or violating helper/caller contracts.
BEGIN RELATED CODE CONTEXT JSON
{related_context_json}
END RELATED CODE CONTEXT JSON

CONTEXT USE POLICY
1. First identify the concrete failing behavior from FAILURE EVIDENCE.
2. Obey TARGET CODE CONTEXT target_envelope.output_contract and local_repair_guardrails before all other guidance.
3. Use TARGET CODE CONTEXT failure_code_links as the first repair-site candidates.
4. Use RELATED CODE CONTEXT external_behavioral_contracts and ranked_context to verify helper/API/caller behavior.
5. Verify every API, macro, type, helper, ownership rule, and caller expectation against the target or related context.
6. Prefer existing same-file helpers, macros, and idioms over inventing new logic.
7. Produce the smallest safe repair supported by failure evidence and both context blocks.
8. Do not copy unrelated helper bodies or examples into the target replacement unit.
9. Preserve the expected behavior stated in FAILURE EVIDENCE. If the test expects valid input to succeed,
   do not turn that path into a validation/error return only to avoid a crash.
10. For crash/null-deref fixes, prefer the smallest guard/fallback/continue/cleanup adjustment that keeps the
   original success semantics. Add a new error return only when the failure evidence expects an error.
11. Avoid formatting churn and broad rewrites; changing unrelated lines increases regression risk.
12. Do not add template prefixes, return types, namespaces, classes, wrappers, includes, or helper functions unless
    target_envelope.replacement_unit already includes that exact surrounding construct.

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ replacement unit for {func_name}.
2. Preserve the existing signature, template context, coding style, macros, and helper APIs unless TARGET CODE CONTEXT explicitly permits otherwise.
3. Keep the patch minimal and localized to the shown replacement unit.
4. Do not add includes, new global helpers, main functions, unrelated refactors, or changes outside the target function.
5. Do not call or rely on an API, macro, type, helper, ownership convention, or error-handling convention unless it appears in the target code context, related code context, or is clearly provided by an included standard/system header shown in the evidence.
6. Do not include explanations, preface text, markdown, code fences, or backticks.

FIXED REPLACEMENT UNIT
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
    target_code_context: dict,
    related_code_context: dict,
    failed_tests_context: str,
) -> Tuple[Optional[str], dict]:
    prompt = build_fix_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        target_code_context=target_code_context,
        related_code_context=related_code_context,
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
