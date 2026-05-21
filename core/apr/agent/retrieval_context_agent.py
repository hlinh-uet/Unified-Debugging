from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


RETRIEVAL_CONTEXT_SYSTEM_PROMPT = (
    "You are a C/C++ retrieval context agent for program repair. Read the target function, "
    "source file context, and local header context, then return a short structured code-context summary "
    "for a repair agent. Do not propose a patch and do not output patched code."
)


def build_retrieval_context_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    local_header_context: str,
    prompt_source: str,
) -> str:
    return f"""RETRIEVAL CONTEXT TASK
Bug ID: {bug_id}
Extract the shortest useful code context from the target C/C++ function, source file context, and local header context.
Do not decide the final patch.

TARGET FUNCTION TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET FUNCTION
{func_code}
END TARGET FUNCTION

SOURCE FILE CONTEXT
Use this source context to identify relevant #include, #define, typedef, struct, enum, global declarations, helper functions, callers/callees, and coding idioms. Do not rewrite this context code.
BEGIN SOURCE CONTEXT
{prompt_source}
END SOURCE CONTEXT

LOCAL HEADER CONTEXT
Use this raw local header context to identify relevant macros, types, structs, enums, declarations, and helper APIs imported by quoted includes.
BEGIN LOCAL HEADER CONTEXT
{local_header_context}
END LOCAL HEADER CONTEXT

RETRIEVAL CONTEXT OUTPUT
Return concise structured notes with exactly these fields:
includes_and_declarations:
local_header_context:
helper_functions:
target_references:
coding_idioms:
risky_operations:
constraints:
uncertainties:

Rules:
- Do not output patched code.
- Do not propose a concrete patch or rewrite strategy.
- Keep only information useful for repairing the target function.
- Put relevant #include, #define, typedef, struct, enum, and global declarations under includes_and_declarations.
- Put relevant imported local-header macros, types, declarations, and helper APIs under local_header_context.
- Put helper functions called by the target function under helper_functions.
- Put places where the target function is called or referenced under target_references.
- Put same-file coding idioms such as ND_TCHECK, ND_PRINT, goto trunc, trunc:, and similar patterns under coding_idioms.
- Put target-function operations that may read invalid memory, dereference unchecked pointers, use input-controlled indexes or lengths, advance pointers, allocate/copy/parse based on external data, or pass computed buffers/lengths into helpers under risky_operations. For each item, include the exact expression or statement, why it is risky, and the visible guard/check nearby if any.
- Put required behavior, preservation rules, and forbidden changes under constraints.
- If source or header context is incomplete, say what is uncertain and avoid inventing facts.
"""


def run_retrieval_context_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    func_name: str,
    cand_label: str,
    func_code: str,
    local_header_context: str,
    prompt_source: str,
) -> Tuple[Optional[str], dict]:
    prompt = build_retrieval_context_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        local_header_context=local_header_context,
        prompt_source=prompt_source,
    )
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=RETRIEVAL_CONTEXT_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        llm_provider=llm_provider,
        step_name="retrieval_context_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "retrieval_context_agent_no_response",
    )
    return response, artifact
