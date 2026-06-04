import json
from typing import Optional, Tuple

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


RETRIEVAL_CONTEXT_SYSTEM_PROMPT = (
    "You are a C/C++ retrieval context agent for program repair. Read deterministic code context "
    "collected from the target function, source file, include inventory, project headers, symbols, "
    "API surfaces, and usage examples. Return a short structured context summary for a repair agent. "
    "Do not propose a patch and do not output patched code."
)


# =============================================================================
# Nhóm 1: Tạo prompt retrieval-context
# =============================================================================

# Nhận collector_context do CodeContextCollector tạo ra:
# - source_context: source slice đã cắt quanh target function.
# - include_inventory: system/project includes và header resolve được.
# - target_symbols: call/type/field/macro-like symbols lấy từ func_code bằng tree-sitter.
# - source_api_surface/project_header_api_context: declaration, macro, type, prototype liên quan.
# - usage_examples: ví dụ dùng API/helper trong source tree để FixAgent không đoán sai API.
# Hàm này ghép context deterministic thành prompt cho LLM tóm tắt, không sinh patch.
def build_retrieval_context_prompt(
    *,
    bug_id: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    collector_context: dict,
) -> str:
    summary_context = dict(collector_context)
    summary_context.pop("repair_evidence_pack", None)
    context_json = json.dumps(summary_context, ensure_ascii=False, indent=2, default=str)
    return f"""RETRIEVAL CONTEXT TASK
Bug ID: {bug_id}
Extract the shortest useful code context from the target C/C++ function and deterministic collector context.
Do not decide the final patch.

TARGET FUNCTION TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET FUNCTION
{func_code}
END TARGET FUNCTION

DETERMINISTIC COLLECTOR CONTEXT
This JSON was produced before the LLM step. It contains include inventory, resolved project headers, target symbols extracted from the target function, declaration/API surfaces from source and headers, and usage examples from the project. Treat it as evidence; if a declaration or include is missing, say it is uncertain instead of inventing APIs.
BEGIN COLLECTOR CONTEXT JSON
{context_json}
END COLLECTOR CONTEXT JSON

RETRIEVAL CONTEXT OUTPUT
Return concise structured notes with exactly these fields:
include_inventory:
library_api_context:
project_header_api_context:
target_symbols:
same_file_helpers:
cross_file_usage_examples:
target_references:
coding_idioms:
repair_relevant_observations:
constraints:
uncertainties:

Rules:
- Do not output patched code.
- Do not propose a concrete patch or rewrite strategy.
- Keep only information useful for repairing the target function.
- Put system/project includes and unresolved includes under include_inventory.
- Put known library/API implications from system includes and observed usage under library_api_context. Do not invent external API contracts not supported by context.
- Put relevant project-header macros, typedefs, structs, enums, declarations, prototypes, and helper APIs under project_header_api_context.
- Put calls, type names, fields, identifiers, and macro-like symbols used by the target function under target_symbols.
- Put same-file helper functions/declarations called by the target function under same_file_helpers.
- Put project usage snippets that show how target APIs/helpers/macros are normally used under cross_file_usage_examples.
- Put places where the target function is called or referenced under target_references.
- Put same-file coding idioms, error-handling conventions, formatting conventions, ownership conventions, validation style, and similar project patterns under coding_idioms.
- Put target-function statements, branches, calls, state updates, formatting operations, validation checks, ownership changes, data transformations, or buffer operations that are likely relevant to repair under repair_relevant_observations. Keep this neutral and evidence-based; do not assume the bug is memory-safety.
- Put required behavior, preservation rules, and forbidden changes under constraints.
- If source, header, declaration, or usage context is incomplete, say what is uncertain and avoid inventing facts.
- Prefer APIs/macros/types that are present in project_header_api_context, source_api_surface, or usage examples; flag any unsupported API as risky.
"""


# =============================================================================
# Nhóm 2: Entry point chạy agent
# =============================================================================

# Entry point được pipeline gọi cho từng candidate function sau CodeContextCollectorAgent.
# Hàm này nhận collector_context đã được xử lý sẵn, đưa vào prompt, gọi LLM,
# ghi artifact prompt/response để debug, rồi trả retrieval summary cho FixAgent.
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
    collector_context: dict,
) -> Tuple[Optional[str], dict]:
    # func_code không bị cắt/lọc ở đây; prompt luôn chứa đầy đủ target function.
    prompt = build_retrieval_context_prompt(
        bug_id=bug_id,
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        collector_context=collector_context,
    )
    # LLM chỉ được yêu cầu tóm tắt context có cấu trúc, không sinh patch.
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=RETRIEVAL_CONTEXT_SYSTEM_PROMPT,
    )
    # Lưu prompt/response/status để có thể trace lại retrieval agent đã thấy gì
    # và đã trả gì trong từng attempt.
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
