from typing import Any, Dict, Optional, Tuple

from core.apr.agent.context_common import parser_diagnostics
from core.apr.artifacts import write_target_code_context_artifact

from .envelope import build_target_envelope
from .failure_localization import build_failure_localization
from .function_ir import extract_function_ir
from .local_constraints import infer_local_contracts
from .repair_atoms import rank_target_repair_atoms

# Điều phối toàn bộ phân tích nội bộ target function và đóng gói evidence cho FixAgent.
def collect_target_code_context(
    *,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    language: str,
    failed_tests_context: str = "",
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    repair_objective = repair_objective or {}
    target_spec = build_target_envelope(
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        source_code=source_code,
        source_path=source_path,
        start_idx=start_idx,
        end_idx=end_idx,
        language=language,
    )
    function_ir = extract_function_ir(
        target_spec=target_spec,
        func_code=func_code,
        source_code=source_code,
        language=language,
    )
    failure_localization = build_failure_localization(
        function_ir=function_ir,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
    )
    repair_atom_localization = rank_target_repair_atoms(
        target_spec=target_spec,
        function_ir=function_ir,
        failure_localization=failure_localization,
        source_code=source_code,
        language=language,
    )
    local_constraints = infer_local_contracts(
        target_spec=target_spec,
        function_ir=function_ir,
        failure_localization=failure_localization,
        source_code=source_code,
    )
    repair_atom_localization = _rerank_with_semantic_contracts(
        repair_atom_localization=repair_atom_localization,
        semantic_repair_contracts=local_constraints.get("semantic_repair_contracts") or [],
    )
    return build_target_context_output(
        target_spec=target_spec,
        function_ir=function_ir,
        failure_localization=failure_localization,
        repair_atom_localization=repair_atom_localization,
        local_constraints=local_constraints,
        language=language,
    )

# Gom output theo schema mới, đồng thời giữ các field phẳng cũ để tương thích downstream.
def build_target_context_output(
    *,
    target_spec: Dict[str, Any],
    function_ir: Dict[str, Any],
    failure_localization: Dict[str, Any],
    repair_atom_localization: Dict[str, Any],
    local_constraints: Dict[str, Any],
    language: str,
) -> Dict[str, Any]:
    analysis = function_ir.get("analysis") or {}
    return {
        "analysis_engine": {
            "name": "target_ast_repair_atom_localization_engine",
            "version": 5,
            "available": bool(analysis.get("analysis_available")),
            "strategy": analysis.get("strategy", "unknown"),
            "parser": analysis.get("parser") or parser_diagnostics(language),
            "capabilities": [
                "exact_target_envelope_validation",
                "intra_function_def_use",
                "control_context_extraction",
                "expression_inventory_extraction",
                "cfg_lite_construction",
                "lightweight_program_dependence_graph",
                "failure_contract_extraction",
                "semantic_invariant_mining",
                "semantic_repair_contract_extraction",
                "ast_repair_atom_localization",
                "semantic_contract_reranking",
                "edit_scope_constraints",
                "repair_objective_routing",
            ],
        },
        "target_spec": {
            "target_identity": target_spec.get("target_identity") or {},
            "target_envelope": target_spec.get("target_envelope") or {},
        },
        "function_ir": function_ir.get("function_ir") or {},
        "failure_localization": failure_localization.get("failure_localization") or {},
        "repair_atom_localization": repair_atom_localization.get("repair_atom_localization") or {},
        "local_constraints": local_constraints.get("local_constraints") or {},
        "target_identity": target_spec.get("target_identity") or {},
        "target_envelope": target_spec.get("target_envelope") or {},
        "target_symbols": function_ir.get("target_symbols") or {},
        "failure_contract": failure_localization.get("failure_contract") or {},
        "structural_regions": function_ir.get("structural_regions") or [],
        "statement_inventory": function_ir.get("statement_inventory") or [],
        "expression_inventory": function_ir.get("expression_inventory") or [],
        "data_flow_summary": function_ir.get("data_flow_summary") or {},
        "control_flow_summary": function_ir.get("control_flow_summary") or {},
        "control_flow_graph": function_ir.get("control_flow_graph") or {},
        "program_dependence_graph": failure_localization.get("program_dependence_graph") or {},
        "failure_slices": failure_localization.get("failure_slices") or [],
        "ranked_repair_sites": failure_localization.get("ranked_repair_sites") or [],
        "ranked_repair_atoms": repair_atom_localization.get("ranked_repair_atoms") or [],
        "repair_atom_summary": repair_atom_localization.get("repair_atom_summary") or {},
        "advanced_intra_function_analysis": local_constraints.get("advanced_intra_function_analysis") or {},
        "semantic_repair_contracts": local_constraints.get("semantic_repair_contracts") or [],
        "semantic_invariants": local_constraints.get("semantic_invariants") or [],
        "failure_code_links": failure_localization.get("failure_code_links") or [],
        "local_behavioral_contracts": local_constraints.get("local_behavioral_contracts") or [],
        "edit_scope": local_constraints.get("edit_scope") or {},
    }


def _rerank_with_semantic_contracts(
    *,
    repair_atom_localization: Dict[str, Any],
    semantic_repair_contracts: list,
) -> Dict[str, Any]:
    atoms = [dict(atom) for atom in repair_atom_localization.get("ranked_repair_atoms") or []]
    if not atoms or not semantic_repair_contracts:
        return repair_atom_localization
    for atom in atoms:
        delta, reasons = _semantic_atom_score_delta(atom, semantic_repair_contracts)
        if delta:
            atom["score"] = int(atom.get("score") or 0) + delta
            evidence = dict(atom.get("evidence") or {})
            evidence["semantic_contract_reasons"] = reasons[:6]
            atom["evidence"] = evidence
    atoms.sort(key=lambda item: (-int(item.get("score") or 0), item.get("line_range") or [10**9], item.get("kind") or ""))
    for idx, atom in enumerate(atoms, start=1):
        atom["id"] = f"RA{idx}"
        atom["rank"] = idx
        atom["confidence"] = "high" if int(atom.get("score") or 0) >= 28 else "medium" if int(atom.get("score") or 0) >= 16 else "low"
    out = dict(repair_atom_localization)
    out["ranked_repair_atoms"] = atoms
    loc = dict(out.get("repair_atom_localization") or {})
    loc["ranked_repair_atoms"] = atoms
    out["repair_atom_localization"] = loc
    return out


def _semantic_atom_score_delta(atom: Dict[str, Any], contracts: list) -> tuple:
    text = str(atom.get("text") or "")
    parent = str((atom.get("parent_statement") or {}).get("text") or "")
    combined = f"{text}\n{parent}".lower()
    delta = 0
    reasons = []
    for contract in contracts:
        kind = contract.get("kind")
        if kind == "numeric_alignment_sign_emission":
            if any(term in combined for term in ("align_numeric", "reserve(", "write_padded", "double_writer")):
                delta += 18
                reasons.append("boosted by numeric_alignment_sign_emission contract")
            if "sign_flag" in combined and "align_numeric" not in combined:
                delta -= 6
                reasons.append("predicate-only sign flag edit is lower priority than sign emission path")
        elif kind == "output_iterator_postcondition":
            if any(term in combined for term in ("ctx.out", "advance_to", "return", "visit(")):
                delta += 16
                reasons.append("boosted by output_iterator_postcondition contract")
            if "handle_dynamic_spec" in combined:
                delta -= 8
                reasons.append("dynamic spec call is preserve-critical unless proven defective")
        elif kind == "error_propagation_contract":
            if any(term in combined for term in ("return -1", "return {}", "on_error", "format_error")):
                delta += 14
                reasons.append("boosted by error_propagation_contract")
            if "assert_fail" in combined:
                delta -= 10
                reasons.append("assert/abort path is not preferred error propagation")
        elif kind == "preserve_critical_call_sequence":
            if any(term in combined for term in ("handle_dynamic_spec", "write_padded", "visit(")):
                delta -= 4
                reasons.append("call sequence is preserve-critical; prefer adjacent value/return edits")
    return delta, reasons

# Chạy TargetCodeContextAgent cho một candidate FL và lưu artifact phân tích ra experiments.
def run_target_code_context_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    language: str,
    failed_tests_context: str = "",
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Tuple[dict, dict]:
    context = collect_target_code_context(
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        source_code=source_code,
        source_path=source_path,
        start_idx=start_idx,
        end_idx=end_idx,
        language=language,
        failed_tests_context=failed_tests_context,
        repair_objective=repair_objective,
    )
    artifact = write_target_code_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        target_code_context=context,
    )
    return context, artifact
