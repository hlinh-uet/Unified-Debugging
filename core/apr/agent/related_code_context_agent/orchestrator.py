from typing import Any, Dict, Optional, Tuple

from core.apr.artifacts import write_related_code_context_artifact
from core.apr.agent.context_common import (
    extract_symbols_from_code,
    parser_diagnostics,
    relpath,
    source_language_from_path,
    source_root,
)

from .contracts import _api_macro_type_contract_engine
from .inventories import (
    _augment_visible_api_inventory,
    _available_symbol_inventory,
    _constructor_initializer_whitelist,
    _member_field_inventory,
    _scope_aware_symbol_contract,
    _visible_api_inventory,
)
from .retrieval import (
    _build_call_references,
    _build_include_inventory,
    _build_project_header_context,
    _collect_project_headers,
    _infer_external_contracts,
    _project_idioms,
    _rank_context,
    _surface_items_from_source,
    trim_source_for_context,
)
from .support import MAX_PROJECT_HEADERS, MAX_SOURCE_SURFACE_ITEMS

def collect_related_code_context(
    *,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    context_root: Optional[str],
    target_code_context: dict,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    repair_objective = repair_objective or {}
    language = source_language_from_path(source_path)
    root = source_root(source_path, context_root)
    source_label = relpath(source_path, root)
    target_unit = (
        (target_code_context.get("target_envelope") or {}).get("replacement_unit")
        or func_code
        or ""
    )
    symbols = extract_symbols_from_code(target_unit, language)
    symbol_set = {
        str(item)
        for key in ("calls", "types", "fields", "identifiers", "macro_like")
        for item in (symbols.get(key) or [])
        if item
    }

    headers, unresolved_headers = _collect_project_headers(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
    )
    include_inventory = _build_include_inventory(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        headers=headers,
        unresolved=unresolved_headers,
    )
    source_excerpt = trim_source_for_context(source_code, start_idx, end_idx)
    source_api_surface = _surface_items_from_source(
        source=source_code,
        language=language,
        source_label=source_label,
        symbols=symbol_set,
        target_start=start_idx,
        target_end=end_idx,
        max_items=MAX_SOURCE_SURFACE_ITEMS,
    )
    same_file_helpers = [
        item for item in source_api_surface
        if str(item.get("kind") or "").startswith("function_definition:")
    ]
    same_file_declarations = [
        item for item in source_api_surface
        if not str(item.get("kind") or "").startswith("function_definition:")
    ]
    header_context = _build_project_header_context(headers, symbol_set)
    usage_examples = _build_call_references(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        call_names=set(symbols.get("calls") or []),
        start_idx=start_idx,
        end_idx=end_idx,
    )
    target_references = _build_call_references(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        call_names={func_name} if func_name else set(),
        start_idx=start_idx,
        end_idx=end_idx,
    )
    external_contracts = _infer_external_contracts(
        target_code=target_unit,
        same_file_helpers=same_file_helpers,
        usage_examples=usage_examples,
        target_references=target_references,
    )
    symbol_inventory = _available_symbol_inventory(
        target_symbols=symbols,
        same_file_helpers=same_file_helpers,
        same_file_declarations=same_file_declarations,
        header_context=header_context,
        usage_examples=usage_examples,
    )
    member_field_inventory = _member_field_inventory(
        source_code=source_code,
        source_label=source_label,
        language=language,
        target_start=start_idx,
        target_func_name=func_name,
        headers=headers,
    )
    constructor_initializer_whitelist = _constructor_initializer_whitelist(
        target_unit=target_unit,
        target_func_name=func_name,
        member_field_inventory=member_field_inventory,
    )
    visible_api_inventory = _visible_api_inventory(
        target_symbols=symbols,
        symbol_inventory=symbol_inventory,
        same_file_helpers=same_file_helpers,
        same_file_declarations=same_file_declarations,
        header_context=header_context,
        usage_examples=usage_examples,
        member_field_inventory=member_field_inventory,
        constructor_initializer_whitelist=constructor_initializer_whitelist,
    )
    contract_engine = _api_macro_type_contract_engine(
        source_code=source_code,
        source_label=source_label,
        language=language,
        headers=headers,
        target_unit=target_unit,
        target_symbols=symbols,
        usage_examples=usage_examples,
        target_references=target_references,
        member_field_inventory=member_field_inventory,
        constructor_initializer_whitelist=constructor_initializer_whitelist,
    )
    visible_api_inventory = _augment_visible_api_inventory(
        visible_api_inventory,
        contract_engine,
    )
    scope_aware_symbol_contract = _scope_aware_symbol_contract(
        target_unit=target_unit,
        target_symbols=symbols,
        visible_api_inventory=visible_api_inventory,
        contract_engine=contract_engine,
        member_field_inventory=member_field_inventory,
    )
    contract_brief = dict(contract_engine.get("contract_brief") or {})
    contract_brief["introducible_functions"] = scope_aware_symbol_contract.get("introducible_functions") or []
    contract_brief["introducible_macros_or_enum_constants"] = (
        scope_aware_symbol_contract.get("introducible_macros_or_enum_constants") or []
    )
    contract_brief["introducible_types"] = scope_aware_symbol_contract.get("introducible_types") or []
    contract_brief["scope_policy"] = scope_aware_symbol_contract.get("symbol_introduction_policy") or []
    project_idioms = _project_idioms(
        source_api_surface=source_api_surface,
        header_context=header_context,
        usage_examples=usage_examples,
    )
    ranked_context = _rank_context(
        same_file_helpers=same_file_helpers,
        same_file_declarations=same_file_declarations,
        header_context=header_context,
        usage_examples=usage_examples,
        target_references=target_references,
        external_contracts=external_contracts,
        contract_engine=contract_engine,
    )
    uncertainties = []
    if include_inventory["unresolved_project_includes"]:
        uncertainties.append(
            "some project includes could not be resolved: "
            + ", ".join(include_inventory["unresolved_project_includes"])
        )
    if len(headers) >= MAX_PROJECT_HEADERS:
        uncertainties.append(f"project header traversal stopped at {MAX_PROJECT_HEADERS} headers")

    return {
        "analysis_engine": {
            "name": "related_api_macro_type_contract_engine",
            "version": 4,
            "parser": parser_diagnostics(language),
            "strategy": "tree_sitter_surface_cross_reference_plus_api_macro_type_contract_inventory",
            "capabilities": [
                "resolved_project_header_traversal",
                "api_signature_inventory",
                "macro_and_enum_group_inventory",
                "bitmask_flag_contracts",
                "type_and_member_contracts",
                "scope_aware_symbol_introduction_contracts",
                "cross_file_usage_mining",
            ],
        },
        "related_code_map": {
            "target_source_excerpt": source_excerpt,
            "include_inventory": include_inventory,
            "same_file_helpers": same_file_helpers,
            "same_file_declarations": same_file_declarations,
            "header_context": header_context,
            "cross_file_usage_examples": usage_examples,
            "caller_context": target_references,
        },
        "visible_api_inventory": visible_api_inventory,
        "scope_aware_symbol_contract": scope_aware_symbol_contract,
        "api_contract_inventory": contract_engine.get("api_contract_inventory") or {},
        "macro_contract_inventory": contract_engine.get("macro_contract_inventory") or {},
        "type_contract_inventory": contract_engine.get("type_contract_inventory") or {},
        "contract_brief": contract_brief,
        "member_field_inventory": member_field_inventory,
        "constructor_initializer_whitelist": constructor_initializer_whitelist,
        "external_behavioral_contracts": external_contracts,
        "project_idioms": project_idioms,
        "ranked_context": ranked_context,
        "uncertainties": uncertainties,
    }

def run_related_code_context_agent(
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
    context_root: Optional[str],
    target_code_context: dict,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Tuple[dict, dict]:
    context = collect_related_code_context(
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        source_code=source_code,
        source_path=source_path,
        start_idx=start_idx,
        end_idx=end_idx,
        context_root=context_root,
        target_code_context=target_code_context,
        repair_objective=repair_objective,
    )
    artifact = write_related_code_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        related_code_context=context,
    )
    return context, artifact
