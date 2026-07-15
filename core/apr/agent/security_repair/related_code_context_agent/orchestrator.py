from typing import Any, Dict, Optional, Tuple

from core.apr.artifacts import write_related_code_context_artifact
from core.apr.common import (
    extract_symbols_from_code,
    parser_diagnostics,
    relpath,
    source_language_from_path,
    source_root,
)
from core.apr.program_analysis import analyze_target_operations

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
    replacement_target: Optional[dict] = None,
    repair_objective: Optional[Dict[str, Any]] = None,
) -> Dict[str, Any]:
    repair_objective = repair_objective or {}
    language = source_language_from_path(source_path)
    root = source_root(source_path, context_root)
    source_label = relpath(source_path, root)
    replacement_context = replacement_target or {}
    target_unit = (
        (replacement_context.get("replacement_envelope") or {}).get("replacement_unit")
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
    semantic_vocabulary = _semantic_vocabulary_from_contracts(
        contract_engine=contract_engine,
        scope_aware_symbol_contract=scope_aware_symbol_contract,
        member_field_inventory=member_field_inventory,
    )
    operation_analysis = analyze_target_operations(
        func_code=target_unit,
        replacement_target=replacement_context,
        related_code_context={
            "source_root": root,
            "scope_aware_symbol_contract": scope_aware_symbol_contract,
            "semantic_vocabulary": semantic_vocabulary,
        },
        source_path=source_path,
        source_root=root,
        function_name=func_name,
        language=language,
    )
    target_operation_context = _target_operation_context(operation_analysis)
    ranked_context = _rank_context(
        same_file_helpers=same_file_helpers,
        same_file_declarations=same_file_declarations,
        header_context=header_context,
        usage_examples=usage_examples,
        target_references=target_references,
        external_contracts=external_contracts,
        contract_engine=contract_engine,
        target_operations=target_operation_context.get("operations") or [],
    )
    uncertainties = []
    if include_inventory["unresolved_project_includes"]:
        uncertainties.append(
            "some project includes could not be resolved: "
            + ", ".join(include_inventory["unresolved_project_includes"])
        )
    if len(headers) >= MAX_PROJECT_HEADERS:
        uncertainties.append(f"project header traversal stopped at {MAX_PROJECT_HEADERS} headers")
    uncertainties.extend(
        f"program_analysis:{item}"
        for item in (operation_analysis.uncertainties or [])[:6]
    )

    return {
        "analysis_engine": {
            "name": "related_api_macro_type_contract_engine",
            "version": 5,
            "parser": parser_diagnostics(language),
            "strategy": "shared_program_analysis_plus_api_macro_type_contract_inventory",
            "capabilities": [
                "shared_program_analysis_target_operations",
                "resolved_project_header_traversal",
                "api_signature_inventory",
                "macro_and_enum_group_inventory",
                "bitmask_flag_contracts",
                "type_and_member_contracts",
                "scope_aware_symbol_introduction_contracts",
                "cross_file_usage_mining",
            ],
            "program_analysis_engine": operation_analysis.engine or {},
        },
        "source_root": root,
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
        "semantic_vocabulary": semantic_vocabulary,
        "program_analysis_context": target_operation_context,
        "member_field_inventory": member_field_inventory,
        "constructor_initializer_whitelist": constructor_initializer_whitelist,
        "external_behavioral_contracts": external_contracts,
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
    replacement_target: Optional[dict] = None,
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
        replacement_target=replacement_target,
        repair_objective=repair_objective,
    )
    artifact = write_related_code_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        related_code_context=context,
        step_name="security_related_code_context_agent",
    )
    return context, artifact


def _semantic_vocabulary_from_contracts(
    *,
    contract_engine: Dict[str, Any],
    scope_aware_symbol_contract: Dict[str, Any],
    member_field_inventory: list,
) -> Dict[str, list]:
    api_inventory = (contract_engine or {}).get("api_contract_inventory") or {}
    macro_inventory = (contract_engine or {}).get("macro_contract_inventory") or {}
    type_inventory = (contract_engine or {}).get("type_contract_inventory") or {}
    return {
        "helpers": [
            {"name": sig.get("name"), "source": sig.get("source")}
            for sig in (api_inventory.get("function_signatures") or [])[:80]
            if sig.get("name")
        ],
        "macros": [
            {"name": macro.get("name"), "source": macro.get("source")}
            for macro in (macro_inventory.get("macro_definitions") or [])[:100]
            if macro.get("name")
        ],
        "enum_or_flags": _semantic_enum_or_flag_groups(macro_inventory),
        "types": [
            {"name": item.get("name") or item.get("alias"), "source": item.get("source")}
            for item in (type_inventory.get("type_definitions") or [])[:80]
            if item.get("name") or item.get("alias")
        ],
        "fields": _semantic_field_items(member_field_inventory),
        "scope_names": [
            {"name": name, "source": "scope_aware_symbol_contract"}
            for name in _first(
                _scope_symbol_names(scope_aware_symbol_contract),
                220,
            )
        ],
    }


def _semantic_enum_or_flag_groups(macro_inventory: Dict[str, Any]) -> list:
    groups = []
    for group in (macro_inventory.get("enum_constant_groups") or [])[:60]:
        name = group.get("name") or group.get("source")
        constants = [str(item) for item in (group.get("constants") or []) if item]
        if constants:
            groups.append({"name": name, "constants": constants[:40], "source": group.get("source")})
    for group in (macro_inventory.get("bitmask_flag_groups") or [])[:60]:
        name = group.get("name") or group.get("expression")
        constants = [str(item) for item in (group.get("allowed_constants") or []) if item]
        if constants:
            groups.append({"name": name, "allowed_constants": constants[:40], "source": group.get("source")})
    return groups[:100]


def _semantic_field_items(member_field_inventory: list) -> list:
    fields = []
    for entry in member_field_inventory or []:
        for field in entry.get("fields") or []:
            fields.append(
                {
                    "name": field,
                    "type": entry.get("class"),
                    "source": entry.get("source"),
                    "relation": entry.get("relation"),
                }
            )
    return fields[:160]


def _scope_symbol_names(scope_aware_symbol_contract: Dict[str, Any]) -> list:
    names = []
    for key in (
        "existing_calls",
        "existing_macros_or_enum_constants",
        "existing_types",
        "existing_member_fields",
        "visible_functions",
        "visible_macros_or_enum_constants",
        "visible_types",
        "visible_member_fields",
        "introducible_functions",
        "introducible_macros_or_enum_constants",
        "introducible_types",
    ):
        names.extend(str(item) for item in (scope_aware_symbol_contract.get(key) or []) if item)
    out = []
    seen = set()
    for name in names:
        if name in seen:
            continue
        seen.add(name)
        out.append(name)
    return out


def _target_operation_context(operation_analysis) -> Dict[str, Any]:
    return {
        "engine": operation_analysis.engine or {},
        "operations": [
            # `roles` is intentionally stripped here: downstream security agents
            # (repair_constraints, fix_agent) must not read or prioritise by role.
            # Ranking uses kind, semantic_symbols, control_ancestors, and code summary only.
            _compact_operation(item)
            for item in (operation_analysis.operations or [])[:40]
            if isinstance(item, dict)
        ],
        "uncertainties": list(operation_analysis.uncertainties or [])[:8],
    }


def _compact_operation(operation: Dict[str, Any]) -> Dict[str, Any]:
    """Compact a raw program-analysis operation for security context output.

    Fields included: id, kind, method, call_name, line, line_end, code,
    symbols (calls/types/fields/identifiers/macro_like), control_ancestors,
    semantic_symbols, dependency_paths, provider.

    Fields intentionally EXCLUDED:
    - ``roles``: Joern provenance roles (target_method, caller_method, etc.) are
      stripped here so that no downstream security agent can display or prioritise
      operations by role. Ranking is based solely on kind, semantic_symbols,
      control_ancestors, and code summary.
    """
    symbols = operation.get("symbols") if isinstance(operation.get("symbols"), dict) else {}
    return {
        "id": operation.get("id"),
        "kind": operation.get("kind"),
        "method": operation.get("method"),
        "call_name": operation.get("call_name"),
        "line": operation.get("line"),
        "line_end": operation.get("line_end"),
        "code": _clip(operation.get("code"), 900),
        "symbols": {
            "calls": _first(symbols.get("calls"), 12),
            "types": _first(symbols.get("types"), 8),
            "fields": _first(symbols.get("fields"), 12),
            "identifiers": _first(symbols.get("identifiers"), 16),
            "macro_like": _first(symbols.get("macro_like"), 12),
        },
        "control_ancestors": [
            {
                "kind": item.get("kind"),
                "line": item.get("line"),
                "code": _clip(item.get("code"), 260),
            }
            for item in _first(operation.get("control_ancestors"), 5)
            if isinstance(item, dict)
        ],
        "semantic_symbols": _first(operation.get("semantic_symbols"), 16),
        "dependency_paths": _first(operation.get("dependency_paths"), 4),
        "provider": operation.get("provider"),
        # "roles" is intentionally absent — see docstring above.
    }


def _first(value, limit: int) -> list:
    if not value:
        return []
    return list(value)[:limit]


def _clip(value, limit: int) -> str:
    text = str(value or "")
    return text[:limit] + ("...<truncated>" if len(text) > limit else "")
