"""Compact source-bound Joern projection for one exact target method."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from core.apr.program_analysis.service import query_cpg_tool

from .evidence_broker import source_back_cpg_results
from .models import clip, stable_id


FACT_GROUPS = {
    "target_method": "target_operations",
    "target_call": "target_operations",
    "target_assignment": "target_operations",
    "target_update": "target_operations",
    "symbol_usage": "variable_flows",
    "callee_definition": "callee_contracts",
}


def analyze_target_behavior(
    *,
    target_contract: Dict[str, Any],
    source_root: str,
    target_inventory: Dict[str, Any] = None,
    limit: int = 256,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Collect call and source-variable contracts without an LLM query planner."""
    result = query_cpg_tool(
        source_root=source_root,
        source_path=str(target_contract.get("source_path") or ""),
        function_name=str(
            target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
        ),
        function_signature=str(target_contract.get("signature") or ""),
        function_start_line=int((target_contract.get("source_range") or {}).get("start_line") or 1),
        tool="get_target_behavior_analysis",
        symbols=[],
        kinds=[],
        region_ids=[],
        region_spans=[],
        limit=max(1, min(int(limit), 256)),
        allow_source_scan_fallback=False,
    )
    facts, source_errors = source_back_cpg_results(
        result.get("results") or [], source_root=source_root, query_round=1
    )
    facts = _select_initial_projection_facts(
        facts, target_inventory=target_inventory or {}
    )
    joern_has_target_operations = any(
        str(fact.get("kind") or "") in {
            "target_method", "target_call", "target_assignment", "target_update"
        }
        for fact in facts
    )
    fallback_used = not facts or not joern_has_target_operations
    if fallback_used:
        facts = _unique_facts([
            *facts,
            *_source_local_inventory_facts(
                target_contract=target_contract,
                target_inventory=target_inventory or {},
            ),
        ])
    groups: Dict[str, List[str]] = {
        "target_operations": [],
        "variable_flows": [],
        "callee_contracts": [],
    }
    for fact in facts:
        group = FACT_GROUPS.get(str(fact.get("kind") or ""))
        if group:
            groups[group].append(str(fact["id"]))
    engine = result.get("engine") if isinstance(result.get("engine"), dict) else {}
    diagnostics = [
        *(result.get("uncertainties") or []),
        *source_errors,
    ]
    warnings = list(dict.fromkeys(
        str(item) for item in (result.get("uncertainties") or []) if str(item)
    ))
    if not engine.get("available"):
        warnings.append("joern_behavior_analysis_backend_unavailable")
    if not joern_has_target_operations:
        warnings.append("joern_behavior_analysis_target_operations_missing")
    if fallback_used:
        warnings.append("behavior_analysis_source_local_fallback")
    truncation = next(
        (str(item) for item in diagnostics if str(item).startswith("joern_target_behavior_truncated:")),
        "",
    )
    if truncation:
        warnings.append(truncation)
    analysis = _build_behavior_context(
        target_contract=target_contract,
        target_inventory=target_inventory or {},
        facts=facts,
    )
    analysis.update({
        "provider": "joern+tree_sitter" if fallback_used else "joern",
        "fact_groups": groups,
        "fact_count": len(facts),
        "evidence_index_count": len(analysis.get("evidence_index") or {}),
        "scope": "exact_target_call_and_source_variable_contract_projection",
        "selection": (
            "exact_target_ast_source_projection"
            if fallback_used else "source_bound_compact_cpg_projection"
        ),
        "unresolved_relations": list(dict.fromkeys(str(item) for item in diagnostics if str(item))),
    })
    record = {
        "round": 1,
        "stage": "target_behavior_analysis",
        "status": (
            "source_fallback" if fallback_used and facts and groups["target_operations"]
            else "incomplete" if truncation
            else "evidence_returned" if facts and groups["target_operations"]
            else "empty"
        ),
        "tool": "get_target_behavior_analysis",
        "engine": engine,
        "raw_result_count": int(result.get("raw_result_count") or len(result.get("results") or [])),
        "source_backed_fact_count": len(facts),
        "fallback_policy": "exact_target_ast_source" if fallback_used else "none",
        "diagnostics": list(dict.fromkeys(str(item) for item in diagnostics if str(item))),
    }
    return analysis, facts, record, list(dict.fromkeys(
        str(item) for item in warnings if str(item)
    ))


def _source_local_inventory_facts(
    *, target_contract: Dict[str, Any], target_inventory: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Project exact Tree-sitter entities into source-backed fallback facts."""
    target_path = str(target_contract.get("source_path") or "")
    target_file = str(target_contract.get("source_file") or "")
    resolved_leaf = str(
        target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
    ).rsplit("::", 1)[-1]
    kind_map = {
        "target_function": "target_method",
        "call": "target_call",
        "assignment": "target_assignment",
        "update": "target_update",
        "declaration": "symbol_usage",
        "parameter": "symbol_usage",
    }
    facts: List[Dict[str, Any]] = []
    for entity in target_inventory.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        entity_kind = str(entity.get("kind") or "")
        fact_kind = kind_map.get(entity_kind)
        if not fact_kind:
            continue
        declared = [str(item) for item in entity.get("declared_symbols") or [] if str(item)]
        symbols = [str(item) for item in entity.get("symbols") or [] if str(item)]
        fact_symbols = declared or symbols[:1] or ([resolved_leaf] if resolved_leaf else [])
        for symbol in fact_symbols or [""]:
            details = {
                "provider": "tree_sitter_source_fallback",
                "node_type": entity.get("node_type"),
                "arguments": [],
                "control_context": [],
                "dependency_paths": [],
                "full_name": (
                    target_contract.get("resolved_name") if fact_kind == "target_method" else ""
                ),
                "signature": (
                    target_contract.get("signature") if fact_kind == "target_method" else ""
                ),
            }
            fact = {
                "id": stable_id("ast_evidence", {
                    "entity_id": entity.get("id"),
                    "kind": fact_kind,
                    "symbol": symbol,
                }),
                "kind": fact_kind,
                "symbol": symbol,
                "symbols": symbols,
                "source_file": target_file,
                "source_path": target_path,
                "source_range": dict(entity.get("source_range") or {}),
                "source_excerpt": str(entity.get("source_excerpt") or ""),
                "semantic_summary": str(entity.get("source_excerpt") or ""),
                "semantic_details": details,
            }
            facts.append(fact)
    return _unique_facts(facts)


def _select_initial_projection_facts(
    facts: List[Dict[str, Any]], *, target_inventory: Dict[str, Any]
) -> List[Dict[str, Any]]:
    """Keep source-level declarations and compact call/write contracts only."""
    declaration_entities = [
        item for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("kind") in {"declaration", "parameter"}
    ]
    declared_symbols = {
        str(symbol)
        for entity in declaration_entities
        for symbol in entity.get("declared_symbols") or []
        if str(symbol)
    }
    always = {"target_method", "target_call", "callee_definition"}
    selected = []
    for fact in facts:
        kind = str(fact.get("kind") or "")
        if kind in always:
            selected.append(fact)
            continue
        if kind in {"target_assignment", "target_update"}:
            if str(fact.get("symbol") or "") in declared_symbols:
                selected.append(fact)
            continue
        if kind != "symbol_usage":
            continue
        symbol = str(fact.get("symbol") or "")
        fact_range = fact.get("source_range") or {}
        if symbol and any(
            symbol in set(str(value) for value in entity.get("declared_symbols") or [])
            and _ranges_overlap(fact_range, entity.get("source_range") or {})
            for entity in declaration_entities
        ):
            selected.append(fact)
    return _unique_facts(selected)


def _ranges_overlap(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    left_start = _range_offset(left, "start_byte")
    left_end = _range_offset(left, "end_byte")
    right_start = _range_offset(right, "start_byte")
    right_end = _range_offset(right, "end_byte")
    return left_start >= 0 and right_start >= 0 and left_start < right_end and right_start < left_end


def _range_offset(source_range: Dict[str, Any], key: str) -> int:
    value = source_range.get(key)
    if value is None:
        return -1
    try:
        return int(value)
    except (TypeError, ValueError):
        return -1


def _unique_facts(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for item in values:
        marker = str(item.get("id") or "")
        if not marker or marker in seen:
            continue
        seen.add(marker)
        out.append(item)
    return out


def merge_expansion_context(
    context: Dict[str, Any],
    *,
    facts: List[Dict[str, Any]],
    information_needs: List[Dict[str, Any]],
) -> Dict[str, Any]:
    """Add follow-up facts through source-region references, never copied excerpts."""
    evidence_index = context.setdefault("evidence_index", {})
    known_evidence_ids = set(str(item) for item in evidence_index)
    regions = context.setdefault("source_regions", [])
    region_by_key = {
        _region_key(item.get("source_file"), item.get("source_range")): str(item.get("id"))
        for item in regions
        if isinstance(item, dict) and item.get("id")
    }
    facts_by_id = {str(item.get("id")): item for item in facts if item.get("id")}
    expansions = context.setdefault("expansions", [])
    existing_need_ids = {str(item.get("need_id")) for item in expansions if isinstance(item, dict)}
    for need in information_needs or []:
        need_id = str(need.get("id") or "")
        if not need_id or need_id in existing_need_ids:
            continue
        evidence = []
        for evidence_id in need.get("evidence_ids") or []:
            fact = facts_by_id.get(str(evidence_id))
            if not fact:
                continue
            source_ref = _source_ref(
                fact,
                target=context.get("target") or {},
                regions=regions,
                region_by_key=region_by_key,
            )
            evidence_index[str(evidence_id)] = _evidence_index_entry(fact, source_ref)
            evidence.append({
                "evidence_id": evidence_id,
                "kind": fact.get("kind"),
                "symbol": fact.get("symbol"),
                "source_ref": source_ref,
                "semantic_summary": clip(fact.get("semantic_summary"), 500),
                "semantic_details": fact.get("semantic_details") or {},
            })
        expansions.append({
            "need_id": need_id,
            "hypothesis_id": need.get("hypothesis_id"),
            "relation": need.get("relation"),
            "question": need.get("question"),
            "status": need.get("status"),
            "evidence": evidence,
        })
        existing_need_ids.add(need_id)
    added = len(set(str(item) for item in evidence_index) - known_evidence_ids)
    context["fact_count"] = int(context.get("fact_count") or 0) + added
    context["evidence_index_count"] = len(evidence_index)
    return context


def _build_behavior_context(
    *, target_contract: Dict[str, Any], target_inventory: Dict[str, Any], facts: List[Dict[str, Any]]
) -> Dict[str, Any]:
    target = {
        "target_id": target_contract.get("target_id"),
        "resolved_name": target_contract.get("resolved_name"),
        "signature": target_contract.get("signature"),
        "source_path": target_contract.get("source_path"),
        "source_range": target_contract.get("source_range"),
        "source_hash": target_contract.get("source_hash"),
        "source": target_contract.get("replacement_unit"),
    }
    regions: List[Dict[str, Any]] = []
    region_by_key: Dict[Tuple[str, int, int], str] = {}
    evidence_index: Dict[str, Dict[str, Any]] = {}

    def ref(fact: Dict[str, Any]) -> Dict[str, Any]:
        source_ref = _source_ref(
            fact, target=target, regions=regions, region_by_key=region_by_key
        )
        evidence_index[str(fact["id"])] = _evidence_index_entry(fact, source_ref)
        return source_ref

    by_kind: Dict[str, List[Dict[str, Any]]] = {}
    for fact in facts:
        by_kind.setdefault(str(fact.get("kind") or ""), []).append(fact)

    callee_contracts = []
    contract_ids_by_full_name: Dict[str, List[str]] = {}
    contract_ids_by_callsite_full_name: Dict[str, List[str]] = {}
    for fact in by_kind.get("callee_definition", []):
        details = fact.get("semantic_details") or {}
        dependencies = details.get("dependency_paths") or []
        contract_id = stable_id("callee_contract", {
            "evidence": fact.get("id"),
            "full_name": details.get("full_name"),
        })
        parameters = [
            {"name": item.get("symbol"), "declaration": item.get("code"), "line": item.get("line")}
            for item in dependencies
            if item.get("kind") == "parameter"
        ]
        returns = [
            {
                "line": item.get("line"),
                "expression": item.get("code"),
                "control_context": item.get("control_context") or [],
            }
            for item in dependencies
            if item.get("kind") == "callee_return"
        ]
        assignments = [
            {
                "line": item.get("line"),
                "symbol": item.get("symbol"),
                "assignment": item.get("code"),
                "control_context": item.get("control_context") or [],
            }
            for item in dependencies
            if item.get("kind") == "callee_assignment"
        ]
        callee_contracts.append({
            "id": contract_id,
            "evidence_id": fact.get("id"),
            "symbol": fact.get("symbol"),
            "full_name": details.get("full_name"),
            "signature": details.get("signature"),
            "definition_ref": ref(fact),
            "parameters": parameters,
            "returns": returns,
            "assignments": assignments,
            "side_effect_analysis": "not_classified_beyond_source_backed_assignments",
        })
        full_name = str(details.get("full_name") or "")
        if full_name:
            contract_ids_by_full_name.setdefault(full_name, []).append(contract_id)
        callsite_full_name = str(details.get("callsite_method_full_name") or "")
        if callsite_full_name:
            contract_ids_by_callsite_full_name.setdefault(callsite_full_name, []).append(contract_id)

    contracts_by_id = {str(item["id"]): item for item in callee_contracts}
    call_entities = [
        item for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("kind") == "call"
    ]
    calls = []
    for fact in by_kind.get("target_call", []):
        details = fact.get("semantic_details") or {}
        full_name = str(details.get("full_name") or "")
        symbol = str(fact.get("symbol") or "")
        contract_ids = (
            contract_ids_by_callsite_full_name.get(full_name)
            or contract_ids_by_full_name.get(full_name)
            or []
        )
        arguments = list(details.get("arguments") or [])
        subject_entity = next((
            entity for entity in call_entities
            if symbol in set(str(value) for value in entity.get("symbols") or [])
            and _ranges_overlap(entity.get("source_range") or {}, fact.get("source_range") or {})
        ), {})
        argument_mapping = []
        for contract_id in list(dict.fromkeys(contract_ids)):
            parameters = (contracts_by_id.get(str(contract_id)) or {}).get("parameters") or []
            argument_mapping.extend({
                "callee_contract_id": contract_id,
                "argument_index": index,
                "argument": argument,
                "parameter": parameters[index].get("declaration") if index < len(parameters) else None,
            } for index, argument in enumerate(arguments))
        calls.append({
            "id": stable_id("call", fact.get("id")),
            "subject_entity_id": subject_entity.get("id"),
            "evidence_id": fact.get("id"),
            "symbol": symbol,
            "resolved_full_name": full_name,
            "callsite_ref": ref(fact),
            "arguments": arguments,
            "argument_mapping": argument_mapping,
            "control_context": details.get("control_context") or [],
            "dataflow": details.get("dependency_paths") or [],
            "callee_contract_ids": list(dict.fromkeys(contract_ids)),
            "status": "resolved" if contract_ids else "callee_contract_unresolved",
        })

    target_assignments = by_kind.get("target_assignment", [])
    target_updates = by_kind.get("target_update", [])
    declaration_facts = by_kind.get("symbol_usage", [])
    declaration_entities = [
        item for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("kind") in {"declaration", "parameter"}
    ]
    variable_symbols = list(dict.fromkeys(
        str(fact.get("symbol") or "")
        for fact in declaration_facts
        if str(fact.get("symbol") or "")
    ))
    variables = []
    for symbol in variable_symbols:
        symbol_declaration_facts = [
            item for item in declaration_facts
            if str(item.get("symbol") or "") == symbol
        ]
        matching_entities = [
            entity for entity in declaration_entities
            if symbol in set(str(value) for value in entity.get("declared_symbols") or [])
            and any(
                _ranges_overlap(entity.get("source_range") or {}, fact.get("source_range") or {})
                for fact in symbol_declaration_facts
            )
        ]
        matching_entities = _canonical_declaration_entities(matching_entities)
        writes = [
            item for item in [*target_assignments, *target_updates]
            if str(item.get("symbol") or "") == symbol
        ]
        call_uses = [
            item for item in by_kind.get("target_call", [])
            if _fact_mentions_symbol(item, symbol)
        ]
        type_name = next((
            str((item.get("semantic_details") or {}).get("signature") or "")
            for item in symbol_declaration_facts
            if str((item.get("semantic_details") or {}).get("signature") or "")
        ), "")
        declaration_records = [
            {
                "entity_id": entity.get("id"),
                "kind": entity.get("kind"),
                "source_range": entity.get("source_range") or {},
                "source": entity.get("source_excerpt"),
                "symbols": entity.get("symbols") or [],
            }
            for entity in matching_entities
        ]
        variables.append({
            "symbol": symbol,
            "subject_entity_id": matching_entities[0].get("id") if matching_entities else None,
            "type": type_name,
            "origin": (
                "parameter" if any(item.get("kind") == "parameter" for item in matching_entities)
                else "local"
            ),
            "declarations": declaration_records,
            "declaration_evidence_ids": [
                item.get("id") for item in symbol_declaration_facts
            ],
            "writes": [
                {
                    "evidence_id": item.get("id"),
                    "source_ref": ref(item),
                    "expression": item.get("semantic_summary"),
                    "control_context": (item.get("semantic_details") or {}).get("control_context") or [],
                }
                for item in writes
            ],
            "call_uses": [
                {
                    "evidence_id": item.get("id"),
                    "call": item.get("semantic_summary"),
                    "source_ref": ref(item),
                }
                for item in call_uses
            ],
            "related_source_symbols": list(dict.fromkeys(
                str(value)
                for entity in matching_entities
                for value in entity.get("symbols") or []
                if str(value) and str(value) != symbol
            ))[:16],
            "status": "source_bound",
        })

    return {
        "version": 2,
        "target": target,
        "source_regions": regions,
        "variables": variables,
        "calls": calls,
        "callee_contracts": callee_contracts,
        "expansions": [],
        "evidence_index": evidence_index,
    }


def _source_ref(
    fact: Dict[str, Any],
    *,
    target: Dict[str, Any],
    regions: List[Dict[str, Any]],
    region_by_key: Dict[Tuple[str, int, int], str],
) -> Dict[str, Any]:
    fact_range = fact.get("source_range") or {}
    target_range = target.get("source_range") or {}
    fact_path = os.path.realpath(str(fact.get("source_path") or ""))
    target_path = os.path.realpath(str(target.get("source_path") or ""))
    start_byte = int(fact_range.get("start_byte") or 0)
    end_byte = int(fact_range.get("end_byte") or 0)
    target_start = int(target_range.get("start_byte") or 0)
    target_end = int(target_range.get("end_byte") or 0)
    if (
        fact_path
        and fact_path == target_path
        and target_end > target_start
        and start_byte >= target_start
        and end_byte <= target_end
    ):
        return {"scope": "target", "source_range": fact_range}
    key = _region_key(fact.get("source_file"), fact_range)
    region_id = region_by_key.get(key)
    if not region_id:
        region_id = stable_id("source_region", key)
        regions.append({
            "id": region_id,
            "source_file": fact.get("source_file"),
            "source_range": fact_range,
            "source": fact.get("source_excerpt"),
        })
        region_by_key[key] = region_id
    return {"scope": "related", "region_id": region_id}


def _region_key(source_file: Any, source_range: Any) -> Tuple[str, int, int]:
    source_range = source_range if isinstance(source_range, dict) else {}
    return (
        str(source_file or ""),
        int(source_range.get("start_byte") or 0),
        int(source_range.get("end_byte") or 0),
    )


def _fact_mentions_symbol(fact: Dict[str, Any], symbol: str) -> bool:
    values = set(str(value) for value in fact.get("symbols") or [] if str(value))
    values.add(str(fact.get("symbol") or ""))
    return bool(symbol) and symbol in values


def _canonical_declaration_entities(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    parameters = [item for item in values if item.get("kind") == "parameter"]
    if parameters:
        return parameters[:1]
    declarations = [item for item in values if item.get("node_type") == "declaration"]
    if declarations:
        return declarations[:1]
    return values[:1]


def _evidence_index_entry(fact: Dict[str, Any], source_ref: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "kind": fact.get("kind"),
        "symbol": fact.get("symbol"),
        "source_ref": source_ref,
    }
