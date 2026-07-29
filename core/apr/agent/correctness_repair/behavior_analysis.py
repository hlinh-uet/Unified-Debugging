"""Bounded syntax anchors enriched only by compiler-resolved semantics."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Set, Tuple

from core.program_analysis.clang_provider import resolve_target_semantics
from .models import clip, stable_id


FACT_GROUPS = {
    "target_method": "target_operations",
    "target_call": "target_operations",
    "target_assignment": "program_slice",
    "target_update": "program_slice",
    "target_return": "program_slice",
    "target_control": "program_slice",
    "symbol_usage": "variable_flows",
}


def analyze_target_behavior(
    *,
    target_contract: Dict[str, Any],
    source_root: str,
    target_inventory: Dict[str, Any] = None,
    compilation_context: Dict[str, Any] = None,
    limit: int = 31,
) -> Tuple[Dict[str, Any], List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Collect bounded syntax facts and compiler semantic deltas without Joern."""
    inventory = target_inventory or {}
    entities = [
        item for item in inventory.get("entities") or [] if isinstance(item, dict)
    ]
    structural_available = (
        str(inventory.get("binding") or "") == "tree_sitter_query_target_syntax_ir"
        and bool((inventory.get("syntax_ir") or {}).get("records"))
    )
    syntax_view = _budgeted_syntax_view(inventory, limit=limit)
    syntax_view["available"] = structural_available
    selected_entity_ids = set(syntax_view.get("entity_ids") or [])
    semantic = resolve_target_semantics(
        source_root=source_root,
        target_contract=target_contract,
        syntax_ir=inventory.get("syntax_ir") or {},
        compilation_context=compilation_context or {},
    )
    indexed_facts = _source_local_inventory_facts(
        target_contract=target_contract,
        target_inventory=inventory,
        call_resolutions=semantic.get("calls") or {},
        variable_resolutions=semantic.get("variables") or {},
    )
    indexed_facts = _unique_facts(indexed_facts)
    view_facts = [
        fact for fact in indexed_facts
        if str(fact.get("subject_entity_id") or "") in selected_entity_ids
    ]
    groups: Dict[str, List[str]] = {
        "target_operations": [],
        "program_slice": [],
        "variable_flows": [],
        "callee_contracts": [],
    }
    for fact in view_facts:
        group = FACT_GROUPS.get(str(fact.get("kind") or ""))
        if group:
            groups[group].append(str(fact["id"]))
    diagnostics = [
        *(inventory.get("diagnostics") or []),
        *(semantic.get("diagnostics") or []),
    ]
    engine = {
        "name": "tree_sitter_syntax_clang_semantics",
        "provider": "tree_sitter+clang",
        "available": structural_available,
        "semantic_resolution": (
            "compiler_frontend" if semantic.get("available") else "syntax_only_degraded"
        ),
    }
    analysis = _build_behavior_context(
        target_contract=target_contract,
        target_inventory=inventory,
        facts=view_facts,
    )
    analysis.update({
        "provider": "tree_sitter+clang",
        "program_slice": syntax_view,
        "fact_groups": groups,
        "fact_count": len(view_facts),
        "indexed_fact_count": len(indexed_facts),
        "evidence_index_policy": "full_target_index_budgeted_llm_view",
        "evidence_index_count": len(analysis.get("evidence_index") or {}),
        "scope": "exact_target_observable_effect_program_slice",
        "selection": "tree_sitter_query_syntax_plus_compiler_semantic_deltas",
        "syntax_ir": inventory.get("syntax_ir") or {},
        "semantic_context": semantic,
        "unresolved_relations": list(dict.fromkeys(str(item) for item in diagnostics if str(item))),
    })
    record = {
        "round": 1,
        "stage": "target_behavior_analysis",
        "status": (
            "degraded" if view_facts and (
                not structural_available or not semantic.get("available")
            )
            else "evidence_returned" if view_facts and groups["target_operations"]
            else "empty"
        ),
        "tool": "tree_sitter_syntax_clang_semantics",
        "engine": engine,
        "slice_engine": engine,
        "semantic_engine": {
            "provider": semantic.get("provider"),
            "available": bool(semantic.get("available")),
            "resolution": semantic.get("semantic_resolution"),
            "command_status": semantic.get("command_status"),
        },
        "slice_raw_node_count": len(entities),
        "slice_retained_node_count": len(selected_entity_ids),
        "raw_result_count": len(entities),
        "source_backed_fact_count": len(view_facts),
        "indexed_source_backed_fact_count": len(indexed_facts),
        "fallback_policy": "none",
        "joern_invoked": False,
        "diagnostics": list(dict.fromkeys(str(item) for item in diagnostics if str(item))),
    }
    return analysis, indexed_facts, record, list(dict.fromkeys(
        str(item) for item in diagnostics if str(item)
    ))


def _budgeted_syntax_view(
    target_inventory: Dict[str, Any], *, limit: int = 31
) -> Dict[str, Any]:
    """Build a bounded LLM view while retaining every record in SyntaxIR."""
    records = [
        item for item in ((target_inventory.get("syntax_ir") or {}).get("records") or [])
        if isinstance(item, dict) and item.get("id")
    ]
    view_limit = max(8, min(int(limit or 31), 64))
    buckets: Dict[str, List[Dict[str, Any]]] = {}
    for record in records:
        buckets.setdefault(str(record.get("kind") or "unknown"), []).append(record)
    nonempty_kinds = sorted(buckets)
    allocations = {kind: 0 for kind in nonempty_kinds}
    # Give every syntax kind a chance to appear, then distribute the remaining
    # budget proportionally. This avoids both kind deletion and source-prefix bias.
    for kind in nonempty_kinds[:view_limit]:
        allocations[kind] = 1
    remaining = max(0, view_limit - sum(allocations.values()))
    while remaining:
        candidates = [
            kind for kind in nonempty_kinds
            if allocations[kind] < len(buckets[kind])
        ]
        if not candidates:
            break
        kind = max(
            candidates,
            key=lambda value: (
                len(buckets[value]) / float(allocations[value] + 1),
                len(buckets[value]),
                value,
            ),
        )
        allocations[kind] += 1
        remaining -= 1
    selected = []
    for kind in nonempty_kinds:
        selected.extend(_evenly_spaced_records(buckets[kind], allocations[kind]))
    selected.sort(key=lambda item: (
        int((item.get("source_range") or {}).get("start_byte") or 0),
        str(item.get("kind") or ""),
    ))
    target_entity = next((
        item for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("kind") == "target_function"
    ), {})
    entity_ids = [str(target_entity.get("id") or "")] if target_entity else []
    entity_ids.extend(str(item["id"]) for item in selected)
    source_lines = sorted({
        int((item.get("source_range") or {}).get("start_line") or 0)
        for item in selected
        if int((item.get("source_range") or {}).get("start_line") or 0) > 0
    })
    symbols = sorted({
        str(value) for item in selected
        for value in item.get("declared_names") or [] if str(value)
    })
    calls = sorted({
        str(item.get("callee_text") or "")
        for item in selected if item.get("kind") == "call" and str(item.get("callee_text") or "")
    })
    return {
        "provider": "tree_sitter_query",
        "criterion": "budgeted_balanced_target_syntax_view",
        "direction": "none_syntax_only",
        "retrieval_scope": "full_target_syntax_ir",
        "indexed_node_count": len(records) + (1 if target_entity else 0),
        "view_node_count": len(entity_ids),
        "excluded_from_view_count": max(0, len(records) - len(selected)),
        "view_limit": view_limit,
        "kind_counts": {kind: len(values) for kind, values in sorted(buckets.items())},
        "view_kind_counts": {
            kind: allocations[kind] for kind in nonempty_kinds if allocations[kind]
        },
        "retained_node_count": len(entity_ids),
        "entity_ids": entity_ids,
        "source_lines": source_lines,
        "symbols": symbols,
        "call_symbols": calls,
        "dependency_edges": [],
    }


def _evenly_spaced_records(
    records: List[Dict[str, Any]], count: int
) -> List[Dict[str, Any]]:
    """Sample a kind across the whole target instead of taking its prefix."""
    if count <= 0 or not records:
        return []
    if count >= len(records):
        return list(records)
    indices = []
    for index in range(count):
        candidate = min(
            len(records) - 1,
            int((index + 0.5) * len(records) / count),
        )
        if candidate not in indices:
            indices.append(candidate)
    return [records[index] for index in indices]


def _source_local_inventory_facts(
    *,
    target_contract: Dict[str, Any],
    target_inventory: Dict[str, Any],
    selected_entity_ids: Set[str] = None,
    call_resolutions: Dict[str, Dict[str, Any]] = None,
    variable_resolutions: Dict[str, Dict[str, Any]] = None,
) -> List[Dict[str, Any]]:
    """Index source-backed facts, optionally restricting them to a view."""
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
        "return": "target_return",
        "branch": "target_control",
        "conditional": "target_control",
        "declaration": "symbol_usage",
        "parameter": "symbol_usage",
    }
    facts: List[Dict[str, Any]] = []
    call_resolutions = call_resolutions or {}
    variable_resolutions = variable_resolutions or {}
    for entity in target_inventory.get("entities") or []:
        if not isinstance(entity, dict):
            continue
        if selected_entity_ids is not None and str(entity.get("id") or "") not in selected_entity_ids:
            continue
        entity_kind = str(entity.get("kind") or "")
        fact_kind = kind_map.get(entity_kind)
        if not fact_kind:
            continue
        symbols = [str(item) for item in entity.get("symbols") or [] if str(item)]
        fact_symbols = _entity_fact_symbols(
            entity, fact_kind=fact_kind, target_leaf=resolved_leaf
        )
        for symbol in fact_symbols or [""]:
            resolution = call_resolutions.get(str(entity.get("id") or "")) or {}
            variable_resolution = variable_resolutions.get(str(entity.get("id") or "")) or {}
            details = {
                "provider": "tree_sitter_target_inventory",
                "subject_entity_id": entity.get("id"),
                "node_type": entity.get("node_type"),
                "write_target": entity.get("write_target") or "",
                "value_expression": entity.get("value_expression") or "",
                "arguments": list(entity.get("arguments") or []),
                "control_context": list(entity.get("control_context") or []),
                "dependency_paths": [],
                "full_name": (
                    target_contract.get("resolved_name") if fact_kind == "target_method" else ""
                ),
                "signature": (
                    target_contract.get("signature") if fact_kind == "target_method"
                    else entity.get("source_excerpt") if fact_kind == "symbol_usage"
                    else ""
                ),
                "declared_type": entity.get("declared_type") or "",
                "resolution_status": (
                    resolution.get("status") or variable_resolution.get("status") or ""
                ),
                "semantic_symbol_id": (
                    resolution.get("symbol_id") or variable_resolution.get("symbol_id") or ""
                ),
                "canonical_type": variable_resolution.get("canonical_type") or "",
            }
            if fact_kind == "target_call":
                details.update({
                    "full_name": resolution.get("resolved_name") or "",
                    "signature": resolution.get("signature") or "",
                    "result_type": resolution.get("result_type") or "",
                    "definition": resolution.get("definition") or {},
                })
            elif fact_kind == "symbol_usage" and variable_resolution:
                details["declared_type"] = variable_resolution.get("type") or ""
            fact = {
                "id": stable_id("ast_evidence", {
                    "entity_id": entity.get("id"),
                    "kind": fact_kind,
                    "symbol": symbol,
                }),
                "kind": fact_kind,
                "subject_entity_id": entity.get("id"),
                "symbol": symbol,
                "symbols": symbols,
                "source_file": target_file,
                "source_path": target_path,
                "source_range": dict(entity.get("source_range") or {}),
                "source_excerpt": str(entity.get("source_excerpt") or ""),
                "semantic_summary": str(entity.get("source_excerpt") or ""),
                "semantic_details": details,
                "evidence_domain": "static_program_semantics",
                "epistemic_status": "static_source_fact",
                "runtime_observed": False,
                "interpretation_limit": (
                    "Syntax is Tree-sitter-backed; types and call identities are included only "
                    "when compiler-resolved; nothing is runtime-observed."
                ),
            }
            facts.append(fact)
    return _unique_facts(facts)


def _entity_fact_symbols(
    entity: Dict[str, Any], *, fact_kind: str, target_leaf: str
) -> List[str]:
    """Choose labels without inferring def-use or data-flow from syntax tokens."""
    if fact_kind == "target_method":
        return [target_leaf] if target_leaf else [""]
    if fact_kind == "target_call":
        callee = _call_entity_symbol(entity)
        return [callee] if callee else [""]
    if fact_kind == "target_control":
        return [""]
    if fact_kind == "target_return":
        return [target_leaf] if target_leaf else [""]
    if fact_kind in {"target_assignment", "target_update"}:
        write_target = str(entity.get("write_target") or "").strip()
        if write_target:
            return [write_target]
        return [next((str(value) for value in entity.get("symbols") or [] if str(value)), "")]
    declared = [str(value) for value in entity.get("declared_names") or [] if str(value)]
    if not declared:
        declared = [str(value) for value in entity.get("declared_symbols") or [] if str(value)]
    return declared or [""]


def _call_entity_symbol(entity: Dict[str, Any]) -> str:
    if str(entity.get("callee_symbol") or ""):
        return str(entity["callee_symbol"])
    return next((str(value) for value in entity.get("symbols") or [] if str(value)), "")


def _ranges_overlap(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    left_start = _range_offset(left, "start_byte")
    left_end = _range_offset(left, "end_byte")
    right_start = _range_offset(right, "start_byte")
    right_end = _range_offset(right, "end_byte")
    return left_start >= 0 and right_start >= 0 and left_start < right_end and right_start < left_end


def _source_ranges_overlap(left: Dict[str, Any], right: Dict[str, Any]) -> bool:
    """Compare source anchors even when Joern lacks exact byte offsets."""
    if _ranges_overlap(left, right):
        return True
    try:
        left_start = int(left.get("start_line") or 0)
        left_end = int(left.get("end_line") or left_start)
        right_start = int(right.get("start_line") or 0)
        right_end = int(right.get("end_line") or right_start)
    except (TypeError, ValueError):
        return False
    return (
        left_start > 0 and right_start > 0
        and left_start <= right_end and right_start <= left_end
    )


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
                "evidence_domain": fact.get("evidence_domain") or "static_program_semantics",
                "epistemic_status": fact.get("epistemic_status") or "static_source_fact",
                "runtime_observed": bool(fact.get("runtime_observed")),
                "interpretation_limit": fact.get("interpretation_limit"),
            })
        expansions.append({
            "need_id": need_id,
            "hypothesis_id": need.get("hypothesis_id"),
            "relation": need.get("relation"),
            "question": need.get("question"),
            "evidence_requirement": need.get("evidence_requirement"),
            "answerable_by": need.get("answerable_by"),
            "status": need.get("status"),
            "answer_scope": need.get("answer_scope"),
            "answer_evidence_ids": need.get("answer_evidence_ids") or [],
            "static_support_evidence_ids": need.get("static_support_evidence_ids") or [],
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

    effects = []
    for kind in (
        "target_assignment", "target_update", "target_return", "target_control"
    ):
        for fact in by_kind.get(kind, []):
            details = fact.get("semantic_details") or {}
            effects.append({
                "evidence_id": fact.get("id"),
                "subject_entity_id": fact.get("subject_entity_id"),
                "kind": kind,
                "symbol": fact.get("symbol"),
                "source_ref": ref(fact),
                "expression": fact.get("semantic_summary"),
                "control_context": details.get("control_context") or [],
                "dataflow": details.get("dependency_paths") or [],
                "epistemic_status": "static_possible_effect",
                "runtime_observed": False,
            })

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
            "epistemic_status": "static_function_contract",
            "runtime_observed": False,
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
            if _ranges_overlap(entity.get("source_range") or {}, fact.get("source_range") or {})
            and (
                symbol in set(str(value) for value in entity.get("symbols") or [])
                or symbol == str(entity.get("callee_symbol") or "")
            )
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
            "signature": details.get("signature") or "",
            "result_type": details.get("result_type") or "",
            "semantic_symbol_id": details.get("semantic_symbol_id") or "",
            "definition": details.get("definition") or {},
            "callsite_ref": ref(fact),
            "arguments": arguments,
            "argument_mapping": argument_mapping,
            "control_context": details.get("control_context") or [],
            "dataflow": details.get("dependency_paths") or [],
            "callee_contract_ids": list(dict.fromkeys(contract_ids)),
            "status": (
                "resolved" if contract_ids or details.get("resolution_status") == "compiler_resolved"
                else str(details.get("resolution_status") or "callee_contract_unresolved")
            ),
            "execution_status": "not_runtime_observed",
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
            str(
                (item.get("semantic_details") or {}).get("canonical_type")
                or (item.get("semantic_details") or {}).get("declared_type")
                or (item.get("semantic_details") or {}).get("signature")
                or ""
            )
            for item in symbol_declaration_facts
            if str(
                (item.get("semantic_details") or {}).get("canonical_type")
                or (item.get("semantic_details") or {}).get("declared_type")
                or (item.get("semantic_details") or {}).get("signature")
                or ""
            )
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
                    "epistemic_status": "static_assignment_site",
                    "runtime_observed": False,
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
        "evidence_semantics": {
            "domain": "static_program_semantics",
            "runtime_observed": False,
            "supports": [
                "source definitions and contracts",
                "possible control-flow and data-flow relations",
                "source-level argument expressions and assignment sites",
            ],
            "does_not_support": [
                "branch taken in the failing execution",
                "concrete runtime value in the failing execution",
                "callee return observed in the failing execution",
            ],
            "runtime_observation_sources": [
                "failure_contract.failure_observation",
                "tested_repairs validation outcomes",
            ],
        },
        "target": target,
        "source_regions": regions,
        "variables": variables,
        "calls": calls,
        "effects": effects,
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
        "evidence_domain": fact.get("evidence_domain") or "static_program_semantics",
        "epistemic_status": fact.get("epistemic_status") or "static_source_fact",
        "runtime_observed": bool(fact.get("runtime_observed")),
    }
