"""Execute optional hypothesis-driven Joern expansions and source-back results."""

from __future__ import annotations

import os
import re
from typing import Any, Dict, Iterable, List, Tuple

from core.program_analysis.service import query_cpg_tools
from core.program_analysis.clang_provider import retrieve_semantic_evidence

from .semantic_queries import (
    RUNTIME_EVIDENCE_REQUIREMENT,
    STATIC_EVIDENCE_REQUIREMENT,
    information_need_evidence_requirement,
    normalize_information_needs,
)
from .models import clip, stable_id, unique_dicts


RELATION_FACT_KINDS = {
    "ALIAS_OR_REFERENCE_FLOW": {"assignment", "control_data_dependency", "symbol_usage"},
    "ALTERNATE_PATH_STATE": {"target_region", "control_data_dependency"},
    "BRANCH_REACHABILITY": {"target_region", "control_data_dependency"},
    "CALLEE_CONTRACT": {"callee_definition", "callee_candidate"},
    "CALL_ARGUMENT_MAPPING": {"call_argument_flow"},
    "CALL_RESULT_CONTRACT": {"callee_definition", "callee_candidate", "call_argument_flow"},
    "CALLER_BRANCH_ON_RESULT": {"caller_context"},
    "CALLER_RESULT_USE": {"caller_context"},
    "CONTROLLING_PREDICATES": {"target_region", "control_data_dependency"},
    "CONVERSION_OPERATORS": {"type_definition", "method_definition"},
    "EARLY_RETURN_CONDITIONS": {"target_region", "control_data_dependency"},
    "ENUM_OR_SENTINEL_VALUES": {"type_definition", "method_definition"},
    "ERROR_PROPAGATION": {"caller_context", "callee_definition", "call_argument_flow"},
    "FIELD_READ_WRITE": {"assignment", "control_data_dependency", "symbol_usage"},
    "OVERLOAD_SET": {"method_definition", "callee_definition", "callee_candidate"},
    "PARALLEL_ERROR_HANDLING": {"symbol_usage", "method_definition"},
    "REACHING_DEFINITIONS": {"assignment", "control_data_dependency", "symbol_usage"},
    "RETURN_VALUE_FLOW": {"caller_context", "control_data_dependency"},
    "SAME_TYPE_OPERATION": {"symbol_usage", "type_definition", "method_definition"},
    "SIBLING_BRANCH": {"symbol_usage", "method_definition"},
    "SIBLING_IMPLEMENTATION": {"symbol_usage", "method_definition", "callee_definition"},
    "STATE_TRANSITIONS": {"assignment", "control_data_dependency", "symbol_usage"},
    "TEMPLATE_SPECIALIZATION": {"type_definition", "method_definition"},
    "TYPE_DEFINITION": {"type_definition", "method_definition"},
    "VALUE_USES": {"control_data_dependency", "symbol_usage"},
}


def execute_behavior_queries(
    *,
    information_needs: Iterable[Dict[str, Any]],
    target_contract: Dict[str, Any],
    target_inventory: Dict[str, Any],
    source_root: str,
    round_index: int,
    semantic_context: Dict[str, Any] = None,
    compilation_context: Dict[str, Any] = None,
    limit: int = 48,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Use budgeted compiler retrieval first, then Joern for unresolved needs."""
    needs, validation_errors = _validate_needs(
        information_needs,
        target_inventory=target_inventory,
    )
    if not needs:
        return [], [], {
            "round": round_index,
            "status": "no_valid_queries",
            "engine": {},
        }, validation_errors or ["behavior_query_round_has_no_valid_needs"]

    runtime_needs = [
        need for need in needs
        if _need_evidence_requirement(need) == RUNTIME_EVIDENCE_REQUIREMENT
    ]
    static_needs = [
        need for need in needs
        if _need_evidence_requirement(need) == STATIC_EVIDENCE_REQUIREMENT
    ]
    runtime_updates = [
        {
            **need,
            "status": "requires_runtime_evidence",
            "answer_scope": "runtime_observation_missing",
            "evidence_ids": [],
            "answer_evidence_ids": [],
            "static_support_evidence_ids": [],
            "semantic_match_count": 0,
        }
        for need in runtime_needs
    ]
    runtime_errors = [
        f"behavior_information_need_requires_runtime_evidence:{need['id']}"
        for need in runtime_needs
    ]
    if not static_needs:
        return runtime_updates, [], {
            "round": round_index,
            "status": "runtime_evidence_required",
            "tool": "get_behavior_evidence",
            "evidence_domain": STATIC_EVIDENCE_REQUIREMENT,
            "queried_need_ids": [],
            "skipped_runtime_need_ids": [need["id"] for need in runtime_needs],
            "engine": {},
            "raw_result_count": 0,
            "source_mapped_fact_count": 0,
            "source_backed_fact_count": 0,
            "linked_fact_count": 0,
            "need_results": [_runtime_need_result(need) for need in runtime_needs],
            "fallback_policy": "none",
        }, list(dict.fromkeys([*validation_errors, *runtime_errors]))

    semantic_facts, semantic_record, semantic_errors = retrieve_semantic_evidence(
        source_root=source_root,
        target_contract=target_contract,
        syntax_ir=target_inventory.get("syntax_ir") or {},
        semantic_context=semantic_context or {},
        information_needs=static_needs,
        compilation_context=compilation_context or {},
        round_index=round_index,
    )
    semantic_linked, semantic_updates, _ = _link_evidence_to_needs(
        semantic_facts,
        needs=static_needs,
        target_contract=target_contract,
    )
    answered_semantic_ids = {
        str(item.get("id") or "")
        for item in semantic_updates
        if item.get("status") == "answered"
    }
    unresolved_static_needs = [
        need for need in static_needs
        if str(need.get("id") or "") not in answered_semantic_ids
    ]
    if not unresolved_static_needs:
        combined_updates = [*semantic_updates, *runtime_updates]
        return combined_updates, semantic_linked, {
            "round": round_index,
            "status": (
                "static_evidence_returned_runtime_evidence_required"
                if runtime_needs else "evidence_returned"
            ),
            "tool": "get_behavior_evidence",
            "evidence_domain": STATIC_EVIDENCE_REQUIREMENT,
            "queried_need_ids": [item["id"] for item in static_needs],
            "skipped_runtime_need_ids": [item["id"] for item in runtime_needs],
            "engine": {"provider": "clang_budgeted_semantic_retrieval", "available": True},
            "semantic_retrieval": semantic_record,
            "raw_result_count": 0,
            "source_mapped_fact_count": len(semantic_facts),
            "source_backed_fact_count": len(semantic_linked),
            "linked_fact_count": len(semantic_linked),
            "need_results": [
                _semantic_need_result(item, semantic_record)
                for item in semantic_updates
            ] + [_runtime_need_result(need) for need in runtime_needs],
            "fallback_policy": "compiler_first_joern_for_unresolved_only",
        }, list(dict.fromkeys([
            *validation_errors, *runtime_errors, *semantic_errors,
        ]))

    per_need_limit = max(8, min(int(limit or 48), 24))
    common = {
        "source_root": source_root,
        "source_path": str(target_contract.get("source_path") or ""),
        "function_name": str(
            target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
        ),
        "function_signature": str(target_contract.get("signature") or ""),
        "function_start_line": int(
            (target_contract.get("source_range") or {}).get("start_line") or 1
        ),
        "tool": "get_behavior_evidence",
        "query": "",
        "allow_source_scan_fallback": False,
    }
    requests = [
        {
            **common,
            "symbols": list(need.get("symbols") or [])[:8],
            "kinds": [str(need["relation"])],
            "region_ids": [str(need["id"])],
            "region_spans": [_need_span(need)],
            "limit": per_need_limit,
            "reason": str(need.get("question") or ""),
        }
        for need in unresolved_static_needs
    ]
    results = query_cpg_tools(requests)
    linked_by_id: Dict[str, Dict[str, Any]] = {
        str(item["id"]): dict(item) for item in semantic_linked if item.get("id")
    }
    mapped_by_id: Dict[str, Dict[str, Any]] = {
        str(item["id"]): dict(item) for item in semantic_facts if item.get("id")
    }
    updated_needs = [
        item for item in semantic_updates if str(item.get("id") or "") in answered_semantic_ids
    ]
    need_results = [
        _semantic_need_result(item, semantic_record)
        for item in semantic_updates if str(item.get("id") or "") in answered_semantic_ids
    ]
    errors = [*validation_errors, *runtime_errors]
    engine = {}
    raw_result_markers = set()
    for need, result in zip(unresolved_static_needs, results):
        result = result if isinstance(result, dict) else {}
        if not engine and isinstance(result.get("engine"), dict):
            engine = dict(result["engine"])
        raw_results = result.get("results") or []
        raw_count = len(raw_results)
        for item in raw_results:
            if not isinstance(item, dict):
                continue
            raw_result_markers.add((
                str(item.get("kind") or ""),
                str(item.get("source") or item.get("file") or item.get("filename") or ""),
                str(item.get("line") or item.get("lineNumber") or ""),
                str(item.get("line_end") or item.get("lineEnd") or ""),
                str(item.get("symbol") or item.get("call_name") or ""),
                str(item.get("code") or ""),
            ))
        facts, mapping_errors = source_back_cpg_results(
            raw_results, source_root=source_root, query_round=round_index
        )
        for fact in facts:
            if fact.get("id"):
                mapped_by_id[str(fact["id"])] = fact
        linked, need_updates, link_errors = _link_evidence_to_needs(
            facts,
            needs=[need],
            target_contract=target_contract,
        )
        for fact in linked:
            fact_id = str(fact.get("id") or "")
            if not fact_id:
                continue
            existing = linked_by_id.setdefault(fact_id, dict(fact))
            for key in ("need_ids", "relations", "hypothesis_ids"):
                existing[key] = list(dict.fromkeys([
                    *(existing.get(key) or []), *(fact.get(key) or [])
                ]))
        updated = need_updates[0] if need_updates else {**need, "status": "unresolved", "evidence_ids": []}
        updated_needs.append(updated)
        uncertainties = list(result.get("uncertainties") or [])
        errors.extend(uncertainties)
        errors.extend(mapping_errors)
        errors.extend(link_errors)
        need_results.append({
            "need_id": need.get("id"),
            "relation": need.get("relation"),
            "symbols": need.get("symbols") or [],
            "evidence_requirement": _need_evidence_requirement(need),
            "status": updated.get("status"),
            "raw_result_count": raw_count,
            "source_mapped_fact_count": len(facts),
            "linked_fact_count": len(linked),
            "semantic_match_count": int(updated.get("semantic_match_count") or 0),
            "answer_evidence_count": len(updated.get("answer_evidence_ids") or []),
            "mapping_diagnostics": list(dict.fromkeys(mapping_errors))[:12],
            "link_diagnostics": list(dict.fromkeys(link_errors))[:12],
            "query_diagnostics": list(dict.fromkeys(uncertainties))[:12],
        })
    need_results.extend(_runtime_need_result(need) for need in runtime_needs)
    updated_by_id = {
        str(item.get("id")): item for item in [*updated_needs, *runtime_updates]
        if item.get("id")
    }
    updated_needs = [
        updated_by_id[str(need["id"])]
        for need in needs
        if str(need.get("id") or "") in updated_by_id
    ]
    linked_facts = list(linked_by_id.values())
    if unresolved_static_needs and not engine.get("available"):
        errors.append("joern_behavior_query_backend_unavailable")
    if not mapped_by_id:
        errors.append(f"joern_behavior_query_round_has_no_source_mapped_evidence:{round_index}")
        errors.extend(semantic_errors)
    elif not linked_facts:
        errors.append(f"joern_behavior_query_round_has_no_linked_evidence:{round_index}")
    answered_count = sum(item.get("status") == "answered" for item in updated_needs)
    if answered_count == len(updated_needs):
        query_status = "evidence_returned"
    elif runtime_needs and answered_count == len(static_needs):
        query_status = "static_evidence_returned_runtime_evidence_required"
    elif linked_facts:
        query_status = "partial"
    elif mapped_by_id:
        query_status = "unlinked"
    else:
        query_status = "empty"
    query_record = {
        "round": round_index,
        "status": query_status,
        "tool": "get_behavior_evidence",
        "evidence_domain": STATIC_EVIDENCE_REQUIREMENT,
        "relations": list(dict.fromkeys(str(need["relation"]) for need in static_needs)),
        "symbols": list(dict.fromkeys(
            str(symbol) for need in static_needs for symbol in need.get("symbols") or [] if str(symbol)
        ))[:24],
        "need_ids": [item["id"] for item in needs],
        "queried_need_ids": [item["id"] for item in static_needs],
        "skipped_runtime_need_ids": [item["id"] for item in runtime_needs],
        "engine": engine,
        "semantic_retrieval": semantic_record,
        "semantic_retrieval_diagnostics": semantic_errors[:12],
        "raw_result_count": len(raw_result_markers),
        "source_mapped_fact_count": len(mapped_by_id),
        "source_backed_fact_count": len(linked_facts),
        "linked_fact_count": len(linked_facts),
        "need_results": need_results,
        "fallback_policy": "compiler_first_joern_for_unresolved_only",
    }
    return updated_needs, linked_facts, query_record, list(dict.fromkeys(
        str(item) for item in errors if str(item)
    ))


def _runtime_need_result(need: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "need_id": need["id"],
        "relation": need.get("relation"),
        "symbols": need.get("symbols") or [],
        "evidence_requirement": RUNTIME_EVIDENCE_REQUIREMENT,
        "status": "requires_runtime_evidence",
        "answer_scope": "runtime_observation_missing",
        "raw_result_count": 0,
        "source_mapped_fact_count": 0,
        "linked_fact_count": 0,
        "semantic_match_count": 0,
        "answer_evidence_count": 0,
        "mapping_diagnostics": [],
        "link_diagnostics": [
            f"behavior_information_need_requires_runtime_evidence:{need['id']}"
        ],
        "query_diagnostics": [],
    }


def _semantic_need_result(
    need: Dict[str, Any], retrieval_record: Dict[str, Any]
) -> Dict[str, Any]:
    return {
        "need_id": need.get("id"),
        "relation": need.get("relation"),
        "symbols": need.get("symbols") or [],
        "evidence_requirement": _need_evidence_requirement(need),
        "status": need.get("status"),
        "raw_result_count": 0,
        "source_mapped_fact_count": len(need.get("evidence_ids") or []),
        "linked_fact_count": len(need.get("evidence_ids") or []),
        "semantic_match_count": int(need.get("semantic_match_count") or 0),
        "answer_evidence_count": len(need.get("answer_evidence_ids") or []),
        "mapping_diagnostics": [],
        "link_diagnostics": [],
        "query_diagnostics": [],
        "provider": retrieval_record.get("provider"),
    }


def merge_information_needs(
    existing: Iterable[Dict[str, Any]], updates: Iterable[Dict[str, Any]]
) -> List[Dict[str, Any]]:
    by_id = {
        str(item.get("id")): dict(item)
        for item in existing or []
        if isinstance(item, dict) and item.get("id")
    }
    order = list(by_id)
    for item in updates or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        item_id = str(item["id"])
        if item_id not in by_id:
            order.append(item_id)
        by_id[item_id] = {**by_id.get(item_id, {}), **item}
    return [by_id[item_id] for item_id in order]


def _validate_needs(
    needs: Iterable[Dict[str, Any]], *, target_inventory: Dict[str, Any]
) -> Tuple[List[Dict[str, Any]], List[str]]:
    raw_needs = list(needs or [])
    normalized, error = normalize_information_needs(
        raw_needs,
        target_inventory=target_inventory,
        max_needs=max(1, len(raw_needs)),
    )
    return normalized, [item for item in str(error or "").split(";") if item]


def _link_evidence_to_needs(
    facts: List[Dict[str, Any]],
    *,
    needs: List[Dict[str, Any]],
    target_contract: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], List[str]]:
    target_leaf = str(
        target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
    ).rsplit("::", 1)[-1]
    linked_by_id: Dict[str, Dict[str, Any]] = {}
    updated_needs = []
    errors = []
    for need in needs:
        evidence_requirement = _need_evidence_requirement(need)
        allowed_kinds = RELATION_FACT_KINDS.get(str(need.get("relation") or ""), set())
        wanted = {
            alias
            for item in need.get("symbols") or []
            for alias in _symbol_aliases(item)
        }
        matches = []
        for fact in facts:
            if str(fact.get("kind") or "") not in allowed_kinds:
                continue
            fact_symbols = {
                alias
                for item in fact.get("symbols") or []
                for alias in _symbol_aliases(item)
            }
            if fact.get("symbol"):
                fact_symbols.update(_symbol_aliases(fact["symbol"]))
            details = fact.get("semantic_details") or {}
            fact_symbols.update(_symbol_aliases(details.get("full_name")))
            if need.get("relation") in {
                "CALLER_RESULT_USE", "CALLER_BRANCH_ON_RESULT", "RETURN_VALUE_FLOW", "ERROR_PROPAGATION"
            }:
                fact_symbols.update(_symbol_aliases(target_leaf))
            if wanted and not wanted.intersection(fact_symbols):
                continue
            matches.append(fact)
        semantic_matches = (
            [] if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT
            else [
                fact for fact in matches if _fact_semantically_satisfies_need(fact, need)
            ]
        )
        answered = (
            evidence_requirement == STATIC_EVIDENCE_REQUIREMENT
            and _semantic_matches_answer_need(semantic_matches, need)
        )
        evidence_ids = []
        for fact in matches:
            fact_id = str(fact["id"])
            linked = linked_by_id.setdefault(
                fact_id,
                {**fact, "need_ids": [], "relations": [], "hypothesis_ids": []},
            )
            if need["id"] not in linked["need_ids"]:
                linked["need_ids"].append(need["id"])
            if need["relation"] not in linked["relations"]:
                linked["relations"].append(need["relation"])
            hypothesis_id = str(need.get("hypothesis_id") or "")
            if hypothesis_id and hypothesis_id not in linked["hypothesis_ids"]:
                linked["hypothesis_ids"].append(hypothesis_id)
            evidence_ids.append(fact_id)
        updated = {
            **need,
            "evidence_requirement": evidence_requirement,
            "answerable_by": (
                "runtime_instrumentation_or_trace"
                if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT
                else "compiler_semantics_or_static_cpg"
            ),
            "status": (
                "requires_runtime_evidence"
                if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT
                else "answered" if answered
                else "partial" if evidence_ids
                else "unresolved"
            ),
            "answer_scope": (
                "runtime_observation_missing"
                if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT
                else "static_semantics_answer"
                if answered
                else "static_semantics_partial"
                if evidence_ids
                else "no_static_evidence"
            ),
            "evidence_ids": evidence_ids,
            "answer_evidence_ids": [str(fact["id"]) for fact in semantic_matches] if answered else [],
            "static_support_evidence_ids": (
                evidence_ids if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT else []
            ),
            "semantic_match_count": len(semantic_matches),
        }
        updated_needs.append(updated)
        if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT:
            errors.append(f"behavior_information_need_requires_runtime_evidence:{need['id']}")
        elif not evidence_ids:
            errors.append(f"behavior_information_need_unresolved:{need['id']}")
        elif not answered:
            errors.append(f"behavior_information_need_partial:{need['id']}")
    return list(linked_by_id.values()), updated_needs, errors


def _fact_semantically_satisfies_need(
    fact: Dict[str, Any], need: Dict[str, Any]
) -> bool:
    relation = str(need.get("relation") or "").upper()
    kind = str(fact.get("kind") or "")
    details = fact.get("semantic_details") or {}
    dependencies = [
        item for item in details.get("dependency_paths") or [] if isinstance(item, dict)
    ]
    dependency_kinds = {
        str(item.get("kind") or "").lower() for item in dependencies
    }
    text = " ".join([
        str(fact.get("source_excerpt") or ""),
        str(fact.get("semantic_summary") or ""),
        str(details.get("full_name") or ""),
        str(details.get("signature") or ""),
        *(str(item.get("code") or "") for item in dependencies),
    ]).lower()
    has_control = bool(details.get("control_context")) or any(
        item.get("control_context") for item in dependencies
    ) or bool(re.search(r"\b(if|else|switch|case|while|for)\b", text))
    has_dataflow = any(
        token in dep_kind
        for dep_kind in dependency_kinds
        for token in ("reaching", "dataflow", "argument", "assignment", "call_result")
    )

    if _need_evidence_requirement(need) == RUNTIME_EVIDENCE_REQUIREMENT:
        return False
    if relation == "CALLEE_CONTRACT":
        return kind == "callee_definition"
    if relation == "CALL_ARGUMENT_MAPPING":
        return kind == "call_argument_flow"
    if relation == "CALL_RESULT_CONTRACT":
        return kind == "callee_definition" and any("callee_return" in value for value in dependency_kinds)
    if relation == "CALLER_RESULT_USE":
        return kind == "caller_context" and any("call_result" in value for value in dependency_kinds)
    if relation == "CALLER_BRANCH_ON_RESULT":
        return kind == "caller_context" and has_control and any("call_result" in value for value in dependency_kinds)
    if relation == "RETURN_VALUE_FLOW":
        return kind in {"caller_context", "control_data_dependency"} and has_dataflow
    if relation == "ERROR_PROPAGATION":
        return bool(re.search(r"\b(err|error|fail|invalid|return|null|false)\b", text)) and (
            has_dataflow or has_control
        )
    if relation == "REACHING_DEFINITIONS":
        return kind == "assignment" or has_dataflow
    if relation == "VALUE_USES":
        return kind in {"symbol_usage", "control_data_dependency"}
    if relation == "FIELD_READ_WRITE":
        return kind == "assignment" or bool(re.search(r"(?:->|\.|\[).*(?:=|\+\+|--)", text))
    if relation == "STATE_TRANSITIONS":
        return kind == "assignment" or (has_dataflow and bool(re.search(r"(?:=|\+\+|--)", text)))
    if relation == "ALIAS_OR_REFERENCE_FLOW":
        return kind == "assignment" or has_dataflow
    if relation in {"CONTROLLING_PREDICATES", "BRANCH_REACHABILITY"}:
        return kind in {"target_region", "control_data_dependency"} and has_control
    if relation == "EARLY_RETURN_CONDITIONS":
        return has_control and "return" in text
    if relation == "ALTERNATE_PATH_STATE":
        return has_control and (kind == "target_region" or has_dataflow)
    if relation == "TYPE_DEFINITION":
        return kind == "type_definition"
    if relation == "ENUM_OR_SENTINEL_VALUES":
        return kind == "type_definition" and bool(re.search(
            r"\b(enum|define|constexpr|const|sentinel)\b|\b[A-Z][A-Z0-9_]{2,}\b",
            " ".join([
                str(fact.get("source_excerpt") or ""),
                str(fact.get("semantic_summary") or ""),
                str(details.get("full_name") or ""),
            ]),
        ))
    if relation == "OVERLOAD_SET":
        return kind in {"method_definition", "callee_definition", "callee_candidate"}
    if relation == "TEMPLATE_SPECIALIZATION":
        return kind in {"type_definition", "method_definition"} and "<" in text and ">" in text
    if relation == "CONVERSION_OPERATORS":
        return kind == "method_definition" and "operator" in text
    if relation == "SIBLING_IMPLEMENTATION":
        return kind == "method_definition" and any("sibling_callsite" in value for value in dependency_kinds)
    if relation == "SIBLING_BRANCH":
        return kind in {"symbol_usage", "method_definition"} and has_control
    if relation == "SAME_TYPE_OPERATION":
        return kind in {"type_definition", "method_definition"}
    if relation == "PARALLEL_ERROR_HANDLING":
        return kind in {"symbol_usage", "method_definition"} and has_control and bool(
            re.search(r"\b(err|error|fail|invalid|return|null|false)\b", text)
        )
    return False


def _semantic_matches_answer_need(
    facts: List[Dict[str, Any]], need: Dict[str, Any]
) -> bool:
    if not facts:
        return False
    relation = str(need.get("relation") or "").upper()
    if relation == "OVERLOAD_SET":
        identities = {
            "|".join([
                str((fact.get("semantic_details") or {}).get("full_name") or fact.get("symbol") or ""),
                str((fact.get("semantic_details") or {}).get("signature") or ""),
            ])
            for fact in facts
        }
        if len({value for value in identities if value}) < 2:
            return False
    covered = set().union(*(_fact_symbol_aliases(fact) for fact in facts))
    requested_groups = [
        _symbol_aliases(value) for value in need.get("symbols") or [] if str(value)
    ]
    return all(group.intersection(covered) for group in requested_groups)


def _fact_symbol_aliases(fact: Dict[str, Any]) -> set:
    details = fact.get("semantic_details") or {}
    values = [
        *(fact.get("symbols") or []),
        fact.get("symbol"),
        details.get("full_name"),
        details.get("callsite_method_full_name"),
    ]
    return {
        alias for value in values if value for alias in _symbol_aliases(value)
    }


def _need_evidence_requirement(need: Dict[str, Any]) -> str:
    explicit = str(need.get("evidence_requirement") or "")
    if explicit in {STATIC_EVIDENCE_REQUIREMENT, RUNTIME_EVIDENCE_REQUIREMENT}:
        return explicit
    return information_need_evidence_requirement(
        need.get("question"),
        required_for=need.get("required_for"),
    )


def _symbol_aliases(value: Any) -> set:
    text = re.sub(r"\s+", "", str(value or ""))
    if not text:
        return set()
    previous = None
    while previous != text:
        previous = text
        text = re.sub(r"<[^<>]*>", "", text)
    text = re.sub(r"\([^()]*\)$", "", text)
    normalized = text.replace("->", ".")
    pieces = [item for item in re.split(r"::|\.", normalized) if item]
    aliases = {normalized, normalized.lower()}
    if pieces:
        aliases.update({pieces[-1], pieces[-1].lower()})
    return {item for item in aliases if item}


def source_back_cpg_results(
    results: Iterable[Dict[str, Any]], *, source_root: str, query_round: int
) -> Tuple[List[Dict[str, Any]], List[str]]:
    root = os.path.realpath(source_root)
    facts = []
    errors = []
    for index, item in enumerate(results or [], start=1):
        if not isinstance(item, dict):
            errors.append(f"joern_result_not_object:round_{query_round}:{index}")
            continue
        source_name = str(item.get("source") or item.get("file") or item.get("filename") or "")
        try:
            line = int(item.get("line") or item.get("lineNumber") or 0)
            line_end = int(item.get("line_end") or item.get("lineEnd") or line)
        except (TypeError, ValueError):
            line, line_end = 0, 0
        source_path = source_name if os.path.isabs(source_name) else os.path.join(root, source_name)
        source_path = os.path.realpath(source_path)
        if not source_name or not _is_within(source_path, root) or not os.path.isfile(source_path):
            errors.append(f"joern_result_source_unmapped:round_{query_round}:{index}")
            continue
        if line < 1 or line_end < line:
            errors.append(f"joern_result_line_range_invalid:round_{query_round}:{index}")
            continue
        try:
            with open(source_path, "rb") as handle:
                raw_source = handle.read()
        except OSError:
            errors.append(f"joern_result_source_read_failed:round_{query_round}:{index}")
            continue
        source_text = raw_source.decode("utf-8", errors="replace")
        source_lines = source_text.splitlines()
        if line > len(source_lines):
            errors.append(f"joern_result_line_out_of_bounds:round_{query_round}:{index}")
            continue
        kind = str(item.get("kind") or "")
        contract_kinds = {
            "target_method", "caller_context", "callee_definition", "callee_candidate",
            "method_definition",
        }
        start_line = line
        # Method nodes already carry their exact Joern AST line range. Preserve
        # that range; ordinary operation evidence stays a compact exact-line card.
        bounded_end = min(
            line_end if kind in contract_kinds else min(line_end, line + 23),
            len(source_lines),
        )
        starts = _line_byte_starts(raw_source)
        start_byte = starts[start_line - 1]
        end_byte = starts[bounded_end] if bounded_end < len(starts) else len(raw_source)
        while end_byte > start_byte and raw_source[end_byte - 1:end_byte] in {b"\n", b"\r"}:
            end_byte -= 1
        excerpt = raw_source[start_byte:end_byte].decode("utf-8", errors="replace")
        fact = {
            "kind": str(item.get("kind") or "behavior_evidence"),
            "symbol": str(item.get("symbol") or item.get("call_name") or ""),
            "symbols": _result_symbols(item),
            "source_path": source_path,
            "source_file": os.path.relpath(source_path, root).replace(os.sep, "/"),
            "source_range": {
                "start_byte": start_byte,
                "end_byte": end_byte,
                "start_line": start_line,
                "end_line": bounded_end,
            },
            "source_excerpt": excerpt,
            "semantic_summary": clip(item.get("reason") or item.get("summary") or item.get("code"), 700),
            "semantic_details": _semantic_details(item),
            "query_round": query_round,
            "source_backing": "joern_ast_coordinate_to_exact_source_byte_range",
            "evidence_domain": STATIC_EVIDENCE_REQUIREMENT,
            "epistemic_status": "static_source_fact",
            "runtime_observed": False,
            "interpretation_limit": (
                "Describes source structure, possible control/data flow, or a static contract; "
                "does not prove a value, branch, or return observed in the failing execution."
            ),
        }
        fact["id"] = stable_id("evidence", {
            "file": fact["source_file"],
            "range": fact["source_range"],
            "kind": fact["kind"],
            "symbol": fact["symbol"],
        })
        facts.append(fact)
    return unique_dicts(facts), errors


def _result_symbols(item: Dict[str, Any]) -> List[str]:
    values = []
    raw = item.get("symbols")
    if isinstance(raw, dict):
        for group in raw.values():
            if isinstance(group, list):
                values.extend(str(value) for value in group if str(value))
    elif isinstance(raw, list):
        values.extend(str(value) for value in raw if str(value))
    for key in ("symbol", "call_name", "method"):
        value = str(item.get(key) or "")
        if value:
            values.append(value)
    return list(dict.fromkeys(values))[:24]


def _semantic_details(item: Dict[str, Any]) -> Dict[str, Any]:
    arguments = [clip(value, 300) for value in item.get("arguments") or []][:12]
    controls = []
    for value in item.get("control_context") or []:
        if not isinstance(value, dict):
            continue
        controls.append({
            "kind": value.get("kind"),
            "line": value.get("line"),
            "line_end": value.get("line_end"),
            "code": clip(value.get("code"), 800),
        })
        if len(controls) >= 6:
            break
    dependencies = []
    for value in item.get("dependency_paths") or []:
        if not isinstance(value, dict):
            continue
        dependencies.append({
            "kind": value.get("kind"),
            "symbol": value.get("symbol"),
            "line": value.get("line"),
            "code": clip(value.get("code"), 500),
            "control_context": [
                {
                    "kind": control.get("kind"),
                    "line": control.get("line"),
                    "line_end": control.get("line_end"),
                    "code": clip(control.get("code"), 500),
                }
                for control in value.get("control_context") or []
                if isinstance(control, dict)
            ][:6],
        })
    return {
        "arguments": arguments,
        "control_context": controls,
        "dependency_paths": dependencies,
        "full_name": clip(item.get("full_name"), 500),
        "signature": clip(item.get("signature"), 500),
        "callsite_method_full_name": clip(item.get("caller"), 500),
        "roles": [str(value) for value in item.get("roles") or [] if str(value)][:8],
    }


def _need_span(need: Dict[str, Any]) -> Dict[str, Any]:
    source_range = need.get("subject_source_range") or {}
    return {
        "id": str(need.get("id") or ""),
        "start_line": int(source_range.get("start_line") or 1),
        "end_line": int(source_range.get("end_line") or source_range.get("start_line") or 1),
    }


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _line_byte_starts(source: bytes) -> List[int]:
    starts = [0]
    offset = 0
    for line in source.splitlines(keepends=True):
        offset += len(line)
        starts.append(offset)
    return starts
