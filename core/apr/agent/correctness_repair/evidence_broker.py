"""Execute optional hypothesis-driven Joern expansions and source-back results."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Tuple

from core.apr.program_analysis.service import query_cpg_tool

from .semantic_queries import BEHAVIOR_RELATIONS
from .models import clip, stable_id, unique_dicts


RELATION_FACT_KINDS = {
    "ALIAS_OR_REFERENCE_FLOW": {"assignment", "control_data_dependency", "symbol_usage"},
    "ALTERNATE_PATH_STATE": {"target_region", "control_data_dependency"},
    "BRANCH_REACHABILITY": {"target_region", "control_data_dependency"},
    "CALLEE_CONTRACT": {"callee_definition"},
    "CALL_ARGUMENT_MAPPING": {"call_argument_flow"},
    "CALL_RESULT_CONTRACT": {"callee_definition"},
    "CALLER_BRANCH_ON_RESULT": {"caller_context"},
    "CALLER_RESULT_USE": {"caller_context"},
    "CONTROLLING_PREDICATES": {"target_region", "control_data_dependency"},
    "CONVERSION_OPERATORS": {"type_definition", "method_definition"},
    "EARLY_RETURN_CONDITIONS": {"target_region", "control_data_dependency"},
    "ENUM_OR_SENTINEL_VALUES": {"type_definition", "method_definition"},
    "ERROR_PROPAGATION": {"caller_context", "callee_definition", "call_argument_flow"},
    "FIELD_READ_WRITE": {"assignment", "control_data_dependency", "symbol_usage"},
    "OVERLOAD_SET": {"method_definition", "callee_definition"},
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
    limit: int = 48,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Run one real, batched Joern traversal over the full cached project CPG."""
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

    symbols = list(dict.fromkeys(
        str(symbol)
        for need in needs
        for symbol in need.get("symbols") or []
        if str(symbol)
    ))[:24]
    relations = list(dict.fromkeys(str(need["relation"]) for need in needs))
    result = query_cpg_tool(
        source_root=source_root,
        source_path=str(target_contract.get("source_path") or ""),
        function_name=str(
            target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
        ),
        function_signature=str(target_contract.get("signature") or ""),
        function_start_line=int((target_contract.get("source_range") or {}).get("start_line") or 1),
        tool="get_behavior_evidence",
        symbols=symbols,
        kinds=relations,
        region_ids=[str(need["id"]) for need in needs],
        region_spans=[_need_span(need) for need in needs],
        limit=max(1, min(int(limit), 64)),
        allow_source_scan_fallback=False,
    )
    facts, mapping_errors = source_back_cpg_results(
        result.get("results") or [], source_root=source_root, query_round=round_index
    )
    linked_facts, updated_needs, link_errors = _link_evidence_to_needs(
        facts,
        needs=needs,
        target_contract=target_contract,
    )
    engine = result.get("engine") if isinstance(result.get("engine"), dict) else {}
    errors = [
        *validation_errors,
        *(result.get("uncertainties") or []),
        *mapping_errors,
        *link_errors,
    ]
    if not engine.get("available"):
        errors.append("joern_behavior_query_backend_unavailable")
    if not linked_facts:
        errors.append(f"joern_behavior_query_round_has_no_source_backed_evidence:{round_index}")
    query_record = {
        "round": round_index,
        "status": "evidence_returned" if linked_facts else "empty",
        "tool": "get_behavior_evidence",
        "relations": relations,
        "symbols": symbols,
        "need_ids": [item["id"] for item in needs],
        "engine": engine,
        "raw_result_count": len(result.get("results") or []),
        "source_backed_fact_count": len(linked_facts),
        "fallback_policy": "none",
    }
    return updated_needs, linked_facts, query_record, list(dict.fromkeys(
        str(item) for item in errors if str(item)
    ))


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
    entities = {
        str(item.get("id")): item
        for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("id")
    }
    out = []
    errors = []
    for raw in needs or []:
        if not isinstance(raw, dict):
            errors.append("behavior_query_need_not_object")
            continue
        need_id = str(raw.get("id") or "")
        relation = str(raw.get("relation") or "").upper()
        entity_id = str(raw.get("subject_entity_id") or "")
        entity = entities.get(entity_id)
        if not need_id or relation not in BEHAVIOR_RELATIONS or entity is None:
            errors.append(f"behavior_query_need_not_source_bound:{need_id or 'missing'}")
            continue
        allowed_symbols = set(str(value) for value in entity.get("symbols") or [] if str(value))
        symbols = [
            str(value) for value in raw.get("symbols") or []
            if str(value) and str(value) in allowed_symbols
        ]
        if raw.get("symbols") and not symbols:
            errors.append(f"behavior_query_symbols_not_source_bound:{need_id}")
            continue
        out.append({
            **raw,
            "relation": relation,
            "subject_kind": entity.get("kind"),
            "subject_source_range": entity.get("source_range") or {},
            "symbols": list(dict.fromkeys(symbols))[:8],
        })
    return unique_dicts(out), errors


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
        allowed_kinds = RELATION_FACT_KINDS.get(str(need.get("relation") or ""), set())
        wanted = set(str(item) for item in need.get("symbols") or [] if str(item))
        matches = []
        for fact in facts:
            if str(fact.get("kind") or "") not in allowed_kinds:
                continue
            fact_symbols = set(str(item) for item in fact.get("symbols") or [] if str(item))
            if fact.get("symbol"):
                fact_symbols.add(str(fact["symbol"]))
            if need.get("relation") in {
                "CALLER_RESULT_USE", "CALLER_BRANCH_ON_RESULT", "RETURN_VALUE_FLOW", "ERROR_PROPAGATION"
            }:
                fact_symbols.add(target_leaf)
            if wanted and not wanted.intersection(fact_symbols):
                continue
            matches.append(fact)
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
            "status": "answered" if evidence_ids else "unresolved",
            "evidence_ids": evidence_ids,
        }
        updated_needs.append(updated)
        if not evidence_ids:
            errors.append(f"behavior_information_need_unresolved:{need['id']}")
    return list(linked_by_id.values()), updated_needs, errors


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
            raw_source = open(source_path, "rb").read()
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
