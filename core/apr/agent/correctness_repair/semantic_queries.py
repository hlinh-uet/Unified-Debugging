"""Contracts for optional hypothesis-driven Joern expansion queries."""

from __future__ import annotations

from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import clip, unique_dicts


BEHAVIOR_RELATIONS = {
    "ALIAS_OR_REFERENCE_FLOW",
    "ALTERNATE_PATH_STATE",
    "BRANCH_REACHABILITY",
    "CALLEE_CONTRACT",
    "CALL_ARGUMENT_MAPPING",
    "CALL_RESULT_CONTRACT",
    "CALLER_BRANCH_ON_RESULT",
    "CALLER_RESULT_USE",
    "CONTROLLING_PREDICATES",
    "CONVERSION_OPERATORS",
    "EARLY_RETURN_CONDITIONS",
    "ENUM_OR_SENTINEL_VALUES",
    "ERROR_PROPAGATION",
    "FIELD_READ_WRITE",
    "OVERLOAD_SET",
    "PARALLEL_ERROR_HANDLING",
    "REACHING_DEFINITIONS",
    "RETURN_VALUE_FLOW",
    "SAME_TYPE_OPERATION",
    "SIBLING_BRANCH",
    "SIBLING_IMPLEMENTATION",
    "STATE_TRANSITIONS",
    "TEMPLATE_SPECIALIZATION",
    "TYPE_DEFINITION",
    "VALUE_USES",
}

RELATION_SUBJECT_KINDS = {
    "CALLER_BRANCH_ON_RESULT": {"target_function", "return"},
    "CALLER_RESULT_USE": {"target_function", "return"},
    "RETURN_VALUE_FLOW": {"target_function", "return"},
    "CALLEE_CONTRACT": {"call"},
    "CALL_ARGUMENT_MAPPING": {"call"},
    "CALL_RESULT_CONTRACT": {"call"},
}


def normalize_information_needs(
    value: Any,
    *,
    target_inventory: Dict[str, Any],
    max_needs: int = 8,
    allowed_hypothesis_ids: Optional[Iterable[str]] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Validate only follow-up proof gaps emitted by causal diagnosis."""
    if not isinstance(value, list) or not value:
        return [], "information_needs_missing"
    entities = {
        str(item.get("id")): item
        for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("id")
    }
    hypothesis_ids = set(str(item) for item in allowed_hypothesis_ids or [])
    needs = []
    errors = []
    for raw in value[:max_needs]:
        if not isinstance(raw, dict):
            errors.append("information_need_not_object")
            continue
        need_id = str(raw.get("id") or "")
        entity_id = str(raw.get("subject_entity_id") or "")
        relation = str(raw.get("relation") or "").upper()
        question = str(raw.get("question") or "").strip()
        entity = entities.get(entity_id)
        allowed_subjects = RELATION_SUBJECT_KINDS.get(relation)
        if (
            not need_id
            or entity is None
            or relation not in BEHAVIOR_RELATIONS
            or not question
            or (allowed_subjects is not None and entity.get("kind") not in allowed_subjects)
        ):
            errors.append(f"information_need_contract_invalid:{need_id or 'missing'}")
            continue
        entity_symbol_values = list(dict.fromkeys(
            str(item) for item in entity.get("symbols") or [] if str(item)
        ))
        entity_symbols = set(entity_symbol_values)
        requested = [str(item).strip() for item in raw.get("symbols") or [] if str(item).strip()]
        symbols = list(dict.fromkeys(item for item in requested if item in entity_symbols))
        if requested and not symbols:
            errors.append(f"information_need_symbols_not_bound_to_subject:{need_id}")
            continue
        if not symbols:
            symbols = entity_symbol_values[:3]
        hypothesis_id = str(raw.get("hypothesis_id") or "")
        if hypothesis_id and hypothesis_ids and hypothesis_id not in hypothesis_ids:
            errors.append(f"information_need_hypothesis_unknown:{need_id}")
            continue
        needs.append({
            "id": need_id,
            "subject_entity_id": entity_id,
            "subject_kind": entity.get("kind"),
            "subject_source_range": entity.get("source_range"),
            "relation": relation,
            "question": clip(question, 600),
            "symbols": symbols[:3],
            "required_for": clip(raw.get("required_for"), 600),
            "priority": str(raw.get("priority") or "supporting"),
            "hypothesis_id": hypothesis_id,
            "status": "pending",
            "evidence_ids": [],
        })
    needs = unique_dicts(needs)
    if not needs:
        return [], ";".join(errors) or "no_valid_information_needs"
    return needs, ";".join(errors)
