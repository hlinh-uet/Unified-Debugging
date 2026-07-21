"""Contracts for optional hypothesis-driven Joern expansion queries."""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .models import clip, stable_id, unique_dicts


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

STATIC_EVIDENCE_REQUIREMENT = "static_program_semantics"
RUNTIME_EVIDENCE_REQUIREMENT = "runtime_observation"

RELATION_SUBJECT_KINDS = {
    "CALLER_BRANCH_ON_RESULT": {"target_function", "return"},
    "CALLER_RESULT_USE": {"target_function", "return"},
    "RETURN_VALUE_FLOW": {"target_function", "return"},
    "CALLEE_CONTRACT": {"call"},
    "CALL_ARGUMENT_MAPPING": {"call"},
    "CALL_RESULT_CONTRACT": {"call"},
}

CALL_RELATIONS = {"CALLEE_CONTRACT", "CALL_ARGUMENT_MAPPING", "CALL_RESULT_CONTRACT"}
CALLER_RELATIONS = {"CALLER_BRANCH_ON_RESULT", "CALLER_RESULT_USE", "RETURN_VALUE_FLOW"}
TARGET_WIDE_RELATIONS = {
    "ALIAS_OR_REFERENCE_FLOW", "ALTERNATE_PATH_STATE", "BRANCH_REACHABILITY",
    "CONTROLLING_PREDICATES", "EARLY_RETURN_CONDITIONS", "ERROR_PROPAGATION",
    "FIELD_READ_WRITE", "PARALLEL_ERROR_HANDLING", "REACHING_DEFINITIONS",
    "SAME_TYPE_OPERATION", "SIBLING_BRANCH", "SIBLING_IMPLEMENTATION",
    "STATE_TRANSITIONS", "VALUE_USES",
}
PRIORITY_ORDER = {"critical": 0, "high": 1, "supporting": 2}
INFORMATION_NEED_NORMALIZATION_VERSION = 2


def normalize_information_needs(
    value: Any,
    *,
    target_inventory: Dict[str, Any],
    max_needs: int = 8,
    allowed_hypothesis_ids: Optional[Iterable[str]] = None,
) -> Tuple[List[Dict[str, Any]], str]:
    """Normalize, source-bind, and budget follow-up proof gaps."""
    if not isinstance(value, list) or not value:
        return [], "information_needs_missing"
    entity_values = [
        item for item in target_inventory.get("entities") or []
        if isinstance(item, dict) and item.get("id")
    ]
    entities = {
        str(item.get("id")): item
        for item in entity_values
    }
    entity_aliases = _entity_id_aliases(entity_values)
    hypothesis_ids = set(str(item) for item in allowed_hypothesis_ids or [])
    needs = []
    errors = []
    raw_values = [item for item in value if isinstance(item, dict)]
    errors.extend("information_need_not_object" for item in value if not isinstance(item, dict))
    # Bound pathological model output without letting low-priority early items
    # consume the executable-query budget.
    raw_limit = max(24, max(1, int(max_needs or 0)) * 4)
    if len(raw_values) > raw_limit:
        raw_values = sorted(raw_values, key=_raw_need_priority)[:raw_limit]
        errors.append("information_needs_raw_budget_exhausted")
    for raw in raw_values:
        if not isinstance(raw, dict):
            continue
        need_id = str(raw.get("id") or "")
        entity_id = str(raw.get("subject_entity_id") or "")
        relation = str(raw.get("relation") or "").upper()
        question = str(raw.get("question") or "").strip()
        requested = [str(item).strip() for item in raw.get("symbols") or [] if str(item).strip()]
        if not need_id or relation not in BEHAVIOR_RELATIONS or not question:
            errors.append(f"information_need_contract_invalid:{need_id or 'missing'}")
            continue
        entity = entities.get(entity_id) or entity_aliases.get(entity_id)
        subject_was_alias = entity is not None and entity_id not in entities
        subject_was_recovered = False
        recovery_reason = ""
        if entity is None:
            entity, recovery_reason = _recover_missing_subject(
                relation=relation,
                requested_symbols=requested,
                question=question,
                entities=entity_values,
            )
            subject_was_recovered = bool(entity)
        if entity is None:
            errors.append(f"information_need_contract_invalid:{need_id or 'missing'}")
            continue
        hypothesis_id = str(raw.get("hypothesis_id") or "")
        if hypothesis_id and hypothesis_ids and hypothesis_id not in hypothesis_ids:
            errors.append(f"information_need_hypothesis_unknown:{need_id}")
            continue
        bound_entity, bound_relation, binding_status, binding_reason = _bind_subject_entity(
            entity=entity,
            relation=relation,
            requested_symbols=requested,
            question=question,
            entities=entity_values,
        )
        if subject_was_alias and binding_status == "exact":
            binding_status = "alias_rebound"
            binding_reason = "behavior_evidence_alias_resolved_to_syntax_entity"
        elif subject_was_recovered:
            binding_status = "source_recovered"
            binding_reason = recovery_reason or binding_reason
        allowed_subjects = RELATION_SUBJECT_KINDS.get(bound_relation)
        if allowed_subjects is not None and str(bound_entity.get("kind") or "") not in allowed_subjects:
            errors.append(f"information_need_subject_unresolved:{need_id}")
            continue
        allowed_aliases = _scope_aliases(
            entity=bound_entity,
            relation=bound_relation,
            entities=entity_values,
        )
        symbols = list(dict.fromkeys(
            item for item in requested
            if allowed_aliases.intersection(_symbol_aliases(item))
        ))
        if requested and not symbols:
            errors.append(f"information_need_symbols_not_bound_to_subject:{need_id}")
            continue
        if not symbols:
            symbols = _entity_symbol_values(bound_entity)[:3]
        dropped_symbols = [item for item in requested if item not in symbols]
        evidence_requirement = information_need_evidence_requirement(
            question,
            required_for=str(raw.get("required_for") or ""),
        )
        original_entity_id = str(raw.get("original_subject_entity_id") or entity_id)
        original_relation = str(raw.get("original_relation") or relation)
        if raw.get("normalization_version") == INFORMATION_NEED_NORMALIZATION_VERSION:
            if binding_status == "exact" and raw.get("binding_status"):
                binding_status = str(raw.get("binding_status"))
                binding_reason = str(raw.get("binding_reason") or binding_reason)
        normalization_diagnostics = list(raw.get("normalization_diagnostics") or [])
        if binding_status != "exact":
            normalization_diagnostics.append(
                f"{binding_status}:{original_entity_id}->{bound_entity.get('id')}"
            )
        if bound_relation != relation:
            normalization_diagnostics.append(f"relation_rewritten:{relation}->{bound_relation}")
        if dropped_symbols:
            normalization_diagnostics.append(
                "dropped_symbols:" + ",".join(dropped_symbols)
            )
        needs.append({
            **raw,
            "id": need_id,
            "normalization_version": INFORMATION_NEED_NORMALIZATION_VERSION,
            "original_subject_entity_id": original_entity_id,
            "subject_entity_id": str(bound_entity.get("id") or ""),
            "subject_kind": bound_entity.get("kind"),
            "subject_source_range": bound_entity.get("source_range"),
            "binding_status": binding_status,
            "binding_reason": binding_reason,
            "original_relation": original_relation,
            "relation": bound_relation,
            "question": clip(question, 600),
            "symbols": symbols[:8],
            "dropped_symbols": dropped_symbols[:8],
            "normalization_diagnostics": list(dict.fromkeys(normalization_diagnostics))[:12],
            "required_for": clip(raw.get("required_for"), 600),
            "priority": str(raw.get("priority") or "supporting"),
            "hypothesis_id": hypothesis_id,
            "evidence_requirement": evidence_requirement,
            "answerable_by": (
                "runtime_instrumentation_or_trace"
                if evidence_requirement == RUNTIME_EVIDENCE_REQUIREMENT
                else "compiler_semantics_or_static_cpg"
            ),
            "status": "pending",
            "evidence_ids": [],
        })
    needs = unique_dicts(sorted(needs, key=_normalized_need_priority))
    executable_limit = max(0, int(max_needs or 0))
    if executable_limit and len(needs) > executable_limit:
        for need in needs[executable_limit:]:
            errors.append(f"information_need_budget_deferred:{need['id']}")
        needs = needs[:executable_limit]
    if not needs:
        return [], ";".join(errors) or "no_valid_information_needs"
    return needs, ";".join(errors)


def _bind_subject_entity(
    *, entity: Dict[str, Any], relation: str, requested_symbols: List[str],
    question: str, entities: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], str, str, str]:
    allowed = RELATION_SUBJECT_KINDS.get(relation)
    if allowed is None or str(entity.get("kind") or "") in allowed:
        return entity, relation, "exact", "subject_contract_already_satisfied"
    if relation in CALL_RELATIONS:
        rewritten = _repair_relation_for_subject(relation, question, requested_symbols)
        if rewritten != relation:
            return entity, rewritten, "relation_rewritten", "question_targets_type_or_field_semantics"
        candidate, reason = _best_call_subject(
            entity=entity,
            requested_symbols=requested_symbols,
            question=question,
            entities=entities,
        )
        if candidate:
            return candidate, relation, "rebound", reason
    if relation in CALLER_RELATIONS:
        targets = [item for item in entities if item.get("kind") == "target_function"]
        if len(targets) == 1:
            return targets[0], relation, "rebound", "caller_relation_rebound_to_target_function"
    return entity, relation, "unresolved", "no_unique_compatible_subject"


def _entity_id_aliases(entities: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    """Resolve LLM-visible evidence/call IDs back to canonical syntax entities."""
    target_leaf = next((
        str(value)
        for entity in entities if entity.get("kind") == "target_function"
        for value in entity.get("symbols") or [] if str(value)
    ), "")
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
    aliases: Dict[str, Dict[str, Any]] = {}
    for entity in entities:
        kind = str(entity.get("kind") or "")
        fact_kind = kind_map.get(kind)
        if not fact_kind:
            continue
        if kind == "target_function":
            symbols = [target_leaf or ""]
        elif kind == "call":
            symbols = [
                str(entity.get("callee_symbol") or "")
                or next((str(value) for value in entity.get("symbols") or [] if str(value)), "")
            ]
        elif kind == "return":
            symbols = [target_leaf or ""]
        elif kind in {"branch", "conditional"}:
            symbols = [""]
        elif kind in {"assignment", "update"}:
            symbols = [
                str(entity.get("write_target") or "")
                or next((str(value) for value in entity.get("symbols") or [] if str(value)), "")
            ]
        else:
            symbols = [
                str(value) for value in entity.get("declared_symbols") or [] if str(value)
            ] or [""]
        for symbol in symbols:
            fact_id = stable_id("ast_evidence", {
                "entity_id": entity.get("id"),
                "kind": fact_kind,
                "symbol": symbol,
            })
            aliases[fact_id] = entity
            if kind == "call":
                aliases[stable_id("call", fact_id)] = entity
    return aliases


def _recover_missing_subject(
    *, relation: str, requested_symbols: List[str], question: str,
    entities: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], str]:
    """Recover an unknown model ID only when a unique source anchor exists."""
    targets = [item for item in entities if item.get("kind") == "target_function"]
    target = targets[0] if len(targets) == 1 else {}
    if relation in CALL_RELATIONS and target:
        candidate, _ = _best_call_subject(
            entity=target,
            requested_symbols=requested_symbols,
            question=question,
            entities=entities,
        )
        if candidate:
            return candidate, "unknown_id_recovered_to_unique_matching_call"
    if relation in CALLER_RELATIONS and target:
        return target, "unknown_id_recovered_to_target_function"
    if relation in TARGET_WIDE_RELATIONS and target:
        wanted = {
            alias for value in requested_symbols for alias in _symbol_aliases(value)
        }
        if not wanted or wanted.intersection(_scope_aliases(
            entity=target, relation=relation, entities=entities
        )):
            return target, "unknown_id_recovered_to_target_scope"
    if relation in {
        "TYPE_DEFINITION", "ENUM_OR_SENTINEL_VALUES", "TEMPLATE_SPECIALIZATION",
        "CONVERSION_OPERATORS",
    }:
        wanted = {
            alias for value in requested_symbols for alias in _symbol_aliases(value)
        }
        candidates = [
            item for item in entities
            if item.get("kind") in {"declaration", "parameter"}
            and wanted.intersection(_entity_aliases(item))
        ]
        if len(candidates) == 1:
            return candidates[0], "unknown_id_recovered_to_unique_declaration"
    return {}, "unknown_id_not_source_recoverable"


def _best_call_subject(
    *, entity: Dict[str, Any], requested_symbols: List[str], question: str,
    entities: List[Dict[str, Any]],
) -> Tuple[Dict[str, Any], str]:
    calls = [item for item in entities if item.get("kind") == "call"]
    if not calls:
        return {}, "call_subject_missing"
    wanted_aliases = {
        alias
        for value in [*requested_symbols, *_question_symbol_hints(question)]
        for alias in _symbol_aliases(value)
    }
    original_aliases = _entity_aliases(entity)
    question_compact = re.sub(r"\s+", "", question).lower()
    scored = []
    for candidate in calls:
        aliases = _entity_aliases(candidate)
        contained = _range_contains(
            entity.get("source_range") or {}, candidate.get("source_range") or {}
        )
        requested_matches = len(wanted_aliases.intersection(aliases))
        original_matches = len(original_aliases.intersection(aliases))
        source_compact = re.sub(
            r"\s+", "", str(candidate.get("source_excerpt") or "")
        ).lower()
        callee_compact = re.sub(
            r"\s+", "", str(candidate.get("callee_symbol") or "")
        ).lower()
        exact_question_match = bool(source_compact and source_compact in question_compact)
        callee_question_match = bool(callee_compact and callee_compact in question_compact)
        if not (contained or requested_matches or original_matches or exact_question_match):
            continue
        distance = _source_distance(entity, candidate)
        score = (
            20 * int(exact_question_match)
            + 10 * int(contained)
            + 6 * int(callee_question_match)
            + 4 * requested_matches
            + 2 * original_matches
            + max(0, 6 - min(distance, 6))
        )
        scored.append((score, -distance, -_range_size(candidate.get("source_range") or {}), candidate))
    if not scored:
        return {}, "call_subject_unmatched"
    scored.sort(key=lambda item: item[:3], reverse=True)
    if len(scored) > 1 and scored[0][0] == scored[1][0]:
        return {}, "call_subject_ambiguous"
    reason = (
        "unique_matching_call_inside_subject"
        if _range_contains(entity.get("source_range") or {}, scored[0][3].get("source_range") or {})
        else "unique_symbol_and_question_matched_call"
    )
    return scored[0][3], reason


def _repair_relation_for_subject(
    relation: str, question: str, requested_symbols: List[str]
) -> str:
    text = f"{question} {' '.join(requested_symbols)}".lower()
    quoted = re.findall(r"`([^`]{1,160})`", str(question or ""))
    primary_quoted_is_call = bool(quoted and "(" in quoted[0] and ")" in quoted[0])
    call_semantics = primary_quoted_is_call or bool(re.search(
        r"\b(?:what does|semantics|return type|return value|callee|contract)\b",
        text,
    ))
    if not call_semantics and re.search(
        r"\b(type|typedef|class|struct|enum|definition of|definitions of)\b", text
    ):
        return "TYPE_DEFINITION"
    if not call_semantics and re.search(
        r"\b(field|member|read|write|assign(?:ed|ment)?)\b", text
    ):
        return "FIELD_READ_WRITE"
    return relation


def _scope_aliases(
    *, entity: Dict[str, Any], relation: str, entities: List[Dict[str, Any]]
) -> set:
    scoped = [entity]
    if relation in TARGET_WIDE_RELATIONS or entity.get("kind") == "target_function":
        subject_range = entity.get("source_range") or {}
        scoped.extend(
            item for item in entities
            if item is not entity and _range_contains(subject_range, item.get("source_range") or {})
        )
    return {alias for item in scoped for alias in _entity_aliases(item)}


def _entity_aliases(entity: Dict[str, Any]) -> set:
    values = [
        *(entity.get("symbols") or []),
        *(entity.get("declared_symbols") or []),
        entity.get("callee_symbol"),
        entity.get("write_target"),
        *(entity.get("arguments") or []),
    ]
    return {
        alias for value in values if str(value)
        for alias in _symbol_aliases(value)
    }


def _entity_symbol_values(entity: Dict[str, Any]) -> List[str]:
    return list(dict.fromkeys(
        str(value) for value in [
            entity.get("callee_symbol"), entity.get("write_target"),
            *(entity.get("declared_symbols") or []), *(entity.get("symbols") or []),
        ] if str(value)
    ))


def _question_symbol_hints(question: str) -> List[str]:
    quoted = re.findall(r"`([^`]{1,160})`", str(question or ""))
    qualified = re.findall(
        r"\b[A-Za-z_]\w*(?:(?:::|\.|->)[A-Za-z_]\w*)+(?:\([^)]{0,120}\))?",
        str(question or ""),
    )
    return list(dict.fromkeys([*quoted, *qualified]))[:16]


def _range_contains(outer: Dict[str, Any], inner: Dict[str, Any]) -> bool:
    try:
        return (
            int(outer.get("start_byte")) <= int(inner.get("start_byte"))
            and int(inner.get("end_byte")) <= int(outer.get("end_byte"))
        )
    except (TypeError, ValueError):
        return False


def _range_size(source_range: Dict[str, Any]) -> int:
    try:
        return max(0, int(source_range.get("end_byte")) - int(source_range.get("start_byte")))
    except (TypeError, ValueError):
        return 0


def _source_distance(left: Dict[str, Any], right: Dict[str, Any]) -> int:
    try:
        left_range = left.get("source_range") or {}
        right_range = right.get("source_range") or {}
        if _range_contains(left_range, right_range) or _range_contains(right_range, left_range):
            return 0
        return min(
            abs(int(left_range.get("start_line") or 0) - int(right_range.get("end_line") or 0)),
            abs(int(right_range.get("start_line") or 0) - int(left_range.get("end_line") or 0)),
        )
    except (TypeError, ValueError):
        return 10**6


def _raw_need_priority(item: Dict[str, Any]) -> Tuple[int, str]:
    return PRIORITY_ORDER.get(str(item.get("priority") or "supporting").lower(), 3), str(item.get("id") or "")


def _normalized_need_priority(item: Dict[str, Any]) -> Tuple[int, int, str]:
    return (
        PRIORITY_ORDER.get(str(item.get("priority") or "supporting").lower(), 3),
        0 if item.get("evidence_requirement") == STATIC_EVIDENCE_REQUIREMENT else 1,
        str(item.get("id") or ""),
    )


def information_need_evidence_requirement(
    question: Any, *, required_for: Any = ""
) -> str:
    """Classify whether a question asks about source semantics or one execution."""
    text = re.sub(
        r"\s+",
        " ",
        f"{str(question or '')} {str(required_for or '')}".lower(),
    ).strip()
    runtime_patterns = (
        r"\b(?:runtime|run-time|execution trace|dynamic trace|observed value|actual value|concrete value)\b",
        r"\b(?:for|in|during)\s+(?:the\s+)?(?:failing|failed)\s+"
        r"(?:test|case|run|execution|input)\b",
        r"\b(?:for|in|during)\s+(?:the\s+)?test(?:\s+case)?\b",
        r"\bat each (?:execution )?step\b",
        r"\bwhich branch (?:is|was|gets) (?:taken|executed)\b",
        r"\bwhat value\b.{0,120}\bwhen\b.{0,120}\b(?:evaluated|executed|called)\b",
        r"\bwhen\b.{0,120}\b(?:condition|branch|call)\b.{0,120}\b"
        r"(?:is|was) (?:evaluated|executed|taken)\b",
        r"\b(?:did|does)\b.{0,120}\breturn\b.{0,120}\b"
        r"(?:failing|failed|test run|this test)\b",
        r"\b(?:build|binary|tests?)\b.{0,100}\b(?:recompiled|executed|ran)\b",
        r"\btested repair\b.{0,100}\b(?:applied|executed|built|compiled)\b",
    )
    if any(re.search(pattern, text, re.IGNORECASE) for pattern in runtime_patterns):
        return RUNTIME_EVIDENCE_REQUIREMENT
    return STATIC_EVIDENCE_REQUIREMENT


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
    aliases = {normalized.lower()}
    if pieces:
        aliases.add(pieces[-1].lower())
    return aliases
