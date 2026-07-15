from typing import Any, Dict, List


DEFAULT_MAX_TEXT = 360


def compact_unsafe_path(path: Dict[str, Any], *, max_text: int = DEFAULT_MAX_TEXT) -> Dict[str, Any]:
    if not isinstance(path, dict):
        return {}
    sink = path.get("sink") or {}
    state = path.get("data_state_before_sink") or {}
    patch_site = path.get("recommended_patch_site") or {}
    return {
        "id": path.get("id"),
        "source_risk_id": path.get("source_risk_id"),
        "sink": {
            "kind": sink.get("kind"),
            "line": sink.get("line"),
            "code": _clip(sink.get("code"), 260),
            "symbols": _first(sink.get("symbols"), 10),
            "provider": sink.get("provider"),
        },
        "data_state_before_sink": {
            "pointer_state": [_clip(item, 180) for item in _first(state.get("pointer_state"), 5)],
            "size_state": [_clip(item, 180) for item in _first(state.get("size_state"), 5)],
            "buffer_capacity_facts": [_clip(item, 180) for item in _first(state.get("buffer_capacity_facts"), 5)],
            "typed_buffer_facts": _compact_typed_buffer_facts(state.get("typed_buffer_facts") or {}),
        },
        "existing_guards": [
            {
                "id": guard.get("id"),
                "line": guard.get("line"),
                "code": _clip(guard.get("code"), 200),
                "source": guard.get("source"),
                "dominates_sink": guard.get("dominates_sink"),
                "covers_sink": guard.get("covers_sink"),
                "missing": _clip(guard.get("missing"), 200),
            }
            for guard in _first(path.get("existing_guards"), 5)
            if isinstance(guard, dict)
        ],
        "cleanup_obligations": [
            {
                "resource": obligation.get("resource"),
                "required_on_fail_closed": obligation.get("required_on_fail_closed"),
                "cleanup_call": _clip(obligation.get("cleanup_call"), 200),
                "evidence": _clip(obligation.get("evidence"), 160),
                "label": obligation.get("label"),
                "label_line": obligation.get("label_line"),
                "line": obligation.get("line"),
            }
            for obligation in _first(path.get("cleanup_obligations"), 5)
            if isinstance(obligation, dict)
        ],
        "recommended_patch_site": {
            "line": patch_site.get("line"),
            "kind": patch_site.get("kind"),
            "before_sink": patch_site.get("before_sink"),
            "dominance_requirement": _clip(patch_site.get("dominance_requirement"), 220),
            "required_property": _clip(patch_site.get("required_property"), 220),
            "operator": patch_site.get("operator"),
        },
        "fail_closed_expectation": _clip(path.get("fail_closed_expectation"), 260),
        "valid_path_preservation": _clip(path.get("valid_path_preservation"), 260),
        "wrong_fix_trap": _clip(path.get("wrong_fix_trap"), 220),
        "confidence": path.get("confidence"),
    }


def compact_unsafe_paths(paths: Any, *, limit: int = 6, max_text: int = DEFAULT_MAX_TEXT) -> List[Dict[str, Any]]:
    return [
        compact_unsafe_path(path, max_text=max_text)
        for path in _first(paths, limit)
        if isinstance(path, dict)
    ]


def unsafe_path_payload_from_constraints_artifact(payload: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    constraints = payload.get("repair_constraints") or {}
    risk_plan = constraints.get("risk_plan") or {}
    return {
        "path_summary": risk_plan.get("path_summary") or {},
        "risk_summary": risk_plan.get("risk_summary") or {},
        "security_failure_contract": risk_plan.get("security_failure_contract") or {},
        "repair_decision_context": constraints.get("repair_decision_context") or {},
        "unsafe_path_selection_policy": constraints.get("unsafe_path_selection_policy") or {},
        "unsafe_paths": risk_plan.get("unsafe_paths") or constraints.get("unsafe_paths") or [],
        "unsafe_path_decision_aids": constraints.get("unsafe_path_decision_aids") or [],
        "risk_operations": (
            risk_plan.get("risk_operations")
            or constraints.get("risk_operations")
            or risk_plan.get("risky_operations")
            or risk_plan.get("ranked_risks")
            or []
        ),
        "risky_operations": (
            risk_plan.get("risky_operations")
            or risk_plan.get("ranked_risks")
            or risk_plan.get("risk_operations")
            or constraints.get("risk_operations")
            or []
        ),
        "wrong_fix_risks": risk_plan.get("wrong_fix_risks") or constraints.get("wrong_fix_risks") or [],
        "constraints": risk_plan.get("constraints") or [],
    }


def compact_unsafe_path_payload(
    payload: Dict[str, Any],
    *,
    path_limit: int = 4,
    risk_limit: int = 6,
) -> Dict[str, Any]:
    if not isinstance(payload, dict):
        return {}
    return {
        "path_summary": payload.get("path_summary") or {},
        "risk_summary": payload.get("risk_summary") or {},
        "security_failure_contract": payload.get("security_failure_contract") or {},
        "repair_decision_context": _compact_mapping(payload.get("repair_decision_context") or {}, 180),
        "unsafe_path_selection_policy": _compact_selection_policy(payload.get("unsafe_path_selection_policy") or {}),
        "unsafe_paths": compact_unsafe_paths(payload.get("unsafe_paths"), limit=path_limit),
        "unsafe_path_decision_aids": [
            _compact_decision_aid(item)
            for item in _first(payload.get("unsafe_path_decision_aids"), path_limit)
            if isinstance(item, dict)
        ],
        "risk_operations": [
            _compact_risky_operation(risk)
            for risk in _first(payload.get("risk_operations") or payload.get("risky_operations") or payload.get("ranked_risks"), risk_limit)
            if isinstance(risk, dict)
        ],
        # Compatibility hazard context; prefer unsafe_paths.
        "risky_operations": [
            _compact_risky_operation(risk)
            for risk in _first(payload.get("risky_operations") or payload.get("ranked_risks") or payload.get("risk_operations"), risk_limit)
            if isinstance(risk, dict)
        ],
        "wrong_fix_risks": _first(payload.get("wrong_fix_risks"), 8),
        "constraints": _first(payload.get("constraints"), 8),
    }


def _compact_selection_policy(policy: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(policy, dict):
        return {}
    return {
        "role": policy.get("role"),
        "unsafe_paths_are": _clip(policy.get("unsafe_paths_are"), 180),
        "must_choose_path_by": [_clip(item, 180) for item in _first(policy.get("must_choose_path_by"), 4)],
        "reject_path_when": [_clip(item, 180) for item in _first(policy.get("reject_path_when"), 4)],
        "tie_breakers": [_clip(item, 180) for item in _first(policy.get("tie_breakers"), 4)],
        "failure_categories": _first(policy.get("failure_categories"), 8),
    }


def _compact_decision_aid(aid: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(aid, dict):
        return {}
    return {
        "id": aid.get("id"),
        "unsafe_path_id": aid.get("unsafe_path_id"),
        "sink": _compact_mapping(aid.get("sink") or {}, 180),
        "selection_signals": _compact_mapping(aid.get("selection_signals") or {}, 180),
        "patch_feasibility": _compact_mapping(aid.get("patch_feasibility") or {}, 180),
        "symbol_facts": _compact_mapping(aid.get("symbol_facts") or {}, 180),
        "guard_evidence": [_compact_mapping(item, 160) for item in _first(aid.get("guard_evidence"), 4) if isinstance(item, dict)],
        "fail_closed_action": _clip(aid.get("fail_closed_action"), 180),
        "cleanup_preservation": [
            _compact_mapping(item, 160)
            for item in _first(aid.get("cleanup_preservation"), 4)
            if isinstance(item, dict)
        ],
        "valid_path_preservation": _clip(aid.get("valid_path_preservation"), 180),
        "wrong_fix_trap": _clip(aid.get("wrong_fix_trap"), 180),
        "failure_categories": _first(aid.get("failure_categories"), 8),
        "confidence": aid.get("confidence"),
    }


def _compact_mapping(value: Dict[str, Any], max_chars: int) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, Any] = {}
    for key, item in value.items():
        if isinstance(item, dict):
            out[key] = _compact_mapping(item, max_chars)
        elif isinstance(item, list):
            out[key] = [_clip(part, max_chars) for part in _first(item, 8)]
        else:
            out[key] = _clip(item, max_chars)
    return out


def _compact_risky_operation(risk: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": risk.get("id"),
        "kind": risk.get("kind"),
        "line": risk.get("line"),
        "sink_code": _clip(risk.get("sink_code") or risk.get("code"), 260),
        "input_controlled_values": _first(risk.get("input_controlled_values"), 8),
        "operation_summary": _compact_mapping(risk.get("operation_summary") or {}, 160),
        "operand_roles": _compact_mapping(risk.get("operand_roles") or {}, 160),
        "boundary_facts": _compact_mapping(risk.get("boundary_facts") or {}, 160),
        "existing_guards": [_compact_guard_context(item) for item in _first(risk.get("existing_guards"), 3)],
        "guard_gap": _compact_mapping(risk.get("guard_gap") or {}, 160),
        "missing_property": _clip(risk.get("missing_property") or risk.get("required_property"), 220),
        "dominance_requirement": _clip(risk.get("dominance_requirement"), 220),
        "suggested_patch_operator": risk.get("suggested_patch_operator"),
        "repair_intent": _compact_mapping(risk.get("repair_intent") or {}, 160),
        "required_related_context": _clip(risk.get("required_related_context"), 220),
        "role": risk.get("role"),
        "why_risky": _clip(risk.get("why_risky"), 220),
        "wrong_fix_trap": _clip(risk.get("wrong_fix_trap"), 220),
        "safe_repair_expectation": _clip(risk.get("safe_repair_expectation"), 220),
        "confidence": risk.get("confidence"),
    }


def _compact_typed_buffer_facts(facts: Dict[str, Any]) -> Dict[str, List[str]]:
    if not isinstance(facts, dict):
        return {}
    return {
        "pointer_symbols": [_clip(item, 80) for item in _first(facts.get("pointer_symbols"), 8)],
        "capacity_symbols": [_clip(item, 80) for item in _first(facts.get("capacity_symbols"), 8)],
        "remaining_symbols": [_clip(item, 80) for item in _first(facts.get("remaining_symbols"), 8)],
        "consumed_symbols": [_clip(item, 80) for item in _first(facts.get("consumed_symbols"), 8)],
        "needed_symbols": [_clip(item, 80) for item in _first(facts.get("needed_symbols"), 8)],
    }


def _compact_guard_context(guard: Any) -> Dict[str, Any]:
    if isinstance(guard, dict):
        return {
            "kind": guard.get("kind"),
            "line": guard.get("line"),
            "code": _clip(guard.get("code"), 180),
            "source": guard.get("source"),
        }
    return {"code": _clip(guard, 180)}


def _first(value: Any, limit: int) -> List[Any]:
    if not value:
        return []
    if isinstance(value, list):
        return value[:limit]
    if isinstance(value, tuple):
        return list(value[:limit])
    return [value]


def _clip(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value)
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"
