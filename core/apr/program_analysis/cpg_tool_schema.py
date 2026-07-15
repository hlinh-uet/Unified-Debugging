"""CPG/fail-context evidence tool definitions and adapters."""

import json
from typing import Any, Dict, List, Optional


_TOOL_METADATA_KEYS = {
    "id",
    "priority",
    "rank",
    "reason",
    "needed_evidence_kind",
    "validates_hypothesis_id",
    "answers_evidence_question_id",
    "answers_evidence_need_id",
}

_DIRECT_ROUTE_REQUIRED = [
    "needed_evidence_kind",
    "validates_hypothesis_id",
    "answers_evidence_question_id",
]

CPG_EVIDENCE_TOOL_NAMES = {
    "get_target_region_evidence",
    "get_control_data_dependencies",
    "get_callers",
    "get_callees",
    "get_symbol_usages",
    "get_type_or_macro_definition",
    "get_semantic_context_bundle",
    "get_behavior_evidence",
    "search_cpg_evidence",
}

CPG_TOOL_KIND_HINTS = {
    "get_behavior_evidence": [
        "caller_context", "callee_definition", "call_argument_flow",
        "control_data_dependency", "target_region", "symbol_usage",
        "method_definition", "type_definition",
    ],
    "get_semantic_context_bundle": [
        "target_operation", "joern_control_data_dependency", "caller_context",
        "direct_callee_context", "usage_example", "method_definition", "type_definition",
    ],
    "get_callers": ["caller_context"],
    "get_callees": ["direct_callee_context", "method_definition", "joern_call_argument_flow"],
    "get_type_or_macro_definition": ["type_definition", "macro_definition", "enum_or_flag_family", "macro_family"],
    "get_control_data_dependencies": [
        "joern_control_data_dependency",
        "target_operation",
        "predicate_condition",
        "joern_call_argument_flow",
        "return_value_flow",
    ],
    "get_target_region_evidence": ["target_operation", "predicate_condition", "numeric_dataflow", "return_value_flow"],
    "get_symbol_usages": [
        "caller_context",
        "direct_callee_context",
        "joern_call_argument_flow",
        "loop_boundary",
        "numeric_dataflow",
        "predicate_condition",
        "return_value_flow",
        "target_operation",
        "usage_example",
    ],
}


def cpg_evidence_tool_specs() -> List[Dict[str, Any]]:
    """Return compact tool descriptions for prompt/debug artifacts."""
    return [
        {
            "tool": item["function"]["name"],
            "args_schema": item["function"].get("parameters") or {},
            "purpose": item["function"].get("description") or "",
        }
        for item in cpg_evidence_tool_definitions()
    ]


def cpg_evidence_tool_definitions() -> List[Dict[str, Any]]:
    """Return OpenAI-compatible tool definitions exposed to the LLM."""
    return [
        _tool(
            "get_behavior_evidence",
            "Execute a typed behavior-evidence batch over the full cached Joern CPG after target-bound information needs are known.",
            {
                "relations": _array("Typed behavior relations to execute."),
                "region_ids": _array("Source-bound information-need IDs."),
                "symbols": _array("Symbols bound to the selected target entities."),
                "limit": _integer("Maximum source-backed results to retrieve."),
                "reason": _string("Which behavior proof obligations this batch answers."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["relations", "reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_semantic_context_bundle",
            "Query one cached Joern CPG bundle containing target slice, dependencies, callers, callees, usages, and definitions.",
            {
                "region_ids": _array("Canonical source-backed target region IDs."),
                "symbols": _array("Visible target symbols and calls."),
                "limit": _integer("Maximum combined results to retrieve."),
                "reason": _string("Why the semantic context bundle is needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_target_region_evidence",
            "Query the cached Joern CPG for target-local operations around regions/symbols.",
            {
                "region_ids": _array("Target causal region IDs."),
                "symbols": _array("Visible symbols to focus on."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why target-local evidence is needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_control_data_dependencies",
            "Query the cached Joern CPG for control/data/reaching-definition/return/argument evidence.",
            {
                "region_ids": _array("Target causal region IDs."),
                "symbols": _array("Variables, calls, returns, or predicates to trace."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Which data/control-flow fact is missing."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_callers",
            "Query the cached Joern CPG for callers of a function/method symbol.",
            {
                "symbol": _string("Function or method symbol to find callers for."),
                "symbols": _array("Optional additional function symbols."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why caller context is needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_callees",
            "Query the cached Joern CPG for callee/helper definitions and call argument flow.",
            {
                "symbol": _string("Callee/helper symbol to inspect."),
                "symbols": _array("Optional additional callee/helper symbols."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why callee contract or argument flow is needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_symbol_usages",
            "Query the cached Joern CPG for same/cross-file usages of a symbol.",
            {
                "symbol": _string("Symbol to search usages for."),
                "symbols": _array("Optional additional symbols."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why symbol usage examples are needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_type_or_macro_definition",
            "Query the cached Joern CPG for struct/type/method definitions; macro-like names may need source fallback.",
            {
                "symbol": _string("Type, macro, enum, or flag symbol to inspect."),
                "symbols": _array("Optional additional type/macro symbols."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why type/macro meaning is needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "search_cpg_evidence",
            "Run a broad cached Joern CPG search when narrower CPG tools do not cover the need.",
            {
                "query": _string("Natural-language evidence need."),
                "kinds": _array("Optional CPG result kinds."),
                "symbols": _array("Optional symbols to focus on."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why broad CPG search is needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["query", "reason", *_DIRECT_ROUTE_REQUIRED],
        ),
        _tool(
            "get_fail_context_runtime_facts",
            "Load runtime-facing facts already captured in fail context/test source; this does not execute code.",
            {
                "query": _string("Natural-language runtime fact needed from failing tests."),
                "expressions": _array("Expressions or values to look for in fail context/test source."),
                "test_ids": _array("Optional failing test IDs."),
                "limit": _integer("Maximum results to retrieve."),
                "reason": _string("Why fail-context runtime facts are needed."),
                "needed_evidence_kind": _evidence_kind(),
                "validates_hypothesis_id": _string("Hypothesis ID this evidence validates."),
                "answers_evidence_question_id": _string("Evidence question ID this answers."),
                "answers_evidence_need_id": _string("Evidence need ID this answers."),
            },
            ["query", "reason", *_DIRECT_ROUTE_REQUIRED],
        ),
    ]


def normalize_cpg_tool_requests(
    parsed: Optional[Dict[str, Any]],
    tool_calls: Optional[List[Dict[str, Any]]] = None,
) -> List[Dict[str, Any]]:
    """Normalize real tool_calls first, then fall back to JSON protocol requests."""
    parsed = parsed if isinstance(parsed, dict) else {}
    needs_by_id = {
        str(item.get("id")): item
        for item in parsed.get("evidence_needs") or []
        if isinstance(item, dict) and item.get("id")
    }
    raw_requests = _requests_from_tool_calls(tool_calls or [])
    if not raw_requests:
        raw_requests = parsed.get("tool_requests") or parsed.get("tools") or []
    out = []
    for idx, raw in enumerate(raw_requests, start=1):
        normalized = _normalize_one_tool_request(raw, idx=idx, needs_by_id=needs_by_id)
        if normalized and _has_direct_evidence_route(normalized):
            out.append(normalized)
    out.sort(key=_tool_request_order_key)
    return out[:8]


def _has_direct_evidence_route(request: Dict[str, Any]) -> bool:
    """Reject broad tool calls that are not tied to a hypothesis and question."""
    return bool(
        str(request.get("needed_evidence_kind") or "").strip()
        and str(request.get("validates_hypothesis_id") or "").strip()
        and str(request.get("answers_evidence_question_id") or "").strip()
    )


def _requests_from_tool_calls(tool_calls: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Convert provider tool_calls into the internal evidence request shape."""
    out = []
    for idx, call in enumerate(tool_calls or [], start=1):
        if not isinstance(call, dict):
            continue
        function = call.get("function") if isinstance(call.get("function"), dict) else {}
        name = str(function.get("name") or call.get("name") or "").strip()
        raw_args = function.get("arguments", call.get("arguments", {}))
        args = _parse_tool_arguments(raw_args)
        out.append(
            {
                "id": call.get("id") or f"tool_call_{idx}",
                "tool": name,
                "args": args,
                **{key: args.get(key) for key in _TOOL_METADATA_KEYS if key in args},
            }
        )
    return out


def _normalize_one_tool_request(
    raw: Any,
    *,
    idx: int,
    needs_by_id: Dict[str, Dict[str, Any]],
) -> Optional[Dict[str, Any]]:
    if not isinstance(raw, dict):
        return None
    allowed = {item["function"]["name"] for item in cpg_evidence_tool_definitions()}
    tool = str(raw.get("tool") or raw.get("name") or "").strip()
    if tool not in allowed:
        return None
    raw_args = raw.get("args") if isinstance(raw.get("args"), dict) else {}
    args = {
        key: value
        for key, value in raw_args.items()
        if key not in _TOOL_METADATA_KEYS
    }
    need_id = _clip(raw.get("answers_evidence_need_id") or raw_args.get("answers_evidence_need_id"), 80)
    need = needs_by_id.get(need_id) if need_id else {}
    needed_kind = (
        raw.get("needed_evidence_kind")
        or raw_args.get("needed_evidence_kind")
        or (need.get("needed_evidence_kind") if isinstance(need, dict) else "")
    )
    reason = raw.get("reason") or raw_args.get("reason") or raw.get("purpose")
    return {
        "id": str(raw.get("id") or f"tool_req_{idx}"),
        "tool": tool,
        "args": args,
        "priority": _optional_int(raw.get("priority") or raw_args.get("priority")),
        "rank": _optional_int(raw.get("rank") or raw_args.get("rank")),
        "needed_evidence_kind": _clip(needed_kind, 120),
        "reason": _clip(reason, 500),
        "validates_hypothesis_id": _clip(
            raw.get("validates_hypothesis_id")
            or raw_args.get("validates_hypothesis_id")
            or (need.get("hypothesis_id") if isinstance(need, dict) else ""),
            80,
        ),
        "answers_evidence_question_id": _clip(
            raw.get("answers_evidence_question_id")
            or raw_args.get("answers_evidence_question_id")
            or (need.get("evidence_question_id") if isinstance(need, dict) else ""),
            80,
        ),
        "answers_evidence_need_id": need_id,
    }


def _tool_request_order_key(request: Dict[str, Any]) -> tuple:
    rank = request.get("rank")
    priority = request.get("priority")
    if isinstance(rank, int):
        return (0, rank)
    if isinstance(priority, int):
        return (1, -priority)
    return (2, 0)


def _optional_int(value: Any) -> Optional[int]:
    if value is None or value == "":
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _parse_tool_arguments(value: Any) -> Dict[str, Any]:
    if isinstance(value, dict):
        return value
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except ValueError:
            return {"query": value}
        return parsed if isinstance(parsed, dict) else {}
    return {}


def _tool(name: str, description: str, properties: Dict[str, Any], required: List[str]) -> Dict[str, Any]:
    properties = {
        **properties,
        "rank": _integer("Optional request rank. Lower numbers run first when more than 6 requests are returned."),
        "priority": _integer("Optional request priority. Higher numbers run first when rank is absent."),
    }
    return {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }


def _string(description: str) -> Dict[str, Any]:
    return {"type": "string", "description": description}


def _array(description: str) -> Dict[str, Any]:
    return {
        "type": "array",
        "items": {"type": "string"},
        "description": description,
    }


def _integer(description: str) -> Dict[str, Any]:
    return {
        "type": "integer",
        "description": description,
        "minimum": 1,
        "maximum": 40,
    }


def _evidence_kind() -> Dict[str, Any]:
    return {
        "type": "string",
        "description": "Kind of evidence this request is meant to retrieve.",
        "enum": [
            "target_region_evidence",
            "return_data_flow",
            "same_file_idiom",
            "callee_contract",
            "caller_contract",
            "symbol_usage",
            "type_or_macro_definition",
            "fail_context_runtime_fact",
        ],
    }


def _clip(value: Any, limit: int) -> str:
    text = str(value or "")
    if len(text) <= limit:
        return text
    return text[:limit] + "\n...[truncated]"
