"""Declarative Tree-sitter query adapter for target-local syntax anchors."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List, Tuple

try:
    from tree_sitter import Query, QueryCursor
except ImportError:  # pragma: no cover - reported through diagnostics
    Query = QueryCursor = None

from core.program_analysis.source_utils import node_text, tree_sitter_language

from .models import clip, stable_id


QUERY_ROOT = Path(__file__).with_name("queries")
PRIMARY_CAPTURES = {
    "target.parameter": "parameter",
    "declaration": "declaration",
    "call": "call",
    "assignment": "assignment",
    "update": "update",
    "return": "return",
    "control.if": "branch",
    "control.switch": "branch",
    "control.conditional": "conditional",
}


def build_target_syntax_ir(
    *, function_node, source_bytes: bytes, language: str,
    source_path: str, base_byte: int, base_line: int,
) -> Tuple[Dict[str, Any], List[str]]:
    """Execute the language query only within the exact target function node."""
    grammar = "cpp" if str(language).lower() in {"cpp", "c++", "cc", "cxx"} else "c"
    query_path = QUERY_ROOT / grammar / "target_syntax.scm"
    if Query is None or QueryCursor is None:
        return _empty_ir(source_path, grammar), ["tree_sitter_query_api_unavailable"]
    lang = tree_sitter_language(language)
    if lang is None:
        return _empty_ir(source_path, grammar), [f"tree_sitter_{grammar}_grammar_unavailable"]
    try:
        query_source = query_path.read_text(encoding="utf-8")
        query = Query(lang, query_source)
        matches = QueryCursor(query).matches(function_node)
    except Exception as exc:
        return _empty_ir(source_path, grammar), [
            f"tree_sitter_target_query_failed:{type(exc).__name__}"
        ]

    records: List[Dict[str, Any]] = []
    for _, captures in matches:
        primary = next(
            (
                (capture, kind, nodes[0])
                for capture, kind in PRIMARY_CAPTURES.items()
                for nodes in [captures.get(capture) or []]
                if nodes
            ),
            None,
        )
        if primary is None:
            continue
        capture, kind, node = primary
        record = _syntax_record(
            node=node,
            kind=kind,
            capture=capture,
            captures=captures,
            source_bytes=source_bytes,
            base_byte=base_byte,
            base_line=base_line,
        )
        records.append(record)
    records = _deduplicate(records)
    return {
        "version": 1,
        "provider": "tree_sitter_query",
        "grammar": grammar,
        "query": str(query_path.relative_to(QUERY_ROOT.parent)),
        "source_path": source_path,
        "target_range": _range(function_node, base_byte=base_byte, base_line=base_line),
        "records": records,
        "record_count": len(records),
        "semantic_resolution": "none",
    }, []


def syntax_ir_entities(
    syntax_ir: Dict[str, Any], *, target_contract: Dict[str, Any], function_source: str
) -> List[Dict[str, Any]]:
    """Compatibility projection; fields remain syntactic and make no def/use claims."""
    target = {
        "id": stable_id("syntax_entity", {
            "kind": "target_function",
            "range": syntax_ir.get("target_range") or {},
        }),
        "node_type": "function_definition",
        "kind": "target_function",
        "source_range": syntax_ir.get("target_range") or {},
        "source_excerpt": clip(function_source, 280),
        "symbols": [
            str(target_contract.get("resolved_name") or "").rsplit("::", 1)[-1]
        ],
        "declared_symbols": [],
        "syntax_only": True,
    }
    entities = [target]
    for record in syntax_ir.get("records") or []:
        if not isinstance(record, dict):
            continue
        entity = {
            "id": record.get("id"),
            "node_type": record.get("node_type"),
            "kind": record.get("kind"),
            "source_range": record.get("source_range") or {},
            "source_excerpt": record.get("source_excerpt") or "",
            "symbols": record.get("identifiers") or [],
            "declared_symbols": record.get("declared_names") or [],
            "callee_symbol": record.get("callee_text") or "",
            "arguments": record.get("arguments") or [],
            "name_range": record.get("name_range") or {},
            "condition": record.get("condition") or "",
            "write_target": record.get("write_target") or "",
            "value_expression": record.get("value_expression") or "",
            "syntax_only": True,
        }
        entities.append(entity)
    return entities


def _syntax_record(
    *, node, kind: str, capture: str, captures: Dict[str, List[Any]],
    source_bytes: bytes, base_byte: int, base_line: int,
) -> Dict[str, Any]:
    names = _declared_names(node, source_bytes) if kind in {"declaration", "parameter"} else []
    function_node = _capture_node(captures, "call.function")
    arguments_node = _capture_node(captures, "call.arguments")
    condition_node = _capture_node(captures, "control.condition")
    assignment_left = _capture_node(captures, "assignment.left")
    assignment_right = _capture_node(captures, "assignment.right")
    update_target = None
    if kind == "update":
        update_target = node.child_by_field_name("argument")
        if update_target is None and node.named_children:
            update_target = node.named_children[0]
    write_target = assignment_left if assignment_left is not None else update_target
    identifiers = _identifier_texts(node, source_bytes)
    source_range = _range(node, base_byte=base_byte, base_line=base_line)
    payload = {
        "kind": kind,
        "capture": capture,
        "node_type": node.type,
        "source_range": source_range,
        "source_excerpt": clip(node_text(node, source_bytes).strip(), 400),
        "identifiers": identifiers[:20],
        "declared_names": names[:8],
        "callee_text": (
            node_text(function_node, source_bytes).strip() if function_node is not None else ""
        ),
        "name_range": (
            _range(function_node, base_byte=base_byte, base_line=base_line)
            if function_node is not None else {}
        ),
        "arguments": [
            node_text(child, source_bytes).strip()
            for child in (arguments_node.named_children if arguments_node is not None else [])
            if node_text(child, source_bytes).strip()
        ][:12],
        "condition": (
            clip(node_text(condition_node, source_bytes).strip(), 240)
            if condition_node is not None else ""
        ),
        "write_target": (
            clip(node_text(write_target, source_bytes).strip(), 240)
            if write_target is not None else ""
        ),
        "value_expression": (
            clip(node_text(assignment_right, source_bytes).strip(), 240)
            if assignment_right is not None else ""
        ),
    }
    payload["id"] = stable_id("syntax_entity", {
        "kind": kind,
        "range": source_range,
    })
    return payload


def _range(node, *, base_byte: int, base_line: int) -> Dict[str, int]:
    return {
        "start_byte": base_byte + int(node.start_byte),
        "end_byte": base_byte + int(node.end_byte),
        "start_line": base_line + int(node.start_point[0]),
        "end_line": base_line + int(node.end_point[0]),
        "start_column": int(node.start_point[1]),
        "end_column": int(node.end_point[1]),
    }


def _capture_node(captures: Dict[str, List[Any]], name: str):
    values = captures.get(name) or []
    return values[0] if values else None


def _declared_names(node, source_bytes: bytes) -> List[str]:
    declarators = []
    if node.type in {"parameter_declaration", "optional_parameter_declaration"}:
        declarator = node.child_by_field_name("declarator")
        if declarator is not None:
            declarators.append(declarator)
    else:
        for child in node.named_children:
            declarator = (
                child.child_by_field_name("declarator")
                if child.type == "init_declarator" else child
            )
            if declarator is not None:
                declarators.append(declarator)
    names = []
    for declarator in declarators:
        candidates = [
            item for item in _walk(declarator)
            if item.type in {"identifier", "field_identifier"}
        ]
        if candidates:
            value = node_text(candidates[-1], source_bytes).strip()
            if value and value not in names:
                names.append(value)
    return names


def _identifier_texts(node, source_bytes: bytes) -> List[str]:
    values = []
    for item in _walk(node):
        if item.type not in {
            "identifier", "field_identifier", "namespace_identifier", "type_identifier"
        }:
            continue
        value = node_text(item, source_bytes).strip()
        if value and value not in values:
            values.append(value)
    return values


def _walk(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.named_children))


def _deduplicate(records: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for record in records:
        marker = str(record.get("id") or "")
        if not marker or marker in seen:
            continue
        seen.add(marker)
        out.append(record)
    out.sort(key=lambda item: (
        int((item.get("source_range") or {}).get("start_byte") or 0),
        str(item.get("kind") or ""),
    ))
    return out


def _empty_ir(source_path: str, grammar: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "provider": "tree_sitter_query",
        "grammar": grammar,
        "source_path": source_path,
        "records": [],
        "record_count": 0,
        "semantic_resolution": "none",
    }
