"""Tree-sitter inventory of source-bound entities inside one exact target."""

from __future__ import annotations

from typing import Any, Dict, List, Tuple

from core.apr.common import node_text, parse_tree, walk_nodes

from .models import clip, stable_id


OPERATION_KINDS = {
    "assignment_expression": "assignment",
    "call_expression": "call",
    "conditional_expression": "conditional",
    "field_expression": "field_access",
    "if_statement": "branch",
    "return_statement": "return",
    "subscript_expression": "subscript",
    "switch_statement": "branch",
    "update_expression": "update",
}

ENTITY_KINDS = {
    "declaration": "declaration",
    "parameter_declaration": "parameter",
}

SYMBOL_NODE_TYPES = {
    "field_identifier",
    "identifier",
    "namespace_identifier",
    "type_identifier",
}


def build_target_inventory(
    target_contract: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    source = str(target_contract.get("replacement_unit") or "")
    language = str(target_contract.get("language") or "c")
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return _minimal_inventory(
            target_contract, ["target_inventory_tree_sitter_parse_failed"]
        ), []
    diagnostics = []
    if tree.root_node.has_error:
        diagnostics.append("target_inventory_tree_sitter_has_error")
    functions = _outer_function_definitions(tree.root_node)
    if len(functions) != 1:
        diagnostics.append(
            f"target_inventory_requires_one_outer_function_definition:found_{len(functions)}"
        )
        return _minimal_inventory(target_contract, diagnostics), []

    base_range = target_contract.get("source_range") or {}
    base_byte = int(base_range.get("start_byte") or 0)
    base_line = int(base_range.get("start_line") or 1)
    function_node = functions[0]
    function_body = function_node.child_by_field_name("body")
    root_symbols = _symbols(function_node, source_bytes)
    entities: List[Dict[str, Any]] = [
        _entity(
            node=function_node,
            source_bytes=source_bytes,
            base_byte=base_byte,
            base_line=base_line,
            kind="target_function",
            symbols=list(dict.fromkeys([
                str(target_contract.get("resolved_name") or "").rsplit("::", 1)[-1],
                *root_symbols,
            ])),
        )
    ]
    for node in _walk_without_nested_functions(function_node):
        kind = OPERATION_KINDS.get(node.type) or ENTITY_KINDS.get(node.type)
        if not kind:
            continue
        if kind in {"declaration", "parameter"} and not _is_target_declaration(
            node, root=function_node, function_body=function_body
        ):
            continue
        entities.append(
            _entity(
                node=node,
                source_bytes=source_bytes,
                base_byte=base_byte,
                base_line=base_line,
                kind=kind,
                symbols=_symbols(node, source_bytes),
                declared_symbols=_declared_symbols(node, source_bytes),
            )
        )
    entities = _dedup_entities(entities)
    inventory = {
        "version": 1,
        "target_id": target_contract.get("target_id"),
        "source_hash": target_contract.get("source_hash"),
        "source_path": target_contract.get("source_path"),
        "entities": entities,
        "entity_count": len(entities),
        "visible_symbols": list(dict.fromkeys(
            str(value) for value in target_contract.get("visible_symbols") or [] if str(value)
        ))[:128],
        "binding": "tree_sitter_target_local_ast_entities",
        "diagnostics": diagnostics,
        "fallback_policy": "minimal_exact_target" if diagnostics else "none",
    }
    inventory["inventory_id"] = stable_id("inventory", {
        "target_id": inventory["target_id"],
        "source_hash": inventory["source_hash"],
        "entities": [item["id"] for item in entities],
    })
    return inventory, []


def _minimal_inventory(
    target_contract: Dict[str, Any], diagnostics: List[str]
) -> Dict[str, Any]:
    """Keep an exact source anchor when isolated AST enrichment is unavailable."""
    source_range = dict(target_contract.get("source_range") or {})
    leaf = str(target_contract.get("resolved_name") or "").rsplit("::", 1)[-1]
    symbols = list(dict.fromkeys([
        leaf,
        *(str(value) for value in target_contract.get("visible_symbols") or []),
    ]))
    entity = {
        "node_type": "exact_source_target",
        "kind": "target_function",
        "source_range": source_range,
        "source_excerpt": clip(target_contract.get("replacement_unit"), 280),
        "symbols": [value for value in symbols if value][:20],
        "declared_symbols": [],
    }
    entity["id"] = stable_id("entity", {
        "type": entity["node_type"],
        "target_id": target_contract.get("target_id"),
        "range": source_range,
    })
    inventory = {
        "version": 1,
        "target_id": target_contract.get("target_id"),
        "source_hash": target_contract.get("source_hash"),
        "source_path": target_contract.get("source_path"),
        "entities": [entity],
        "entity_count": 1,
        "visible_symbols": [
            str(value) for value in target_contract.get("visible_symbols") or [] if str(value)
        ][:128],
        "binding": "exact_target_source_minimal_inventory",
        "diagnostics": list(dict.fromkeys(str(item) for item in diagnostics if str(item))),
        "fallback_policy": "minimal_exact_target",
    }
    inventory["inventory_id"] = stable_id("inventory", {
        "target_id": inventory["target_id"],
        "source_hash": inventory["source_hash"],
        "entities": [entity["id"]],
    })
    return inventory


def _entity(
    *, node, source_bytes: bytes, base_byte: int, base_line: int, kind: str,
    symbols: List[str], declared_symbols: List[str] = None
) -> Dict[str, Any]:
    absolute_start = base_byte + int(node.start_byte)
    absolute_end = base_byte + int(node.end_byte)
    payload = {
        "node_type": node.type,
        "kind": kind,
        "source_range": {
            "start_byte": absolute_start,
            "end_byte": absolute_end,
            "start_line": base_line + int(node.start_point[0]),
            "end_line": base_line + int(node.end_point[0]),
        },
        "source_excerpt": clip(node_text(node, source_bytes), 280),
        "symbols": list(dict.fromkeys(value for value in symbols if value))[:20],
        "declared_symbols": list(dict.fromkeys(
            value for value in declared_symbols or [] if value
        ))[:8],
    }
    payload["id"] = stable_id("entity", {
        "type": node.type,
        "start": absolute_start,
        "end": absolute_end,
    })
    return payload


def _is_target_declaration(node, *, root, function_body) -> bool:
    if node.type == "parameter_declaration":
        return function_body is not None and int(node.end_byte) <= int(function_body.start_byte)
    parent = node.parent
    while parent is not None and parent is not root:
        if parent.type in {"struct_specifier", "class_specifier", "union_specifier"}:
            return False
        parent = parent.parent
    return True


def _declared_symbols(node, source_bytes: bytes) -> List[str]:
    if node.type == "parameter_declaration":
        declarator = node.child_by_field_name("declarator")
        name = _declarator_name(declarator, source_bytes)
        return [name] if name else []
    values = []
    for child in node.named_children:
        candidate = child.child_by_field_name("declarator") if child.type == "init_declarator" else child
        name = _declarator_name(candidate, source_bytes)
        if name and name not in values:
            values.append(name)
    return values


def _declarator_name(node, source_bytes: bytes) -> str:
    if node is None:
        return ""
    if node.type in {"identifier", "field_identifier"}:
        return node_text(node, source_bytes).strip()
    nested = node.child_by_field_name("declarator")
    if nested is not None:
        name = _declarator_name(nested, source_bytes)
        if name:
            return name
    if node.type in {
        "pointer_declarator", "reference_declarator", "array_declarator",
        "function_declarator", "parenthesized_declarator", "init_declarator",
    }:
        for child in node.named_children:
            if child.type in {"argument_list", "initializer_list", "parameter_list"}:
                continue
            name = _declarator_name(child, source_bytes)
            if name:
                return name
    return ""


def _symbols(node, source_bytes: bytes) -> List[str]:
    values = []
    for child in walk_nodes(node):
        if child.type not in SYMBOL_NODE_TYPES:
            continue
        value = node_text(child, source_bytes).strip()
        if value and value not in values:
            values.append(value)
    return values[:20]


def _dedup_entities(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for value in values:
        marker = value.get("id")
        if marker in seen:
            continue
        seen.add(marker)
        out.append(value)
    return out


def _outer_function_definitions(root):
    """Enumerate outer functions while structurally pruning every function body."""
    functions = []
    stack = [root]
    while stack:
        node = stack.pop()
        if node.type == "function_definition":
            functions.append(node)
            continue
        stack.extend(reversed(node.children))
    return functions


def _walk_without_nested_functions(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        children = [] if node is not root and node.type == "function_definition" else list(node.children)
        stack.extend(reversed(children))
