"""Tree-sitter inventory of source-bound entities inside one exact target."""

from __future__ import annotations

import os
from typing import Any, Dict, List, Tuple

from core.program_analysis.source_utils import parse_tree, walk_nodes

from .models import clip, stable_id
from .syntax_queries import build_target_syntax_ir, syntax_ir_entities


def build_target_inventory(
    target_contract: Dict[str, Any]
) -> Tuple[Dict[str, Any], List[str]]:
    source = str(target_contract.get("replacement_unit") or "")
    language = str(target_contract.get("language") or "c")
    (
        tree, source_bytes, function_node, base_byte, base_line,
        parse_scope, parse_diagnostics,
    ) = (
        _parse_target_function(target_contract, source=source, language=language)
    )
    if tree is None or source_bytes is None:
        return _minimal_inventory(
            target_contract, ["target_inventory_tree_sitter_parse_failed"]
        ), []
    diagnostics = list(parse_diagnostics)
    if tree.root_node.has_error:
        diagnostics.append("target_inventory_tree_sitter_has_error")
    if function_node is None:
        functions = _outer_function_definitions(tree.root_node)
        diagnostics.append(
            f"target_inventory_requires_one_outer_function_definition:found_{len(functions)}"
        )
        return _minimal_inventory(target_contract, diagnostics), []

    syntax_ir, query_diagnostics = build_target_syntax_ir(
        function_node=function_node,
        source_bytes=source_bytes,
        language=language,
        source_path=str(target_contract.get("source_path") or ""),
        base_byte=base_byte,
        base_line=base_line,
    )
    diagnostics.extend(query_diagnostics)
    entities = syntax_ir_entities(
        syntax_ir,
        target_contract=target_contract,
        function_source=str(target_contract.get("replacement_unit") or ""),
    )
    inventory = {
        "version": 3,
        "target_id": target_contract.get("target_id"),
        "source_hash": target_contract.get("source_hash"),
        "source_path": target_contract.get("source_path"),
        "entities": entities,
        "entity_count": len(entities),
        "visible_symbols": list(dict.fromkeys(
            str(value) for value in target_contract.get("visible_symbols") or [] if str(value)
        ))[:128],
        "binding": "tree_sitter_query_target_syntax_ir",
        "parse_scope": parse_scope,
        "syntax_ir": syntax_ir,
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
        "callee_symbol": "",
        "syntax_only": True,
    }
    entity["id"] = stable_id("entity", {
        "type": entity["node_type"],
        "target_id": target_contract.get("target_id"),
        "range": source_range,
    })
    inventory = {
        "version": 3,
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


def _parse_target_function(
    target_contract: Dict[str, Any], *, source: str, language: str
):
    """Prefer the full translation unit so macros/templates retain their context."""
    source_path = os.path.realpath(str(target_contract.get("source_path") or ""))
    target_range = target_contract.get("source_range") or {}
    try:
        target_start = int(target_range.get("start_byte"))
        target_end = int(target_range.get("end_byte"))
    except (TypeError, ValueError):
        target_start = target_end = -1
    if source_path and os.path.isfile(source_path) and target_start >= 0 and target_end > target_start:
        try:
            with open(source_path, "r", encoding="utf-8") as stream:
                full_source = stream.read()
        except (OSError, UnicodeError):
            full_source = ""
        if full_source:
            full_tree, full_bytes = parse_tree(full_source, language)
            if full_tree is not None and full_bytes is not None:
                function = _function_for_exact_range(
                    full_tree.root_node, start_byte=target_start, end_byte=target_end
                )
                if function is not None:
                    diagnostics = []
                    if full_tree.root_node.has_error:
                        diagnostics.append("target_inventory_full_source_tree_sitter_has_error")
                    return full_tree, full_bytes, function, 0, 1, "full_source", diagnostics

    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return None, None, None, 0, 1, "unavailable", []
    functions = _outer_function_definitions(tree.root_node)
    function = functions[0] if len(functions) == 1 else None
    base_line = int(target_range.get("start_line") or 1)
    base_byte = max(0, target_start)
    return (
        tree,
        source_bytes,
        function,
        base_byte,
        base_line,
        "replacement_unit",
        ["target_inventory_used_isolated_replacement_unit"],
    )


def _function_for_exact_range(root, *, start_byte: int, end_byte: int):
    exact = []
    containing = []
    for node in walk_nodes(root):
        if node.type != "function_definition":
            continue
        if int(node.start_byte) == start_byte and int(node.end_byte) == end_byte:
            exact.append(node)
        elif int(node.start_byte) <= start_byte and int(node.end_byte) >= end_byte:
            containing.append(node)
    if len(exact) == 1:
        return exact[0]
    if not exact and containing:
        return min(containing, key=lambda item: int(item.end_byte) - int(item.start_byte))
    return None


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
