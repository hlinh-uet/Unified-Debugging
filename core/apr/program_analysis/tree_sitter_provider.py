from typing import Any, Dict, List, Set, Tuple

from core.apr.common import (
    clip_text,
    extract_symbols_from_code,
    node_text,
    parse_tree,
    walk_nodes,
)

from .models import (
    TargetAnalysisRequest,
    TargetOperationAnalysis,
    replacement_language,
    replacement_start_line,
    semantic_names,
)


TREE_SITTER_ENGINE = {
    "name": "tree_sitter_program_analysis",
    "version": 1,
    "provider": "tree_sitter",
    "strategy": "tree_sitter_operation_inventory_with_control_ancestors",
}


def analyze_target_operations_tree_sitter(request: TargetAnalysisRequest) -> TargetOperationAnalysis:
    language = request.language or replacement_language(request.replacement_target)
    tree, source_bytes = parse_tree(request.func_code or "", language)
    if tree is None or source_bytes is None:
        return TargetOperationAnalysis(
            engine={**TREE_SITTER_ENGINE, "available": False},
            operations=[],
            uncertainties=["tree_sitter_parse_failed"],
        )

    semantic = semantic_names(request.related_code_context)
    start_line = replacement_start_line(request.replacement_target)
    operations = []
    seen = set()
    interesting = {
        "return_statement",
        "call_expression",
        "assignment_expression",
        "update_expression",
        "if_statement",
        "switch_statement",
        "conditional_expression",
        "throw_statement",
        "goto_statement",
        "declaration",
        "init_declarator",
    }
    for node in walk_nodes(tree.root_node):
        if node.type not in interesting:
            continue
        code = node_text(node, source_bytes).strip()
        if not code:
            continue
        line = start_line + int(node.start_point[0])
        key = (node.type, line, code[:180])
        if key in seen:
            continue
        seen.add(key)
        symbols = extract_symbols_from_code(code[:3000], language)
        symbol_set = symbol_set_from_symbols(symbols)
        operations.append(
            {
                "id": f"op_{len(operations) + 1}",
                "kind": node.type,
                "line": line,
                "line_end": start_line + int(node.end_point[0]),
                "code": clip_text(code, 700),
                "symbols": {
                    "calls": (symbols.get("calls") or [])[:12],
                    "types": (symbols.get("types") or [])[:8],
                    "fields": (symbols.get("fields") or [])[:12],
                    "identifiers": (symbols.get("identifiers") or [])[:16],
                    "macro_like": (symbols.get("macro_like") or [])[:12],
                },
                "control_ancestors": control_ancestors(node, source_bytes, start_line),
                "semantic_symbols": sorted(symbol_set & semantic)[:16],
                "provider": "tree_sitter",
            }
        )
        if len(operations) >= 80:
            break
    return TargetOperationAnalysis(
        engine={**TREE_SITTER_ENGINE, "available": True},
        operations=rank_target_operations_for_default_view(operations)[:60],
        uncertainties=[],
    )


def symbol_set_from_symbols(symbols: Dict[str, Any]) -> Set[str]:
    out: Set[str] = set()
    for key in ("calls", "types", "fields", "identifiers", "macro_like"):
        out.update(str(item) for item in (symbols.get(key) or []) if str(item).strip())
    return out


def control_ancestors(node, source_bytes: bytes, start_line: int) -> List[dict]:
    ancestors = []
    cur = getattr(node, "parent", None)
    while cur is not None:
        if cur.type in {"if_statement", "switch_statement", "for_statement", "while_statement", "conditional_expression"}:
            text = node_text(cur, source_bytes).strip()
            ancestors.append(
                {
                    "kind": cur.type,
                    "line": start_line + int(cur.start_point[0]),
                    "code": clip_text(control_header(text), 260),
                }
            )
        cur = getattr(cur, "parent", None)
    ancestors.reverse()
    return ancestors[:6]


def control_header(text: str) -> str:
    first = str(text or "").splitlines()[0].strip()
    if "{" in first:
        first = first.split("{", 1)[0].strip()
    return first


def rank_target_operations_for_default_view(operations: List[dict]) -> List[dict]:
    def priority(operation: Dict[str, Any]) -> Tuple[int, int]:
        kind = str(operation.get("kind") or "")
        score = 0
        if kind in {"if_statement", "switch_statement", "conditional_expression"}:
            score += 20
        if kind in {"call_expression", "return_statement"}:
            score += 18
        if kind in {"assignment_expression", "update_expression", "init_declarator", "declaration"}:
            score += 14
        if operation.get("semantic_symbols"):
            score += 10
        if operation.get("control_ancestors"):
            score += 6
        return -score, int(operation.get("line") or 0)

    return sorted(operations, key=priority)
