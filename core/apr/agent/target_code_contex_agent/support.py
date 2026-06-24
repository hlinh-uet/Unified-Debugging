"""Shared constants and helpers for TargetCodeContext analysis."""

import re
from typing import Any, Dict, List, Optional, Set, Tuple

from core.apr.agent.context_common import (
    clip_text,
    dedup_keep_order,
    extract_symbols_from_code,
    line_number_for_byte,
    node_text,
)

MAX_STATEMENT_TEXT = 900
MAX_STATEMENTS = 120
MAX_STRUCTURAL_REGIONS = 80
MAX_EXPRESSIONS = 160
MAX_CFG_EDGES = 220
MAX_REPAIR_SITES = 8
MAX_FAILURE_SLICES = 8
MAX_REPAIR_ATOMS = 12

STATEMENT_NODE_TYPES = {
    "if_statement",
    "for_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "case_statement",
    "return_statement",
    "expression_statement",
    "declaration",
    "goto_statement",
    "break_statement",
    "continue_statement",
    "labeled_statement",
}

EXPRESSION_NODE_TYPES = {
    "assignment_expression",
    "binary_expression",
    "unary_expression",
    "update_expression",
    "conditional_expression",
    "call_expression",
    "subscript_expression",
    "field_expression",
    "pointer_expression",
    "parenthesized_expression",
    "init_declarator",
    "initializer_list",
    "field_initializer",
    "identifier",
    "field_identifier",
    "statement_identifier",
    "string_literal",
    "char_literal",
    "number_literal",
    "true",
    "false",
    "null",
    "nullptr",
}

REGION_NODE_TYPES = {
    "if_statement",
    "else_clause",
    "for_statement",
    "while_statement",
    "do_statement",
    "switch_statement",
    "case_statement",
}

IDENTIFIER_NODE_TYPES = {
    "identifier",
    "field_identifier",
    "statement_identifier",
}

LITERAL_NODE_TYPES = {
    "string_literal",
    "char_literal",
    "number_literal",
    "true",
    "false",
    "null",
    "nullptr",
}

KEYWORDS = {
    "if",
    "for",
    "while",
    "do",
    "switch",
    "case",
    "default",
    "else",
    "return",
    "sizeof",
    "goto",
    "break",
    "continue",
    "static",
    "const",
    "volatile",
    "struct",
    "class",
    "enum",
    "union",
    "void",
    "int",
    "char",
    "short",
    "long",
    "float",
    "double",
    "signed",
    "unsigned",
    "bool",
    "true",
    "false",
    "NULL",
    "nullptr",
}

# Tìm statement nhỏ nhất bao quanh byte range của một atom.
def _statement_for_atom(start_byte: int, end_byte: int, statements: List[dict]) -> Optional[dict]:
    best = None
    best_span = 10**18
    for statement in statements:
        stmt_start = statement.get("start_byte")
        stmt_end = statement.get("end_byte")
        if not isinstance(stmt_start, int) or not isinstance(stmt_end, int):
            continue
        if stmt_start <= start_byte and end_byte <= stmt_end:
            span = stmt_end - stmt_start
            if span < best_span:
                best = statement
                best_span = span
    return best

# Kiểm tra node con có phải field condition của if/while/for/switch không.
def _is_condition_field(parent, child) -> bool:
    if getattr(parent, "type", "") not in {"if_statement", "while_statement", "for_statement", "switch_statement"}:
        return False
    return _is_named_field(parent, "condition", child)

# So khớp node con với named field của tree-sitter parent.
def _is_named_field(parent, field_name: str, child) -> bool:
    try:
        field = parent.child_by_field_name(field_name)
    except Exception:
        field = None
    return field is not None and _node_key(field) == _node_key(child)

# Kiểm tra node có nằm trong condition ancestor hay không.
def _node_has_condition_ancestor(node) -> bool:
    cur = node
    while getattr(cur, "parent", None) is not None:
        parent = cur.parent
        if _is_condition_field(parent, cur):
            return True
        cur = parent
    return False

# Kiểm tra node có nằm trong biểu thức bitwise OR, thường là flag/macro combination.
def _node_has_bitwise_or_ancestor(node, source_bytes: bytes) -> bool:
    cur = node
    while getattr(cur, "parent", None) is not None:
        parent = cur.parent
        if getattr(parent, "type", "") == "binary_expression":
            text = node_text(parent, source_bytes)
            if text and "|" in text:
                return True
        cur = parent
    return False

# Phát hiện atom condition chứa assignment để downrank vì dễ gây sửa quá rộng.
def _atom_has_assignment_churn(text: str) -> bool:
    return bool(re.search(r"(?<![=!<>])=(?!=)", text or ""))

# Tóm tắt symbol/literal có trong atom để giải thích điểm và đối chiếu failure terms.
def _atom_symbol_summary(text: str, language: str) -> Dict[str, List[str]]:
    symbols = extract_symbols_from_code(text or "", language)
    return {
        "calls": (symbols.get("calls") or [])[:8],
        "identifiers": (symbols.get("identifiers") or [])[:12],
        "fields": (symbols.get("fields") or [])[:8],
        "macro_like": (symbols.get("macro_like") or [])[:12],
        "literals": re.findall(r'"[^"\n]{0,120}"|\'[^\'\n]{0,80}\'|\b\d+(?:\.\d+)?\b', text or "")[:8],
    }

# Tạo control edges xấp xỉ khi AST enclosing regions không đủ thông tin.
def _fallback_control_edges(statements: List[dict]) -> List[dict]:
    edges = []
    branches = [
        statement
        for statement in statements
        if statement.get("kind") in {"if_statement", "switch_statement", "case_statement", "loop_statement"}
        or _has_any_signal(statement, {"branch_or_loop"})
    ]
    for statement in statements:
        if statement.get("enclosing_regions"):
            continue
        line = statement.get("line") or 0
        for branch in reversed(branches):
            branch_line = branch.get("line") or 0
            branch_end = branch.get("end_line") or branch_line
            if branch_line < line <= branch_end + 8:
                edges.append(
                    {
                        "from": branch.get("id"),
                        "to": statement.get("id"),
                        "kind": "approx_control_dependency",
                        "condition": branch.get("text", ""),
                    }
                )
                break
    return edges

# Loại edge trùng trong dependence graph.
def _dedup_edges(edges: List[dict]) -> List[dict]:
    out = []
    seen = set()
    for edge in edges:
        key = (
            edge.get("from"),
            edge.get("to"),
            edge.get("kind"),
            edge.get("symbol", ""),
            edge.get("condition", ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(edge)
    return out

# Tìm branch gần nhất đứng trước một statement, thường dùng cho error-path invariant.
def _nearest_preceding_branch(statement: dict, statements: List[dict]) -> Optional[dict]:
    line = statement.get("line") or 0
    best = None
    for candidate in statements:
        cand_line = candidate.get("line") or 0
        if cand_line >= line:
            continue
        if candidate.get("kind") in {"if_statement", "switch_statement", "case_statement", "loop_statement"} or _has_any_signal(candidate, {"branch_or_loop"}):
            if line - cand_line <= 10:
                best = candidate
    return best

# Tính byte/line range phần signature để đóng băng khỏi các sửa đổi không cần thiết.
def _signature_range(
    *,
    replacement_unit: str,
    replacement_start: int,
    source_code: str,
) -> Dict[str, Any]:
    brace = replacement_unit.find("{")
    if brace < 0:
        brace = min(len(replacement_unit), 240)
    end_byte = replacement_start + len(replacement_unit[: brace + 1].encode("utf-8"))
    return {
        "line_range": [
            line_number_for_byte(source_code, replacement_start),
            line_number_for_byte(source_code, end_byte),
        ],
        "byte_range": [replacement_start, end_byte],
    }

# Lấy text condition từ AST node branch/loop/case.
def _condition_text(node, source_bytes: bytes) -> str:
    try:
        condition = node.child_by_field_name("condition")
    except Exception:
        condition = None
    if condition is not None:
        return node_text(condition, source_bytes).strip()
    for child in node.children:
        if child.type == "parenthesized_expression":
            return node_text(child, source_bytes).strip()
    if node.type == "case_statement":
        text = node_text(node, source_bytes).strip()
        return text.split(":", 1)[0].strip()
    return ""

# Lấy header một dòng đại diện cho structural region.
def _region_header(node, source_bytes: bytes) -> str:
    text = node_text(node, source_bytes).strip()
    if "\n" in text:
        return text.splitlines()[0].strip()
    return text

# Chuẩn hóa tree-sitter node type thành loại region dễ đọc.
def _region_kind(node) -> str:
    if node.type == "if_statement":
        return "if"
    if node.type == "else_clause":
        return "else"
    if node.type in {"for_statement", "while_statement", "do_statement"}:
        return "loop"
    if node.type == "switch_statement":
        return "switch"
    if node.type == "case_statement":
        return "case"
    return node.type

# Tạo khóa ổn định cho AST node dựa trên byte range và type.
def _node_key(node) -> Tuple[int, int, str]:
    return node.start_byte, node.end_byte, node.type

# Tìm structural region gần nhất bao quanh một AST node.
def _nearest_region(node, region_by_node_key: Dict[Tuple[int, int, str], dict]) -> Optional[dict]:
    cur = node
    while cur is not None:
        region = region_by_node_key.get(_node_key(cur))
        if region:
            return region
        cur = getattr(cur, "parent", None)
    return None

# Thu thập id các region bao quanh node theo thứ tự ngoài vào trong.
def _enclosing_region_ids(node, region_by_node_key: Dict[Tuple[int, int, str], dict]) -> List[str]:
    ids = []
    cur = node
    while cur is not None:
        region = region_by_node_key.get(_node_key(cur))
        if region and region.get("id"):
            ids.append(region["id"])
        cur = getattr(cur, "parent", None)
    return list(reversed(ids))

# Rút gọn structural region để đưa vào artifact/prompt.
def _compact_region(region: dict) -> dict:
    return {
        "id": region.get("id"),
        "kind": region.get("kind"),
        "line_start": region.get("line_start"),
        "line_end": region.get("line_end"),
        "condition": region.get("condition"),
        "condition_variables": region.get("condition_variables") or [],
        "parent_region_id": region.get("parent_region_id", ""),
    }

# Rút gọn statement, tùy chọn kèm facts reads/writes/calls.
def _compact_statement(statement: dict, include_facts: bool = False) -> dict:
    data = {
        "id": statement.get("id"),
        "line": statement.get("line"),
        "end_line": statement.get("end_line"),
        "kind": statement.get("kind"),
        "text": statement.get("text"),
        "signals": statement.get("signals") or [],
    }
    if include_facts:
        data.update(
            {
                "reads": statement.get("reads") or [],
                "writes": statement.get("writes") or [],
                "calls": statement.get("calls") or [],
                "enclosing_conditions": statement.get("enclosing_conditions") or [],
            }
        )
    return data

# Rút gọn dependency statement và giữ dependency_kind.
def _compact_dependency(statement: dict) -> dict:
    data = _compact_statement(statement, include_facts=True)
    data["dependency_kind"] = statement.get("dependency_kind", "")
    return data

# Tạo line reference ngắn cho summary mapping.
def _line_ref(statement: dict) -> dict:
    return {
        "statement_id": statement.get("id"),
        "line": statement.get("line"),
        "kind": statement.get("kind"),
        "text": clip_text(statement.get("text") or "", 220),
    }

# Giới hạn số key/value của mapping để artifact không phình token.
def _limit_mapping(mapping: Dict[str, List[dict]], max_keys: int, max_values: int) -> Dict[str, List[dict]]:
    out = {}
    for key in sorted(mapping.keys())[:max_keys]:
        out[key] = mapping[key][:max_values]
    return out

# Kiểm tra statement có chứa ít nhất một signal mong muốn không.
def _has_any_signal(statement: dict, names: Set[str]) -> bool:
    return bool(set(statement.get("signals") or []) & set(names))

# Tách identifier từ text sau khi bỏ literal để tránh nhiễu.
def _identifiers_from_text(text: str) -> List[str]:
    identifiers = []
    scrubbed = _strip_quoted_literals(str(text or ""))
    for token in re.findall(r"\b[A-Za-z_][A-Za-z0-9_]*\b", scrubbed):
        if _is_identifier_like(token):
            identifiers.append(token)
    return dedup_keep_order(identifiers)

# Xóa string/char literal trước khi trích identifier.
def _strip_quoted_literals(text: str) -> str:
    return re.sub(r'"(?:\\.|[^"\\])*"|\'(?:\\.|[^\'\\])*\'', " ", text)

# Trích identifier ở vế trái assignment trong fallback regex.
def _assignment_lhs_from_text(text: str) -> List[str]:
    match = re.match(r"\s*([A-Za-z_][A-Za-z0-9_]*(?:\s*(?:->|\.)\s*[A-Za-z_][A-Za-z0-9_]*)?)\s*(?:=|\+=|-=|\*=|/=|%=)", text)
    if not match:
        return []
    return _identifiers_from_text(match.group(1))[:4]

# Kiểm tra token có phải identifier hợp lệ và không phải keyword C/C++.
def _is_identifier_like(value: str) -> bool:
    text = str(value or "").strip()
    if not re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text):
        return False
    return text not in KEYWORDS

# Nhận diện tên biến có vẻ liên quan size/length/index/bounds.
def _looks_size_like(value: str) -> bool:
    return bool(re.search(r"(len|length|size|cnt|count|idx|index|off|offset|pos|end|limit|bound)", str(value or ""), re.IGNORECASE))

# Nhận diện return/throw mang ý nghĩa lỗi hoặc sentinel thất bại.
def _looks_error_sentinel_return(text: str) -> bool:
    value = str(text or "")
    return bool(
        re.search(r"\breturn\s+(-1|nullptr|NULL|false)\s*;", value)
        or re.search(r"\b(return|throw)\b.*\b(error|invalid|not_found|fail|npos)\b", value, re.IGNORECASE)
    )

# Nhận diện return mặc định/thành công có thể sai trong bug thiếu expected error.
def _looks_success_default_return(text: str) -> bool:
    value = str(text or "")
    return bool(
        re.search(r"\breturn\s+(\{\}|0|true)\s*;", value)
        or re.search(r"\breturn\s+[A-Za-z_][A-Za-z0-9_]*\s*;", value)
    )
