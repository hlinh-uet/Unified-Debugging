import re
from typing import Any, Dict, List, Optional, Set, Tuple

from core.apr.agent.context_common import (
    call_name_from_node,
    clip_text,
    dedup_keep_order,
    extract_symbols_from_code,
    line_number_for_byte,
    node_text,
    parse_tree,
    parser_diagnostics,
    walk_nodes,
)

from .support import (
    _assignment_lhs_from_text,
    _atom_symbol_summary,
    _compact_region,
    _compact_statement,
    _condition_text,
    _dedup_edges,
    _enclosing_region_ids,
    _fallback_control_edges,
    _has_any_signal,
    _identifiers_from_text,
    _is_identifier_like,
    _line_ref,
    _limit_mapping,
    _nearest_region,
    _node_has_condition_ancestor,
    _node_key,
    _region_header,
    _region_kind,
    _statement_for_atom,
    EXPRESSION_NODE_TYPES,
    IDENTIFIER_NODE_TYPES,
    KEYWORDS,
    LITERAL_NODE_TYPES,
    MAX_CFG_EDGES,
    MAX_EXPRESSIONS,
    MAX_STATEMENT_TEXT,
    MAX_STATEMENTS,
    MAX_STRUCTURAL_REGIONS,
    REGION_NODE_TYPES,
    STATEMENT_NODE_TYPES,
)
from .repair_atoms import _repair_atom_kind

# Stage 2: trích AST/IR nội bộ function gồm symbols, statements, regions, data/control summaries.
def extract_function_ir(
    *,
    target_spec: Dict[str, Any],
    func_code: str,
    source_code: str,
    language: str,
) -> Dict[str, Any]:
    replacement_unit = target_spec.get("replacement_unit") or func_code or ""
    replacement_start = int(target_spec.get("replacement_start") or 0)
    symbols = extract_symbols_from_code(replacement_unit, language)
    analysis = _analyze_intra_function(
        source_code=source_code,
        func_code=replacement_unit,
        function_start_byte=replacement_start,
        language=language,
    )
    statements = analysis.get("statement_inventory") or []
    structural_regions = analysis.get("structural_regions") or []
    expressions = analysis.get("expression_inventory") or []
    control_flow_graph = analysis.get("control_flow_graph") or {}
    return {
        "target_symbols": symbols,
        "structural_regions": structural_regions,
        "statement_inventory": statements,
        "expression_inventory": expressions,
        "data_flow_summary": analysis.get("data_flow_summary") or {},
        "control_flow_summary": analysis.get("control_flow_summary") or {},
        "control_flow_graph": control_flow_graph,
        "analysis": analysis,
        "function_ir": {
            "symbols": symbols,
            "regions": structural_regions,
            "statements": statements,
            "expressions": expressions,
            "data_flow_summary": analysis.get("data_flow_summary") or {},
            "control_flow_summary": analysis.get("control_flow_summary") or {},
            "control_flow_graph": control_flow_graph,
        },
    }

# Phân tích nội bộ function bằng tree-sitter, fallback sang regex khi parser không khả dụng.
def _analyze_intra_function(
    *,
    source_code: str,
    func_code: str,
    function_start_byte: int,
    language: str,
) -> Dict[str, Any]:
    tree, source_bytes = parse_tree(func_code, language)
    if tree is None or source_bytes is None:
        statements = _statement_inventory_regex(
            source_code=source_code,
            func_code=func_code,
            function_start_byte=function_start_byte,
        )
        control_flow_graph = _control_flow_graph(statements, [])
        return {
            "analysis_available": False,
            "strategy": "regex_statement_fallback",
            "parser": parser_diagnostics(language),
            "fallback_reason": "tree_sitter_parse_tree_unavailable",
            "structural_regions": [],
            "statement_inventory": statements,
            "expression_inventory": [],
            "data_flow_summary": _data_flow_summary(statements),
            "control_flow_summary": _control_flow_summary(statements, [], func_code),
            "control_flow_graph": control_flow_graph,
        }

    structural_regions, region_by_node_key = _structural_regions(
        root=tree.root_node,
        source_code=source_code,
        source_bytes=source_bytes,
        function_start_byte=function_start_byte,
    )
    statements = _statement_inventory_ast(
        root=tree.root_node,
        source_code=source_code,
        source_bytes=source_bytes,
        function_start_byte=function_start_byte,
        regions=structural_regions,
        region_by_node_key=region_by_node_key,
    )
    expressions = _expression_inventory_ast(
        root=tree.root_node,
        source_code=source_code,
        source_bytes=source_bytes,
        function_start_byte=function_start_byte,
        statements=statements,
        language=language,
    )
    control_flow_graph = _control_flow_graph(statements, structural_regions)
    return {
        "analysis_available": True,
        "strategy": "tree_sitter_ast_expression_cfg_repair_atom_slice",
        "parser": parser_diagnostics(language),
        "structural_regions": structural_regions,
        "statement_inventory": statements,
        "expression_inventory": expressions,
        "data_flow_summary": _data_flow_summary(statements),
        "control_flow_summary": _control_flow_summary(statements, structural_regions, func_code),
        "control_flow_graph": control_flow_graph,
    }

# Trích xuất các vùng control-flow như if/loop/switch/case để dùng làm control context.
def _structural_regions(
    *,
    root,
    source_code: str,
    source_bytes: bytes,
    function_start_byte: int,
) -> Tuple[List[dict], Dict[Tuple[int, int, str], dict]]:
    nodes = [node for node in walk_nodes(root) if node.type in REGION_NODE_TYPES]
    regions = []
    region_by_node_key: Dict[Tuple[int, int, str], dict] = {}
    for idx, node in enumerate(nodes[:MAX_STRUCTURAL_REGIONS], start=1):
        abs_start = function_start_byte + node.start_byte
        abs_end = function_start_byte + node.end_byte
        condition = _condition_text(node, source_bytes)
        region = {
            "id": f"R{idx}",
            "kind": _region_kind(node),
            "node_type": node.type,
            "line_start": line_number_for_byte(source_code, abs_start),
            "line_end": line_number_for_byte(source_code, abs_end),
            "start_byte": abs_start,
            "end_byte": abs_end,
            "header": clip_text(_region_header(node, source_bytes), 240),
            "condition": clip_text(condition, 240),
            "condition_variables": _identifiers_from_text(condition),
            "parent_region_id": "",
        }
        regions.append(region)
        region_by_node_key[_node_key(node)] = region

    for node in nodes[:MAX_STRUCTURAL_REGIONS]:
        region = region_by_node_key.get(_node_key(node))
        if not region:
            continue
        parent_region = _nearest_region(getattr(node, "parent", None), region_by_node_key)
        if parent_region:
            region["parent_region_id"] = parent_region.get("id", "")
    return regions, region_by_node_key

# Tạo inventory statement từ AST kèm reads/writes/calls/signals và enclosing conditions.
def _statement_inventory_ast(
    *,
    root,
    source_code: str,
    source_bytes: bytes,
    function_start_byte: int,
    regions: List[dict],
    region_by_node_key: Dict[Tuple[int, int, str], dict],
) -> List[dict]:
    region_by_id = {region.get("id"): region for region in regions}
    statements = []
    seen = set()
    for node in walk_nodes(root):
        if node.type not in STATEMENT_NODE_TYPES:
            continue
        text = node_text(node, source_bytes).strip()
        if not text:
            continue
        key = _node_key(node)
        if key in seen:
            continue
        seen.add(key)
        facts = _code_facts(node, source_bytes)
        abs_start = function_start_byte + node.start_byte
        abs_end = function_start_byte + node.end_byte
        enclosing_ids = _enclosing_region_ids(getattr(node, "parent", None), region_by_node_key)
        enclosing_regions = [
            _compact_region(region_by_id[region_id])
            for region_id in enclosing_ids
            if region_id in region_by_id
        ]
        enclosing_conditions = [
            region.get("condition")
            for region in enclosing_regions
            if region.get("condition")
        ]
        statements.append(
            {
                "id": f"S{len(statements) + 1}",
                "kind": node.type,
                "line": line_number_for_byte(source_code, abs_start),
                "end_line": line_number_for_byte(source_code, abs_end),
                "start_byte": abs_start,
                "end_byte": abs_end,
                "text": clip_text(text, MAX_STATEMENT_TEXT),
                "signals": _statement_signals_ast(node, source_bytes, facts),
                "reads": facts["reads"],
                "writes": facts["writes"],
                "calls": facts["calls"],
                "literals": facts["literals"],
                "enclosing_regions": enclosing_regions,
                "enclosing_conditions": enclosing_conditions[:8],
            }
        )
        if len(statements) >= MAX_STATEMENTS:
            break
    return statements

# Tạo inventory các expression/atom quan trọng từ AST để locator có độ mịn nhỏ hơn statement.
def _expression_inventory_ast(
    *,
    root,
    source_code: str,
    source_bytes: bytes,
    function_start_byte: int,
    statements: List[dict],
    language: str,
) -> List[dict]:
    expressions = []
    seen = set()
    for node in walk_nodes(root):
        if node.type not in EXPRESSION_NODE_TYPES:
            continue
        kind = _expression_inventory_kind(node, source_bytes)
        if not kind:
            continue
        text = node_text(node, source_bytes).strip()
        if not _expression_text_allowed(text, kind):
            continue
        key = (node.start_byte, node.end_byte, kind, text)
        if key in seen:
            continue
        seen.add(key)
        abs_start = function_start_byte + node.start_byte
        abs_end = function_start_byte + node.end_byte
        statement = _statement_for_atom(abs_start, abs_end, statements) or {}
        facts = _code_facts(node, source_bytes)
        expressions.append(
            {
                "id": f"E{len(expressions) + 1}",
                "kind": kind,
                "node_type": node.type,
                "line": line_number_for_byte(source_code, abs_start),
                "end_line": line_number_for_byte(source_code, max(abs_start, abs_end - 1)),
                "byte_range": [abs_start, abs_end],
                "text": clip_text(text, 360),
                "parent_statement_id": statement.get("id", ""),
                "parent_statement_line": statement.get("line"),
                "parent_statement_kind": statement.get("kind", ""),
                "enclosing_conditions": statement.get("enclosing_conditions") or [],
                "signals": _expression_signals_ast(
                    node=node,
                    source_bytes=source_bytes,
                    expression_kind=kind,
                    facts=facts,
                    parent_statement=statement,
                ),
                "symbols": _expression_symbol_summary(facts=facts, text=text, language=language),
            }
        )
        if len(expressions) >= MAX_EXPRESSIONS:
            break
    return expressions

# Phân loại expression bằng AST repair atom trước, sau đó dùng node type như fallback có kiểm soát.
def _expression_inventory_kind(node, source_bytes: bytes) -> str:
    kind = _repair_atom_kind(node, source_bytes)
    if kind:
        return kind
    node_type = getattr(node, "type", "")
    text = node_text(node, source_bytes).strip()
    if node_type == "assignment_expression":
        return "assignment_expression"
    if node_type == "update_expression":
        return "update_expression"
    if node_type == "conditional_expression":
        return "conditional_expression"
    if node_type == "pointer_expression":
        return "pointer_deref_expression"
    if node_type == "field_initializer":
        return "initializer_value"
    if node_type == "initializer_list":
        return "initializer_list"
    if node_type == "init_declarator":
        return "initializer_expression"
    if node_type == "parenthesized_expression" and _node_has_condition_ancestor(node):
        return "condition_expression"
    if node_type in LITERAL_NODE_TYPES:
        return "literal_expression"
    if node_type in IDENTIFIER_NODE_TYPES:
        if text.isupper() and len(text) >= 3:
            return "macro_or_enum_constant"
        if _node_has_condition_ancestor(node):
            return "condition_operand"
    return ""

# Lọc expression quá rộng hoặc quá nguyên tử để giữ context đủ gọn cho FixAgent.
def _expression_text_allowed(text: str, kind: str) -> bool:
    if not text or text in {"(", ")", ",", ";", "{", "}"}:
        return False
    if len(text) > 700:
        return False
    if kind in {"condition_operand", "macro_or_enum_constant", "literal_expression"}:
        return len(text) <= 160
    if "\n" in text and len(text.splitlines()) > 6:
        return False
    return True

# Gắn signal ở cấp expression để FixAgent biết atom đó là guard, value-flow, call hay access.
def _expression_signals_ast(
    *,
    node,
    source_bytes: bytes,
    expression_kind: str,
    facts: Dict[str, List[str]],
    parent_statement: dict,
) -> List[str]:
    signals = []
    node_type = getattr(node, "type", "")
    text = node_text(node, source_bytes)
    calls = [str(item) for item in facts.get("calls") or []]
    identifiers = [str(item) for item in (facts.get("reads") or []) + (facts.get("writes") or [])]

    if expression_kind.startswith("condition"):
        signals.append("guard_or_predicate")
    if expression_kind in {"assignment_rhs", "assignment_expression", "initializer_value", "initializer_expression"}:
        signals.append("value_definition")
    if expression_kind in {"call_argument", "call_expression"}:
        signals.append("api_call_or_argument")
    if expression_kind in {"array_subscript", "array_index"} or node_type == "subscript_expression":
        signals.append("index_or_array_access")
    if expression_kind in {"member_or_field_access", "pointer_deref_expression"}:
        signals.append("pointer_or_member_access")
    if expression_kind in {"return_expression"}:
        signals.append("observable_return_value")
    if expression_kind in {"literal_expression"}:
        signals.append("literal_or_sentinel")
    if expression_kind in {"macro_or_enum_constant", "bitmask_or_macro_expression"}:
        signals.append("macro_or_enum")
    if node_type in {"binary_expression", "unary_expression", "update_expression"}:
        if any(op in text for op in ("+", "-", "*", "/", "%", "<<", ">>")):
            signals.append("numeric_value_flow")
        if any(op in text for op in ("==", "!=", "<=", ">=", "<", ">", "&&", "||")):
            signals.append("guard_or_predicate")
    if any(call.isupper() and len(call) >= 3 for call in calls):
        signals.append("macro_call")

    lowered_values = [item.lower() for item in identifiers + calls]
    if any(any(term in value for term in ("len", "size", "count", "left", "tail", "remaining")) for value in lowered_values):
        signals.append("size_or_tail_value_flow")
    if parent_statement:
        signals.extend(parent_statement.get("signals") or [])
    return dedup_keep_order(signals)

# Tóm tắt symbol ở cấp expression mà không cần lặp lại toàn bộ statement text.
def _expression_symbol_summary(
    *,
    facts: Dict[str, List[str]],
    text: str,
    language: str,
) -> Dict[str, List[str]]:
    symbols = _atom_symbol_summary(text, language)
    return {
        "reads": (facts.get("reads") or [])[:10],
        "writes": (facts.get("writes") or [])[:6],
        "calls": dedup_keep_order((facts.get("calls") or []) + (symbols.get("calls") or []))[:8],
        "identifiers": symbols.get("identifiers") or [],
        "fields": symbols.get("fields") or [],
        "macro_like": symbols.get("macro_like") or [],
        "literals": dedup_keep_order((facts.get("literals") or []) + (symbols.get("literals") or []))[:8],
    }

# Tạo inventory statement bằng regex khi AST không dùng được.
def _statement_inventory_regex(
    *,
    source_code: str,
    func_code: str,
    function_start_byte: int,
) -> List[dict]:
    statements = []
    for item in _logical_statement_lines(func_code, function_start_byte):
        text = item["text"].strip()
        abs_start = item["start_byte"]
        abs_end = item["end_byte"]
        if not text:
            continue
        if not re.search(r"\b(if|for|while|switch|case|return|goto|break|continue)\b|=|->|\.|\w+\s*\(", text):
            continue
        calls = re.findall(r"\b([A-Za-z_]\w*)\s*\(", text)
        writes = _assignment_lhs_from_text(text)
        identifiers = _identifiers_from_text(text)
        reads = [item for item in identifiers if item not in set(writes) and item not in set(calls)]
        statements.append(
            {
                "id": f"S{len(statements) + 1}",
                "kind": _fallback_statement_kind(text),
                "line": line_number_for_byte(source_code, abs_start),
                "end_line": line_number_for_byte(source_code, max(abs_start, abs_end - 1)),
                "start_byte": abs_start,
                "end_byte": abs_end,
                "text": clip_text(text, MAX_STATEMENT_TEXT),
                "signals": _statement_signals(text),
                "reads": reads[:16],
                "writes": writes[:8],
                "calls": [call for call in calls if call not in KEYWORDS][:12],
                "literals": re.findall(r'"[^"]*"|\'[^\']*\'|\b\d+\b', text)[:12],
                "enclosing_regions": [],
                "enclosing_conditions": [],
            }
        )
        if len(statements) >= MAX_STATEMENTS:
            break
    return statements

# Gom các dòng source thành logical statement để fallback regex bớt vỡ với condition nhiều dòng.
def _logical_statement_lines(func_code: str, function_start_byte: int) -> List[dict]:
    items = []
    pending_lines: List[str] = []
    pending_start: Optional[int] = None
    pending_end: Optional[int] = None
    byte_offset = 0
    for raw_line in func_code.splitlines(keepends=True):
        stripped = raw_line.strip()
        abs_start = function_start_byte + byte_offset
        abs_end = abs_start + len(raw_line.encode("utf-8"))
        byte_offset += len(raw_line.encode("utf-8"))
        if pending_lines:
            pending_lines.append(raw_line)
            pending_end = abs_end
            text = "".join(pending_lines)
            if _logical_statement_complete(text):
                items.append(
                    {
                        "text": _collapse_continuation_statement(text),
                        "start_byte": pending_start,
                        "end_byte": pending_end,
                    }
                )
                pending_lines = []
                pending_start = None
                pending_end = None
            continue
        if not stripped:
            continue
        if _starts_multiline_branch(stripped) and not _logical_statement_complete(raw_line):
            pending_lines = [raw_line]
            pending_start = abs_start
            pending_end = abs_end
            continue
        items.append({"text": stripped, "start_byte": abs_start, "end_byte": abs_end})

    if pending_lines:
        items.append(
            {
                "text": _collapse_continuation_statement("".join(pending_lines)),
                "start_byte": pending_start,
                "end_byte": pending_end,
            }
        )
    return items

# Nhận diện dòng mở đầu branch/loop có thể kéo dài qua nhiều dòng.
def _starts_multiline_branch(stripped_line: str) -> bool:
    return bool(re.match(r"^(if|for|while|switch)\s*\(", stripped_line))

# Kiểm tra logical statement đã đủ ngoặc để coi là hoàn chỉnh chưa.
def _logical_statement_complete(text: str) -> bool:
    stripped = text.strip()
    if not _starts_multiline_branch(stripped):
        return True
    if _paren_balance(stripped) > 0:
        return False
    return True

# Đếm cân bằng ngoặc tròn và bỏ qua ngoặc nằm trong string/char literal.
def _paren_balance(text: str) -> int:
    balance = 0
    in_string = ""
    escaped = False
    for char in text:
        if in_string:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == in_string:
                in_string = ""
            continue
        if char in {"'", '"'}:
            in_string = char
        elif char == "(":
            balance += 1
        elif char == ")":
            balance -= 1
    return balance

# Gộp statement nhiều dòng thành một dòng ngắn cho artifact.
def _collapse_continuation_statement(text: str) -> str:
    return " ".join(line.strip() for line in text.splitlines() if line.strip())

# Suy luận loại statement cơ bản trong chế độ regex fallback.
def _fallback_statement_kind(text: str) -> str:
    stripped = text.strip()
    if re.match(r"^if\s*\(", stripped):
        return "if_statement"
    if re.match(r"^(for|while|do)\b", stripped):
        return "loop_statement"
    if re.match(r"^switch\s*\(", stripped):
        return "switch_statement"
    if re.match(r"^(case\b|default\s*:)", stripped):
        return "case_statement"
    if re.match(r"^return\b", stripped):
        return "return_statement"
    if re.match(r"^goto\b", stripped):
        return "goto_statement"
    return "line_statement"

# Trích facts cục bộ của một statement AST: reads, writes, calls và literals.
def _code_facts(node, source_bytes: bytes) -> Dict[str, List[str]]:
    calls = []
    literals = []
    writes: List[str] = []
    call_function_keys = set()

    for child in walk_nodes(node):
        if child.type == "call_expression":
            function_node = child.child_by_field_name("function")
            if function_node is not None:
                call = call_name_from_node(function_node, source_bytes)
                if call:
                    calls.append(call)
                call_function_keys.add(_node_key(function_node))
        elif child.type in LITERAL_NODE_TYPES:
            text = node_text(child, source_bytes).strip()
            if text:
                literals.append(text)
        elif child.type == "assignment_expression":
            lhs = child.child_by_field_name("left") or (child.children[0] if child.children else None)
            writes.extend(_identifiers_in_node(lhs, source_bytes))
        elif child.type == "init_declarator":
            lhs = child.child_by_field_name("declarator") or (child.children[0] if child.children else None)
            writes.extend(_identifiers_in_node(lhs, source_bytes))
        elif child.type == "update_expression":
            writes.extend(_identifiers_in_node(child, source_bytes))

    all_identifiers = []
    for child in walk_nodes(node):
        if child.type not in IDENTIFIER_NODE_TYPES:
            continue
        if _node_key(child) in call_function_keys:
            continue
        ident = node_text(child, source_bytes).strip()
        if _is_identifier_like(ident):
            all_identifiers.append(ident)

    writes = dedup_keep_order([item for item in writes if _is_identifier_like(item)])
    reads = dedup_keep_order([
        item
        for item in all_identifiers
        if item not in set(writes) and item not in set(calls)
    ])
    return {
        "reads": reads[:20],
        "writes": writes[:12],
        "calls": dedup_keep_order([item for item in calls if item not in KEYWORDS])[:16],
        "literals": dedup_keep_order(literals)[:16],
    }

# Thu thập identifier hợp lệ bên trong một node AST.
def _identifiers_in_node(node, source_bytes: bytes) -> List[str]:
    if node is None:
        return []
    identifiers = []
    for child in walk_nodes(node):
        if child.type in IDENTIFIER_NODE_TYPES:
            text = node_text(child, source_bytes).strip()
            if _is_identifier_like(text):
                identifiers.append(text)
    return dedup_keep_order(identifiers)

# Gắn signal bằng AST/node facts cho đường phân tích chính, hạn chế phụ thuộc regex text.
def _statement_signals_ast(node, source_bytes: bytes, facts: Dict[str, List[str]]) -> List[str]:
    signals = []
    node_type = getattr(node, "type", "")
    calls = [str(item) for item in facts.get("calls") or []]
    calls_lc = [item.lower() for item in calls]
    identifiers_lc = [str(item).lower() for item in (facts.get("reads") or []) + (facts.get("writes") or [])]

    if node_type == "return_statement":
        signals.append("return")
    if node_type in {"goto_statement", "throw_statement"}:
        signals.append("error_or_cleanup_path")
    if node_type in {"if_statement", "while_statement", "for_statement", "switch_statement", "case_statement"}:
        signals.append("branch_or_loop")
    if node_type in {"if_statement", "while_statement", "for_statement", "switch_statement"}:
        signals.append("guard_or_predicate")

    buffer_io_calls = {
        "memcpy", "memmove", "strcpy", "strncpy", "snprintf", "sprintf",
        "read", "fread", "write", "fwrite",
    }
    output_calls = {
        "printf", "fprintf", "sprintf", "snprintf", "puts", "putchar",
        "ND_PRINT", "ND_PRINTZ", "write",
    }
    error_calls = {"on_error", "throw", "FMT_THROW", "assert"}
    state_call_terms = (
        "free", "malloc", "calloc", "realloc", "unlink", "remove", "apply",
        "switch", "insert", "add", "append", "delete", "release", "destroy",
    )
    numeric_terms = (
        "digit", "digits", "num_digits", "carry", "overflow", "round",
        "rounding", "precision", "numerator", "denominator", "divmod",
        "to_unsigned", "exp", "mantissa",
    )
    tail_terms = (
        "leftover", "remaining", "num_chars_left", "chars_left", "bytes_left",
        "left", "tail", "memcpy", "memmove", "transcode", "decode", "encode",
        "utf", "size",
    )
    chrono_terms = (
        "duration", "seconds", "milliseconds", "chrono", "count", "negative",
        "to_unsigned",
    )

    if any(call in buffer_io_calls for call in calls_lc):
        signals.append("buffer_or_io_call")
    if any(call in output_calls or call.upper() in output_calls for call in calls):
        signals.append("output_call")
    if any(call in error_calls or call.upper() in error_calls for call in calls):
        signals.append("error_or_cleanup_path")
    if any(any(term in call for term in state_call_terms) for call in calls_lc):
        signals.append("state_or_ownership_call")
    if any(call.isupper() and len(call) >= 3 for call in calls):
        signals.append("macro_call")
    if any(any(term in value for term in numeric_terms) for value in identifiers_lc + calls_lc):
        signals.append("numeric_value_flow")
    if any(any(term in value for term in tail_terms) for value in identifiers_lc + calls_lc):
        signals.append("tail_or_leftover_processing")
    if any(any(term in value for term in chrono_terms) for value in identifiers_lc + calls_lc):
        signals.append("chrono_duration_flow")

    for child in walk_nodes(node):
        child_type = getattr(child, "type", "")
        if child_type in {"pointer_expression", "field_expression"}:
            signals.append("pointer_deref")
        elif child_type == "subscript_expression":
            signals.append("index_or_array_access")
        elif child_type in {"binary_expression", "conditional_expression"}:
            expr = node_text(child, source_bytes)
            if any(op in expr for op in ("==", "!=", "<=", ">=", "<", ">", "&&", "||")):
                signals.append("guard_or_predicate")
            if any(op in expr for op in ("+", "-", "*", "/", "%", "<<", ">>")):
                signals.append("numeric_value_flow")
        elif child_type == "parenthesized_expression" and node_type in {"if_statement", "while_statement", "for_statement", "switch_statement"}:
            signals.append("guard_or_predicate")
        elif child_type == "call_expression":
            call_node = child.child_by_field_name("function")
            call_name = call_name_from_node(call_node, source_bytes) if call_node is not None else ""
            if call_name and call_name.isupper() and len(call_name) >= 3:
                signals.append("macro_call")

    text = node_text(node, source_bytes)
    if node_type == "labeled_statement" and any(label in text.lower() for label in ("cleanup", "error", "fail", "out")):
        signals.append("error_or_cleanup_path")
    return dedup_keep_order(signals)

# Fallback text-based signal extraction khi AST/parser không khả dụng.
def _statement_signals(text: str) -> List[str]:
    signals = []
    if "return" in text:
        signals.append("return")
    if (
        "goto" in text
        or re.search(r"(?:^|[_\W])(cleanup|error|fail)(?:$|[_\W])", text)
        or re.search(r"\b(on_error|throw|FMT_THROW|assert)\b", text)
    ):
        signals.append("error_or_cleanup_path")
    if "->" in text or re.search(r"(?<!\w)\*\w+", text):
        signals.append("pointer_deref")
    if "[" in text and "]" in text:
        signals.append("index_or_array_access")
    if re.search(r"\b(memcpy|memmove|strcpy|strncpy|snprintf|sprintf|read|fread|write|fwrite)\s*\(", text):
        signals.append("buffer_or_io_call")
    if re.search(r"\b(free|malloc|calloc|realloc|unlink|remove|apply|switch|insert|add|append|delete|release|destroy)\w*\s*\(", text):
        signals.append("state_or_ownership_call")
    if re.search(r"\b(printf|fprintf|sprintf|snprintf|puts|putchar|ND_PRINT|ND_PRINTZ|out|write|format)\w*\s*\(", text):
        signals.append("output_call")
    if re.search(r"\b[A-Z_][A-Z0-9_]{2,}\s*\(", text):
        signals.append("macro_call")
    if re.search(
        r"\b(digit|digits|num_digits|carry|overflow|round|rounding|precision|"
        r"numerator|denominator|divmod|to_unsigned|exp|mantissa)\b|['\"]0['\"]\s*\+|[/%]",
        text,
        flags=re.IGNORECASE,
    ):
        signals.append("numeric_value_flow")
    if re.search(
        r"\b(leftover|remaining|num_chars_left|chars_left|bytes_left|left|tail|"
        r"memcpy|memmove|transcode|decode|encode|utf|size\s*\(\s*\))\b",
        text,
        flags=re.IGNORECASE,
    ):
        signals.append("tail_or_leftover_processing")
    if re.search(
        r"\b(duration|seconds|milliseconds|chrono|count|negative|to_unsigned)\b",
        text,
        flags=re.IGNORECASE,
    ):
        signals.append("chrono_duration_flow")
    if re.search(r"\b(if|while|for|switch)\b", text):
        signals.append("branch_or_loop")
    if re.search(r"(==|!=|<=|>=|(?<!-)<|(?<!-)>|\|\||&&|\bNULL\b|\bnullptr\b)", text):
        signals.append("guard_or_predicate")
    return signals

# Tổng hợp def-use/call-site và các nhóm operation quan trọng từ statement inventory.
def _data_flow_summary(statements: List[dict]) -> Dict[str, Any]:
    definitions: Dict[str, List[dict]] = {}
    uses: Dict[str, List[dict]] = {}
    call_sites: Dict[str, List[dict]] = {}
    for statement in statements:
        for var in statement.get("writes") or []:
            definitions.setdefault(var, []).append(_line_ref(statement))
        for var in statement.get("reads") or []:
            uses.setdefault(var, []).append(_line_ref(statement))
        for call in statement.get("calls") or []:
            call_sites.setdefault(call, []).append(_line_ref(statement))
    return {
        "definitions": _limit_mapping(definitions, 40, 8),
        "uses": _limit_mapping(uses, 60, 8),
        "call_sites": _limit_mapping(call_sites, 60, 8),
        "memory_or_pointer_operations": [
            _compact_statement(statement)
            for statement in statements
            if _has_any_signal(statement, {"pointer_deref", "index_or_array_access", "buffer_or_io_call"})
        ][:20],
        "state_or_ownership_operations": [
            _compact_statement(statement)
            for statement in statements
            if _has_any_signal(statement, {"state_or_ownership_call", "error_or_cleanup_path"})
        ][:20],
        "output_operations": [
            _compact_statement(statement)
            for statement in statements
            if _has_any_signal(statement, {"output_call", "return"})
        ][:20],
    }

# Tổng hợp branch, exit point, guarded access và cleanup/goto shape trong function.
def _control_flow_summary(statements: List[dict], regions: List[dict], func_code: str) -> Dict[str, Any]:
    return {
        "branch_regions": [
            {
                "id": region.get("id"),
                "kind": region.get("kind"),
                "line_start": region.get("line_start"),
                "line_end": region.get("line_end"),
                "condition": region.get("condition"),
                "condition_variables": region.get("condition_variables") or [],
                "parent_region_id": region.get("parent_region_id"),
            }
            for region in regions
            if region.get("kind") in {"if", "else", "loop", "switch", "case"}
        ][:MAX_STRUCTURAL_REGIONS],
        "exit_points": [
            _compact_statement(statement)
            for statement in statements
            if _has_any_signal(statement, {"return", "error_or_cleanup_path"})
            or statement.get("kind") in {"break_statement", "continue_statement"}
        ][:30],
        "guarded_accesses": [
            {
                **_compact_statement(statement),
                "guards": statement.get("enclosing_conditions") or [],
            }
            for statement in statements
            if _has_any_signal(statement, {"pointer_deref", "index_or_array_access", "buffer_or_io_call"})
        ][:30],
        "cleanup_labels_and_gotos": [
            line.strip()
            for line in func_code.splitlines()
            if re.search(r"\b(cleanup|error|fail|out)\s*:|\bgoto\s+(cleanup|error|fail|out)\b", line)
        ][:20],
    }

# Dựng CFG nhẹ từ statement order và structural regions để phục vụ slicing/ranking.
def _control_flow_graph(statements: List[dict], structural_regions: List[dict]) -> Dict[str, Any]:
    nodes = [_compact_statement(statement, include_facts=True) for statement in statements[:MAX_STATEMENTS]]
    if not statements:
        return {
            "nodes": [],
            "regions": [],
            "edges": [],
            "entry": {},
            "exits": [],
            "notes": ["empty_target_function_or_statement_inventory_unavailable"],
        }

    edges = []
    for current, nxt in zip(statements, statements[1:]):
        if _statement_is_terminal(current):
            continue
        edges.append(
            {
                "from": current.get("id"),
                "to": nxt.get("id"),
                "kind": "fallthrough",
            }
        )

    for region in structural_regions[:MAX_STRUCTURAL_REGIONS]:
        region_id = region.get("id")
        if not region_id:
            continue
        controller = _region_controller_statement(region, statements)
        controlled = _statements_controlled_by_region(region_id, statements)
        if controller:
            first_inside = next(
                (statement for statement in controlled if statement.get("id") != controller.get("id")),
                None,
            )
            if first_inside:
                edges.append(
                    {
                        "from": controller.get("id"),
                        "to": first_inside.get("id"),
                        "kind": "control_entry",
                        "region_id": region_id,
                        "condition": region.get("condition", ""),
                    }
                )
            if region.get("kind") == "loop" and controlled:
                last_inside = controlled[-1]
                if last_inside.get("id") != controller.get("id") and not _statement_is_terminal(last_inside):
                    edges.append(
                        {
                            "from": last_inside.get("id"),
                            "to": controller.get("id"),
                            "kind": "loop_back",
                            "region_id": region_id,
                            "condition": region.get("condition", ""),
                        }
                    )
        for statement in controlled:
            edges.append(
                {
                    "from": region_id,
                    "to": statement.get("id"),
                    "kind": "region_membership",
                    "condition": region.get("condition", ""),
                }
            )

    edges.extend(_fallback_control_edges(statements))
    edges = _dedup_edges(edges)[:MAX_CFG_EDGES]
    return {
        "nodes": nodes,
        "regions": [_compact_region(region) for region in structural_regions[:MAX_STRUCTURAL_REGIONS]],
        "edges": edges,
        "entry": _compact_statement(statements[0], include_facts=True),
        "exits": [
            _compact_statement(statement, include_facts=True)
            for statement in statements
            if _statement_is_terminal(statement)
        ][:20],
        "notes": [
            "cfg_lite_uses_tree_sitter_statement_ranges_and_structural_regions",
            "region_membership edges use region ids as control nodes; fallthrough edges use statement ids.",
        ],
    }

# Xác định statement kết thúc control flow trực tiếp.
def _statement_is_terminal(statement: dict) -> bool:
    return statement.get("kind") in {
        "return_statement",
        "goto_statement",
        "break_statement",
        "continue_statement",
        "throw_statement",
    } or _has_any_signal(statement, {"return"})

# Tìm statement điều khiển một structural region.
def _region_controller_statement(region: dict, statements: List[dict]) -> Optional[dict]:
    start = region.get("start_byte")
    end = region.get("end_byte")
    if isinstance(start, int) and isinstance(end, int):
        exact = _statement_for_atom(start, min(end, start + 1), statements)
        if exact:
            return exact
    line_start = region.get("line_start")
    for statement in statements:
        if statement.get("line") == line_start and _has_any_signal(statement, {"branch_or_loop", "guard_or_predicate"}):
            return statement
    return None

# Lấy các statement nằm trong một region theo enclosing region metadata.
def _statements_controlled_by_region(region_id: str, statements: List[dict]) -> List[dict]:
    controlled = []
    for statement in statements:
        if any(region.get("id") == region_id for region in statement.get("enclosing_regions") or []):
            controlled.append(statement)
    return controlled
