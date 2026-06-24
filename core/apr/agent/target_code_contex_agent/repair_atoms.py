import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.agent.context_common import (
    clip_text,
    dedup_keep_order,
    line_number_for_byte,
    node_text,
    parse_tree,
    walk_nodes,
)

from .support import (
    _atom_has_assignment_churn,
    _atom_symbol_summary,
    _compact_statement,
    _has_any_signal,
    _is_condition_field,
    _is_named_field,
    _node_has_bitwise_or_ancestor,
    _node_has_condition_ancestor,
    _node_key,
    _statement_for_atom,
    IDENTIFIER_NODE_TYPES,
    LITERAL_NODE_TYPES,
    MAX_REPAIR_ATOMS,
    MAX_REPAIR_SITES,
)

# Stage 4: rank expression-level repair atoms dựa trên AST và failure localization.
def rank_target_repair_atoms(
    *,
    target_spec: Dict[str, Any],
    function_ir: Dict[str, Any],
    failure_localization: Dict[str, Any],
    source_code: str,
    language: str,
) -> Dict[str, Any]:
    ranked_repair_atoms = _rank_repair_atoms(
        replacement_unit=target_spec.get("replacement_unit") or "",
        replacement_start=int(target_spec.get("replacement_start") or 0),
        source_code=source_code,
        language=language,
        statements=function_ir.get("statement_inventory") or [],
        failure_slices=failure_localization.get("failure_slices") or [],
        ranked_repair_sites=failure_localization.get("ranked_repair_sites") or [],
        failure_contract=failure_localization.get("failure_contract") or {},
    )
    repair_atom_summary = _repair_atom_summary(ranked_repair_atoms)
    return {
        "ranked_repair_atoms": ranked_repair_atoms,
        "repair_atom_summary": repair_atom_summary,
        "repair_atom_localization": {
            "ranked_repair_atoms": ranked_repair_atoms,
            "repair_atom_summary": repair_atom_summary,
        },
    }

# Rank các AST repair atom cấp expression để xác định điểm sửa nhỏ nhất có khả năng đúng.
def _rank_repair_atoms(
    *,
    replacement_unit: str,
    replacement_start: int,
    source_code: str,
    language: str,
    statements: List[dict],
    failure_slices: List[dict],
    ranked_repair_sites: List[dict],
    failure_contract: Dict[str, Any],
) -> List[dict]:
    tree, source_bytes = parse_tree(replacement_unit or "", language)
    if tree is None or source_bytes is None:
        return _rank_repair_atoms_regex(
            statements=statements,
            ranked_repair_sites=ranked_repair_sites,
            failure_contract=failure_contract,
        )

    statement_by_id = {statement.get("id"): statement for statement in statements}
    site_by_statement_id = {
        (site.get("primary_statement") or {}).get("id"): site
        for site in ranked_repair_sites
        if (site.get("primary_statement") or {}).get("id")
    }
    slice_score_by_statement_id = {
        (failure_slice.get("seed_statement") or {}).get("id"): failure_slice.get("score", 0)
        for failure_slice in failure_slices
        if (failure_slice.get("seed_statement") or {}).get("id")
    }
    slice_by_statement_id = {
        (failure_slice.get("seed_statement") or {}).get("id"): failure_slice
        for failure_slice in failure_slices
        if (failure_slice.get("seed_statement") or {}).get("id")
    }

    atoms = []
    seen_nodes = set()
    for node in walk_nodes(tree.root_node):
        if _node_key(node) in seen_nodes:
            continue
        kind = _repair_atom_kind(node, source_bytes)
        if not kind:
            continue
        text = node_text(node, source_bytes).strip()
        if not _repair_atom_text_allowed(text, kind):
            continue
        seen_nodes.add(_node_key(node))
        abs_start = replacement_start + node.start_byte
        abs_end = replacement_start + node.end_byte
        statement = _statement_for_atom(abs_start, abs_end, statements)
        if not statement:
            continue
        if _looks_like_function_signature_statement(statement):
            continue
        statement_id = statement.get("id")
        site = site_by_statement_id.get(statement_id) or _site_for_atom(
            abs_start,
            abs_end,
            ranked_repair_sites,
        )
        failure_slice = slice_by_statement_id.get(statement_id) or _slice_for_atom(
            statement_id,
            failure_slices,
        )
        score, reasons = _score_repair_atom(
            atom_kind=kind,
            atom_text=text,
            atom_node=node,
            source_bytes=source_bytes,
            statement=statement,
            site=site,
            failure_slice=failure_slice,
            slice_score=slice_score_by_statement_id.get(statement_id, 0),
            failure_contract=failure_contract,
            language=language,
        )
        if score <= 0:
            continue
        atoms.append(
            {
                "id": "",
                "rank": 0,
                "kind": kind,
                "score": score,
                "confidence": "high" if score >= 28 else "medium" if score >= 16 else "low",
                "line_range": [
                    line_number_for_byte(source_code, abs_start),
                    line_number_for_byte(source_code, max(abs_start, abs_end - 1)),
                ],
                "byte_range": [abs_start, abs_end],
                "text": clip_text(text, 360),
                "operator_hint": _operator_hint_for_atom(kind, text, failure_contract),
                "allowed_operations": _allowed_operations_for_atom(kind),
                "forbidden_operations": _forbidden_operations_for_atom(kind),
                "parent_statement": _compact_statement(statement, include_facts=True),
                "repair_site_id": (site or {}).get("id", ""),
                "failure_slice_id": (failure_slice or {}).get("id", ""),
                "evidence": {
                    "reasons": reasons[:8],
                    "atom_symbols": _atom_symbol_summary(text, language),
                    "statement_signals": statement.get("signals") or [],
                    "enclosing_conditions": statement.get("enclosing_conditions") or [],
                },
            }
        )

    if not atoms:
        return _rank_repair_atoms_regex(
            statements=statements,
            ranked_repair_sites=ranked_repair_sites,
            failure_contract=failure_contract,
        )

    atoms = _dedup_repair_atoms(atoms)
    atoms.sort(key=lambda item: (-int(item.get("score") or 0), item.get("line_range") or [10**9], item.get("kind") or ""))
    for idx, atom in enumerate(atoms[:MAX_REPAIR_ATOMS], start=1):
        atom["id"] = f"RA{idx}"
        atom["rank"] = idx
    return atoms[:MAX_REPAIR_ATOMS]

# Rank repair atom bằng regex khi AST không parse được.
def _rank_repair_atoms_regex(
    *,
    statements: List[dict],
    ranked_repair_sites: List[dict],
    failure_contract: Dict[str, Any],
) -> List[dict]:
    atoms = []
    site_by_statement_id = {
        (site.get("primary_statement") or {}).get("id"): site
        for site in ranked_repair_sites
        if (site.get("primary_statement") or {}).get("id")
    }
    for statement in statements:
        text = str(statement.get("text") or "").strip()
        if not text:
            continue
        if _looks_like_function_signature_statement(statement):
            continue
        candidates = _regex_atoms_from_statement(text)
        site = site_by_statement_id.get(statement.get("id"))
        for kind, atom_text in candidates:
            score, reasons = _score_repair_atom(
                atom_kind=kind,
                atom_text=atom_text,
                atom_node=None,
                source_bytes=None,
                statement=statement,
                site=site,
                failure_slice={},
                slice_score=(site or {}).get("score", 0),
                failure_contract=failure_contract,
                language="cpp",
            )
            if score <= 0:
                continue
            atoms.append(
                {
                    "id": "",
                    "rank": 0,
                    "kind": kind,
                    "score": score,
                    "confidence": "high" if score >= 28 else "medium" if score >= 16 else "low",
                    "line_range": [statement.get("line"), statement.get("end_line") or statement.get("line")],
                    "byte_range": [statement.get("start_byte"), statement.get("end_byte")],
                    "text": clip_text(atom_text, 360),
                    "operator_hint": _operator_hint_for_atom(kind, atom_text, failure_contract),
                    "allowed_operations": _allowed_operations_for_atom(kind),
                    "forbidden_operations": _forbidden_operations_for_atom(kind),
                    "parent_statement": _compact_statement(statement, include_facts=True),
                    "repair_site_id": (site or {}).get("id", ""),
                    "failure_slice_id": "",
                    "evidence": {
                        "reasons": reasons[:8],
                        "atom_symbols": _atom_symbol_summary(atom_text, "cpp"),
                        "statement_signals": statement.get("signals") or [],
                        "enclosing_conditions": statement.get("enclosing_conditions") or [],
                    },
                }
            )
    atoms = _dedup_repair_atoms(atoms)
    atoms.sort(key=lambda item: (-int(item.get("score") or 0), item.get("line_range") or [10**9], item.get("kind") or ""))
    for idx, atom in enumerate(atoms[:MAX_REPAIR_ATOMS], start=1):
        atom["id"] = f"RA{idx}"
        atom["rank"] = idx
    return atoms[:MAX_REPAIR_ATOMS]

# Tách các atom ứng viên từ một statement text trong fallback regex.
def _regex_atoms_from_statement(text: str) -> List[Tuple[str, str]]:
    out: List[Tuple[str, str]] = []
    stripped = text.strip()
    match = re.search(r"\b(if|while|switch)\s*\((.*)\)", stripped)
    if match:
        out.append(("condition_expression", match.group(2).strip()))
    match = re.match(r"return\s+(.+?);?$", stripped)
    if match:
        out.append(("return_expression", match.group(1).strip()))
    match = re.search(r"=\s*(.+?);?$", stripped)
    if match and "==" not in stripped:
        out.append(("assignment_rhs", match.group(1).strip()))
    if "|" in stripped and re.search(r"\b[A-Z_][A-Z0-9_]{2,}\b", stripped):
        out.append(("bitmask_or_macro_expression", stripped))
    if re.search(r"[+\-*/%]|<<|>>", stripped):
        out.append(("arithmetic_expression", stripped))
    return out[:5] or [("statement_expression", stripped)]

# Phân loại AST node thành loại repair atom như condition, return, macro, call argument.
def _repair_atom_kind(node, source_bytes: bytes) -> str:
    parent = getattr(node, "parent", None)
    if parent is None:
        return ""
    node_type = getattr(node, "type", "")
    parent_type = getattr(parent, "type", "")
    text = node_text(node, source_bytes).strip()
    if not text:
        return ""
    if _is_condition_field(parent, node):
        return "condition_expression"
    if node_type == "binary_expression":
        if "|" in text and re.search(r"\b[A-Z_][A-Z0-9_]{2,}\b", text):
            return "bitmask_or_macro_expression"
        if re.search(r"(\+|-|\*|/|%|<<|>>)", text):
            return "arithmetic_expression"
        if _node_has_condition_ancestor(node):
            return "condition_binary_expression"
        return "binary_expression"
    if node_type == "unary_expression" and _node_has_condition_ancestor(node):
        return "condition_operand"
    if node_type in IDENTIFIER_NODE_TYPES and re.match(r"^[A-Z_][A-Z0-9_]{2,}$", text):
        if _node_has_bitwise_or_ancestor(node, source_bytes) or _node_has_condition_ancestor(node):
            return "macro_or_enum_constant"
    if parent_type == "assignment_expression" and _is_named_field(parent, "right", node):
        return "assignment_rhs"
    if parent_type == "init_declarator" and _is_named_field(parent, "value", node):
        return "initializer_value"
    if parent_type == "return_statement" and node_type not in {"return", ";"}:
        if len(text) <= 500:
            return "return_expression"
    if parent_type == "argument_list" and node_type not in {"(", ")", ","}:
        return "call_argument"
    if node_type == "call_expression":
        return "call_expression"
    if node_type == "subscript_expression":
        return "array_subscript"
    if parent_type == "subscript_expression" and _is_named_field(parent, "index", node):
        return "array_index"
    if node_type == "field_expression":
        return "member_or_field_access"
    if node_type in LITERAL_NODE_TYPES and parent_type in {
        "binary_expression",
        "assignment_expression",
        "init_declarator",
        "return_statement",
        "argument_list",
    }:
        return "literal_expression"
    return ""

# Lọc bỏ atom quá rộng, rỗng hoặc không phù hợp để FixAgent sửa trực tiếp.
def _repair_atom_text_allowed(text: str, kind: str) -> bool:
    if not text or len(text) > 700:
        return False
    if text in {"(", ")", ",", ";", "{", "}"}:
        return False
    if kind in {"literal_expression", "macro_or_enum_constant"}:
        return len(text) <= 120
    if "\n" in text and len(text.splitlines()) > 8:
        return False
    return True

# Loại chữ ký hàm/declaration khỏi repair atom: chúng có thể chứa expression hợp lệ
# như decltype(ctx.out()), nhưng gần như luôn thuộc vùng cấm sửa của APR target.
def _looks_like_function_signature_statement(statement: dict) -> bool:
    text = str(statement.get("text") or "").strip()
    if not text:
        return False
    if text.endswith(";"):
        return False
    if "{" not in text or "(" not in text or ")" not in text:
        return False
    if text.startswith(("if ", "if(", "for ", "for(", "while ", "while(", "switch ", "switch(")):
        return False
    if "->" in text:
        return True
    if re.match(r"^(template\s*<.*>\s*)?(static\s+|inline\s+|constexpr\s+|friend\s+|virtual\s+|auto\s+|[A-Za-z_:][\\w:<>,~*&\\s]+\\s+)[~A-Za-z_]\\w*\\s*\\([^;{}]*\\)\\s*(const\\s*)?(noexcept\\s*)?(override\\s*)?\\{?$", text):
        return True
    return False

# Chấm điểm một repair atom dựa trên failure contract, repair site, signal và symbol overlap.
def _score_repair_atom(
    *,
    atom_kind: str,
    atom_text: str,
    atom_node,
    source_bytes: Optional[bytes],
    statement: dict,
    site: Optional[dict],
    failure_slice: Optional[dict],
    slice_score: int,
    failure_contract: Dict[str, Any],
    language: str,
) -> Tuple[int, List[str]]:
    categories = set(failure_contract.get("categories") or [])
    route = str(failure_contract.get("route") or "")
    high_terms = set(str(item).lower() for item in failure_contract.get("high_value_terms") or [])
    symbolic_terms = set(str(item).lower() for item in failure_contract.get("symbolic_terms") or [])
    atom_symbols = _atom_symbol_summary(atom_text, language)
    atom_terms = set(str(item).lower() for values in atom_symbols.values() for item in values)
    text_lc = str(atom_text or "").lower()
    signals = set(statement.get("signals") or [])

    score = 0
    reasons = []
    if site:
        site_score = int(site.get("score") or 0)
        site_rank = int(site.get("rank") or MAX_REPAIR_SITES)
        score += min(16, site_score) + max(0, 8 - site_rank)
        reasons.append(f"inside ranked repair site {site.get('id')}")
    elif slice_score:
        score += min(10, int(slice_score))
        reasons.append("inside failure slice seed statement")
    else:
        score += 2

    overlap_high = sorted(high_terms & atom_terms)
    overlap_symbolic = sorted(symbolic_terms & atom_terms)
    if overlap_high:
        score += 10 + min(6, len(overlap_high) * 2)
        reasons.append("atom matches high-value failure terms: " + ", ".join(overlap_high[:4]))
    if overlap_symbolic:
        score += 5 + min(4, len(overlap_symbolic))
        reasons.append("atom matches failure symbolic terms: " + ", ".join(overlap_symbolic[:4]))
    for literal in failure_contract.get("failure_literals") or []:
        lit = str(literal).strip().lower()
        if lit and len(lit) >= 2 and lit in text_lc:
            score += 6
            reasons.append("atom contains failure literal")
            break

    if atom_kind in {"condition_expression", "condition_binary_expression", "condition_operand"}:
        if categories & {"crash_or_memory_safety", "bounds_or_size", "state_or_contract", "missing_expected_error"}:
            score += 8
            reasons.append("condition atom can gate unsafe/state/error behavior")
        if "output_or_return_mismatch" in categories and route == "correctness_repair":
            score += 5
            reasons.append("condition atom can select expected-vs-actual behavior")
    if atom_kind == "bitmask_or_macro_expression":
        score += 9
        reasons.append("bitmask/macro atom is a compact option/flag repair point")
        if route == "correctness_repair" or "state_or_contract" in categories:
            score += 6
            reasons.append("correctness/state contract route favors precise flag or option edits")
    if atom_kind == "macro_or_enum_constant":
        score += 7
        reasons.append("macro/enum atom can be replaced by a contract-compatible sibling constant")
        if route == "correctness_repair" or "state_or_contract" in categories:
            score += 5
            reasons.append("macro/enum atom is a precise contract-compatible substitution point")
    if atom_kind in {"arithmetic_expression", "literal_expression"}:
        if categories & {"output_or_return_mismatch", "bounds_or_size"} or signals & {"numeric_value_flow", "tail_or_leftover_processing"}:
            score += 8
            reasons.append("arithmetic/literal atom feeds numeric, size, or observable value flow")
    if atom_kind in {"assignment_rhs", "initializer_value"}:
        if statement.get("writes") or categories & {"output_or_return_mismatch", "state_or_contract"}:
            score += 6
            reasons.append("assignment/value atom can repair local data flow")
    if atom_kind == "return_expression" and categories & {"output_or_return_mismatch", "missing_expected_error", "state_or_contract"}:
        score += 8
        reasons.append("return atom is directly observable")
    if atom_kind in {"call_argument", "call_expression"}:
        if statement.get("calls") or categories & {"state_or_contract", "crash_or_memory_safety"}:
            score += 5
            reasons.append("call atom is constrained by related API contracts")
    if atom_kind in {"array_subscript", "array_index"} and categories & {"crash_or_memory_safety", "bounds_or_size"}:
        score += 10
        reasons.append("array/index atom is an unsafe sink or bounds expression")
    if atom_kind == "member_or_field_access":
        score += 4
        reasons.append("member/field atom must obey RelatedCodeContext member/type contracts")

    if _atom_has_assignment_churn(atom_text) and atom_kind in {"condition_expression", "condition_binary_expression"}:
        score -= 4
        reasons.append("downranked because condition atom spans assignment-like side effects")
    if len(atom_text) > 300:
        score -= 3
        reasons.append("downranked because atom is broad")

    return score, dedup_keep_order(reasons)

# Gợi ý operator sửa phù hợp với loại atom và loại failure.
def _operator_hint_for_atom(kind: str, text: str, failure_contract: Dict[str, Any]) -> str:
    categories = set(failure_contract.get("categories") or [])
    if kind in {"condition_expression", "condition_binary_expression", "condition_operand"}:
        if "crash_or_memory_safety" in categories:
            return "tighten_or_add_guard_predicate"
        if "missing_expected_error" in categories:
            return "restore_error_path_predicate"
        return "adjust_predicate_or_dispatch_condition"
    if kind in {"bitmask_or_macro_expression", "macro_or_enum_constant"}:
        return "replace_with_contract_compatible_macro_or_enum_constant"
    if kind in {"arithmetic_expression", "literal_expression"}:
        return "repair_numeric_range_or_size_expression"
    if kind in {"assignment_rhs", "initializer_value"}:
        return "repair_local_value_flow_expression"
    if kind == "return_expression":
        return "repair_observable_return_expression"
    if kind in {"call_argument", "call_expression"}:
        return "repair_api_call_argument_or_preserve_signature"
    if kind in {"array_subscript", "array_index"}:
        return "repair_index_or_bounds_expression"
    if kind == "member_or_field_access":
        return "repair_existing_member_access_only"
    return "minimal_expression_level_edit"

# Liệt kê các thao tác được phép cho từng loại repair atom.
def _allowed_operations_for_atom(kind: str) -> List[str]:
    mapping = {
        "condition_expression": ["edit condition operands/operators", "add a local conjunct/disjunct backed by slice evidence"],
        "condition_binary_expression": ["edit comparison/logical operator", "edit one operand"],
        "condition_operand": ["negate/tighten operand", "replace operand with equivalent local symbol"],
        "bitmask_or_macro_expression": ["replace one macro/enum flag", "add/remove one flag only if Related contract supports it"],
        "macro_or_enum_constant": ["replace with sibling macro/enum constant from Related contract inventory"],
        "arithmetic_expression": ["edit arithmetic sub-expression", "preserve surrounding assignment/call shape"],
        "literal_expression": ["adjust literal/sentinel/size constant only with failure evidence"],
        "assignment_rhs": ["edit right-hand expression only", "preserve left-hand target and surrounding side effects"],
        "initializer_value": ["edit initializer value only", "do not invent new member fields"],
        "return_expression": ["edit returned expression/sentinel", "preserve function signature"],
        "call_argument": ["edit argument expression only", "preserve callee signature and argument count"],
        "call_expression": ["prefer argument/local predicate repair before changing callee"],
        "array_subscript": ["repair index/length expression", "preserve base object"],
        "array_index": ["edit index expression only"],
        "member_or_field_access": ["use existing visible member fields only"],
    }
    return mapping.get(kind, ["make the smallest expression-level edit"])

# Liệt kê thao tác cấm cho repair atom để tránh hallucinate API/macro/field.
def _forbidden_operations_for_atom(kind: str) -> List[str]:
    common = ["do not rewrite unrelated statements", "do not add helpers/includes/globals"]
    if kind in {"call_argument", "call_expression"}:
        return common + ["do not change API arity unless Related contract proves the new signature"]
    if kind in {"macro_or_enum_constant", "bitmask_or_macro_expression"}:
        return common + ["do not invent a macro or enum constant outside Related contract inventory"]
    if kind == "member_or_field_access":
        return common + ["do not invent new member fields"]
    return common

# Rút gọn danh sách atom thành primary/alternative atom cho prompt FixAgent.
def _repair_atom_summary(atoms: List[dict]) -> Dict[str, Any]:
    if not atoms:
        return {
            "primary_atom": {},
            "alternative_atoms": [],
            "policy": "No AST repair atom could be localized; fall back to ranked_repair_sites.",
        }
    return {
        "primary_atom": {
            "id": atoms[0].get("id"),
            "kind": atoms[0].get("kind"),
            "line_range": atoms[0].get("line_range"),
            "text": atoms[0].get("text"),
            "operator_hint": atoms[0].get("operator_hint"),
            "score": atoms[0].get("score"),
            "confidence": atoms[0].get("confidence"),
        },
        "alternative_atoms": [
            {
                "id": atom.get("id"),
                "kind": atom.get("kind"),
                "line_range": atom.get("line_range"),
                "text": atom.get("text"),
                "operator_hint": atom.get("operator_hint"),
                "score": atom.get("score"),
            }
            for atom in atoms[1:5]
        ],
        "policy": "Prefer the primary repair atom over broad statement rewrites when it is consistent with failure evidence and RelatedCodeContext contracts.",
    }

# Loại atom trùng nhau theo loại, line range và text.
def _dedup_repair_atoms(atoms: List[dict]) -> List[dict]:
    out = []
    seen = set()
    for atom in atoms:
        line_range = tuple(atom.get("line_range") or [])
        text = str(atom.get("text") or "").strip()
        key = (atom.get("kind"), line_range, text)
        if key in seen:
            continue
        seen.add(key)
        out.append(atom)
    return out

# Tìm ranked repair site chứa atom theo byte range.
def _site_for_atom(start_byte: int, end_byte: int, ranked_repair_sites: List[dict]) -> dict:
    for site in ranked_repair_sites:
        byte_range = site.get("byte_range") or []
        if len(byte_range) == 2 and isinstance(byte_range[0], int) and isinstance(byte_range[1], int):
            if byte_range[0] <= start_byte and end_byte <= byte_range[1]:
                return site
    return {}

# Tìm failure slice liên quan đến statement chứa atom.
def _slice_for_atom(statement_id: str, failure_slices: List[dict]) -> dict:
    for failure_slice in failure_slices:
        seed = failure_slice.get("seed_statement") or {}
        if seed.get("id") == statement_id:
            return failure_slice
        for key in ("backward_dependencies", "forward_impacts"):
            for dep in failure_slice.get(key) or []:
                if dep.get("id") == statement_id:
                    return failure_slice
    return {}
