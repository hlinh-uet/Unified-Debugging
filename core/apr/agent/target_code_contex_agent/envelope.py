from typing import Any, Dict, List, Tuple

from core.apr.agent.context_common import (
    find_function_node,
    function_name_from_declarator,
    line_number_for_byte,
    source_slice_by_byte_range,
)

# Stage 1: xác định target function và replacement envelope.
def build_target_envelope(
    *,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    language: str,
) -> Dict[str, Any]:
    (
        replacement_start,
        replacement_end,
        replacement_unit,
        envelope_notes,
        resolved_name,
    ) = _replacement_envelope(
        source_code=source_code,
        func_name=func_name,
        language=language,
        fallback_start=start_idx,
        fallback_end=end_idx,
    )
    if not replacement_unit:
        replacement_start, replacement_end = start_idx, end_idx
        replacement_unit = func_code or ""
        envelope_notes.append("fallback_to_original_extracted_function_range")

    target_identity = _target_identity(
        requested_name=func_name,
        resolved_name=resolved_name,
        cand_label=cand_label,
        source_path=source_path,
        language=language,
        source_code=source_code,
        original_start=start_idx,
        original_end=end_idx,
        replacement_start=replacement_start,
        replacement_end=replacement_end,
        envelope_notes=envelope_notes,
    )
    target_envelope = {
        "function_name": func_name,
        "resolved_function_name": resolved_name or func_name,
        "source_file": cand_label,
        "source_path": source_path,
        "language": language,
        "original_function_range": {
            "start_byte": start_idx,
            "end_byte": end_idx,
            "start_line": line_number_for_byte(source_code, start_idx),
            "end_line": line_number_for_byte(source_code, end_idx),
        },
        "replacement_range": {
            "start_byte": replacement_start,
            "end_byte": replacement_end,
            "start_line": line_number_for_byte(source_code, replacement_start),
            "end_line": line_number_for_byte(source_code, replacement_end),
        },
        "replacement_includes_prefix": replacement_start != start_idx,
        "replacement_prefix": source_slice_by_byte_range(source_code, replacement_start, start_idx)
        if replacement_start != start_idx else "",
        "replacement_unit": replacement_unit,
        "output_contract": _output_contract(
            replacement_start=replacement_start,
            original_start=start_idx,
            language=language,
            replacement_unit=replacement_unit,
        ),
        "notes": envelope_notes,
    }
    return {
        "target_identity": target_identity,
        "target_envelope": target_envelope,
        "replacement_start": replacement_start,
        "replacement_end": replacement_end,
        "replacement_unit": replacement_unit,
        "envelope_notes": envelope_notes,
        "resolved_name": resolved_name or func_name,
        "original_start": start_idx,
        "original_end": end_idx,
    }

# Xác định replacement unit chính xác bằng tree-sitter, gồm cả template prefix nếu cần.
def _replacement_envelope(
    *,
    source_code: str,
    func_name: str,
    language: str,
    fallback_start: int,
    fallback_end: int,
) -> Tuple[int, int, str, List[str], str]:
    notes = []
    node, _, source_bytes = find_function_node(source_code, func_name, language)
    if node is None or source_bytes is None:
        notes.append("tree_sitter_function_node_not_found")
        return fallback_start, fallback_end, "", notes, ""
    if not _ranges_overlap_strongly(node.start_byte, node.end_byte, fallback_start, fallback_end):
        notes.append("tree_sitter_function_node_mismatched_caller_range")
        fallback = source_slice_by_byte_range(source_code, fallback_start, fallback_end)
        return fallback_start, fallback_end, fallback, notes, func_name

    resolved_name = ""
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        resolved_name = function_name_from_declarator(declarator, source_bytes)

    start = node.start_byte
    end = node.end_byte
    parent = getattr(node, "parent", None)
    if parent is not None and parent.type in {"template_declaration", "template_declaration_repeat1"}:
        start = parent.start_byte
        end = parent.end_byte
        notes.append(f"replacement_range_expanded_to_parent:{parent.type}")

    start = _expand_to_adjacent_template_prefix(source_code, start)
    if start < node.start_byte and "replacement_range_expanded_to_adjacent_template_prefix" not in notes:
        notes.append("replacement_range_expanded_to_adjacent_template_prefix")

    replacement = source_bytes[start:end].decode("utf-8", errors="replace")
    return start, end, replacement, notes, resolved_name

# Kiểm tra range tree-sitter có khớp đủ mạnh với range extractor ban đầu không.
def _ranges_overlap_strongly(start: int, end: int, fallback_start: int, fallback_end: int) -> bool:
    if start < 0 or end <= start or fallback_start < 0 or fallback_end <= fallback_start:
        return True
    overlap = max(0, min(end, fallback_end) - max(start, fallback_start))
    min_len = max(1, min(end - start, fallback_end - fallback_start))
    return overlap / min_len >= 0.80

# Mở rộng range lùi lên dòng template liền trước để replacement C++ không mất ngữ cảnh.
def _expand_to_adjacent_template_prefix(source_code: str, start_byte: int) -> int:
    source_bytes = source_code.encode("utf-8")
    start_char = len(source_bytes[:start_byte].decode("utf-8", errors="replace"))
    prefix = source_code[:start_char]
    line_start = prefix.rfind("\n") + 1
    prev_end = line_start
    while prev_end > 0:
        prev_start = prefix.rfind("\n", 0, prev_end - 1) + 1
        line = prefix[prev_start:prev_end].strip()
        if not line:
            prev_end = prev_start
            continue
        if line.startswith("template"):
            return len(source_code[:prev_start].encode("utf-8"))
        break
    return start_byte

# Tóm tắt danh tính target và độ tin cậy của range được chọn.
def _target_identity(
    *,
    requested_name: str,
    resolved_name: str,
    cand_label: str,
    source_path: str,
    language: str,
    source_code: str,
    original_start: int,
    original_end: int,
    replacement_start: int,
    replacement_end: int,
    envelope_notes: List[str],
) -> Dict[str, Any]:
    notes = set(envelope_notes or [])
    tree_sitter_found = not (
        "tree_sitter_function_node_not_found" in notes
        or "tree_sitter_function_node_mismatched_caller_range" in notes
    )
    exact_replacement = replacement_start == original_start and replacement_end == original_end
    confidence = "high" if tree_sitter_found else "medium"
    if not exact_replacement and not tree_sitter_found:
        confidence = "low"
    return {
        "requested_name": requested_name,
        "resolved_name": resolved_name or requested_name,
        "source_file": cand_label,
        "source_path": source_path,
        "language": language,
        "resolution_strategy": "tree_sitter_function_definition" if tree_sitter_found else "caller_extracted_fallback_range",
        "range_confidence": confidence,
        "original_line_range": [
            line_number_for_byte(source_code, original_start),
            line_number_for_byte(source_code, original_end),
        ],
        "replacement_line_range": [
            line_number_for_byte(source_code, replacement_start),
            line_number_for_byte(source_code, replacement_end),
        ],
        "replacement_matches_original_range": exact_replacement,
        "notes": envelope_notes,
    }

# Sinh contract output để LLM trả về đúng raw replacement unit.
def _output_contract(
    *,
    replacement_start: int,
    original_start: int,
    language: str,
    replacement_unit: str,
) -> List[str]:
    rules = [
        "Output raw source only: no markdown, prose, XML, or code fences.",
        "The output will replace target_envelope.replacement_range exactly.",
        "Preserve target_identity.resolved_name, signature, and enclosing scope.",
    ]
    if replacement_start != original_start:
        rules.append("Output must preserve any template/declaration prefix included in target_envelope.replacement_unit.")
    elif language in {"cpp", "c++"} and "template" not in replacement_unit[:200]:
        rules.append("Do not add an external template prefix unless it appears in target_envelope.replacement_unit.")
    return rules
