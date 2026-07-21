import hashlib
import json
import os
import re
from typing import Any, Dict, List, Optional, Tuple

from dotenv import load_dotenv

from core.utils import (
    Language,
    Parser,
    source_byte_range_to_char_range,
    tree_sitter_c,
    tree_sitter_cpp,
)


load_dotenv()

DEFAULT_LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter").strip().lower()

APR_TOP_K = int(os.getenv("APR_TOP_K", "3"))
APR_MAX_SOURCE_CHARS = int(os.getenv("APR_MAX_SOURCE_CHARS", "30000"))
APR_MAX_LOCAL_HEADER_CONTEXT_CHARS = int(os.getenv("APR_MAX_LOCAL_HEADER_CONTEXT_CHARS", "12000"))
APR_MAX_TEST_ID_STORE = int(os.getenv("APR_MAX_TEST_ID_STORE", "50"))
APR_MAX_FAILURE_SIGNAL_LINES = int(os.getenv("APR_MAX_FAILURE_SIGNAL_LINES", "20"))
APR_MAX_FAILURE_SIGNAL_LINE_CHARS = int(os.getenv("APR_MAX_FAILURE_SIGNAL_LINE_CHARS", "300"))
APR_SKIP_EXISTING = os.getenv("APR_SKIP_EXISTING", "1").strip().lower() not in ("0", "false", "no")

SOURCE_EXTS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".inl",
    ".inc",
}


def clip_text(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value).rstrip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"


def dedup_keep_order(values: List[str]) -> List[str]:
    out = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        out.append(text)
        seen.add(text)
    return out


def source_language_from_path(path: str) -> str:
    ext = os.path.splitext(path or "")[1].lower()
    return "cpp" if ext in (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".h") else "c"


def is_defects4c_dataset(dataset: str) -> bool:
    return (dataset or "").strip().lower() != "codeflaws"


def candidate_relpath_from_buggy_tree(candidate_path: str, raw_meta: Optional[dict]) -> str:
    if not candidate_path or not raw_meta:
        return ""
    buggy_tree_dir = raw_meta.get("buggy_tree_dir") or ""
    if not buggy_tree_dir:
        return ""
    try:
        rel = os.path.relpath(candidate_path, buggy_tree_dir).replace(os.sep, "/")
    except ValueError:
        return ""
    if rel.startswith("../") or rel == ".." or os.path.isabs(rel):
        return ""
    return rel


def build_replacement_target(
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
    """Resolve the exact source range APR may replace for one candidate function."""
    (
        replacement_start,
        replacement_end,
        replacement_unit,
        notes,
        resolved_name,
        range_metadata,
    ) = _replacement_envelope(
        source_code=source_code,
        func_name=func_name,
        language=language,
        fallback_start=start_idx,
        fallback_end=end_idx,
    )
    if not replacement_unit:
        return {
            "analysis_engine": {
                "name": "replacement_target",
                "version": 1,
                "strategy": "tree_sitter_source_byte_range_resolution",
                "parser": parser_diagnostics(language),
                "capabilities": [
                    "replacement_range_resolution",
                    "template_prefix_preservation",
                ],
            },
            "status": "not_found",
            "error": ";".join(notes) or "tree_sitter_function_node_not_found",
            "replacement_identity": {},
            "replacement_envelope": {},
            "replacement_start": -1,
            "replacement_end": -1,
            "replacement_unit": "",
        }

    replacement_identity = _replacement_identity(
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
        notes=notes,
    )
    replacement_envelope = {
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
        "replacement_prefix": (
            source_slice_by_byte_range(source_code, replacement_start, start_idx)
            if replacement_start != start_idx
            else ""
        ),
        "replacement_unit": replacement_unit,
        "range_normalization": range_metadata,
        "notes": notes,
    }
    return {
        "analysis_engine": {
            "name": "replacement_target",
            "version": 1,
            "strategy": "tree_sitter_source_byte_range_resolution",
            "parser": parser_diagnostics(language),
            "capabilities": [
                "replacement_range_resolution",
                "template_prefix_preservation",
            ],
        },
        "replacement_identity": replacement_identity,
        "replacement_envelope": replacement_envelope,
        "replacement_start": replacement_start,
        "replacement_end": replacement_end,
        "replacement_unit": replacement_unit,
        "repair_scope": build_repair_scope([replacement_identity]),
    }


def enumerate_function_targets(
    source_code: str,
    requested_name: str,
    language: str,
    *,
    source_path: str = "",
    source_file: str = "",
) -> List[Dict[str, Any]]:
    """Return every AST definition compatible with a requested symbol.

    Target discovery must preserve overload ambiguity.  The returned identity
    includes scope, signature, byte/line range and a stable source hash so CPG
    backends can enrich, but never silently replace, source identity.
    """
    tree, source_bytes = parse_tree(source_code or "", language)
    if tree is None or source_bytes is None:
        return []
    requested = _clean_qualified_name(requested_name)
    requested_scoped = "::" in requested
    out = []
    for node in walk_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        actual = function_name_from_declarator(declarator, source_bytes)
        names = _function_candidate_names(node, actual, source_bytes)
        qualified = max(names, key=lambda value: value.count("::"), default=actual)
        if requested_scoped:
            matched = any(
                name == requested or name.endswith("::" + requested)
                for name in names
            )
        else:
            matched = any(name.rsplit("::", 1)[-1] == requested for name in names)
        if not matched:
            continue
        code = node_text(node, source_bytes)
        header = signature_without_constructor_initializers(code)
        scopes = qualified.split("::")[:-1] if "::" in qualified else []
        digest = hashlib.sha256(code.encode("utf-8", errors="replace")).hexdigest()
        target_identity = {
            "identity_version": 1,
            "source_file": os.path.normpath(source_file or source_path or "").replace("\\", "/"),
            "language": language,
            "start_byte": int(node.start_byte),
            "end_byte": int(node.end_byte),
            "ast_hash": digest,
        }
        target_id = "tsfn:" + hashlib.sha256(
            json.dumps(target_identity, sort_keys=True, separators=(",", ":")).encode("utf-8")
        ).hexdigest()
        out.append({
            "id": f"ast_target_{len(out) + 1:03d}_{digest[:10]}",
            "target_id": target_id,
            "requested_name": requested_name,
            "resolved_name": qualified or actual or requested_name,
            "leaf_name": (qualified or actual or requested_name).rsplit("::", 1)[-1],
            "signature": header,
            "enclosing_scopes": scopes,
            "source_path": source_path,
            "source_file": source_file,
            "language": language,
            "start_byte": int(node.start_byte),
            "end_byte": int(node.end_byte),
            "start_line": int(node.start_point[0]) + 1,
            "end_line": int(node.end_point[0]) + 1,
            "ast_hash": digest,
            "code": code,
            "resolution_strategy": "tree_sitter_ast_enumeration",
            "resolution_confidence": "high" if len(names) > 1 or actual == requested else "medium",
        })
    return out


def build_repair_scope(units: List[Dict[str, Any]], *, atomic: bool = True) -> Dict[str, Any]:
    compact = []
    keep = {
        "id", "target_id", "identity_version", "requested_name", "resolved_name", "qualified_name", "leaf_name",
        "signature", "enclosing_scopes", "source_path", "source_file", "language",
        "start_byte", "end_byte", "start_line", "end_line", "ast_hash",
        "resolution_strategy", "resolution_confidence", "range_confidence",
    }
    for index, unit in enumerate(units or [], start=1):
        if not isinstance(unit, dict):
            continue
        item = {key: unit.get(key) for key in keep if key in unit}
        item.setdefault("id", f"repair_unit_{index:03d}")
        compact.append(item)
    return {
        "kind": "single_unit" if len(compact) <= 1 else "coordinated_units",
        "atomic": bool(atomic),
        "units": compact,
        "unit_count": len(compact),
    }


def disambiguate_function_targets(
    candidates: List[Dict[str, Any]],
    hints: Optional[Dict[str, Any]] = None,
    *,
    signature_hint: str = "",
    line_hints: Optional[List[int]] = None,
    runtime_frames: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Resolve only when exact structural discriminators select one AST node."""
    candidates = [dict(item) for item in candidates or [] if isinstance(item, dict)]
    if len(candidates) <= 1:
        return {"status": "resolved" if candidates else "not_found", "candidate": candidates[0] if candidates else None, "candidates": candidates, "scores": []}
    hints = hints if isinstance(hints, dict) else {}
    signature_hint = "".join(
        str(signature_hint or hints.get("signature") or hints.get("signature_hint") or "").split()
    )
    covered_lines = {int(item) for item in (line_hints or hints.get("covered_lines") or []) if str(item).isdigit()}
    exact_sets = []
    discriminators = []
    if signature_hint:
        signature_ids = {
            str(item.get("target_id") or item.get("id") or "")
            for item in candidates
            if "".join(str(item.get("signature") or "").split()) == signature_hint
        }
        exact_sets.append(signature_ids)
        discriminators.append("exact_signature")
    if covered_lines:
        line_ids = {
            str(item.get("target_id") or item.get("id") or "")
            for item in candidates
            if any(
                int(item.get("start_line") or 0) <= line <= int(item.get("end_line") or 0)
                for line in covered_lines
            )
        }
        exact_sets.append(line_ids)
        discriminators.append("exact_source_line_containment")
    matched_ids = set.intersection(*exact_sets) if exact_sets else set()
    matched = [
        item for item in candidates
        if str(item.get("target_id") or item.get("id") or "") in matched_ids
    ]
    if len(matched) == 1:
        return {
            "status": "resolved",
            "candidate": matched[0],
            "candidates": matched,
            "scores": [],
            "discriminator": discriminators,
        }
    uncertainties = ["exact_target_discriminator_not_unique"]
    if runtime_frames or hints.get("stack_frames"):
        uncertainties.append("unstructured_runtime_frames_not_used_for_hard_resolution")
    return {
        "status": "ambiguous",
        "candidates": candidates,
        "scores": [],
        "uncertainties": uncertainties,
    }


def _replacement_envelope(
    *,
    source_code: str,
    func_name: str,
    language: str,
    fallback_start: int,
    fallback_end: int,
) -> Tuple[int, int, str, List[str], str, Dict[str, Any]]:
    notes: List[str] = []
    node, _, source_bytes = find_function_node_at_byte_range(
        source_code,
        language,
        fallback_start,
        fallback_end,
    )
    if node is None:
        node, _, source_bytes = find_function_node(source_code, func_name, language)
    if node is None or source_bytes is None:
        notes.append("tree_sitter_function_node_not_found")
        return fallback_start, fallback_end, "", notes, "", {}
    if not _ranges_overlap_strongly(node.start_byte, node.end_byte, fallback_start, fallback_end):
        notes.append("tree_sitter_function_node_mismatched_caller_range")
        fallback = source_slice_by_byte_range(source_code, fallback_start, fallback_end)
        return fallback_start, fallback_end, fallback, notes, func_name, {}

    resolved_name = ""
    declarator = node.child_by_field_name("declarator")
    if declarator is not None:
        resolved_name = function_name_from_declarator(declarator, source_bytes)

    start, end, range_metadata = _normalize_tree_sitter_replacement_range(
        source_code=source_code,
        node=node,
        notes=notes,
    )

    replacement = source_bytes[start:end].decode("utf-8", errors="replace")
    return start, end, replacement, notes, resolved_name, range_metadata


def extract_function_code_by_line_range(
    source_code: str,
    *,
    start_line: int,
    end_line: int,
    language: str,
    requested_name: str = "",
) -> Tuple[Optional[str], int, int, str, List[str], Dict[str, Any]]:
    tree, source_bytes = parse_tree(source_code or "", language)
    if tree is None or source_bytes is None:
        return None, -1, -1, "", ["tree_sitter_parse_failed_for_resolved_line_range"], {}
    try:
        target_start = int(start_line)
    except Exception:
        target_start = -1
    try:
        target_end = int(end_line)
    except Exception:
        target_end = target_start
    if target_start <= 0:
        return None, -1, -1, "", ["invalid_resolved_start_line"], {}
    if target_end < target_start:
        target_end = target_start

    candidates = []
    for node in walk_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        node_start = int(node.start_point[0]) + 1
        node_end = int(node.end_point[0]) + 1
        score = _line_range_overlap_score(node_start, node_end, target_start, target_end)
        if score <= 0:
            continue
        declarator = node.child_by_field_name("declarator")
        resolved_name = function_name_from_declarator(declarator, source_bytes) if declarator is not None else ""
        name_bonus = 1 if requested_name and function_matches(resolved_name, requested_name) else 0
        candidates.append((score, name_bonus, -(abs(node_start - target_start)), node, resolved_name))
    if not candidates:
        return None, -1, -1, "", ["tree_sitter_function_node_not_found_for_resolved_line_range"], {}

    _, _, _, node, resolved_name = max(candidates, key=lambda item: (item[0], item[1], item[2]))
    notes = ["tree_sitter_range_from_resolved_line_range"]
    start, end, range_metadata = _normalize_tree_sitter_replacement_range(
        source_code=source_code,
        node=node,
        notes=notes,
    )
    code = source_bytes[start:end].decode("utf-8", errors="replace")
    return code, start, end, resolved_name, notes, range_metadata


def _line_range_overlap_score(
    node_start: int,
    node_end: int,
    target_start: int,
    target_end: int,
) -> int:
    if node_start <= target_start <= node_end:
        return 1000 - min(500, abs(node_start - target_start))
    overlap = max(0, min(node_end, target_end) - max(node_start, target_start) + 1)
    if overlap:
        return overlap
    return 0


def _ranges_overlap_strongly(start: int, end: int, fallback_start: int, fallback_end: int) -> bool:
    if start < 0 or end <= start or fallback_start < 0 or fallback_end <= fallback_start:
        return True
    overlap = max(0, min(end, fallback_end) - max(start, fallback_start))
    min_len = max(1, min(end - start, fallback_end - fallback_start))
    return overlap / min_len >= 0.80


def _normalize_tree_sitter_replacement_range(
    *,
    source_code: str,
    node: Any,
    notes: List[str],
) -> Tuple[int, int, Dict[str, Any]]:
    raw_start = int(node.start_byte)
    raw_end = int(node.end_byte)
    start = raw_start
    end = raw_end
    expansion_reasons: List[str] = []

    parent = getattr(node, "parent", None)
    if parent is not None and parent.type in {"template_declaration", "template_declaration_repeat1"}:
        start = int(parent.start_byte)
        end = int(parent.end_byte)
        reason = f"replacement_range_expanded_to_parent:{parent.type}"
        notes.append(reason)
        expansion_reasons.append(reason)

    normalized_start = _expand_to_adjacent_declaration_prefix(source_code, start)
    if normalized_start < start:
        reason = "replacement_range_expanded_to_adjacent_declaration_prefix"
        notes.append(reason)
        expansion_reasons.append(reason)
        start = normalized_start

    return start, end, {
        "raw_ast_range": {
            "start_byte": raw_start,
            "end_byte": raw_end,
            "start_line": line_number_for_byte(source_code, raw_start),
            "end_line": line_number_for_byte(source_code, raw_end),
        },
        "normalized_range": {
            "start_byte": start,
            "end_byte": end,
            "start_line": line_number_for_byte(source_code, start),
            "end_line": line_number_for_byte(source_code, end),
        },
        "expanded_prefix": source_slice_by_byte_range(source_code, start, raw_start) if start < raw_start else "",
        "expansion_reasons": expansion_reasons,
    }


def _expand_to_adjacent_declaration_prefix(source_code: str, start_byte: int) -> int:
    start = _expand_to_same_line_declaration_prefix(source_code, start_byte)
    return _expand_to_previous_declaration_prefix_lines(source_code, start)


def _expand_to_same_line_declaration_prefix(source_code: str, start_byte: int) -> int:
    start_char, _ = source_byte_range_to_char_range(source_code, start_byte, start_byte)
    line_start = source_code.rfind("\n", 0, start_char) + 1
    prefix = source_code[line_start:start_char]
    if _is_safe_declaration_prefix(prefix):
        return len(source_code[:line_start].encode("utf-8"))
    return start_byte


def _expand_to_previous_declaration_prefix_lines(source_code: str, start_byte: int) -> int:
    start_char, _ = source_byte_range_to_char_range(source_code, start_byte, start_byte)
    cursor = source_code.rfind("\n", 0, start_char)
    if cursor < 0:
        return start_byte
    best_char = start_char
    while cursor >= 0:
        prev_end = cursor
        prev_start = source_code.rfind("\n", 0, prev_end)
        line_start = 0 if prev_start < 0 else prev_start + 1
        line = source_code[line_start:prev_end]
        stripped = line.strip()
        if not stripped:
            break
        if not _is_declaration_prefix_line(stripped):
            break
        best_char = line_start
        if prev_start < 0:
            break
        cursor = prev_start
    if best_char < start_char:
        return len(source_code[:best_char].encode("utf-8"))
    return start_byte


def _is_safe_declaration_prefix(prefix: str) -> bool:
    stripped = (prefix or "").strip()
    if not stripped:
        return False
    if any(ch in stripped for ch in (";", "{", "}")):
        return False
    if stripped.startswith("#"):
        return False
    return _balanced_prefix_delimiters(stripped)


def _is_declaration_prefix_line(stripped: str) -> bool:
    if not _is_safe_declaration_prefix(stripped):
        return False
    if stripped.startswith("//") or stripped.startswith("/*") or stripped.startswith("*"):
        return False
    if stripped.startswith("template") or stripped.startswith("[["):
        return True
    first = _first_identifier_token(stripped)
    if not first:
        return False
    if first in {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "case",
        "do",
        "else",
        "goto",
        "typedef",
    }:
        return False
    return True


def _first_identifier_token(text: str) -> str:
    token = []
    for ch in text.lstrip():
        if ch == "_" or ch.isalpha() or (token and ch.isdigit()):
            token.append(ch)
            continue
        break
    return "".join(token)


def _balanced_prefix_delimiters(text: str) -> bool:
    pairs = {")": "(", "]": "[", ">": "<"}
    stack: List[str] = []
    quote = ""
    escaped = False
    for ch in text:
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "([<":
            stack.append(ch)
        elif ch in ")]>":
            if not stack or stack[-1] != pairs[ch]:
                return False
            stack.pop()
    return not stack and not quote


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


def _replacement_identity(
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
    notes: List[str],
) -> Dict[str, Any]:
    note_set = set(notes or [])
    tree_sitter_found = not (
        "tree_sitter_function_node_not_found" in note_set
        or "tree_sitter_function_node_mismatched_caller_range" in note_set
    )
    exact_replacement = replacement_start == original_start and replacement_end == original_end
    confidence = "high" if tree_sitter_found else "medium"
    if not exact_replacement and not tree_sitter_found:
        confidence = "low"
    replacement_source = source_slice_by_byte_range(source_code, replacement_start, replacement_end)
    resolved = resolved_name or requested_name
    return {
        "requested_name": requested_name,
        "resolved_name": resolved_name or requested_name,
        "qualified_name": resolved,
        "leaf_name": _clean_qualified_name(resolved).rsplit("::", 1)[-1],
        "signature": signature_without_constructor_initializers(replacement_source),
        "enclosing_scopes": _clean_qualified_name(resolved).split("::")[:-1],
        "ast_hash": hashlib.sha256(replacement_source.encode("utf-8", errors="replace")).hexdigest(),
        "source_file": cand_label,
        "source_path": source_path,
        "language": language,
        "resolution_strategy": (
            "tree_sitter_function_definition"
            if tree_sitter_found
            else "caller_extracted_fallback_range"
        ),
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
        "notes": notes,
    }


def compact_test_list(test_ids):
    """Bound stored test IDs in result JSON without changing validation behavior."""
    if not test_ids or APR_MAX_TEST_ID_STORE <= 0 or len(test_ids) <= APR_MAX_TEST_ID_STORE:
        return list(test_ids) if test_ids else []
    extra = len(test_ids) - APR_MAX_TEST_ID_STORE
    return list(test_ids[:APR_MAX_TEST_ID_STORE]) + [f"...(+{extra} more)"]


def dedup_initial_test_ids(tests):
    """Return unique initial passed/failed test IDs, with FAIL winning duplicates."""
    status_by_id = {}
    order = []
    for test in tests or []:
        if not isinstance(test, dict):
            continue
        tid = str(test.get("test_id") or "").strip()
        if not tid:
            continue
        if tid not in status_by_id:
            status_by_id[tid] = "PASS"
            order.append(tid)
        outcome = str(test.get("outcome") or "").upper()
        if outcome in ("FAIL", "FAILED"):
            status_by_id[tid] = "FAIL"
        elif outcome in ("PASS", "PASSED") and status_by_id.get(tid) != "FAIL":
            status_by_id[tid] = "PASS"

    failed = [tid for tid in order if status_by_id.get(tid) == "FAIL"]
    passed = [tid for tid in order if status_by_id.get(tid) == "PASS"]
    return passed, failed


def _failed_test_log_segment(test_id: str, validation_log_tail: str) -> str:
    marker = f"__UD_FAIL__ {test_id}"
    lines = str(validation_log_tail or "").splitlines()
    segment = []
    collecting = False
    for line in lines:
        if line.strip() == marker:
            collecting = True
            segment.append(line)
            continue
        if collecting and re.match(r"^__UD_(?:PASS|FAIL|TIMEOUT)__\s+", line):
            break
        if collecting:
            segment.append(line)
    return "\n".join(segment)


def is_zero_test_artifact_failure(test_id: str, validation_details: Optional[dict]) -> bool:
    """Return True for CTest targets that passed but contained zero gtests."""
    tid = str(test_id or "").strip()
    if not tid or "::" in tid or not isinstance(validation_details, dict):
        return False

    segment = _failed_test_log_segment(
        tid,
        str(validation_details.get("validation_log_tail") or ""),
    )
    if not segment or "Running 0 tests" not in segment:
        return False
    if "***Failed" in segment or "[  FAILED  ]" in segment:
        return False
    return "100% tests passed" in segment or "[  PASSED  ] 0 tests" in segment


def filter_zero_test_artifact_failures(test_ids, validation_details: Optional[dict]):
    return [
        str(tid).strip()
        for tid in test_ids or []
        if str(tid).strip()
        and not is_zero_test_artifact_failure(str(tid).strip(), validation_details)
    ]


def classify_patch_outcome(init_failed, post_failed, validation_error: str = "") -> str:
    """Classify one patch using the same test scope for init and post."""
    if str(validation_error or "").strip():
        return "invalid"

    init_failed_set = {str(t).strip() for t in init_failed or [] if str(t).strip()}
    post_failed_set = {str(t).strip() for t in post_failed or [] if str(t).strip()}
    if not post_failed_set:
        return "plausible"

    fixed = init_failed_set - post_failed_set
    regressions = post_failed_set - init_failed_set
    if fixed and regressions:
        return "noisefix"
    if fixed:
        return "cleanfix"
    if regressions:
        return "negfix"
    return "nonefix"


def is_plausible_status(status: object) -> bool:
    """Accept both the current outcome label and legacy APR success records."""
    return str(status or "").strip().lower() in {"plausible", "success"}


def candidate_list_len(candidate: dict, key: str, default: int = 10**9) -> int:
    """Return the length of a stored test-list field for candidate ranking."""
    candidate = candidate or {}
    values = candidate.get(key)
    return len(values) if isinstance(values, list) else default


_CANDIDATE_STATUS_RANK = {
    # A candidate that passes the complete validation scope is always best.
    "plausible": 0,
    "success": 0,
    # Preserve semantic progress before comparing raw failure counts.  In
    # particular, a ReFix that loses an original fix (nonefix) must not replace
    # an earlier partial fix merely because the regression set is smaller.
    "cleanfix": 1,
    "noisefix": 2,
    "nonefix": 3,
    "negfix": 4,
    "invalid": 5,
}


def candidate_status_rank(status: object) -> int:
    """Return the APR outcome rank used to retain the best candidate so far."""
    normalized = str(status or "").strip().lower()
    return _CANDIDATE_STATUS_RANK.get(normalized, 6)


def candidate_quality_key(candidate: dict) -> tuple:
    """Lower is better when comparing Fix/ReFix candidates or artifacts."""
    status = str((candidate or {}).get("status") or "").strip().lower()
    real_status = str((candidate or {}).get("real_status") or status).strip().lower()
    return (
        candidate_status_rank(status),
        candidate_status_rank(real_status),
        candidate_list_len(candidate, "post_failed_tests"),
        candidate_list_len(candidate, "full_post_failed_tests"),
        -candidate_list_len(candidate, "post_passed_tests", default=0),
        -candidate_list_len(candidate, "full_post_passed_tests", default=0),
        1 if str((candidate or {}).get("validation_error") or "").strip() else 0,
    )


def candidate_is_strictly_better(candidate: dict, baseline: dict) -> bool:
    """Return True only when candidate improves the best-so-far baseline."""
    if not candidate:
        return False
    if not baseline:
        return True

    candidate_key = candidate_quality_key(candidate)
    baseline_key = candidate_quality_key(baseline)
    if candidate_key >= baseline_key:
        return False

    candidate_patch_failed = candidate_list_len(candidate, "post_failed_tests")
    baseline_patch_failed = candidate_list_len(baseline, "post_failed_tests")
    candidate_full_failed = candidate_list_len(candidate, "full_post_failed_tests")
    baseline_full_failed = candidate_list_len(baseline, "full_post_failed_tests")

    if candidate_patch_failed > baseline_patch_failed:
        return False
    if candidate_full_failed > baseline_full_failed:
        return False

    return True


def is_source_like(path: str) -> bool:
    return os.path.splitext(path or "")[1].lower() in SOURCE_EXTS


def nearest_git_root(path: str) -> str:
    cur = path if os.path.isdir(path) else os.path.dirname(path)
    while cur and cur != os.path.dirname(cur):
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        cur = os.path.dirname(cur)
    return ""


def source_root(source_path: str, context_root: Optional[str]) -> str:
    if context_root and os.path.isdir(context_root):
        return os.path.normpath(context_root)
    return nearest_git_root(source_path) or os.path.normpath(os.path.dirname(source_path))


def relpath(path: str, root: str) -> str:
    try:
        value = os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path
    return value if not value.startswith("../") else path


def tree_sitter_language(language: str):
    key = (language or "c").strip().lower()
    module = tree_sitter_cpp if key in ("cpp", "c++", "cc", "cxx") else tree_sitter_c
    if module is None or Language is None:
        return None
    try:
        return Language(module.language())
    except Exception:
        try:
            return module.language()
        except Exception:
            return None


def parser_diagnostics(language: str) -> Dict[str, Any]:
    key = (language or "c").strip().lower()
    wants_cpp = key in ("cpp", "c++", "cc", "cxx")
    module = tree_sitter_cpp if wants_cpp else tree_sitter_c
    grammar = "tree_sitter_cpp" if wants_cpp else "tree_sitter_c"
    available = Parser is not None and Language is not None and module is not None
    lang = tree_sitter_language(language) if available else None
    return {
        "parser_package_available": Parser is not None and Language is not None,
        "grammar": grammar,
        "grammar_available": module is not None,
        "language_object_available": lang is not None,
        "ast_preferred": True,
        "fallback_policy": "No parser fallback; callers must report tree-sitter resolution failures.",
    }


def parse_tree(source: str, language: str):
    if Parser is None:
        return None, None
    lang = tree_sitter_language(language)
    if lang is None:
        return None, None
    parser = Parser()
    try:
        parser.language = lang
    except Exception:
        try:
            parser.set_language(lang)
        except Exception:
            return None, None
    source_bytes = source.encode("utf-8")
    try:
        return parser.parse(source_bytes), source_bytes
    except Exception:
        return None, None


def constructor_initializer_names(source: str, language: str = "cpp") -> List[str]:
    names = _constructor_initializer_names_ast(source, language)
    if names:
        return names
    initializer_text = _constructor_initializer_text(source)
    if not initializer_text:
        return []
    out = []
    for part in split_top_level_commas(initializer_text):
        match = re.match(r"\s*([A-Za-z_]\w*)\s*(?:\(|\{)", part)
        if match:
            out.append(match.group(1))
    return dedup_keep_order(out)


def signature_without_constructor_initializers(source: str) -> str:
    header = str(source or "").split("{", 1)[0]
    close = _find_first_parameter_list_close(header)
    if close >= 0:
        suffix = header[close + 1 :]
        colon = _find_top_level_constructor_colon(suffix)
        if colon >= 0:
            header = header[: close + 1] + suffix[:colon]
    return re.sub(r"\s+", " ", header).strip()


def split_top_level_commas(text: str) -> List[str]:
    parts = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for idx, ch in enumerate(text or ""):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:idx])
            start = idx + 1
    parts.append((text or "")[start:])
    return parts


def _constructor_initializer_names_ast(source: str, language: str) -> List[str]:
    tree, source_bytes = parse_tree(source or "", language)
    if tree is None or source_bytes is None:
        return []
    names = []
    for node in walk_nodes(tree.root_node):
        if node.type != "field_initializer":
            continue
        field = None
        try:
            field = node.child_by_field_name("field")
        except Exception:
            field = None
        if field is not None:
            text = node_text(field, source_bytes).strip()
            if text:
                names.append(text)
                continue
        for child in node.children:
            if child.type == "field_identifier":
                text = node_text(child, source_bytes).strip()
                if text:
                    names.append(text)
                    break
    return dedup_keep_order(names)


def _constructor_initializer_text(source: str) -> str:
    header = str(source or "").split("{", 1)[0]
    if not header:
        return ""
    close = _find_first_parameter_list_close(header)
    if close < 0:
        return ""
    suffix = header[close + 1 :]
    colon = _find_top_level_constructor_colon(suffix)
    return suffix[colon + 1 :].strip() if colon >= 0 else ""


def _find_first_parameter_list_close(header: str) -> int:
    open_idx = header.find("(")
    if open_idx < 0:
        return -1
    depth = 0
    quote = ""
    escaped = False
    for idx in range(open_idx, len(header)):
        ch = header[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _find_top_level_constructor_colon(text: str) -> int:
    depth = 0
    quote = ""
    escaped = False
    for idx, ch in enumerate(text or ""):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        elif ch == ":" and depth == 0:
            prev_ch = text[idx - 1] if idx > 0 else ""
            next_ch = text[idx + 1] if idx + 1 < len(text) else ""
            if prev_ch != ":" and next_ch != ":":
                return idx
    return -1


def walk_nodes(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def function_name_from_declarator(declarator, source_bytes: bytes) -> str:
    nested = declarator.child_by_field_name("declarator")
    if nested is not None:
        name = function_name_from_declarator(nested, source_bytes)
        if name:
            return name

    for field in ("name", "field", "operator"):
        try:
            child = declarator.child_by_field_name(field)
        except Exception:
            child = None
        if child is not None:
            return _clean_qualified_name(node_text(child, source_bytes))

    if declarator.type in (
        "identifier",
        "field_identifier",
        "destructor_name",
        "operator_name",
    ):
        return _clean_qualified_name(node_text(declarator, source_bytes))

    if declarator.type in ("qualified_identifier", "template_function"):
        return _clean_qualified_name(node_text(declarator, source_bytes))

    for child in declarator.children:
        name = function_name_from_declarator(child, source_bytes)
        if name:
            return name
    return ""


def call_name_from_node(function_node, source_bytes: bytes) -> str:
    text = node_text(function_node, source_bytes).strip()
    if not text:
        return ""
    text = text.split("::")[-1].split("<", 1)[0].strip()
    if "->" in text:
        text = text.rsplit("->", 1)[-1].strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1].strip()
    return text


def function_matches(actual: str, requested: str) -> bool:
    actual = _clean_qualified_name(actual)
    requested = _clean_qualified_name(requested)
    if actual == requested:
        return True
    if "::" in requested and actual.endswith("::" + requested):
        return True
    if "::" in requested:
        return False
    if actual.rsplit("::", 1)[-1] == requested.rsplit("::", 1)[-1]:
        return True
    return False


def find_function_node(source: str, func_name: str, language: str):
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return None, None, None
    for node in walk_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        actual = function_name_from_declarator(declarator, source_bytes)
        candidate_names = _function_candidate_names(node, actual, source_bytes)
        if any(function_matches(name, func_name) for name in candidate_names):
            return node, tree, source_bytes
    return None, tree, source_bytes


def find_function_node_at_byte_range(
    source: str,
    language: str,
    start_byte: int,
    end_byte: int,
):
    """Return only the function_definition at the exact source byte range."""
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return None, tree, source_bytes
    for node in walk_nodes(tree.root_node):
        if (
            node.type == "function_definition"
            and int(node.start_byte) == int(start_byte)
            and int(node.end_byte) == int(end_byte)
        ):
            return node, tree, source_bytes
    return None, tree, source_bytes


def _function_candidate_names(node, actual: str, source_bytes: bytes) -> List[str]:
    actual = _clean_qualified_name(actual)
    names = [actual] if actual else []
    if actual and "::" not in actual:
        header_qualified = _qualified_name_from_function_header(node_text(node, source_bytes), actual)
        if header_qualified:
            names.append(header_qualified)
        scopes = _enclosing_cpp_scopes(node, source_bytes)
        if scopes:
            names.append("::".join([*scopes, actual]))
    return dedup_keep_order(names)


def _qualified_name_from_function_header(code: str, leaf_name: str) -> str:
    header = str(code or "").split("{", 1)[0]
    leaf = _clean_qualified_name(leaf_name).rsplit("::", 1)[-1]
    if not header or not leaf:
        return ""
    # Out-of-class C++ definitions carry their type scope in the declarator,
    # not as AST ancestors: ``basic_writer<Range>::write_double(...)``.
    pattern = re.compile(
        r"((?:[A-Za-z_]\w*(?:\s*<[^<>;{}()]*>)?\s*::\s*)+)" + re.escape(leaf) + r"\s*\("
    )
    matches = list(pattern.finditer(header))
    if not matches:
        return ""
    scope = re.sub(r"<[^<>]*>", "", matches[-1].group(1))
    scope = re.sub(r"\s+", "", scope).strip(":")
    return _clean_qualified_name(scope + "::" + leaf)


def _enclosing_cpp_scopes(node, source_bytes: bytes) -> List[str]:
    scopes = []
    cur = getattr(node, "parent", None)
    while cur is not None:
        if cur.type in ("class_specifier", "struct_specifier", "union_specifier"):
            name_node = cur.child_by_field_name("name")
            if name_node is not None:
                name = _clean_function_name(node_text(name_node, source_bytes))
                if name:
                    scopes.append(name)
        elif cur.type == "namespace_definition":
            name_node = cur.child_by_field_name("name")
            if name_node is not None:
                name = _clean_function_name(node_text(name_node, source_bytes))
                if name:
                    scopes.append(name)
        cur = getattr(cur, "parent", None)
    return list(reversed(scopes))


def source_slice_by_byte_range(source: str, start_byte: int, end_byte: int) -> str:
    start_char, end_char = source_byte_range_to_char_range(source, start_byte, end_byte)
    if start_char < 0 or end_char < start_char:
        return ""
    return source[start_char:end_char]


def line_number_for_byte(source: str, byte_index: int) -> int:
    char_index, _ = source_byte_range_to_char_range(source, byte_index, byte_index)
    if char_index < 0:
        return -1
    return source[:char_index].count("\n") + 1


def include_records_from_source(source: str, language: str, origin: str) -> List[dict]:
    records = []
    tree, source_bytes = parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        for node in walk_nodes(tree.root_node):
            if node.type != "preproc_include":
                continue
            raw = node_text(node, source_bytes).strip()
            name = ""
            kind = ""
            for child in node.children:
                if child.type == "system_lib_string":
                    name = node_text(child, source_bytes).strip()[1:-1]
                    kind = "system"
                    break
                if child.type == "string_literal":
                    name = node_text(child, source_bytes).strip().strip('"')
                    kind = "project"
                    break
            if name:
                records.append({"kind": kind, "name": name, "raw": raw, "origin": origin})
    if records:
        return records

    include_re = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.MULTILINE)
    for match in include_re.finditer(source):
        opener, name = match.group(1), match.group(2).strip()
        records.append(
            {
                "kind": "system" if opener == "<" else "project",
                "name": name,
                "raw": match.group(0).strip(),
                "origin": origin,
            }
        )
    return records


def extract_symbols_from_code(source: str, language: str) -> dict:
    calls = []
    types = []
    fields = []
    identifiers = []
    tree, source_bytes = parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        for node in walk_nodes(tree.root_node):
            if node.type == "call_expression":
                function_node = node.child_by_field_name("function")
                if function_node is not None:
                    calls.append(call_name_from_node(function_node, source_bytes))
            elif node.type in ("type_identifier", "primitive_type", "sized_type_specifier"):
                types.append(node_text(node, source_bytes).strip())
            elif node.type == "field_identifier":
                fields.append(node_text(node, source_bytes).strip())
            elif node.type == "identifier":
                identifiers.append(node_text(node, source_bytes).strip())
    else:
        calls.extend(re.findall(r'\b([A-Za-z_]\w*)\s*\(', source))
        identifiers.extend(re.findall(r'\b[A-Za-z_]\w*\b', source))

    keywords = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "case",
        "break",
        "continue",
        "goto",
    }
    macro_like = re.findall(r'\b[A-Z_][A-Z0-9_]{2,}\b', source)
    return {
        "calls": [x for x in dedup_keep_order(calls) if x and x not in keywords],
        "types": [x for x in dedup_keep_order(types) if x],
        "fields": [x for x in dedup_keep_order(fields) if x],
        "identifiers": [x for x in dedup_keep_order(identifiers) if x and x not in keywords],
        "macro_like": dedup_keep_order(macro_like),
    }


def contains_symbol(text: str, symbols: set) -> bool:
    if not symbols:
        return False
    for symbol in symbols:
        if re.search(r'\b' + re.escape(symbol) + r'\b', text):
            return True
    return False


def iter_candidate_project_files(root: str, source_path: str, limit: int):
    source_dir = os.path.dirname(source_path)
    yielded = set()
    for cur_root in (source_dir, root):
        if not cur_root or not os.path.isdir(cur_root):
            continue
        for dirpath, dirs, files in os.walk(cur_root):
            dirs[:] = [
                d for d in dirs
                if d not in {".git", "build", "cmake-build-debug"} and not d.startswith("build_meta_")
            ]
            for filename in files:
                path = os.path.join(dirpath, filename)
                if path in yielded or path == source_path or not is_source_like(path):
                    continue
                yielded.add(path)
                yield path
                if len(yielded) >= limit:
                    return


def _clean_function_name(value: str) -> str:
    text = str(value or "").strip()
    text = text.split("<", 1)[0].strip()
    return text.split("::")[-1].strip()


def _clean_qualified_name(value: str) -> str:
    parts = []
    for part in str(value or "").strip().split("::"):
        part = part.strip()
        if not part:
            continue
        parts.append(part.split("<", 1)[0].strip())
    return "::".join(parts)
