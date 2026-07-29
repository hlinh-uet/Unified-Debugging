"""Exact tree-sitter source target contract used by every repair round."""

from __future__ import annotations

import hashlib
import os
from typing import Any, Dict, List, Tuple

from core.program_analysis.source_utils import node_text, parse_tree, walk_nodes

from .models import stable_id


def build_target_contract(
    *, func_code: str, replacement_target: Dict[str, Any], source_path: str, func_name: str
) -> Tuple[Dict[str, Any], List[str]]:
    envelope = replacement_target.get("replacement_envelope") or {}
    identity = replacement_target.get("replacement_identity") or {}
    resolved_path = os.path.realpath(str(envelope.get("source_path") or source_path or ""))
    replacement_range = envelope.get("replacement_range") or {}
    language = str(envelope.get("language") or identity.get("language") or "c")
    errors: List[str] = []
    diagnostics: List[str] = []
    try:
        start_byte = int(replacement_range.get("start_byte"))
        end_byte = int(replacement_range.get("end_byte"))
    except (TypeError, ValueError):
        start_byte, end_byte = -1, -1
        errors.append("replacement_byte_range_missing")
    source_bytes = b""
    if not resolved_path or not os.path.isfile(resolved_path):
        errors.append("replacement_source_file_missing")
    else:
        try:
            source_bytes = open(resolved_path, "rb").read()
        except OSError:
            errors.append("replacement_source_read_failed")
    exact_unit = ""
    if source_bytes:
        if start_byte < 0 or end_byte <= start_byte or end_byte > len(source_bytes):
            errors.append("replacement_byte_range_invalid")
        else:
            try:
                exact_unit = source_bytes[start_byte:end_byte].decode("utf-8", errors="strict")
            except UnicodeDecodeError:
                errors.append("replacement_byte_range_not_utf8")
            else:
                if exact_unit != func_code:
                    errors.append("replacement_unit_not_equal_to_source_byte_range")
    tree, parsed_bytes = parse_tree(func_code or "", language)
    if tree is None or parsed_bytes is None:
        diagnostics.append("replacement_unit_tree_sitter_parse_failed")
    elif tree.root_node.has_error:
        # Exact full-file target resolution, byte-range equality and source
        # identity are the safety boundary.  Isolated C/C++ snippets can have
        # harmless parse errors when declaration macros (for example
        # FMT_CONSTEXPR) lose their surrounding preprocessor context.
        diagnostics.append("replacement_unit_tree_sitter_has_error")
    target_id = str(identity.get("target_id") or identity.get("id") or "")
    if not target_id:
        errors.append("replacement_target_id_missing")
    source_hash = hashlib.sha256((func_code or "").encode("utf-8")).hexdigest()
    contract = {
        "target_id": target_id,
        "requested_name": func_name,
        "resolved_name": str(identity.get("resolved_name") or func_name),
        "signature": str(identity.get("signature") or ""),
        "source_path": resolved_path,
        "source_file": str(identity.get("source_file") or envelope.get("source_file") or ""),
        "language": language,
        "source_range": {
            "start_byte": start_byte,
            "end_byte": end_byte,
            "start_line": replacement_range.get("start_line"),
            "end_line": replacement_range.get("end_line"),
        },
        "source_hash": source_hash,
        "replacement_unit": func_code,
        "visible_symbols": _visible_symbols(tree, parsed_bytes) if tree is not None and parsed_bytes is not None else [],
        "binding": "tree_sitter_exact_source_byte_range",
        "fallback_policy": "none",
        "diagnostics": diagnostics,
    }
    contract["contract_id"] = stable_id("target", {
        "target_id": target_id,
        "source_path": resolved_path,
        "range": contract["source_range"],
        "hash": source_hash,
    })
    return contract, errors


def _visible_symbols(tree, source_bytes: bytes) -> List[str]:
    values = []
    seen = set()
    for node in walk_nodes(tree.root_node):
        if node.type not in {"identifier", "field_identifier", "type_identifier", "namespace_identifier"}:
            continue
        value = node_text(node, source_bytes).strip()
        if value and value not in seen:
            values.append(value)
            seen.add(value)
    return values[:128]
