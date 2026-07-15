"""Exact source target identities for oracle/valid APR runs.

Valid mode already has access to buggy and fixed revisions.  It must therefore
localize the changed tree-sitter function definition itself, rather than
assigning certainty to a lossy ``file:function-name`` group.
"""

from __future__ import annotations

import difflib
import os
from typing import Any, Dict, Iterable, List, Tuple

from core.utils import parse_sbfl_qualified_name

from .common import enumerate_function_targets, source_language_from_path


def build_valid_oracle_targets(
    bug: Any,
    *,
    ground_truth_groups: Iterable[str] | None = None,
) -> Dict[str, Any]:
    """Map ground-truth groups to changed buggy AST definitions.

    The result is exact only when a changed byte span or an exact unchanged
    declaration identity selects the buggy function definition.  No candidate
    is selected by lexical similarity, score thresholds, or name ranking.
    """
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    buggy_root = str(raw.get("buggy_tree_dir") or "")
    fixed_root = str(raw.get("fixed_tree_dir") or "")
    revision = str(raw.get("commit_before") or raw.get("revision") or "")
    selected_groups = (
        ground_truth_groups
        if ground_truth_groups is not None
        else getattr(bug, "ground_truth", []) or []
    )
    ground_truth = [str(item) for item in selected_groups if str(item)]
    if not buggy_root or not fixed_root:
        return _result(
            status="unavailable",
            targets=[],
            diagnostics=["buggy_or_fixed_tree_missing"],
            ground_truth=ground_truth,
        )

    targets: List[Dict[str, Any]] = []
    diagnostics: List[str] = []
    for fl_key in ground_truth:
        file_hint, function_name = parse_sbfl_qualified_name(fl_key)
        if not file_hint or not function_name:
            diagnostics.append(f"invalid_ground_truth_key:{fl_key}")
            continue
        relpath, path_error = _resolve_source_relpath(file_hint, raw)
        if not relpath:
            diagnostics.append(f"{path_error}:{fl_key}")
            continue
        buggy_path = os.path.join(buggy_root, relpath)
        fixed_path = os.path.join(fixed_root, relpath)
        if not os.path.isfile(buggy_path) or not os.path.isfile(fixed_path):
            diagnostics.append(f"buggy_or_fixed_source_missing:{relpath}")
            continue
        with open(buggy_path, "r", encoding="utf-8", errors="replace") as handle:
            buggy_source = handle.read()
        with open(fixed_path, "r", encoding="utf-8", errors="replace") as handle:
            fixed_source = handle.read()
        language = source_language_from_path(relpath)
        buggy_candidates = enumerate_function_targets(
            buggy_source,
            function_name,
            language,
            source_path=buggy_path,
            source_file=relpath,
        )
        fixed_candidates = enumerate_function_targets(
            fixed_source,
            function_name,
            language,
            source_path=fixed_path,
            source_file=relpath,
        )
        selected = _changed_buggy_candidates(
            buggy_source=buggy_source,
            fixed_source=fixed_source,
            buggy_candidates=buggy_candidates,
            fixed_candidates=fixed_candidates,
        )
        if not selected:
            diagnostics.append(f"ground_truth_group_has_no_changed_ast_definition:{fl_key}")
            continue
        for candidate in selected:
            targets.append({
                **_identity_payload(candidate, repository_revision=revision),
                "fl_key": fl_key,
                "score": 1.0,
                "oracle_source": "buggy_fixed_tree_sitter_ast_delta",
            })

    targets = _dedup_targets(targets)
    status = "resolved" if targets and not diagnostics else "partial" if targets else "unresolved"
    return _result(
        status=status,
        targets=targets,
        diagnostics=diagnostics,
        ground_truth=ground_truth,
    )


def exact_target_matches(candidate: Dict[str, Any], identity: Dict[str, Any]) -> bool:
    """Verify a persisted exact identity against a freshly parsed AST node."""
    if not isinstance(candidate, dict) or not isinstance(identity, dict):
        return False
    required = ("target_id", "source_file", "start_byte", "end_byte", "ast_hash")
    if any(identity.get(key) in (None, "") for key in required):
        return False
    return bool(
        str(candidate.get("target_id") or "") == str(identity.get("target_id") or "")
        and _norm_path(candidate.get("source_file")) == _norm_path(identity.get("source_file"))
        and _as_int(candidate.get("start_byte"), -1) == _as_int(identity.get("start_byte"), -2)
        and _as_int(candidate.get("end_byte"), -1) == _as_int(identity.get("end_byte"), -2)
        and str(candidate.get("ast_hash") or "") == str(identity.get("ast_hash") or "")
    )


def _changed_buggy_candidates(
    *,
    buggy_source: str,
    fixed_source: str,
    buggy_candidates: List[Dict[str, Any]],
    fixed_candidates: List[Dict[str, Any]],
) -> List[Dict[str, Any]]:
    changed_spans, insertion_points = _buggy_changed_byte_locations(buggy_source, fixed_source)
    selected = [
        candidate for candidate in buggy_candidates
        if _candidate_touches_delta(candidate, changed_spans, insertion_points)
    ]
    if selected:
        return selected

    # An insertion can occur on a parser boundary (for example immediately
    # before a declaration).  Pair declarations only by exact structural
    # identity and retain the buggy definition when its complete source differs.
    fixed_by_declaration: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = {}
    for candidate in fixed_candidates:
        fixed_by_declaration.setdefault(_declaration_identity(candidate), []).append(candidate)
    for candidate in buggy_candidates:
        matches = fixed_by_declaration.get(_declaration_identity(candidate), [])
        if len(matches) == 1 and str(candidate.get("code") or "") != str(matches[0].get("code") or ""):
            selected.append(candidate)
    return selected


def _buggy_changed_byte_locations(
    buggy_source: str,
    fixed_source: str,
) -> Tuple[List[Tuple[int, int]], List[int]]:
    buggy_lines = buggy_source.splitlines(keepends=True)
    fixed_lines = fixed_source.splitlines(keepends=True)
    offsets = [0]
    for line in buggy_lines:
        offsets.append(offsets[-1] + len(line.encode("utf-8", errors="replace")))
    spans: List[Tuple[int, int]] = []
    insertions: List[int] = []
    matcher = difflib.SequenceMatcher(a=buggy_lines, b=fixed_lines, autojunk=False)
    for tag, buggy_start, buggy_end, _fixed_start, _fixed_end in matcher.get_opcodes():
        if tag == "equal":
            continue
        start_byte = offsets[buggy_start]
        end_byte = offsets[buggy_end]
        if buggy_start == buggy_end:
            insertions.append(start_byte)
        else:
            spans.append((start_byte, end_byte))
    return spans, insertions


def _candidate_touches_delta(
    candidate: Dict[str, Any],
    spans: Iterable[Tuple[int, int]],
    insertions: Iterable[int],
) -> bool:
    start = _as_int(candidate.get("start_byte"), -1)
    end = _as_int(candidate.get("end_byte"), -1)
    if start < 0 or end <= start:
        return False
    if any(max(start, changed_start) < min(end, changed_end) for changed_start, changed_end in spans):
        return True
    return any(start < point < end for point in insertions)


def _declaration_identity(candidate: Dict[str, Any]) -> Tuple[Any, ...]:
    return (
        _norm_path(candidate.get("source_file")),
        str(candidate.get("resolved_name") or ""),
        tuple(str(item) for item in candidate.get("enclosing_scopes") or []),
        "".join(str(candidate.get("signature") or "").split()),
    )


def _identity_payload(candidate: Dict[str, Any], *, repository_revision: str) -> Dict[str, Any]:
    keep = (
        "target_id", "id", "requested_name", "resolved_name", "leaf_name",
        "signature", "enclosing_scopes", "source_file", "language", "start_byte",
        "end_byte", "start_line", "end_line", "ast_hash", "resolution_strategy",
        "resolution_confidence",
    )
    return {
        **{key: candidate.get(key) for key in keep if candidate.get(key) not in (None, "")},
        "identity_version": 1,
        "repository_revision": repository_revision,
        "source_hash": str(candidate.get("ast_hash") or ""),
    }


def _resolve_source_relpath(file_hint: str, raw: Dict[str, Any]) -> Tuple[str, str]:
    normalized_hint = _norm_path(file_hint)
    known = [
        _norm_path(item)
        for item in raw.get("src_files") or []
        if isinstance(item, str) and _norm_path(item)
    ]
    source_relpath = _norm_path(raw.get("source_relpath"))
    if source_relpath:
        known.append(source_relpath)
    known = list(dict.fromkeys(known))
    exact = [item for item in known if item == normalized_hint]
    if len(exact) == 1:
        return exact[0], ""
    suffix = [item for item in known if item.endswith("/" + normalized_hint)]
    if len(suffix) == 1:
        return suffix[0], ""
    basename = [item for item in known if os.path.basename(item) == os.path.basename(normalized_hint)]
    if len(basename) == 1:
        return basename[0], ""
    return "", "ground_truth_source_path_ambiguous_or_missing"


def _dedup_targets(targets: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for target in targets:
        key = str(target.get("target_id") or "")
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(target)
    return out


def _result(
    *,
    status: str,
    targets: List[Dict[str, Any]],
    diagnostics: List[str],
    ground_truth: List[str],
) -> Dict[str, Any]:
    return {
        "status": status,
        "strategy": "buggy_fixed_tree_sitter_ast_delta",
        "targets": targets,
        "diagnostics": diagnostics,
        "ground_truth_groups": ground_truth,
        "fallback_policy": "none",
    }


def _norm_path(value: Any) -> str:
    normalized = os.path.normpath(str(value or "").replace("\\", "/")).replace("\\", "/")
    if normalized == ".":
        return ""
    while normalized.startswith("./"):
        normalized = normalized[2:]
    return normalized


def _as_int(value: Any, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
