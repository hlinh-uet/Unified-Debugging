import os
import re
from typing import Optional

from core.apr.config import (
    APR_MAX_LOCAL_HEADER_CONTEXT_CHARS,
    APR_MAX_SOURCE_CHARS,
    APR_MAX_TEST_ID_STORE,
)
from core.utils import source_byte_range_to_char_range


def is_defects4c_dataset(dataset: str) -> bool:
    return (dataset or "").strip().lower() != "codeflaws"


def source_language_from_path(path: str) -> str:
    ext = os.path.splitext(path or "")[1].lower()
    return "cpp" if ext in (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".h") else "c"


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


def trim_source_for_prompt(source_code: str, start_idx: int, end_idx: int) -> str:
    """Keep a bounded source slice around the target function for APR prompts."""
    start_char, end_char = source_byte_range_to_char_range(source_code, start_idx, end_idx)
    if len(source_code) <= APR_MAX_SOURCE_CHARS or start_char < 0 or end_char < 0:
        return source_code

    head_budget = min(6000, APR_MAX_SOURCE_CHARS // 4)
    remaining = APR_MAX_SOURCE_CHARS - head_budget
    neighborhood = max(2000, remaining // 2)

    head = source_code[:head_budget]
    func_lo = max(head_budget, start_char - neighborhood)
    func_hi = min(len(source_code), end_char + neighborhood)
    middle_skipped = func_lo > head_budget
    tail_skipped = func_hi < len(source_code)

    parts = [head]
    if middle_skipped:
        parts.append("\n\n/* ... [source truncated - prelude shown above] ... */\n\n")
    parts.append(source_code[func_lo:func_hi])
    if tail_skipped:
        parts.append("\n\n/* ... [source truncated - tail omitted] ... */\n")
    return "".join(parts)


def build_local_header_context(source_code: str, source_path: str) -> str:
    """Read raw local headers included by the source file for the retrieval agent."""
    if not source_code or not source_path:
        return "LOCAL HEADER CONTEXT\nNo local header context is available.\n"

    source_dir = os.path.dirname(source_path)
    if not source_dir:
        return "LOCAL HEADER CONTEXT\nNo local header context is available.\n"

    include_names = []
    for match in re.finditer(r'^\s*#\s*include\s+"([^"]+)"', source_code, re.MULTILINE):
        include_name = match.group(1).strip()
        if include_name and include_name not in include_names:
            include_names.append(include_name)

    if not include_names:
        return "LOCAL HEADER CONTEXT\nNo local quoted includes are present in this source file.\n"

    source_root = os.path.normpath(source_dir)
    parts = ["LOCAL HEADER CONTEXT"]
    total_chars = len(parts[0]) + 1
    for include_name in include_names:
        header_path = os.path.normpath(os.path.join(source_dir, include_name))
        try:
            in_source_tree = os.path.commonpath([source_root, header_path]) == source_root
        except ValueError:
            in_source_tree = False
        if not in_source_tree or not os.path.isfile(header_path):
            continue
        try:
            with open(header_path, "r", errors="replace") as f:
                header_text = f.read()
        except OSError:
            continue

        block = f"\nBEGIN LOCAL HEADER {include_name}\n{header_text}\nEND LOCAL HEADER {include_name}\n"
        remaining = APR_MAX_LOCAL_HEADER_CONTEXT_CHARS - total_chars
        if remaining <= 0:
            parts.append("... [local header context truncated]\n")
            break
        if len(block) > remaining:
            parts.append(block[:remaining].rstrip() + "\n... [local header context truncated]\n")
            break
        parts.append(block)
        total_chars += len(block)

    if len(parts) == 1:
        parts.append("No readable local header files were found.\n")
    return "".join(parts)


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


def failed_candidate_result(
    *,
    qualified_name: str,
    score: float,
    status: str,
    validation_error: str,
    candidate_path: str,
    candidate_relpath: str,
    patched_function: str,
    patched_file: str,
    llm_patch_artifact: dict,
) -> dict:
    return {
        "function": qualified_name,
        "score": score,
        "status": status,
        "status_scope": "patch_comparison_excluding_fixed_fail_tests",
        "patch_comparison_status": "failed",
        "real_status": "failed",
        "validation_error": validation_error,
        "repair_target_file": candidate_path,
        "repair_target_relpath": candidate_relpath,
        "patched_function": patched_function,
        "patched_file": patched_file,
        "llm_patch_artifact": llm_patch_artifact,
        "post_scope": "full_suite",
        "post_passed_count": 0,
        "post_failed_count": 0,
        "post_passed_tests": [],
        "post_failed_tests": [],
        "full_post_passed_count": 0,
        "full_post_failed_count": 0,
        "full_post_passed_tests": [],
        "full_post_failed_tests": [],
        "patch_comparison_post_passed_count": 0,
        "patch_comparison_post_failed_count": 0,
        "patch_comparison_post_passed_tests": [],
        "patch_comparison_post_failed_tests": [],
        "fixed_fail_excluded_count": 0,
        "fixed_fail_excluded_tests": [],
        "validation_details": {
            "validation_error": validation_error,
            "full_post_passed_tests": [],
            "full_post_failed_tests": [],
            "effective_post_passed_tests": [],
            "effective_post_failed_tests": [],
            "fixed_fail_excluded_tests": [],
        },
    }
