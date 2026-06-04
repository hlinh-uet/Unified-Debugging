import os
from typing import Optional

from core.apr.config import APR_MAX_TEST_ID_STORE


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
