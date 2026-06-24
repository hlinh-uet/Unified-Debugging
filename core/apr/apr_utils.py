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


def candidate_quality_key(candidate: dict) -> tuple:
    """Lower is better when comparing Fix/ReFix candidates or artifacts."""
    status = str((candidate or {}).get("status") or "").strip().lower()
    return (
        0 if is_plausible_status(status) else 1,
        1 if status == "invalid" else 0,
        candidate_list_len(candidate, "post_failed_tests"),
        candidate_list_len(candidate, "full_post_failed_tests"),
        -candidate_list_len(candidate, "post_passed_tests", default=0),
        -candidate_list_len(candidate, "full_post_passed_tests", default=0),
        1 if str((candidate or {}).get("validation_error") or "").strip() else 0,
    )


def candidate_is_strictly_better(candidate: dict, baseline: dict) -> bool:
    """Return True only when candidate improves baseline without adding failures.

    ReFix is useful only when it beats the FixAgent result on the same validation
    surface. A patch that fixes one failing test while adding a full-suite
    regression should not replace the original FixAgent patch.
    """
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
