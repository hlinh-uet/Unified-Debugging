from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Tuple

from data_loaders.base_loader import BugRecord


FAIL_OUTCOMES = {"FAIL", "FAILED"}
PASS_OUTCOMES = {"PASS", "PASSED"}
ZERO_TEST_NOOP_IDS = {"ranges-test"}


def is_fail_outcome(value) -> bool:
    return str(value or "").strip().upper() in FAIL_OUTCOMES


def is_pass_outcome(value) -> bool:
    return str(value or "").strip().upper() in PASS_OUTCOMES


def is_buggy_and_fixed_fail(test: dict) -> bool:
    if not isinstance(test, dict):
        return False
    return is_fail_outcome(test.get("outcome")) and is_fail_outcome(test.get("outcome_fixed"))


def _covered_items(test: dict) -> list:
    covered = test.get("covered_functions")
    if covered is None:
        covered = test.get("covered_methods")
    return covered if isinstance(covered, list) else []


def is_zero_coverage_pass_test(test: dict) -> bool:
    if not isinstance(test, dict):
        return False
    fixed_outcome = str(test.get("outcome_fixed") or "").strip()
    fixed_is_compatible = not fixed_outcome or is_pass_outcome(fixed_outcome)
    return is_pass_outcome(test.get("outcome")) and fixed_is_compatible and not _covered_items(test)


def is_zero_test_noop_pass_test(test: dict) -> bool:
    if not is_zero_coverage_pass_test(test):
        return False
    tid = str(test.get("test_id") or "").strip()
    return tid in ZERO_TEST_NOOP_IDS


def has_failed_tests(tests: list) -> bool:
    return any(is_fail_outcome(test.get("outcome")) for test in tests or [] if isinstance(test, dict))


def filter_buggy_and_fixed_fail_tests(tests: list) -> Tuple[List[dict], List[str]]:
    kept = []
    excluded_ids = []
    seen_excluded = set()
    for test in tests or []:
        if is_buggy_and_fixed_fail(test):
            tid = str(test.get("test_id") or "").strip()
            if tid and tid not in seen_excluded:
                excluded_ids.append(tid)
                seen_excluded.add(tid)
            continue
        kept.append(test)
    return kept, excluded_ids


def filter_zero_coverage_pass_tests(tests: list) -> Tuple[List[dict], List[str]]:
    kept = []
    excluded_ids = []
    seen_excluded = set()
    for test in tests or []:
        if is_zero_coverage_pass_test(test):
            tid = str(test.get("test_id") or "").strip()
            if tid and tid not in seen_excluded:
                excluded_ids.append(tid)
                seen_excluded.add(tid)
            continue
        kept.append(test)
    return kept, excluded_ids


def filter_zero_test_noop_pass_tests(tests: list) -> Tuple[List[dict], List[str]]:
    kept = []
    excluded_ids = []
    seen_excluded = set()
    for test in tests or []:
        if is_zero_test_noop_pass_test(test):
            tid = str(test.get("test_id") or "").strip()
            if tid and tid not in seen_excluded:
                excluded_ids.append(tid)
                seen_excluded.add(tid)
            continue
        kept.append(test)
    return kept, excluded_ids


def filtered_bug_record_for_pipeline(bug: BugRecord, *, exclude_fixed_fail_tests: bool) -> Tuple[BugRecord, List[str]]:
    kept_tests, zero_test_noop_excluded_ids = filter_zero_test_noop_pass_tests(bug.tests)
    if exclude_fixed_fail_tests:
        kept_tests, excluded_ids = filter_buggy_and_fixed_fail_tests(kept_tests)
    else:
        excluded_ids = []

    if not zero_test_noop_excluded_ids and not excluded_ids:
        return bug, []

    raw = bug.raw
    if isinstance(raw, dict):
        raw = {
            **raw,
            "tests": kept_tests,
            "pipeline_excluded_fixed_fail_tests": list(excluded_ids),
            "pipeline_excluded_zero_test_noop_tests": list(zero_test_noop_excluded_ids),
        }

    return replace(bug, tests=kept_tests, raw=raw), excluded_ids


def filter_bug_map_for_pipeline(
    bug_map: Dict[str, BugRecord],
    *,
    exclude_fixed_fail_tests: bool,
) -> Tuple[Dict[str, BugRecord], Dict[str, List[str]]]:
    if not exclude_fixed_fail_tests:
        return bug_map, {}

    filtered = {}
    excluded_by_bug = {}
    for bug_id, bug in bug_map.items():
        filtered_bug, excluded = filtered_bug_record_for_pipeline(
            bug,
            exclude_fixed_fail_tests=True,
        )
        filtered[bug_id] = filtered_bug
        if excluded:
            excluded_by_bug[bug_id] = excluded
    return filtered, excluded_by_bug
