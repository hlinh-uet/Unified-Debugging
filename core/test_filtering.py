from __future__ import annotations

from dataclasses import replace
from typing import Dict, List, Tuple

from data_loaders.base_loader import BugRecord


FAIL_OUTCOMES = {"FAIL", "FAILED"}


def is_fail_outcome(value) -> bool:
    return str(value or "").strip().upper() in FAIL_OUTCOMES


def is_buggy_and_fixed_fail(test: dict) -> bool:
    if not isinstance(test, dict):
        return False
    return is_fail_outcome(test.get("outcome")) and is_fail_outcome(test.get("outcome_fixed"))


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


def filtered_bug_record_for_pipeline(bug: BugRecord, *, exclude_fixed_fail_tests: bool) -> Tuple[BugRecord, List[str]]:
    if not exclude_fixed_fail_tests:
        return bug, []

    kept_tests, excluded_ids = filter_buggy_and_fixed_fail_tests(bug.tests)
    raw = bug.raw
    if isinstance(raw, dict):
        raw = {
            **raw,
            "tests": kept_tests,
            "pipeline_excluded_fixed_fail_tests": list(excluded_ids),
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
