from typing import Optional

from core.apr.apr_utils import (
    classify_patch_outcome,
    compact_test_list,
    dedup_initial_test_ids,
)
from core.test_filtering import filter_buggy_and_fixed_fail_tests


EVALUATION_SNAPSHOT_KEYS = (
    "status",
    "real_status",
    "validation_error",
    "init_passed_tests",
    "init_failed_tests",
    "full_init_passed_tests",
    "full_init_failed_tests",
    "post_passed_tests",
    "post_failed_tests",
    "full_post_passed_tests",
    "full_post_failed_tests",
    "fixed_fail_excluded_tests",
    "validation_details",
)

LEGACY_EVALUATION_KEYS = {
    "status_scope",
    "patch_comparison_status",
    "init_scope",
    "init_passed_count",
    "init_failed_count",
    "full_init_passed_count",
    "full_init_failed_count",
    "post_scope",
    "post_passed_count",
    "post_failed_count",
    "full_post_passed_count",
    "full_post_failed_count",
    "patch_comparison_post_passed_count",
    "patch_comparison_post_failed_count",
    "patch_comparison_post_passed_tests",
    "patch_comparison_post_failed_tests",
    "fixed_fail_excluded_count",
    "test_filter",
}

VALIDATION_RESULT_KEYS = {
    "validation_error",
    "full_post_passed_tests",
    "full_post_failed_tests",
    "patch_comparison_post_passed_tests",
    "patch_comparison_post_failed_tests",
    "fixed_fail_excluded_tests",
    "exclude_fixed_fail_tests_from_run",
    "validation_test_count",
}


def build_initial_test_snapshot(
    tests: list,
    *,
    exclude_fixed_fail_tests: bool,
    excluded_fixed_fail_tests: Optional[list] = None,
) -> dict:
    """Build full and comparison-scope initial test data."""
    source_tests = list(tests or [])
    explicit_excluded = list(dict.fromkeys(excluded_fixed_fail_tests or []))

    if exclude_fixed_fail_tests and explicit_excluded:
        comparison_tests = source_tests
        excluded = explicit_excluded
        comparison_passed, comparison_failed = dedup_initial_test_ids(comparison_tests)
        full_passed = list(comparison_passed)
        full_failed = list(dict.fromkeys([*comparison_failed, *excluded]))
    else:
        full_passed, full_failed = dedup_initial_test_ids(source_tests)
        if exclude_fixed_fail_tests:
            comparison_tests, excluded = filter_buggy_and_fixed_fail_tests(source_tests)
        else:
            comparison_tests = source_tests
            excluded = []
        comparison_passed, comparison_failed = dedup_initial_test_ids(comparison_tests)

    return {
        "comparison_passed": comparison_passed,
        "comparison_failed": comparison_failed,
        "full_passed": full_passed,
        "full_failed": full_failed,
        "excluded": excluded,
        "fields": {
            "init_passed_tests": compact_test_list(comparison_passed),
            "init_failed_tests": compact_test_list(comparison_failed),
            "full_init_passed_tests": compact_test_list(full_passed),
            "full_init_failed_tests": compact_test_list(full_failed),
        },
    }


def build_validation_snapshot(
    initial: dict,
    *,
    validation_details: Optional[dict],
    post_passed: Optional[list] = None,
    post_failed: Optional[list] = None,
    validation_error: str = "",
    exclude_fixed_fail_tests: bool,
) -> dict:
    """Build the persisted evaluation contract for one validated patch."""
    raw_details = dict(validation_details or {})
    error = str(validation_error or raw_details.get("validation_error") or "").strip()
    full_post_passed = list(raw_details.get("full_post_passed_tests", post_passed or []))
    full_post_failed = list(raw_details.get("full_post_failed_tests", post_failed or []))

    if exclude_fixed_fail_tests:
        comparison_post_passed = list(post_passed or [])
        comparison_post_failed = list(post_failed or [])
        excluded = list(dict.fromkeys([
            *initial.get("excluded", []),
            *raw_details.get("fixed_fail_excluded_tests", []),
        ]))
    else:
        comparison_post_passed = full_post_passed
        comparison_post_failed = full_post_failed
        excluded = []

    status = classify_patch_outcome(
        initial.get("comparison_failed", []),
        comparison_post_failed,
        error,
    )
    real_status = classify_patch_outcome(
        initial.get("full_failed", []),
        full_post_failed,
        error,
    )

    return {
        "status": status,
        "real_status": real_status,
        "validation_error": error,
        **initial.get("fields", {}),
        "post_passed_tests": comparison_post_passed,
        "post_failed_tests": comparison_post_failed,
        "full_post_passed_tests": full_post_passed,
        "full_post_failed_tests": full_post_failed,
        "fixed_fail_excluded_tests": excluded,
        "validation_details": compact_validation_details(raw_details),
    }


def build_invalid_snapshot(
    initial: dict,
    *,
    validation_error: str,
    exclude_fixed_fail_tests: bool,
) -> dict:
    details = {
        "validation_error": validation_error,
        "full_post_passed_tests": [],
        "full_post_failed_tests": [],
        "fixed_fail_excluded_tests": list(initial.get("excluded", [])),
    }
    return build_validation_snapshot(
        initial,
        validation_details=details,
        post_passed=[],
        post_failed=[],
        validation_error=validation_error,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )


def extract_evaluation_snapshot(record: dict) -> dict:
    snapshot = {key: record.get(key) for key in EVALUATION_SNAPSHOT_KEYS if key in record}
    return sanitize_evaluation_data(snapshot)


def sanitize_evaluation_data(value):
    """Remove superseded evaluation fields before metadata is persisted."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key.startswith("effective_post_") or key in LEGACY_EVALUATION_KEYS:
                continue
            if key == "validation_details" and isinstance(item, dict):
                cleaned[key] = compact_validation_details(item)
            else:
                cleaned[key] = sanitize_evaluation_data(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_evaluation_data(item) for item in value]
    return value


def compact_validation_details(details: dict) -> dict:
    return sanitize_evaluation_data({
        key: value
        for key, value in (details or {}).items()
        if key not in VALIDATION_RESULT_KEYS
        and not key.startswith("effective_post_")
    })
