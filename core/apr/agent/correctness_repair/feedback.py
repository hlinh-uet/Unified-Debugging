"""Deterministic validation outcome routing for causal APR."""

from __future__ import annotations

from typing import Any, Dict, Set

from .models import clip, compact_strings


def classify_validation_feedback(details: Dict[str, Any]) -> Dict[str, Any]:
    details = details or {}
    initial = _test_set(
        details.get("initial_failed_tests")
        or details.get("init_failed_tests")
        or details.get("pre_failed_tests")
    )
    post = _test_set(details.get("post_failed_tests"))
    error = str(details.get("validation_error") or "").strip()
    log_tail = str(details.get("validation_log_tail") or "")
    if details.get("validation_executed") is False:
        category = "materialization_error"
        transition = "repair_source_binding_or_patch_shape"
    elif error:
        category = "synthesis_error"
        transition = "refine_edit"
    elif not post:
        category = "plausible_candidate"
        transition = "retain_in_plausible_pool"
    elif initial and initial <= post:
        category = "mechanism_not_supported"
        transition = "rediagnose_mechanism"
    elif (initial - post) and (post - initial):
        category = "preservation_conflict"
        transition = "revise_preservation_constraints"
    elif initial - post:
        category = "partial_behavior_fix"
        transition = "revise_preservation_constraints"
    else:
        category = "validation_inconclusive"
        transition = "rediagnose_mechanism"
    return {
        "category": category,
        "transition": transition,
        "validation_error": clip(error, 800),
        "initial_failed_tests": sorted(initial),
        "post_failed_tests": sorted(post),
        "fixed_tests": sorted(initial - post),
        "regressed_tests": sorted(post - initial),
        "validation_log_tail": clip(log_tail[-4000:], 4000),
        "rule": "deterministic_test_set_and_validation_status_routing",
    }


def validation_feedback_mode(details: Dict[str, Any]) -> str:
    return str(classify_validation_feedback(details).get("transition") or "rediagnose_mechanism")


def _test_set(values: Any) -> Set[str]:
    return set(compact_strings(values, limit=10000, chars=500))
