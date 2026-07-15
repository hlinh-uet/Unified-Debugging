"""Compact, source-backed failure contracts.

This module does not infer expected/actual values with log regexes.  It keeps
the failing assertion/test definition and the runner output as oracle evidence
for the causal reasoner.
"""

from __future__ import annotations

from typing import Any, Dict, List

from .models import clip, compact_strings, stable_id


def build_failure_contract(context: Dict[str, Any]) -> Dict[str, Any]:
    behavior = context.get("behavior_context") if isinstance(context, dict) else {}
    if not isinstance(behavior, dict):
        behavior = context if isinstance(context, dict) else {}
    tests = behavior.get("tests") or context.get("tests") or []
    compact_tests: List[Dict[str, Any]] = []
    for test in tests[:4]:
        if not isinstance(test, dict):
            continue
        compact_tests.append({
            "test_id": str(test.get("test_id") or ""),
            "test_source_path": str(test.get("test_source_path") or ""),
            "test_source_range": test.get("test_source_range") or {},
            "test_source": clip(test.get("test_source"), 5000),
            "failure_log": clip(test.get("failure_log") or test.get("fail_reason"), 4000),
            "actual_output": clip(test.get("actual_output"), 1800),
            "covered_target": bool(test.get("covered_target")),
        })
    contract = {
        "version": 1,
        "oracle_kind": "test_behavior",
        "tests": compact_tests,
        "runtime_facts": compact_strings(behavior.get("runtime_facts"), limit=12, chars=300),
        "validation_feedback": _compact_validation_feedback(
            behavior.get("validation_feedback") or context.get("validation_feedback") or {}
        ),
        "evidence_gaps": compact_strings(
            behavior.get("evidence_gaps") or context.get("evidence_gaps"), limit=8, chars=240
        ),
    }
    contract["contract_id"] = stable_id("failure", contract)
    return contract


def _compact_validation_feedback(value: Any) -> Dict[str, Any]:
    if not isinstance(value, dict):
        return {}
    return {
        "validation_error": clip(value.get("validation_error"), 600),
        "initial_failed_tests": compact_strings(
            value.get("initial_failed_tests") or value.get("init_failed_tests"), limit=12, chars=180
        ),
        "post_failed_tests": compact_strings(value.get("post_failed_tests"), limit=12, chars=180),
        "validation_log_tail": clip(value.get("validation_log_tail"), 2500),
    }
