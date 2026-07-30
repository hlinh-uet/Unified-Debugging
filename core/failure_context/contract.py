"""Shared compact, source-backed failure contracts.

This module does not infer expected/actual values with log regexes.  It keeps
the failing assertion/test definition and the runner output as oracle evidence
for the causal reasoner.
"""

from __future__ import annotations

import os
import re
from typing import Any, Dict, List, Set

from core.program_analysis.source_utils import (
    node_text,
    parse_tree,
    source_language_from_path,
    walk_nodes,
)

from .utils import (
    clip,
    compact_strings,
    stable_id,
)


def build_failure_contract(context: Dict[str, Any]) -> Dict[str, Any]:
    behavior = context.get("behavior_context") if isinstance(context, dict) else {}
    if not isinstance(behavior, dict):
        behavior = context if isinstance(context, dict) else {}
    tests = behavior.get("tests") or context.get("tests") or []
    compact_tests: List[Dict[str, Any]] = []
    for test in tests[:4]:
        if not isinstance(test, dict):
            continue
        focused = _focused_test_evidence(test)
        assertion = _compact_assertion(focused.get("failing_assertion") or {})
        dependency_slice = _compact_dependency_slice(
            focused.get("test_dependency_slice") or {}
        )
        test_input = _compact_test_input(test.get("test_input") or {})
        expected_oracle = _compact_expected_oracle(
            test.get("expected_oracle") or {}
        )
        regression_output = _compact_regression_output(
            test.get("regression_output") or {}
        )
        resolved_test_case = _compact_resolved_test_case(
            test.get("resolved_test_case") or {}
        )
        test_inputs = [
            _compact_test_input(item)
            for item in test.get("test_inputs") or []
            if isinstance(item, dict) and item
        ]
        observation = focused.get("failure_observation") or {}
        failure_log = str(test.get("failure_log") or test.get("fail_reason") or "")
        actual_output = str(test.get("actual_output") or "")
        compact_tests.append({
            "test_id": str(test.get("test_id") or ""),
            "test_source_path": str(test.get("test_source_path") or ""),
            "test_source_range": test.get("test_source_range") or {},
            "failing_assertion": assertion,
            "test_dependency_slice": dependency_slice,
            "test_input": test_input,
            "expected_oracle": expected_oracle,
            "regression_output": regression_output,
            "failure_observation": observation,
            "proof_obligation": _proof_obligation(
                assertion=assertion,
                observation=observation,
                expected_oracle=expected_oracle,
            ),
            # Kept only as an audit fallback. Causal reasoning should use the
            # assertion and dependency slice above instead of the function head.
            "test_source_excerpt": (
                "" if assertion or dependency_slice or observation.get("failure_mode") == "signal"
                else clip(test.get("test_source"), 1800)
            ),
            "failure_log": _diagnostic_log_excerpt(failure_log, observation),
            "actual_output": (
                "" if _normalized_output(actual_output) == _normalized_output(failure_log)
                else clip(actual_output, 1000)
            ),
        })
        if (
            resolved_test_case
            and resolved_test_case.get("framework") != "source_test"
        ):
            compact_tests[-1]["resolved_test_case"] = resolved_test_case
        if len(test_inputs) > 1:
            compact_tests[-1]["test_inputs"] = test_inputs[:12]
    uses_resolved_test_contract = any(
        test.get("resolved_test_case") or test.get("test_inputs")
        for test in compact_tests
    )
    contract = {
        # Keep the existing contract version/shape for source-based tests
        # (fmt/libyang). Version 5 is only needed when a project resolver adds
        # manifest/fixture semantics such as TCPdump TESTLIST or PHP PHPT.
        "version": 5 if uses_resolved_test_contract else 4,
        "oracle_kind": "regression_input_output_behavior",
        "tests": compact_tests,
        "runtime_facts": compact_strings(behavior.get("runtime_facts"), limit=12, chars=300),
        "validation_feedback": _compact_validation_feedback(
            behavior.get("validation_feedback") or context.get("validation_feedback") or {}
        ),
        "evidence_gaps": compact_strings(
            behavior.get("evidence_gaps") or context.get("evidence_gaps"), limit=8, chars=240
        ),
    }
    failure_signature = _failure_signature(compact_tests)
    contract["failure_signature"] = failure_signature
    contract["failure_signature_id"] = stable_id(
        "failure_signature",
        failure_signature,
    )
    contract["contract_id"] = stable_id("failure", contract)
    return contract


def _failure_signature(tests: List[Dict[str, Any]]) -> Dict[str, Any]:
    """Return the provenance-independent identity of reproduced failures.

    A Fail Context contract also records where evidence came from, return
    codes, and the runner's complete output. Those audit fields legitimately
    change between census, detailed, and recovery executions, so they cannot
    be used to decide whether two executions reproduced the same failure.
    """
    signatures = []
    for test in tests:
        assertion = test.get("failing_assertion") or {}
        observation = test.get("failure_observation") or {}
        proof = test.get("proof_obligation") or {}
        test_input = test.get("test_input") or {}
        expected_oracle = test.get("expected_oracle") or {}
        has_structured_failure = bool(
            assertion
            or observation.get("failure_mode")
            or observation.get("runner_assertion_observation")
            or observation.get("reported_line")
        )
        signature_input = {
            "kind": test_input.get("kind"),
            "selection_basis": test_input.get("selection_basis"),
            "source_path": _signature_path(
                test_input.get("source_path")
            ),
            "source_ranges": test_input.get("source_ranges") or [],
            "source": _normalized_output(test_input.get("source")),
            "symbols": test_input.get("symbols") or [],
        }
        if test_input.get("sha256"):
            signature_input["sha256"] = str(test_input.get("sha256"))
        if test_input.get("size") is not None:
            signature_input["size"] = int(test_input.get("size") or 0)

        signature_observation = {
            "reported_source": _signature_path(
                observation.get("reported_source_path")
            ),
            "reported_line": int(
                observation.get("reported_line") or 0
            ),
            "runner_assertion_observation": _normalized_output(
                observation.get("runner_assertion_observation")
            ),
            "failure_mode": str(
                observation.get("failure_mode") or ""
            ),
            "signal_name": str(
                observation.get("signal_name") or ""
            ),
            "signal_number": int(
                observation.get("signal_number") or 0
            ),
        }
        if observation.get("sanitizer_kind"):
            signature_observation["sanitizer_kind"] = str(
                observation.get("sanitizer_kind")
            )
        if observation.get("sanitizer_error"):
            signature_observation["sanitizer_error"] = str(
                observation.get("sanitizer_error")
            )

        signatures.append({
            "test_id": str(test.get("test_id") or ""),
            "assertion": {
                "kind": assertion.get("kind"),
                "callee": assertion.get("callee"),
                "source_range": assertion.get("source_range") or {},
                "expected_expression": _normalized_output(
                    assertion.get("expected_expression")
                ),
                "actual_expression": _normalized_output(
                    assertion.get("actual_expression")
                ),
            },
            "test_input": signature_input,
            "expected_oracle": {
                "kind": expected_oracle.get("kind"),
                "source_path": _signature_path(
                    expected_oracle.get("source_path")
                ),
                "source": _normalized_output(
                    expected_oracle.get("source")
                ),
            },
            "observation": signature_observation,
            "proof_obligation": _signature_proof_obligation(proof),
            "diagnostic_fallback": (
                ""
                if has_structured_failure
                else _normalized_output(test.get("failure_log"))
            ),
        })
    return {
        "version": 1,
        "tests": signatures,
    }


def _signature_path(value: Any) -> str:
    path = str(value or "").replace("\\", "/").strip()
    if not path:
        return ""
    return os.path.basename(os.path.normpath(path))


def _signature_proof_obligation(value: Dict[str, Any]) -> Dict[str, Any]:
    """Keep only stable sanitizer identity fields in failure signatures.

    Probe rebuilds can make the same sanitizer summary switch between a
    checkout-relative and an absolute source path. The complete summary stays
    in the auditable contract, but it must not make an identical crash look
    like a different regression failure.
    """
    if not isinstance(value, dict):
        return {}
    if value.get("kind") != "prevent_observed_sanitizer_failure":
        return value
    return {
        "kind": value.get("kind"),
        "sanitizer_kind": value.get("sanitizer_kind"),
        "sanitizer_error": value.get("sanitizer_error"),
        "source_location_status": value.get("source_location_status"),
    }


def _compact_assertion(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not value:
        return {}
    convention = str(value.get("operand_convention") or "")
    keep_arguments = convention in {
        "custom_assertion_semantics_unknown",
        "symmetric_or_unknown",
        "unknown",
    }
    return {
        "kind": value.get("kind"),
        "callee": value.get("callee"),
        "source_range": value.get("source_range") or {},
        "source": clip(value.get("source"), 1000),
        "arguments": [
            clip(item, 600) for item in value.get("arguments") or []
        ][:8] if keep_arguments else [],
        "expected_expression": clip(value.get("expected_expression"), 600),
        "actual_expression": clip(value.get("actual_expression"), 600),
        "operand_convention": convention,
        "asserted_symbols": (value.get("asserted_symbols") or [])[:24],
        "selection_basis": value.get("selection_basis"),
        "location_confidence": value.get("location_confidence"),
    }


def _compact_dependency_slice(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not value:
        return {}
    return {
        "strategy": value.get("strategy"),
        "source_path": value.get("source_path"),
        "symbols": (value.get("symbols") or [])[:24],
        "statements": [
            {
                "source_range": item.get("source_range") or {},
                "source": clip(item.get("source"), 800),
            }
            for item in value.get("statements") or []
            if isinstance(item, dict)
        ][:10],
        "uncertainty": value.get("uncertainty"),
    }


def _compact_test_input(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not value:
        return {}
    compact = {
        "kind": value.get("kind"),
        "selection_basis": value.get("selection_basis"),
        "source_path": value.get("source_path"),
        "source_ranges": [
            item
            for item in value.get("source_ranges") or []
            if isinstance(item, dict)
        ][:12],
        "source": clip(value.get("source"), 3_000),
        "symbols": (value.get("symbols") or [])[:32],
    }
    optional = {
        "role": value.get("role"),
        "primary": value.get("primary"),
        "path": value.get("path"),
        "media_type": value.get("media_type"),
        "sha256": value.get("sha256"),
        "size": value.get("size"),
        "content_ref": value.get("content_ref"),
        "preview": value.get("preview"),
    }
    compact.update({
        key: item
        for key, item in optional.items()
        if item not in (None, "", {}, [])
    })
    return compact


def _compact_expected_oracle(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not value:
        return {}
    compact = {
        "kind": value.get("kind"),
        "source_path": value.get("source_path"),
        "source": clip(value.get("source"), 2_000),
    }
    compact.update({
        key: value.get(key)
        for key in (
            "selection_basis",
            "path",
            "media_type",
            "sha256",
            "size",
            "content_ref",
        )
        if value.get(key) not in (None, "")
    })
    return compact


def _compact_resolved_test_case(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not value:
        return {}
    definition = value.get("definition") or {}
    execution = value.get("execution") or {}
    provenance = value.get("provenance") or {}
    return {
        "schema": value.get("schema"),
        "version": value.get("version"),
        "test_id": value.get("test_id"),
        "framework": value.get("framework"),
        "definition": {
            "kind": definition.get("kind"),
            "source_path": definition.get("source_path"),
            "source_range": definition.get("source_range") or {},
            "source": clip(definition.get("source"), 1_500),
        },
        "execution": {
            "runner": execution.get("runner"),
            "cwd": execution.get("cwd"),
            "executable_hint": execution.get("executable_hint"),
            "arguments": [
                clip(item, 300)
                for item in execution.get("arguments") or []
            ][:32],
        },
        "inputs": [
            _compact_test_input(item)
            for item in value.get("inputs") or []
            if isinstance(item, dict) and item
        ][:12],
        "oracle": _compact_expected_oracle(value.get("oracle") or {}),
        "provenance": {
            "resolver": provenance.get("resolver"),
            "confidence": provenance.get("confidence"),
            "ground_truth_used": bool(
                provenance.get("ground_truth_used")
            ),
        },
        "diagnostics": compact_strings(
            value.get("diagnostics"),
            limit=8,
            chars=240,
        ),
    }


def _compact_regression_output(value: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(value, dict) or not value:
        return {}
    return {
        "source": value.get("source"),
        "returncode": value.get("returncode"),
        "failed_as_expected": value.get("failed_as_expected"),
        "test_executed": value.get("test_executed"),
        "text": clip(value.get("text"), 2_000),
    }


def _normalized_output(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _diagnostic_log_excerpt(
    failure_log: str, observation: Dict[str, Any]
) -> str:
    """Keep diagnostics that are not already structured in failure_observation."""
    runner_observation = _normalized_output(
        str(observation.get("runner_assertion_observation") or "")
    )
    retained = []
    for raw_line in str(failure_log or "").splitlines():
        line = raw_line.strip()
        if not line:
            continue
        if re.match(
            r"^\[(?:=+|\s*(?:RUN|FAILED|PASSED)\s*)\]",
            line,
            re.IGNORECASE,
        ):
            continue
        if re.match(r"^\d+\s+FAILED TEST\(S\)$", line, re.IGNORECASE):
            continue
        if line.startswith("[   LINE   ]"):
            continue
        error_match = re.match(r"^\[\s*ERROR\s*\]\s*---\s*(.*)$", line)
        if error_match and _normalized_output(error_match.group(1)) == runner_observation:
            continue
        retained.append(line)
    return clip("\n".join(retained), 1400)


def _proof_obligation(
    *,
    assertion: Dict[str, Any],
    observation: Dict[str, Any],
    expected_oracle: Dict[str, Any] = None,
) -> Dict[str, Any]:
    if observation.get("failure_mode") == "sanitizer":
        return {
            "kind": "prevent_observed_sanitizer_failure",
            "sanitizer_kind": observation.get("sanitizer_kind"),
            "sanitizer_error": observation.get("sanitizer_error"),
            "sanitizer_summary": observation.get("sanitizer_summary"),
            "source_location_status": observation.get(
                "source_location_status"
            ),
        }
    if observation.get("failure_mode") == "signal":
        return {
            "kind": "prevent_observed_signal",
            "signal_name": observation.get("signal_name"),
            "signal_number": observation.get("signal_number"),
            "source_location_status": observation.get("source_location_status"),
        }
    if not assertion:
        if expected_oracle:
            return {
                "kind": "match_expected_regression_output",
                "expected_output": expected_oracle.get("source"),
                "oracle_source": expected_oracle.get("source_path"),
                "runner_observation": (
                    observation.get("runner_assertion_observation")
                ),
            }
        return {
            "kind": "resolve_assertion_oracle",
            "runner_observation": observation.get("runner_assertion_observation"),
            "source_location_status": observation.get("source_location_status"),
            "uncertainty": "failing_assertion_not_uniquely_located",
        }
    return {
        "kind": "satisfy_failing_assertion",
        "assertion_callee": assertion.get("callee"),
        "expected_expression": assertion.get("expected_expression"),
        "actual_expression": assertion.get("actual_expression"),
        "selection_basis": assertion.get("selection_basis"),
        "location_confidence": assertion.get("location_confidence"),
    }


def analyze_test_failure_source(
    *,
    source: str,
    source_path: str,
    source_range: Dict[str, Any],
    failure_log: str,
    language: str = "",
) -> Dict[str, Any]:
    """Extract the exact failed assertion and a compact source dependency slice."""
    test = {
        "test_source": source,
        "test_source_path": source_path,
        "test_source_range": source_range or {},
        "failure_log": failure_log,
        "language": language or source_language_from_path(source_path),
    }
    return _focused_test_evidence(test)


def _focused_test_evidence(test: Dict[str, Any]) -> Dict[str, Any]:
    existing_assertion = test.get("failing_assertion")
    existing_slice = test.get("test_dependency_slice")
    existing_observation = test.get("failure_observation")
    if isinstance(existing_assertion, dict) and existing_assertion:
        return {
            "failing_assertion": existing_assertion,
            "test_dependency_slice": existing_slice if isinstance(existing_slice, dict) else {},
            "failure_observation": (
                existing_observation if isinstance(existing_observation, dict)
                else _failure_observation(str(test.get("failure_log") or ""), test)
            ),
        }

    source_range = test.get("test_source_range") or {}
    failure_log = str(test.get("failure_log") or test.get("fail_reason") or "")
    observation = _failure_observation(failure_log, test)
    source = _complete_test_source(
        test,
        source=str(test.get("test_source") or ""),
        source_range=source_range,
        observation=observation,
    )
    if not source:
        return {
            "failing_assertion": {},
            "test_dependency_slice": {},
            "failure_observation": observation,
        }

    language = str(
        test.get("language")
        or source_language_from_path(str(test.get("test_source_path") or ""))
        or "c"
    )
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return {
            "failing_assertion": _line_assertion_fallback(source, source_range, observation),
            "test_dependency_slice": {},
            "failure_observation": observation,
        }

    base_line = int(source_range.get("start_line") or 1)
    reported_line = int(observation.get("reported_line") or 0)
    relative_row = reported_line - base_line if reported_line >= base_line else -1
    assertion_node = _assertion_node_at_row(tree.root_node, source_bytes, relative_row)
    selection_basis = ""
    location_confidence = ""
    if assertion_node is not None:
        selection_basis = "runner_reported_source_line"
        location_confidence = "high"
    elif observation.get("failure_mode") != "signal" and not reported_line:
        candidates = _assertion_nodes(tree.root_node, source_bytes)
        if len(candidates) == 1:
            assertion_node = candidates[0]
            selection_basis = "only_assertion_in_test"
            location_confidence = "medium"
    if assertion_node is None:
        return {
            "failing_assertion": _line_assertion_fallback(source, source_range, observation),
            "test_dependency_slice": (
                {}
                if observation.get("failure_mode") == "signal"
                else _assertion_candidate_slice(
                    tree.root_node,
                    source_bytes=source_bytes,
                    source_path=str(test.get("test_source_path") or ""),
                    source_range=source_range,
                )
            ),
            "failure_observation": observation,
        }

    assertion = _assertion_record(
        assertion_node,
        source_bytes=source_bytes,
        source_path=str(test.get("test_source_path") or ""),
        source_range=source_range,
    )
    assertion["selection_basis"] = selection_basis
    assertion["location_confidence"] = location_confidence
    dependency_slice = _test_dependency_slice(
        tree.root_node,
        assertion_node=assertion_node,
        assertion=assertion,
        source_bytes=source_bytes,
        source_path=str(test.get("test_source_path") or ""),
        source_range=source_range,
    )
    return {
        "failing_assertion": assertion,
        "test_dependency_slice": dependency_slice,
        "failure_observation": observation,
    }


def _failure_observation(failure_log: str, test: Dict[str, Any]) -> Dict[str, Any]:
    source_range = test.get("test_source_range") or {}
    start_line = int(source_range.get("start_line") or 0)
    end_line = int(source_range.get("end_line") or 0)
    reported_path, reported_line = _reported_test_location(
        failure_log,
        test_source_path=str(test.get("test_source_path") or ""),
        start_line=start_line,
        end_line=end_line,
    )
    error_payload = ""
    for line in failure_log.splitlines():
        match = re.match(r"\s*\[\s*ERROR\s*\]\s*---\s*(.*)", line)
        if match:
            error_payload = match.group(1).strip()
            break
    signal_match = re.search(
        r"\b(Segmentation fault|Abort|Bus error|Illegal instruction)"
        r"(?:\((\d+)\))?",
        failure_log,
        re.IGNORECASE,
    )
    signal_name = ""
    if signal_match:
        signal_name = {
            "segmentation fault": "SIGSEGV",
            "abort": "SIGABRT",
            "bus error": "SIGBUS",
            "illegal instruction": "SIGILL",
        }.get(signal_match.group(1).lower(), signal_match.group(1))
    sanitizer_match = re.search(
        r"ERROR:\s*(?P<kind>AddressSanitizer|"
        r"UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer)"
        r":\s*(?P<error>[^\n\r]+)",
        failure_log,
        re.IGNORECASE,
    )
    sanitizer_kind = ""
    sanitizer_error = ""
    sanitizer_summary = ""
    if sanitizer_match:
        sanitizer_kind = {
            "addresssanitizer": "address",
            "undefinedbehaviorsanitizer": "undefined",
            "memorysanitizer": "memory",
            "threadsanitizer": "thread",
        }.get(
            sanitizer_match.group("kind").lower(),
            sanitizer_match.group("kind"),
        )
        sanitizer_error = re.sub(
            r"\s+on\s+(?:unknown\s+)?(?:address\s+)?"
            r"0x[0-9a-f]+.*$",
            "",
            sanitizer_match.group("error").strip(),
            flags=re.IGNORECASE,
        )
        summary_match = re.search(
            r"SUMMARY:\s*[^\n\r]+",
            failure_log,
            re.IGNORECASE,
        )
        sanitizer_summary = (
            summary_match.group(0).strip()
            if summary_match
            else ""
        )
    failure_mode = (
        "sanitizer"
        if sanitizer_match
        else "signal"
        if signal_match
        else "assertion"
    )
    observation = {
        "reported_source_path": reported_path,
        "reported_line": reported_line,
        "runner_assertion_observation": clip(error_payload, 800),
        "runner_log_kind": (
            "sanitizer" if sanitizer_match
            else "cmocka" if "[  ERROR   ]" in failure_log
            else "gtest" if "[ RUN      ]" in failure_log
            else "generic"
        ),
        "failure_mode": failure_mode,
        "signal_name": signal_name,
        "signal_number": int(signal_match.group(2)) if signal_match and signal_match.group(2) else 0,
        "source_location_status": "exact" if reported_line else "unavailable",
    }
    if sanitizer_match:
        observation.update({
            "sanitizer_kind": sanitizer_kind,
            "sanitizer_error": clip(sanitizer_error, 500),
            "sanitizer_summary": clip(sanitizer_summary, 1_000),
        })
    return observation


def _reported_test_location(
    failure_log: str,
    *,
    test_source_path: str,
    start_line: int,
    end_line: int,
) -> tuple:
    """Prefer an explicit runner test location over unrelated diagnostics."""
    pattern = re.compile(
        r"(?P<path>(?:/[^\n:]+|[A-Za-z0-9_./\\-]+\.[A-Za-z0-9]+)):"
        r"(?P<line>\d+)(?::\d+)?:?"
    )
    expected_basename = os.path.basename(test_source_path)
    candidates = []
    sequence = 0
    for raw_line in str(failure_log or "").splitlines():
        explicit_runner_line = bool(
            re.search(r"\[\s*LINE\s*\]", raw_line, re.IGNORECASE)
            or re.search(r"\b(?:error:\s*)?Failure!?\s*$", raw_line, re.IGNORECASE)
        )
        for match in pattern.finditer(raw_line):
            line = int(match.group("line"))
            if start_line and end_line and not start_line <= line <= end_line:
                continue
            path = match.group("path")
            score = 0
            if explicit_runner_line:
                score += 100
            if expected_basename and os.path.basename(path) == expected_basename:
                score += 50
            if start_line and end_line:
                score += 10
            candidates.append((score, -sequence, path, line))
            sequence += 1
    if not candidates:
        return "", 0
    _, _, path, line = max(candidates)
    return path, line


def _complete_test_source(
    test: Dict[str, Any],
    *,
    source: str,
    source_range: Dict[str, Any],
    observation: Dict[str, Any],
) -> str:
    """Reload an isolated function when a legacy artifact clipped its tail."""
    start_line = int(source_range.get("start_line") or 1)
    end_line = int(source_range.get("end_line") or start_line)
    reported_line = int(observation.get("reported_line") or 0)
    expected_line_count = max(1, end_line - start_line + 1)
    source_line_count = len(source.splitlines())
    contains_reported_line = (
        not reported_line
        or reported_line < start_line
        or reported_line - start_line < source_line_count
    )
    if source and source_line_count >= expected_line_count and contains_reported_line:
        return source
    path = str(test.get("test_source_path") or "")
    if not path or not os.path.isfile(path):
        return source
    try:
        with open(path, "rb") as handle:
            raw = handle.read()
        start_byte = int(source_range.get("start_byte") or 0)
        end_byte = int(source_range.get("end_byte") or 0)
    except (OSError, TypeError, ValueError):
        return source
    if start_byte < 0 or end_byte <= start_byte or end_byte > len(raw):
        return source
    return raw[start_byte:end_byte].decode("utf-8", errors="replace")


def _assertion_node_at_row(root, source_bytes: bytes, row: int):
    if row < 0:
        return None
    candidates = []
    for node in walk_nodes(root):
        if not _node_contains_row(node, row):
            continue
        if node.type == "call_expression":
            name = _call_name(node, source_bytes)
            if _looks_like_assertion(name):
                candidates.append(node)
    if candidates:
        return min(candidates, key=lambda item: int(item.end_byte) - int(item.start_byte))
    return None


def _assertion_nodes(root, source_bytes: bytes) -> List[Any]:
    return [
        node for node in walk_nodes(root)
        if node.type == "call_expression"
        and _looks_like_assertion(_call_name(node, source_bytes))
    ]


def _looks_like_assertion(name: str) -> bool:
    leaf = str(name or "").rsplit("::", 1)[-1]
    return bool(re.match(
        r"(?i)^(?:assert|expect|check|verify|fail)(?:_|$)", leaf
    ))


def _call_name(node, source_bytes: bytes) -> str:
    function = node.child_by_field_name("function")
    if function is None:
        return ""
    return node_text(function, source_bytes).strip()


def _assertion_record(
    node,
    *,
    source_bytes: bytes,
    source_path: str,
    source_range: Dict[str, Any],
) -> Dict[str, Any]:
    name = _call_name(node, source_bytes)
    arguments_node = node.child_by_field_name("arguments")
    arguments = [
        node_text(child, source_bytes).strip()
        for child in (arguments_node.named_children if arguments_node is not None else [])
        if node_text(child, source_bytes).strip()
    ]
    expected, actual, convention = _expected_actual_expressions(name, arguments)
    return {
        "kind": "test_assertion",
        "callee": name,
        "source_path": source_path,
        "source_range": _absolute_node_range(node, source_range),
        "source": clip(node_text(node, source_bytes), 1800),
        "arguments": arguments[:12],
        "expected_expression": expected,
        "actual_expression": actual,
        "operand_convention": convention,
        "asserted_symbols": sorted(_node_identifiers(node, source_bytes))[:24],
    }


def _expected_actual_expressions(name: str, arguments: List[str]) -> tuple:
    leaf = str(name or "").lower()
    if ("assert_null" in leaf or leaf.endswith("assertnull")) and arguments:
        return "NULL", arguments[0], "null_assertion"
    if ("assert_non_null" in leaf or "assert_not_null" in leaf) and arguments:
        return "non-NULL", arguments[0], "non_null_assertion"
    if not re.match(r"^(?:assert|expect).*(?:equal|eq|same)", leaf):
        return "", "", "custom_assertion_semantics_unknown"
    if len(arguments) < 2:
        return "", "", "unknown"
    left_expected = _looks_like_expected_literal(arguments[0])
    right_expected = _looks_like_expected_literal(arguments[1])
    if left_expected and not right_expected:
        return arguments[0], arguments[1], "literal_or_constant_expected_operand"
    if right_expected and not left_expected:
        return arguments[1], arguments[0], "literal_or_constant_expected_operand"
    return "", "", "symmetric_or_unknown"


def _looks_like_expected_literal(value: str) -> bool:
    text = str(value or "").strip()
    return bool(
        re.match(r"^(?:[-+]?(?:0x[0-9A-Fa-f]+|\d+(?:\.\d+)?)|NULL|nullptr|true|false)$", text)
        or (len(text) >= 2 and text[0] in {'"', "'"} and text[-1] == text[0])
        or re.match(r"^(?:LY|LYS|LYD|LYXP|EXIT|EINVAL|E[A-Z0-9_]+)_[A-Z0-9_]+$", text)
        or text in {"LY_SUCCESS", "LY_EVALID", "LY_EINVAL"}
    )


def _test_dependency_slice(
    root,
    *,
    assertion_node,
    assertion: Dict[str, Any],
    source_bytes: bytes,
    source_path: str,
    source_range: Dict[str, Any],
) -> Dict[str, Any]:
    statements = _preceding_statements(root, assertion_node)
    demanded = {
        value for value in assertion.get("asserted_symbols") or []
        if _is_variable_like_symbol(value)
    }
    assertion_definitions = _statement_definitions(assertion_node, source_bytes)
    demanded.difference_update(assertion_definitions)
    demanded.difference_update(_node_call_names(assertion_node, source_bytes))
    selected = []
    # A small local window preserves scenario setup even when a helper mutates
    # an object through a pointer or macro that static def/use cannot resolve.
    for statement in statements[-6:]:
        selected.append(statement)
    if assertion_definitions:
        selected = [
            statement for statement in selected
            if not _statement_definitions(statement, source_bytes).intersection(
                assertion_definitions
            )
        ]
    boundary = _scenario_boundary(selected, source_bytes)
    if boundary >= 0:
        selected = [
            statement for statement in selected
            if int(statement.start_byte) >= boundary
        ]
    resolved_by_reference = {
        symbol
        for statement in selected
        for symbol in demanded
        if re.search(
            r"(?:&|\*)\s*" + re.escape(symbol) + r"\b",
            node_text(statement, source_bytes),
        )
    }
    for statement in reversed(statements):
        if boundary >= 0 and int(statement.start_byte) < boundary:
            break
        defined = _statement_definitions(statement, source_bytes)
        source = node_text(statement, source_bytes)
        mentions_demanded = demanded.intersection(_node_identifiers(statement, source_bytes))
        passes_by_reference = any(
            re.search(r"(?:&|\*)\s*" + re.escape(symbol) + r"\b", source)
            for symbol in demanded - resolved_by_reference
        )
        if defined.intersection(demanded) or (mentions_demanded and passes_by_reference):
            selected.append(statement)
            resolved_by_reference.update(
                symbol for symbol in demanded
                if re.search(r"(?:&|\*)\s*" + re.escape(symbol) + r"\b", source)
            )
            demanded.update(
                value for value in _node_identifiers(statement, source_bytes)
                if _is_variable_like_symbol(value)
            )
        if len({int(item.start_byte) for item in selected}) >= 12:
            break
    unique = {int(item.start_byte): item for item in selected}
    ordered = [unique[key] for key in sorted(unique)]
    records = [
        {
            "source_range": _absolute_node_range(item, source_range),
            "source": clip(node_text(item, source_bytes), 1200),
        }
        for item in ordered
    ]
    return {
        "strategy": "assertion_backward_local_def_use_slice",
        "source_path": source_path,
        "symbols": sorted(demanded)[:32],
        "statements": records,
        "source": "\n".join(
            f"L{(item['source_range'] or {}).get('start_line')}: {item['source']}"
            for item in records
        ),
    }


def _scenario_boundary(statements: List[Any], source_bytes: bytes) -> int:
    """Find the nearest literal input reset in the local pre-assertion window."""
    candidates = [
        int(statement.start_byte)
        for statement in statements
        if _contains_literal_assignment(statement, source_bytes)
    ]
    # Blank lines commonly separate independent test scenarios. Prefer the
    # latest contiguous setup/assertion group over assertions from a prior case.
    for previous, current in zip(statements, statements[1:]):
        if int(current.start_point[0]) - int(previous.end_point[0]) > 1:
            candidates.append(int(current.start_byte))
    # A new non-assert setup statement after completed assertions is another
    # common scenario boundary (for example, installing a new callback).
    last_assertion_index = -1
    for index, statement in enumerate(statements):
        if any(
            _looks_like_assertion(name)
            for name in _node_call_names(statement, source_bytes)
        ):
            last_assertion_index = index
    if 0 <= last_assertion_index < len(statements) - 1:
        candidates.append(int(statements[last_assertion_index + 1].start_byte))
    return max(candidates, default=-1)


def _contains_literal_assignment(node, source_bytes: bytes) -> bool:
    """Use syntax nodes so '=' text inside a string is not a scenario reset."""
    for child in walk_nodes(node):
        value = None
        if child.type == "assignment_expression":
            value = child.child_by_field_name("right")
        elif child.type == "init_declarator":
            value = child.child_by_field_name("value")
        if value is None:
            continue
        value_text = node_text(value, source_bytes).lstrip()
        if value.type in {
            "string_literal",
            "concatenated_string",
            "char_literal",
        } or re.match(r"^(?:u8|u|U|L|R)?[\"']", value_text):
            return True
    return False


def _assertion_candidate_slice(
    root,
    *,
    source_bytes: bytes,
    source_path: str,
    source_range: Dict[str, Any],
) -> Dict[str, Any]:
    """Expose bounded candidates without claiming which assertion failed."""
    candidates = _assertion_nodes(root, source_bytes)[-8:]
    records = [
        {
            "source_range": _absolute_node_range(item, source_range),
            "source": clip(node_text(item, source_bytes), 1200),
        }
        for item in candidates
    ]
    return {
        "strategy": "assertion_location_unavailable_candidates",
        "source_path": source_path,
        "symbols": [],
        "statements": records,
        "source": "\n".join(
            f"L{(item['source_range'] or {}).get('start_line')}: {item['source']}"
            for item in records
        ),
        "uncertainty": "runner_did_not_uniquely_locate_failing_assertion",
    }


def _preceding_statements(root, assertion_node) -> List[Any]:
    allowed = {
        "declaration", "expression_statement", "return_statement",
    }
    values = []
    for node in walk_nodes(root):
        if node.type not in allowed or int(node.end_byte) > int(assertion_node.start_byte):
            continue
        # Nested calls/expressions are represented by their enclosing statement.
        values.append(node)
    return sorted(values, key=lambda item: int(item.start_byte))


def _statement_definitions(node, source_bytes: bytes) -> Set[str]:
    definitions: Set[str] = set()
    if node.type == "declaration":
        for child in walk_nodes(node):
            if child.type in {"init_declarator", "pointer_declarator", "array_declarator"}:
                declarator = child.child_by_field_name("declarator")
                if declarator is not None:
                    definitions.update(_node_identifiers(declarator, source_bytes))
        if not definitions:
            identifiers = list(_node_identifiers(node, source_bytes))
            if identifiers:
                definitions.add(identifiers[-1])
    for child in walk_nodes(node):
        if child.type != "assignment_expression":
            continue
        left = child.child_by_field_name("left")
        if left is not None:
            definitions.update(_node_identifiers(left, source_bytes))
    return definitions


def _node_identifiers(node, source_bytes: bytes) -> Set[str]:
    return {
        node_text(child, source_bytes).strip()
        for child in walk_nodes(node)
        if child.type in {
            "identifier", "field_identifier", "namespace_identifier", "type_identifier",
        }
        and node_text(child, source_bytes).strip()
    }


def _node_call_names(node, source_bytes: bytes) -> Set[str]:
    return {
        _call_name(child, source_bytes).rsplit("::", 1)[-1]
        for child in walk_nodes(node)
        if child.type == "call_expression" and _call_name(child, source_bytes)
    }


def _is_variable_like_symbol(value: str) -> bool:
    text = str(value or "")
    return bool(
        re.match(r"^[A-Za-z_][A-Za-z0-9_]*$", text)
        and not text.isupper()
        and not _looks_like_assertion(text)
    )


def _absolute_node_range(node, source_range: Dict[str, Any]) -> Dict[str, int]:
    base_byte = int(source_range.get("start_byte") or 0)
    base_line = int(source_range.get("start_line") or 1)
    return {
        "start_byte": base_byte + int(node.start_byte),
        "end_byte": base_byte + int(node.end_byte),
        "start_line": base_line + int(node.start_point[0]),
        "end_line": base_line + int(node.end_point[0]),
    }


def _node_contains_row(node, row: int) -> bool:
    return int(node.start_point[0]) <= row <= int(node.end_point[0])


def _line_assertion_fallback(
    source: str, source_range: Dict[str, Any], observation: Dict[str, Any]
) -> Dict[str, Any]:
    base_line = int(source_range.get("start_line") or 1)
    reported_line = int(observation.get("reported_line") or 0)
    index = reported_line - base_line
    lines = source.splitlines()
    if index < 0 or index >= len(lines):
        return {}
    return {
        "kind": "source_line_fallback",
        "callee": "",
        "source_range": {
            "start_line": reported_line,
            "end_line": reported_line,
        },
        "source": clip(lines[index].strip(), 1800),
        "arguments": [],
        "expected_expression": "",
        "actual_expression": "",
        "operand_convention": "unknown",
        "asserted_symbols": [],
    }


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
