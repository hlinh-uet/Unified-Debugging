"""Scenario-first extraction for failed regression tests."""

from __future__ import annotations

import hashlib
import json
import os
import re
from typing import Any, Dict, List

from core.program_analysis.source_utils import (
    node_text,
    parse_tree,
    source_language_from_path,
    walk_nodes,
)


_ASSERTION_PREFIXES = (
    "assert",
    "expect",
    "check",
    "require",
    "verify",
)
SCENARIO_SCHEMA = "unified_debugging.failure_scenario.v2"


def build_scenario_analysis(evidence: Dict[str, Any]) -> Dict[str, Any]:
    """Split test bodies into assertions and select the first observed failure."""
    tests = []
    first_failure = None
    for test in evidence.get("tests") or []:
        source = str(test.get("focused_test_source") or "")
        source_start_line = int(test.get("focused_test_start_line") or 1)
        source_path = str(test.get("resolved_test_source_path") or "")
        scenarios = extract_assertion_scenarios(
            source=source,
            source_path=source_path,
            source_start_line=source_start_line,
            test_id=str(test.get("test_id") or ""),
        )
        observations = list(test.get("failure_observations") or [])
        executions = []
        for observation_index, observation in enumerate(observations):
            line = int(observation.get("reported_line") or 0)
            producer_site = _producer_site_for_observation(
                test, observation_index=observation_index
            )
            if not line:
                # Frameworks often report ``unknown file`` for an exception
                # escaping the test body. The producer resolver still knows
                # the last test statement whose call entered production code.
                line = int(producer_site.get("line") or 0)
            matched = _scenario_at_line(scenarios, line=line)
            site_calls = _producer_calls_for_observation(
                test, observation_index=observation_index
            )
            matched_calls = (
                matched.get("producer_calls") if matched else []
            ) or []
            producer_calls = list(dict.fromkeys([
                *matched_calls,
                *site_calls,
            ]))
            execution = {
                "test_id": test.get("test_id"),
                "observation_index": observation_index,
                "scenario_id": (
                    matched.get("scenario_id")
                    if matched
                    else _synthetic_scenario_id(
                        str(test.get("test_id") or ""),
                        line=line,
                        observation_index=observation_index,
                    )
                ),
                "scenario_fingerprint": (
                    matched.get("scenario_fingerprint")
                    if matched
                    else _synthetic_scenario_id(
                        str(test.get("test_id") or ""),
                        line=line,
                        observation_index=observation_index,
                    )
                ),
                "source_marker_id": (
                    matched.get("source_marker_id")
                    if matched else ""
                ),
                "source_line": line,
                "source_end_line": (
                    int(matched.get("end_line") or line)
                    if matched else line
                ),
                "assertion": (
                    matched.get("assertion") if matched else ""
                ),
                "source": (
                    matched.get("source")
                    if matched
                    else _producer_source_for_observation(
                        test, observation_index=observation_index
                    )
                ),
                "arguments": matched.get("arguments") if matched else [],
                "expected_expression": (
                    matched.get("expected_expression") if matched else ""
                ),
                "actual_expression": (
                    matched.get("actual_expression") if matched else ""
                ),
                "producer_calls": producer_calls,
                "producer_source": _producer_source_for_observation(
                    test, observation_index=observation_index
                ),
                "input_literals": _scenario_input_literals(
                    scenario=matched,
                    producer_source=_producer_source_for_observation(
                        test, observation_index=observation_index
                    ),
                    fallback=test.get("input_literals") or [],
                ),
                "observed_output": _complete_observed_contract(
                    observation.get("observed_output") or {},
                    scenario=matched,
                ),
                "status": "failed",
                "execution_mode": "observed_in_ordered_test_run",
            }
            executions.append(execution)
            if first_failure is None:
                first_failure = execution
        failed_ids = {
            str(item.get("scenario_id") or "") for item in executions
        }
        for scenario in scenarios:
            scenario["status"] = (
                "failed" if scenario["scenario_id"] in failed_ids
                else "executed_before_or_after_failure_unknown"
            )
        tests.append({
            "test_id": test.get("test_id"),
            "source_path": source_path,
            "scenario_count": len(scenarios),
            "scenarios": scenarios,
            "failure_executions": executions,
        })
    return {
        "schema": SCENARIO_SCHEMA,
        "version": 2,
        "selection": "first failure observation in fresh test output",
        "tests": tests,
        "first_failing_scenario": first_failure or {},
        "diagnostics": (
            [] if first_failure else ["first_failing_scenario_unavailable"]
        ),
    }


def extract_assertion_scenarios(
    *,
    source: str,
    source_path: str,
    source_start_line: int,
    test_id: str = "",
) -> List[Dict[str, Any]]:
    if not source:
        return []
    language = source_language_from_path(source_path)
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return _lexical_assertion_scenarios(
            source=source,
            source_start_line=source_start_line,
            source_path=source_path,
            test_id=test_id,
        )
    raw_scenarios = []
    seen_statements = set()
    for node in walk_nodes(tree.root_node):
        if node.type != "call_expression":
            continue
        function = node.child_by_field_name("function")
        arguments = node.child_by_field_name("arguments")
        if function is None or arguments is None:
            continue
        assertion = node_text(function, source_bytes).strip()
        if not _is_assertion_name(assertion):
            continue
        statement = _containing_statement(node)
        if statement is None:
            # Calls inside a preprocessor/macro definition or a parser error
            # do not have an executable statement boundary. Instrumenting
            # their translation-unit span would emit a marker at file scope.
            continue
        statement_key = (
            int(statement.start_byte),
            int(statement.end_byte),
        )
        if statement_key in seen_statements:
            continue
        seen_statements.add(statement_key)
        argument_values = [
            node_text(child, source_bytes).strip()
            for child in arguments.named_children
            if node_text(child, source_bytes).strip()
        ]
        producer_calls = _nested_non_assertion_calls(
            node, source_bytes=source_bytes
        )
        line = source_start_line + int(statement.start_point[0])
        end_line = source_start_line + int(statement.end_point[0])
        statement_source = node_text(statement, source_bytes).strip()[:2000]
        raw_scenarios.append({
            "start_byte": int(statement.start_byte),
            "end_byte": int(statement.end_byte),
            "line": line,
            "end_line": end_line,
            "assertion": assertion,
            "source": statement_source,
            "arguments": argument_values[:16],
            "expected_expression": (
                argument_values[0] if len(argument_values) >= 2 else ""
            ),
            "actual_expression": (
                argument_values[1] if len(argument_values) >= 2 else (
                    argument_values[0] if argument_values else ""
                )
            ),
            "producer_calls": producer_calls[:24],
        })
    raw_scenarios.sort(
        key=lambda item: (
            int(item.get("start_byte") or 0),
            int(item.get("end_byte") or 0),
            str(item.get("source") or ""),
        )
    )
    scenarios = []
    for ordinal, item in enumerate(raw_scenarios, start=1):
        fingerprint = scenario_fingerprint(
            test_id=test_id,
            source_path=source_path,
            start_byte=int(item.get("start_byte") or 0),
            end_byte=int(item.get("end_byte") or 0),
            start_line=int(item.get("line") or 0),
            end_line=int(item.get("end_line") or 0),
            source=str(item.get("source") or ""),
        )
        source_marker_id = scenario_fingerprint(
            test_id="",
            source_path=source_path,
            start_byte=int(item.get("start_byte") or 0),
            end_byte=int(item.get("end_byte") or 0),
            start_line=int(item.get("line") or 0),
            end_line=int(item.get("end_line") or 0),
            source=str(item.get("source") or ""),
        )
        scenarios.append({
            **item,
            "scenario_id": f"scenario_{fingerprint}",
            "scenario_fingerprint": fingerprint,
            "source_marker_id": source_marker_id,
            "ordinal": ordinal,
        })
    return scenarios


def _containing_statement(node: Any) -> Any | None:
    current = node
    statement_types = {
        "expression_statement",
        "declaration",
        "return_statement",
    }
    while current is not None:
        if current.type in statement_types:
            return current
        if (
            current.type == "translation_unit"
            or current.type.startswith("preproc_")
        ):
            return None
        current = current.parent
    return None


def _nested_non_assertion_calls(
    node: Any, *, source_bytes: bytes
) -> List[str]:
    output = []
    for child in walk_nodes(node):
        if child == node or child.type != "call_expression":
            continue
        function = child.child_by_field_name("function")
        if function is None:
            continue
        value = node_text(function, source_bytes).strip()
        if value and not _is_assertion_name(value) and value not in output:
            output.append(value)
    return output


def _is_assertion_name(value: str) -> bool:
    leaf = str(value or "").strip().rsplit("::", 1)[-1]
    if leaf == "assert":
        return True
    # C/C++ test frameworks overwhelmingly expose assertion macros in upper
    # case (EXPECT_EQ, ASSERT_TRUE, CHECK, REQUIRE, ...). Treating arbitrary
    # lowercase helpers such as ``check_format_string`` as assertions can
    # instrument constexpr/library code and break the build.
    if not leaf or leaf != leaf.upper():
        return False
    lowered = leaf.lower()
    return any(
        lowered == prefix or lowered.startswith(prefix + "_")
        for prefix in _ASSERTION_PREFIXES
    )


def _scenario_at_line(
    scenarios: List[Dict[str, Any]], *, line: int
) -> Dict[str, Any]:
    exact = [
        item
        for item in scenarios
        if int(item.get("line") or 0) <= line
        <= int(item.get("end_line") or item.get("line") or 0)
    ]
    if not exact:
        return {}
    return min(
        exact,
        key=lambda item: (
            int(item.get("end_line") or item.get("line") or 0)
            - int(item.get("line") or 0),
            int(item.get("start_byte") or 0),
            str(item.get("scenario_id") or ""),
        ),
    )


def _producer_source_for_observation(
    test: Dict[str, Any], *, observation_index: int
) -> str:
    for site in test.get("producer_call_sites") or []:
        if int(site.get("observation_index") or 0) == observation_index:
            return str(site.get("source") or "")
    return ""


def _producer_site_for_observation(
    test: Dict[str, Any], *, observation_index: int
) -> Dict[str, Any]:
    for site in test.get("producer_call_sites") or []:
        if int(site.get("observation_index") or 0) == observation_index:
            return site
    return {}


def _producer_calls_for_observation(
    test: Dict[str, Any], *, observation_index: int
) -> List[str]:
    output = []
    sites = [
        site for site in test.get("producer_call_sites") or []
        if int(site.get("observation_index") or 0) == observation_index
    ]
    if sites:
        nearest = min(
            int(site.get("distance_to_failure") or 0) for site in sites
        )
        sites = [
            site for site in sites
            if int(site.get("distance_to_failure") or 0) == nearest
        ]
    for site in sites:
        for value in site.get("calls") or []:
            if str(value) and str(value) not in output:
                output.append(str(value))
    return output


def _complete_observed_contract(
    observed: Dict[str, Any], *, scenario: Dict[str, Any]
) -> Dict[str, Any]:
    """Fill exception contracts from the matched assertion, not the dataset."""
    result = {
        key: list(value) if isinstance(value, list) else value
        for key, value in observed.items()
    }
    assertion = str(scenario.get("assertion") or "").upper()
    arguments = scenario.get("arguments") or []
    if "THROW" in assertion and not result.get("expected") and arguments:
        expected = str(arguments[-1] or "").strip()
        if expected:
            result["expected"] = [expected]
    return result


def _synthetic_scenario_id(
    test_id: str, *, line: int, observation_index: int
) -> str:
    digest = _stable_digest({
        "test_id": str(test_id or ""),
        "line": int(line or 0),
        "observation_index": int(observation_index),
        "kind": "synthetic_failure",
    })
    return f"scenario_{digest}"


def scenario_fingerprint(
    *,
    test_id: str,
    source_path: str,
    start_byte: int,
    end_byte: int,
    start_line: int = 0,
    end_line: int = 0,
    source: str,
) -> str:
    """Return a stable scenario identity independent of extraction ordinal.

    Test source may be loaded from a host checkout or a container path. Only
    the basename is part of the identity; absolute source lines and normalized
    assertion text protect against collisions within that file.
    """
    return _stable_digest({
        "test_id": str(test_id or ""),
        "source_file": os.path.basename(
            str(source_path or "").replace("\\", "/")
        ),
        # Absolute source lines remain stable when the resolver supplies a
        # complete test body on one run and a bounded source window on another.
        "start_line": int(start_line),
        "end_line": int(end_line),
        "source": _normalize_source(source),
    })


def scenario_analysis_identity(
    scenario_analysis: Dict[str, Any],
) -> Dict[str, Any]:
    """Compact identity used by trace-plan and ranking caches."""
    scenario = (
        (scenario_analysis or {}).get("first_failing_scenario") or {}
    )
    return {
        "schema": SCENARIO_SCHEMA,
        "scenario_id": str(scenario.get("scenario_id") or ""),
        "scenario_fingerprint": str(
            scenario.get("scenario_fingerprint")
            or str(scenario.get("scenario_id") or "").removeprefix(
                "scenario_"
            )
        ),
        "test_id": str(scenario.get("test_id") or ""),
        "observation_index": int(
            scenario.get("observation_index") or 0
        ),
    }


def _scenario_input_literals(
    *,
    scenario: Dict[str, Any],
    producer_source: str,
    fallback: List[str],
) -> List[str]:
    """Keep inputs local to the failing assertion and its producer statement."""
    local_source = "\n".join(
        value
        for value in (
            str(producer_source or ""),
            str((scenario or {}).get("source") or ""),
        )
        if value
    )
    local = _literal_values(local_source)
    if local:
        return local
    return list(dict.fromkeys(str(value) for value in fallback if str(value)))[:40]


def _literal_values(source: str) -> List[str]:
    values = []
    pattern = re.compile(
        r"""(?x)
        "(?:\\.|[^"\\])*"
        |'(?:\\.|[^'\\])*'
        |(?<![A-Za-z0-9_])[-+]?(?:0[xX][0-9A-Fa-f]+|\d+(?:\.\d+)?)
        """
    )
    for match in pattern.finditer(str(source or "")):
        value = match.group(0)
        if value not in values:
            values.append(value)
    return values[:40]


def _stable_digest(value: Dict[str, Any]) -> str:
    payload = json.dumps(
        value, sort_keys=True, ensure_ascii=False, separators=(",", ":")
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:20]


def _normalize_source(value: str) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()


def _lexical_assertion_scenarios(
    *,
    source: str,
    source_start_line: int,
    source_path: str = "",
    test_id: str = "",
) -> List[Dict[str, Any]]:
    scenarios = []
    pattern = re.compile(
        r"\b((?:ASSERT|EXPECT|CHECK|REQUIRE|VERIFY)[A-Za-z0-9_]*)\s*\("
    )
    in_preprocessor = False
    for local_line, line in enumerate(source.splitlines()):
        stripped = line.lstrip()
        if stripped.startswith("#"):
            in_preprocessor = line.rstrip().endswith("\\")
            continue
        if in_preprocessor:
            in_preprocessor = line.rstrip().endswith("\\")
            continue
        match = pattern.search(line)
        if not match:
            continue
        absolute_line = source_start_line + local_line
        start_byte = sum(
            len(item.encode("utf-8")) + 1
            for item in source.splitlines()[:local_line]
        )
        statement_source = line.strip()[:2000]
        fingerprint = scenario_fingerprint(
            test_id=test_id,
            source_path=source_path,
            start_byte=start_byte,
            end_byte=start_byte + len(line.encode("utf-8")),
            start_line=absolute_line,
            end_line=absolute_line,
            source=statement_source,
        )
        source_marker_id = scenario_fingerprint(
            test_id="",
            source_path=source_path,
            start_byte=start_byte,
            end_byte=start_byte + len(line.encode("utf-8")),
            start_line=absolute_line,
            end_line=absolute_line,
            source=statement_source,
        )
        scenarios.append({
            "scenario_id": f"scenario_{fingerprint}",
            "scenario_fingerprint": fingerprint,
            "source_marker_id": source_marker_id,
            "ordinal": len(scenarios) + 1,
            "start_byte": start_byte,
            "end_byte": start_byte + len(line.encode("utf-8")),
            "line": absolute_line,
            "end_line": absolute_line,
            "assertion": match.group(1),
            "source": statement_source,
            "arguments": [],
            "expected_expression": "",
            "actual_expression": "",
            "producer_calls": [],
        })
    return scenarios
