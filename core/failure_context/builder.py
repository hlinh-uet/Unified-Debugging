"""Build the canonical Fail Context at the regression-execution boundary."""

from __future__ import annotations

import copy
import os
from typing import Any, Dict, Iterable, List, Optional, Set, Tuple

from data_loaders.base_loader import BugRecord

from core.program_analysis.source_utils import (
    node_text,
    parse_tree,
    parser_diagnostics,
    source_language_from_path,
    walk_nodes,
)
from .contract import analyze_test_failure_source, build_failure_contract
from .utils import clip


FAIL_CONTEXT_SCHEMA = "unified_debugging.regression_fail_context.v1"
_INLINE_INPUT_FIELDS = (
    "test_input",
    "input",
    "input_data",
    "stdin",
    "stdin_data",
    "arguments",
    "args",
)
_INPUT_FILE_FIELDS = (
    "input_file",
    "stdin_file",
    "test_input_file",
)


def build_regression_fail_context(
    bug: Optional[BugRecord],
    *,
    runtime_evidence: Optional[Dict[str, Any]] = None,
    test_ids: Optional[Iterable[str]] = None,
) -> dict:
    """Join exact test input with the fresh observed regression output.

    Dataset output is retained only as a compatibility fallback when no fresh
    execution result is available. Ground truth and FL candidates are never
    consulted while this context is built.
    """
    if bug is None:
        return _empty_context("bug_record_missing")

    raw = bug.raw if isinstance(bug.raw, dict) else {}
    buggy_root = os.path.realpath(
        str(
            raw.get("buggy_tree_dir")
            or raw.get("source_repo_dir")
            or os.path.dirname(str(bug.source_file or ""))
            or ""
        )
    )
    selected_ids: Optional[Set[str]] = None
    if test_ids is not None:
        selected_ids = {
            str(value).strip()
            for value in test_ids
            if str(value).strip()
        }
    runtime_by_id = {
        str(item.get("test_id") or ""): item
        for item in (runtime_evidence or {}).get("tests") or []
        if isinstance(item, dict)
    }
    test_files = _test_source_files(raw, buggy_root)
    tests = []
    runtime_facts = []
    gaps = []

    for record in bug.tests or []:
        if not _is_regression_failure(record):
            continue
        test_id = str(record.get("test_id") or "").strip()
        if selected_ids is not None and test_id not in selected_ids:
            continue

        runtime_test = runtime_by_id.get(test_id) or {}
        fresh_output = str(runtime_test.get("fresh_output") or "")
        runtime_observed = bool(runtime_test) and (
            bool(runtime_test.get("test_executed"))
            or runtime_test.get("returncode") is not None
            or bool(runtime_test.get("failed_as_expected"))
        )
        metadata_output = "\n".join(
            str(value or "")
            for value in (
                record.get("fail_reason"),
                record.get("actual_output"),
            )
            if value
        )
        failure_log = clip(
            fresh_output if runtime_observed else metadata_output,
            12_000,
        )
        output_source = (
            "fresh_regression_run"
            if runtime_observed
            else "dataset_metadata_fallback"
        )

        source_match, match_error = _find_test_definition(
            test_id,
            test_files,
        )
        if match_error:
            gaps.append(f"{test_id}:{match_error}")
        focused = analyze_test_failure_source(
            source=str(source_match.get("source") or ""),
            source_path=str(source_match.get("source_path") or ""),
            source_range=source_match.get("source_range") or {},
            failure_log=failure_log,
            language=str(source_match.get("language") or ""),
        )
        test_input = _build_test_input(
            bug=bug,
            record=record,
            test_id=test_id,
            root=buggy_root,
            source_match=source_match,
            focused=focused,
        )
        if test_input.get("kind") == "unavailable":
            gaps.append(f"{test_id}:exact_test_input_unavailable")

        regression_output = {
            "source": output_source,
            "text": failure_log,
            "artifact": str(runtime_test.get("output_artifact") or ""),
            "returncode": runtime_test.get("returncode"),
            "failed_as_expected": runtime_test.get("failed_as_expected"),
            "test_executed": runtime_test.get("test_executed"),
        }
        expected_oracle = _expected_oracle(
            bug=bug,
            record=record,
            test_id=test_id,
        )
        tests.append({
            "test_id": test_id,
            "test_source_path": source_match.get("source_path", ""),
            "test_source_range": source_match.get("source_range", {}),
            "test_source": clip(source_match.get("source"), 4_000),
            "failing_assertion": focused.get("failing_assertion") or {},
            "test_dependency_slice": (
                focused.get("test_dependency_slice") or {}
            ),
            "test_input": test_input,
            "expected_oracle": expected_oracle,
            "failure_observation": (
                focused.get("failure_observation") or {}
            ),
            "regression_output": regression_output,
            # Compatibility fields used by the existing correctness agents.
            "failure_log": failure_log,
            "actual_output": clip(
                fresh_output or record.get("actual_output"),
                2_200,
            ),
            "runtime_output_artifact": regression_output["artifact"],
            "runtime_trace_artifact": str(
                runtime_test.get("trace_artifact") or ""
            ),
        })
        runtime_facts.append(
            f"{test_id}: output={output_source}, "
            f"returncode={runtime_test.get('returncode')}, "
            f"failed_as_expected={runtime_test.get('failed_as_expected')}"
        )

    gaps = list(dict.fromkeys(value for value in gaps if value))
    behavior = {
        "analysis_engine": {
            "name": "shared_regression_fail_context_builder",
            "version": 1,
            "strategy": (
                "fresh_output_plus_failing_test_input_dependency_slice"
            ),
            "parser": parser_diagnostics(_project_language(bug)),
            "llm_used": False,
            "ground_truth_used": False,
            "fallback_policy": (
                "dataset_output_only_when_fresh_execution_is_absent"
            ),
        },
        "project_info": {
            "dataset": bug.dataset,
            "language": _project_language(bug),
            "buggy_root": buggy_root,
        },
        "tests": tests,
        "runtime_facts": runtime_facts,
        "evidence_gaps": gaps,
    }
    result = {
        "schema": FAIL_CONTEXT_SCHEMA,
        "version": 1,
        "stage": "post_regression_pre_localization",
        "behavior_context": behavior,
        "tests": tests,
        "runtime_facts": runtime_facts,
        "evidence_gaps": gaps,
    }
    result["failure_contract"] = build_failure_contract(result)
    result["context_id"] = result["failure_contract"].get(
        "contract_id",
        "",
    )
    result["summary_text"] = _summary(result["failure_contract"])
    return result


def reusable_fail_context(value: Any) -> Optional[dict]:
    """Validate and isolate a Fail Context loaded from an FL artifact."""
    if not isinstance(value, dict):
        return None
    if (
        value.get("schema") != FAIL_CONTEXT_SCHEMA
        or value.get("stage") != "post_regression_pre_localization"
    ):
        return None
    tests = value.get("tests")
    if not isinstance(tests, list) or not tests:
        return None
    if not all(isinstance(item, dict) for item in tests):
        return None
    if any(
        str(
            (item.get("regression_output") or {}).get("source")
            or ""
        )
        != "fresh_regression_run"
        for item in tests
    ):
        return None
    context_id = str(value.get("context_id") or "")
    contract_id = str(
        (value.get("failure_contract") or {}).get("contract_id")
        or ""
    )
    if not context_id or context_id != contract_id:
        return None
    return copy.deepcopy(value)


def _empty_context(error: str) -> dict:
    result = {
        "schema": FAIL_CONTEXT_SCHEMA,
        "version": 1,
        "stage": "post_regression_pre_localization",
        "behavior_context": {
            "tests": [],
            "runtime_facts": [],
            "evidence_gaps": [error],
        },
        "tests": [],
        "runtime_facts": [],
        "evidence_gaps": [error],
    }
    result["failure_contract"] = build_failure_contract(result)
    result["context_id"] = result["failure_contract"].get(
        "contract_id",
        "",
    )
    result["summary_text"] = ""
    return result


def _is_regression_failure(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    before = str(record.get("outcome") or "").upper()
    after = str(record.get("outcome_fixed") or "").upper()
    if after:
        return (
            before in {"FAIL", "FAILED"}
            and after in {"PASS", "PASSED"}
        )
    return before in {"FAIL", "FAILED"}


def _test_source_files(
    raw: Dict[str, Any],
    buggy_root: str,
) -> List[str]:
    paths = []
    for value in raw.get("test_files") or []:
        path = str(value or "")
        candidate = (
            path
            if os.path.isabs(path)
            else os.path.join(buggy_root, path)
        )
        real = os.path.realpath(candidate)
        if (
            buggy_root
            and _is_within(real, buggy_root)
            and os.path.isfile(real)
        ):
            paths.append(real)
    return list(dict.fromkeys(paths))


def _find_test_definition(
    test_id: str,
    paths: Iterable[str],
) -> Tuple[Dict[str, Any], str]:
    source_symbol = (
        [part for part in test_id.split("::") if part] or [""]
    )[-1]
    needles = [part for part in source_symbol.split(".") if part]
    if not needles:
        return {}, "test_id_missing"
    matches = []
    parser_errors = []
    for path in paths:
        language = source_language_from_path(path)
        try:
            with open(
                path,
                "r",
                encoding="utf-8",
                errors="replace",
            ) as stream:
                source = stream.read()
        except OSError:
            parser_errors.append(f"test_source_read_failed:{path}")
            continue
        tree, source_bytes = parse_tree(source, language)
        if tree is None or source_bytes is None:
            parser_errors.append(f"test_source_parse_failed:{path}")
            continue
        for node in walk_nodes(tree.root_node):
            if node.type != "function_definition":
                continue
            declarator = node.child_by_field_name("declarator")
            if declarator is None:
                continue
            identifiers = {
                node_text(child, source_bytes)
                for child in walk_nodes(declarator)
                if child.type in {
                    "identifier",
                    "field_identifier",
                    "type_identifier",
                }
            }
            if all(needle in identifiers for needle in needles):
                matches.append((path, node, source_bytes))
    if len(matches) != 1:
        if not matches:
            return (
                {},
                ";".join(parser_errors)
                or "tree_sitter_test_definition_not_found",
            )
        return {}, "tree_sitter_test_definition_ambiguous"
    path, node, source_bytes = matches[0]
    return {
        "source_path": path,
        "language": source_language_from_path(path),
        "source_range": {
            "start_byte": int(node.start_byte),
            "end_byte": int(node.end_byte),
            "start_line": int(node.start_point[0]) + 1,
            "end_line": int(node.end_point[0]) + 1,
        },
        "source": node_text(node, source_bytes),
    }, ""


def _build_test_input(
    *,
    bug: BugRecord,
    record: Dict[str, Any],
    test_id: str,
    root: str,
    source_match: Dict[str, Any],
    focused: Dict[str, Any],
) -> dict:
    dependency_slice = focused.get("test_dependency_slice") or {}
    statements = [
        item
        for item in dependency_slice.get("statements") or []
        if isinstance(item, dict)
        and str(item.get("source") or "").strip()
    ]
    if statements:
        return {
            "kind": "source_dependency_slice",
            "selection_basis": dependency_slice.get("strategy"),
            "source_path": (
                dependency_slice.get("source_path")
                or source_match.get("source_path")
                or ""
            ),
            "source_ranges": [
                item.get("source_range") or {}
                for item in statements
            ],
            "source": "\n".join(
                str(item.get("source") or "")
                for item in statements
            ),
            "symbols": dependency_slice.get("symbols") or [],
        }
    external = _external_input(
        bug=bug,
        record=record,
        test_id=test_id,
        root=root,
    )
    if external:
        return external
    assertion = focused.get("failing_assertion") or {}
    actual = str(assertion.get("actual_expression") or "").strip()
    if actual:
        return {
            "kind": "asserted_expression",
            "selection_basis": "failing_assertion_actual_operand",
            "source_path": source_match.get("source_path") or "",
            "source_ranges": [assertion.get("source_range") or {}],
            "source": actual,
            "symbols": assertion.get("asserted_symbols") or [],
        }
    return {
        "kind": "unavailable",
        "selection_basis": "no_source_slice_or_external_fixture",
        "source_path": "",
        "source_ranges": [],
        "source": "",
        "symbols": [],
    }


def _external_input(
    *,
    bug: BugRecord,
    record: Dict[str, Any],
    test_id: str,
    root: str,
) -> dict:
    for field in _INLINE_INPUT_FIELDS:
        value = record.get(field)
        if value is not None and value != "" and value != [] and value != {}:
            return {
                "kind": "metadata_input",
                "selection_basis": f"test_record.{field}",
                "source_path": "",
                "source_ranges": [],
                "source": clip(value, 12_000),
                "symbols": [],
            }
    for field in _INPUT_FILE_FIELDS:
        path = _safe_file(str(record.get(field) or ""), root)
        if path:
            return _file_input(
                path,
                selection_basis=f"test_record.{field}",
            )
    source_dir = os.path.dirname(str(bug.source_file or ""))
    for name in (
        f"input-{test_id}",
        f"input_{test_id}",
    ):
        path = _safe_file(os.path.join(source_dir, name), source_dir)
        if path:
            return _file_input(
                path,
                selection_basis="dataset_test_id_fixture",
            )
    return {}


def _expected_oracle(
    *,
    bug: BugRecord,
    record: Dict[str, Any],
    test_id: str,
) -> dict:
    expected = record.get("expected_output")
    if expected is not None and str(expected) != "":
        return {
            "kind": "metadata_expected_output",
            "source": clip(expected, 8_000),
            "source_path": "",
        }
    source_dir = os.path.dirname(str(bug.source_file or ""))
    path = _safe_file(
        os.path.join(source_dir, f"output-{test_id}"),
        source_dir,
    )
    if not path:
        return {}
    record_value = _file_input(
        path,
        selection_basis="dataset_expected_output_fixture",
    )
    return {
        "kind": "expected_output_fixture",
        "source": record_value.get("source") or "",
        "source_path": path,
    }


def _safe_file(value: str, root: str) -> str:
    if not value or not root:
        return ""
    candidate = (
        value if os.path.isabs(value)
        else os.path.join(root, value)
    )
    real = os.path.realpath(candidate)
    real_root = os.path.realpath(root)
    if _is_within(real, real_root) and os.path.isfile(real):
        return real
    return ""


def _file_input(path: str, *, selection_basis: str) -> dict:
    try:
        with open(
            path,
            "r",
            encoding="utf-8",
            errors="replace",
        ) as stream:
            value = stream.read(12_001)
    except OSError:
        return {}
    return {
        "kind": "stdin_fixture",
        "selection_basis": selection_basis,
        "source_path": path,
        "source_ranges": [],
        "source": clip(value, 12_000),
        "symbols": [],
    }


def _is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False


def _project_language(bug: BugRecord) -> str:
    raw = bug.raw if isinstance(bug.raw, dict) else {}
    value = str(raw.get("language") or "").lower()
    if value in {"c++", "cpp", "cc", "cxx"}:
        return "cpp"
    return source_language_from_path(bug.source_file)


def _summary(contract: Dict[str, Any]) -> str:
    return "; ".join(
        f"{test.get('test_id')}: "
        f"{clip(test.get('failure_log'), 300)}"
        for test in contract.get("tests") or []
    )
