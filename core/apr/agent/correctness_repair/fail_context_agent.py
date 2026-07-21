"""Deterministic failing-test source extraction for correctness APR."""

from __future__ import annotations

import os
from typing import Any, Dict, Iterable, List, Optional, Tuple

from data_loaders.base_loader import BugRecord

from core.apr.artifacts import write_fail_context_artifact
from core.apr.common import node_text, parse_tree, parser_diagnostics, source_language_from_path, walk_nodes

from .failure_contract import analyze_test_failure_source, build_failure_contract
from .models import clip


def run_correctness_fail_context_agent(
    *, bug: Optional[BugRecord], bug_id: str, llm_provider: Optional[str] = None
) -> Tuple[Optional[dict], dict]:
    del llm_provider  # Failure contracts are deterministic by design.
    fail_context = build_correctness_fail_context(bug)
    tests = fail_context.get("tests") or []
    error = "" if tests else "no_reproducible_failed_tests"
    artifact = write_fail_context_artifact(
        bug_id=bug_id,
        attempt_index=0,
        qualified_name="test_fail_context",
        candidate_relpath="",
        fail_context=fail_context,
        step_name="correctness_failure_contract_builder",
        status="generated" if tests else "empty",
        error=error,
    )
    return fail_context, artifact


def build_correctness_fail_context(bug: Optional[BugRecord]) -> dict:
    if bug is None:
        return _empty_context("bug_record_missing")
    raw = bug.raw if isinstance(bug.raw, dict) else {}
    buggy_root = os.path.realpath(str(raw.get("buggy_tree_dir") or raw.get("source_repo_dir") or ""))
    target_names = {str(item) for item in bug.ground_truth or [] if str(item)}
    test_files = _test_source_files(raw, buggy_root)
    tests = []
    gaps = []
    for record in bug.tests or []:
        if not _is_repair_failure(record):
            continue
        test_id = str(record.get("test_id") or "").strip()
        failure_log = clip(record.get("fail_reason"), 5000)
        source_match, match_error = _find_test_definition(test_id, test_files)
        if match_error:
            gaps.append(f"{test_id}:{match_error}")
        covered = {
            str(item) for item in (record.get("covered_functions") or record.get("covered_methods") or [])
        }
        focused = analyze_test_failure_source(
            source=str(source_match.get("source") or ""),
            source_path=str(source_match.get("source_path") or ""),
            source_range=source_match.get("source_range") or {},
            failure_log=failure_log,
            language=str(source_match.get("language") or ""),
        )
        tests.append({
            "test_id": test_id,
            "test_source_path": source_match.get("source_path", ""),
            "test_source_range": source_match.get("source_range", {}),
            "test_source": clip(source_match.get("source"), 1800),
            "failing_assertion": focused.get("failing_assertion") or {},
            "test_dependency_slice": focused.get("test_dependency_slice") or {},
            "failure_observation": focused.get("failure_observation") or {},
            "failure_log": failure_log,
            "actual_output": clip(record.get("actual_output"), 2200),
            "covered_target": bool(target_names & covered),
        })
    behavior = {
        "analysis_engine": {
            "name": "correctness_failure_contract_builder",
            "version": 2,
            "strategy": "tree_sitter_failing_assertion_and_test_dependency_slice",
            "parser": parser_diagnostics(_project_language(bug)),
            "llm_used": False,
            "fallback_policy": "none",
        },
        "project_info": {
            "dataset": bug.dataset,
            "language": _project_language(bug),
            "buggy_root": buggy_root,
        },
        "tests": tests,
        "runtime_facts": [],
        "evidence_gaps": gaps,
    }
    result = {
        "behavior_context": behavior,
        "tests": tests,
        "evidence_gaps": gaps,
    }
    result["failure_contract"] = build_failure_contract(result)
    result["summary_text"] = _summary(result["failure_contract"])
    return result


def _empty_context(error: str) -> dict:
    result = {
        "behavior_context": {"tests": [], "runtime_facts": [], "evidence_gaps": [error]},
        "tests": [],
        "evidence_gaps": [error],
    }
    result["failure_contract"] = build_failure_contract(result)
    result["summary_text"] = ""
    return result


def _is_repair_failure(record: Any) -> bool:
    if not isinstance(record, dict):
        return False
    before = str(record.get("outcome") or "").upper()
    after = str(record.get("outcome_fixed") or "").upper()
    return before in {"FAIL", "FAILED"} and after in {"PASS", "PASSED"}


def _test_source_files(raw: Dict[str, Any], buggy_root: str) -> List[str]:
    paths = []
    for value in raw.get("test_files") or []:
        path = str(value or "")
        candidate = path if os.path.isabs(path) else os.path.join(buggy_root, path)
        real = os.path.realpath(candidate)
        if buggy_root and _is_within(real, buggy_root) and os.path.isfile(real):
            paths.append(real)
    return list(dict.fromkeys(paths))


def _find_test_definition(test_id: str, paths: Iterable[str]) -> Tuple[Dict[str, Any], str]:
    parts = [part for part in test_id.split("::") if part]
    # Dataset IDs use <test-binary-or-suite>::<source test symbol>.  Only the
    # final component is a source identifier; requiring the runner name would
    # make the AST match incorrect.
    source_symbol = parts[-1] if parts else ""
    needles = [part for part in source_symbol.split(".") if part]
    if not needles:
        return {}, "test_id_missing"
    matches = []
    parser_errors = []
    for path in paths:
        language = source_language_from_path(path)
        try:
            source = open(path, "r", encoding="utf-8", errors="replace").read()
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
                if child.type in {"identifier", "field_identifier", "type_identifier"}
            }
            if all(needle in identifiers for needle in needles):
                matches.append((path, node, source_bytes))
    if len(matches) != 1:
        if not matches:
            return {}, ";".join(parser_errors) or "tree_sitter_test_definition_not_found"
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
        # Keep the complete isolated function until the failing assertion has
        # been extracted. The persisted contract stores only focused excerpts.
        "source": node_text(node, source_bytes),
    }, ""


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
        f"{test.get('test_id')}: {clip(test.get('failure_log'), 300)}"
        for test in contract.get("tests") or []
    )
