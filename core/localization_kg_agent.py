from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from data_loaders.defects4c_loader import (
    FAIL_OUTCOMES,
    PASS_OUTCOMES,
    Defects4CLoadConfig,
    default_defects4c_root,
    load_defects4c_bugs,
)

from core.localization_agent_tools import (
    CODE_MODES,
    DEFAULT_OPENROUTER_MODEL,
    DEFAULT_OPENROUTER_URL,
    EVAL_TOP_KS,
    _call_openrouter_for_localization,
    _code_behavior_features,
    _covered_functions,
    _extract_json_object,
    _function_tail,
    _generic_function_penalty,
    _hit_rank_for_function_ids,
    _outcome,
    _split_function_key,
    _tokenize,
    _topk_flags,
    collect_line_coverage,
    compare_fail_pass_coverage,
    get_candidate_slice,
    get_function_code,
)


AGENT_TOOLS = [
    "get_case_bootstrap",
    "search_functions_by_terms",
    "get_failing_execution_path",
    "find_fail_pass_contrast",
    "compare_fail_pass_coverage",
    "expand_function_dependencies",
    "get_function_slice",
    "get_function_code",
    "submit_localization",
]

INTENTS = {
    "semantic_relevance",
    "execution_path",
    "fail_pass_contrast",
    "dependency_expansion",
}

BROAD_SEARCH_TERMS = {
    "format",
    "parse",
    "formatter",
    "arg",
    "value",
    "string",
    "test",
    "error",
    "type",
}


@dataclass
class LocalizationKgBuildConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    kg_file: str = ""
    bug_id_filter: str = ""
    exclude_fixed_fail_tests: bool = True
    max_code_terms_per_function: int = 60
    dependency_scan_mode: str = "failing"


@dataclass
class LocalizationKgExploreConfig:
    dataset: str = "fmt"
    kg_file: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    model: str = DEFAULT_OPENROUTER_MODEL
    api_url: str = DEFAULT_OPENROUTER_URL
    api_key_env: str = "OPENROUTER_API_KEY"
    timeout_seconds: int = 120
    max_tokens: int = 1024
    temperature: float = 0.0
    max_steps: int = 12
    max_tool_calls: int = 24
    stop_confidence: float = 0.75
    stop_stable_rounds: int = 3
    dry_run: bool = False
    request_interval_seconds: float = 0.0
    code_mode: str = "executed_lines"
    max_code_lines: int = 80
    context_lines: int = 2


def _default_dataset_dir(dataset: str) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    experiments_dir = os.path.abspath(os.path.join(here, "..", "experiments"))
    return os.path.join(experiments_dir, dataset)


def default_kg_file(dataset: str) -> str:
    return os.path.join(_default_dataset_dir(dataset), "localization_evidence_kg.json")


def default_explore_output_file(dataset: str) -> str:
    return os.path.join(_default_dataset_dir(dataset), "localization_explore_results.json")


def _write_json(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def _load_json(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _filter_bug_ids(value: str) -> set:
    return {item.strip() for item in str(value or "").split(",") if item.strip()}


def _node_id(kind: str, *parts: object) -> str:
    body = "||".join(str(part or "").replace("\n", " ") for part in parts)
    return f"{kind}:{body}"


def _add_edge(edges: List[dict], source: str, relation: str, target: str, attrs: Optional[dict] = None) -> None:
    edges.append(
        {
            "source": source,
            "relation": relation,
            "target": target,
            "attrs": attrs or {},
        }
    )


def _failure_dict(test: dict) -> dict:
    failure = test.get("failure") or {}
    return failure if isinstance(failure, dict) else {}


def _failure_terms_from_tests(tests: Sequence[dict]) -> List[str]:
    chunks: List[str] = []
    for test in tests:
        chunks.append(str(test.get("test_id") or ""))
        failure = _failure_dict(test)
        chunks.extend(
            [
                str(failure.get("expected_value") or ""),
                str(failure.get("actual_value") or ""),
                str(failure.get("observed_expression") or ""),
                " ".join(str(line) for line in (failure.get("signal_lines") or [])[:8]),
            ]
        )
    return sorted(dict.fromkeys(_tokenize(" ".join(chunks))))


def _line_keys_for_function(test: dict, function_id: str) -> List[str]:
    function_lines = test.get("covered_function_lines") or {}
    if not isinstance(function_lines, dict):
        return []
    values = function_lines.get(function_id) or []
    if not isinstance(values, list):
        return []
    return sorted(dict.fromkeys(str(value) for value in values if value))


def _bug_from_record(record: dict) -> dict:
    return {
        "bug_id": record.get("bug_id", ""),
        "metadata_bug_id": record.get("metadata_bug_id", ""),
        "dataset": record.get("dataset", ""),
        "metadata_path": record.get("metadata_path", ""),
        "project": record.get("project", ""),
        "source_file": record.get("source_file", ""),
        "source_basename": record.get("source_basename", ""),
        "ground_truth": record.get("ground_truth", []),
        "tests": record.get("raw_tests", []),
    }


def _build_case_bootstrap_from_bug(bug: dict, metadata: dict) -> dict:
    failing_tests = []
    for test in bug.get("tests", []):
        if _outcome(test.get("outcome")) not in FAIL_OUTCOMES:
            continue
        failure = _failure_dict(test)
        failing_tests.append(
            {
                "test_id": test.get("test_id", ""),
                "expected": failure.get("expected_value", ""),
                "actual": failure.get("actual_value", ""),
                "failure_type": failure.get("type", ""),
                "assertion_location": failure.get("assertion_location", ""),
                "output_summary": (failure.get("signal_lines") or [])[:8],
            }
        )
    return {
        "bug_id": bug.get("bug_id", ""),
        "metadata_bug_id": bug.get("metadata_bug_id", ""),
        "project": bug.get("project", metadata.get("project", "")),
        "bug_type": metadata.get("type_name", ""),
        "failing_tests": failing_tests,
        "available_tools": AGENT_TOOLS,
    }


def _code_terms_for_function(
    bug: dict,
    function_id: str,
    metadata: dict,
    defects4c_root: str,
    max_lines: int,
) -> List[str]:
    if max_lines <= 0:
        return []
    failing_tests = [test for test in bug.get("tests", []) if _outcome(test.get("outcome")) in FAIL_OUTCOMES]
    selected = next((test for test in failing_tests if function_id in set(_covered_functions(test))), None)
    if not selected:
        return []
    code = get_function_code(
        bug,
        function_id,
        mode="executed_lines",
        max_lines=max_lines,
        context_lines=1,
        test_id=str(selected.get("test_id") or ""),
        metadata=metadata,
        defects4c_root=defects4c_root,
    )
    if not code.get("available"):
        return []
    text = "\n".join(str(row.get("text") or "") for row in code.get("lines", []))
    return sorted(dict.fromkeys(_tokenize(text)))


def _function_stats_for_bug(bug: dict, function_id: str) -> dict:
    failing_tests = []
    passing_tests = []
    executed_lines_by_test = {}
    for test in bug.get("tests", []):
        if function_id not in set(_covered_functions(test)):
            continue
        line_keys = _line_keys_for_function(test, function_id)
        if line_keys:
            executed_lines_by_test[str(test.get("test_id") or "")] = line_keys
        outcome = _outcome(test.get("outcome"))
        row = {
            "test_id": test.get("test_id", ""),
            "executed_line_count": len(line_keys),
        }
        if outcome in FAIL_OUTCOMES:
            failing_tests.append(row)
        elif outcome in PASS_OUTCOMES:
            passing_tests.append(row)
    total_failing = sum(1 for test in bug.get("tests", []) if _outcome(test.get("outcome")) in FAIL_OUTCOMES)
    total_passing = sum(1 for test in bug.get("tests", []) if _outcome(test.get("outcome")) in PASS_OUTCOMES)
    failing_count = len(failing_tests)
    passing_count = len(passing_tests)
    failing_coverage = failing_count / total_failing if total_failing else 0.0
    passing_coverage = passing_count / total_passing if total_passing else 0.0
    contrast = failing_coverage * (1.0 - passing_coverage)
    return {
        "failing_count": failing_count,
        "passing_count": passing_count,
        "total_failing": total_failing,
        "total_passing": total_passing,
        "failing_coverage": round(failing_coverage, 6),
        "passing_coverage": round(passing_coverage, 6),
        "contrast": round(contrast, 6),
        "failing_tests": failing_tests[:20],
        "passing_tests_sample": passing_tests[:20],
        "executed_lines_by_test": executed_lines_by_test,
    }


def _build_dependency_edges_for_bug(
    kg: dict,
    bug: dict,
    metadata: dict,
    defects4c_root: str,
    scan_mode: str,
) -> None:
    tests = bug.get("tests", [])
    all_functions = sorted({function_id for test in tests for function_id in _covered_functions(test)})
    failing_functions = sorted(
        {
            function_id
            for test in tests
            if _outcome(test.get("outcome")) in FAIL_OUTCOMES
            for function_id in _covered_functions(test)
        }
    )
    scanned = failing_functions if scan_mode == "failing" else all_functions
    tails = {function_id: _function_tail(function_id) for function_id in all_functions}
    for function_id in scanned:
        code = get_function_code(
            bug,
            function_id,
            mode="full",
            max_lines=240,
            context_lines=1,
            metadata=metadata,
            defects4c_root=defects4c_root,
        )
        if not code.get("available"):
            continue
        code_text = "\n".join(str(row.get("text") or "") for row in code.get("lines", []))
        source = _node_id("function", bug["bug_id"], function_id)
        for other, tail in tails.items():
            if not tail or other == function_id:
                continue
            pattern = re.compile(r"(?<![A-Za-z0-9_:~])" + re.escape(tail) + r"\s*\(")
            if pattern.search(code_text):
                target = _node_id("function", bug["bug_id"], other)
                _add_edge(kg["edges"], source, "CALLS", target)
                _add_edge(kg["edges"], target, "CALLED_BY", source)


def build_localization_evidence_kg(config: LocalizationKgBuildConfig) -> dict:
    loader_config = Defects4CLoadConfig(
        dataset=config.dataset,
        metadata_dir=config.metadata_dir,
        defects4c_root=config.defects4c_root,
        bug_id_filter=config.bug_id_filter,
        exclude_fixed_fail_tests=config.exclude_fixed_fail_tests,
    )
    bugs = load_defects4c_bugs(loader_config)
    defects4c_root = config.defects4c_root or default_defects4c_root()
    kg = {
        "schema_version": 1,
        "dataset": config.dataset,
        "bugs": {},
        "tests": {},
        "failures": {},
        "functions": {},
        "files": {},
        "edges": [],
        "term_index": {},
        "bug_function_stats": {},
    }

    for bug in bugs:
        metadata = {}
        try:
            with open(bug.get("metadata_path", ""), "r", encoding="utf-8") as f:
                metadata = json.load(f)
        except Exception:
            metadata = {}
        bug_id = bug["bug_id"]
        failing_tests = [test for test in bug.get("tests", []) if _outcome(test.get("outcome")) in FAIL_OUTCOMES]
        bootstrap = _build_case_bootstrap_from_bug(bug, metadata)
        function_ids = sorted({function_id for test in bug.get("tests", []) for function_id in _covered_functions(test)})
        kg["term_index"][bug_id] = {}
        kg["bug_function_stats"][bug_id] = {}
        kg["bugs"][bug_id] = {
            "bug_id": bug_id,
            "metadata_bug_id": bug.get("metadata_bug_id", ""),
            "dataset": bug.get("dataset", config.dataset),
            "project": bug.get("project", metadata.get("project", "")),
            "language": metadata.get("language", ""),
            "type_name": metadata.get("type_name", ""),
            "metadata_path": bug.get("metadata_path", ""),
            "source_file": bug.get("source_file", ""),
            "source_basename": bug.get("source_basename", ""),
            "ground_truth": bug.get("ground_truth", []), # we use it for evaluation only, not for localization
            "failure_terms": _failure_terms_from_tests(failing_tests),
            "bootstrap": bootstrap,
            "function_ids": function_ids,
            "raw_tests": bug.get("tests", []),
        }
        bug_node = _node_id("bug", bug_id)

        for test in bug.get("tests", []):
            test_id = str(test.get("test_id") or "")
            test_key = _node_id("test", bug_id, test_id)
            line_cov = collect_line_coverage(test)
            kg["tests"][test_key] = {
                "bug_id": bug_id,
                "test_id": test_id,
                "outcome": test.get("outcome", ""),
                "outcome_fixed": test.get("outcome_fixed", ""),
                "covered_function_count": len(_covered_functions(test)),
                "line_coverage": line_cov,
            }
            _add_edge(kg["edges"], bug_node, "HAS_TEST", test_key)
            if _outcome(test.get("outcome")) in FAIL_OUTCOMES:
                failure_id = _node_id("failure", bug_id, test_id)
                failure = _failure_dict(test)
                kg["failures"][failure_id] = {
                    "bug_id": bug_id,
                    "test_id": test_id,
                    "failure_type": failure.get("type", ""),
                    "expected": failure.get("expected_value", ""),
                    "actual": failure.get("actual_value", ""),
                    "assertion_location": failure.get("assertion_location", ""),
                    "output_summary": (failure.get("signal_lines") or [])[:8],
                }
                _add_edge(kg["edges"], bug_node, "HAS_FAILURE", failure_id)
            for function_id in _covered_functions(test):
                function_key = _node_id("function", bug_id, function_id)
                line_keys = _line_keys_for_function(test, function_id)
                _add_edge(
                    kg["edges"],
                    test_key,
                    "COVERS_FUNCTION",
                    function_key,
                    {
                        "outcome": test.get("outcome", ""),
                        "executed_line_count": len(line_keys),
                    },
                )
                if line_keys:
                    _add_edge(
                        kg["edges"],
                        test_key,
                        "EXECUTES_LINES",
                        function_key,
                        {"line_keys": line_keys[:100], "line_count": len(line_keys)},
                    )

        for function_id in function_ids:
            file_part, name = _split_function_key(function_id)
            function_key = _node_id("function", bug_id, function_id)
            file_key = _node_id("file", bug_id, file_part)
            function_terms = set(_tokenize(function_id))
            function_terms.update(
                _code_terms_for_function(
                    bug,
                    function_id,
                    metadata,
                    defects4c_root,
                    config.max_code_terms_per_function,
                )
            )
            terms = sorted(function_terms)
            kg["functions"][function_key] = {
                "bug_id": bug_id,
                "function_id": function_id,
                "file": file_part,
                "name": name,
                "terms": terms,
            }
            kg["files"].setdefault(file_key, {"bug_id": bug_id, "file": file_part})
            _add_edge(kg["edges"], function_key, "IN_FILE", file_key)
            for term in terms:
                kg["term_index"][bug_id].setdefault(term, [])
                if function_id not in kg["term_index"][bug_id][term]:
                    kg["term_index"][bug_id][term].append(function_id)
                _add_edge(kg["edges"], function_key, "HAS_TERM", f"term:{term}")
            kg["bug_function_stats"][bug_id][function_id] = _function_stats_for_bug(bug, function_id)

        _build_dependency_edges_for_bug(
            kg,
            bug,
            metadata,
            defects4c_root,
            config.dependency_scan_mode,
        )

    output_file = config.kg_file or default_kg_file(config.dataset)
    config.kg_file = output_file
    _write_json(output_file, kg)
    return kg


def _function_id_matches(candidate: str, target: object) -> bool:
    candidate = str(candidate or "")
    target_text = str(target or "")
    return bool(candidate and target_text and (candidate == target_text or candidate.endswith(target_text) or target_text.endswith(candidate)))


def _topk_metric_summary(results: Dict[str, dict]) -> Dict[int, dict]:
    ranks = [
        (entry.get("evaluation_only") or {}).get("hit_rank")
        for entry in results.values()
        if (entry.get("evaluation_only") or {}).get("ground_truth")
    ]
    metrics = {}
    for k in EVAL_TOP_KS:
        hits = sum(1 for rank in ranks if rank is not None and rank <= k)
        total = len(ranks)
        metrics[k] = {"hits": hits, "total": total, "accuracy": (hits / total) if total else 0.0}
    return metrics


class EvidenceKgToolbox:
    def __init__(self, kg: dict, config: LocalizationKgExploreConfig):
        self.kg = kg
        self.config = config
        self.dependency_index = self._build_dependency_index()

    def _build_dependency_index(self) -> dict:
        index = {"calls": {}, "called_by": {}}
        for edge in self.kg.get("edges", []):
            relation = edge.get("relation")
            if relation == "CALLS":
                source = edge.get("source")
                target = edge.get("target")
                index["calls"].setdefault(source, set()).add(target)
            elif relation == "CALLED_BY":
                source = edge.get("source")
                target = edge.get("target")
                index["called_by"].setdefault(source, set()).add(target)
        return index

    def bug_record(self, bug_id: str) -> dict:
        return self.kg.get("bugs", {}).get(bug_id, {})

    def bug(self, bug_id: str) -> dict:
        return _bug_from_record(self.bug_record(bug_id))

    def get_case_bootstrap(self, bug_id: str) -> dict:
        return {
            "tool": "get_case_bootstrap",
            "bug_id": bug_id,
            "bootstrap": self.bug_record(bug_id).get("bootstrap", {}),
            "evidence_items": [{"type": "case_bootstrap", "value": "loaded"}],
        }

    def search_functions_by_terms(self, bug_id: str, terms: Sequence[object], limit: int = 20) -> dict:
        normalized_terms = sorted(dict.fromkeys(token for term in terms for token in _tokenize(term)))
        term_index = self.kg.get("term_index", {}).get(bug_id, {})
        scores: Dict[str, float] = {}
        matched_terms: Dict[str, List[str]] = {}
        for term in normalized_terms:
            for function_id in term_index.get(term, []):
                scores[function_id] = scores.get(function_id, 0.0) + 1.0
                matched_terms.setdefault(function_id, []).append(term)
        rows = []
        for function_id, score in scores.items():
            rows.append(
                {
                    "function_id": function_id,
                    "score": round(score / max(1, len(normalized_terms)), 6),
                    "matched_terms": sorted(dict.fromkeys(matched_terms.get(function_id, []))),
                }
            )
        rows.sort(key=lambda item: (-item["score"], item["function_id"]))
        rows = rows[: max(1, int(limit))]
        return {
            "tool": "search_functions_by_terms",
            "intent": "semantic_relevance",
            "terms": normalized_terms,
            "functions": rows,
            "evidence_items": [
                {"type": "semantic_match", "function_id": row["function_id"], "terms": row["matched_terms"]}
                for row in rows
            ],
        }

    def get_failing_execution_path(self, bug_id: str, test_id: str = "", limit: int = 30) -> dict:
        bug = self.bug(bug_id)
        failing = [test for test in bug.get("tests", []) if _outcome(test.get("outcome")) in FAIL_OUTCOMES]
        selected = None
        if test_id:
            selected = next((test for test in failing if str(test.get("test_id") or "") == test_id), None)
        selected = selected or (failing[0] if failing else None)
        if not selected:
            return {"tool": "get_failing_execution_path", "intent": "execution_path", "functions": [], "evidence_items": []}
        rows = []
        for function_id in _covered_functions(selected):
            rows.append(
                {
                    "function_id": function_id,
                    "test_id": selected.get("test_id", ""),
                    "executed_line_count": len(_line_keys_for_function(selected, function_id)),
                }
            )
        rows.sort(key=lambda item: (-item["executed_line_count"], item["function_id"]))
        rows = rows[: max(1, int(limit))]
        return {
            "tool": "get_failing_execution_path",
            "intent": "execution_path",
            "test_id": selected.get("test_id", ""),
            "functions": rows,
            "line_coverage": collect_line_coverage(selected),
            "evidence_items": [
                {
                    "type": "failing_execution",
                    "function_id": row["function_id"],
                    "test_id": row["test_id"],
                    "executed_line_count": row["executed_line_count"],
                }
                for row in rows
            ],
        }

    def find_fail_pass_contrast(self, bug_id: str, scope: object = "all", limit: int = 30) -> dict:
        stats = self.kg.get("bug_function_stats", {}).get(bug_id, {})
        allowed = None
        if isinstance(scope, list):
            allowed = {str(item) for item in scope}
        elif isinstance(scope, str) and scope not in {"", "all"}:
            allowed = {
                function_id
                for function_id in stats
                if scope in function_id or scope in _split_function_key(function_id)[0]
            }
        rows = []
        for function_id, item in stats.items():
            if allowed is not None and function_id not in allowed:
                continue
            if int(item.get("failing_count", 0)) <= 0:
                continue
            rows.append(
                {
                    "function_id": function_id,
                    "contrast": float(item.get("contrast", 0.0)),
                    "failing_count": item.get("failing_count", 0),
                    "passing_count": item.get("passing_count", 0),
                    "total_failing": item.get("total_failing", 0),
                    "total_passing": item.get("total_passing", 0),
                }
            )
        rows.sort(key=lambda item: (-item["contrast"], item["passing_count"], item["function_id"]))
        rows = rows[: max(1, int(limit))]
        return {
            "tool": "find_fail_pass_contrast",
            "intent": "fail_pass_contrast",
            "scope": scope,
            "functions": rows,
            "evidence_items": [
                {
                    "type": "fail_pass_contrast",
                    "function_id": row["function_id"],
                    "contrast": row["contrast"],
                    "failing_count": row["failing_count"],
                    "passing_count": row["passing_count"],
                }
                for row in rows
            ],
        }

    def compare_fail_pass_coverage(self, bug_id: str, function_id: str) -> dict:
        bug = self.bug(bug_id)
        comparison = compare_fail_pass_coverage(function_id, bug.get("tests", []))
        stats = self.kg.get("bug_function_stats", {}).get(bug_id, {}).get(function_id, {})
        return {
            "tool": "compare_fail_pass_coverage",
            "intent": "fail_pass_contrast",
            "function_id": function_id,
            "comparison": comparison,
            "functions": [{"function_id": function_id, "contrast": stats.get("contrast", 0.0)}],
            "evidence_items": [
                {"type": "fail_coverage", "function_id": function_id, "value": comparison.get("failing_count", 0)},
                {"type": "pass_coverage", "function_id": function_id, "value": comparison.get("passing_count", 0)},
                {"type": "fail_pass_contrast", "function_id": function_id, "contrast": stats.get("contrast", 0.0)},
            ],
        }

    def expand_function_dependencies(self, bug_id: str, function_id: str, direction: str = "both", depth: int = 1, limit: int = 20) -> dict:
        start = _node_id("function", bug_id, function_id)
        directions = ["calls", "called_by"] if direction == "both" else [direction]
        seen = {start}
        frontier = {start}
        functions = []
        for _ in range(max(1, int(depth))):
            next_frontier = set()
            for node in frontier:
                for dir_name in directions:
                    for target in self.dependency_index.get(dir_name, {}).get(node, set()):
                        if target in seen:
                            continue
                        seen.add(target)
                        next_frontier.add(target)
                        target_function = target.split("||", 1)[1] if "||" in target else target
                        functions.append({"function_id": target_function, "relation": dir_name})
                        if len(functions) >= max(1, int(limit)):
                            break
                    if len(functions) >= max(1, int(limit)):
                        break
                if len(functions) >= max(1, int(limit)):
                    break
            frontier = next_frontier
            if not frontier or len(functions) >= max(1, int(limit)):
                break
        return {
            "tool": "expand_function_dependencies",
            "intent": "dependency_expansion",
            "function_id": function_id,
            "direction": direction,
            "depth": depth,
            "functions": functions,
            "evidence_items": [
                {"type": "dependency_neighbor", "function_id": item["function_id"], "source": function_id, "relation": item["relation"]}
                for item in functions
            ],
        }

    def get_function_slice(self, bug_id: str, function_id: str, test_id: str = "", mode: str = "mixed") -> dict:
        record = self.bug_record(bug_id)
        bug = self.bug(bug_id)
        result = get_candidate_slice(
            bug,
            function_id,
            mode=mode,
            max_lines=self.config.max_code_lines,
            context_lines=self.config.context_lines,
            test_id=test_id,
            defects4c_root=default_defects4c_root(),
        )
        code = (result.get("code") or {}) if isinstance(result, dict) else {}
        features = _code_behavior_features(code.get("lines", []))
        return {
            "tool": "get_function_slice",
            "intent": "execution_path",
            "function_id": function_id,
            "available": bool(result.get("available")),
            "slice": result,
            "functions": [{"function_id": function_id, "code_features": features}],
            "evidence_items": [
                {"type": "code_slice", "function_id": function_id, "available": bool(result.get("available")), "features": features}
            ],
            "metadata_path": record.get("metadata_path", ""),
        }

    def get_function_code(self, bug_id: str, function_id: str, mode: str = "executed_lines") -> dict:
        bug = self.bug(bug_id)
        code_mode = mode if mode in CODE_MODES else self.config.code_mode
        code = get_function_code(
            bug,
            function_id,
            mode=code_mode,
            max_lines=self.config.max_code_lines,
            context_lines=self.config.context_lines,
            defects4c_root=default_defects4c_root(),
        )
        features = _code_behavior_features(code.get("lines", []))
        return {
            "tool": "get_function_code",
            "intent": "execution_path",
            "function_id": function_id,
            "available": bool(code.get("available")),
            "code": code,
            "functions": [{"function_id": function_id, "code_features": features}],
            "evidence_items": [
                {"type": "code_view", "function_id": function_id, "available": bool(code.get("available")), "features": features}
            ],
        }

    def call_tool(self, bug_id: str, action: dict) -> dict:
        tool = str(action.get("tool") or "")
        args = action.get("args") if isinstance(action.get("args"), dict) else {}
        if tool == "get_case_bootstrap":
            return self.get_case_bootstrap(bug_id)
        if tool == "search_functions_by_terms":
            return self.search_functions_by_terms(bug_id, args.get("terms", []), int(args.get("limit", 20)))
        if tool == "get_failing_execution_path":
            return self.get_failing_execution_path(bug_id, str(args.get("test_id") or ""), int(args.get("limit", 30)))
        if tool == "find_fail_pass_contrast":
            return self.find_fail_pass_contrast(bug_id, args.get("scope", "all"), int(args.get("limit", 30)))
        if tool == "compare_fail_pass_coverage":
            return self.compare_fail_pass_coverage(bug_id, str(args.get("function_id") or ""))
        if tool == "expand_function_dependencies":
            return self.expand_function_dependencies(
                bug_id,
                str(args.get("function_id") or ""),
                str(args.get("direction") or "both"),
                int(args.get("depth", 1)),
                int(args.get("limit", 20)),
            )
        if tool == "get_function_slice":
            return self.get_function_slice(bug_id, str(args.get("function_id") or ""), str(args.get("test_id") or ""), str(args.get("mode") or "mixed"))
        if tool == "get_function_code":
            return self.get_function_code(bug_id, str(args.get("function_id") or ""), str(args.get("mode") or self.config.code_mode))
        if tool == "submit_localization":
            return {
                "tool": "submit_localization",
                "intent": "submit",
                "top_locations": args.get("top_locations", []),
                "evidence_items": [{"type": "explicit_submit", "value": True}],
            }
        return {"tool": tool, "error": f"unknown tool {tool}", "evidence_items": []}


def _empty_belief_state() -> dict:
    return {
        "candidates": {},
        "tool_history": [],
        "stable_topk_rounds": 0,
        "last_topk": [],
        "low_eig_rounds": 0,
        "tool_calls": 0,
    }


def _ensure_candidate(state: dict, function_id: str) -> dict:
    candidates = state.setdefault("candidates", {})
    if function_id not in candidates:
        candidates[function_id] = {
            "function_id": function_id,
            "belief": 0.0,
            "uncertainty": 1.0,
            "signals": {},
            "penalty": round(_generic_function_penalty(function_id), 6),
            "evidence": [],
            "checked_intents": {},
        }
    return candidates[function_id]


def _recompute_candidate(candidate: dict) -> None:
    score = sum(float(value) for value in candidate.get("signals", {}).values()) - float(candidate.get("penalty", 0.0))
    belief = max(0.0, min(0.99, score))
    candidate["belief"] = round(belief, 6)
    candidate["uncertainty"] = round(max(0.01, 1.0 - belief), 6)


def _add_signal(candidate: dict, signal: str, value: float) -> bool:
    signals = candidate.setdefault("signals", {})
    old_value = float(signals.get(signal, 0.0))
    new_value = max(old_value, value)
    signals[signal] = round(new_value, 6)
    _recompute_candidate(candidate)
    return new_value > old_value


def _append_evidence(candidate: dict, evidence: dict) -> None:
    compact = {key: value for key, value in evidence.items() if key != "function_id"}
    if compact not in candidate.setdefault("evidence", []):
        candidate["evidence"].append(compact)
    candidate["evidence"] = candidate["evidence"][-12:]


def _update_belief_from_response(state: dict, response: dict) -> Tuple[int, int]:
    new_candidates = 0
    new_evidence = 0
    intent = str(response.get("intent") or "")
    for evidence in response.get("evidence_items", []):
        if not isinstance(evidence, dict):
            continue
        function_id = str(evidence.get("function_id") or "")
        if not function_id:
            continue
        existed = function_id in state.get("candidates", {})
        candidate = _ensure_candidate(state, function_id)
        if not existed:
            new_candidates += 1
        if intent in INTENTS:
            candidate.setdefault("checked_intents", {})[intent] = True
        ev_type = str(evidence.get("type") or "")
        changed = False
        if ev_type == "semantic_match":
            terms = evidence.get("terms") if isinstance(evidence.get("terms"), list) else []
            changed = _add_signal(candidate, "semantic_relevance", min(0.28, 0.10 + 0.04 * len(terms)))
        elif ev_type == "failing_execution":
            line_count = int(evidence.get("executed_line_count") or 0)
            changed = _add_signal(candidate, "execution_path", 0.18 + min(0.12, line_count / 100.0))
        elif ev_type == "fail_pass_contrast":
            contrast = float(evidence.get("contrast") or 0.0)
            changed = _add_signal(candidate, "fail_pass_contrast", 0.12 + 0.28 * contrast)
        elif ev_type == "dependency_neighbor":
            changed = _add_signal(candidate, "dependency_expansion", 0.10)
        elif ev_type in {"code_slice", "code_view"}:
            candidate.setdefault("checked_intents", {})["code_slice"] = True
            features = evidence.get("features") if isinstance(evidence.get("features"), dict) else {}
            markers = features.get("suspicious_logic_markers") if isinstance(features.get("suspicious_logic_markers"), list) else []
            value = 0.08 + min(0.20, 0.04 * len(markers))
            if features.get("is_thin_accessor") or features.get("is_wrapper"):
                candidate["penalty"] = round(float(candidate.get("penalty", 0.0)) + 0.08, 6)
            changed = _add_signal(candidate, "code_logic", value)
        elif ev_type in {"fail_coverage", "pass_coverage"}:
            candidate.setdefault("checked_intents", {})["coverage_compared"] = True
            changed = True
        if changed:
            new_evidence += 1
        _append_evidence(candidate, evidence)
    return new_candidates, new_evidence


def _ranked_candidates(state: dict, limit: int = 30) -> List[dict]:
    rows = list(state.get("candidates", {}).values())
    rows.sort(key=lambda item: (-float(item.get("belief", 0.0)), float(item.get("uncertainty", 1.0)), item.get("function_id", "")))
    return rows[:limit]


def _failure_terms_for_bug(kg: dict, bug_id: str) -> List[str]:
    return kg.get("bugs", {}).get(bug_id, {}).get("failure_terms", [])[:12]


def _tool_history(state: dict) -> List[dict]:
    return [item for item in state.get("tool_history", []) if isinstance(item, dict)]


def _tool_count(state: dict, tool: str) -> int:
    return sum(1 for item in _tool_history(state) if item.get("tool") == tool)


def _intent_count(state: dict, intent: str) -> int:
    return sum(1 for item in _tool_history(state) if item.get("intent") == intent)


def _searched_terms(state: dict) -> set:
    terms = set()
    for item in _tool_history(state):
        if item.get("tool") != "search_functions_by_terms":
            continue
        args = item.get("args") if isinstance(item.get("args"), dict) else {}
        for term in args.get("terms", []):
            terms.update(_tokenize(term))
    return terms


def _semantic_action(kg: dict, bug_id: str, why: str = "start from failure/test vocabulary without preloaded candidates") -> dict:
    return {
        "intent": "semantic_relevance",
        "tool": "search_functions_by_terms",
        "args": {"terms": _failure_terms_for_bug(kg, bug_id), "limit": 20},
        "why": why,
    }


def _execution_path_action() -> dict:
    return {
        "intent": "execution_path",
        "tool": "get_failing_execution_path",
        "args": {"limit": 30},
        "why": "discover functions actually executed by the failing test",
    }


def _global_contrast_action() -> dict:
    return {
        "intent": "fail_pass_contrast",
        "tool": "find_fail_pass_contrast",
        "args": {"scope": "all", "limit": 30},
        "why": "separate failing-specific functions from broadly-covered helpers",
    }


def _candidate_needing_flag(state: dict, flag: str, limit: int = 8) -> Optional[str]:
    for candidate in _ranked_candidates(state, limit):
        function_id = str(candidate.get("function_id") or "")
        if function_id and not candidate.get("checked_intents", {}).get(flag):
            return function_id
    return None


def _compare_candidate_action(state: dict) -> Optional[dict]:
    function_id = _candidate_needing_flag(state, "coverage_compared", limit=6)
    if not function_id:
        return None
    return {
        "intent": "fail_pass_contrast",
        "tool": "compare_fail_pass_coverage",
        "args": {"function_id": function_id},
        "why": "validate fail/pass evidence for a high-belief candidate",
    }


def _dependency_action(state: dict) -> Optional[dict]:
    function_id = _candidate_needing_flag(state, "dependency_expansion", limit=6)
    if not function_id:
        return None
    return {
        "intent": "dependency_expansion",
        "tool": "expand_function_dependencies",
        "args": {"function_id": function_id, "direction": "both", "depth": 1, "limit": 20},
        "why": "inspect dependency neighbors around a high-belief candidate",
    }


def _slice_action(state: dict) -> Optional[dict]:
    function_id = _candidate_needing_flag(state, "code_slice", limit=6)
    if not function_id:
        return None
    return {
        "intent": "execution_path",
        "tool": "get_function_slice",
        "args": {"function_id": function_id, "mode": "mixed"},
        "why": "inspect executed code slice for behavior evidence",
    }


def _mandatory_phase_action(kg: dict, bug_id: str, state: dict) -> Optional[dict]:
    if _tool_count(state, "search_functions_by_terms") == 0:
        action = _semantic_action(kg, bug_id)
        action["phase"] = "phase_1_bootstrap_understanding"
        return action
    if _tool_count(state, "get_failing_execution_path") == 0:
        action = _execution_path_action()
        action["phase"] = "phase_1_bootstrap_understanding"
        return action
    if _tool_count(state, "find_fail_pass_contrast") == 0:
        action = _global_contrast_action()
        action["phase"] = "phase_2_discrimination"
        return action
    if _tool_count(state, "compare_fail_pass_coverage") < 2:
        action = _compare_candidate_action(state)
        if action:
            action["phase"] = "phase_2_discrimination"
            return action
    if _tool_count(state, "expand_function_dependencies") == 0:
        action = _dependency_action(state)
        if action:
            action["phase"] = "phase_3_causal_expansion"
            return action
    if _tool_count(state, "get_function_slice") == 0:
        action = _slice_action(state)
        if action:
            action["phase"] = "phase_3_causal_expansion"
            return action
    return None


def _adaptive_action(kg: dict, bug_id: str, state: dict) -> dict:
    action = _compare_candidate_action(state) or _dependency_action(state) or _slice_action(state)
    if action:
        action["phase"] = "phase_4_adaptive_decision"
        return action
    if _tool_count(state, "search_functions_by_terms") < 2:
        action = _semantic_action(kg, bug_id, why="one extra semantic query is allowed after required evidence is collected")
        action["phase"] = "phase_4_adaptive_decision"
        return action
    action = _global_contrast_action()
    action["phase"] = "phase_4_adaptive_decision"
    action["why"] = "fallback exploration after known candidates were checked"
    return action


def _scripted_action(kg: dict, bug_id: str, state: dict, step: int) -> dict:
    action = _mandatory_phase_action(kg, bug_id, state) or _adaptive_action(kg, bug_id, state)
    action.setdefault("phase", "phase_4_adaptive_decision")
    return action


def _expected_information_gain(action: dict, state: dict) -> float:
    tool = str(action.get("tool") or "")
    intent = str(action.get("intent") or "")
    args = action.get("args") if isinstance(action.get("args"), dict) else {}
    score = 0.0
    if intent in INTENTS:
        known = _ranked_candidates(state, 10)
        missing = [item for item in known if not item.get("checked_intents", {}).get(intent)]
        score += 0.20 if missing else 0.05
    if tool in {"search_functions_by_terms", "get_failing_execution_path", "find_fail_pass_contrast"}:
        score += 0.35
    if tool in {"compare_fail_pass_coverage", "expand_function_dependencies", "get_function_slice", "get_function_code"}:
        function_id = str(args.get("function_id") or "")
        candidate = state.get("candidates", {}).get(function_id)
        score += 0.20 if candidate else 0.05
        if candidate:
            score += 0.20 * float(candidate.get("uncertainty", 1.0))
    tool_repeats = _tool_count(state, tool)
    intent_repeats = _intent_count(state, intent)
    if tool_repeats:
        score -= min(0.35, 0.15 * tool_repeats)
    if intent_repeats:
        score -= min(0.30, 0.10 * intent_repeats)
    if tool == "search_functions_by_terms":
        terms = {token for term in args.get("terms", []) for token in _tokenize(term)}
        broad_count = len(terms & BROAD_SEARCH_TERMS)
        overlap = len(terms & _searched_terms(state))
        score -= min(0.25, 0.03 * broad_count)
        score -= min(0.30, 0.04 * overlap)
        if tool_repeats >= 1:
            score -= 0.20
        if tool_repeats >= 2:
            score -= 0.25
    if tool == "submit_localization":
        score -= 0.25
    return round(max(0.0, score), 6)


def _valid_action(action: dict) -> bool:
    return isinstance(action, dict) and action.get("tool") in AGENT_TOOLS and (action.get("intent") in INTENTS or action.get("tool") == "submit_localization")


def _build_planner_messages(bootstrap: dict, state: dict, step: int) -> List[dict]:
    prompt = {
        "task": "Choose exactly one KG tool call for function-level fault localization. Do not submit a patch.",
        "step": step,
        "phase_policy": {
            "phase_1": "bootstrap understanding: one semantic search and one failing execution path query",
            "phase_2": "discrimination: global fail/pass contrast and targeted compare coverage for top candidates",
            "phase_3": "causal expansion: dependency expansion and code slice for high-belief candidates",
            "phase_4": "decision: only then refine or submit",
            "important": "Do not repeat semantic search once execution, contrast, dependency, or code evidence is missing.",
        },
        "case_bootstrap": bootstrap,
        "belief_state_summary": {
            "candidates": _ranked_candidates(state, 10),
            "tool_calls": state.get("tool_calls", 0),
            "tool_counts": {tool: _tool_count(state, tool) for tool in AGENT_TOOLS},
        },
        "allowed_intents": sorted(INTENTS),
        "available_tools": AGENT_TOOLS,
        "required_output_schema": {
            "intent": "semantic_relevance",
            "tool": "search_functions_by_terms",
            "args": {"terms": ["term"], "limit": 20},
            "why": "short reason",
        },
    }
    system = (
        "You are a KG exploration planner for fault localization. "
        "You only choose tool calls; backend scoring and stopping are deterministic. "
        "Return strict JSON only."
    )
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(prompt, indent=2, ensure_ascii=False)},
    ]


def _choose_action(kg: dict, bug_id: str, state: dict, step: int, toolbox: EvidenceKgToolbox, config: LocalizationKgExploreConfig) -> Tuple[dict, Optional[dict], float]:
    mandatory_action = _mandatory_phase_action(kg, bug_id, state)
    if mandatory_action:
        eig = _expected_information_gain(mandatory_action, state)
        override = None
        if not config.dry_run:
            override = {
                "model_tool": "",
                "chosen_tool": mandatory_action["tool"],
                "reason": "required phase action; model planner not queried",
            }
        return mandatory_action, override, eig

    default_action = _adaptive_action(kg, bug_id, state)
    default_eig = _expected_information_gain(default_action, state)
    if config.dry_run:
        return default_action, None, default_eig
    bootstrap = toolbox.get_case_bootstrap(bug_id).get("bootstrap", {})
    model_action = {}
    try:
        response_text, _ = _call_openrouter_for_localization(_build_planner_messages(bootstrap, state, step), config)  # type: ignore[arg-type]
        model_action = _extract_json_object(response_text)
    except Exception as exc:
        override = {
            "model_tool": "",
            "chosen_tool": default_action["tool"],
            "reason": f"planner call failed: {exc}",
        }
        return default_action, override, default_eig
    if not _valid_action(model_action):
        override = {
            "model_tool": model_action.get("tool", ""),
            "chosen_tool": default_action["tool"],
            "reason": "invalid planner action",
        }
        return default_action, override, default_eig
    model_eig = _expected_information_gain(model_action, state)
    if model_eig + 0.05 < default_eig:
        override = {
            "model_tool": model_action.get("tool", ""),
            "chosen_tool": default_action["tool"],
            "reason": "higher expected information gain",
        }
        return default_action, override, default_eig
    return model_action, None, model_eig


def _update_stability(state: dict) -> None:
    topk = [item["function_id"] for item in _ranked_candidates(state, 5)]
    if topk and topk == state.get("last_topk"):
        state["stable_topk_rounds"] = int(state.get("stable_topk_rounds", 0)) + 1
    else:
        state["stable_topk_rounds"] = 0
    state["last_topk"] = topk


def _candidate_has_decision_evidence(candidate: dict) -> bool:
    checked = candidate.get("checked_intents", {}) if isinstance(candidate.get("checked_intents"), dict) else {}
    signals = candidate.get("signals", {}) if isinstance(candidate.get("signals"), dict) else {}
    has_execution = bool(checked.get("execution_path") or signals.get("execution_path"))
    has_contrast = bool(checked.get("fail_pass_contrast") or checked.get("coverage_compared") or signals.get("fail_pass_contrast"))
    has_causal = bool(checked.get("dependency_expansion") or checked.get("code_slice") or signals.get("dependency_expansion") or signals.get("code_logic"))
    return has_execution and has_contrast and has_causal


def _required_phases_complete(state: dict) -> bool:
    return (
        _tool_count(state, "search_functions_by_terms") >= 1
        and _tool_count(state, "get_failing_execution_path") >= 1
        and _tool_count(state, "find_fail_pass_contrast") >= 1
        and _tool_count(state, "compare_fail_pass_coverage") >= 2
        and _tool_count(state, "expand_function_dependencies") >= 1
        and _tool_count(state, "get_function_slice") >= 1
    )


def _stop_reason(state: dict, config: LocalizationKgExploreConfig, step: int, last_eig: float, explicit_submit: bool) -> str:
    if explicit_submit:
        return "explicit_submit"
    ranked = _ranked_candidates(state, 2)
    phases_complete = _required_phases_complete(state)
    if ranked and phases_complete:
        top1 = float(ranked[0].get("belief", 0.0))
        top2 = float(ranked[1].get("belief", 0.0)) if len(ranked) > 1 else 0.0
        if top1 >= config.stop_confidence and (top1 - top2) >= 0.15 and _candidate_has_decision_evidence(ranked[0]):
            return "confidence"
    if phases_complete and int(state.get("stable_topk_rounds", 0)) >= config.stop_stable_rounds:
        return "stability"
    history = state.get("tool_history", [])
    if phases_complete and len(history) >= 4 and all(item.get("new_candidates", 0) == 0 and item.get("new_evidence", 0) == 0 for item in history[-4:]):
        return "evidence_saturation"
    if last_eig < 0.05:
        state["low_eig_rounds"] = int(state.get("low_eig_rounds", 0)) + 1
    else:
        state["low_eig_rounds"] = 0
    if phases_complete and int(state.get("low_eig_rounds", 0)) >= 3:
        return "diminishing_returns"
    if step >= config.max_steps or int(state.get("tool_calls", 0)) >= config.max_tool_calls:
        return "budget"
    return ""


def _final_locations(state: dict, limit: int = 30) -> List[dict]:
    locations = []
    for rank, item in enumerate(_ranked_candidates(state, limit), start=1):
        locations.append(
            {
                "rank": rank,
                "function_id": item.get("function_id", ""),
                "belief": item.get("belief", 0.0),
                "uncertainty": item.get("uncertainty", 1.0),
                "evidence": item.get("evidence", [])[:8],
                "checked_intents": item.get("checked_intents", {}),
            }
        )
    return locations


def run_localization_kg_explorer(config: LocalizationKgExploreConfig) -> Dict[str, dict]:
    kg_file = config.kg_file or default_kg_file(config.dataset)
    config.kg_file = kg_file
    if not os.path.exists(kg_file):
        raise FileNotFoundError(f"Evidence KG not found: {kg_file}. Run --localization-agent-build-kg first.")
    kg = _load_json(kg_file)
    filters = _filter_bug_ids(config.bug_id_filter)
    toolbox = EvidenceKgToolbox(kg, config)
    results: Dict[str, dict] = {}

    for bug_id in sorted(kg.get("bugs", {})):
        record = kg["bugs"][bug_id]
        metadata_bug_id = record.get("metadata_bug_id", "")
        if filters and bug_id not in filters and metadata_bug_id not in filters:
            continue
        state = _empty_belief_state()
        bootstrap = toolbox.get_case_bootstrap(bug_id).get("bootstrap", {})
        stop_reason = "budget"
        explicit_submit = False
        for step in range(1, max(1, config.max_steps) + 1):
            action, override, eig = _choose_action(kg, bug_id, state, step, toolbox, config)
            response = toolbox.call_tool(bug_id, action)
            if response.get("tool") == "submit_localization":
                explicit_submit = True
            new_candidates, new_evidence = _update_belief_from_response(state, response)
            state["tool_calls"] = int(state.get("tool_calls", 0)) + 1
            trace_item = {
                "step": step,
                "phase": action.get("phase", ""),
                "intent": action.get("intent", ""),
                "tool": action.get("tool", ""),
                "args": action.get("args", {}),
                "why": action.get("why", ""),
                "expected_information_gain": eig,
                "new_candidates": new_candidates,
                "new_evidence": new_evidence,
                "planner_override": override,
                "response_summary": {
                    "tool": response.get("tool", ""),
                    "function_count": len(response.get("functions", [])) if isinstance(response.get("functions"), list) else 0,
                    "evidence_count": len(response.get("evidence_items", [])) if isinstance(response.get("evidence_items"), list) else 0,
                    "error": response.get("error", ""),
                },
            }
            state.setdefault("tool_history", []).append(trace_item)
            _update_stability(state)
            reason = _stop_reason(state, config, step, eig, explicit_submit)
            if reason:
                stop_reason = reason
                break
            if config.request_interval_seconds > 0 and not config.dry_run:
                time.sleep(config.request_interval_seconds)

        final_candidates = _final_locations(state, 30)
        ground_truth = record.get("ground_truth", [])
        hit_rank = _hit_rank_for_function_ids([item.get("function_id", "") for item in final_candidates], ground_truth)
        results[bug_id] = {
            "bug_id": bug_id,
            "case_bootstrap": bootstrap,
            "final_candidates": final_candidates,
            "tool_trace": state.get("tool_history", []),
            "stop_reason": stop_reason,
            "dry_run": config.dry_run,
            "evaluation_only": {
                "ground_truth": ground_truth,
                "hit_rank": hit_rank,
                "topk": _topk_flags(hit_rank),
            },
        }

    output_file = config.output_file or default_explore_output_file(config.dataset)
    config.output_file = output_file
    _write_json(output_file, results)
    return results


def print_localization_kg_summary(kg: dict, output_file: str = "") -> None:
    print("\nLocalization evidence KG summary:")
    print(f"  bugs: {len(kg.get('bugs', {}))}")
    print(f"  tests: {len(kg.get('tests', {}))}")
    print(f"  failures: {len(kg.get('failures', {}))}")
    print(f"  functions: {len(kg.get('functions', {}))}")
    print(f"  files: {len(kg.get('files', {}))}")
    print(f"  edges: {len(kg.get('edges', []))}")
    if output_file:
        print(f"  output: {output_file}")


def print_localization_explore_summary(results: Dict[str, dict], output_file: str = "") -> None:
    print("\nKG-exploration localization summary:")
    print(f"  bugs: {len(results)}")
    for bug_id, entry in sorted(results.items()):
        top = entry.get("final_candidates", [{}])[0].get("function_id", "") if entry.get("final_candidates") else ""
        hit_rank = (entry.get("evaluation_only") or {}).get("hit_rank")
        suffix = f" hit_rank={hit_rank}" if hit_rank is not None else ""
        print(f"  {bug_id}: stop={entry.get('stop_reason', '')} top={top}{suffix}")
    metrics = _topk_metric_summary(results)
    if metrics:
        print("  KG-explore eval:")
        for k in EVAL_TOP_KS:
            item = metrics[k]
            print(f"    Top@{k}: {item['hits']}/{item['total']} = {item['accuracy'] * 100:.1f}%")
    if output_file:
        print(f"  output: {output_file}")


def add_localization_kg_agent_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--localization-agent-build-kg", action="store_true", help="Build JSON Evidence KG for KG-exploration localization.")
    parser.add_argument("--localization-agent-explore", action="store_true", help="Run KG-exploration localization agent without preloaded top candidates.")
    parser.add_argument("--loc-agent-kg-file", default="", help="Evidence KG JSON path.")
    parser.add_argument("--loc-agent-explore-output-file", default="", help="KG exploration result JSON path.")
    parser.add_argument("--loc-agent-max-steps", type=int, default=12, help="Maximum exploration steps per bug.")
    parser.add_argument("--loc-agent-max-tool-calls", type=int, default=24, help="Maximum KG tool calls per bug.")
    parser.add_argument("--loc-agent-stop-confidence", type=float, default=0.75, help="Belief threshold for confidence stopping.")
    parser.add_argument("--loc-agent-stop-stable-rounds", type=int, default=3, help="Stable top-k rounds before stopping.")
    parser.add_argument("--loc-agent-model", default=DEFAULT_OPENROUTER_MODEL, help="OpenRouter model for KG planner.")
    parser.add_argument("--loc-agent-dry-run", action="store_true", help="Use scripted planner; do not call OpenRouter.")
    parser.add_argument("--loc-agent-kg-max-code-terms", type=int, default=60, help="Max executed code lines used for KG term extraction.")


def localization_kg_build_config_from_args(args: argparse.Namespace) -> LocalizationKgBuildConfig:
    return LocalizationKgBuildConfig(
        dataset=args.loc_agent_dataset,
        metadata_dir=args.loc_agent_metadata_dir,
        defects4c_root=args.loc_agent_defects4c_root,
        kg_file=args.loc_agent_kg_file,
        bug_id_filter=args.loc_agent_bug_id,
        exclude_fixed_fail_tests=not args.loc_agent_include_fixed_fail,
        max_code_terms_per_function=args.loc_agent_kg_max_code_terms,
    )


def localization_kg_explore_config_from_args(args: argparse.Namespace) -> LocalizationKgExploreConfig:
    return LocalizationKgExploreConfig(
        dataset=args.loc_agent_dataset,
        kg_file=args.loc_agent_kg_file,
        output_file=args.loc_agent_explore_output_file,
        bug_id_filter=args.loc_agent_bug_id,
        model=args.loc_agent_model,
        api_url=args.loc_agent_llm_api_url,
        api_key_env=args.loc_agent_llm_api_key_env,
        timeout_seconds=args.loc_agent_llm_timeout,
        max_tokens=args.loc_agent_llm_max_tokens,
        temperature=args.loc_agent_llm_temperature,
        max_steps=args.loc_agent_max_steps,
        max_tool_calls=args.loc_agent_max_tool_calls,
        stop_confidence=args.loc_agent_stop_confidence,
        stop_stable_rounds=args.loc_agent_stop_stable_rounds,
        dry_run=args.loc_agent_dry_run,
        request_interval_seconds=args.loc_agent_llm_request_interval,
        code_mode=args.loc_agent_code_mode,
        max_code_lines=args.loc_agent_max_code_lines,
        context_lines=args.loc_agent_context_lines,
    )
