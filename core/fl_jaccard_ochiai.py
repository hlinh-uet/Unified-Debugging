from __future__ import annotations

import argparse
import json
import math
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from data_loaders.defects4c_loader import (
    FAIL_OUTCOMES,
    PASS_OUTCOMES,
    Defects4CLoadConfig,
    load_defects4c_bugs,
)


TOPK_VALUES = (1, 3, 5, 10, 20, 30)


@dataclass
class JaccardOchiaiConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    selection: str = "threshold"
    threshold: float = 0.5
    top_k: int = 50
    exclude_fixed_fail_tests: bool = True


def _outcome(value: object) -> str:
    return str(value or "").strip().upper()


def _covered_functions(test: dict) -> List[str]:
    covered = test.get("covered_functions")
    if covered is None:
        covered = test.get("covered_methods", [])
    if not isinstance(covered, list):
        return []
    return [str(item) for item in covered if item]


def _coverage_set(test: dict) -> set:
    return set(_covered_functions(test))


def _sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def jaccard_similarity(left: set, right: set) -> float:
    if not left and not right:
        return 0.0
    intersection = len(left & right)
    union = len(left | right)
    return float(intersection) / float(union) if union else 0.0


def split_tests(test_data: Sequence[dict]) -> Tuple[List[dict], List[dict]]:
    failing = []
    passing = []
    for test in test_data:
        outcome = _outcome(test.get("outcome"))
        if outcome in FAIL_OUTCOMES:
            failing.append(test)
        elif outcome in PASS_OUTCOMES:
            passing.append(test)
    return failing, passing


def score_passing_tests_by_jaccard(
    failing_tests: Sequence[dict],
    passing_tests: Sequence[dict],
) -> List[dict]:
    failing_vectors = [
        (str(test.get("test_id") or f"fail_{index}"), _coverage_set(test))
        for index, test in enumerate(failing_tests)
    ]
    scored = []
    for index, test in enumerate(passing_tests):
        pass_vector = _coverage_set(test)
        best_score = 0.0
        best_fail_id = ""
        for fail_id, fail_vector in failing_vectors:
            score = jaccard_similarity(fail_vector, pass_vector)
            if score > best_score:
                best_score = score
                best_fail_id = fail_id
        scored.append(
            {
                "index": index,
                "test_id": str(test.get("test_id") or f"pass_{index}"),
                "score": best_score,
                "nearest_fail_test": best_fail_id,
                "covered_function_count": len(pass_vector),
            }
        )
    return sorted(scored, key=lambda item: (-item["score"], item["test_id"]))


def select_passing_tests(
    failing_tests: Sequence[dict],
    passing_tests: Sequence[dict],
    selection: str = "threshold",
    threshold: float = 0.5,
    top_k: int = 50,
) -> Tuple[List[dict], dict]:
    scored = score_passing_tests_by_jaccard(failing_tests, passing_tests)
    if selection == "topk":
        selected_scores = scored[: max(0, top_k)]
    else:
        selected_scores = [item for item in scored if item["score"] >= threshold]

    selected_indices = {item["index"] for item in selected_scores}
    selected_passes = [
        test
        for index, test in enumerate(passing_tests)
        if index in selected_indices
    ]
    all_scores = [item["score"] for item in scored]
    kept_scores = [item["score"] for item in selected_scores]
    stats = {
        "selection": selection,
        "threshold": threshold,
        "top_k": top_k,
        "original_failing_tests": len(failing_tests),
        "original_passing_tests": len(passing_tests),
        "selected_passing_tests": len(selected_passes),
        "reduction_ratio": (
            1.0 - (len(selected_passes) / len(passing_tests))
            if passing_tests
            else 0.0
        ),
        "max_jaccard": max(all_scores) if all_scores else 0.0,
        "avg_jaccard": (sum(all_scores) / len(all_scores)) if all_scores else 0.0,
        "min_selected_jaccard": min(kept_scores) if kept_scores else 0.0,
        "max_selected_jaccard": max(kept_scores) if kept_scores else 0.0,
        "selected_tests": selected_scores,
    }
    return selected_passes, stats


def calculate_ochiai(test_data: Sequence[dict]) -> Dict[str, float]:
    failing_tests, passing_tests = split_tests(test_data)
    total_failed = len(failing_tests)
    if total_failed == 0:
        return {}

    failed_by_function: Dict[str, int] = {}
    passed_by_function: Dict[str, int] = {}
    for test in failing_tests:
        for function in _coverage_set(test):
            failed_by_function[function] = failed_by_function.get(function, 0) + 1
    for test in passing_tests:
        for function in _coverage_set(test):
            passed_by_function[function] = passed_by_function.get(function, 0) + 1

    scores: Dict[str, float] = {}
    for function in set(failed_by_function) | set(passed_by_function):
        ef = failed_by_function.get(function, 0)
        if ef <= 0:
            scores[function] = 0.0
            continue
        ep = passed_by_function.get(function, 0)
        denominator = math.sqrt(total_failed * (ef + ep))
        scores[function] = float(ef) / denominator if denominator else 0.0
    return _sort_scores(scores)


def reduce_tests_and_rank(
    test_data: Sequence[dict],
    selection: str = "threshold",
    threshold: float = 0.5,
    top_k: int = 50,
) -> Tuple[Dict[str, float], dict]:
    failing_tests, passing_tests = split_tests(test_data)
    selected_passes, stats = select_passing_tests(
        failing_tests,
        passing_tests,
        selection=selection,
        threshold=threshold,
        top_k=top_k,
    )
    reduced_tests = list(failing_tests) + selected_passes
    scores = calculate_ochiai(reduced_tests)
    stats["reduced_test_count"] = len(reduced_tests)
    stats["scored_function_count"] = len(scores)
    return scores, stats


def _default_experiments_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "experiments"))


def _default_output_file(config: JaccardOchiaiConfig) -> str:
    experiments_dir = _default_experiments_dir()
    if str(config.dataset).lower() == "all" and not config.metadata_dir:
        return os.path.join(experiments_dir, "defects4c_jaccard_ochiai_function_results.json")
    return os.path.join(experiments_dir, config.dataset, "jaccard_ochiai_function_results.json")


def _resolve_config(config: JaccardOchiaiConfig) -> JaccardOchiaiConfig:
    config.selection = str(config.selection or "threshold").lower()
    if config.selection not in {"threshold", "topk"}:
        raise ValueError("Jaccard selection must be 'threshold' or 'topk'")
    if not config.output_file:
        config.output_file = _default_output_file(config)
    return config


def _rank_ground_truth(scores: Dict[str, float], ground_truth: Sequence[str]) -> Optional[int]:
    for rank, (key, _) in enumerate(
        sorted((scores or {}).items(), key=lambda item: (-item[1], item[0])),
        start=1,
    ):
        for gt in ground_truth:
            if key == gt or key.endswith(f":{gt}") or key.endswith(f"::{gt}"):
                return rank
    return None


def run_jaccard_ochiai_fault_localization(config: JaccardOchiaiConfig) -> Dict[str, dict]:
    config = _resolve_config(config)
    loader_config = Defects4CLoadConfig(
        dataset=config.dataset,
        metadata_dir=config.metadata_dir,
        defects4c_root=config.defects4c_root,
        bug_id_filter=config.bug_id_filter,
        exclude_fixed_fail_tests=config.exclude_fixed_fail_tests,
    )
    bugs = load_defects4c_bugs(loader_config)
    output: Dict[str, dict] = {}

    for bug in bugs:
        scores, reduction = reduce_tests_and_rank(
            bug.get("tests", []),
            selection=config.selection,
            threshold=config.threshold,
            top_k=config.top_k,
        )
        output[bug["bug_id"]] = {
            "dataset": bug.get("dataset", config.dataset),
            "formula": "ochiai",
            "preprocessing": "jaccard_test_suite_reduction",
            "scores": scores,
            "jaccard_ochiai_scores": scores,
            "ground_truth": bug.get("ground_truth", []),
            "metadata_path": bug.get("metadata_path", ""),
            "metadata_bug_id": bug.get("metadata_bug_id", ""),
            "project": bug.get("project", ""),
            "source_file": bug.get("source_file", ""),
            "reduction": reduction,
            "test_filter": bug.get("test_filter", {}),
        }

    os.makedirs(os.path.dirname(config.output_file), exist_ok=True)
    with open(config.output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def jaccard_ochiai_summary_file(output_file: str) -> str:
    base, ext = os.path.splitext(output_file)
    return f"{base}_summary{ext or '.json'}"


def summarize_jaccard_ochiai_results(results: Dict[str, dict]) -> Dict[str, object]:
    rows = []
    selected_pass_counts = []
    original_pass_counts = []
    for bug_id, entry in sorted(results.items()):
        reduction = entry.get("reduction") or {}
        rank = _rank_ground_truth(entry.get("jaccard_ochiai_scores", {}), entry.get("ground_truth", []))
        selected_pass_counts.append(int(reduction.get("selected_passing_tests") or 0))
        original_pass_counts.append(int(reduction.get("original_passing_tests") or 0))
        rows.append(
            {
                "bug_id": bug_id,
                "rank": rank,
                "ground_truth": entry.get("ground_truth", []),
                "original_passing_tests": reduction.get("original_passing_tests", 0),
                "selected_passing_tests": reduction.get("selected_passing_tests", 0),
                "max_jaccard": reduction.get("max_jaccard", 0.0),
                "avg_jaccard": reduction.get("avg_jaccard", 0.0),
                "scored_function_count": reduction.get("scored_function_count", 0),
            }
        )

    total = len(rows)
    topk = {}
    for k in TOPK_VALUES:
        count = sum(1 for row in rows if row["rank"] is not None and row["rank"] <= k)
        topk[f"top{k}"] = {
            "k": k,
            "count": count,
            "percent": (count / total * 100.0) if total else 0.0,
        }

    return {
        "total": total,
        "evaluated": sum(1 for row in rows if row["rank"] is not None),
        "topk": topk,
        "pass_tests": {
            "original_total": sum(original_pass_counts),
            "selected_total": sum(selected_pass_counts),
            "selected_avg": (sum(selected_pass_counts) / total) if total else 0.0,
        },
        "rows": rows,
    }


def print_jaccard_ochiai_summary(results: Dict[str, dict], output_file: str = "") -> None:
    summary = summarize_jaccard_ochiai_results(results)
    print("\nJaccard-reduced Ochiai function-level FL summary:")
    print(f"  bugs: {summary['total']} evaluated={summary['evaluated']}")
    for label in ("top1", "top3", "top5", "top10", "top20", "top30"):
        item = summary["topk"][label]
        print(f"  {label}: {item['count']}/{summary['total']} ({item['percent']:.2f}%)")
    pass_tests = summary["pass_tests"]
    print(
        "  pass tests: "
        f"selected {pass_tests['selected_total']}/{pass_tests['original_total']} "
        f"(avg {pass_tests['selected_avg']:.2f}/bug)"
    )
    if output_file:
        summary_file = jaccard_ochiai_summary_file(output_file)
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)
        print(f"  output: {output_file}")
        print(f"  summary: {summary_file}")


def add_jaccard_ochiai_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fl-jaccard-ochiai", action="store_true", help="Run Jaccard-reduced Ochiai FL for Defects4C.")
    parser.add_argument("--jaccard-dataset", default="fmt", help="Defects4C unified_debugging dataset, e.g. fmt, cjson, tcpdump, or all.")
    parser.add_argument("--jaccard-metadata-dir", default="", help="Directory containing Defects4C *_meta.json files.")
    parser.add_argument("--jaccard-defects4c-root", default="", help="Path to the defects4c repository.")
    parser.add_argument("--jaccard-output-file", default="", help="Output JSON path for Jaccard-Ochiai FL results.")
    parser.add_argument("--jaccard-bug-id", default="", help="Optional comma-separated bug ids to run.")
    parser.add_argument("--jaccard-selection", choices=("threshold", "topk"), default="threshold", help="Pass-test reduction strategy.")
    parser.add_argument("--jaccard-threshold", type=float, default=0.5, help="Keep pass tests with Jaccard >= threshold.")
    parser.add_argument("--jaccard-top-k", type=int, default=50, help="Keep top K most similar pass tests when selection=topk.")
    parser.add_argument("--jaccard-include-fixed-fail", action="store_true", help="Keep tests that also fail on the fixed version.")


def jaccard_ochiai_config_from_args(args: argparse.Namespace) -> JaccardOchiaiConfig:
    return JaccardOchiaiConfig(
        dataset=args.jaccard_dataset,
        metadata_dir=args.jaccard_metadata_dir,
        defects4c_root=args.jaccard_defects4c_root,
        output_file=args.jaccard_output_file,
        bug_id_filter=args.jaccard_bug_id,
        selection=args.jaccard_selection,
        threshold=args.jaccard_threshold,
        top_k=args.jaccard_top_k,
        exclude_fixed_fail_tests=not args.jaccard_include_fixed_fail,
    )
