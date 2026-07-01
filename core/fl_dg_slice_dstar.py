from __future__ import annotations

import argparse
import json
import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Sequence, Tuple

from data_loaders.defects4c_loader import (
    FAIL_OUTCOMES,
    PASS_OUTCOMES,
    Defects4CLoadConfig,
    load_defects4c_bugs,
)


@dataclass
class DgSliceDStarConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    star: int = 2
    exclude_fixed_fail_tests: bool = True


def _outcome(value: object) -> str:
    return str(value or "").strip().upper()


def _slice_features(test: dict) -> List[str]:
    llvm_slice = test.get("llvm_slice") or {}
    if not isinstance(llvm_slice, dict):
        return []
    outcome = _outcome(test.get("outcome"))
    if outcome in FAIL_OUTCOMES:
        features = llvm_slice.get("dynamic_slice_functions") or []
    elif outcome in PASS_OUTCOMES:
        features = llvm_slice.get("executed_functions") or []
    else:
        features = []
    if not isinstance(features, list):
        return []
    return [str(item) for item in features if item]


def _sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def spectrum_counts(test_data: Sequence[dict]) -> Tuple[int, int, Dict[str, int], Dict[str, int]]:
    total_passed = 0
    total_failed = 0
    passed_by_function: Dict[str, int] = {}
    failed_by_function: Dict[str, int] = {}

    for test in test_data:
        outcome = _outcome(test.get("outcome"))
        covered = set(_slice_features(test))
        if outcome in PASS_OUTCOMES:
            total_passed += 1
            for function in covered:
                passed_by_function[function] = passed_by_function.get(function, 0) + 1
        elif outcome in FAIL_OUTCOMES:
            total_failed += 1
            for function in covered:
                failed_by_function[function] = failed_by_function.get(function, 0) + 1

    return total_passed, total_failed, passed_by_function, failed_by_function


def calculate_dg_slice_dstar(test_data: Sequence[dict], star: int = 2) -> Dict[str, float]:
    if star < 1:
        raise ValueError("DStar exponent must be >= 1")
    total_passed, total_failed, passed_by_function, failed_by_function = spectrum_counts(test_data)
    if total_failed == 0:
        return {}

    all_functions = set(passed_by_function) | set(failed_by_function)
    denominator_zero_score = float((total_failed + 1) ** star)
    scores: Dict[str, float] = {}
    for function in all_functions:
        failed = failed_by_function.get(function, 0)
        if failed <= 0:
            scores[function] = 0.0
            continue
        passed = passed_by_function.get(function, 0)
        failed_not_covered = total_failed - failed
        denominator = passed + failed_not_covered
        scores[function] = denominator_zero_score if denominator == 0 else float(failed**star) / float(denominator)
    return _sort_scores(scores)


def _default_experiments_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "experiments"))


def _default_output_file(config: DgSliceDStarConfig) -> str:
    experiments_dir = _default_experiments_dir()
    dataset_dir = os.path.join(experiments_dir, config.dataset)
    return os.path.join(dataset_dir, "dg_slice_dstar_function_results.json")


def _resolve_config(config: DgSliceDStarConfig) -> DgSliceDStarConfig:
    if not config.output_file:
        config.output_file = _default_output_file(config)
    return config


def _rank_ground_truth(scores: Dict[str, float], ground_truth: Sequence[str]) -> Optional[int]:
    for rank, (key, _) in enumerate(sorted((scores or {}).items(), key=lambda item: (-item[1], item[0])), start=1):
        for gt in ground_truth:
            if key == gt or key.endswith(f":{gt}") or key.endswith(f"::{gt}"):
                return rank
    return None


def run_dg_slice_dstar_fault_localization(config: DgSliceDStarConfig) -> Dict[str, dict]:
    config = _resolve_config(config)
    bugs = load_defects4c_bugs(
        Defects4CLoadConfig(
            dataset=config.dataset,
            metadata_dir=config.metadata_dir,
            defects4c_root=config.defects4c_root,
            bug_id_filter=config.bug_id_filter,
            exclude_fixed_fail_tests=config.exclude_fixed_fail_tests,
        )
    )
    output: Dict[str, dict] = {}
    for bug in bugs:
        scores = calculate_dg_slice_dstar(bug.get("tests", []), star=config.star)
        total_passed, total_failed, _, _ = spectrum_counts(bug.get("tests", []))
        output[bug["bug_id"]] = {
            "dataset": bug.get("dataset", config.dataset),
            "formula": "dstar",
            "reranker": "llvm_dg_slice",
            "scores": scores,
            "dg_slice_dstar_scores": scores,
            "ground_truth": bug.get("ground_truth", []),
            "metadata_path": bug.get("metadata_path", ""),
            "metadata_bug_id": bug.get("metadata_bug_id", ""),
            "project": bug.get("project", ""),
            "source_file": bug.get("source_file", ""),
            "spectrum": {
                "total_passed": total_passed,
                "total_failed": total_failed,
                "covered_function_count": len(scores),
                "star": config.star,
                "failed_feature_field": "llvm_slice.dynamic_slice_functions",
                "passed_feature_field": "llvm_slice.executed_functions",
            },
            "test_filter": bug.get("test_filter", {}),
        }

    os.makedirs(os.path.dirname(config.output_file), exist_ok=True)
    with open(config.output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def dg_slice_dstar_summary_file(output_file: str) -> str:
    base, ext = os.path.splitext(output_file)
    return f"{base}_summary{ext or '.json'}"


def summarize_dg_slice_dstar_results(results: Dict[str, dict]) -> Dict[str, object]:
    rows = []
    for bug_id, entry in sorted(results.items()):
        rows.append(
            {
                "bug_id": bug_id,
                "rank": _rank_ground_truth(entry.get("dg_slice_dstar_scores", {}), entry.get("ground_truth", [])),
                "ground_truth": entry.get("ground_truth", []),
                "covered_function_count": (entry.get("spectrum") or {}).get("covered_function_count", 0),
            }
        )
    total = len(rows)
    topk = {}
    for k in (1, 3, 5, 10, 20, 30):
        count = sum(1 for row in rows if row["rank"] is not None and row["rank"] <= k)
        topk[f"top{k}"] = {"k": k, "count": count, "percent": (count / total * 100.0) if total else 0.0}
    return {
        "total": total,
        "evaluated": sum(1 for row in rows if row["rank"] is not None),
        "topk": topk,
        "rows": rows,
    }


def print_dg_slice_dstar_summary(results: Dict[str, dict], output_file: str = "") -> None:
    summary = summarize_dg_slice_dstar_results(results)
    print("\nDG-slice DStar function-level FL summary:")
    print(f"  bugs: {summary['total']} evaluated={summary['evaluated']}")
    for label in ("top1", "top3", "top5", "top10", "top20", "top30"):
        item = summary["topk"][label]
        print(f"  {label}: {item['count']}/{summary['total']} ({item['percent']:.2f}%)")
    if output_file:
        summary_file = dg_slice_dstar_summary_file(output_file)
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)
        print(f"  output: {output_file}")
        print(f"  summary: {summary_file}")


def add_dg_slice_dstar_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fl-dg-slice-dstar", action="store_true", help="Run Defects4C DStar using LLVM/DG slice evidence.")
    parser.add_argument("--dg-slice-dataset", default="fmt", help="Defects4C unified_debugging dataset.")
    parser.add_argument("--dg-slice-metadata-dir", default="", help="Directory containing Defects4C *_meta.json files.")
    parser.add_argument("--dg-slice-defects4c-root", default="", help="Path to the defects4c repository.")
    parser.add_argument("--dg-slice-output-file", default="", help="Output JSON path for DG-slice DStar results.")
    parser.add_argument("--dg-slice-bug-id", default="", help="Optional comma-separated bug ids to run.")
    parser.add_argument("--dg-slice-star", type=int, default=2, help="DStar exponent, commonly 2.")
    parser.add_argument("--dg-slice-include-fixed-fail", action="store_true", help="Keep tests that also fail on the fixed version.")


def dg_slice_dstar_config_from_args(args: argparse.Namespace) -> DgSliceDStarConfig:
    return DgSliceDStarConfig(
        dataset=args.dg_slice_dataset,
        metadata_dir=args.dg_slice_metadata_dir,
        defects4c_root=args.dg_slice_defects4c_root,
        output_file=args.dg_slice_output_file,
        bug_id_filter=args.dg_slice_bug_id,
        star=args.dg_slice_star,
        exclude_fixed_fail_tests=not args.dg_slice_include_fixed_fail,
    )
