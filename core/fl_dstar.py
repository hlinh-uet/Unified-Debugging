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
    summarize_loaded_bugs,
)


@dataclass
class DStarConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    star: int = 2
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


def _sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def spectrum_counts(test_data: Sequence[dict]) -> Tuple[int, int, Dict[str, int], Dict[str, int]]:
    total_passed = 0
    total_failed = 0
    passed_by_function: Dict[str, int] = {}
    failed_by_function: Dict[str, int] = {}

    for test in test_data:
        outcome = _outcome(test.get("outcome"))
        covered = set(_covered_functions(test))
        if outcome in PASS_OUTCOMES:
            total_passed += 1
            for function in covered:
                passed_by_function[function] = passed_by_function.get(function, 0) + 1
        elif outcome in FAIL_OUTCOMES:
            total_failed += 1
            for function in covered:
                failed_by_function[function] = failed_by_function.get(function, 0) + 1

    return total_passed, total_failed, passed_by_function, failed_by_function


def calculate_dstar(test_data: Sequence[dict], star: int = 2) -> Dict[str, float]:
    """
    Compute DStar suspiciousness for each covered function.

    DStar(e) = failed(e)^star / (passed(e) + failed(not e)).
    The usual star value is 2. If the denominator is zero, the function was
    covered by every failing test and no passing test; it receives a finite
    sentinel above any possible non-zero-denominator score for this bug.
    """
    if star < 1:
        raise ValueError("DStar exponent must be >= 1")

    total_passed, total_failed, passed_by_function, failed_by_function = spectrum_counts(test_data)
    if total_failed == 0:
        return {}

    scores: Dict[str, float] = {}
    all_functions = set(passed_by_function) | set(failed_by_function)
    denominator_zero_score = float((total_failed + 1) ** star)

    for function in all_functions:
        failed = failed_by_function.get(function, 0)
        if failed <= 0:
            scores[function] = 0.0
            continue

        passed = passed_by_function.get(function, 0)
        failed_not_covered = total_failed - failed
        denominator = passed + failed_not_covered
        if denominator == 0:
            score = denominator_zero_score
        else:
            score = float(failed**star) / float(denominator)
        scores[function] = score

    return _sort_scores(scores)


def _default_experiments_dir() -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "experiments"))


def _default_output_file(config: DStarConfig) -> str:
    experiments_dir = _default_experiments_dir()
    if str(config.dataset).lower() == "all" and not config.metadata_dir:
        return os.path.join(experiments_dir, "defects4c_dstar_function_results.json")
    dataset_dir = os.path.join(experiments_dir, config.dataset)
    return os.path.join(dataset_dir, "dstar_function_results.json")


def _resolve_config(config: DStarConfig) -> DStarConfig:
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


def run_dstar_fault_localization(config: DStarConfig) -> Dict[str, dict]:
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
        scores = calculate_dstar(bug.get("tests", []), star=config.star)
        total_passed, total_failed, _, _ = spectrum_counts(bug.get("tests", []))
        output[bug["bug_id"]] = {
            "dataset": bug.get("dataset", config.dataset),
            "formula": "dstar",
            "reranker": "none",
            "scores": scores,
            "dstar_scores": scores,
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
            },
            "test_filter": bug.get("test_filter", {}),
        }

    os.makedirs(os.path.dirname(config.output_file), exist_ok=True)
    with open(config.output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def dstar_summary_file(output_file: str) -> str:
    base, ext = os.path.splitext(output_file)
    suffix = ext or ".json"
    return f"{base}_summary{suffix}"


def summarize_dstar_results(results: Dict[str, dict]) -> Dict[str, object]:
    rows = []
    for bug_id, entry in sorted(results.items()):
        rank = _rank_ground_truth(entry.get("dstar_scores", {}), entry.get("ground_truth", []))
        rows.append(
            {
                "bug_id": bug_id,
                "rank": rank,
                "ground_truth": entry.get("ground_truth", []),
                "covered_function_count": (entry.get("spectrum") or {}).get("covered_function_count", 0),
            }
        )

    total = len(rows)
    topk = {}
    for k in (1, 3, 5, 10, 20, 30):
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
        "rows": rows,
    }


def print_dstar_summary(results: Dict[str, dict], output_file: str = "") -> None:
    summary = summarize_dstar_results(results)
    print("\nDStar function-level FL summary:")
    print(f"  bugs: {summary['total']} evaluated={summary['evaluated']}")
    for label in ("top1", "top3", "top5", "top10", "top20", "top30"):
        item = summary["topk"][label]
        print(f"  {label}: {item['count']}/{summary['total']} ({item['percent']:.2f}%)")
    if output_file:
        summary_file = dstar_summary_file(output_file)
        with open(summary_file, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=4)
        print(f"  output: {output_file}")
        print(f"  summary: {summary_file}")


def print_defects4c_load_summary(config: DStarConfig) -> None:
    loader_config = Defects4CLoadConfig(
        dataset=config.dataset,
        metadata_dir=config.metadata_dir,
        defects4c_root=config.defects4c_root,
        bug_id_filter=config.bug_id_filter,
        exclude_fixed_fail_tests=config.exclude_fixed_fail_tests,
    )
    bugs = load_defects4c_bugs(loader_config)
    summary = summarize_loaded_bugs(bugs)
    print("\nDefects4C metadata load summary:")
    for key, value in summary.items():
        print(f"  {key}: {value}")


def add_dstar_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--fl-dstar", action="store_true", help="Run Defects4C function-level FL with DStar.")
    parser.add_argument("--dstar-dataset", default="fmt", help="Defects4C unified_debugging dataset, e.g. fmt, cjson, tcpdump, or all.")
    parser.add_argument("--dstar-metadata-dir", default="", help="Directory containing Defects4C *_meta.json files.")
    parser.add_argument("--dstar-defects4c-root", default="", help="Path to the defects4c repository.")
    parser.add_argument("--dstar-output-file", default="", help="Output JSON path for DStar FL results.")
    parser.add_argument("--dstar-bug-id", default="", help="Optional comma-separated bug ids to run.")
    parser.add_argument("--dstar-star", type=int, default=2, help="DStar exponent, commonly 2.")
    parser.add_argument("--dstar-include-fixed-fail", action="store_true", help="Keep tests that also fail on the fixed version.")


def dstar_config_from_args(args: argparse.Namespace) -> DStarConfig:
    return DStarConfig(
        dataset=args.dstar_dataset,
        metadata_dir=args.dstar_metadata_dir,
        defects4c_root=args.dstar_defects4c_root,
        output_file=args.dstar_output_file,
        bug_id_filter=args.dstar_bug_id,
        star=args.dstar_star,
        exclude_fixed_fail_tests=not args.dstar_include_fixed_fail,
    )
