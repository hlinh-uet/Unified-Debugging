#!/usr/bin/env python
"""
Rerank FL scores with strict group-only APR validation feedback.

This script does not call APR, validation, or any LLM. It only reads the new
APR artifact format under experiments/<experiment>/<dataset>.
"""

from __future__ import annotations

import argparse
import csv
import json
import os
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple


PROJECT_ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXPERIMENTS_ROOT = PROJECT_ROOT / "experiments"

VALID_STATUSES = {"invalid", "plausible", "cleanfix", "noisefix", "negfix", "nonefix"}
PATCH_ATTEMPT_NAME_RE = re.compile(r"^\d\d__.+\.json$")

STATUS_TO_GROUP = {
    "plausible": "Plausible",
    "cleanfix": "CleanFix",
    "noisefix": "NoiseFix",
    "invalid": "Invalid",
    "nonefix": "NoneFix",
    "negfix": "NegFix",
}

GROUP_SCORES = {
    "Plausible": 1.00,
    "CleanFix": 0.85,
    "NoiseFix": 0.55,
    "Unknown": 0.00,
    "Invalid": -0.05,
    "NoneFix": -0.10,
    "NegFix": -0.70,
}

REQUIRED_APR_RECORD_FIELDS = ("llm_patch_artifact", "status", "real_status")
REQUIRED_SELECTED_ARTIFACT_FIELDS = ("metadata_path", "status", "real_status")
REQUIRED_ATTEMPT_FIELDS = (
    "bug_id",
    "attempt_index",
    "function",
    "repair_target_relpath",
    "metadata_path",
    "patched_file_path",
    "status",
    "real_status",
    "validation_error",
)


class DataContractError(RuntimeError):
    """Raised when APR/FL artifacts do not satisfy the strict input contract."""


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Rerank FL results using only strict APR group feedback."
    )
    parser.add_argument(
        "--experiment",
        default="Ver2.5_new",
        help=(
            "Experiment name under Unified-Debugging/experiments, or an absolute/"
            "relative path to an experiment directory. Default: Ver2.5_new."
        ),
    )
    parser.add_argument(
        "--dataset",
        action="append",
        default=[],
        help="Dataset slug to process. Can be passed multiple times.",
    )
    parser.add_argument(
        "--all-datasets",
        action="store_true",
        help="Process every child directory that contains FL and APR result files.",
    )
    parser.add_argument(
        "--output-prefix",
        default="apr_feedback_group_only",
        help="Output file prefix. Default: apr_feedback_group_only.",
    )
    parser.add_argument(
        "--group-weight",
        type=float,
        default=1.0,
        help="Weight for APR group score. Default: 1.0.",
    )
    args = parser.parse_args()

    experiment_root = resolve_experiment_root(args.experiment)
    dataset_dirs = discover_dataset_dirs(experiment_root, args.dataset, args.all_datasets)
    if not dataset_dirs:
        print(f"[APR-FB] No dataset directories found under {experiment_root}")
        return 1

    exit_code = 0
    for dataset_dir in dataset_dirs:
        try:
            process_dataset(
                dataset_dir=dataset_dir,
                output_prefix=args.output_prefix,
                group_weight=args.group_weight,
            )
        except DataContractError as exc:
            print(f"[APR-FB] DATA ERROR {dataset_dir.name}: {exc}")
            exit_code = 1
        except FileNotFoundError as exc:
            print(f"[APR-FB] MISSING {dataset_dir.name}: {exc}")
            exit_code = 1
        except Exception as exc:
            print(f"[APR-FB] ERROR {dataset_dir.name}: {exc}")
            exit_code = 1
    return exit_code


def resolve_experiment_root(value: str) -> Path:
    raw = Path(value)
    if raw.exists():
        return raw.resolve()
    return (DEFAULT_EXPERIMENTS_ROOT / value).resolve()


def discover_dataset_dirs(
    experiment_root: Path,
    datasets: Sequence[str],
    all_datasets: bool,
) -> List[Path]:
    if datasets:
        return [(experiment_root / dataset).resolve() for dataset in datasets]
    if all_datasets:
        if not experiment_root.is_dir():
            return []
        return sorted(
            path
            for path in experiment_root.iterdir()
            if path.is_dir()
            and (path / "fault_localization_results.json").exists()
            and (path / "apr_results.json").exists()
        )
    return [(experiment_root / "fmt").resolve()]


def process_dataset(
    *,
    dataset_dir: Path,
    output_prefix: str,
    group_weight: float,
) -> None:
    dataset = dataset_dir.name
    fl_path = dataset_dir / "fault_localization_results.json"
    apr_path = dataset_dir / "apr_results.json"
    llm_patches_dir = dataset_dir / "llm_patches"

    require_file(fl_path)
    require_file(apr_path)
    require_dir(llm_patches_dir)

    fl_results = read_json_object(fl_path, label="FL results")
    apr_results = read_json_object(apr_path, label="APR results")

    output_results: Dict[str, Any] = {}
    output_features: Dict[str, Any] = {}
    rank_rows: List[Dict[str, Any]] = []
    metric_pairs: List[Tuple[Dict[str, float], Dict[str, float], List[str]]] = []
    status_counts: Counter[str] = Counter()
    real_status_counts: Counter[str] = Counter()
    excluded_attempts: List[Dict[str, Any]] = []

    total_bugs = 0
    processed_bugs = 0
    skipped_no_scores = 0

    for bug_id, fl_record in fl_results.items():
        if not isinstance(fl_record, dict):
            raise DataContractError(f"{dataset}/{bug_id}: FL record is not an object")
        total_bugs += 1

        base_scores = to_float_scores(fl_record.get("scores") or {})
        if not base_scores:
            skipped_no_scores += 1
            output_results[bug_id] = dict(fl_record)
            output_features[bug_id] = {"error": "missing_scores"}
            continue

        apr_record = require_apr_record(
            dataset_dir=dataset_dir,
            apr_results=apr_results,
            bug_id=bug_id,
        )
        attempts, excluded = load_validated_attempts(
            dataset_dir=dataset_dir,
            bug_id=bug_id,
            bug_llm_dir=llm_patches_dir / bug_id,
        )
        excluded_attempts.extend(excluded)
        for attempt in attempts:
            status_counts[str(attempt["status"])] += 1
            real_status_counts[str(attempt["real_status"])] += 1

        reranked = rerank_bug(
            bug_id=bug_id,
            fl_record=fl_record,
            base_scores=base_scores,
            apr_record=apr_record,
            attempts=attempts,
            group_weight=group_weight,
        )

        ground_truth = normalize_ground_truth_for_score_keys(
            list(fl_record.get("ground_truth") or []),
            base_scores,
        )
        rank_rows.extend(
            build_rank_rows(
                dataset=dataset,
                bug_id=bug_id,
                ground_truth=ground_truth,
                old_scores=base_scores,
                new_scores=reranked["scores"],
            )
        )
        if ground_truth:
            metric_pairs.append((base_scores, reranked["scores"], ground_truth))

        output_results[bug_id] = {
            "dataset": fl_record.get("dataset", dataset),
            "formula": fl_record.get("formula", "tarantula"),
            "reranker": f"{fl_record.get('reranker', 'ir')}+apr_group_feedback",
            "scores": reranked["scores"],
            "base_scores": base_scores,
            "tarantula_scores": fl_record.get("tarantula_scores", {}),
            "ground_truth": ground_truth,
            "test_filter": fl_record.get("test_filter", {}),
            "feedback": {
                "mode": "group_only_strict",
                "signals": ["group"],
                "status_scope": "status",
                "group_scores": GROUP_SCORES,
                "group_weight": group_weight,
            },
        }
        output_features[bug_id] = reranked["features"]
        processed_bugs += 1

    safe_prefix = sanitize_output_prefix(output_prefix)
    results_path = dataset_dir / f"fault_localization_{safe_prefix}_results.json"
    features_path = dataset_dir / f"{safe_prefix}_features.json"
    rank_path = dataset_dir / f"{safe_prefix}_rank_changes.csv"
    summary_path = dataset_dir / f"{safe_prefix}_summary.json"
    eval_report_path = dataset_dir / f"{safe_prefix}_fl_result.txt"

    summary = {
        "dataset": dataset,
        "mode": "group_only_strict",
        "strict_mode": True,
        "signals": ["group"],
        "status_scope": "status",
        "weights": {
            "group_weight": group_weight,
            "group_scores": GROUP_SCORES,
        },
        "total_bugs": total_bugs,
        "processed_bugs": processed_bugs,
        "skipped_no_scores": skipped_no_scores,
        "attempts_used": sum(
            len(feature.get("attempts_used", []))
            for feature in output_features.values()
            if isinstance(feature, dict)
        ),
        "attempts_excluded": len(excluded_attempts),
        "excluded_attempts": excluded_attempts,
        "attempt_status_counts": dict(sorted(status_counts.items())),
        "attempt_real_status_counts": dict(sorted(real_status_counts.items())),
        "metrics": summarize_metric_pairs(metric_pairs),
        "data_contract": {
            "required_apr_record_fields": list(REQUIRED_APR_RECORD_FIELDS),
            "required_selected_artifact_fields": list(REQUIRED_SELECTED_ARTIFACT_FIELDS),
            "required_attempt_fields": list(REQUIRED_ATTEMPT_FIELDS),
            "valid_statuses": sorted(VALID_STATUSES),
            "post_plausible_attempt_policy": "exclude_and_report",
        },
        "outputs": {
            "results": str(results_path),
            "features": str(features_path),
            "rank_changes": str(rank_path),
            "summary": str(summary_path),
            "fl_result": str(eval_report_path),
        },
    }

    write_json(results_path, output_results)
    write_json(features_path, output_features)
    write_rank_csv(rank_path, rank_rows)
    write_json(summary_path, summary)
    write_eval_report(eval_report_path, summary, rank_rows)

    print_dataset_summary(dataset, summary, rank_rows)


def require_apr_record(
    *,
    dataset_dir: Path,
    apr_results: Dict[str, Any],
    bug_id: str,
) -> Dict[str, Any]:
    if bug_id not in apr_results:
        raise DataContractError(f"{dataset_dir.name}/{bug_id}: missing APR record")
    record = apr_results[bug_id]
    if not isinstance(record, dict):
        raise DataContractError(f"{dataset_dir.name}/{bug_id}: APR record is not an object")
    missing = [field for field in REQUIRED_APR_RECORD_FIELDS if field not in record]
    if missing:
        raise DataContractError(
            f"{dataset_dir.name}/{bug_id}: APR record missing fields {missing}"
        )

    artifact = record.get("llm_patch_artifact")
    if not isinstance(artifact, dict):
        raise DataContractError(
            f"{dataset_dir.name}/{bug_id}: llm_patch_artifact is not an object"
        )
    artifact_missing = [
        field for field in REQUIRED_SELECTED_ARTIFACT_FIELDS if field not in artifact
    ]
    if artifact_missing:
        raise DataContractError(
            f"{dataset_dir.name}/{bug_id}: selected artifact missing fields {artifact_missing}"
        )

    metadata_path = str(artifact.get("metadata_path") or "")
    if not metadata_path:
        raise DataContractError(f"{dataset_dir.name}/{bug_id}: empty selected metadata_path")
    selected_path = dataset_dir / metadata_path
    require_file(selected_path)
    if not is_patch_attempt_metadata(selected_path):
        raise DataContractError(
            f"{dataset_dir.name}/{bug_id}: selected metadata is not a patch attempt: "
            f"{metadata_path}"
        )
    ensure_valid_status(
        dataset=dataset_dir.name,
        bug_id=bug_id,
        path=metadata_path,
        status=artifact.get("status"),
    )
    return record


def load_validated_attempts(
    *,
    dataset_dir: Path,
    bug_id: str,
    bug_llm_dir: Path,
) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]]]:
    require_dir(bug_llm_dir)
    attempts: List[Dict[str, Any]] = []
    excluded: List[Dict[str, Any]] = []
    seen_plausible = False

    for path in sorted(bug_llm_dir.glob("*.json")):
        if not is_patch_attempt_metadata(path):
            continue

        if seen_plausible:
            payload = read_json_object(path, label="post-plausible attempt")
            excluded.append(
                {
                    "dataset": dataset_dir.name,
                    "bug_id": bug_id,
                    "path": relpath(path),
                    "attempt_index": payload.get("attempt_index"),
                    "function": payload.get("function"),
                    "status": payload.get("status"),
                    "real_status": payload.get("real_status"),
                    "reason": "excluded_post_plausible_unvalidated",
                }
            )
            continue

        payload = read_json_object(path, label="patch attempt")
        if not is_patch_attempt_payload(payload):
            continue
        validate_attempt_payload(
            dataset=dataset_dir.name,
            bug_id=bug_id,
            path=path,
            payload=payload,
        )
        attempts.append(payload)
        if payload.get("status") == "plausible":
            seen_plausible = True

    if not attempts:
        raise DataContractError(f"{dataset_dir.name}/{bug_id}: no validated patch attempts")
    return attempts, excluded


def is_patch_attempt_metadata(path: Path) -> bool:
    return PATCH_ATTEMPT_NAME_RE.match(path.name) is not None and path.stem.count("__") == 1


def is_patch_attempt_payload(payload: Dict[str, Any]) -> bool:
    return bool(payload.get("patched_file_path") and payload.get("repair_target_relpath"))


def validate_attempt_payload(
    *,
    dataset: str,
    bug_id: str,
    path: Path,
    payload: Dict[str, Any],
) -> None:
    missing = [field for field in REQUIRED_ATTEMPT_FIELDS if field not in payload]
    if missing:
        raise DataContractError(
            f"{dataset}/{bug_id}/{path.name}: attempt missing fields {missing}"
        )
    if str(payload.get("bug_id")) != str(bug_id):
        raise DataContractError(
            f"{dataset}/{bug_id}/{path.name}: bug_id mismatch "
            f"({payload.get('bug_id')!r})"
        )
    ensure_valid_status(
        dataset=dataset,
        bug_id=bug_id,
        path=relpath(path),
        status=payload.get("status"),
    )
    real_status = str(payload.get("real_status") or "")
    if real_status not in VALID_STATUSES:
        raise DataContractError(
            f"{dataset}/{bug_id}/{path.name}: unsupported real_status {real_status!r}"
        )
    metadata_path = str(payload.get("metadata_path") or "")
    if metadata_path and (PROJECT_ROOT / "experiments" / metadata_path).exists():
        return
    # For copied experiment folders, metadata_path is relative to the dataset dir.
    if metadata_path and path.name == Path(metadata_path).name:
        return
    raise DataContractError(
        f"{dataset}/{bug_id}/{path.name}: metadata_path does not point to this attempt "
        f"({metadata_path!r})"
    )


def ensure_valid_status(*, dataset: str, bug_id: str, path: str, status: Any) -> None:
    status_text = str(status or "")
    if status_text not in VALID_STATUSES:
        raise DataContractError(
            f"{dataset}/{bug_id}: unsupported status {status_text!r} in {path}"
        )


def rerank_bug(
    *,
    bug_id: str,
    fl_record: Dict[str, Any],
    base_scores: Dict[str, float],
    apr_record: Dict[str, Any],
    attempts: List[Dict[str, Any]],
    group_weight: float,
) -> Dict[str, Any]:
    base_norm = normalize_scores(base_scores)
    old_ranks = assign_worst_case_ranks(sort_score_items(base_scores))

    attempt_by_function: Dict[str, Dict[str, Any]] = {}
    attempts_used: List[Dict[str, Any]] = []

    for attempt in attempts:
        func_key = str(attempt.get("function") or "")
        if func_key not in base_scores:
            raise DataContractError(
                f"{bug_id}/{attempt.get('metadata_path')}: attempt function "
                f"{func_key!r} is not an exact key in FL scores"
            )
        if func_key in attempt_by_function:
            previous = attempt_by_function[func_key]
            raise DataContractError(
                f"{bug_id}: multiple attempts map to {func_key!r}: "
                f"{previous.get('metadata_path')} and {attempt.get('metadata_path')}"
            )

        group = STATUS_TO_GROUP[str(attempt["status"])]
        normalized_attempt = {
            "attempt_index": attempt.get("attempt_index"),
            "function": func_key,
            "matched_function_key": func_key,
            "repair_target_relpath": attempt.get("repair_target_relpath"),
            "status": attempt.get("status"),
            "real_status": attempt.get("real_status"),
            "group": group,
            "group_score": GROUP_SCORES[group],
            "validation_error": attempt.get("validation_error"),
            "metadata_path": attempt.get("metadata_path"),
        }
        attempt_by_function[func_key] = normalized_attempt
        attempts_used.append(normalized_attempt)

    raw_intra: Dict[str, float] = {}
    function_features: Dict[str, Any] = {}
    for func_key, base_score in base_scores.items():
        attempt = attempt_by_function.get(func_key)
        group = attempt["group"] if attempt else "Unknown"
        group_score = GROUP_SCORES[group]
        group_component = group_weight * group_score
        final_score = base_norm.get(func_key, 0.0) + group_component
        raw_intra[func_key] = final_score
        function_features[func_key] = {
            "base_score": base_score,
            "base_norm": base_norm.get(func_key, 0.0),
            "base_rank": old_ranks.get(func_key),
            "group": group,
            "group_score": group_score,
            "group_component": group_component,
            "apr_attempt": attempt or {},
            "raw_intra_score": final_score,
        }

    final_scores = dict(sort_score_items(raw_intra))
    new_ranks = assign_worst_case_ranks(sort_score_items(final_scores))
    for func_key, info in function_features.items():
        info["feedback_score"] = final_scores.get(func_key, 0.0)
        info["new_rank"] = new_ranks.get(func_key)

    selected_artifact = apr_record.get("llm_patch_artifact") or {}
    return {
        "scores": final_scores,
        "features": {
            "bug_id": bug_id,
            "mode": "group_only_strict",
            "status_scope": "status",
            "selected_artifact": {
                "metadata_path": selected_artifact.get("metadata_path"),
                "function": selected_artifact.get("function"),
                "status": selected_artifact.get("status"),
                "real_status": selected_artifact.get("real_status"),
            },
            "attempts_used": attempts_used,
            "functions": function_features,
            "weights": {
                "group_scores": GROUP_SCORES,
                "group_weight": group_weight,
            },
        },
    }


def normalize_function_key(value: str) -> str:
    text = str(value or "").strip().replace("\\", "/")
    first_colon = re.search(r"(?<!:):(?!:)", text)
    if first_colon:
        file_hint = text[: first_colon.start()]
        func = text[first_colon.end() :]
        return f"{os.path.basename(file_hint)}:{func}"
    if "::" in text:
        file_hint, func = text.rsplit("::", 1)
        return f"{os.path.basename(file_hint)}:{func}"
    return text


def normalize_ground_truth_for_score_keys(
    ground_truth: List[str],
    scores: Dict[str, float],
) -> List[str]:
    if not isinstance(ground_truth, list):
        return []
    uses_file_colon = any(
        isinstance(key, str) and "::" not in key and ":" in key
        for key in scores.keys()
    )
    if not uses_file_colon:
        return [item for item in ground_truth if isinstance(item, str)]
    out = []
    for item in ground_truth:
        if isinstance(item, str):
            normalized = normalize_function_key(item)
            if normalized:
                out.append(normalized)
    return sorted(set(out))


def normalize_scores(scores: Dict[str, float]) -> Dict[str, float]:
    if not scores:
        return {}
    values = list(scores.values())
    min_score = min(values)
    max_score = max(values)
    if max_score == min_score:
        return {key: (1.0 if max_score > 0 else 0.0) for key in scores}
    return {
        key: (value - min_score) / (max_score - min_score)
        for key, value in scores.items()
    }


def sort_score_items(scores: Dict[str, float]) -> List[Tuple[str, float]]:
    return sorted(scores.items(), key=lambda item: (-item[1], item[0]))


def assign_worst_case_ranks(sorted_items: Sequence[Tuple[str, float]]) -> Dict[str, int]:
    ranks: Dict[str, int] = {}
    i = 0
    while i < len(sorted_items):
        j = i
        while j < len(sorted_items) and sorted_items[j][1] == sorted_items[i][1]:
            j += 1
        worst_rank = j
        for k in range(i, j):
            ranks[sorted_items[k][0]] = worst_rank
        i = j
    return ranks


def build_rank_rows(
    *,
    dataset: str,
    bug_id: str,
    ground_truth: List[str],
    old_scores: Dict[str, float],
    new_scores: Dict[str, float],
) -> List[Dict[str, Any]]:
    if not ground_truth:
        return [
            {
                "dataset": dataset,
                "bug_id": bug_id,
                "ground_truth": "",
                "old_rank": "",
                "new_rank": "",
                "rank_delta": "",
                "old_first_rank": "",
                "new_first_rank": "",
                "old_top1": "",
                "new_top1": "",
                "old_top3": "",
                "new_top3": "",
                "old_top5": "",
                "new_top5": "",
                "old_top10": "",
                "new_top10": "",
            }
        ]

    old_ranks = assign_worst_case_ranks(sort_score_items(old_scores))
    new_ranks = assign_worst_case_ranks(sort_score_items(new_scores))
    total = len(old_scores)
    old_gt_ranks = [old_ranks.get(gt, total + 1) for gt in ground_truth]
    new_gt_ranks = [new_ranks.get(gt, total + 1) for gt in ground_truth]
    old_first = min(old_gt_ranks)
    new_first = min(new_gt_ranks)
    rows = []
    for gt in ground_truth:
        old_rank = old_ranks.get(gt, total + 1)
        new_rank = new_ranks.get(gt, total + 1)
        rows.append(
            {
                "dataset": dataset,
                "bug_id": bug_id,
                "ground_truth": gt,
                "old_rank": old_rank,
                "new_rank": new_rank,
                "rank_delta": old_rank - new_rank,
                "old_first_rank": old_first,
                "new_first_rank": new_first,
                "old_top1": int(old_first <= 1),
                "new_top1": int(new_first <= 1),
                "old_top3": int(old_first <= 3),
                "new_top3": int(new_first <= 3),
                "old_top5": int(old_first <= 5),
                "new_top5": int(new_first <= 5),
                "old_top10": int(old_first <= 10),
                "new_top10": int(new_first <= 10),
            }
        )
    return rows


def summarize_metric_pairs(
    pairs: List[Tuple[Dict[str, float], Dict[str, float], List[str]]]
) -> Dict[str, Any]:
    old = metric_summary([(old_scores, gt) for old_scores, _, gt in pairs])
    new = metric_summary([(new_scores, gt) for _, new_scores, gt in pairs])
    return {"before": old, "after": new, "delta": metric_delta(old, new)}


def metric_summary(pairs: List[Tuple[Dict[str, float], List[str]]]) -> Dict[str, Any]:
    evaluated = 0
    top1 = top3 = top5 = top10 = 0
    first_ranks = []
    avg_ranks = []
    exam_scores = []

    for scores, ground_truth in pairs:
        if not scores or not ground_truth:
            continue
        evaluated += 1
        total = len(scores)
        ranks = assign_worst_case_ranks(sort_score_items(scores))
        gt_ranks = [ranks.get(gt, total + 1) for gt in ground_truth]
        first = min(gt_ranks)
        avg = sum(gt_ranks) / len(gt_ranks)
        first_ranks.append(first)
        avg_ranks.append(avg)
        exam_scores.append(first / total if total else 0.0)
        top1 += int(first <= 1)
        top3 += int(first <= 3)
        top5 += int(first <= 5)
        top10 += int(first <= 10)

    if not evaluated:
        return {"evaluated": 0}
    return {
        "evaluated": evaluated,
        "top1": top1,
        "top3": top3,
        "top5": top5,
        "top10": top10,
        "top1_accuracy": top1 / evaluated,
        "top3_accuracy": top3 / evaluated,
        "top5_accuracy": top5 / evaluated,
        "top10_accuracy": top10 / evaluated,
        "mfr": sum(first_ranks) / evaluated,
        "mar": sum(avg_ranks) / evaluated,
        "exam": sum(exam_scores) / evaluated,
    }


def metric_delta(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    out = {}
    for key in ("top1", "top3", "top5", "top10", "mfr", "mar", "exam"):
        if key in old and key in new:
            out[key] = new[key] - old[key]
    return out


def print_dataset_summary(
    dataset: str,
    summary: Dict[str, Any],
    rank_rows: List[Dict[str, Any]],
) -> None:
    metrics = summary.get("metrics", {})
    before = metrics.get("before", {})
    after = metrics.get("after", {})
    print(f"\n[APR-FB] Dataset: {dataset}")
    print("  mode: group_only_strict; signals: group")
    print(f"  status_scope: {summary.get('status_scope')}")
    print(f"  group_weight: {summary.get('weights', {}).get('group_weight', 0.0):.3f}")
    print(
        f"  processed: {summary['processed_bugs']}/{summary['total_bugs']} "
        f"(skipped_no_scores={summary['skipped_no_scores']})"
    )
    print(
        f"  attempts: used={summary['attempts_used']}, "
        f"excluded={summary['attempts_excluded']}"
    )
    if before.get("evaluated"):
        print(
            "  Top-1/3/5 before: "
            f"{before['top1']}/{before['top3']}/{before['top5']} "
            "after: "
            f"{after['top1']}/{after['top3']}/{after['top5']}"
        )
        print(
            "  MFR before -> after: "
            f"{before['mfr']:.4f} -> {after['mfr']:.4f}; "
            f"MAR: {before['mar']:.4f} -> {after['mar']:.4f}"
        )
    print("  Ground-truth rank changes:")
    shown = 0
    for row in rank_rows:
        gt = row.get("ground_truth")
        if not gt:
            continue
        print(
            f"    {row['bug_id']} | {gt}: "
            f"{row['old_rank']} -> {row['new_rank']} "
            f"(delta={row['rank_delta']})"
        )
        shown += 1
        if shown >= 25:
            remaining = len([r for r in rank_rows if r.get("ground_truth")]) - shown
            if remaining > 0:
                print(f"    ... {remaining} more rows in rank_changes.csv")
            break
    print(f"  wrote: {summary['outputs']['results']}")
    print(f"         {summary['outputs']['features']}")
    print(f"         {summary['outputs']['rank_changes']}")
    print(f"         {summary['outputs']['summary']}")
    print(f"         {summary['outputs']['fl_result']}")


def write_eval_report(
    path: Path,
    summary: Dict[str, Any],
    rank_rows: List[Dict[str, Any]],
) -> None:
    metrics = summary.get("metrics", {})
    before = metrics.get("before", {})
    after = metrics.get("after", {})
    delta = metrics.get("delta", {})
    weights = summary.get("weights", {})

    lines = [
        f"APR Group Feedback FL Result - {summary.get('dataset', '')}",
        f"Mode: {summary.get('mode', '')}",
        "Signals: group",
        f"Status scope: {summary.get('status_scope', '')}",
        f"Group weight: {weights.get('group_weight', 0.0):.3f}",
        f"Processed bugs: {summary.get('processed_bugs', 0)}/{summary.get('total_bugs', 0)}",
        f"Skipped no scores: {summary.get('skipped_no_scores', 0)}",
        f"Attempts used: {summary.get('attempts_used', 0)}",
        f"Attempts excluded: {summary.get('attempts_excluded', 0)}",
        "",
        "Attempt status counts",
    ]
    for status, count in sorted(summary.get("attempt_status_counts", {}).items()):
        lines.append(f"{status}: {count}")

    excluded = summary.get("excluded_attempts", [])
    if excluded:
        lines.extend(["", "Excluded attempts"])
        for item in excluded:
            lines.append(
                f"{item.get('bug_id', '')} | {item.get('path', '')} | "
                f"status={item.get('status', '')} | reason={item.get('reason', '')}"
            )

    lines.append("")
    if not before.get("evaluated"):
        lines.append("No evaluable bugs with both ground truth and scores.")
    else:
        evaluated = before.get("evaluated", 0)
        lines.extend(
            [
                "Aggregate metrics",
                f"Evaluated bugs: {evaluated}",
                "",
                "Before APR feedback",
                metric_line("Top-1", before, "top1", "top1_accuracy"),
                metric_line("Top-3", before, "top3", "top3_accuracy"),
                metric_line("Top-5", before, "top5", "top5_accuracy"),
                metric_line("Top-10", before, "top10", "top10_accuracy"),
                f"MFR: {before.get('mfr', 0.0):.4f}",
                f"MAR: {before.get('mar', 0.0):.4f}",
                f"EXAM: {before.get('exam', 0.0):.6f}",
                "",
                "After APR feedback",
                metric_line("Top-1", after, "top1", "top1_accuracy"),
                metric_line("Top-3", after, "top3", "top3_accuracy"),
                metric_line("Top-5", after, "top5", "top5_accuracy"),
                metric_line("Top-10", after, "top10", "top10_accuracy"),
                f"MFR: {after.get('mfr', 0.0):.4f}",
                f"MAR: {after.get('mar', 0.0):.4f}",
                f"EXAM: {after.get('exam', 0.0):.6f}",
                "",
                "Delta (after - before; lower MFR/MAR/EXAM is better)",
                f"Top-1: {delta.get('top1', 0):+}",
                f"Top-3: {delta.get('top3', 0):+}",
                f"Top-5: {delta.get('top5', 0):+}",
                f"Top-10: {delta.get('top10', 0):+}",
                f"MFR: {delta.get('mfr', 0.0):+.4f}",
                f"MAR: {delta.get('mar', 0.0):+.4f}",
                f"EXAM: {delta.get('exam', 0.0):+.6f}",
            ]
        )

    gt_rows = [row for row in rank_rows if row.get("ground_truth")]
    lines.extend(["", "Ground-truth rank changes"])
    if not gt_rows:
        lines.append("No ground-truth rank rows.")
    else:
        lines.append("bug_id | ground_truth | old_rank -> new_rank | delta")
        for row in gt_rows:
            lines.append(
                f"{row.get('bug_id', '')} | {row.get('ground_truth', '')} | "
                f"{row.get('old_rank', '')} -> {row.get('new_rank', '')} | "
                f"{row.get('rank_delta', '')}"
            )

    path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def metric_line(label: str, metric: Dict[str, Any], count_key: str, acc_key: str) -> str:
    evaluated = metric.get("evaluated", 0) or 0
    count = metric.get(count_key, 0)
    acc = metric.get(acc_key, 0.0)
    return f"{label}: {count}/{evaluated} ({acc * 100:.2f}%)"


def require_file(path: Path) -> None:
    if not path.is_file():
        raise FileNotFoundError(str(path))


def require_dir(path: Path) -> None:
    if not path.is_dir():
        raise FileNotFoundError(str(path))


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def read_json_object(path: Path, *, label: str) -> Dict[str, Any]:
    try:
        payload = read_json(path)
    except Exception as exc:
        raise DataContractError(f"cannot read {label} JSON at {path}: {exc}") from exc
    if not isinstance(payload, dict):
        raise DataContractError(f"{label} JSON at {path} is not an object")
    return payload


def write_json(path: Path, payload: Any) -> None:
    with path.open("w", encoding="utf-8") as f:
        json.dump(payload, f, indent=4, ensure_ascii=False)


def write_rank_csv(path: Path, rows: List[Dict[str, Any]]) -> None:
    fieldnames = [
        "dataset",
        "bug_id",
        "ground_truth",
        "old_rank",
        "new_rank",
        "rank_delta",
        "old_first_rank",
        "new_first_rank",
        "old_top1",
        "new_top1",
        "old_top3",
        "new_top3",
        "old_top5",
        "new_top5",
        "old_top10",
        "new_top10",
    ]
    with path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row.get(key, "") for key in fieldnames})


def to_float_scores(value: Any) -> Dict[str, float]:
    if not isinstance(value, dict):
        return {}
    out = {}
    for key, score in value.items():
        try:
            out[str(key)] = float(score)
        except (TypeError, ValueError):
            continue
    return out


def sanitize_output_prefix(value: str) -> str:
    value = str(value or "apr_feedback_group_only").strip()
    value = re.sub(r"[^A-Za-z0-9_.-]+", "_", value)
    return value or "apr_feedback_group_only"


def relpath(path: Path) -> str:
    try:
        return str(path.resolve().relative_to(PROJECT_ROOT)).replace("\\", "/")
    except Exception:
        return str(path).replace("\\", "/")


if __name__ == "__main__":
    raise SystemExit(main())
