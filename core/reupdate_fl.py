import argparse
import json
import math
import os
import sys
from typing import Dict, Iterable, List, Tuple

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from configs.path import EXPERIMENTS_DIR
from evaluation.eval_fl import evaluate_fl


BASE_FL_FILE = "fault_localization_results.json"
APR_FILE = "apr_results.json"
LLM_PATCHES_DIRNAME = "llm_patches"
OUTPUT_FILE = "fault_localization_apr_feedback_results.json"


TEST_DELTA_BLOCK_STATUSES = {
    "invalid",
    "validation_error",
    "llm_failed",
    "skipped",
}


def score_update_unit(scores: Dict[str, float]) -> float:
    """Derive an APR update unit from the score distribution of one bug."""
    if not scores:
        return 1.0

    values = [float(v) for v in scores.values()]
    span = max(values) - min(values)
    if span <= 1e-12:
        return 1.0 / math.sqrt(max(1, len(values)))
    return span / math.sqrt(max(1, len(values)))


def sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def clamp(value: float, lower: float, upper: float) -> float:
    return max(lower, min(upper, value))


def test_set(record: dict, key: str) -> set:
    values = record.get(key) or []
    if not isinstance(values, list):
        return set()
    return {str(value).strip() for value in values if str(value).strip()}


def extract_file(score_key: str) -> str:
    """Extract file component from keys such as file.c:func or path/file.c::func."""
    text = str(score_key or "")
    for idx, char in enumerate(text):
        if char != ":":
            continue
        prev_is_colon = idx > 0 and text[idx - 1] == ":"
        next_is_colon = idx + 1 < len(text) and text[idx + 1] == ":"
        if not prev_is_colon and not next_is_colon:
            return os.path.basename(text[:idx])
    if "::" in text:
        return os.path.basename(text.rsplit("::", 1)[0])
    return text


def apr_feedback_signal(
    apr_record: dict,
    *,
    miss_penalty: float,
    signal_min: float,
    signal_max: float,
) -> Tuple[float, dict]:
    status = str(apr_record.get("status") or "").strip().lower()
    validation_error = str(apr_record.get("validation_error") or "").strip()
    init_failed = test_set(apr_record, "init_failed_tests")
    post_failed = test_set(apr_record, "post_failed_tests")

    fixed = init_failed - post_failed
    still_failed = init_failed & post_failed
    regressions = post_failed - init_failed

    test_delta_used = not validation_error and status not in TEST_DELTA_BLOCK_STATUSES
    if status in {"plausible", "success"}:
        raw_signal = 1.0
    elif status in {"llm_failed", "skipped"}:
        raw_signal = 0.0
    elif status in TEST_DELTA_BLOCK_STATUSES or validation_error:
        raw_signal = -miss_penalty
    elif status in {"nonefix", "failed"}:
        raw_signal = -miss_penalty
    elif test_delta_used:
        evidence_denom = max(1, len(init_failed | post_failed))
        raw_signal = (len(fixed) - len(regressions)) / evidence_denom
        if status == "negfix" and raw_signal >= 0.0:
            raw_signal = -miss_penalty
        elif status == "cleanfix" and raw_signal <= 0.0:
            raw_signal = miss_penalty
    else:
        raw_signal = 0.0
    signal = clamp(raw_signal, signal_min, signal_max)

    return signal, {
        "status": status,
        "validation_error": validation_error,
        "raw_signal": raw_signal,
        "signal": signal,
        "miss_penalty": miss_penalty,
        "test_delta_used_for_signal": test_delta_used,
        "init_failed_count": len(init_failed),
        "post_failed_count": len(post_failed),
        "fixed_count": len(fixed),
        "still_failed_count": len(still_failed),
        "regression_count": len(regressions),
    }


def patch_attempt_function(candidate: dict) -> str:
    return str(candidate.get("function") or candidate.get("selected_function") or "").strip()


def is_patch_attempt_artifact(data: dict) -> bool:
    if not isinstance(data, dict):
        return False
    if data.get("step_name"):
        return False
    if not data.get("bug_id") or not patch_attempt_function(data):
        return False
    if not data.get("status"):
        return False
    artifact_markers = (
        "patched_function_path",
        "llm_response_path",
        "raw_patch_path",
        "patched_file_path",
    )
    return any(key in data for key in artifact_markers)


def load_llm_patch_attempts(llm_patches_dir: str) -> Dict[str, List[dict]]:
    candidates_by_bug: Dict[str, List[dict]] = {}
    if not llm_patches_dir or not os.path.isdir(llm_patches_dir):
        return candidates_by_bug

    for dirpath, _, filenames in os.walk(llm_patches_dir):
        for filename in filenames:
            if not filename.endswith(".json"):
                continue
            path = os.path.join(dirpath, filename)
            try:
                data = load_json(path)
            except Exception:
                continue
            if not is_patch_attempt_artifact(data):
                continue
            bug_id = str(data.get("bug_id") or "").strip()
            data = dict(data)
            data["_feedback_source"] = "llm_patches"
            data["_artifact_path"] = os.path.relpath(path, os.path.dirname(llm_patches_dir))
            candidates_by_bug.setdefault(bug_id, []).append(data)

    for candidates in candidates_by_bug.values():
        candidates.sort(
            key=lambda item: (
                int(item.get("attempt_index") or 0),
                patch_attempt_function(item),
                str(item.get("metadata_path") or item.get("_artifact_path") or ""),
            )
        )
    return candidates_by_bug


def same_file_keys(keys: Iterable[str], selected_function: str) -> set:
    selected_file = extract_file(selected_function)
    if not selected_file:
        return set()
    return {
        key for key in keys
        if key != selected_function and extract_file(key) == selected_file
    }


def update_one_bug_scores(
    fl_scores: Dict[str, float],
    apr_candidates: List[dict],
    *,
    apr_strength: float,
    file_weight: float,
    signal_min: float,
    signal_max: float,
) -> Tuple[Dict[str, float], dict]:
    updated = {key: float(value) for key, value in fl_scores.items()}
    apr_evidence = {key: 0.0 for key in updated}
    update_unit = score_update_unit(fl_scores)
    candidate_feedback = []
    candidate_not_in_fl_scores = 0
    miss_penalty = 1.0 / max(1, len(apr_candidates))

    for candidate in apr_candidates:
        candidate_function = patch_attempt_function(candidate)
        signal, feedback = apr_feedback_signal(
            candidate,
            miss_penalty=miss_penalty,
            signal_min=signal_min,
            signal_max=signal_max,
        )
        feedback["function"] = candidate_function
        feedback["attempt_index"] = candidate.get("attempt_index")
        feedback["metadata_path"] = candidate.get("metadata_path") or candidate.get("_artifact_path", "")
        feedback["source"] = candidate.get("_feedback_source", "apr_results")
        feedback["function_in_fl_scores"] = candidate_function in apr_evidence

        if candidate_function and candidate_function in apr_evidence:
            apr_evidence[candidate_function] += signal

            if signal > 0.0 and file_weight > 0.0:
                peer_keys = same_file_keys(apr_evidence.keys(), candidate_function)
                for key in peer_keys:
                    apr_evidence[key] += file_weight * signal
                feedback["same_file_boosted_count"] = len(peer_keys)
            else:
                feedback["same_file_boosted_count"] = 0
        else:
            candidate_not_in_fl_scores += 1
            feedback["same_file_boosted_count"] = 0

        candidate_feedback.append(feedback)

    bounded_apr_evidence = {}
    for key, value in apr_evidence.items():
        bounded = clamp(value, signal_min, signal_max)
        bounded_apr_evidence[key] = bounded
        updated[key] += apr_strength * update_unit * bounded

    final_scores = sort_scores(updated)
    return final_scores, {
        "candidate_count": len(apr_candidates),
        "candidate_not_in_fl_scores": candidate_not_in_fl_scores,
        "apr_strength": apr_strength,
        "score_update_unit": update_unit,
        "miss_penalty": miss_penalty,
        "candidate_feedback": candidate_feedback,
    }


def apr_result_as_candidate(apr_record: dict) -> dict:
    candidate = dict(apr_record)
    candidate["function"] = str(apr_record.get("selected_function") or "").strip()
    candidate["_feedback_source"] = "apr_results"
    return candidate


def build_apr_feedback_fl_results(
    fl_results: dict,
    apr_results: dict,
    candidates_by_bug: Dict[str, List[dict]],
    *,
    apr_strength: float,
    file_weight: float,
    signal_min: float,
    signal_max: float,
) -> Tuple[dict, dict]:
    output = {}
    summary = {
        "total_fl_records": 0,
        "updated_records": 0,
        "updated_from_llm_patches": 0,
        "updated_from_apr_results_fallback": 0,
        "candidate_records": 0,
        "missing_apr_records": 0,
        "missing_scores_records": 0,
        "candidate_not_in_fl_scores": 0,
        "status_counts": {},
    }

    for bug_id, fl_record in fl_results.items():
        summary["total_fl_records"] += 1
        if not isinstance(fl_record, dict):
            output[bug_id] = fl_record
            summary["missing_scores_records"] += 1
            continue

        scores = fl_record.get("scores") or {}
        if not isinstance(scores, dict) or not scores:
            new_record = dict(fl_record)
            new_record["scores"] = {}
            new_record["apr_feedback"] = {"applied": False, "reason": "missing_fl_scores"}
            output[bug_id] = new_record
            summary["missing_scores_records"] += 1
            continue

        apr_candidates = list(candidates_by_bug.get(bug_id) or [])
        source = "llm_patches" if apr_candidates else ""
        if not apr_candidates:
            apr_record = apr_results.get(bug_id)
            if isinstance(apr_record, dict):
                apr_candidates = [apr_result_as_candidate(apr_record)]
                source = "apr_results_fallback"

        if not apr_candidates:
            new_record = dict(fl_record)
            new_record["scores"] = sort_scores({key: float(value) for key, value in scores.items()})
            new_record["apr_feedback"] = {"applied": False, "reason": "missing_apr_feedback"}
            output[bug_id] = new_record
            summary["missing_apr_records"] += 1
            continue

        new_scores, feedback = update_one_bug_scores(
            scores,
            apr_candidates,
            apr_strength=apr_strength,
            file_weight=file_weight,
            signal_min=signal_min,
            signal_max=signal_max,
        )

        summary["candidate_records"] += feedback["candidate_count"]
        summary["candidate_not_in_fl_scores"] += feedback["candidate_not_in_fl_scores"]
        if source == "llm_patches":
            summary["updated_from_llm_patches"] += 1
        elif source == "apr_results_fallback":
            summary["updated_from_apr_results_fallback"] += 1
        for candidate in feedback["candidate_feedback"]:
            status = candidate.get("status") or "<empty>"
            summary["status_counts"][status] = summary["status_counts"].get(status, 0) + 1
        summary["updated_records"] += 1

        new_record = dict(fl_record)
        new_record["scores"] = new_scores
        new_record["base_scores_file"] = BASE_FL_FILE
        new_record["formula"] = fl_record.get("formula", "tarantula")
        new_record["reranker"] = "ir+apr_feedback"
        new_record["apr_feedback"] = {
            "applied": True,
            "normalization": "raw_fl_score + apr_strength * score_update_unit * bounded_apr_evidence",
            "apr_strength": apr_strength,
            "same_file_weight": file_weight,
            "signal_min": signal_min,
            "signal_max": signal_max,
            "source": source,
            **feedback,
        }
        output[bug_id] = new_record

    return output, summary


def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def write_json(path: str, data: dict):
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def parse_args():
    parser = argparse.ArgumentParser(
        description="Update FL scores using APR validation feedback."
    )
    parser.add_argument(
        "--input-dir",
        default=EXPERIMENTS_DIR,
        help="Thư mục chứa fault_localization_results.json và apr_results.json.",
    )
    parser.add_argument("--dataset", default="", help="Dataset filter dùng cho FL evaluation.")
    parser.add_argument("--base-fl-file", default=BASE_FL_FILE)
    parser.add_argument("--apr-file", default=APR_FILE)
    parser.add_argument(
        "--llm-patches-dir",
        default=None,
        help=(
            "Thư mục chứa APR attempt artifacts. Mặc định là "
            "<input-dir>/llm_patches. Nếu bug không có artifact, script fallback "
            "về apr_results.json."
        ),
    )
    parser.add_argument("--output-file", default=OUTPUT_FILE)
    parser.add_argument(
        "--apr-strength",
        "--candidate-weight",
        "--selected-weight",
        dest="apr_strength",
        type=float,
        default=1.0,
        help=(
            "Mức tác động của APR log-evidence lên phân phối FL. "
            "Default 1.0 nghĩa là dùng trực tiếp signal như log-likelihood ratio."
        ),
    )
    parser.add_argument(
        "--same-file-weight",
        type=float,
        default=0.0,
        help="Lan truyền positive APR evidence sang function cùng file. Default tắt để giảm setting cứng.",
    )
    parser.add_argument(
        "--signal-min",
        type=float,
        default=-1.0,
        help=(
            "Lower bound for signed APR feedback signal. Default allows bad "
            "APR attempts to penalize candidate functions."
        ),
    )
    parser.add_argument("--signal-max", type=float, default=1.0)
    parser.add_argument(
        "--no-eval",
        action="store_true",
        help="Chỉ ghi file kết quả mới, không chạy evaluation FL.",
    )
    return parser.parse_args()


def main():
    args = parse_args()
    input_dir = os.path.abspath(args.input_dir)
    fl_path = os.path.join(input_dir, args.base_fl_file)
    apr_path = os.path.join(input_dir, args.apr_file)
    llm_patches_dir = os.path.abspath(
        args.llm_patches_dir or os.path.join(input_dir, LLM_PATCHES_DIRNAME)
    )
    output_path = os.path.join(input_dir, args.output_file)

    if not os.path.exists(fl_path):
        raise FileNotFoundError(f"Không tìm thấy FL results: {fl_path}")

    fl_results = load_json(fl_path)
    apr_results = load_json(apr_path) if os.path.exists(apr_path) else {}
    candidates_by_bug = load_llm_patch_attempts(llm_patches_dir)
    updated_results, summary = build_apr_feedback_fl_results(
        fl_results,
        apr_results,
        candidates_by_bug,
        apr_strength=args.apr_strength,
        file_weight=args.same_file_weight,
        signal_min=args.signal_min,
        signal_max=args.signal_max,
    )
    write_json(output_path, updated_results)

    print(f"[APR-FL] Wrote {output_path}")
    print(
        "[APR-FL] Summary: "
        f"updated={summary['updated_records']}/{summary['total_fl_records']}, "
        f"from_llm_patches={summary['updated_from_llm_patches']}, "
        f"fallback_apr_results={summary['updated_from_apr_results_fallback']}, "
        f"candidate_records={summary['candidate_records']}, "
        f"missing_feedback={summary['missing_apr_records']}, "
        f"missing_scores={summary['missing_scores_records']}, "
        f"candidate_not_in_scores={summary['candidate_not_in_fl_scores']}"
    )
    print(f"[APR-FL] LLM patches dir: {llm_patches_dir}")
    print(f"[APR-FL] Status counts: {summary['status_counts']}")

    if not args.no_eval:
        evaluate_fl(args.dataset, level="apr_feedback", results_dir=input_dir)


if __name__ == "__main__":
    main()
