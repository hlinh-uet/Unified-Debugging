"""APR-feedback update for fault-localization rankings."""

import argparse
import json
import math
import os
import sys
from typing import Dict, Iterable, List, Tuple

PROJECT_ROOT = os.path.dirname(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
)
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from configs.path import EXPERIMENTS_DIR
from core.apr.common import filter_zero_test_artifact_failures
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

NEGATIVE_PATCH_STATUSES = {
    "nonefix",
    "failed",
    "negfix",
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
        return os.path.basename(text.split("::", 1)[0])
    return text


def apr_feedback_signal(
    apr_record: dict,
    *,
    miss_penalty: float,
    signal_min: float,
    signal_max: float,
) -> Tuple[float, dict]:
    """Convert patch validation into *localization* evidence.

    A failed patch is evidence about the patch, not proof that its target
    function is innocent.  Negative APR outcomes are therefore neutral for FL.
    Fixing an original failing test is positive evidence; newly introduced
    regressions discount that evidence but never turn it negative.
    """
    status = str(apr_record.get("status") or "").strip().lower()
    validation_error = str(apr_record.get("validation_error") or "").strip()
    init_failed = test_set(apr_record, "init_failed_tests")
    post_failed = set(filter_zero_test_artifact_failures(
        test_set(apr_record, "post_failed_tests"),
        apr_record.get("validation_details") if isinstance(apr_record.get("validation_details"), dict) else {},
    ))

    fixed = init_failed - post_failed
    still_failed = init_failed & post_failed
    regressions = post_failed - init_failed

    test_delta_used = not validation_error and status not in TEST_DELTA_BLOCK_STATUSES
    if status in TEST_DELTA_BLOCK_STATUSES or validation_error:
        raw_signal = 0.0
        evidence_reason = "validation_unusable"
    elif status in {"plausible", "success"}:
        raw_signal = 1.0
        evidence_reason = "complete_validation_passed"
    elif status in NEGATIVE_PATCH_STATUSES:
        raw_signal = 0.0
        evidence_reason = "patch_failure_is_not_negative_localization_evidence"
    elif test_delta_used:
        fixed_ratio = len(fixed) / max(1, len(init_failed))
        regression_discount = (
            len(fixed) / max(1, len(fixed) + len(regressions))
            if fixed else 0.0
        )
        raw_signal = fixed_ratio * regression_discount
        if status == "cleanfix" and not init_failed:
            # Preserve compatibility with legacy summaries that stored only
            # the cleanfix label without the test lists used to derive it.
            raw_signal = 1.0
        evidence_reason = (
            "original_failure_reduction_discounted_by_regressions"
            if raw_signal > 0.0 else
            "no_original_failure_reduction"
        )
    else:
        raw_signal = 0.0
        evidence_reason = "no_usable_validation_evidence"

    # ``signal_min`` is retained in the public API for compatibility with old
    # runs, but neutral evidence must stay exactly zero.  In particular, a
    # positive lower bound must not boost every untested function.
    signal = (
        clamp(raw_signal, max(0.0, signal_min), signal_max)
        if raw_signal > 0.0 else 0.0
    )

    return signal, {
        "status": status,
        "validation_error": validation_error,
        "raw_signal": raw_signal,
        "signal": signal,
        "miss_penalty": miss_penalty,
        "evidence_reason": evidence_reason,
        "test_delta_used_for_signal": test_delta_used,
        "init_failed_count": len(init_failed),
        "post_failed_count": len(post_failed),
        "fixed_count": len(fixed),
        "still_failed_count": len(still_failed),
        "regression_count": len(regressions),
    }


def patch_attempt_function(candidate: dict) -> str:
    return str(candidate.get("function") or candidate.get("selected_function") or "").strip()


def score_key_symbol(score_key: str) -> str:
    """Return the symbol part of a file-qualified FL key."""
    text = str(score_key or "")
    for idx, char in enumerate(text):
        if char != ":":
            continue
        prev_is_colon = idx > 0 and text[idx - 1] == ":"
        next_is_colon = idx + 1 < len(text) and text[idx + 1] == ":"
        if not prev_is_colon and not next_is_colon:
            return text[idx + 1:].strip(":")
    if "::" in text:
        return text.split("::", 1)[1]
    return text


def _qualified_symbol_equivalent(left: str, right: str) -> bool:
    left = "".join(str(left or "").split())
    right = "".join(str(right or "").split())
    return bool(left and right) and (
        left == right
        or left.endswith("::" + right)
        or right.endswith("::" + left)
    )


def candidate_feedback_function(
    candidate: dict,
    score_keys: Iterable[str],
) -> Tuple[str, str]:
    """Map an APR artifact back to the source function actually patched.

    Runtime symbols may describe an inlined lambda (and can even be malformed),
    while replacement-target resolution correctly expands the patch to its
    enclosing source function.  Prefer that resolved source identity when it
    maps uniquely to the FL candidate set.
    """
    keys = list(score_keys)
    resolved = str(candidate.get("_resolved_feedback_function") or "").strip()
    if resolved:
        if resolved in keys:
            return resolved, "replacement_target_exact"
        resolved_file = extract_file(resolved)
        resolved_symbol = score_key_symbol(resolved)
        matches = [
            key for key in keys
            if extract_file(key) == resolved_file
            and _qualified_symbol_equivalent(
                score_key_symbol(key),
                resolved_symbol,
            )
        ]
        if len(matches) == 1:
            return matches[0], "replacement_target_namespace_suffix"

    requested = patch_attempt_function(candidate)
    if requested in keys:
        return requested, "requested_function_exact"
    return requested, "unmatched"


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


def _resolve_artifact_reference(reference: str, containing_path: str) -> str:
    reference = str(reference or "").strip()
    if not reference:
        return ""
    candidates = []
    if os.path.isabs(reference):
        candidates.append(reference)
    candidates.extend([
        os.path.join(os.path.dirname(containing_path), os.path.basename(reference)),
        os.path.join(EXPERIMENTS_DIR, reference),
        os.path.join(PROJECT_ROOT, reference),
    ])
    for candidate in candidates:
        if os.path.isfile(candidate):
            return os.path.abspath(candidate)
    return ""


def _replacement_target_identity(data: dict, artifact_path: str) -> dict:
    direct = data.get("replacement_identity")
    if isinstance(direct, dict) and direct:
        return direct

    artifact = data.get("replacement_target_artifact")
    if not isinstance(artifact, dict):
        return {}
    nested = artifact.get("replacement_identity")
    if isinstance(nested, dict) and nested:
        return nested

    reference = (
        artifact.get("replacement_target_path")
        or artifact.get("metadata_path")
    )
    target_path = _resolve_artifact_reference(reference, artifact_path)
    if not target_path:
        return {}
    try:
        target = load_json(target_path)
    except Exception:
        return {}
    identity = target.get("replacement_identity")
    return identity if isinstance(identity, dict) else {}


def _resolved_feedback_function(data: dict, artifact_path: str) -> Tuple[str, dict]:
    identity = _replacement_target_identity(data, artifact_path)
    resolved_name = str(identity.get("resolved_name") or "").strip()
    source_file = str(
        identity.get("source_file")
        or identity.get("source_path")
        or data.get("repair_target_relpath")
        or ""
    ).strip()
    if not resolved_name or not source_file:
        return "", identity
    return f"{os.path.basename(source_file)}:{resolved_name}", identity


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
            resolved_function, target_identity = _resolved_feedback_function(
                data,
                path,
            )
            if resolved_function:
                data["_resolved_feedback_function"] = resolved_function
            if target_identity:
                data["_feedback_target_identity"] = target_identity
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
        requested_function = patch_attempt_function(candidate)
        candidate_function, function_resolution = candidate_feedback_function(
            candidate,
            apr_evidence.keys(),
        )
        signal, feedback = apr_feedback_signal(
            candidate,
            miss_penalty=miss_penalty,
            signal_min=signal_min,
            signal_max=signal_max,
        )
        feedback["requested_function"] = requested_function
        feedback["function"] = candidate_function
        feedback["function_resolution"] = function_resolution
        feedback["resolved_feedback_function"] = candidate.get(
            "_resolved_feedback_function",
            "",
        )
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
        bounded = (
            clamp(value, max(0.0, signal_min), signal_max)
            if value > 0.0 else 0.0
        )
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


def apr_feedback_history(fl_record: dict) -> List[dict]:
    """Return prior feedback events without duplicating the latest event."""
    history = [
        dict(item)
        for item in (fl_record.get("apr_feedback_history") or [])
        if isinstance(item, dict)
    ]
    latest = fl_record.get("apr_feedback")
    if isinstance(latest, dict) and (not history or history[-1] != latest):
        history.append(dict(latest))
    return history


def feedback_event(payload: dict, feedback_round: int = None) -> dict:
    event = dict(payload)
    if feedback_round is not None:
        event["round"] = int(feedback_round)
    return event


def attach_feedback_event(
    record: dict,
    event: dict,
    *,
    prior_record: dict,
) -> None:
    history = apr_feedback_history(prior_record)
    history.append(dict(event))
    record["apr_feedback"] = event
    record["apr_feedback_history"] = history


def build_apr_feedback_fl_results(
    fl_results: dict,
    apr_results: dict,
    candidates_by_bug: Dict[str, List[dict]],
    *,
    apr_strength: float,
    file_weight: float,
    signal_min: float,
    signal_max: float,
    skip_bug_ids: set = None,
    feedback_round: int = None,
) -> Tuple[dict, dict]:
    output = {}
    skipped_bugs = {
        str(bug_id).strip()
        for bug_id in (skip_bug_ids or set())
        if str(bug_id).strip()
    }
    summary = {
        "total_fl_records": 0,
        "updated_records": 0,
        "skipped_plausible_records": 0,
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

        if bug_id in skipped_bugs:
            new_record = dict(fl_record)
            scores = new_record.get("scores") or {}
            if isinstance(scores, dict):
                new_record["scores"] = sort_scores(
                    {key: float(value) for key, value in scores.items()}
                )
            event = feedback_event({
                "applied": False,
                "reason": "plausible_converged",
                "scores_preserved": True,
            }, feedback_round)
            attach_feedback_event(
                new_record,
                event,
                prior_record=fl_record,
            )
            output[bug_id] = new_record
            summary["skipped_plausible_records"] += 1
            continue

        scores = fl_record.get("scores") or {}
        if not isinstance(scores, dict) or not scores:
            new_record = dict(fl_record)
            new_record["scores"] = {}
            event = feedback_event(
                {"applied": False, "reason": "missing_fl_scores"},
                feedback_round,
            )
            attach_feedback_event(new_record, event, prior_record=fl_record)
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
            event = feedback_event(
                {"applied": False, "reason": "missing_apr_feedback"},
                feedback_round,
            )
            attach_feedback_event(new_record, event, prior_record=fl_record)
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
        new_record["formula"] = fl_record.get(
            "formula", "io_scenario_first_causal_tiers_v7"
        )
        new_record["reranker"] = "ir+apr_feedback"
        event = feedback_event({
            "applied": True,
            "normalization": (
                "raw_fl_score + apr_strength * score_update_unit * "
                "bounded_nonnegative_apr_evidence"
            ),
            "evidence_policy": (
                "patch failures are neutral; original-test fixes are positive; "
                "regressions discount positive evidence"
            ),
            "apr_strength": apr_strength,
            "same_file_weight": file_weight,
            "signal_min": signal_min,
            "signal_max": signal_max,
            "source": source,
            **feedback,
        }, feedback_round)
        attach_feedback_event(new_record, event, prior_record=fl_record)
        output[bug_id] = new_record

    return output, summary


def load_json(path: str) -> dict:
    with open(path, "r") as f:
        return json.load(f)


def write_json(path: str, data: dict):
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w") as f:
        json.dump(data, f, indent=4)


def update_fl_from_apr(
    *,
    fl_path: str,
    apr_path: str,
    llm_patches_dir: str,
    output_path: str,
    apr_strength: float = 1.0,
    file_weight: float = 0.0,
    signal_min: float = 0.0,
    signal_max: float = 1.0,
    skip_bug_ids: set = None,
    feedback_round: int = None,
) -> Tuple[dict, dict]:
    """Update one FL result file from one explicitly scoped APR round.

    Explicit paths are required so iterative runs cannot accidentally mix
    artifacts from another dataset or overwrite another round.
    """
    fl_path = os.path.abspath(fl_path)
    apr_path = os.path.abspath(apr_path)
    llm_patches_dir = os.path.abspath(llm_patches_dir)
    output_path = os.path.abspath(output_path)

    if not os.path.exists(fl_path):
        raise FileNotFoundError(f"Không tìm thấy FL results: {fl_path}")

    fl_results = load_json(fl_path)
    apr_results = load_json(apr_path) if os.path.exists(apr_path) else {}
    candidates_by_bug = load_llm_patch_attempts(llm_patches_dir)
    updated_results, summary = build_apr_feedback_fl_results(
        fl_results,
        apr_results,
        candidates_by_bug,
        apr_strength=apr_strength,
        file_weight=file_weight,
        signal_min=signal_min,
        signal_max=signal_max,
        skip_bug_ids=skip_bug_ids,
        feedback_round=feedback_round,
    )
    write_json(output_path, updated_results)
    return updated_results, summary


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
        default=0.0,
        help=(
            "Lower bound for positive APR feedback signal. Patch failures are "
            "always neutral for FL; default: 0.0."
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

    _, summary = update_fl_from_apr(
        fl_path=fl_path,
        apr_path=apr_path,
        llm_patches_dir=llm_patches_dir,
        output_path=output_path,
        apr_strength=args.apr_strength,
        file_weight=args.same_file_weight,
        signal_min=args.signal_min,
        signal_max=args.signal_max,
        feedback_round=None,
    )

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
