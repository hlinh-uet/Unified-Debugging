import os
import json
import argparse
import io
import re
import sys
import uuid
from contextlib import contextmanager, redirect_stdout
from datetime import datetime, timezone

from data_loaders.base_loader import get_loader
from core.fault_localization import (
    calculate_fault_localization,
    calculate_fault_localization_class_level,
    calculate_fault_localization_file_level,
    calculate_ir_reranked_class_scores,
    calculate_ir_reranked_file_scores,
    calculate_ir_reranked_function_scores,
    _extract_class_from_key,
    _extract_file_from_key,
)
from core.apr_baseline import run_apr_pipeline
from core.apr.revalidate import run_apr_validation_only
from core.apr.agent.refix import run_refix_from_saved_artifacts
from core.apr.common import is_plausible_status
from core.apr.oracle_target_identity import build_valid_oracle_targets
from core.reupdate_fl import update_fl_from_apr, write_json
from core.test_filtering import (
    filter_zero_coverage_pass_tests,
    filtered_bug_record_for_pipeline,
    has_failed_tests,
)
from evaluation.eval_fl import evaluate_fl
from evaluation.eval_apr import evaluate_apr
from configs.path import EXPERIMENTS_DIR


VALID_FL_RESULTS_FILENAME = "fault_localization_results_valid.json"
VALID_APR_RESULTS_FILENAME = "apr_results_valid.json"
FULL_PIPELINE_DIRNAME = "full_pipeline_runs"
FULL_PIPELINE_DEFAULT_ROUNDS = 2


def _extract_file_from_gt(gt_key):
    """
    Trích xuất tên file từ ground truth key.
    Hỗ trợ cả dạng 'file.c:function', 'file.h:class::method',
    và 'path/to/file.c::function'.
    """
    import re

    # Tìm dấu ':' đơn đầu tiên (không phải '::')
    match = re.search(r'(?<!:):(?!:)', gt_key)
    if match:
        file_part = gt_key[:match.start()]
        return os.path.basename(file_part) if file_part else gt_key

    # Fallback: chỉ có '::'
    if "::" in gt_key:
        src_path = gt_key.rsplit("::", 1)[0]
        return os.path.basename(src_path)

    return gt_key


def _extract_class_from_gt(gt_key):
    return _extract_class_from_key(gt_key)


def run_fl(
    dataset: str = "codeflaws",
    exclude_fixed_fail_tests: bool = True,
    results_dir: str = None,
):
    """
    Bước 1 – Fault Localization (Tarantula).
    Tính điểm Tarantula ở 3 mức rồi rerank bằng IR metadata:
      - Function-level → fault_localization_function_results.json
      - File-level     → fault_localization_file_results.json
      - Class-level    → fault_localization_class_results.json
    Pipeline:
      1. Tarantula file → IR reranker → file_score
      2. Tarantula class + file_score → IR reranker → class_score
      3. Tarantula function + class/file_score → IR reranker → final function score
      → fault_localization_results.json
    """
    print(f"[FL] Đang load bugs từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bugs = loader.load_all()
    print(f"[FL] Đã load {len(bugs)} bugs.")

    if not bugs:
        print(f"[FL] Không tìm thấy bug nào. Kiểm tra lại đường dẫn dataset '{dataset}'.")
        return

    output_dir = os.path.abspath(results_dir or EXPERIMENTS_DIR)
    os.makedirs(output_dir, exist_ok=True)

    func_results = {}
    file_results = {}
    class_results = {}
    combined_results = {}

    total_excluded_fixed_fail = 0
    total_excluded_zero_coverage = 0

    for bug in bugs:
        print(f"[FL] Tính điểm Tarantula cho {bug.bug_id}...")
        bug_for_fl, excluded_fixed_fail = filtered_bug_record_for_pipeline(
            bug,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        zero_test_noop_excluded = (
            (bug_for_fl.raw or {}).get("pipeline_excluded_zero_test_noop_tests", [])
            if bug_for_fl and isinstance(bug_for_fl.raw, dict)
            else []
        )
        fl_tests, fl_zero_coverage_excluded = filter_zero_coverage_pass_tests(
            bug_for_fl.tests if bug_for_fl else []
        )
        zero_coverage_excluded = list(dict.fromkeys([
            *zero_test_noop_excluded,
            *fl_zero_coverage_excluded,
        ]))
        total_excluded_fixed_fail += len(excluded_fixed_fail)
        total_excluded_zero_coverage += len(zero_coverage_excluded)
        if excluded_fixed_fail:
            print(
                f"    [FL] Loại {len(excluded_fixed_fail)} test buggy+fixed đều FAIL "
                "khỏi FL."
            )
        if zero_coverage_excluded:
            print(
                f"    [FL] Loại {len(zero_coverage_excluded)} test PASS nhưng coverage rỗng "
                "khỏi FL/APR scope."
            )

        tests_for_fl = fl_tests
        if exclude_fixed_fail_tests and not has_failed_tests(tests_for_fl):
            print("    [FL] Không còn failed test actionable sau khi lọc; ghi score rỗng.")
            tarantula_func_scores = {}
            tarantula_file_scores = {}
            tarantula_class_scores = {}
            file_scores = {}
            class_scores = {}
            func_scores = {}
        else:
            # --- Raw Tarantula scores ---
            tarantula_func_scores = calculate_fault_localization(tests_for_fl)
            tarantula_file_scores = calculate_fault_localization_file_level(tests_for_fl)
            tarantula_class_scores = calculate_fault_localization_class_level(tests_for_fl)

            functions_by_file = {}
            functions_by_class = {}
            for func_key in tarantula_func_scores:
                file_key = _extract_file_from_key(func_key)
                functions_by_file.setdefault(file_key, []).append(func_key)

                class_key = _extract_class_from_key(func_key)
                if class_key:
                    functions_by_class.setdefault(class_key, []).append(func_key)

            # --- 1. File-level: Tarantula file → IR reranker → file_score ---
            file_scores = calculate_ir_reranked_file_scores(
                tests_for_fl,
                tarantula_file_scores,
                functions_by_file=functions_by_file,
            )

            # --- 2. Class-level: Tarantula class + file_score → IR reranker → class_score ---
            class_scores = calculate_ir_reranked_class_scores(
                tests_for_fl,
                tarantula_class_scores,
                file_scores,
                functions_by_class=functions_by_class,
            )

            # --- 3. Function-level: Tarantula function + class/file score → IR reranker ---
            func_scores = calculate_ir_reranked_function_scores(
                tests_for_fl,
                tarantula_func_scores,
                class_scores,
                file_scores,
            )

        # --- Ground truth cho file-level / class-level ---
        gt_functions = bug.ground_truth  # list[str], ví dụ: ["file.c:func"]
        gt_files = list(set(_extract_file_from_gt(g) for g in gt_functions))
        gt_classes = sorted(
            set(c for g in gt_functions for c in [_extract_class_from_gt(g)] if c)
        )

        # Lưu function-level
        test_filter_info = {
            "exclude_fixed_fail_tests": exclude_fixed_fail_tests,
            "excluded_fixed_fail_count": len(excluded_fixed_fail),
            "excluded_fixed_fail_tests": list(excluded_fixed_fail),
            "excluded_zero_coverage_pass_count": len(zero_coverage_excluded),
            "excluded_zero_coverage_pass_tests": list(zero_coverage_excluded),
        }

        func_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       func_scores,
            "tarantula_scores": tarantula_func_scores,
            "ground_truth": gt_functions,
            "test_filter":  test_filter_info,
        }

        # Lưu file-level
        file_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       file_scores,
            "tarantula_scores": tarantula_file_scores,
            "ground_truth": gt_files,
            "test_filter":  test_filter_info,
        }

        # Lưu class-level
        class_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       class_scores,
            "tarantula_scores": tarantula_class_scores,
            "ground_truth": gt_classes,
            "test_filter":  test_filter_info,
        }

        # Final FL score chính là function score sau pipeline 3 mức.
        combined_scores = func_scores

        combined_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "tarantula",
            "reranker":     "ir",
            "scores":       combined_scores,
            "tarantula_scores": tarantula_func_scores,
            "ground_truth": gt_functions,
            "test_filter":  test_filter_info,
        }

    if exclude_fixed_fail_tests:
        print(f"[FL] Đã loại tổng cộng {total_excluded_fixed_fail} test buggy+fixed đều FAIL.")
    print(f"[FL] Đã loại tổng cộng {total_excluded_zero_coverage} test PASS có coverage rỗng.")

    # --- Ghi file function-level ---
    func_file = os.path.join(output_dir, "fault_localization_function_results.json")
    with open(func_file, "w") as f:
        json.dump(func_results, f, indent=4)
    print(f"[FL] Function-level scores → {func_file}")

    # --- Ghi file file-level ---
    file_file = os.path.join(output_dir, "fault_localization_file_results.json")
    with open(file_file, "w") as f:
        json.dump(file_results, f, indent=4)
    print(f"[FL] File-level scores     → {file_file}")

    # --- Ghi file class-level ---
    class_file = os.path.join(output_dir, "fault_localization_class_results.json")
    with open(class_file, "w") as f:
        json.dump(class_results, f, indent=4)
    print(f"[FL] Class-level scores    → {class_file}")

    # --- Ghi file combined ---
    combined_file = os.path.join(output_dir, "fault_localization_results.json")
    with open(combined_file, "w") as f:
        json.dump(combined_results, f, indent=4)
    print(f"[FL] Final FL scores (file→class→function IR rerank) → {combined_file}")


def run_valid_fl(
    dataset: str = "codeflaws",
    exclude_fixed_fail_tests: bool = True,
    results_dir: str = None,
) -> str:
    """
    Oracle FL cho kịch bản APR-only: đưa ground-truth function lên top 1.
    File này tách khỏi FL thường để không trộn kết quả Tarantula/IR.
    """
    print(f"[FL-valid] Đang load bugs từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bugs = loader.load_all()
    print(f"[FL-valid] Đã load {len(bugs)} bugs.")

    output_dir = os.path.abspath(results_dir or EXPERIMENTS_DIR)
    os.makedirs(output_dir, exist_ok=True)
    valid_results = {}
    total_excluded_fixed_fail = 0
    total_excluded_zero_coverage = 0
    missing_gt = 0
    exact_target_count = 0
    unresolved_exact_target_count = 0

    for bug in bugs:
        bug_for_valid, excluded_fixed_fail = filtered_bug_record_for_pipeline(
            bug,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        zero_test_noop_excluded = (
            (bug_for_valid.raw or {}).get("pipeline_excluded_zero_test_noop_tests", [])
            if bug_for_valid and isinstance(bug_for_valid.raw, dict)
            else []
        )
        _valid_tests, valid_zero_coverage_excluded = filter_zero_coverage_pass_tests(
            bug_for_valid.tests if bug_for_valid else []
        )
        zero_coverage_excluded = list(dict.fromkeys([
            *zero_test_noop_excluded,
            *valid_zero_coverage_excluded,
        ]))
        total_excluded_fixed_fail += len(excluded_fixed_fail)
        total_excluded_zero_coverage += len(zero_coverage_excluded)

        gt_functions = list(dict.fromkeys(bug.ground_truth or []))
        oracle_top1 = gt_functions[0] if gt_functions else ""
        if not oracle_top1:
            missing_gt += 1
        oracle_resolution = build_valid_oracle_targets(
            bug,
            ground_truth_groups=[oracle_top1] if oracle_top1 else [],
        )
        exact_targets = list(oracle_resolution.get("targets") or [])
        exact_target_count += len(exact_targets)
        if oracle_top1 and not exact_targets:
            unresolved_exact_target_count += 1
            print(
                f"    [FL-valid] {bug.bug_id}: không resolve được exact AST oracle target "
                f"({', '.join(oracle_resolution.get('diagnostics') or ['unknown'])})."
            )

        test_filter_info = {
            "exclude_fixed_fail_tests": exclude_fixed_fail_tests,
            "excluded_fixed_fail_count": len(excluded_fixed_fail),
            "excluded_fixed_fail_tests": list(excluded_fixed_fail),
            "excluded_zero_coverage_pass_count": len(zero_coverage_excluded),
            "excluded_zero_coverage_pass_tests": list(zero_coverage_excluded),
        }
        scores = {oracle_top1: 1.0} if oracle_top1 else {}
        valid_results[bug.bug_id] = {
            "dataset": dataset,
            "formula": "oracle",
            "reranker": "ground_truth_top1",
            "scores": scores,
            "tarantula_scores": {},
            "ground_truth": gt_functions,
            "oracle_top1": oracle_top1,
            "exact_targets": exact_targets,
            "exact_target_resolution": oracle_resolution,
            "valid_mode": True,
            "test_filter": test_filter_info,
        }

    if exclude_fixed_fail_tests:
        print(
            f"[FL-valid] Đã ghi metadata lọc cho {total_excluded_fixed_fail} "
            "test buggy+fixed đều FAIL."
        )
    print(
        f"[FL-valid] Đã ghi metadata lọc cho {total_excluded_zero_coverage} "
        "test PASS có coverage rỗng."
    )
    if missing_gt:
        print(f"[FL-valid] Cảnh báo: {missing_gt} bugs không có ground-truth function.")
    print(
        f"[FL-valid] Exact AST oracle targets: {exact_target_count}; "
        f"unresolved bugs: {unresolved_exact_target_count}."
    )

    out_file = os.path.join(output_dir, VALID_FL_RESULTS_FILENAME)
    with open(out_file, "w") as f:
        json.dump(valid_results, f, indent=4)
    print(f"[FL-valid] Oracle top-1 FL → {out_file}")
    return out_file


class _Tee(io.TextIOBase):
    """Mirror evaluation output to the terminal and a persistent report."""

    def __init__(self, *streams):
        self.streams = streams

    def write(self, text):
        for stream in self.streams:
            stream.write(text)
        return len(text)

    def flush(self):
        for stream in self.streams:
            stream.flush()


def _safe_run_part(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", str(value or "")).strip("._-")
    return text or "unknown"


def _new_full_run_id() -> str:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    return f"{stamp}_{uuid.uuid4().hex[:8]}"


def _relpath(path: str, root: str) -> str:
    return os.path.relpath(os.path.abspath(path), os.path.abspath(root))


@contextmanager
def _apr_round_environment(
    *,
    round_dir: str,
    dataset: str,
    round_index: int,
):
    """Scope all mutable APR outputs to one full-pipeline round."""
    updates = {
        "APR_RUNTIME_DIR": os.path.abspath(round_dir),
        "APR_LLM_PATCHES_DIR": os.path.join(os.path.abspath(round_dir), "llm_patches"),
        "APR_PATCHES_DIR": os.path.join(os.path.abspath(round_dir), "patches"),
        "APR_RUN_DATASET": dataset,
        "APR_RUN_ROUND": str(round_index),
    }
    previous = {key: os.environ.get(key) for key in updates}
    os.environ.update(updates)
    try:
        yield
    finally:
        for key, value in previous.items():
            if value is None:
                os.environ.pop(key, None)
            else:
                os.environ[key] = value


def _write_round_evaluation(
    *,
    dataset: str,
    round_dir: str,
    round_index: int,
    has_updated_fl: bool,
    apr_results_filename: str = "apr_results.json",
) -> str:
    """Run and persist the complete FL/APR console report for one round."""
    report_path = os.path.join(round_dir, "evaluation.txt")
    with open(report_path, "w") as report:
        tee = _Tee(sys.stdout, report)
        with redirect_stdout(tee):
            print(
                f"\n[Full] Evaluation vòng {round_index}: "
                "FL input + APR"
                + (" + FL sau APR feedback" if has_updated_fl else "")
            )
            evaluate_fl(dataset, level="combined", results_dir=round_dir)
            if has_updated_fl:
                evaluate_fl(dataset, level="apr_feedback", results_dir=round_dir)
            evaluate_apr(
                dataset,
                results_filename=apr_results_filename,
                label=f"LLM-based APR — full round {round_index}",
                results_dir=round_dir,
            )
    return report_path


def run_full_pipeline(
    dataset: str,
    *,
    rounds: int = FULL_PIPELINE_DEFAULT_ROUNDS,
    llm_provider: str = None,
    exclude_fixed_fail_tests: bool = True,
    only_missing: bool = False,
    apr_strength: float = 1.0,
    same_file_weight: float = 0.0,
    output_root: str = None,
    run_id: str = None,
) -> str:
    """Run FL once, then APR → FL update for the requested APR rounds.

    Every round is isolated under its own directory.  The FL feedback produced
    after round N becomes ``fault_localization_results.json`` for round N+1.
    """
    if rounds < 1:
        raise ValueError("Số vòng APR của --full phải >= 1.")

    full_root = os.path.abspath(
        output_root or os.path.join(EXPERIMENTS_DIR, FULL_PIPELINE_DIRNAME)
    )
    dataset_dir = os.path.join(full_root, _safe_run_part(dataset))
    selected_run_id = _safe_run_part(run_id or _new_full_run_id())
    run_dir = os.path.join(dataset_dir, selected_run_id)
    if os.path.exists(run_dir):
        raise FileExistsError(f"Full-pipeline run đã tồn tại: {run_dir}")
    os.makedirs(run_dir, exist_ok=False)

    run_manifest_path = os.path.join(run_dir, "run_manifest.json")
    run_manifest = {
        "schema": "unified_debugging.full_pipeline.v1",
        "run_id": selected_run_id,
        "dataset": dataset,
        "round_count": rounds,
        "llm_provider": llm_provider or "default",
        "exclude_fixed_fail_tests": exclude_fixed_fail_tests,
        "apr_strength": apr_strength,
        "same_file_weight": same_file_weight,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "rounds": [],
    }
    write_json(run_manifest_path, run_manifest)

    print(
        f"[Full] Bắt đầu pipeline '{dataset}' với {rounds} vòng APR. "
        f"Run dir: {run_dir}"
    )

    active_round_manifest = None
    active_round_manifest_path = ""
    converged_bug_ids = set()
    cumulative_apr_results = {}
    stop_reason = ""
    try:
        first_round_dir = os.path.join(run_dir, "round_01")
        os.makedirs(first_round_dir, exist_ok=False)
        run_fl(
            dataset,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            results_dir=first_round_dir,
        )

        for round_index in range(1, rounds + 1):
            round_dir = os.path.join(run_dir, f"round_{round_index:02d}")
            os.makedirs(round_dir, exist_ok=True)
            input_fl_path = os.path.join(
                round_dir,
                "fault_localization_results.json",
            )
            if not os.path.isfile(input_fl_path):
                raise FileNotFoundError(
                    f"Thiếu FL input cho vòng {round_index}: {input_fl_path}"
                )
            with open(input_fl_path, "r") as stream:
                round_fl_results = json.load(stream)
            scored_bug_ids = {
                str(bug_id)
                for bug_id, record in round_fl_results.items()
                if isinstance(record, dict)
                and isinstance(record.get("scores"), dict)
                and record.get("scores")
            }
            active_bug_ids = scored_bug_ids - converged_bug_ids
            if not active_bug_ids:
                stop_reason = "no_unresolved_scored_bugs"
                print(
                    f"[Full] Dừng trước vòng {round_index}: không còn bug có "
                    "FL scores cần APR."
                )
                break

            apr_results_path = os.path.join(round_dir, "apr_results.json")
            cumulative_apr_results_path = os.path.join(
                round_dir,
                "apr_results_cumulative.json",
            )
            llm_patches_dir = os.path.join(round_dir, "llm_patches")
            patches_dir = os.path.join(round_dir, "patches")
            os.makedirs(llm_patches_dir, exist_ok=True)
            os.makedirs(patches_dir, exist_ok=True)
            round_manifest = {
                "schema": "unified_debugging.full_pipeline.round.v1",
                "round": round_index,
                "status": "running",
                "input_fl": _relpath(input_fl_path, run_dir),
                "apr_results": _relpath(apr_results_path, run_dir),
                "llm_patches_dir": _relpath(llm_patches_dir, run_dir),
                "patches_dir": _relpath(patches_dir, run_dir),
                "active_bug_count": len(active_bug_ids),
                "active_bug_ids": sorted(active_bug_ids),
                "skipped_plausible_bug_ids": sorted(converged_bug_ids),
            }
            round_manifest_path = os.path.join(round_dir, "round_manifest.json")
            write_json(round_manifest_path, round_manifest)
            active_round_manifest = round_manifest
            active_round_manifest_path = round_manifest_path

            print(
                f"\n[Full] Vòng {round_index}/{rounds}: APR dùng "
                f"{input_fl_path}"
            )
            with _apr_round_environment(
                round_dir=round_dir,
                dataset=dataset,
                round_index=round_index,
            ):
                run_apr_pipeline(
                    dataset,
                    llm_provider=llm_provider,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                    fl_results_filename=input_fl_path,
                    apr_results_filename=apr_results_path,
                    only_missing=only_missing,
                    skip_bug_ids=converged_bug_ids,
                )

            if not os.path.isfile(apr_results_path):
                raise RuntimeError(
                    f"APR vòng {round_index} không tạo kết quả: {apr_results_path}"
                )

            with open(apr_results_path, "r") as stream:
                current_apr_results = json.load(stream)
            for bug_id, result in current_apr_results.items():
                previous = cumulative_apr_results.get(bug_id)
                if isinstance(previous, dict) and is_plausible_status(
                    previous.get("status")
                ):
                    continue
                cumulative_apr_results[bug_id] = result

            plausible_this_round = {
                str(bug_id)
                for bug_id, result in current_apr_results.items()
                if isinstance(result, dict)
                and is_plausible_status(result.get("status"))
            }
            converged_bug_ids.update(plausible_this_round)
            unresolved_bug_ids = scored_bug_ids - converged_bug_ids
            write_json(cumulative_apr_results_path, cumulative_apr_results)
            round_manifest["apr_results_cumulative"] = _relpath(
                cumulative_apr_results_path,
                run_dir,
            )
            round_manifest["plausible_bug_ids"] = sorted(plausible_this_round)
            round_manifest["cumulative_plausible_bug_ids"] = sorted(
                converged_bug_ids
            )
            round_manifest["unresolved_bug_count"] = len(unresolved_bug_ids)

            should_continue = round_index < rounds and bool(unresolved_bug_ids)
            has_updated_fl = should_continue
            if has_updated_fl:
                feedback_path = os.path.join(
                    round_dir,
                    "fault_localization_apr_feedback_results.json",
                )
                updated_results, update_summary = update_fl_from_apr(
                    fl_path=input_fl_path,
                    apr_path=apr_results_path,
                    llm_patches_dir=llm_patches_dir,
                    output_path=feedback_path,
                    apr_strength=apr_strength,
                    file_weight=same_file_weight,
                    skip_bug_ids=converged_bug_ids,
                )
                next_round_dir = os.path.join(
                    run_dir,
                    f"round_{round_index + 1:02d}",
                )
                os.makedirs(next_round_dir, exist_ok=True)
                next_fl_path = os.path.join(
                    next_round_dir,
                    "fault_localization_results.json",
                )
                write_json(next_fl_path, updated_results)
                round_manifest["updated_fl"] = _relpath(feedback_path, run_dir)
                round_manifest["next_round_fl"] = _relpath(next_fl_path, run_dir)
                round_manifest["fl_update_summary"] = update_summary
                print(
                    f"[Full] Vòng {round_index}: Update FL "
                    f"{update_summary['updated_records']}/"
                    f"{update_summary['total_fl_records']} records → {next_fl_path}"
                )
            elif round_index < rounds:
                stop_reason = "all_scored_bugs_plausible"
                round_manifest["early_stop"] = True
                round_manifest["stop_reason"] = stop_reason
                print(
                    f"[Full] Dừng sớm sau vòng {round_index}: toàn bộ "
                    f"{len(scored_bug_ids)} bug có FL scores đã plausible."
                )

            evaluation_path = _write_round_evaluation(
                dataset=dataset,
                round_dir=round_dir,
                round_index=round_index,
                has_updated_fl=has_updated_fl,
                apr_results_filename="apr_results_cumulative.json",
            )
            round_manifest["evaluation"] = _relpath(evaluation_path, run_dir)
            round_manifest["status"] = "complete"
            write_json(round_manifest_path, round_manifest)
            run_manifest["rounds"].append(round_manifest)
            write_json(run_manifest_path, run_manifest)
            active_round_manifest = None
            active_round_manifest_path = ""
            if stop_reason:
                break

        run_manifest["status"] = "complete"
        run_manifest["completed_round_count"] = len(run_manifest["rounds"])
        run_manifest["early_stopped"] = bool(
            stop_reason and len(run_manifest["rounds"]) < rounds
        )
        run_manifest["stop_reason"] = stop_reason
        run_manifest["cumulative_plausible_bug_ids"] = sorted(converged_bug_ids)
        run_manifest["completed_at"] = datetime.now(timezone.utc).isoformat()
        write_json(run_manifest_path, run_manifest)
        os.makedirs(dataset_dir, exist_ok=True)
        write_json(
            os.path.join(dataset_dir, "latest.json"),
            {
                "run_id": selected_run_id,
                "run_dir": _relpath(run_dir, dataset_dir),
                "manifest": _relpath(run_manifest_path, dataset_dir),
                "round_count": rounds,
                "completed_round_count": len(run_manifest["rounds"]),
                "early_stopped": run_manifest["early_stopped"],
                "stop_reason": stop_reason,
                "status": "complete",
            },
        )
    except Exception as exc:
        if active_round_manifest is not None and active_round_manifest_path:
            active_round_manifest["status"] = "failed"
            active_round_manifest["error"] = f"{type(exc).__name__}: {exc}"
            write_json(active_round_manifest_path, active_round_manifest)
            if not any(
                item.get("round") == active_round_manifest.get("round")
                for item in run_manifest["rounds"]
            ):
                run_manifest["rounds"].append(active_round_manifest)
        run_manifest["status"] = "failed"
        run_manifest["error"] = f"{type(exc).__name__}: {exc}"
        run_manifest["failed_at"] = datetime.now(timezone.utc).isoformat()
        write_json(run_manifest_path, run_manifest)
        raise

    print(f"[Full] Hoàn tất {rounds} vòng. Manifest: {run_manifest_path}")
    return run_dir


def main():
    parser = argparse.ArgumentParser(description="Unified Debugging Pipeline")
    parser.add_argument(
        "--dataset", default="codeflaws",
        help="Tên dataset cần chạy: codeflaws (mặc định), defects4c, ..."
    )
    parser.add_argument("--fl",           action="store_true", help="Chỉ chạy Fault Localization (Tarantula)")
    parser.add_argument("--apr",          action="store_true", help="Chỉ chạy APR với LLM")
    parser.add_argument("--apr-validate", action="store_true", help="Chỉ validate lại các patch LLM đã lưu, không gọi LLM")
    parser.add_argument("--refix",        action="store_true", help="Chạy ReFix từ llm_patches đã lưu")
    parser.add_argument("--eval",         action="store_true", help="Chỉ chạy Evaluation")
    parser.add_argument("--all",          action="store_true", help="Chạy toàn bộ: FL → APR → Evaluation")
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "Chạy pipeline lặp đầy đủ: FL → APR → Update FL → APR...; "
            "mỗi vòng có artifact và evaluation riêng."
        ),
    )
    parser.add_argument(
        "--full-rounds",
        "--rounds",
        dest="full_rounds",
        type=int,
        default=FULL_PIPELINE_DEFAULT_ROUNDS,
        help=(
            "Tổng số vòng APR khi dùng --full (mặc định: 2). "
            "Update FL được chạy giữa hai vòng liên tiếp."
        ),
    )
    parser.add_argument(
        "--full-apr-strength",
        type=float,
        default=1.0,
        help="Trọng số APR feedback khi Update FL trong --full (mặc định: 1.0).",
    )
    parser.add_argument(
        "--full-same-file-weight",
        type=float,
        default=0.0,
        help=(
            "Lan truyền positive APR feedback sang function cùng file trong "
            "--full (mặc định: 0.0)."
        ),
    )
    parser.add_argument(
        "--valid",
        action="store_true",
        help=(
            "Chạy kịch bản APR với FL oracle: exact changed AST target ở top 1, "
            "lưu vào fault_localization_results_valid.json và APR chỉ thử top 1."
        ),
    )
    parser.add_argument("--bug-id",       default=None, help="Chỉ chạy trên một bug cụ thể, ví dụ CVE-2018-7584")
    parser.add_argument(
        "--with-refix",
        action="store_true",
        help="Sau APR, chạy thêm ReFix trên các patch LLM đã fail rồi mới evaluation.",
    )
    parser.add_argument(
        "--only-missing",
        action="store_true",
        help=(
            "APR chỉ chạy bug chưa có thư mục experiments/llm_patches/<bug-id>; "
            "giữ nguyên và không retry artifact đã tồn tại."
        ),
    )
    parser.add_argument(
        "--include-fixed-fail-tests",
        action="store_true",
        help=(
            "Không loại các test có outcome=FAIL và outcome_fixed=FAIL. "
            "Mặc định FL/APR sẽ loại các test này."
        ),
    )
    parser.add_argument(
        "--fl-eval-level",
        default="combined",
        choices=["combined", "valid", "apr_feedback", "function", "file", "class", "all"],
        help=(
            "Mức kết quả FL dùng khi evaluation: combined "
            "(fault_localization_results.json), valid "
            "(fault_localization_results_valid.json), apr_feedback "
            "(fault_localization_apr_feedback_results.json), function "
            "(fault_localization_function_results.json), file "
            "(fault_localization_file_results.json), class "
            "(fault_localization_class_results.json), hoặc all."
        ),
    )
    parser.add_argument(
        "--llm",
        default=None,
        choices=["openai", "openrouter"],
        help="LLM provider cho APR: openai hoặc openrouter. "
             "Override biến môi trường LLM_PROVIDER.",
    )
    args = parser.parse_args()

    dataset      = args.dataset
    llm_provider = args.llm   # None → đọc từ LLM_PROVIDER trong .env
    fl_eval_level = "valid" if args.valid and args.fl_eval_level == "combined" else args.fl_eval_level
    exclude_fixed_fail_tests = not args.include_fixed_fail_tests

    if not (
        args.full
        or args.all
        or args.fl
        or args.apr
        or args.apr_validate
        or args.refix
        or args.eval
    ):
        parser.error(
            "Hãy chọn một mode: --full, --fl, --apr, --apr-validate, "
            "--refix, --eval, hoặc --all."
        )

    if args.full:
        other_modes = (
            args.all
            or args.fl
            or args.apr
            or args.apr_validate
            or args.refix
            or args.eval
        )
        if other_modes:
            parser.error("--full không dùng đồng thời với mode khác.")
        if args.valid:
            parser.error("--full hiện dùng FL thực; không dùng đồng thời với --valid.")
        if args.with_refix:
            parser.error(
                "--full không cần --with-refix vì APR đã chạy ReFix nội tuyến."
            )
        if args.bug_id:
            parser.error("--bug-id chưa áp dụng cho --full; hãy chọn dataset riêng.")
        if args.full_rounds < 1:
            parser.error("--full-rounds/--rounds phải >= 1.")
        run_full_pipeline(
            dataset,
            rounds=args.full_rounds,
            llm_provider=llm_provider,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            only_missing=args.only_missing,
            apr_strength=args.full_apr_strength,
            same_file_weight=args.full_same_file_weight,
        )
        return

    run_all = args.all

    if run_all:
        print(f"[Pipeline] Chạy toàn bộ quy trình trên dataset '{dataset}' (FL → APR LLM → Evaluation)...")
        if args.valid:
            run_valid_fl(dataset, exclude_fixed_fail_tests=exclude_fixed_fail_tests)
        else:
            run_fl(dataset, exclude_fixed_fail_tests=exclude_fixed_fail_tests)
        run_apr_pipeline(
            dataset,
            llm_provider=llm_provider,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            fl_results_filename=VALID_FL_RESULTS_FILENAME if args.valid else "fault_localization_results.json",
            apr_results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
            apr_top_k=1 if args.valid else None,
            valid_mode=args.valid,
            only_missing=args.only_missing,
        )
        if args.with_refix:
            run_refix_from_saved_artifacts(
                dataset,
                bug_id=args.bug_id,
                llm_provider=llm_provider,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                apr_results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
            )
        evaluate_fl(dataset, level=fl_eval_level)
        evaluate_apr(
            dataset,
            results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
            label="LLM-based APR (valid FL)" if args.valid else "LLM-based APR",
        )
    else:
        if args.fl:
            print(f"[Pipeline] Chạy Fault Localization trên dataset '{dataset}'...")
            if args.valid:
                run_valid_fl(dataset, exclude_fixed_fail_tests=exclude_fixed_fail_tests)
            else:
                run_fl(dataset, exclude_fixed_fail_tests=exclude_fixed_fail_tests)
            evaluate_fl(dataset, level=fl_eval_level)

        if args.apr:
            if args.valid:
                print(
                    f"[Pipeline] Chạy APR-valid (LLM: {llm_provider or 'default'}) "
                    f"trên dataset '{dataset}'..."
                )
                run_valid_fl(dataset, exclude_fixed_fail_tests=exclude_fixed_fail_tests)
            else:
                print(f"[Pipeline] Chạy APR (LLM: {llm_provider or 'default'}) trên dataset '{dataset}'...")
            run_apr_pipeline(
                dataset,
                llm_provider=llm_provider,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                fl_results_filename=VALID_FL_RESULTS_FILENAME if args.valid else "fault_localization_results.json",
                apr_results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
                apr_top_k=1 if args.valid else None,
                valid_mode=args.valid,
                only_missing=args.only_missing,
            )
            if args.with_refix:
                run_refix_from_saved_artifacts(
                    dataset,
                    bug_id=args.bug_id,
                    llm_provider=llm_provider,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                    apr_results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
                )
            evaluate_apr(
                dataset,
                results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
                label="LLM-based APR (valid FL)" if args.valid else "LLM-based APR",
            )

        if args.apr_validate:
            print(f"[Pipeline] Validate lại APR artifacts trên dataset '{dataset}'...")
            run_apr_validation_only(
                dataset,
                bug_id=args.bug_id,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                apr_results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
            )
            evaluate_apr(
                dataset,
                results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
                label="LLM-based APR (valid FL)" if args.valid else "LLM-based APR",
            )

        if args.refix:
            print(f"[Pipeline] Chạy ReFix từ artifacts đã lưu trên dataset '{dataset}'...")
            run_refix_from_saved_artifacts(
                dataset,
                bug_id=args.bug_id,
                llm_provider=llm_provider,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                apr_results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
            )
            evaluate_apr(
                dataset,
                results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
                label="LLM-based APR (valid FL)" if args.valid else "LLM-based APR",
            )

        if args.eval:
            print("[Pipeline] Chạy Evaluation...")
            evaluate_fl(dataset, level=fl_eval_level)
            evaluate_apr(
                dataset,
                results_filename=VALID_APR_RESULTS_FILENAME if args.valid else "apr_results.json",
                label="LLM-based APR (valid FL)" if args.valid else "LLM-based APR",
            )


if __name__ == "__main__":
    main()
