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
    calculate_causal_hierarchy_scores,
    _extract_class_from_key,
)
from core.fault_localization.runtime import compact_runtime_evidence
from core.fault_localization.artifacts import (
    atomic_write_json,
    load_bug_localization_checkpoints,
    write_causal_evidence_artifact,
    write_bug_localization_checkpoint,
)
from core.apr_baseline import run_apr_pipeline
from core.apr.revalidate import run_apr_validation_only
from core.apr.agent.refix import run_refix_from_saved_artifacts
from core.apr.common import (
    APR_TOP_K,
    is_plausible_status,
    select_untried_fl_functions,
)
from core.apr.oracle_target_identity import build_valid_oracle_targets
from core.fault_localization.update import update_fl_from_apr, write_json
from core.test_filtering import (
    filtered_bug_record_for_pipeline,
    has_failed_tests,
)
from core.failure_context import (
    build_regression_fail_context,
    fail_context_runtime_dir,
    run_fail_context_agent,
)
from evaluation.eval_fl import evaluate_fl
from evaluation.eval_apr import evaluate_apr
from configs.path import EXPERIMENTS_DIR


VALID_FL_RESULTS_FILENAME = "fault_localization_results_valid.json"
VALID_APR_RESULTS_FILENAME = "apr_results_valid.json"
FULL_PIPELINE_DIRNAME = "full_pipeline_runs"
FULL_PIPELINE_DEFAULT_ROUNDS = 2
FL_DEFAULT_LLM_PROVIDER = "openrouter"


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
    llm_provider: str = None,
    llm_rerank: bool = True,
    refresh_runtime_traces: bool = False,
    cache_only: bool = False,
    include_bug_ids: set = None,
):
    """
    Bước 1 – Input/output-guided dynamic Fault Localization.
    Chạy regression failed tests để dựng shared Fail Context từ fresh output
    và exact test input, sau đó rank theo selective trace/failure contract:
      - Function-level → fault_localization_function_results.json
      - File-level     → fault_localization_file_results.json
      - Class-level    → fault_localization_class_results.json

    Output ``scores`` giữ nguyên schema cũ để APR và vòng Update FL không cần
    thay đổi. Coverage production-source có sẵn trong metadata chỉ xác định
    candidate universe; count/edge census và detailed scope đều không dùng
    ground truth hay spectrum score để xếp hạng.
    """
    print(f"[FL] Đang load bugs từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bugs = loader.load_all()
    requested_bug_ids = {
        str(bug_id).strip()
        for bug_id in (include_bug_ids or set())
        if str(bug_id).strip()
    }
    if requested_bug_ids:
        bugs = [
            bug for bug in bugs
            if str(bug.bug_id) in requested_bug_ids
        ]
        print(
            f"[FL] Chọn {len(bugs)}/{len(requested_bug_ids)} bug theo "
            "per-bug pipeline."
        )
    else:
        print(f"[FL] Đã load {len(bugs)} bugs.")

    if not bugs:
        print(f"[FL] Không tìm thấy bug nào. Kiểm tra lại đường dẫn dataset '{dataset}'.")
        return

    output_dir = os.path.abspath(results_dir or EXPERIMENTS_DIR)
    os.makedirs(output_dir, exist_ok=True)
    fl_llm_provider = (
        str(llm_provider or FL_DEFAULT_LLM_PROVIDER).strip().lower()
    )
    if llm_rerank:
        print(
            f"[FL] LLM trace guide mặc định: {fl_llm_provider} "
            "(dùng cùng lớp cấu hình/API key với APR)."
        )
    func_results = {}
    file_results = {}
    class_results = {}
    combined_results = {}
    if requested_bug_ids:
        result_maps = (
            (
                "fault_localization_function_results.json",
                func_results,
            ),
            (
                "fault_localization_file_results.json",
                file_results,
            ),
            (
                "fault_localization_class_results.json",
                class_results,
            ),
            (
                "fault_localization_results.json",
                combined_results,
            ),
        )
        for filename, target in result_maps:
            path = os.path.join(output_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as stream:
                    previous = json.load(stream)
            except (
                OSError,
                UnicodeError,
                json.JSONDecodeError,
            ):
                previous = {}
            if not isinstance(previous, dict):
                continue
            for previous_bug_id, record in previous.items():
                if (
                    isinstance(record, dict)
                    and str(record.get("dataset") or "") == str(dataset)
                ):
                    target[str(previous_bug_id)] = record

    progress_records = {}
    recovered_bug_ids = set()
    recovered = load_bug_localization_checkpoints(
        output_dir=output_dir,
    )
    recovered_manifest = recovered.get("manifest") or {}
    if (
        recovered_manifest
        and recovered_manifest.get("aggregate_materialized") is False
    ):
        selected_ids = {
            str(bug.bug_id) for bug in bugs
        }
        for level, target in (
            ("function", func_results),
            ("file", file_results),
            ("class", class_results),
            ("combined", combined_results),
        ):
            for recovered_bug_id, record in (
                (recovered.get(level) or {}).items()
            ):
                if (
                    recovered_bug_id in selected_ids
                    and isinstance(record, dict)
                    and str(record.get("dataset") or "")
                    == str(dataset)
                ):
                    target[recovered_bug_id] = record
        recovered_bug_ids = {
            bug_id
            for bug_id in (
                set(recovered.get("checkpoint_paths") or {})
                & selected_ids
            )
            if all(
                isinstance(
                    (recovered.get(level) or {}).get(bug_id),
                    dict,
                )
                and str(
                    (
                        (recovered.get(level) or {}).get(bug_id)
                        or {}
                    ).get("dataset")
                    or ""
                )
                == str(dataset)
                for level in (
                    "function",
                    "file",
                    "class",
                    "combined",
                )
            )
        }
        progress_records.update({
            bug_id: path
            for bug_id, path in (
                recovered.get("checkpoint_paths") or {}
            ).items()
            if bug_id in recovered_bug_ids
        })
        if recovered_bug_ids:
            print(
                f"[FL] Khôi phục {len(recovered_bug_ids)} bug từ "
                "per-bug checkpoint chưa materialize."
            )

    total_excluded_fixed_fail = 0
    processed_count = 0
    for bug in bugs:
        if (
            str(bug.bug_id) in recovered_bug_ids
            and not refresh_runtime_traces
        ):
            processed_count += 1
            print(
                f"[FL] Resume {bug.bug_id}: dùng checkpoint hoàn chỉnh."
            )
            continue
        print(f"[FL] Input/output runtime localization cho {bug.bug_id}...")
        bug_for_fl, excluded_fixed_fail = filtered_bug_record_for_pipeline(
            bug,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        total_excluded_fixed_fail += len(excluded_fixed_fail)
        if excluded_fixed_fail:
            print(
                f"    [FL] Loại {len(excluded_fixed_fail)} test buggy+fixed đều FAIL "
                "khỏi FL."
            )

        trace_dir = fail_context_runtime_dir(
            root=EXPERIMENTS_DIR,
            dataset=dataset,
            bug_id=bug.bug_id,
        )
        tests_for_fl = bug_for_fl.tests if bug_for_fl else []
        fail_context = None
        fail_context_artifact = ""
        if exclude_fixed_fail_tests and not has_failed_tests(tests_for_fl):
            print("    [FL] Không còn failed test actionable sau khi lọc; ghi score rỗng.")
            file_scores = {}
            class_scores = {}
            func_scores = {}
            causal_evidence = {
                "version": 8,
                "engine": "scenario_first_input_aware_causal_trace",
                "ground_truth_used": False,
                "tests": [],
                "diagnostics": ["no_actionable_failed_tests"],
            }
            fail_context = build_regression_fail_context(bug_for_fl)
            causal_evidence["fail_context"] = fail_context
            causal_evidence["fail_context_id"] = fail_context.get(
                "context_id",
                "",
            )
        else:
            if refresh_runtime_traces:
                print("    [FailContext] Ép refresh runtime evidence.")
            fail_context_run = run_fail_context_agent(
                bug=bug_for_fl,
                artifact_dir=trace_dir,
                refresh_runtime=refresh_runtime_traces,
                cache_only=cache_only,
                query_llm_provider=fl_llm_provider,
                query_llm_enabled=llm_rerank,
            )
            if fail_context_run.get("status") in {
                "cache_miss",
                "cache_incomplete",
            }:
                print(
                    "    [FailContext] Cache-only không có full ordered "
                    "runtime evidence hợp lệ; bỏ qua bug này."
                )
                continue
            runtime_evidence = (
                fail_context_run.get("runtime_evidence") or {}
            )
            cache_info = fail_context_run.get("runtime_cache") or {}
            if cache_info.get("hit"):
                cache_kind = (
                    "full"
                    if cache_info.get("full_ordered_events")
                    else "legacy/compact"
                )
                print(
                    f"    [FailContext] Runtime cache HIT ({cache_kind}); "
                    "không build/chạy regression test lại."
                )
            else:
                print(
                    "    [FailContext] Runtime cache MISS; regression "
                    "evidence đã được thu thập."
                )
            fail_context = fail_context_run.get("fail_context") or {}
            fail_context_artifact = str(
                fail_context_run.get("fail_context_artifact") or ""
            )
            print(
                "    [FailContext] Shared context "
                f"{fail_context.get('context_id') or 'unavailable'}: "
                f"{len(fail_context.get('tests') or [])} failing test(s), "
                f"artifact={fail_context_artifact or 'unavailable'}."
            )
            for trace_test in runtime_evidence.get("tests") or []:
                trace_scope = trace_test.get("trace_scope") or {}
                if trace_scope.get("enabled"):
                    print(
                        "    [FL] Census → detailed trace scope "
                        f"{trace_test.get('test_id')}: "
                        f"{trace_scope.get('matched_function_count', 0)} "
                        "functions, "
                        f"{trace_scope.get('range_count', 0)} ranges."
                    )
                    if trace_scope.get("selection_strategy"):
                        print(
                            "    [FL] Query-driven trace budget: "
                            f"{trace_scope.get('estimated_total_event_count', 0)} "
                            "/ "
                            f"{trace_scope.get('detailed_event_budget', 0)} "
                            "events; "
                            f"{trace_scope.get('path_function_count', 0)} "
                            "path functions, "
                            f"{trace_scope.get('slice_probe_count', 0)} "
                            "source probes, "
                            f"{trace_scope.get('aggregate_only_function_count', 0)} "
                            "hot/aggregate-only functions."
                        )
                elif trace_scope.get("diagnostics"):
                    print(
                        "    [FL] Census/detailed trace scope fallback: "
                        f"{trace_scope.get('diagnostics')[0]}"
                    )
                retry_count = int(
                    trace_test.get("adaptive_trace_retry_count") or 0
                )
                if retry_count:
                    mode = (
                        "scenario-window"
                        if trace_test.get("scenario_window")
                        else "full"
                    )
                    print(
                        "    [FL] Adaptive trace "
                        f"{trace_test.get('test_id')}: "
                        f"{retry_count} retry, "
                        f"limit={trace_test.get('trace_event_limit')}, "
                        f"mode={mode}, "
                        f"complete={trace_test.get('trace_complete')}"
                    )
                elif (
                    trace_test.get("trace_truncated")
                    and trace_test.get("trace_collection_strategy")
                    == "bounded_slice_single_pass"
                ):
                    print(
                        "    [FL] Ordered slice reached its budget "
                        f"{trace_test.get('trace_event_limit')} events; "
                        "giữ census aggregate và query completeness cho "
                        "phần còn lại."
                    )
                query_evidence = (
                    trace_test.get("trace_query_evidence") or {}
                )
                if query_evidence:
                    print(
                        "    [FL] TraceQuery "
                        f"{trace_test.get('test_id')}: "
                        f"status={query_evidence.get('status')}, "
                        "probe_recovery="
                        f"{bool(query_evidence.get('probe_recovery_used'))}, "
                        "answers="
                        f"{query_evidence.get('status_counts') or {}}."
                    )
            full_cache_path = str(
                fail_context_run.get(
                    "full_runtime_cache_artifact"
                )
                or ""
            )
            if full_cache_path:
                print(
                    "    [FailContext] Bounded runtime evidence cache → "
                    f"{full_cache_path}"
                )
            if not runtime_evidence.get("fresh_execution"):
                print(
                    "    [FL] Không thu được fresh runtime trace; "
                    "không fallback sang coverage metadata."
                )
                runtime_diagnostics = list(dict.fromkeys(
                    str(value)
                    for value in (
                        runtime_evidence.get("diagnostics") or []
                    )
                    if str(value)
                ))
                if runtime_diagnostics:
                    print(
                        "    [FL] Diagnostics: "
                        + ", ".join(runtime_diagnostics[:8])
                    )
                compile_record = runtime_evidence.get("compile") or {}
                if compile_record.get("returncode") not in {None, 0}:
                    print(
                        "    [FL] Compile log: "
                        f"{compile_record.get('artifact') or 'unavailable'}"
                    )
                func_scores = {}
                file_scores = {}
                class_scores = {}
                causal_evidence = {
                    "version": 8,
                    "engine": "scenario_first_input_aware_causal_trace",
                    "ground_truth_used": False,
                    "tests": [],
                    "runtime_trace": compact_runtime_evidence(
                        runtime_evidence
                    ),
                    "diagnostics": list(dict.fromkeys([
                        "fresh_runtime_trace_unavailable",
                        *(runtime_evidence.get("diagnostics") or []),
                    ])),
                    "fail_context": fail_context,
                    "fail_context_id": fail_context.get(
                        "context_id",
                        "",
                    ),
                    "fail_context_artifact": fail_context_artifact,
                }
            else:
                (
                    func_scores,
                    file_scores,
                    class_scores,
                    causal_evidence,
                ) = calculate_causal_hierarchy_scores(
                    bug=bug_for_fl,
                    runtime_evidence=runtime_evidence,
                    llm_provider=fl_llm_provider,
                    llm_rerank=llm_rerank,
                    artifact_dir=trace_dir,
                    fail_context=fail_context,
                )
                causal_evidence["fail_context_artifact"] = (
                    fail_context_artifact
                )

        causal_evidence_ref = write_causal_evidence_artifact(
            artifact_dir=trace_dir,
            bug_id=bug.bug_id,
            evidence=causal_evidence,
        )
        causal_evidence_summary = _causal_evidence_summary(
            causal_evidence
        )
        causal_result_fields = {
            "causal_evidence_ref": causal_evidence_ref,
            "causal_evidence_summary": causal_evidence_summary,
        }
        if not causal_evidence_ref.get("path"):
            # A failed artifact write must not make the result unusable.
            causal_result_fields["causal_evidence"] = (
                causal_evidence
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
            "regression_only_runtime_trace": True,
        }

        func_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "evidence_driven_causal_proofs_v8",
            "reranker":     (
                "scenario+llm_trace_plan+causal_tiers"
                if llm_rerank
                else "scenario+deterministic_trace_plan+causal_tiers"
            ),
            "scores":       func_scores,
            "ground_truth": gt_functions,
            "test_filter":  test_filter_info,
            **causal_result_fields,
        }

        # Lưu file-level
        file_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "evidence_driven_causal_proofs_v8",
            "reranker":     (
                "scenario+llm_trace_plan+causal_tiers"
                if llm_rerank
                else "scenario+deterministic_trace_plan+causal_tiers"
            ),
            "scores":       file_scores,
            "ground_truth": gt_files,
            "test_filter":  test_filter_info,
            **causal_result_fields,
        }

        # Lưu class-level
        class_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "evidence_driven_causal_proofs_v8",
            "reranker":     (
                "scenario+llm_trace_plan+causal_tiers"
                if llm_rerank
                else "scenario+deterministic_trace_plan+causal_tiers"
            ),
            "scores":       class_scores,
            "ground_truth": gt_classes,
            "test_filter":  test_filter_info,
            **causal_result_fields,
        }

        # Final FL score chính là function score sau pipeline 3 mức.
        combined_scores = func_scores

        combined_results[bug.bug_id] = {
            "dataset":      dataset,
            "formula":      "evidence_driven_causal_proofs_v8",
            "reranker":     (
                "scenario+llm_trace_plan+causal_tiers"
                if llm_rerank
                else "scenario+deterministic_trace_plan+causal_tiers"
            ),
            "scores":       combined_scores,
            "ground_truth": gt_functions,
            "test_filter":  test_filter_info,
            **causal_result_fields,
        }
        checkpoint_path = write_bug_localization_checkpoint(
            artifact_dir=output_dir,
            bug_id=bug.bug_id,
            function_result=func_results[bug.bug_id],
            file_result=file_results[bug.bug_id],
            class_result=class_results[bug.bug_id],
            combined_result=combined_results[bug.bug_id],
        )
        progress_records[bug.bug_id] = checkpoint_path
        processed_count += 1
        _checkpoint_fl_progress(
            output_dir=output_dir,
            checkpoint_paths=progress_records,
            aggregate_materialized=False,
        )
        print(
            f"    [FL] Checkpoint {processed_count}/{len(bugs)} bug đã hoàn tất."
        )

    if exclude_fixed_fail_tests:
        print(f"[FL] Đã loại tổng cộng {total_excluded_fixed_fail} test buggy+fixed đều FAIL.")

    # --- Ghi file function-level ---
    func_file = os.path.join(output_dir, "fault_localization_function_results.json")
    atomic_write_json(func_file, func_results, indent=4)
    print(f"[FL] Function-level scores → {func_file}")

    # --- Ghi file file-level ---
    file_file = os.path.join(output_dir, "fault_localization_file_results.json")
    atomic_write_json(file_file, file_results, indent=4)
    print(f"[FL] File-level scores     → {file_file}")

    # --- Ghi file class-level ---
    class_file = os.path.join(output_dir, "fault_localization_class_results.json")
    atomic_write_json(class_file, class_results, indent=4)
    print(f"[FL] Class-level scores    → {class_file}")

    # --- Ghi file combined ---
    combined_file = os.path.join(output_dir, "fault_localization_results.json")
    atomic_write_json(combined_file, combined_results, indent=4)
    print(f"[FL] Final input/output dynamic-trace FL scores → {combined_file}")
    _checkpoint_fl_progress(
        output_dir=output_dir,
        checkpoint_paths=progress_records,
        aggregate_materialized=True,
    )
    if cache_only:
        print(
            f"[FL] Cache-only hoàn tất: đánh giá được {processed_count}/"
            f"{len(bugs)} bug đã có cache."
        )


def _checkpoint_fl_progress(
    *,
    output_dir: str,
    checkpoint_paths: dict,
    aggregate_materialized: bool,
) -> None:
    """Checkpoint O(number-of-bugs) references, not four growing payloads."""
    atomic_write_json(
        os.path.join(
            output_dir, "fault_localization_progress.json"
        ),
        {
            "schema": "unified_debugging.fl_progress.v2",
            "aggregate_materialized": bool(
                aggregate_materialized
            ),
            "completed_bug_count": len(checkpoint_paths),
            "bug_checkpoints": checkpoint_paths,
        },
        indent=2,
    )


def _causal_evidence_summary(evidence: dict) -> dict:
    """Keep file/class result files compact while retaining audit metadata."""
    ranking = evidence.get("ranking") or {}
    slicing = evidence.get("dynamic_producer_slicing") or {}
    scenarios = evidence.get("scenario_analysis") or {}
    first_scenario = scenarios.get("first_failing_scenario") or {}
    trace_plan = evidence.get("trace_plan") or {}
    tiers = evidence.get("causal_tiers") or {}
    probes = evidence.get("probe_evidence") or {}
    broker = (
        (evidence.get("runtime_trace") or {}).get(
            "investigation_query_broker"
        )
        or {}
    )
    return {
        "version": evidence.get("version"),
        "engine": evidence.get("engine"),
        "ground_truth_used": evidence.get("ground_truth_used", False),
        "fail_context_id": evidence.get("fail_context_id", ""),
        "fail_context_artifact": evidence.get(
            "fail_context_artifact",
            "",
        ),
        "failed_test_count": len(evidence.get("tests") or []),
        "candidate_count": ranking.get("candidate_count", 0),
        "formula": ranking.get("formula", ""),
        "dynamic_producer_slicing_used": bool(
            ranking.get("dynamic_producer_slicing_used")
        ),
        "producer_invocation_count": len(slicing.get("invocations") or []),
        "first_failing_scenario_id": first_scenario.get("scenario_id"),
        "trace_plan_mode": trace_plan.get("mode"),
        "supported_hypothesis_count": tiers.get(
            "supported_hypothesis_count", 0
        ),
        "source_dossier_count": tiers.get("source_dossier_count", 0),
        "probe_observed_count": probes.get("observed_count", 0),
        "probe_build_pass_limit": broker.get(
            "probe_build_pass_limit", 0
        ),
        "post_ranking_runtime_passes": broker.get(
            "post_ranking_runtime_passes", 0
        ),
        "broker_planned_probe_count": broker.get(
            "planned_probe_count", 0
        ),
        "first_bad_transformation_confirmed": bool(
            tiers.get("first_bad_transformation_confirmed")
        ),
        "boundary_data_gap": tiers.get("boundary_data_gap") or "",
        "diagnostics": evidence.get("diagnostics") or [],
    }


def run_valid_fl(
    dataset: str = "codeflaws",
    exclude_fixed_fail_tests: bool = True,
    results_dir: str = None,
) -> str:
    """
    Oracle FL cho kịch bản APR-only: đưa ground-truth function lên top 1.
    File này tách khỏi FL thường để không trộn kết quả causal FL.
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
    bug_id: str = "",
):
    """Scope all mutable APR outputs to one full-pipeline round."""
    updates = {
        "APR_RUNTIME_DIR": os.path.abspath(round_dir),
        "APR_LLM_PATCHES_DIR": os.path.join(os.path.abspath(round_dir), "llm_patches"),
        "APR_PATCHES_DIR": os.path.join(os.path.abspath(round_dir), "patches"),
        "APR_RUN_DATASET": dataset,
        "APR_RUN_ROUND": str(round_index),
        "APR_RUN_BUG_ID": str(bug_id or ""),
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
    bug_id: str = "",
) -> str:
    """Run and persist the complete FL/APR console report for one round."""
    report_path = os.path.join(round_dir, "evaluation.txt")
    with open(report_path, "w") as report:
        tee = _Tee(sys.stdout, report)
        with redirect_stdout(tee):
            print(
                f"\n[Full] Evaluation "
                + (f"bug {bug_id}, " if bug_id else "")
                + f"vòng {round_index}: FL input + APR"
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


def _write_full_run_evaluation(*, dataset: str, run_dir: str) -> str:
    """Persist aggregate evaluation after every bug-major full run."""
    report_path = os.path.join(run_dir, "evaluation.txt")
    with open(report_path, "w") as report:
        tee = _Tee(sys.stdout, report)
        with redirect_stdout(tee):
            print("\n[Full] Evaluation tổng hợp per-bug pipeline")
            evaluate_fl(dataset, level="combined", results_dir=run_dir)
            evaluate_fl(dataset, level="apr_feedback", results_dir=run_dir)
            evaluate_apr(
                dataset,
                results_filename="apr_results_cumulative.json",
                label="LLM-based APR — per-bug unified pipeline",
                results_dir=run_dir,
            )
    return report_path


def _apr_consumed_functions(apr_result: dict) -> set:
    """Return exact FL keys consumed by one APR round."""
    if not isinstance(apr_result, dict):
        return set()
    values = apr_result.get("attempted_functions") or []
    if not values:
        values = (
            (apr_result.get("candidate_selection") or {}).get(
                "selected_functions"
            )
            or []
        )
    if not values and apr_result.get("selected_function"):
        values = [apr_result["selected_function"]]
    return {
        str(value).strip()
        for value in values
        if str(value).strip()
    }


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
    fl_llm_rerank: bool = True,
    refresh_runtime_traces: bool = False,
    bug_ids: set = None,
) -> str:
    """Run the complete FL → APR → feedback loop for one bug at a time.

    Bug N is fully converged or exhausts its APR-round budget before bug N+1
    starts.  Per-bug artifacts remain isolated while aggregate result files are
    checkpointed at run level after each completed bug.
    """
    if rounds < 1:
        raise ValueError("Số vòng APR tối đa cho mỗi bug phải >= 1.")

    requested_bug_ids = {
        str(bug_id).strip()
        for bug_id in (bug_ids or set())
        if str(bug_id).strip()
    }
    loader = get_loader(dataset)
    dataset_bugs = loader.load_all()
    selected_bugs = [
        bug for bug in dataset_bugs
        if not requested_bug_ids or str(bug.bug_id) in requested_bug_ids
    ]
    found_bug_ids = {str(bug.bug_id) for bug in selected_bugs}
    missing_bug_ids = sorted(requested_bug_ids - found_bug_ids)
    if missing_bug_ids:
        raise ValueError(
            "Không tìm thấy bug trong dataset "
            f"'{dataset}': {', '.join(missing_bug_ids)}"
        )
    if not selected_bugs:
        raise ValueError(f"Dataset '{dataset}' không có bug để chạy.")

    full_root = os.path.abspath(
        output_root or os.path.join(EXPERIMENTS_DIR, FULL_PIPELINE_DIRNAME)
    )
    dataset_dir = os.path.join(full_root, _safe_run_part(dataset))
    selected_run_id = _safe_run_part(run_id or _new_full_run_id())
    run_dir = os.path.join(dataset_dir, selected_run_id)
    if os.path.exists(run_dir):
        raise FileExistsError(f"Full-pipeline run đã tồn tại: {run_dir}")
    bugs_root = os.path.join(run_dir, "bugs")
    os.makedirs(bugs_root, exist_ok=False)

    run_manifest_path = os.path.join(run_dir, "run_manifest.json")
    run_manifest = {
        "schema": "unified_debugging.full_pipeline.v2",
        "execution_order": "bug_major",
        "run_id": selected_run_id,
        "dataset": dataset,
        "bug_count": len(selected_bugs),
        "bug_ids": [str(bug.bug_id) for bug in selected_bugs],
        "round_count": rounds,
        "max_rounds_per_bug": rounds,
        "llm_provider": llm_provider or "default",
        "fl_llm_guide": bool(fl_llm_rerank),
        "fl_llm_provider": (
            llm_provider or FL_DEFAULT_LLM_PROVIDER
            if fl_llm_rerank else "disabled"
        ),
        "exclude_fixed_fail_tests": exclude_fixed_fail_tests,
        "apr_strength": apr_strength,
        "same_file_weight": same_file_weight,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "status": "running",
        "bugs": [],
    }
    write_json(run_manifest_path, run_manifest)

    print(
        f"[Full] Bắt đầu per-bug pipeline '{dataset}': "
        f"{len(selected_bugs)} bug, tối đa {rounds} vòng/bug. "
        f"Run dir: {run_dir}"
    )

    fl_result_filenames = (
        "fault_localization_results.json",
        "fault_localization_function_results.json",
        "fault_localization_file_results.json",
        "fault_localization_class_results.json",
    )
    aggregate_fl_results = {
        filename: {} for filename in fl_result_filenames
    }
    aggregate_final_fl_results = {}
    aggregate_apr_results = {}
    plausible_bug_ids = set()
    completed_round_count = 0
    active_bug_manifest = None
    active_bug_manifest_path = ""
    active_round_manifest = None
    active_round_manifest_path = ""

    try:
        for bug_index, bug in enumerate(selected_bugs, start=1):
            bug_id = str(bug.bug_id)
            bug_dir = os.path.join(
                bugs_root,
                f"bug_{bug_index:03d}__{_safe_run_part(bug_id)}",
            )
            os.makedirs(bug_dir, exist_ok=False)
            bug_manifest_path = os.path.join(bug_dir, "bug_manifest.json")
            bug_manifest = {
                "schema": "unified_debugging.full_pipeline.bug.v1",
                "bug_index": bug_index,
                "bug_id": bug_id,
                "status": "running",
                "max_rounds": rounds,
                "rounds": [],
                "started_at": datetime.now(timezone.utc).isoformat(),
            }
            write_json(bug_manifest_path, bug_manifest)
            active_bug_manifest = bug_manifest
            active_bug_manifest_path = bug_manifest_path
            run_manifest["active_bug"] = {
                "bug_index": bug_index,
                "bug_id": bug_id,
                "manifest": _relpath(bug_manifest_path, run_dir),
            }
            write_json(run_manifest_path, run_manifest)

            print(
                f"\n[Full] Bug {bug_index}/{len(selected_bugs)} — {bug_id}: "
                "bắt đầu FL → APR → Update FL."
            )
            first_round_dir = os.path.join(bug_dir, "round_01")
            os.makedirs(first_round_dir, exist_ok=False)
            run_fl(
                dataset,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                results_dir=first_round_dir,
                llm_provider=llm_provider,
                llm_rerank=fl_llm_rerank,
                refresh_runtime_traces=refresh_runtime_traces,
                include_bug_ids={bug_id},
            )

            for filename in fl_result_filenames:
                path = os.path.join(first_round_dir, filename)
                if not os.path.isfile(path):
                    continue
                with open(path, "r") as stream:
                    one_bug_results = json.load(stream)
                if bug_id in one_bug_results:
                    aggregate_fl_results[filename][bug_id] = one_bug_results[
                        bug_id
                    ]
                    write_json(
                        os.path.join(run_dir, filename),
                        aggregate_fl_results[filename],
                    )

            base_record = aggregate_fl_results[
                "fault_localization_results.json"
            ].get(bug_id)
            if not isinstance(base_record, dict):
                raise RuntimeError(
                    f"FL không tạo record cho bug {bug_id}."
                )

            latest_bug_fl_results = {bug_id: base_record}
            bug_apr_results = {}
            bug_converged = False
            bug_stop_reason = ""
            attempted_fl_functions = set()
            scores = base_record.get("scores") or {}
            if not isinstance(scores, dict) or not scores:
                bug_stop_reason = "missing_fl_scores"
                print(
                    f"[Full] Bug {bug_id}: FL không có scores; bỏ qua APR."
                )
            else:
                for round_index in range(1, rounds + 1):
                    round_dir = os.path.join(
                        bug_dir,
                        f"round_{round_index:02d}",
                    )
                    os.makedirs(round_dir, exist_ok=True)
                    input_fl_path = os.path.join(
                        round_dir,
                        "fault_localization_results.json",
                    )
                    if not os.path.isfile(input_fl_path):
                        raise FileNotFoundError(
                            f"Thiếu FL input cho {bug_id}, vòng "
                            f"{round_index}: {input_fl_path}"
                        )

                    apr_results_path = os.path.join(
                        round_dir,
                        "apr_results.json",
                    )
                    cumulative_apr_path = os.path.join(
                        round_dir,
                        "apr_results_cumulative.json",
                    )
                    llm_patches_dir = os.path.join(
                        round_dir,
                        "llm_patches",
                    )
                    patches_dir = os.path.join(round_dir, "patches")
                    os.makedirs(llm_patches_dir, exist_ok=True)
                    os.makedirs(patches_dir, exist_ok=True)
                    round_manifest = {
                        "schema": (
                            "unified_debugging.full_pipeline.bug_round.v1"
                        ),
                        "bug_id": bug_id,
                        "round": round_index,
                        "status": "running",
                        "input_fl": _relpath(input_fl_path, bug_dir),
                        "apr_results": _relpath(
                            apr_results_path,
                            bug_dir,
                        ),
                        "llm_patches_dir": _relpath(
                            llm_patches_dir,
                            bug_dir,
                        ),
                        "patches_dir": _relpath(patches_dir, bug_dir),
                    }
                    round_manifest_path = os.path.join(
                        round_dir,
                        "round_manifest.json",
                    )
                    write_json(round_manifest_path, round_manifest)
                    active_round_manifest = round_manifest
                    active_round_manifest_path = round_manifest_path

                    print(
                        f"[Full] Bug {bug_id}, vòng "
                        f"{round_index}/{rounds}: APR."
                    )
                    with _apr_round_environment(
                        round_dir=round_dir,
                        dataset=dataset,
                        round_index=round_index,
                        bug_id=bug_id,
                    ):
                        run_apr_pipeline(
                            dataset,
                            llm_provider=llm_provider,
                            exclude_fixed_fail_tests=(
                                exclude_fixed_fail_tests
                            ),
                            fl_results_filename=input_fl_path,
                            apr_results_filename=apr_results_path,
                            only_missing=only_missing,
                            skip_bug_ids=set(),
                            exclude_functions_by_bug={
                                bug_id: set(
                                    attempted_fl_functions
                                ),
                            },
                        )

                    if not os.path.isfile(apr_results_path):
                        raise RuntimeError(
                            f"APR không tạo kết quả cho {bug_id}, "
                            f"vòng {round_index}: {apr_results_path}"
                        )
                    with open(apr_results_path, "r") as stream:
                        current_apr_results = json.load(stream)
                    current_result = current_apr_results.get(bug_id)
                    candidate_space_exhausted = (
                        isinstance(current_result, dict)
                        and current_result.get("validation_error")
                        == "no_untried_fl_candidates"
                    )
                    round_attempted_functions = (
                        _apr_consumed_functions(current_result)
                    )
                    attempted_fl_functions.update(
                        round_attempted_functions
                    )
                    if isinstance(current_result, dict):
                        previous = bug_apr_results.get(bug_id)
                        if (
                            not candidate_space_exhausted
                            and not (
                                isinstance(previous, dict)
                                and is_plausible_status(
                                    previous.get("status")
                                )
                            )
                        ):
                            bug_apr_results[bug_id] = current_result
                        elif previous is None:
                            bug_apr_results[bug_id] = current_result
                    write_json(cumulative_apr_path, bug_apr_results)

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
                        skip_bug_ids=set(),
                        feedback_round=round_index,
                    )
                    latest_bug_fl_results = updated_results
                    bug_converged = (
                        isinstance(current_result, dict)
                        and is_plausible_status(
                            current_result.get("status")
                        )
                    )
                    next_round_selection = {}
                    if (
                        not bug_converged
                        and not candidate_space_exhausted
                        and round_index < rounds
                    ):
                        next_record = (
                            updated_results.get(bug_id) or {}
                        )
                        next_scores = (
                            next_record.get("scores") or {}
                            if isinstance(next_record, dict)
                            else {}
                        )
                        (
                            next_round_candidates,
                            next_round_selection,
                        ) = select_untried_fl_functions(
                            next_scores,
                            top_k=APR_TOP_K,
                            excluded_functions=(
                                attempted_fl_functions
                            ),
                        )
                        candidate_space_exhausted = not bool(
                            next_round_candidates
                        )

                    round_manifest["apr_results_cumulative"] = _relpath(
                        cumulative_apr_path,
                        bug_dir,
                    )
                    round_manifest["updated_fl"] = _relpath(
                        feedback_path,
                        bug_dir,
                    )
                    round_manifest["fl_update_summary"] = update_summary
                    round_manifest["plausible"] = bug_converged
                    round_manifest["candidate_selection"] = (
                        (current_result or {}).get(
                            "candidate_selection"
                        )
                        if isinstance(current_result, dict)
                        else {}
                    )
                    round_manifest["attempted_functions"] = sorted(
                        round_attempted_functions
                    )
                    round_manifest[
                        "cumulative_attempted_functions"
                    ] = sorted(attempted_fl_functions)
                    if bug_converged:
                        bug_stop_reason = "plausible_converged"
                        round_manifest["stop_reason"] = bug_stop_reason
                    elif candidate_space_exhausted:
                        bug_stop_reason = "candidate_space_exhausted"
                        round_manifest["stop_reason"] = bug_stop_reason
                        if next_round_selection:
                            round_manifest[
                                "next_round_candidate_selection"
                            ] = next_round_selection
                    elif round_index < rounds:
                        next_round_dir = os.path.join(
                            bug_dir,
                            f"round_{round_index + 1:02d}",
                        )
                        os.makedirs(next_round_dir, exist_ok=True)
                        next_fl_path = os.path.join(
                            next_round_dir,
                            "fault_localization_results.json",
                        )
                        write_json(next_fl_path, updated_results)
                        round_manifest["next_round_fl"] = _relpath(
                            next_fl_path,
                            bug_dir,
                        )
                        round_manifest[
                            "next_round_candidate_selection"
                        ] = next_round_selection
                    else:
                        bug_stop_reason = "max_rounds_exhausted"
                        round_manifest["stop_reason"] = bug_stop_reason

                    evaluation_path = _write_round_evaluation(
                        dataset=dataset,
                        round_dir=round_dir,
                        round_index=round_index,
                        has_updated_fl=True,
                        apr_results_filename=(
                            "apr_results_cumulative.json"
                        ),
                        bug_id=bug_id,
                    )
                    round_manifest["evaluation"] = _relpath(
                        evaluation_path,
                        bug_dir,
                    )
                    round_manifest["status"] = "complete"
                    write_json(round_manifest_path, round_manifest)
                    bug_manifest["rounds"].append(round_manifest)
                    bug_manifest["completed_round_count"] = len(
                        bug_manifest["rounds"]
                    )
                    write_json(bug_manifest_path, bug_manifest)
                    completed_round_count += 1
                    active_round_manifest = None
                    active_round_manifest_path = ""
                    if bug_converged or candidate_space_exhausted:
                        break

            aggregate_final_fl_results[bug_id] = (
                latest_bug_fl_results.get(bug_id, base_record)
            )
            if bug_id in bug_apr_results:
                aggregate_apr_results[bug_id] = bug_apr_results[bug_id]
            if bug_converged:
                plausible_bug_ids.add(bug_id)

            bug_final_fl_path = os.path.join(
                bug_dir,
                "fault_localization_apr_feedback_results.json",
            )
            bug_final_apr_path = os.path.join(
                bug_dir,
                "apr_results_cumulative.json",
            )
            write_json(bug_final_fl_path, latest_bug_fl_results)
            write_json(bug_final_apr_path, bug_apr_results)
            write_json(
                os.path.join(
                    run_dir,
                    "fault_localization_apr_feedback_results.json",
                ),
                aggregate_final_fl_results,
            )
            write_json(
                os.path.join(run_dir, "apr_results_cumulative.json"),
                aggregate_apr_results,
            )

            bug_manifest["status"] = "complete"
            bug_manifest["outcome"] = (
                "plausible" if bug_converged else "unresolved"
            )
            bug_manifest["stop_reason"] = (
                bug_stop_reason or "complete"
            )
            bug_manifest["completed_round_count"] = len(
                bug_manifest["rounds"]
            )
            bug_manifest["attempted_functions"] = sorted(
                attempted_fl_functions
            )
            bug_manifest["final_fl_results"] = _relpath(
                bug_final_fl_path,
                bug_dir,
            )
            bug_manifest["final_apr_results"] = _relpath(
                bug_final_apr_path,
                bug_dir,
            )
            bug_manifest["completed_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            write_json(bug_manifest_path, bug_manifest)
            run_manifest["bugs"].append({
                "bug_index": bug_index,
                "bug_id": bug_id,
                "status": bug_manifest["status"],
                "outcome": bug_manifest["outcome"],
                "stop_reason": bug_manifest["stop_reason"],
                "completed_round_count": bug_manifest[
                    "completed_round_count"
                ],
                "manifest": _relpath(bug_manifest_path, run_dir),
            })
            run_manifest["completed_bug_count"] = len(
                run_manifest["bugs"]
            )
            run_manifest["completed_round_count"] = completed_round_count
            run_manifest["plausible_bug_ids"] = sorted(
                plausible_bug_ids
            )
            write_json(run_manifest_path, run_manifest)
            active_bug_manifest = None
            active_bug_manifest_path = ""
            run_manifest.pop("active_bug", None)
            write_json(run_manifest_path, run_manifest)
            print(
                f"[Full] Bug {bug_id}: {bug_manifest['outcome']} sau "
                f"{bug_manifest['completed_round_count']} vòng."
            )

        final_apr_path = os.path.join(
            run_dir,
            "apr_results_cumulative.json",
        )
        final_fl_path = os.path.join(
            run_dir,
            "fault_localization_apr_feedback_results.json",
        )
        write_json(final_apr_path, aggregate_apr_results)
        write_json(final_fl_path, aggregate_final_fl_results)
        evaluation_path = _write_full_run_evaluation(
            dataset=dataset,
            run_dir=run_dir,
        )
        run_manifest["status"] = "complete"
        run_manifest.pop("active_bug", None)
        run_manifest["completed_bug_count"] = len(run_manifest["bugs"])
        run_manifest["completed_round_count"] = completed_round_count
        run_manifest["plausible_bug_ids"] = sorted(plausible_bug_ids)
        run_manifest["plausible_bug_count"] = len(plausible_bug_ids)
        run_manifest["final_apr_results"] = _relpath(
            final_apr_path,
            run_dir,
        )
        run_manifest["final_fl_results"] = _relpath(
            final_fl_path,
            run_dir,
        )
        run_manifest["evaluation"] = _relpath(
            evaluation_path,
            run_dir,
        )
        run_manifest["completed_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        write_json(run_manifest_path, run_manifest)
        os.makedirs(dataset_dir, exist_ok=True)
        write_json(
            os.path.join(dataset_dir, "latest.json"),
            {
                "run_id": selected_run_id,
                "run_dir": _relpath(run_dir, dataset_dir),
                "manifest": _relpath(
                    run_manifest_path,
                    dataset_dir,
                ),
                "execution_order": "bug_major",
                "bug_count": len(selected_bugs),
                "completed_bug_count": len(run_manifest["bugs"]),
                "plausible_bug_count": len(plausible_bug_ids),
                "max_rounds_per_bug": rounds,
                "status": "complete",
            },
        )
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        if active_round_manifest is not None and active_round_manifest_path:
            active_round_manifest["status"] = "failed"
            active_round_manifest["error"] = error
            write_json(
                active_round_manifest_path,
                active_round_manifest,
            )
        if active_bug_manifest is not None and active_bug_manifest_path:
            active_bug_manifest["status"] = "failed"
            active_bug_manifest["error"] = error
            active_bug_manifest["failed_at"] = datetime.now(
                timezone.utc
            ).isoformat()
            write_json(
                active_bug_manifest_path,
                active_bug_manifest,
            )
        run_manifest["status"] = "failed"
        run_manifest["error"] = error
        run_manifest["failed_at"] = datetime.now(
            timezone.utc
        ).isoformat()
        write_json(run_manifest_path, run_manifest)
        raise

    print(
        f"[Full] Hoàn tất {len(run_manifest['bugs'])}/"
        f"{len(selected_bugs)} bug; plausible="
        f"{len(plausible_bug_ids)}. Manifest: {run_manifest_path}"
    )
    return run_dir


def main():
    parser = argparse.ArgumentParser(description="Unified Debugging Pipeline")
    parser.add_argument(
        "--dataset", default="codeflaws",
        help="Tên dataset cần chạy: codeflaws (mặc định), defects4c, ..."
    )
    parser.add_argument(
        "--fl",
        action="store_true",
        help="Chỉ chạy input/output-guided dynamic Fault Localization",
    )
    parser.add_argument("--apr",          action="store_true", help="Chỉ chạy APR với LLM")
    parser.add_argument("--apr-validate", action="store_true", help="Chỉ validate lại các patch LLM đã lưu, không gọi LLM")
    parser.add_argument("--refix",        action="store_true", help="Chạy ReFix từ llm_patches đã lưu")
    parser.add_argument("--eval",         action="store_true", help="Chỉ chạy Evaluation")
    parser.add_argument("--all",          action="store_true", help="Chạy toàn bộ: FL → APR → Evaluation")
    parser.add_argument(
        "--full",
        action="store_true",
        help=(
            "Chạy unified pipeline theo từng bug: hoàn tất "
            "FL → APR → Update FL → ... cho bug hiện tại rồi mới sang bug kế."
        ),
    )
    parser.add_argument(
        "--full-rounds",
        "--rounds",
        dest="full_rounds",
        type=int,
        default=FULL_PIPELINE_DEFAULT_ROUNDS,
        help=(
            "Số vòng APR tối đa cho mỗi bug khi dùng --full "
            "(mặc định: 2)."
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
        help=(
            "LLM provider cho APR và FL guide: openai hoặc openrouter. "
            "Nếu bỏ trống, APR đọc LLM_PROVIDER còn FL mặc định OpenRouter."
        ),
    )
    fl_llm_group = parser.add_mutually_exclusive_group()
    fl_llm_group.add_argument(
        "--fl-llm-guide",
        "--fl-llm-rerank",
        dest="fl_llm_rerank",
        action="store_true",
        help=(
            "Dùng LLM phân tích Input/Expected/Actual và lập boundary trace "
            "plan (mặc định bật). Nếu không truyền --llm, FL dùng OpenRouter "
            "và OPENROUTER_API_KEY giống APR."
        ),
    )
    fl_llm_group.add_argument(
        "--no-fl-llm-guide",
        dest="fl_llm_rerank",
        action="store_false",
        help=(
            "Tắt LLM trace guide của FL và chỉ dùng trace plan deterministic."
        ),
    )
    parser.set_defaults(fl_llm_rerank=True)
    parser.add_argument(
        "--refresh-runtime-traces",
        action="store_true",
        help=(
            "Bỏ qua runtime cache và build/chạy lại regression tests cho FL. "
            "Mặc định tái sử dụng cache hợp lệ theo từng bug."
        ),
    )
    parser.add_argument(
        "--fl-cache-only",
        action="store_true",
        help=(
            "Chỉ tổng hợp/evaluate các bug đã có runtime cache; không build "
            "hoặc chạy test cho bug còn thiếu. Chỉ dùng với --fl."
        ),
    )
    args = parser.parse_args()

    dataset      = args.dataset
    llm_provider = args.llm   # None → đọc từ LLM_PROVIDER trong .env
    fl_eval_level = "valid" if args.valid and args.fl_eval_level == "combined" else args.fl_eval_level
    exclude_fixed_fail_tests = not args.include_fixed_fail_tests
    if args.fl_cache_only and (
        not args.fl
        or args.full
        or args.all
        or args.apr
        or args.apr_validate
        or args.refix
    ):
        parser.error("--fl-cache-only chỉ dùng với mode --fl.")

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
            fl_llm_rerank=args.fl_llm_rerank,
            refresh_runtime_traces=args.refresh_runtime_traces,
            bug_ids={args.bug_id} if args.bug_id else None,
        )
        return

    run_all = args.all

    if run_all:
        print(f"[Pipeline] Chạy toàn bộ quy trình trên dataset '{dataset}' (FL → APR LLM → Evaluation)...")
        if args.valid:
            run_valid_fl(dataset, exclude_fixed_fail_tests=exclude_fixed_fail_tests)
        else:
            run_fl(
                dataset,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                llm_provider=llm_provider,
                llm_rerank=args.fl_llm_rerank,
                refresh_runtime_traces=args.refresh_runtime_traces,
            )
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
                run_fl(
                    dataset,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                    llm_provider=llm_provider,
                    llm_rerank=args.fl_llm_rerank,
                    refresh_runtime_traces=args.refresh_runtime_traces,
                    cache_only=args.fl_cache_only,
                    include_bug_ids=(
                        {args.bug_id} if args.bug_id else None
                    ),
                )
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
