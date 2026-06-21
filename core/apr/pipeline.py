import json
import os
import shutil
from typing import Optional

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR
from core.apr.agent import (
    run_fail_context_agent,
    run_fix_agent,
    run_related_code_context_agent,
    run_target_code_context_agent,
)
from core.apr.apr_utils import (
    candidate_relpath_from_buggy_tree,
    candidate_quality_key,
    is_plausible_status,
    is_defects4c_dataset,
    source_language_from_path,
)
from core.apr.artifacts import write_llm_patch_artifact
from core.apr.config import APR_SKIP_EXISTING, APR_TOP_K
from core.apr.evaluation_snapshot import (
    build_initial_test_snapshot,
    build_invalid_snapshot,
    build_validation_snapshot,
    extract_evaluation_snapshot,
)
from core.apr.validation import validate_patch
from core.apr.refix import run_refix_for_failed_artifacts
from core.test_filtering import (
    filter_bug_map_for_pipeline,
    has_failed_tests,
)
from core.utils import (
    extract_function_code,
    normalize_code_for_edit_distance,
    parse_sbfl_qualified_name,
    replace_source_range_bytes,
    resolve_fl_candidate_source_path,
    source_function_name_for_extraction,
)
from data_loaders.base_loader import get_loader
from data_loaders.sandbox_adapter import defects4c_docker_ready, get_sandbox_adapter


def _build_patch_validation_context(
    *,
    agent: str,
    bug_id: str,
    qualified_name: str,
    candidate_relpath: str,
    repair_target_file: str,
    raw_patch: str,
    patched_function: str,
    snapshot: dict,
    validation_details: dict,
    fail_context_agent_artifact: dict,
    target_code_context_agent_artifact: dict,
    related_code_context_agent_artifact: dict,
    fix_agent_artifact: dict,
) -> dict:
    """Build rich validation feedback for ReFix/debug artifacts."""
    return {
        "agent": agent,
        "bug_id": bug_id,
        "function": qualified_name,
        "repair_target_file": repair_target_file,
        "repair_target_relpath": candidate_relpath,
        "evaluation_snapshot": extract_evaluation_snapshot(snapshot),
        "raw_validation_details": validation_details or {},
        "raw_patch_excerpt": (raw_patch or "")[:8000],
        "patched_function_excerpt": (patched_function or "")[:8000],
        "fail_context_agent_artifact": fail_context_agent_artifact or {},
        "target_code_context_agent_artifact": target_code_context_agent_artifact or {},
        "related_code_context_agent_artifact": related_code_context_agent_artifact or {},
        "fix_agent_artifact": fix_agent_artifact or {},
    }


def _target_replacement_unit(target_code_context: dict, fallback_code: str) -> str:
    envelope = (target_code_context or {}).get("target_envelope") or {}
    return envelope.get("replacement_unit") or fallback_code or ""


def _target_replacement_range(target_code_context: dict, fallback_start: int, fallback_end: int) -> tuple:
    envelope = (target_code_context or {}).get("target_envelope") or {}
    replacement_range = envelope.get("replacement_range") or {}
    try:
        start = int(replacement_range.get("start_byte", fallback_start))
        end = int(replacement_range.get("end_byte", fallback_end))
    except Exception:
        return fallback_start, fallback_end
    if start < 0 or end < start:
        return fallback_start, fallback_end
    return start, end


def _target_replacement_requires_raw_unit(
    target_code_context: dict,
    fallback_start: int,
) -> bool:
    envelope = (target_code_context or {}).get("target_envelope") or {}
    replacement_range = envelope.get("replacement_range") or {}
    try:
        replacement_start = int(replacement_range.get("start_byte", fallback_start))
    except Exception:
        replacement_start = fallback_start
    return bool(envelope.get("replacement_includes_prefix")) or replacement_start != fallback_start


def _normalize_llm_replacement(
    *,
    raw_patch: str,
    target_code_context: dict,
    fallback_start: int,
    source_func_name: str,
    source_language: str,
) -> tuple:
    """Return (replacement_text, validation_error) for the target replacement range."""
    replacement = (raw_patch or "").strip()
    if "```" in replacement or "<fixed_code" in replacement.lower():
        return "", "wrapped_response"
    if not replacement:
        return "", "empty_response"

    if _target_replacement_requires_raw_unit(target_code_context, fallback_start):
        envelope = (target_code_context or {}).get("target_envelope") or {}
        prefix = str(envelope.get("replacement_prefix") or "")
        first_prefix_line = prefix.strip().splitlines()[0] if prefix.strip() else ""
        if first_prefix_line and first_prefix_line not in replacement[: max(300, len(first_prefix_line) + 20)]:
            replacement = prefix + replacement

    reparsed_func, _, _ = extract_function_code(
        replacement,
        source_func_name,
        language=source_language,
    )
    if not reparsed_func:
        return "", "malformed_function"

    if _target_replacement_requires_raw_unit(target_code_context, fallback_start):
        return replacement, ""
    return reparsed_func, ""


def _candidate_trace_record(candidate: Optional[dict], *, agent: str) -> dict:
    """Return a compact manifest entry; full patch content stays in artifact files."""
    if not candidate:
        return {}
    artifact = candidate.get("llm_patch_artifact") or {}
    return {
        "agent": agent,
        "function": candidate.get("function"),
        "score": candidate.get("score"),
        "repair_target_file": candidate.get("repair_target_file"),
        "repair_target_relpath": candidate.get("repair_target_relpath"),
        "llm_patch_artifact": artifact,
        "validation_context_path": artifact.get("validation_context_path", ""),
        "quality_key": list(candidate_quality_key(candidate)),
        **extract_evaluation_snapshot(candidate),
    }


def run_apr_pipeline(
    dataset: str = "codeflaws",
    llm_provider: Optional[str] = None,
    exclude_fixed_fail_tests: bool = True,
    fl_results_filename: str = "fault_localization_results.json",
    apr_results_filename: str = "apr_results.json",
    apr_top_k: Optional[int] = None,
    valid_mode: bool = False,
):
    """
    Pipeline APR (LLM-based).
    Load dữ liệu qua get_loader() – không đọc lại file JSON thủ công.

    Args:
        dataset:      Tên dataset (mặc định 'codeflaws').
        llm_provider: 'openai' | 'openrouter'.
                      Nếu None, đọc từ LLM_PROVIDER trong .env.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    fl_results_file = (
        fl_results_filename
        if os.path.isabs(fl_results_filename)
        else os.path.join(EXPERIMENTS_DIR, fl_results_filename)
    )
    if not os.path.exists(fl_results_file):
        print(f"[APR] Lỗi: {fl_results_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(fl_results_file, "r") as f:
        fl_results = json.load(f)
    top_k = APR_TOP_K if apr_top_k is None else apr_top_k

    ds_lc = (dataset or "").lower()
    if is_defects4c_dataset(ds_lc):
        ok_d, info_d = defects4c_docker_ready(dataset)
        if not ok_d:
            print(f"[APR] {info_d}")
            print("[APR] Dừng sớm — không gọi LLM khi chưa validate được trên Docker.")
            return
        os.environ["DEFECTS4C_CONTAINER"] = info_d
        print(f"[APR] Defects4C: dùng container '{info_d}' để validate patch.")

    print(f"[APR] Đang load bug records từ dataset '{dataset}'...")
    loader = get_loader(dataset)
    bug_map = {b.bug_id: b for b in loader.load_all()}
    bug_map, excluded_fixed_fail_by_bug = filter_bug_map_for_pipeline(
        bug_map,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    if exclude_fixed_fail_tests:
        total_excluded = sum(len(v) for v in excluded_fixed_fail_by_bug.values())
        print(
            f"[APR] Fixed-fail filtering bật: loại {total_excluded} "
            "test buggy+fixed đều FAIL khỏi context APR."
        )
    dataset_key = (dataset or "").strip().lower()
    filtered_fl_results = {}
    skipped_other_dataset = 0
    skipped_missing_bug = 0
    for bug_id, result_data in fl_results.items():
        result_dataset = ""
        if isinstance(result_data, dict):
            result_dataset = str(result_data.get("dataset") or "").strip().lower()
        if result_dataset and result_dataset != dataset_key:
            skipped_other_dataset += 1
            continue
        if bug_id not in bug_map:
            skipped_missing_bug += 1
            continue
        filtered_fl_results[bug_id] = result_data
    fl_results = filtered_fl_results
    if skipped_other_dataset or skipped_missing_bug:
        print(
            f"[APR] Bỏ qua {skipped_other_dataset} FL records khác dataset và "
            f"{skipped_missing_bug} records không có trong loader '{dataset}'."
        )

    apr_results = {}
    apr_results_file = (
        apr_results_filename
        if os.path.isabs(apr_results_filename)
        else os.path.join(EXPERIMENTS_DIR, apr_results_filename)
    )
    if os.path.exists(apr_results_file):
        try:
            with open(apr_results_file, "r") as f:
                apr_results = json.load(f)
        except Exception:
            pass
    apr_results = {
        bug_id: result
        for bug_id, result in apr_results.items()
        if bug_id in bug_map and (
            not isinstance(result, dict)
            or not result.get("dataset")
            or str(result.get("dataset")).strip().lower() == dataset_key
        )
    }

    print("[APR] Đang chạy Automated Program Repair (LLM)...")

    for bug_id, result_data in fl_results.items():
        if bug_id in apr_results:
            if APR_SKIP_EXISTING:
                print(
                    f"[APR] Bỏ qua bug {bug_id} vì đã có record trong "
                    f"{os.path.basename(apr_results_file)}."
                )
                continue
            if is_plausible_status(apr_results[bug_id].get("status")):
                print(f"[APR] Bỏ qua bug {bug_id} vì đã có patch plausible.")
                continue

        bug_record = bug_map.get(bug_id)
        excluded_fixed_fail_tests = excluded_fixed_fail_by_bug.get(bug_id, [])
        if exclude_fixed_fail_tests and bug_record and not has_failed_tests(bug_record.tests):
            print(
                f"    [APR] Bỏ qua {bug_id}: không còn failed test actionable "
                "sau khi loại buggy+fixed đều FAIL."
            )
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": valid_mode,
                "fl_results_file": os.path.basename(fl_results_file),
                "status": "skipped",
                "real_status": "skipped",
                "validation_error": "no_actionable_failed_tests_after_fixed_fail_filter",
                "fixed_fail_excluded_tests": list(excluded_fixed_fail_tests),
            }
            with open(apr_results_file, "w") as f:
                json.dump(apr_results, f, indent=4)
            continue

        scores = result_data.get("scores", result_data) if isinstance(result_data, dict) else result_data
        if not scores:
            continue

        sorted_funcs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_funcs = sorted_funcs[:top_k] if top_k > 0 else sorted_funcs
        print(f"[APR] Xử lý bug {bug_id}... (top-{top_k if top_k > 0 else 'all'})")

        try:
            adapter = get_sandbox_adapter(dataset, bug_id)
            bug_source_path = adapter.get_source_path()
        except Exception as e:
            print(f"    [Error] Không thể lấy adapter cho {bug_id}: {e}")
            continue

        if not os.path.exists(bug_source_path):
            print(f"    [Skip] File nguồn không tồn tại: {bug_source_path}")
            continue

        primary_base = os.path.basename(bug_source_path)
        raw_meta = bug_record.raw if bug_record else None
        source_cache: dict = {}

        failed_tests_context, fail_context_agent_artifact = run_fail_context_agent(
            bug=bug_record,
            bug_id=bug_id,
            llm_provider=llm_provider,
        )
        if not failed_tests_context:
            print(f"    [ERROR] FailContextAgent trả về None. Bỏ qua bug {bug_id}.")
            continue
        initial = build_initial_test_snapshot(
            bug_record.tests if bug_record else [],
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            excluded_fixed_fail_tests=excluded_fixed_fail_tests,
        )

        target_func = None
        attempted = False
        llm_attempted = False
        llm_patch_attempt_index = 0
        candidate_results = []
        best_candidate = None

        for qualified_name, score in top_funcs:
            if score == 0.0:
                continue

            file_hint, func_name = parse_sbfl_qualified_name(qualified_name)
            if not func_name:
                continue
            if is_defects4c_dataset(ds_lc) and not file_hint:
                print(f"  - [Skip] FL key thiếu file hint cho dataset nhiều file: {qualified_name}")
                continue

            candidate_path = resolve_fl_candidate_source_path(
                dataset, bug_source_path, file_hint or "", raw_meta, func_name=func_name
            )
            if not os.path.isfile(candidate_path):
                print(
                    f"  - [Skip] Không tìm thấy file nguồn cho '{qualified_name}': {candidate_path}"
                )
                continue
            if candidate_path not in source_cache:
                with open(candidate_path, "r") as f:
                    source_cache[candidate_path] = f.read()
            source_code = source_cache[candidate_path]
            candidate_relpath = candidate_relpath_from_buggy_tree(candidate_path, raw_meta)
            cand_base = os.path.basename(candidate_relpath or candidate_path)
            cand_label = candidate_relpath or cand_base

            print(f"  - Kiểm tra hàm '{func_name}' trong {cand_label} (Score: {score:.4f})")
            source_language = source_language_from_path(candidate_path)
            source_func_name = source_function_name_for_extraction(
                func_name,
                candidate_path,
                raw_meta,
            )
            if source_func_name != func_name:
                print(f"    [MAP] Symbol build '{func_name}' -> source '{source_func_name}'")
            func_code, start_idx, end_idx = extract_function_code(
                source_code,
                source_func_name,
                language=source_language,
            )
            if not func_code:
                print(f"    WARNING: Không thể trích xuất hàm {func_name}")
                continue

            target_func = qualified_name
            attempted = True

            header_context_root = ""
            if isinstance(raw_meta, dict):
                header_context_root = raw_meta.get("buggy_tree_dir") or raw_meta.get("source_repo_dir") or ""
            llm_patch_attempt_index += 1
            target_code_context, target_code_context_agent_artifact = run_target_code_context_agent(
                bug_id=bug_id,
                attempt_index=llm_patch_attempt_index,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                func_name=source_func_name,
                cand_label=cand_label,
                func_code=func_code,
                source_code=source_code,
                source_path=candidate_path,
                start_idx=start_idx,
                end_idx=end_idx,
                language=source_language,
                failed_tests_context=failed_tests_context,
            )
            related_code_context, related_code_context_agent_artifact = run_related_code_context_agent(
                bug_id=bug_id,
                attempt_index=llm_patch_attempt_index,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                func_name=source_func_name,
                cand_label=cand_label,
                func_code=func_code,
                source_code=source_code,
                source_path=candidate_path,
                start_idx=start_idx,
                end_idx=end_idx,
                context_root=header_context_root,
                target_code_context=target_code_context,
            )
            target_replacement_unit = _target_replacement_unit(target_code_context, func_code)
            replacement_start_idx, replacement_end_idx = _target_replacement_range(
                target_code_context,
                start_idx,
                end_idx,
            )

            raw_patch, fix_agent_artifact = run_fix_agent(
                bug_id=bug_id,
                attempt_index=llm_patch_attempt_index,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                llm_provider=llm_provider,
                func_name=source_func_name,
                cand_label=cand_label,
                func_code=target_replacement_unit,
                target_code_context=target_code_context,
                related_code_context=related_code_context,
                failed_tests_context=failed_tests_context,
            )
            if not raw_patch:
                print("    [ERROR] LLM trả về None. Bỏ qua hàm này.")
                continue

            llm_attempted = True
            candidate_patched_func, normalize_error = _normalize_llm_replacement(
                raw_patch=raw_patch,
                target_code_context=target_code_context,
                fallback_start=start_idx,
                source_func_name=source_func_name,
                source_language=source_language,
            )
            if normalize_error:
                print("    [ERROR] LLM trả về function không hoàn chỉnh/không parse được. Bỏ qua validate.")
                snapshot = build_invalid_snapshot(
                    initial,
                    validation_error=normalize_error,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                )
                llm_patch_artifact = write_llm_patch_artifact(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    llm_provider=llm_provider,
                    raw_patch=raw_patch,
                    patched_function=candidate_patched_func,
                    status=snapshot["status"],
                    validation_error=snapshot["validation_error"],
                    evaluation_snapshot=snapshot,
                    validation_context=_build_patch_validation_context(
                        agent="fix_agent",
                        bug_id=bug_id,
                        qualified_name=qualified_name,
                        candidate_relpath=candidate_relpath,
                        repair_target_file=candidate_path,
                        raw_patch=raw_patch,
                        patched_function=candidate_patched_func,
                        snapshot=snapshot,
                        validation_details=snapshot.get("validation_details") or {},
                        fail_context_agent_artifact=fail_context_agent_artifact,
                        target_code_context_agent_artifact=target_code_context_agent_artifact,
                        related_code_context_agent_artifact=related_code_context_agent_artifact,
                        fix_agent_artifact=fix_agent_artifact,
                    ),
                    fail_context_agent_artifact=fail_context_agent_artifact,
                    target_code_context_agent_artifact=target_code_context_agent_artifact,
                    related_code_context_agent_artifact=related_code_context_agent_artifact,
                    fix_agent_artifact=fix_agent_artifact,
                )
                candidate_results.append({
                    "function": qualified_name,
                    "score": score,
                    "repair_target_file": candidate_path,
                    "repair_target_relpath": candidate_relpath,
                    "patched_function": candidate_patched_func,
                    "patched_file": "",
                    "llm_patch_artifact": llm_patch_artifact,
                    "fix_agent_evaluation": extract_evaluation_snapshot(snapshot),
                    **snapshot,
                })
                continue

            candidate_patched_source = replace_source_range_bytes(
                source_code,
                replacement_start_idx,
                replacement_end_idx,
                candidate_patched_func,
            )

            orig_norm = normalize_code_for_edit_distance(target_replacement_unit)
            patched_norm = normalize_code_for_edit_distance(candidate_patched_func)
            if not patched_norm or candidate_patched_source == source_code:
                print("    [NO-OP] Patch không thay đổi hàm nguồn, bỏ qua candidate này.")
                snapshot = build_invalid_snapshot(
                    initial,
                    validation_error="no_op",
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                )
                llm_patch_artifact = write_llm_patch_artifact(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    llm_provider=llm_provider,
                    raw_patch=raw_patch,
                    patched_function=candidate_patched_func,
                    patched_file=candidate_patched_source,
                    status=snapshot["status"],
                    validation_error=snapshot["validation_error"],
                    evaluation_snapshot=snapshot,
                    validation_context=_build_patch_validation_context(
                        agent="fix_agent",
                        bug_id=bug_id,
                        qualified_name=qualified_name,
                        candidate_relpath=candidate_relpath,
                        repair_target_file=candidate_path,
                        raw_patch=raw_patch,
                        patched_function=candidate_patched_func,
                        snapshot=snapshot,
                        validation_details=snapshot.get("validation_details") or {},
                        fail_context_agent_artifact=fail_context_agent_artifact,
                        target_code_context_agent_artifact=target_code_context_agent_artifact,
                        related_code_context_agent_artifact=related_code_context_agent_artifact,
                        fix_agent_artifact=fix_agent_artifact,
                    ),
                    fail_context_agent_artifact=fail_context_agent_artifact,
                    target_code_context_agent_artifact=target_code_context_agent_artifact,
                    related_code_context_agent_artifact=related_code_context_agent_artifact,
                    fix_agent_artifact=fix_agent_artifact,
                )
                candidate_results.append({
                    "function": qualified_name,
                    "score": score,
                    "repair_target_file": candidate_path,
                    "repair_target_relpath": candidate_relpath,
                    "patched_function": candidate_patched_func,
                    "patched_file": candidate_patched_source,
                    "llm_patch_artifact": llm_patch_artifact,
                    "fix_agent_evaluation": extract_evaluation_snapshot(snapshot),
                    **snapshot,
                })
                continue
            if patched_norm == orig_norm:
                print("    [WARN] Patch chỉ khác theo normalized diff; vẫn validate để tránh bỏ nhầm.")

            safe_cand = cand_label.replace("/", "__").replace(" ", "_")
            tmp_path = os.path.join(EXPERIMENTS_DIR, f"tmp_{bug_id.replace('@', '__')}__{safe_cand}")
            with open(tmp_path, "w") as f:
                f.write(candidate_patched_source)

            _, post_passed, post_failed = validate_patch(
                tmp_path,
                bug_id,
                dataset,
                src_basename=cand_base,
                src_relpath=candidate_relpath,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            )
            validation_details = getattr(validate_patch, "last_details", {}) or {}
            validation_error = validation_details.get("validation_error", "")
            snapshot = build_validation_snapshot(
                initial,
                validation_details=validation_details,
                post_passed=post_passed,
                post_failed=post_failed,
                validation_error=validation_error,
                exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            )
            candidate_result = {
                "function": qualified_name,
                "score": score,
                "repair_target_file": candidate_path,
                "repair_target_relpath": candidate_relpath,
                "patched_function": candidate_patched_func,
                "patched_file": candidate_patched_source,
                **snapshot,
            }
            candidate_result["llm_patch_artifact"] = write_llm_patch_artifact(
                bug_id=bug_id,
                attempt_index=llm_patch_attempt_index,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                llm_provider=llm_provider,
                raw_patch=raw_patch,
                patched_function=candidate_patched_func,
                patched_file=candidate_patched_source,
                status=snapshot["status"],
                validation_error=snapshot["validation_error"],
                evaluation_snapshot=snapshot,
                validation_context=_build_patch_validation_context(
                    agent="fix_agent",
                    bug_id=bug_id,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    repair_target_file=candidate_path,
                    raw_patch=raw_patch,
                    patched_function=candidate_patched_func,
                    snapshot=snapshot,
                    validation_details=validation_details,
                    fail_context_agent_artifact=fail_context_agent_artifact,
                    target_code_context_agent_artifact=target_code_context_agent_artifact,
                    related_code_context_agent_artifact=related_code_context_agent_artifact,
                    fix_agent_artifact=fix_agent_artifact,
                ),
                fail_context_agent_artifact=fail_context_agent_artifact,
                target_code_context_agent_artifact=target_code_context_agent_artifact,
                related_code_context_agent_artifact=related_code_context_agent_artifact,
                fix_agent_artifact=fix_agent_artifact,
            )
            candidate_result["fix_agent_evaluation"] = extract_evaluation_snapshot(snapshot)
            candidate_results.append(candidate_result)

            if snapshot["status"] == "plausible":
                print(f"    [SUCCESS] Bản vá hợp lệ cho {bug_id} trong hàm '{func_name}'!")
                patch_name = f"{bug_id}_patch.c" if cand_base == primary_base else f"{bug_id}_patch__{safe_cand}"
                patch_path = os.path.join(PATCHES_DIR, patch_name)
                os.makedirs(PATCHES_DIR, exist_ok=True)
                try:
                    shutil.move(tmp_path, patch_path)
                except Exception as e_mv:
                    print(f"    [WARN] Không lưu được patch file: {e_mv}")
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                best_candidate = candidate_result
                break
            else:
                print("    [FAIL] Bản vá không vượt qua kiểm tra.")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        if best_candidate is None and candidate_results:
            best_candidate = min(
                candidate_results,
                key=candidate_quality_key,
            )
            target_func = best_candidate["function"]
            print(
                f"    [BEST] Chọn candidate tốt nhất: {target_func} "
                f"(patch_failed={len(best_candidate['post_failed_tests'])}, "
                f"full_failed={len(best_candidate['full_post_failed_tests'])})"
            )

        fix_agent_best_candidate = best_candidate
        refix_result = None
        refix_selected = False
        if best_candidate and not is_plausible_status(best_candidate.get("status")):
            refix_artifacts = []
            artifact = dict(best_candidate.get("llm_patch_artifact") or {})
            if artifact.get("patched_file_path") or artifact.get("patched_function_path"):
                artifact["_repair_target_file_abs_path"] = best_candidate.get("repair_target_file") or ""
                refix_artifacts.append(artifact)
            if refix_artifacts and bug_record:
                print("    [REFIX] FixAgent chưa success; chạy ReFix trên best failed candidate.")
                refix_result = run_refix_for_failed_artifacts(
                    dataset=dataset,
                    bug=bug_record,
                    artifacts=refix_artifacts,
                    llm_provider=llm_provider,
                    exclude_fixed_fail_tests=exclude_fixed_fail_tests,
                    excluded_fixed_fail_tests=excluded_fixed_fail_tests,
                    refix_round=1,
                )
                if refix_result:
                    if candidate_quality_key(refix_result) < candidate_quality_key(best_candidate):
                        best_candidate = refix_result
                        refix_selected = True
                        print(
                            f"    [REFIX] ReFix tốt hơn FixAgent best: status={refix_result.get('status')} "
                            f"full_status={refix_result.get('real_status')}"
                        )
                    else:
                        print(
                            f"    [REFIX] Giữ FixAgent best vì ReFix không cải thiện: "
                            f"refix_status={refix_result.get('status')} "
                            f"refix_full_status={refix_result.get('real_status')}"
                        )

        if best_candidate:
            fix_agent_evaluation = (
                extract_evaluation_snapshot(fix_agent_best_candidate)
                if fix_agent_best_candidate
                else {}
            )
            refix_agent_evaluation = (
                extract_evaluation_snapshot(refix_result)
                if refix_result
                else {}
            )
            evaluation_history = []
            if fix_agent_evaluation:
                evaluation_history.append(
                    {
                        "agent": "fix_agent",
                        "artifact": (fix_agent_best_candidate or {}).get("llm_patch_artifact") or {},
                        **fix_agent_evaluation,
                    }
                )
            if refix_agent_evaluation:
                evaluation_history.append(
                    {
                        "agent": "refix_agent",
                        "artifact": (refix_result or {}).get("llm_patch_artifact") or {},
                        **refix_agent_evaluation,
                    }
                )
            fix_agent_candidates = [
                _candidate_trace_record(candidate, agent="fix_agent")
                for candidate in candidate_results
            ]
            fix_agent_best_trace = _candidate_trace_record(
                fix_agent_best_candidate,
                agent="fix_agent",
            )
            refix_agent_result_trace = _candidate_trace_record(
                refix_result,
                agent="refix_agent",
            )
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": valid_mode,
                "fl_results_file": os.path.basename(fl_results_file),
                "patched_function": best_candidate.get("patched_function"),
                "patched_file": best_candidate.get("patched_file"),
                "llm_patch_artifact": best_candidate.get("llm_patch_artifact") or {},
                "selected_agent": "refix_agent" if refix_selected else "fix_agent",
                "selected_candidate": _candidate_trace_record(
                    best_candidate,
                    agent="refix_agent" if refix_selected else "fix_agent",
                ),
                "fix_agent_candidates": fix_agent_candidates,
                "fix_agent_best_candidate": fix_agent_best_trace,
                "refix_agent_result": refix_agent_result_trace,
                "fix_agent_evaluation": fix_agent_evaluation,
                "refix_agent_evaluation": refix_agent_evaluation,
                "evaluation_history": evaluation_history,
                "refix_attempted": bool(refix_result),
                "refix_selected": refix_selected,
                "refix_applied": refix_selected,
                "refix_source_artifact": (refix_result or {}).get("refix_source_artifact") or {},
                "repair_target_file": best_candidate.get("repair_target_file"),
                "repair_target_relpath": candidate_relpath_from_buggy_tree(
                    best_candidate.get("repair_target_file") or "",
                    raw_meta,
                ) or best_candidate.get("repair_target_relpath", ""),
                "selected_function": best_candidate.get("function"),
                **extract_evaluation_snapshot(best_candidate),
            }
        else:
            apr_results[bug_id] = {
                "dataset": dataset,
                "valid_mode": valid_mode,
                "fl_results_file": os.path.basename(fl_results_file),
                "status": "llm_failed" if attempted and not llm_attempted else "skipped",
                "real_status": "llm_failed" if attempted and not llm_attempted else "skipped",
                "validation_error": "",
                **initial["fields"],
                "fixed_fail_excluded_tests": list(initial["excluded"]),
            }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)
