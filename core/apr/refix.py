import json
import os
import shutil
from typing import Optional

from configs.path import EXPERIMENTS_DIR, LLM_PATCHES_DIR, PATCHES_DIR
from core.apr.agent import run_patch_validation_agent, run_refix_agent
from core.apr.apr_utils import (
    candidate_relpath_from_buggy_tree,
    candidate_is_strictly_better,
    candidate_quality_key,
    is_plausible_status,
    is_defects4c_dataset,
    source_language_from_path,
)
from core.apr.artifacts import write_refix_patch_artifact
from core.apr.evaluation_snapshot import (
    build_initial_test_snapshot,
    build_invalid_snapshot,
    build_validation_snapshot,
    extract_evaluation_snapshot,
)
from core.apr.validation import validate_patch
from core.test_filtering import filter_bug_map_for_pipeline
from core.utils import (
    extract_function_code,
    normalize_code_for_edit_distance,
    parse_sbfl_qualified_name,
    replace_source_range_bytes,
    source_function_name_for_extraction,
)
from data_loaders.base_loader import get_loader
from data_loaders.sandbox_adapter import defects4c_docker_ready, get_sandbox_adapter


def run_refix_for_failed_artifacts(
    *,
    dataset: str,
    bug,
    artifacts: list,
    llm_provider: Optional[str],
    exclude_fixed_fail_tests: bool,
    excluded_fixed_fail_tests: list,
    refix_round: int = 1,
) -> Optional[dict]:
    """Run ReFix directly from failed patch artifacts produced in the current APR run."""
    return _refix_bug_artifacts(
        dataset=dataset,
        bug=bug,
        artifacts=artifacts,
        llm_provider=llm_provider,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        excluded_fixed_fail_tests=excluded_fixed_fail_tests,
        refix_round=refix_round,
    )


def _candidate_trace_record(candidate: Optional[dict], *, agent: str) -> dict:
    """Return a compact manifest entry; full patch content stays in artifact files."""
    if not candidate:
        return {}
    artifact = candidate.get("llm_patch_artifact") or {}
    return {
        "agent": agent,
        "function": candidate.get("function") or candidate.get("selected_function"),
        "repair_target_file": candidate.get("repair_target_file"),
        "repair_target_relpath": candidate.get("repair_target_relpath"),
        "llm_patch_artifact": artifact,
        "validation_context_path": artifact.get("validation_context_path", ""),
        "quality_key": list(candidate_quality_key(candidate)),
        **extract_evaluation_snapshot(candidate),
    }


def _artifact_trace_record(artifact: Optional[dict], *, agent: str) -> dict:
    """Return a compact manifest entry for a saved patch metadata artifact."""
    if not artifact:
        return {}
    return {
        "agent": agent,
        "function": artifact.get("function"),
        "repair_target_relpath": artifact.get("repair_target_relpath"),
        "llm_patch_artifact": artifact,
        "validation_context_path": artifact.get("validation_context_path", ""),
        "quality_key": list(candidate_quality_key(artifact)),
        **extract_evaluation_snapshot(artifact),
    }


def _merge_evaluation_history(existing_history: list, refix_result: dict) -> list:
    """Keep prior history and append the standalone ReFix evaluation if missing."""
    history = list(existing_history) if isinstance(existing_history, list) else []
    refix_artifact = (refix_result or {}).get("llm_patch_artifact") or {}
    refix_path = refix_artifact.get("metadata_path") or refix_artifact.get("patched_function_path")
    for item in history:
        artifact = item.get("artifact") if isinstance(item, dict) else {}
        if isinstance(artifact, dict) and refix_path and (
            artifact.get("metadata_path") == refix_path
            or artifact.get("patched_function_path") == refix_path
        ):
            return history
    history.append(
        {
            "agent": "refix_agent",
            "artifact": refix_artifact,
            **extract_evaluation_snapshot(refix_result),
        }
    )
    return history


def run_refix_from_saved_artifacts(
    dataset: str = "codeflaws",
    *,
    bug_id: Optional[str] = None,
    llm_provider: Optional[str] = None,
    exclude_fixed_fail_tests: bool = True,
    refix_round: int = 1,
    apr_results_filename: str = "apr_results.json",
):
    """
    Run ReFix from saved APR artifacts under experiments/llm_patches.

    Modes:
      - bug_id is None: scan all bugs in the dataset and refix failed APR artifacts.
      - bug_id is set: refix only that bug.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    ds_lc = (dataset or "").lower()
    if is_defects4c_dataset(ds_lc):
        ok_d, info_d = defects4c_docker_ready(dataset)
        if not ok_d:
            print(f"[REFIX] {info_d}")
            print("[REFIX] Dừng sớm — không gọi LLM khi chưa validate được trên Docker.")
            return
        os.environ["DEFECTS4C_CONTAINER"] = info_d
        print(f"[REFIX] Defects4C: dùng container '{info_d}' để validate patch.")

    loader = get_loader(dataset)
    if bug_id:
        bug = loader.load_one(bug_id)
        bug_map = {bug.bug_id: bug} if bug else {}
    else:
        bug_map = {b.bug_id: b for b in loader.load_all()}
    bug_map, excluded_fixed_fail_by_bug = filter_bug_map_for_pipeline(
        bug_map,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    if not bug_map:
        print(f"[REFIX] Không tìm thấy bug phù hợp cho dataset '{dataset}'.")
        return

    apr_results_file = (
        apr_results_filename
        if os.path.isabs(apr_results_filename)
        else os.path.join(EXPERIMENTS_DIR, apr_results_filename)
    )
    apr_results = _load_json(apr_results_file, default={})

    updated = 0
    for cur_bug_id, bug in bug_map.items():
        artifacts = _refix_source_artifacts_for_bug(cur_bug_id)
        if not artifacts:
            print(f"[REFIX] Bỏ qua {cur_bug_id}: không có failed APR artifact để refix.")
            continue
        best_fix_artifact = min(artifacts, key=candidate_quality_key)

        print(
            f"[REFIX] Xử lý {cur_bug_id}: chọn best FixAgent artifact từ "
            f"{len(artifacts)} failed artifact."
        )
        result = _refix_bug_artifacts(
            dataset=dataset,
            bug=bug,
            artifacts=[best_fix_artifact],
            llm_provider=llm_provider,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            excluded_fixed_fail_tests=excluded_fixed_fail_by_bug.get(cur_bug_id, []),
            refix_round=refix_round,
        )
        if not result:
            continue
        existing_result = apr_results.get(cur_bug_id) if isinstance(apr_results, dict) else {}
        if not isinstance(existing_result, dict):
            existing_result = {}
        refix_is_better = candidate_is_strictly_better(result, best_fix_artifact)
        if refix_is_better:
            apr_results[cur_bug_id] = {
                **result,
                "selected_agent": "refix_agent",
                "selected_candidate": _candidate_trace_record(result, agent="refix_agent"),
                "fix_agent_best_candidate": _artifact_trace_record(best_fix_artifact, agent="fix_agent"),
                "refix_agent_result": _candidate_trace_record(result, agent="refix_agent"),
                "refix_attempted": True,
                "refix_selected": True,
                "refix_applied": True,
            }
            updated += 1
        else:
            print(
                f"[REFIX] Giữ FixAgent artifact cho {cur_bug_id}: "
                f"ReFix không cải thiện status={result.get('status')}"
            )
            apr_results[cur_bug_id] = {
                **existing_result,
                "selected_agent": existing_result.get("selected_agent") or "fix_agent",
                "fix_agent_best_candidate": existing_result.get("fix_agent_best_candidate")
                or _artifact_trace_record(best_fix_artifact, agent="fix_agent"),
                "refix_agent_result": _candidate_trace_record(result, agent="refix_agent"),
                "refix_agent_evaluation": extract_evaluation_snapshot(result),
                "refix_attempted": True,
                "refix_selected": False,
                "refix_applied": False,
                "refix_source_artifact": result.get("refix_source_artifact") or {},
                "evaluation_history": _merge_evaluation_history(
                    existing_result.get("evaluation_history") or [],
                    result,
                ),
            }
        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)

    print(f"[REFIX] Đã cập nhật {updated} bug trong {apr_results_file}.")


def _refix_bug_artifacts(
    *,
    dataset: str,
    bug,
    artifacts: list,
    llm_provider: Optional[str],
    exclude_fixed_fail_tests: bool,
    excluded_fixed_fail_tests: list,
    refix_round: int,
) -> Optional[dict]:
    raw_meta = bug.raw or {}
    initial = build_initial_test_snapshot(
        bug.tests if bug else [],
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        excluded_fixed_fail_tests=excluded_fixed_fail_tests,
    )

    candidate_results = []
    best_candidate = None

    for artifact in artifacts:
        target_relpath = str(artifact.get("repair_target_relpath") or "").strip()
        qualified_name = str(artifact.get("function") or "").strip()
        attempt_index = int(artifact.get("attempt_index") or 0)
        print(f"  - ReFix {qualified_name or target_relpath}")

        candidate = _run_one_refix_candidate(
            dataset=dataset,
            bug=bug,
            raw_meta=raw_meta,
            artifact=artifact,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            attempt_index=attempt_index,
            llm_provider=llm_provider,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            initial=initial,
            refix_round=refix_round,
        )
        if not candidate:
            continue
        candidate_results.append(candidate)
        if is_plausible_status(candidate.get("status")):
            best_candidate = candidate
            print(f"    [SUCCESS] ReFix hợp lệ cho {bug.bug_id}.")
            _save_success_patch(bug, candidate)
            break
        print("    [FAIL] ReFix chưa vượt qua validation.")

    if best_candidate is None and candidate_results:
        best_candidate = min(
            candidate_results,
            key=candidate_quality_key,
        )
        print(
            f"    [BEST] Chọn ReFix candidate tốt nhất: {best_candidate.get('function')} "
            f"(patch_failed={len(best_candidate['post_failed_tests'])}, "
            f"full_failed={len(best_candidate['full_post_failed_tests'])})"
        )

    if not best_candidate:
        return None

    fix_agent_evaluation = extract_evaluation_snapshot(
        best_candidate.get("refix_source_artifact") or {}
    )
    refix_agent_evaluation = extract_evaluation_snapshot(best_candidate)
    evaluation_history = []
    if fix_agent_evaluation:
        evaluation_history.append(
            {
                "agent": "fix_agent",
                "artifact": best_candidate.get("refix_source_artifact") or {},
                **fix_agent_evaluation,
            }
        )
    if refix_agent_evaluation:
        evaluation_history.append(
            {
                "agent": "refix_agent",
                "artifact": best_candidate.get("llm_patch_artifact") or {},
                **refix_agent_evaluation,
            }
        )

    return {
        "dataset": dataset,
        "patched_function": best_candidate.get("patched_function"),
        "patched_file": best_candidate.get("patched_file"),
        "llm_patch_artifact": best_candidate.get("llm_patch_artifact") or {},
        "selected_agent": "refix_agent",
        "selected_candidate": _candidate_trace_record(best_candidate, agent="refix_agent"),
        "refix_agent_candidates": [
            _candidate_trace_record(candidate, agent="refix_agent")
            for candidate in candidate_results
        ],
        "fix_agent_best_candidate": _artifact_trace_record(
            best_candidate.get("refix_source_artifact") or {},
            agent="fix_agent",
        ),
        "refix_agent_result": _candidate_trace_record(best_candidate, agent="refix_agent"),
        "refix_attempted": True,
        "refix_selected": True,
        "refix_applied": True,
        "refix_source_artifact": best_candidate.get("refix_source_artifact") or {},
        "fix_agent_evaluation": fix_agent_evaluation,
        "refix_agent_evaluation": refix_agent_evaluation,
        "evaluation_history": evaluation_history,
        "repair_target_file": best_candidate.get("repair_target_file"),
        "repair_target_relpath": best_candidate.get("repair_target_relpath")
        or candidate_relpath_from_buggy_tree(best_candidate.get("repair_target_file") or "", raw_meta),
        "selected_function": best_candidate.get("function"),
        **extract_evaluation_snapshot(best_candidate),
    }


def _run_one_refix_candidate(
    *,
    dataset: str,
    bug,
    raw_meta: dict,
    artifact: dict,
    qualified_name: str,
    target_relpath: str,
    attempt_index: int,
    llm_provider: Optional[str],
    exclude_fixed_fail_tests: bool,
    initial: dict,
    refix_round: int,
) -> Optional[dict]:
    original_path = (
        artifact.get("_repair_target_file_abs_path")
        or _repair_target_file(raw_meta, target_relpath)
        or _fallback_repair_target_file(dataset, bug.bug_id, target_relpath)
    )
    if not original_path or not os.path.isfile(original_path):
        print(f"    [SKIP] Không tìm thấy source gốc cho {target_relpath}.")
        return None

    previous_function = _read_artifact_text(artifact.get("patched_function_path"))
    previous_patched_file = artifact.get("_patched_file_abs_path") or _experiment_path(
        str(artifact.get("patched_file_path") or "")
    )
    if not previous_function.strip():
        print("    [SKIP] Artifact thiếu previous patched function.")
        return None

    with open(original_path, "r", errors="replace") as f:
        source_code = f.read()
    source_language = source_language_from_path(original_path)
    _, func_name = parse_sbfl_qualified_name(qualified_name)
    source_func_name = source_function_name_for_extraction(
        func_name,
        original_path,
        raw_meta,
    )
    original_function, start_idx, end_idx = extract_function_code(
        source_code,
        source_func_name,
        language=source_language,
    )
    if not original_function:
        print(f"    [SKIP] Không trích xuất được function gốc {source_func_name}.")
        return None
    target_code_context = _target_code_context_from_artifact(artifact)
    original_replacement_unit = _target_replacement_unit(target_code_context, original_function)
    replacement_start_idx, replacement_end_idx = _target_replacement_range(
        target_code_context,
        start_idx,
        end_idx,
    )

    previous_validation = _validation_feedback_from_artifact(artifact)
    if not previous_validation and os.path.isfile(previous_patched_file):
        previous_validation = _validate_existing_artifact(
            dataset=dataset,
            bug_id=bug.bug_id,
            patched_file_path=previous_patched_file,
            target_relpath=target_relpath,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )

    prior_context = _prior_context_from_artifact(artifact)
    patch_validation_analysis, patch_validation_agent_artifact = run_patch_validation_agent(
        bug_id=bug.bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=target_relpath,
        llm_provider=llm_provider,
        func_name=source_func_name,
        cand_label=target_relpath or os.path.basename(original_path),
        original_function=original_replacement_unit,
        patched_function=previous_function,
        validation_details=previous_validation,
        prior_context=prior_context,
    )
    if patch_validation_agent_artifact:
        artifact["patch_validation_agent_artifact"] = patch_validation_agent_artifact

    raw_patch, refix_agent_artifact = run_refix_agent(
        bug_id=bug.bug_id,
        attempt_index=attempt_index,
        refix_round=refix_round,
        qualified_name=qualified_name,
        candidate_relpath=target_relpath,
        llm_provider=llm_provider,
        func_name=source_func_name,
        cand_label=target_relpath or os.path.basename(original_path),
        original_function=original_replacement_unit,
        previous_patched_function=previous_function,
        validation_details=previous_validation,
        patch_validation_analysis=patch_validation_analysis,
        prior_context=prior_context,
    )
    if not raw_patch:
        return _failed_refix_candidate(
            bug=bug,
            artifact=artifact,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            original_path=original_path,
            validation_error="refix_agent_no_response",
            initial=initial,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            refix_agent_artifact=refix_agent_artifact,
        )

    candidate_patched_func = raw_patch.strip()
    if "```" in candidate_patched_func or "<fixed_code" in candidate_patched_func.lower():
        return _failed_refix_candidate(
            bug=bug,
            artifact=artifact,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            original_path=original_path,
            validation_error="malformed_function",
            initial=initial,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            refix_agent_artifact=refix_agent_artifact,
            raw_patch=raw_patch,
        )

    candidate_patched_func, normalize_error = _normalize_refix_replacement(
        raw_patch=candidate_patched_func,
        target_code_context=target_code_context,
        fallback_start=start_idx,
        source_func_name=source_func_name,
        source_language=source_language,
    )
    if normalize_error:
        return _failed_refix_candidate(
            bug=bug,
            artifact=artifact,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            original_path=original_path,
            validation_error=normalize_error,
            initial=initial,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            refix_agent_artifact=refix_agent_artifact,
            raw_patch=raw_patch,
            patched_function=candidate_patched_func,
        )

    if normalize_code_for_edit_distance(candidate_patched_func) == normalize_code_for_edit_distance(previous_function):
        return _failed_refix_candidate(
            bug=bug,
            artifact=artifact,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            original_path=original_path,
            validation_error="no_op",
            initial=initial,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
            refix_agent_artifact=refix_agent_artifact,
            raw_patch=raw_patch,
            patched_function=candidate_patched_func,
        )

    candidate_patched_source = replace_source_range_bytes(
        source_code,
        replacement_start_idx,
        replacement_end_idx,
        candidate_patched_func,
    )

    safe_target = (target_relpath or os.path.basename(original_path)).replace("/", "__").replace(" ", "_")
    tmp_path = os.path.join(
        EXPERIMENTS_DIR,
        f"tmp_refix_{bug.bug_id.replace('@', '__')}__{safe_target}",
    )
    with open(tmp_path, "w") as f:
        f.write(candidate_patched_source)

    _, post_passed, post_failed = validate_patch(
        tmp_path,
        bug.bug_id,
        dataset,
        src_basename=os.path.basename(target_relpath),
        src_relpath=target_relpath,
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
    refix_patch_artifact = write_refix_patch_artifact(
        bug_id=bug.bug_id,
        attempt_index=attempt_index,
        refix_round=refix_round,
        qualified_name=qualified_name,
        candidate_relpath=target_relpath,
        llm_provider=llm_provider,
        raw_patch=raw_patch,
        patched_function=candidate_patched_func,
        patched_file=candidate_patched_source,
        status=snapshot["status"],
        validation_error=snapshot["validation_error"],
        validation_details=validation_details,
        evaluation_snapshot=snapshot,
        validation_context=_refix_validation_context(
            bug_id=bug.bug_id,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            original_path=original_path,
            raw_patch=raw_patch,
            patched_function=candidate_patched_func,
            snapshot=snapshot,
            validation_details=validation_details,
            parent_patch_artifact=_public_artifact(artifact),
            patch_validation_agent_artifact=artifact.get("patch_validation_agent_artifact") or {},
            refix_agent_artifact=refix_agent_artifact,
        ),
        parent_patch_artifact=_public_artifact(artifact),
        patch_validation_agent_artifact=artifact.get("patch_validation_agent_artifact") or {},
        refix_agent_artifact=refix_agent_artifact,
    )

    if os.path.exists(tmp_path):
        os.remove(tmp_path)

    return {
        "function": qualified_name,
        "score": 0.0,
        "repair_target_file": original_path,
        "repair_target_relpath": target_relpath,
        "patched_function": candidate_patched_func,
        "patched_file": candidate_patched_source,
        "llm_patch_artifact": refix_patch_artifact,
        "refix_source_artifact": _public_artifact(artifact),
        **snapshot,
    }


def _failed_refix_candidate(
    *,
    bug,
    artifact: dict,
    qualified_name: str,
    target_relpath: str,
    original_path: str,
    validation_error: str,
    initial: dict,
    exclude_fixed_fail_tests: bool,
    refix_agent_artifact: dict,
    raw_patch: str = "",
    patched_function: str = "",
    validation_details: Optional[dict] = None,
) -> dict:
    if validation_details:
        snapshot = build_validation_snapshot(
            initial,
            validation_details=validation_details,
            post_passed=[],
            post_failed=[],
            validation_error=validation_error,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
    else:
        snapshot = build_invalid_snapshot(
            initial,
            validation_error=validation_error,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
    refix_patch_artifact = write_refix_patch_artifact(
        bug_id=bug.bug_id,
        attempt_index=int(artifact.get("attempt_index") or 0),
        refix_round=int(refix_agent_artifact.get("refix_round") or 1),
        qualified_name=qualified_name,
        candidate_relpath=target_relpath,
        llm_provider=artifact.get("llm_provider"),
        raw_patch=raw_patch,
        patched_function=patched_function,
        patched_file="",
        status=snapshot["status"],
        validation_error=validation_error,
        validation_details=snapshot["validation_details"],
        evaluation_snapshot=snapshot,
        validation_context=_refix_validation_context(
            bug_id=bug.bug_id,
            qualified_name=qualified_name,
            target_relpath=target_relpath,
            original_path=original_path,
            raw_patch=raw_patch,
            patched_function=patched_function,
            snapshot=snapshot,
            validation_details=snapshot.get("validation_details") or {},
            parent_patch_artifact=_public_artifact(artifact),
            patch_validation_agent_artifact=artifact.get("patch_validation_agent_artifact") or {},
            refix_agent_artifact=refix_agent_artifact,
        ),
        parent_patch_artifact=_public_artifact(artifact),
        patch_validation_agent_artifact=artifact.get("patch_validation_agent_artifact") or {},
        refix_agent_artifact=refix_agent_artifact,
    )
    return {
        "function": qualified_name,
        "score": 0.0,
        "repair_target_file": original_path,
        "repair_target_relpath": target_relpath,
        "patched_function": patched_function,
        "patched_file": "",
        "llm_patch_artifact": refix_patch_artifact,
        "refix_source_artifact": _public_artifact(artifact),
        **snapshot,
    }


def _refix_validation_context(
    *,
    bug_id: str,
    qualified_name: str,
    target_relpath: str,
    original_path: str,
    raw_patch: str,
    patched_function: str,
    snapshot: dict,
    validation_details: dict,
    parent_patch_artifact: dict,
    patch_validation_agent_artifact: dict,
    refix_agent_artifact: dict,
) -> dict:
    """Build rich validation feedback for ReFix-produced artifacts."""
    return {
        "agent": "refix_agent",
        "bug_id": bug_id,
        "function": qualified_name,
        "repair_target_file": original_path,
        "repair_target_relpath": target_relpath,
        "evaluation_snapshot": extract_evaluation_snapshot(snapshot),
        "raw_validation_details": validation_details or {},
        "raw_patch_excerpt": (raw_patch or "")[:8000],
        "patched_function_excerpt": (patched_function or "")[:8000],
        "parent_patch_artifact": parent_patch_artifact or {},
        "patch_validation_agent_artifact": patch_validation_agent_artifact or {},
        "refix_agent_artifact": refix_agent_artifact or {},
    }


def _refix_source_artifacts_for_bug(bug_id: str) -> list:
    bug_dir = os.path.join(LLM_PATCHES_DIR, _safe_artifact_part(bug_id, 80))
    if not os.path.isdir(bug_dir):
        return []

    artifacts = []
    for name in sorted(os.listdir(bug_dir)):
        if not name.endswith(".json"):
            continue
        path = os.path.join(bug_dir, name)
        data = _load_json(path, default={})
        if not isinstance(data, dict):
            continue
        if data.get("agent") == "refix_agent" or "__refix" in name:
            continue
        if data.get("step_name"):
            continue
        if is_plausible_status(data.get("status")):
            continue
        patched_rel = data.get("patched_file_path")
        patched_function_rel = data.get("patched_function_path")
        target_rel = data.get("repair_target_relpath")
        if not patched_rel and not patched_function_rel:
            continue
        patched_path = _experiment_path(str(patched_rel)) if patched_rel else ""
        patched_function_path = _experiment_path(str(patched_function_rel)) if patched_function_rel else ""
        if patched_rel and not os.path.isfile(patched_path):
            continue
        if not patched_rel and not os.path.isfile(patched_function_path):
            continue
        data["_metadata_abs_path"] = path
        if patched_path:
            data["_patched_file_abs_path"] = patched_path
        artifacts.append(data)

    return sorted(
        artifacts,
        key=lambda item: (
            int(item.get("attempt_index") or 0),
            1 if item.get("validation_error") else 0,
            _failed_count(item),
            str(item.get("function") or ""),
        ),
    )


def _failed_count(artifact: dict) -> int:
    failed = artifact.get("post_failed_tests")
    if isinstance(failed, list):
        return len(failed)
    return 10**9


def _validate_existing_artifact(
    *,
    dataset: str,
    bug_id: str,
    patched_file_path: str,
    target_relpath: str,
    exclude_fixed_fail_tests: bool,
) -> dict:
    _, _, post_failed = validate_patch(
        patched_file_path,
        bug_id,
        dataset,
        src_basename=os.path.basename(target_relpath),
        src_relpath=target_relpath,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )
    details = getattr(validate_patch, "last_details", {}) or {}
    return {
        **details,
        "post_failed_tests": post_failed,
    }


def _validation_feedback_from_artifact(artifact: dict) -> dict:
    validation_context = _artifact_validation_context(artifact)
    details = dict(validation_context.get("raw_validation_details") or {})
    if not details:
        details = dict(validation_context.get("validation_details") or {})
    if not details:
        details = dict(artifact.get("validation_details") or {})
    for key in ("validation_error", "post_failed_tests", "full_post_failed_tests"):
        value = artifact.get(key) or (validation_context.get("evaluation_snapshot") or {}).get(key)
        if value:
            details[key] = value
    return details


def _target_code_context_from_artifact(artifact: dict) -> dict:
    target_artifact = artifact.get("target_code_context_agent_artifact") or {}
    path_value = target_artifact.get("target_code_context_path")
    if not path_value:
        validation_context = _artifact_validation_context(artifact)
        target_artifact = validation_context.get("target_code_context_agent_artifact") or {}
        path_value = target_artifact.get("target_code_context_path")
    if not path_value:
        return {}
    data = _load_json(_experiment_path(str(path_value)), default={})
    return data if isinstance(data, dict) else {}


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


def _target_replacement_requires_raw_unit(target_code_context: dict, fallback_start: int) -> bool:
    envelope = (target_code_context or {}).get("target_envelope") or {}
    replacement_range = envelope.get("replacement_range") or {}
    try:
        replacement_start = int(replacement_range.get("start_byte", fallback_start))
    except Exception:
        replacement_start = fallback_start
    return bool(envelope.get("replacement_includes_prefix")) or replacement_start != fallback_start


def _normalize_refix_replacement(
    *,
    raw_patch: str,
    target_code_context: dict,
    fallback_start: int,
    source_func_name: str,
    source_language: str,
) -> tuple:
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


def _prior_context_from_artifact(artifact: dict) -> dict:
    validation_context = _artifact_validation_context(artifact)
    out = {
        "function": artifact.get("function"),
        "status": artifact.get("status"),
        "validation_error": artifact.get("validation_error"),
        "repair_target_relpath": artifact.get("repair_target_relpath"),
        "validation_context": validation_context,
        "fail_context_agent_artifact": artifact.get("fail_context_agent_artifact") or {},
        "repair_objective_classifier_artifact": artifact.get("repair_objective_classifier_artifact") or {},
        "target_code_context_agent_artifact": artifact.get("target_code_context_agent_artifact") or {},
        "related_code_context_agent_artifact": artifact.get("related_code_context_agent_artifact") or {},
        "retrieval_context_agent_artifact": artifact.get("retrieval_context_agent_artifact") or {},
        "fix_agent_artifact": artifact.get("fix_agent_artifact") or {},
        "patch_validation_agent_artifact": artifact.get("patch_validation_agent_artifact") or {},
    }
    for key in (
        "fail_context_agent_artifact",
        "retrieval_context_agent_artifact",
        "fix_agent_artifact",
        "patch_validation_agent_artifact",
    ):
        response_path = (out.get(key) or {}).get("response_path")
        text = _read_artifact_text(response_path)
        if text:
            out[f"{key}_response_excerpt"] = text[:4000]
    return out


def _artifact_validation_context(artifact: dict) -> dict:
    path_value = artifact.get("validation_context_path")
    if not path_value:
        return {}
    return _load_json(_experiment_path(str(path_value)), default={})


def _save_success_patch(bug, candidate: dict):
    target_relpath = candidate.get("repair_target_relpath") or ""
    patched_file = candidate.get("llm_patch_artifact", {}).get("patched_file_path")
    patched_file = _experiment_path(patched_file) if patched_file else ""
    if not patched_file or not os.path.isfile(patched_file):
        return

    primary_base = os.path.basename(getattr(bug, "source_file", "") or "")
    target_base = os.path.basename(target_relpath or "")
    if primary_base and target_base == primary_base:
        patch_name = f"{bug.bug_id}_patch.c"
    else:
        safe_target = (target_relpath or target_base or "patch").replace("/", "__").replace(" ", "_")
        patch_name = f"{bug.bug_id}_patch__{safe_target}"

    os.makedirs(PATCHES_DIR, exist_ok=True)
    shutil.copyfile(patched_file, os.path.join(PATCHES_DIR, patch_name))


def _repair_target_file(raw_meta: dict, relpath: str) -> str:
    buggy_tree = (raw_meta or {}).get("buggy_tree_dir") or ""
    if buggy_tree and relpath:
        path = os.path.join(buggy_tree, relpath)
        if os.path.isfile(path):
            return path
    return ""


def _fallback_repair_target_file(dataset: str, bug_id: str, relpath: str) -> str:
    """Resolve source path for saved artifacts that lack repair_target_relpath."""
    if relpath:
        return ""
    try:
        source_path = get_sandbox_adapter(dataset, bug_id).get_source_path()
    except Exception:
        return ""
    return source_path if source_path and os.path.isfile(source_path) else ""


def _read_artifact_text(path_value: object) -> str:
    if not path_value:
        return ""
    path = _experiment_path(str(path_value))
    try:
        with open(path, "r", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _experiment_path(path_value: str) -> str:
    if os.path.isabs(path_value):
        return path_value
    return os.path.join(EXPERIMENTS_DIR, path_value)


def _public_artifact(artifact: dict) -> dict:
    return {k: v for k, v in artifact.items() if not k.startswith("_")}


def _load_json(path: str, default):
    try:
        with open(path, "r") as f:
            return json.load(f)
    except Exception:
        return default


def _safe_artifact_part(value: object, max_len: int = 120) -> str:
    import re

    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return (text or "unknown")[:max_len]
