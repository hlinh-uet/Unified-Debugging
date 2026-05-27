import json
import os
import shutil
from typing import Optional

from configs.path import EXPERIMENTS_DIR, LLM_PATCHES_DIR, PATCHES_DIR
from core.apr.apr_utils import (
    candidate_relpath_from_buggy_tree,
    compact_test_list,
    dedup_initial_test_ids,
)
from core.apr.validation import validate_patch
from data_loaders.base_loader import get_loader


def run_apr_validation_only(
    dataset: str = "codeflaws",
    bug_id: Optional[str] = None,
    exclude_fixed_fail_tests: bool = True,
):
    """Re-run validation for saved LLM patch artifacts without calling an LLM."""
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_results.json")
    apr_results = _load_json(apr_results_file, default={})

    loader = get_loader(dataset)
    bug_records = _load_bug_records(loader, bug_id)
    if not bug_records:
        print(f"[APR-VALIDATE] Không tìm thấy bug nào cho dataset '{dataset}'.")
        return

    updated = 0
    for bug in bug_records:
        artifacts = _patch_artifacts_for_bug(bug.bug_id)
        if not artifacts:
            print(f"[APR-VALIDATE] Bỏ qua {bug.bug_id}: không có patch artifact.")
            continue

        print(f"[APR-VALIDATE] Validate lại {bug.bug_id}: {len(artifacts)} candidate artifact.")
        _remove_success_patches_for_bug(bug.bug_id)
        result = _validate_bug_artifacts(
            dataset,
            bug,
            artifacts,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        apr_results[bug.bug_id] = result
        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)
        updated += 1

    print(f"[APR-VALIDATE] Đã cập nhật {updated} bug trong {apr_results_file}.")


def _load_bug_records(loader, bug_id: Optional[str]):
    if bug_id:
        bug = loader.load_one(bug_id)
        return [bug] if bug else []
    return loader.load_all()


def _patch_artifacts_for_bug(bug_id: str) -> list:
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
        patched_rel = data.get("patched_file_path")
        target_rel = data.get("repair_target_relpath")
        if not patched_rel or not target_rel:
            continue
        patched_path = _experiment_path(patched_rel)
        if not os.path.isfile(patched_path):
            continue
        data["_metadata_abs_path"] = path
        data["_patched_file_abs_path"] = patched_path
        artifacts.append(data)

    return sorted(
        artifacts,
        key=lambda item: (
            int(item.get("attempt_index") or 0),
            str(item.get("function") or ""),
        ),
    )


def _validate_bug_artifacts(
    dataset: str,
    bug,
    artifacts: list,
    exclude_fixed_fail_tests: bool = True,
) -> dict:
    raw_meta = bug.raw or {}
    init_passed_all, init_failed_all = dedup_initial_test_ids(bug.tests if bug else [])
    init_passed = compact_test_list(init_passed_all)
    init_failed = compact_test_list(init_failed_all)

    candidate_results = []
    best_candidate = None
    status = "failed"

    for artifact in artifacts:
        target_relpath = str(artifact.get("repair_target_relpath") or "").strip()
        target_func = str(artifact.get("function") or "").strip()
        patched_file_path = artifact["_patched_file_abs_path"]
        print(f"  - Validate {target_func or target_relpath}")

        is_valid, post_passed, post_failed = validate_patch(
            patched_file_path,
            bug.bug_id,
            dataset,
            src_basename=os.path.basename(target_relpath),
            src_relpath=target_relpath,
            exclude_fixed_fail_tests=exclude_fixed_fail_tests,
        )
        validation_details = getattr(validate_patch, "last_details", {}) or {}
        validation_error = validation_details.get("validation_error", "")
        full_post_passed = validation_details.get("full_post_passed_tests", post_passed)
        full_post_failed = validation_details.get("full_post_failed_tests", post_failed)
        patch_post_passed = validation_details.get("effective_post_passed_tests", post_passed)
        patch_post_failed = validation_details.get("effective_post_failed_tests", post_failed)
        fixed_fail_excluded = validation_details.get("fixed_fail_excluded_tests", [])

        candidate_status = "success" if is_valid else ("validation_error" if validation_error else "failed")
        candidate_result = {
            "function": target_func,
            "score": 0.0,
            "status": candidate_status,
            "status_scope": "patch_comparison_excluding_fixed_fail_tests",
            "patch_comparison_status": "success" if not patch_post_failed and not validation_error else "failed",
            "real_status": "success" if not full_post_failed and not validation_error else "failed",
            "validation_error": validation_error,
            "repair_target_file": _repair_target_file(raw_meta, target_relpath),
            "repair_target_relpath": target_relpath,
            "patched_function": _read_artifact_text(artifact.get("patched_function_path")),
            "patched_file": _read_artifact_text(artifact.get("patched_file_path")),
            "llm_patch_artifact": _public_artifact(artifact),
            "post_scope": "full_suite",
            "post_passed_count": len(full_post_passed),
            "post_failed_count": len(full_post_failed),
            "post_passed_tests": list(full_post_passed),
            "post_failed_tests": list(full_post_failed),
            "full_post_passed_count": len(full_post_passed),
            "full_post_failed_count": len(full_post_failed),
            "full_post_passed_tests": list(full_post_passed),
            "full_post_failed_tests": list(full_post_failed),
            "patch_comparison_post_passed_count": len(patch_post_passed),
            "patch_comparison_post_failed_count": len(patch_post_failed),
            "patch_comparison_post_passed_tests": list(patch_post_passed),
            "patch_comparison_post_failed_tests": list(patch_post_failed),
            "fixed_fail_excluded_count": len(fixed_fail_excluded),
            "fixed_fail_excluded_tests": list(fixed_fail_excluded),
            "validation_details": validation_details,
        }
        candidate_results.append(candidate_result)
        _update_patch_artifact_status(artifact, candidate_status, validation_error, validation_details)

        if is_valid:
            _save_success_patch(bug, artifact, target_relpath)
            best_candidate = candidate_result
            status = "success"
            print(f"    [SUCCESS] Patch hợp lệ cho {bug.bug_id}.")
            break
        print("    [FAIL] Patch không vượt qua validation.")

    if best_candidate is None and candidate_results:
        best_candidate = min(
            candidate_results,
            key=lambda c: (
                1 if c.get("validation_error") else 0,
                c["patch_comparison_post_failed_count"],
                -c["patch_comparison_post_passed_count"],
            ),
        )
        print(
            f"    [BEST] Chọn candidate tốt nhất: {best_candidate.get('function')} "
            f"(patch_failed={best_candidate['patch_comparison_post_failed_count']}, "
            f"full_failed={best_candidate['full_post_failed_count']})"
        )

    if not best_candidate:
        return {
            "dataset": dataset,
            "status": "skipped",
            "validation_error": "no_patch_artifacts",
            "init_passed_count": len(init_passed_all),
            "init_failed_count": len(init_failed_all),
            "init_passed_tests": init_passed,
            "init_failed_tests": init_failed,
        }

    validation_details = best_candidate.get("validation_details") or {}
    validation_error = best_candidate.get("validation_error", "")
    full_post_passed = best_candidate.get("full_post_passed_tests", [])
    full_post_failed = best_candidate.get("full_post_failed_tests", [])
    patch_post_passed = best_candidate.get("patch_comparison_post_passed_tests", [])
    patch_post_failed = best_candidate.get("patch_comparison_post_failed_tests", [])
    fixed_fail_excluded = best_candidate.get("fixed_fail_excluded_tests", [])

    return {
        "dataset": dataset,
        "status": status,
        "status_scope": "patch_comparison_excluding_fixed_fail_tests",
        "patch_comparison_status": "success" if not patch_post_failed and not validation_error else "failed",
        "real_status": "success" if not full_post_failed and not validation_error else "failed",
        "patched_function": best_candidate.get("patched_function"),
        "patched_file": best_candidate.get("patched_file"),
        "llm_patch_artifact": best_candidate.get("llm_patch_artifact") or {},
        "repair_target_file": best_candidate.get("repair_target_file"),
        "repair_target_relpath": candidate_relpath_from_buggy_tree(
            best_candidate.get("repair_target_file") or "",
            raw_meta,
        ) or best_candidate.get("repair_target_relpath", ""),
        "selected_function": best_candidate.get("function"),
        "init_passed_count": len(init_passed_all),
        "init_failed_count": len(init_failed_all),
        "init_passed_tests": init_passed,
        "init_failed_tests": init_failed,
        "post_scope": "full_suite",
        "post_passed_count": len(full_post_passed),
        "post_failed_count": len(full_post_failed),
        "post_passed_tests": list(full_post_passed),
        "post_failed_tests": list(full_post_failed),
        "full_post_passed_count": len(full_post_passed),
        "full_post_failed_count": len(full_post_failed),
        "full_post_passed_tests": list(full_post_passed),
        "full_post_failed_tests": list(full_post_failed),
        "patch_comparison_post_passed_count": len(patch_post_passed),
        "patch_comparison_post_failed_count": len(patch_post_failed),
        "patch_comparison_post_passed_tests": list(patch_post_passed),
        "patch_comparison_post_failed_tests": list(patch_post_failed),
        "fixed_fail_excluded_count": len(fixed_fail_excluded),
        "fixed_fail_excluded_tests": list(fixed_fail_excluded),
        "validation_error": validation_error,
        "validation_details": validation_details,
    }


def _update_patch_artifact_status(artifact: dict, status: str, validation_error: str, details: dict):
    path = artifact.get("_metadata_abs_path")
    if not path:
        return
    public = _public_artifact(artifact)
    public["status"] = status
    public["validation_error"] = validation_error
    public["validation_details"] = details or {}
    with open(path, "w") as f:
        json.dump(public, f, indent=4)


def _save_success_patch(bug, artifact: dict, target_relpath: str):
    patched_file = artifact.get("_patched_file_abs_path")
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


def _remove_success_patches_for_bug(bug_id: str):
    if not bug_id or not os.path.isdir(PATCHES_DIR):
        return
    prefix = f"{bug_id}_patch"
    for name in os.listdir(PATCHES_DIR):
        if not name.startswith(prefix):
            continue
        path = os.path.join(PATCHES_DIR, name)
        if os.path.isfile(path):
            os.remove(path)


def _public_artifact(artifact: dict) -> dict:
    return {k: v for k, v in artifact.items() if not k.startswith("_")}


def _repair_target_file(raw_meta: dict, relpath: str) -> str:
    buggy_tree = (raw_meta or {}).get("buggy_tree_dir") or ""
    if buggy_tree and relpath:
        path = os.path.join(buggy_tree, relpath)
        if os.path.isfile(path):
            return path
    return ""


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
