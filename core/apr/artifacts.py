import json
import os
import re
from typing import Optional

from configs.path import EXPERIMENTS_DIR, LLM_PATCHES_DIR

from core.apr.common import (
    DEFAULT_LLM_PROVIDER,
    classify_patch_outcome,
    compact_test_list,
    dedup_initial_test_ids,
    filter_zero_test_artifact_failures,
)
from core.test_filtering import filter_buggy_and_fixed_fail_tests, filter_zero_test_noop_pass_tests


EVALUATION_SNAPSHOT_KEYS = (
    "status",
    "real_status",
    "validation_error",
    "validation_executed",
    "compile_executed",
    "tests_executed",
    "init_passed_tests",
    "init_failed_tests",
    "full_init_passed_tests",
    "full_init_failed_tests",
    "post_passed_tests",
    "post_failed_tests",
    "full_post_passed_tests",
    "full_post_failed_tests",
    "fixed_fail_excluded_tests",
    "validation_details",
)

LEGACY_EVALUATION_KEYS = {
    "status_scope",
    "patch_comparison_status",
    "init_scope",
    "init_passed_count",
    "init_failed_count",
    "full_init_passed_count",
    "full_init_failed_count",
    "post_scope",
    "post_passed_count",
    "post_failed_count",
    "full_post_passed_count",
    "full_post_failed_count",
    "patch_comparison_post_passed_count",
    "patch_comparison_post_failed_count",
    "patch_comparison_post_passed_tests",
    "patch_comparison_post_failed_tests",
    "fixed_fail_excluded_count",
    "test_filter",
}

VALIDATION_RESULT_KEYS = {
    "validation_error",
    "full_post_passed_tests",
    "full_post_failed_tests",
    "patch_comparison_post_passed_tests",
    "patch_comparison_post_failed_tests",
    "fixed_fail_excluded_tests",
    "exclude_fixed_fail_tests_from_run",
    "validation_test_count",
}


def build_initial_test_snapshot(
    tests: list,
    *,
    exclude_fixed_fail_tests: bool,
    excluded_fixed_fail_tests: Optional[list] = None,
) -> dict:
    """Build full and comparison-scope initial test data."""
    source_tests, _zero_test_noop_excluded = filter_zero_test_noop_pass_tests(list(tests or []))
    explicit_excluded = list(dict.fromkeys(excluded_fixed_fail_tests or []))

    if exclude_fixed_fail_tests and explicit_excluded:
        comparison_tests = source_tests
        excluded = explicit_excluded
        comparison_passed, comparison_failed = dedup_initial_test_ids(comparison_tests)
        full_passed = list(comparison_passed)
        full_failed = list(dict.fromkeys([*comparison_failed, *excluded]))
    else:
        full_passed, full_failed = dedup_initial_test_ids(source_tests)
        if exclude_fixed_fail_tests:
            comparison_tests, excluded = filter_buggy_and_fixed_fail_tests(source_tests)
        else:
            comparison_tests = source_tests
            excluded = []
        comparison_passed, comparison_failed = dedup_initial_test_ids(comparison_tests)

    return {
        "comparison_passed": comparison_passed,
        "comparison_failed": comparison_failed,
        "full_passed": full_passed,
        "full_failed": full_failed,
        "excluded": excluded,
        "fields": {
            "init_passed_tests": compact_test_list(comparison_passed),
            "init_failed_tests": compact_test_list(comparison_failed),
            "full_init_passed_tests": compact_test_list(full_passed),
            "full_init_failed_tests": compact_test_list(full_failed),
        },
    }


def build_validation_snapshot(
    initial: dict,
    *,
    validation_details: Optional[dict],
    post_passed: Optional[list] = None,
    post_failed: Optional[list] = None,
    validation_error: str = "",
    exclude_fixed_fail_tests: bool,
) -> dict:
    """Build the persisted evaluation contract for one validated patch."""
    raw_details = dict(validation_details or {})
    error = str(validation_error or raw_details.get("validation_error") or "").strip()
    validation_executed = bool(raw_details.get("validation_executed", True))
    compile_executed = bool(raw_details.get("compile_executed", validation_executed))
    full_post_passed = list(raw_details.get("full_post_passed_tests", post_passed or []))
    raw_full_post_failed = list(raw_details.get("full_post_failed_tests", post_failed or []))
    full_post_failed = filter_zero_test_artifact_failures(raw_full_post_failed, raw_details)
    full_filtered = set(full_post_failed)
    full_zero_test_artifacts = [
        str(tid).strip()
        for tid in raw_full_post_failed
        if str(tid).strip() and str(tid).strip() not in full_filtered
    ]
    full_post_passed = list(dict.fromkeys([*full_post_passed, *full_zero_test_artifacts]))
    tests_executed = bool(raw_details.get(
        "tests_executed",
        validation_executed and bool(full_post_passed or raw_full_post_failed or post_passed or post_failed),
    ))

    if exclude_fixed_fail_tests:
        comparison_post_passed = list(post_passed or [])
        raw_comparison_post_failed = list(post_failed or [])
        comparison_post_failed = filter_zero_test_artifact_failures(
            raw_comparison_post_failed,
            raw_details,
        )
        comparison_filtered = set(comparison_post_failed)
        comparison_zero_test_artifacts = [
            str(tid).strip()
            for tid in raw_comparison_post_failed
            if str(tid).strip() and str(tid).strip() not in comparison_filtered
        ]
        comparison_post_passed = list(dict.fromkeys([
            *comparison_post_passed,
            *comparison_zero_test_artifacts,
        ]))
        excluded = list(dict.fromkeys([
            *initial.get("excluded", []),
            *raw_details.get("fixed_fail_excluded_tests", []),
        ]))
    else:
        comparison_post_passed = full_post_passed
        comparison_post_failed = full_post_failed
        excluded = []

    status = classify_patch_outcome(
        initial.get("comparison_failed", []),
        comparison_post_failed,
        error,
    )
    real_status = classify_patch_outcome(
        initial.get("full_failed", []),
        full_post_failed,
        error,
    )

    return {
        "status": status,
        "real_status": real_status,
        "validation_error": error,
        "validation_executed": validation_executed,
        "compile_executed": compile_executed,
        "tests_executed": tests_executed,
        **initial.get("fields", {}),
        "post_passed_tests": comparison_post_passed,
        "post_failed_tests": comparison_post_failed,
        "full_post_passed_tests": full_post_passed,
        "full_post_failed_tests": full_post_failed,
        "fixed_fail_excluded_tests": excluded,
        "validation_details": compact_validation_details(raw_details),
    }


def build_invalid_snapshot(
    initial: dict,
    *,
    validation_error: str,
    exclude_fixed_fail_tests: bool,
) -> dict:
    details = {
        "validation_error": validation_error,
        "validation_executed": False,
        "compile_executed": False,
        "tests_executed": False,
        "full_post_passed_tests": [],
        "full_post_failed_tests": [],
        "fixed_fail_excluded_tests": list(initial.get("excluded", [])),
    }
    return build_validation_snapshot(
        initial,
        validation_details=details,
        post_passed=[],
        post_failed=[],
        validation_error=validation_error,
        exclude_fixed_fail_tests=exclude_fixed_fail_tests,
    )


def extract_evaluation_snapshot(record: dict) -> dict:
    snapshot = {key: record.get(key) for key in EVALUATION_SNAPSHOT_KEYS if key in record}
    return sanitize_evaluation_data(snapshot)


def sanitize_evaluation_data(value):
    """Remove superseded evaluation fields before metadata is persisted."""
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            if key.startswith("effective_post_") or key in LEGACY_EVALUATION_KEYS:
                continue
            if key == "validation_details" and isinstance(item, dict):
                cleaned[key] = compact_validation_details(item)
            else:
                cleaned[key] = sanitize_evaluation_data(item)
        return cleaned
    if isinstance(value, list):
        return [sanitize_evaluation_data(item) for item in value]
    return value


def compact_validation_details(details: dict) -> dict:
    return sanitize_evaluation_data({
        key: value
        for key, value in (details or {}).items()
        if key not in VALIDATION_RESULT_KEYS
        and not key.startswith("effective_post_")
    })


def safe_artifact_part(value: object, max_len: int = 120) -> str:
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return (text or "unknown")[:max_len]


def rel_experiment_path(path: str) -> str:
    try:
        return os.path.relpath(path, EXPERIMENTS_DIR)
    except ValueError:
        return path


def llm_bug_artifact_dir(bug_id: str) -> str:
    bug_part = safe_artifact_part(bug_id, 80)
    bug_dir = os.path.join(LLM_PATCHES_DIR, bug_part)
    os.makedirs(bug_dir, exist_ok=True)
    return bug_dir


def llm_artifact_base_name(attempt_index: int, qualified_name: str, suffix: str = "") -> str:
    func_part = safe_artifact_part(qualified_name, 140)
    base_name = f"{attempt_index:02d}__{func_part}"
    if suffix:
        base_name = f"{base_name}__{safe_artifact_part(suffix, 60)}"
    return base_name


def write_llm_step_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    step_name: str,
    prompt: str,
    response: str,
    status: str = "generated",
    error: str = "",
) -> dict:
    """Save one LLM agent step prompt/response under experiments/llm_patches/<bug-id>."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(attempt_index, qualified_name, step_name)

    prompt_path = os.path.join(bug_dir, f"{base_name}.prompt.txt")
    response_path = os.path.join(bug_dir, f"{base_name}.response.txt")
    metadata_path = os.path.join(bug_dir, f"{base_name}.json")

    with open(prompt_path, "w") as f:
        f.write(prompt or "")
    with open(response_path, "w") as f:
        f.write(response or "")

    artifact = {
        "bug_id": bug_id,
        "attempt_index": attempt_index,
        "function": qualified_name,
        "repair_target_relpath": candidate_relpath,
        "llm_provider": llm_provider or DEFAULT_LLM_PROVIDER,
        "step_name": step_name,
        "status": status,
        "error": error,
        "artifact_dir": rel_experiment_path(bug_dir),
        "prompt_path": rel_experiment_path(prompt_path),
        "response_path": rel_experiment_path(response_path),
        "metadata_path": rel_experiment_path(metadata_path),
    }

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, indent=4)

    return artifact


def write_fail_context_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    fail_context: dict,
    step_name: str = "fail_context_agent",
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name=step_name,
        payload=fail_context,
        payload_suffix="fail_context",
        status=status,
        error=error,
    )


def _write_deterministic_context_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    step_name: str,
    payload: dict,
    payload_suffix: str,
    status: str = "generated",
    error: str = "",
) -> dict:
    """Save deterministic APR context output for debugging repair prompts."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(attempt_index, qualified_name, step_name)

    payload_path = os.path.join(bug_dir, f"{base_name}.{payload_suffix}.json")
    metadata_path = os.path.join(bug_dir, f"{base_name}.json")

    with open(payload_path, "w") as f:
        json.dump(payload or {}, f, ensure_ascii=False, indent=2, default=str)

    artifact = {
        "bug_id": bug_id,
        "attempt_index": attempt_index,
        "function": qualified_name,
        "repair_target_relpath": candidate_relpath,
        "step_name": step_name,
        "status": status,
        "error": error,
        "artifact_dir": rel_experiment_path(bug_dir),
        f"{payload_suffix}_path": rel_experiment_path(payload_path),
        "metadata_path": rel_experiment_path(metadata_path),
    }

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, ensure_ascii=False, indent=4)

    return artifact


def write_replacement_target_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    replacement_target: dict,
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name="replacement_target",
        payload=replacement_target,
        payload_suffix="replacement_target",
        status=status,
        error=error,
    )


def write_related_code_context_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    related_code_context: dict,
    step_name: str = "related_code_context_agent",
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name=step_name,
        payload=related_code_context,
        payload_suffix="related_code_context",
        status=status,
        error=error,
    )


def write_repair_constraints_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    repair_constraints: dict,
    step_name: str = "repair_constraints_agent",
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name=step_name,
        payload=repair_constraints,
        payload_suffix="repair_constraints",
        status=status,
        error=error,
    )


def write_repair_suggestions_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    repair_suggestions: dict,
    step_name: str = "correctness_suggestor_agent",
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name=step_name,
        payload=repair_suggestions,
        payload_suffix="repair_suggestions",
        status=status,
        error=error,
    )


def write_repair_objective_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    repair_objective: dict,
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name="repair_objective_default",
        payload=repair_objective,
        payload_suffix="repair_objective",
        status=status,
        error=error,
    )


def write_llm_patch_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    raw_patch: str,
    patched_function: str,
    patched_file: Optional[str] = None,
    status: str = "generated",
    validation_error: str = "",
    evaluation_snapshot: Optional[dict] = None,
    validation_context: Optional[dict] = None,
    fail_context_agent_artifact: Optional[dict] = None,
    repair_objective_artifact: Optional[dict] = None,
    replacement_target_artifact: Optional[dict] = None,
    related_code_context_agent_artifact: Optional[dict] = None,
    repair_context_agent_artifact: Optional[dict] = None,
    repair_constraints_agent_artifact: Optional[dict] = None,
    retrieval_context_agent_artifact: Optional[dict] = None,
    fix_agent_artifact: Optional[dict] = None,
    artifact_suffix: str = "",
) -> dict:
    """Luu patch LLM sinh ra de trace/debug, ke ca khi validate fail."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(attempt_index, qualified_name, artifact_suffix)

    response_path = os.path.join(bug_dir, f"{base_name}.response.txt")
    function_path = os.path.join(bug_dir, f"{base_name}.function.c")
    patched_file_path = os.path.join(bug_dir, f"{base_name}.patched.c")
    validation_context_path = os.path.join(bug_dir, f"{base_name}.validation.json")
    metadata_path = os.path.join(bug_dir, f"{base_name}.json")

    with open(response_path, "w") as f:
        f.write(raw_patch or "")
    with open(function_path, "w") as f:
        f.write(patched_function or "")

    artifact = {
        "bug_id": bug_id,
        "attempt_index": attempt_index,
        "function": qualified_name,
        "repair_target_relpath": candidate_relpath,
        "llm_provider": llm_provider or DEFAULT_LLM_PROVIDER,
        "status": status,
        "validation_error": validation_error,
        "artifact_dir": rel_experiment_path(bug_dir),
        "llm_response_path": rel_experiment_path(response_path),
        "raw_patch_path": rel_experiment_path(response_path),
        "patched_function_path": rel_experiment_path(function_path),
        "patched_file_path": "",
        "validation_context_path": "",
        "metadata_path": rel_experiment_path(metadata_path),
        "fail_context_agent_artifact": fail_context_agent_artifact or {},
        "repair_objective_artifact": repair_objective_artifact or {},
        "replacement_target_artifact": replacement_target_artifact or {},
        "related_code_context_agent_artifact": related_code_context_agent_artifact or {},
        "repair_context_agent_artifact": repair_context_agent_artifact or repair_constraints_agent_artifact or {},
        "repair_constraints_agent_artifact": repair_constraints_agent_artifact or repair_context_agent_artifact or {},
        "retrieval_context_agent_artifact": retrieval_context_agent_artifact or {},
        "fix_agent_artifact": fix_agent_artifact or {},
    }
    artifact.update(evaluation_snapshot or {})
    artifact = sanitize_evaluation_data(artifact)

    if patched_file:
        with open(patched_file_path, "w") as f:
            f.write(patched_file)
        artifact["patched_file_path"] = rel_experiment_path(patched_file_path)

    if validation_context:
        with open(validation_context_path, "w") as f:
            json.dump(sanitize_evaluation_data(validation_context), f, ensure_ascii=False, indent=2, default=str)
        artifact["validation_context_path"] = rel_experiment_path(validation_context_path)

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, indent=4)

    return artifact


def write_refix_patch_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    refix_round: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    raw_patch: str,
    patched_function: str,
    patched_file: Optional[str] = None,
    status: str = "generated",
    validation_error: str = "",
    validation_details: Optional[dict] = None,
    evaluation_snapshot: Optional[dict] = None,
    validation_context: Optional[dict] = None,
    parent_patch_artifact: Optional[dict] = None,
    patch_validation_agent_artifact: Optional[dict] = None,
    refix_agent_artifact: Optional[dict] = None,
) -> dict:
    """Save a ReFix-produced patch without overwriting the original APR artifact."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(
        attempt_index,
        qualified_name,
        f"refix{refix_round:02d}",
    )

    response_path = os.path.join(bug_dir, f"{base_name}.response.txt")
    function_path = os.path.join(bug_dir, f"{base_name}.function.c")
    patched_file_path = os.path.join(bug_dir, f"{base_name}.patched.c")
    validation_context_path = os.path.join(bug_dir, f"{base_name}.validation.json")
    metadata_path = os.path.join(bug_dir, f"{base_name}.json")

    with open(response_path, "w") as f:
        f.write(raw_patch or "")
    with open(function_path, "w") as f:
        f.write(patched_function or "")

    artifact = {
        "bug_id": bug_id,
        "attempt_index": attempt_index,
        "refix_round": refix_round,
        "function": qualified_name,
        "repair_target_relpath": candidate_relpath,
        "llm_provider": llm_provider or DEFAULT_LLM_PROVIDER,
        "agent": "refix_agent",
        "status": status,
        "validation_error": validation_error,
        "validation_details": validation_details or {},
        "artifact_dir": rel_experiment_path(bug_dir),
        "llm_response_path": rel_experiment_path(response_path),
        "raw_patch_path": rel_experiment_path(response_path),
        "patched_function_path": rel_experiment_path(function_path),
        "patched_file_path": "",
        "validation_context_path": "",
        "metadata_path": rel_experiment_path(metadata_path),
        "parent_patch_artifact": parent_patch_artifact or {},
        "patch_validation_agent_artifact": patch_validation_agent_artifact or {},
        "refix_agent_artifact": refix_agent_artifact or {},
    }
    artifact.update(evaluation_snapshot or {})
    artifact = sanitize_evaluation_data(artifact)

    if patched_file:
        with open(patched_file_path, "w") as f:
            f.write(patched_file)
        artifact["patched_file_path"] = rel_experiment_path(patched_file_path)

    if validation_context:
        with open(validation_context_path, "w") as f:
            json.dump(sanitize_evaluation_data(validation_context), f, ensure_ascii=False, indent=2, default=str)
        artifact["validation_context_path"] = rel_experiment_path(validation_context_path)

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, indent=4)

    return artifact


def update_patch_artifact_evaluation(artifact: dict, evaluation_snapshot: dict) -> dict:
    """Persist a validation snapshot into an existing patch metadata artifact."""
    metadata_path = artifact.get("_metadata_abs_path")
    if not metadata_path:
        return artifact

    artifact.update(extract_evaluation_snapshot(evaluation_snapshot))
    cleaned = sanitize_evaluation_data(artifact)
    artifact.clear()
    artifact.update(cleaned)
    public = {k: v for k, v in artifact.items() if not k.startswith("_")}
    with open(metadata_path, "w") as f:
        json.dump(public, f, indent=4)
    return artifact
