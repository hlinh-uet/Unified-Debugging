import json
import os
import re
from typing import Optional

from configs.path import EXPERIMENTS_DIR, LLM_PATCHES_DIR

from core.apr.config import DEFAULT_LLM_PROVIDER
from core.apr.evaluation_snapshot import (
    extract_evaluation_snapshot,
    sanitize_evaluation_data,
)


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


def write_target_code_context_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    target_code_context: dict,
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name="target_code_context_agent",
        payload=target_code_context,
        payload_suffix="target_code_context",
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
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name="related_code_context_agent",
        payload=related_code_context,
        payload_suffix="related_code_context",
        status=status,
        error=error,
    )


def write_repair_suggestion_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    repair_suggestion: dict,
    status: str = "generated",
    error: str = "",
) -> dict:
    return _write_deterministic_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        step_name="repair_suggester_agent",
        payload=repair_suggestion,
        payload_suffix="repair_suggestion",
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
        step_name="repair_objective_classifier_agent",
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
    repair_objective_classifier_artifact: Optional[dict] = None,
    target_code_context_agent_artifact: Optional[dict] = None,
    related_code_context_agent_artifact: Optional[dict] = None,
    repair_suggester_agent_artifact: Optional[dict] = None,
    retrieval_context_agent_artifact: Optional[dict] = None,
    fix_agent_artifact: Optional[dict] = None,
) -> dict:
    """Luu patch LLM sinh ra de trace/debug, ke ca khi validate fail."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(attempt_index, qualified_name)

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
        "repair_objective_classifier_artifact": repair_objective_classifier_artifact or {},
        "target_code_context_agent_artifact": target_code_context_agent_artifact or {},
        "related_code_context_agent_artifact": related_code_context_agent_artifact or {},
        "repair_suggester_agent_artifact": repair_suggester_agent_artifact or {},
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
