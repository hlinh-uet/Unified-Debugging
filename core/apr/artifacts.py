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


def write_code_context_collector_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    collector_context: dict,
    repair_evidence_pack: dict,
    status: str = "generated",
    error: str = "",
) -> dict:
    """Save deterministic code-context collector output for debugging APR prompts."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(attempt_index, qualified_name, "code_context_collector_agent")

    context_path = os.path.join(bug_dir, f"{base_name}.context.json")
    evidence_path = os.path.join(bug_dir, f"{base_name}.repair_evidence.json")
    metadata_path = os.path.join(bug_dir, f"{base_name}.json")

    with open(context_path, "w") as f:
        json.dump(collector_context or {}, f, ensure_ascii=False, indent=2, default=str)
    with open(evidence_path, "w") as f:
        json.dump(repair_evidence_pack or {}, f, ensure_ascii=False, indent=2, default=str)

    artifact = {
        "bug_id": bug_id,
        "attempt_index": attempt_index,
        "function": qualified_name,
        "repair_target_relpath": candidate_relpath,
        "step_name": "code_context_collector_agent",
        "status": status,
        "error": error,
        "artifact_dir": rel_experiment_path(bug_dir),
        "collector_context_path": rel_experiment_path(context_path),
        "repair_evidence_pack_path": rel_experiment_path(evidence_path),
        "metadata_path": rel_experiment_path(metadata_path),
    }

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, ensure_ascii=False, indent=4)

    return artifact


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
    code_context_collector_agent_artifact: Optional[dict] = None,
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
        "code_context_collector_agent_artifact": code_context_collector_agent_artifact or {},
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
