import json
import os
import re
from typing import Optional

from configs.path import EXPERIMENTS_DIR, LLM_PATCHES_DIR

from core.apr.config import DEFAULT_LLM_PROVIDER


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
    retrieval_context_agent_artifact: Optional[dict] = None,
    fix_agent_artifact: Optional[dict] = None,
) -> dict:
    """Luu patch LLM sinh ra de trace/debug, ke ca khi validate fail."""
    bug_dir = llm_bug_artifact_dir(bug_id)
    base_name = llm_artifact_base_name(attempt_index, qualified_name)

    response_path = os.path.join(bug_dir, f"{base_name}.response.txt")
    function_path = os.path.join(bug_dir, f"{base_name}.function.c")
    patched_file_path = os.path.join(bug_dir, f"{base_name}.patched.c")
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
        "metadata_path": rel_experiment_path(metadata_path),
        "retrieval_context_agent_artifact": retrieval_context_agent_artifact or {},
        "fix_agent_artifact": fix_agent_artifact or {},
    }

    if patched_file:
        with open(patched_file_path, "w") as f:
            f.write(patched_file)
        artifact["patched_file_path"] = rel_experiment_path(patched_file_path)

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, indent=4)

    return artifact
