"""Shared regression-evidence/FailContext orchestration for FL and APR."""

from __future__ import annotations

import os
import re
from typing import Any, Dict

from .builder import (
    build_regression_fail_context,
    reusable_fail_context,
)


FAIL_CONTEXT_AGENT_SCHEMA = "unified_debugging.fail_context_agent.v1"


def fail_context_runtime_dir(
    *,
    root: str,
    dataset: str,
    bug_id: str,
) -> str:
    """Return the collision-free shared runtime directory for one bug."""

    def safe(value: str) -> str:
        cleaned = re.sub(
            r"[^A-Za-z0-9._-]+", "_", str(value or "")
        ).strip("._-")
        return cleaned or "unknown"

    return os.path.join(
        os.path.abspath(root),
        "runtime_traces",
        safe(str(dataset or "").strip().lower()),
        safe(bug_id),
    )


def run_fail_context_agent(
    *,
    bug: Any,
    artifact_dir: str,
    refresh_runtime: bool = False,
    cache_only: bool = False,
    require_full_runtime: bool = True,
    query_llm_provider: str = None,
    query_llm_enabled: bool = True,
) -> Dict[str, Any]:
    """Return one canonical fresh regression context shared by FL and APR.

    Runtime collection remains implemented by the runtime subsystem, while
    cache selection, context construction and durable publication belong to
    this shared pre-localization agent.
    """
    # Lazy imports avoid making the shared context contract depend on FL at
    # package-import time.  The agent is the orchestration boundary.
    from core.fault_localization.artifacts import atomic_write_json
    from core.fault_localization.runtime import (
        collect_regression_runtime_evidence,
        compact_runtime_evidence,
        load_cached_runtime_evidence,
        write_full_runtime_evidence_cache,
    )

    runtime_evidence = None
    cache_info = {"hit": False, "diagnostics": []}
    if not refresh_runtime:
        runtime_evidence, cache_info = load_cached_runtime_evidence(
            bug,
            artifact_dir=artifact_dir,
            require_current_instrumentation=not cache_only,
        )
    if runtime_evidence is not None:
        cache_kind = (
            "full"
            if cache_info.get("full_ordered_events")
            else "legacy/compact"
        )
        if (
            cache_only
            and require_full_runtime
            and cache_kind != "full"
        ):
            return _agent_result(
                status="cache_incomplete",
                runtime_evidence={},
                fail_context={},
                fail_context_artifact="",
                cache_info=cache_info,
                diagnostics=[
                    "cache_only_requires_full_ordered_runtime"
                ],
            )
    elif cache_only:
        return _agent_result(
            status="cache_miss",
            runtime_evidence={},
            fail_context={},
            fail_context_artifact="",
            cache_info=cache_info,
            diagnostics=cache_info.get("diagnostics") or [
                "runtime_cache_not_found"
            ],
        )
    else:
        runtime_evidence = collect_regression_runtime_evidence(
            bug,
            artifact_dir=artifact_dir,
            query_llm_provider=query_llm_provider,
            query_llm_enabled=query_llm_enabled,
        )

    fail_context = reusable_fail_context(
        (runtime_evidence or {}).get("fail_context")
    )
    if fail_context is None:
        fail_context = build_regression_fail_context(
            bug,
            runtime_evidence=runtime_evidence or {},
        )
    runtime_evidence["fail_context"] = fail_context
    fail_context_artifact = atomic_write_json(
        os.path.join(artifact_dir, "fail_context.json"),
        fail_context,
    )

    full_cache_path = ""
    if not cache_info.get("hit"):
        atomic_write_json(
            os.path.join(artifact_dir, "runtime_evidence.json"),
            compact_runtime_evidence(runtime_evidence),
        )
        if runtime_evidence.get("fresh_execution"):
            full_cache_path = write_full_runtime_evidence_cache(
                runtime_evidence,
                artifact_dir=artifact_dir,
            )
    return _agent_result(
        status=(
            "ready"
            if runtime_evidence.get("fresh_execution")
            else "runtime_unavailable"
        ),
        runtime_evidence=runtime_evidence,
        fail_context=fail_context,
        fail_context_artifact=fail_context_artifact,
        cache_info=cache_info,
        full_cache_path=full_cache_path,
        diagnostics=runtime_evidence.get("diagnostics") or [],
    )


def _agent_result(
    *,
    status: str,
    runtime_evidence: Dict[str, Any],
    fail_context: Dict[str, Any],
    fail_context_artifact: str,
    cache_info: Dict[str, Any],
    diagnostics: list,
    full_cache_path: str = "",
) -> Dict[str, Any]:
    return {
        "schema": FAIL_CONTEXT_AGENT_SCHEMA,
        "version": 1,
        "status": status,
        "runtime_evidence": runtime_evidence,
        "fail_context": fail_context,
        "fail_context_id": fail_context.get("context_id", ""),
        "fail_context_artifact": fail_context_artifact,
        "runtime_cache": cache_info,
        "full_runtime_cache_artifact": full_cache_path,
        "diagnostics": list(dict.fromkeys(
            str(value) for value in diagnostics if str(value)
        )),
    }
