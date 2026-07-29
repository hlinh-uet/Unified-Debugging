"""Atomic, per-bug artifacts for the initial fault-localization pipeline."""

from __future__ import annotations

import gzip
import hashlib
import json
import os
import re
from typing import Any, Dict


def atomic_write_json(path: str, value: Any, *, indent: int | None = 2) -> str:
    """Write JSON through a sibling temporary file and atomically replace it."""
    if not path:
        return ""
    absolute = os.path.abspath(path)
    os.makedirs(os.path.dirname(absolute), exist_ok=True)
    temporary = absolute + f".tmp.{os.getpid()}"
    try:
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(
                value,
                stream,
                indent=indent,
                ensure_ascii=False,
                sort_keys=False,
            )
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, absolute)
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(temporary)
        except OSError:
            pass
        return ""
    return absolute


def atomic_write_gzip_json(path: str, value: Any) -> str:
    """Atomically persist a complete compressed JSON artifact."""
    if not path:
        return ""
    absolute = os.path.abspath(path)
    os.makedirs(os.path.dirname(absolute), exist_ok=True)
    temporary = absolute + f".tmp.{os.getpid()}"
    try:
        with gzip.open(
            temporary, "wt", encoding="utf-8", compresslevel=6
        ) as stream:
            json.dump(
                value,
                stream,
                ensure_ascii=False,
                separators=(",", ":"),
            )
        os.replace(temporary, absolute)
    except (OSError, TypeError, ValueError):
        try:
            os.unlink(temporary)
        except OSError:
            pass
        return ""
    return absolute


def read_json(path: str) -> Any:
    try:
        with open(path, "r", encoding="utf-8") as stream:
            return json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return None


def write_causal_evidence_artifact(
    *,
    artifact_dir: str,
    bug_id: str,
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Persist one immutable, deduplicated causal payload."""
    persisted = _externalize_source_investigation(evidence)
    try:
        encoded = json.dumps(
            persisted,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    except (TypeError, ValueError):
        artifact_identity = ""
        path = ""
    else:
        artifact_identity = hashlib.sha256(encoded).hexdigest()
        path = atomic_write_gzip_json(
            os.path.join(
                artifact_dir,
                "causal_evidence",
                artifact_identity + ".json.gz",
            ),
            persisted,
        )
    return {
        "schema": "unified_debugging.causal_evidence_ref.v1",
        "bug_id": str(bug_id or ""),
        "path": path,
        "compression": "gzip",
        "artifact_identity": artifact_identity,
        "fail_context_id": str(
            evidence.get("fail_context_id") or ""
        ),
        "version": evidence.get("version"),
    }


def load_causal_evidence_reference(reference: Any) -> Dict[str, Any]:
    """Load a canonical causal payload without requiring it in result JSON."""
    if not isinstance(reference, dict):
        return {}
    path = str(reference.get("path") or "")
    if not path or not os.path.isfile(path):
        return {}
    try:
        opener = gzip.open if path.endswith(".gz") else open
        with opener(path, "rt", encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return {}
    if not isinstance(payload, dict):
        return {}
    expected_artifact = str(
        reference.get("artifact_identity") or ""
    )
    if expected_artifact:
        actual_artifact = hashlib.sha256(
            json.dumps(
                payload,
                ensure_ascii=False,
                sort_keys=True,
                separators=(",", ":"),
            ).encode("utf-8")
        ).hexdigest()
        if actual_artifact != expected_artifact:
            return {}
    expected_context = str(
        reference.get("fail_context_id") or ""
    )
    actual_context = str(payload.get("fail_context_id") or "")
    if (
        expected_context
        and actual_context
        and expected_context != actual_context
    ):
        return {}
    return payload


def _externalize_source_investigation(
    evidence: Dict[str, Any],
) -> Dict[str, Any]:
    """Reference the existing source cache instead of copying all dossiers."""
    source = evidence.get("source_investigation") or {}
    source_path = str(
        (source.get("cache") or {}).get("source") or ""
    )
    if (
        not isinstance(source, dict)
        or not source_path
        or not os.path.isfile(source_path)
    ):
        return evidence
    persisted = dict(evidence)
    persisted["source_investigation"] = {
        "schema": source.get("schema"),
        "identity": source.get("identity"),
        "request_identity": source.get("request_identity"),
        "source_root": source.get("source_root"),
        "candidate_count": source.get("candidate_count"),
        "diagnostics": source.get("diagnostics") or [],
        "ground_truth_used": source.get(
            "ground_truth_used", False
        ),
        "artifact_ref": {
            "schema": "unified_debugging.source_evidence_ref.v1",
            "path": source_path,
            "compression": (
                "gzip" if source_path.endswith(".gz") else "none"
            ),
            "identity": source.get("identity"),
        },
    }
    return persisted


def safe_artifact_component(value: str) -> str:
    cleaned = re.sub(
        r"[^A-Za-z0-9._-]+", "_", str(value or "")
    ).strip("._-")
    return cleaned or "unknown"


def write_bug_localization_checkpoint(
    *,
    artifact_dir: str,
    bug_id: str,
    function_result: Dict[str, Any],
    file_result: Dict[str, Any],
    class_result: Dict[str, Any],
    combined_result: Dict[str, Any],
) -> str:
    """Persist one compact bug record before advancing to the next bug."""
    return atomic_write_json(
        os.path.join(
            artifact_dir,
            "fl_checkpoints",
            safe_artifact_component(bug_id) + ".json",
        ),
        {
            "schema": "unified_debugging.initial_fl_result.v2",
            "bug_id": str(bug_id or ""),
            "function": function_result,
            "file": file_result,
            "class": class_result,
            "combined": {
                "$ref": "#/function",
                "result_file": "fault_localization_results.json",
                "same_score_identity": (
                    combined_result.get("scores")
                    == function_result.get("scores")
                ),
            },
        },
    )


def load_bug_localization_checkpoints(
    *,
    output_dir: str,
) -> Dict[str, Any]:
    """Recover compact per-bug FL records after an interrupted run."""
    manifest = read_json(
        os.path.join(output_dir, "fault_localization_progress.json")
    )
    empty = {
        "manifest": {},
        "checkpoint_paths": {},
        "function": {},
        "file": {},
        "class": {},
        "combined": {},
        "diagnostics": [],
    }
    if (
        not isinstance(manifest, dict)
        or manifest.get("schema") != "unified_debugging.fl_progress.v2"
    ):
        return empty

    result = {
        **empty,
        "manifest": manifest,
    }
    for raw_bug_id, raw_path in (
        manifest.get("bug_checkpoints") or {}
    ).items():
        bug_id = str(raw_bug_id or "")
        path = str(raw_path or "")
        if path and not os.path.isabs(path):
            path = os.path.join(output_dir, path)
        payload = read_json(path)
        if (
            not bug_id
            or not isinstance(payload, dict)
            or payload.get("schema")
            != "unified_debugging.initial_fl_result.v2"
            or str(payload.get("bug_id") or "") != bug_id
        ):
            result["diagnostics"].append(
                f"invalid_bug_checkpoint:{bug_id or 'unknown'}"
            )
            continue
        function_result = payload.get("function")
        file_result = payload.get("file")
        class_result = payload.get("class")
        if not all(
            isinstance(value, dict)
            for value in (
                function_result,
                file_result,
                class_result,
            )
        ):
            result["diagnostics"].append(
                f"incomplete_bug_checkpoint:{bug_id}"
            )
            continue
        combined = payload.get("combined")
        if (
            isinstance(combined, dict)
            and combined.get("$ref") == "#/function"
        ):
            combined_result = dict(function_result)
        elif isinstance(combined, dict):
            combined_result = combined
        else:
            result["diagnostics"].append(
                f"invalid_combined_checkpoint:{bug_id}"
            )
            continue
        result["checkpoint_paths"][bug_id] = path
        result["function"][bug_id] = function_result
        result["file"][bug_id] = file_result
        result["class"][bug_id] = class_result
        result["combined"][bug_id] = combined_result
    return result
