"""Atomic, per-bug artifacts for the initial fault-localization pipeline."""

from __future__ import annotations

import gzip
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
    """Persist one complete bug before the pipeline advances to the next bug."""
    return atomic_write_json(
        os.path.join(artifact_dir, "fault_localization.result.json"),
        {
            "schema": "unified_debugging.initial_fl_result.v1",
            "bug_id": str(bug_id or ""),
            "function": function_result,
            "file": file_result,
            "class": class_result,
            "combined": combined_result,
        },
    )

