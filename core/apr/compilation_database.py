"""Materialize analysis compilation databases from real sandbox build output."""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple


STANDARD_BUILD_DIRS = (
    "build", "build-debug", "build-release", "cmake-build-debug",
    "build_meta", "build_meta_fmt", "build_meta_libyang", "build_meta_php",
)


def find_build_compilation_database(roots: Iterable[str]) -> str:
    """Find a database in known build locations without walking the whole project."""
    for value in roots:
        root = Path(str(value or ""))
        if not root.is_dir():
            continue
        direct = root / "compile_commands.json"
        if direct.is_file():
            return str(direct.resolve())
        analysis_cache = root / ".apr" / "compile_commands.json"
        if analysis_cache.is_file():
            return str(analysis_cache.resolve())
        for dirname in STANDARD_BUILD_DIRS:
            candidate = root / dirname / "compile_commands.json"
            if candidate.is_file():
                return str(candidate.resolve())
        for candidate in sorted(root.glob("build_meta_*/compile_commands.json"))[:12]:
            if candidate.is_file():
                return str(candidate.resolve())
    return ""


def materialize_analysis_database(
    *, source_database: str, output_database: str,
    build_source_root: str, analysis_source_root: str,
    path_mappings: Iterable[Tuple[str, str]] = (),
) -> Dict[str, Any]:
    """Rewrite build commands so source includes bind to the immutable buggy tree."""
    try:
        with open(source_database, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError) as exc:
        return _unavailable(f"compilation_database_read_failed:{type(exc).__name__}")
    if not isinstance(payload, list):
        return _unavailable("compilation_database_not_array")

    build_root = os.path.realpath(build_source_root)
    analysis_root = os.path.realpath(analysis_source_root)
    mappings = [
        (os.path.normpath(str(old)), os.path.normpath(str(new)))
        for old, new in path_mappings
        if str(old) and str(new)
    ]
    rewritten = []
    for raw in payload:
        if not isinstance(raw, dict):
            continue
        entry = dict(raw)
        original_directory = _map_path(str(entry.get("directory") or build_root), mappings)
        directory = original_directory or build_root
        original_file = _absolute_entry_file(entry)
        mapped_file = _analysis_source_path(
            _map_path(original_file, mappings),
            build_root=build_root,
            analysis_root=analysis_root,
        )
        entry["directory"] = directory
        entry["file"] = mapped_file
        arguments = _entry_arguments(entry)
        if arguments:
            entry.pop("command", None)
            entry["arguments"] = _rewrite_arguments(
                arguments,
                original_directory=str(raw.get("directory") or build_root),
                build_root=build_root,
                analysis_root=analysis_root,
                source_from=original_file,
                source_to=mapped_file,
                mappings=mappings,
            )
        rewritten.append(entry)
    if not rewritten:
        return _unavailable("compilation_database_has_no_commands")

    output_path = os.path.realpath(output_database)
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        temporary = output_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump(rewritten, stream, indent=2)
        os.replace(temporary, output_path)
    except OSError as exc:
        return _unavailable(f"compilation_database_write_failed:{type(exc).__name__}")
    return {
        "version": 1,
        "available": True,
        "database_path": output_path,
        "source_database": os.path.realpath(source_database),
        "command_count": len(rewritten),
        "build_source_root": build_root,
        "analysis_source_root": analysis_root,
        "allowed_source_roots": list(dict.fromkeys([
            value for value in (analysis_root, build_root) if value
        ])),
        "path_policy": "build_flags_with_buggy_source_remap",
        "diagnostics": [],
    }


def write_single_file_database(
    *, output_database: str, directory: str, source_path: str,
    arguments: List[str], provider: str,
) -> Dict[str, Any]:
    """Write an adapter-owned command that is already the real validation command."""
    output_path = os.path.realpath(output_database)
    entry = {
        "directory": os.path.realpath(directory),
        "file": os.path.realpath(source_path),
        "arguments": [str(value) for value in arguments],
    }
    try:
        os.makedirs(os.path.dirname(output_path), exist_ok=True)
        temporary = output_path + ".tmp"
        with open(temporary, "w", encoding="utf-8") as stream:
            json.dump([entry], stream, indent=2)
        os.replace(temporary, output_path)
    except OSError as exc:
        return _unavailable(f"compilation_database_write_failed:{type(exc).__name__}")
    root = os.path.realpath(directory)
    return {
        "version": 1,
        "available": True,
        "database_path": output_path,
        "source_database": output_path,
        "command_count": 1,
        "build_source_root": root,
        "analysis_source_root": root,
        "allowed_source_roots": [root],
        "provider": provider,
        "path_policy": "adapter_exact_validation_command",
        "diagnostics": [],
    }


def _rewrite_arguments(
    arguments: List[str], *, original_directory: str,
    build_root: str, analysis_root: str, source_from: str, source_to: str,
    mappings: List[Tuple[str, str]],
) -> List[str]:
    out = []
    index = 0
    path_flags = {"-I", "-isystem", "-iquote", "-include", "-imacros"}
    while index < len(arguments):
        argument = str(arguments[index])
        if argument in path_flags and index + 1 < len(arguments):
            out.extend([argument, _rewrite_include_path(
                str(arguments[index + 1]), original_directory=original_directory,
                build_root=build_root, analysis_root=analysis_root, mappings=mappings,
            )])
            index += 2
            continue
        joined_flag = next((flag for flag in path_flags if argument.startswith(flag) and argument != flag), "")
        if joined_flag:
            out.append(joined_flag + _rewrite_include_path(
                argument[len(joined_flag):], original_directory=original_directory,
                build_root=build_root, analysis_root=analysis_root, mappings=mappings,
            ))
        else:
            resolved = _resolve_argument_path(argument, original_directory)
            if resolved == source_from:
                out.append(source_to)
            else:
                out.append(_map_path(argument, mappings))
        index += 1
    return out


def _rewrite_include_path(
    value: str, *, original_directory: str, build_root: str,
    analysis_root: str, mappings: List[Tuple[str, str]],
) -> str:
    resolved = value if os.path.isabs(value) else os.path.join(original_directory, value)
    resolved = os.path.realpath(resolved)
    mapped = _analysis_source_path(
        _map_path(resolved, mappings),
        build_root=build_root,
        analysis_root=analysis_root,
    )
    return mapped if os.path.exists(mapped) else _map_path(value, mappings)


def _analysis_source_path(path: str, *, build_root: str, analysis_root: str) -> str:
    try:
        relative = os.path.relpath(path, build_root)
    except ValueError:
        return path
    if relative == ".." or relative.startswith(".." + os.sep):
        return path
    candidate = os.path.realpath(os.path.join(analysis_root, relative))
    return candidate if os.path.exists(candidate) else path


def _map_path(value: str, mappings: Iterable[Tuple[str, str]]) -> str:
    normalized = os.path.normpath(str(value or ""))
    for old, new in mappings:
        if normalized == old:
            return new
        prefix = old.rstrip(os.sep) + os.sep
        if normalized.startswith(prefix):
            return new.rstrip(os.sep) + os.sep + normalized[len(prefix):]
    return value


def _absolute_entry_file(entry: Dict[str, Any]) -> str:
    directory = str(entry.get("directory") or ".")
    value = str(entry.get("file") or "")
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(directory, value))


def _entry_arguments(entry: Dict[str, Any]) -> List[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        return [str(value) for value in arguments]
    try:
        return shlex.split(str(entry.get("command") or ""))
    except ValueError:
        return []


def _resolve_argument_path(value: str, directory: str) -> str:
    if not value or value.startswith("-"):
        return ""
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(directory, value))


def _unavailable(reason: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "available": False,
        "database_path": "",
        "diagnostics": [reason],
    }
