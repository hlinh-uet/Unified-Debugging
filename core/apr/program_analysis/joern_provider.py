import hashlib
import json
import os
import re
import shutil
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any, Dict, List

from core.apr.common import clip_text

from .models import (
    TargetAnalysisRequest,
    TargetOperationAnalysis,
    replacement_function_name,
    replacement_function_signature,
    replacement_source_path,
    replacement_start_line,
)


JOERN_ENGINE = {
    "name": "joern_program_analysis",
    "version": 1,
    "provider": "joern",
    "strategy": "joern_cpg_target_operation_query",
}


def joern_available() -> bool:
    return bool(_joern_bin() and _joern_parse_bin())


def joern_target_data_flow_slice(
    *,
    source_root: str,
    source_path: str,
    function_name: str,
    slice_depth: int = 8,
) -> Dict[str, Any]:
    """Run joern-slice on the cached CPG for one target method.

    ``joern-slice`` is deliberately given the existing CPG instead of source
    code.  Some Joern distributions bundle a slicer and a language frontend
    with slightly different CLI flags; reusing our cached CPG also avoids a
    second parse of the project.
    """
    joern_slice = _joern_slice_bin()
    joern_parse = _joern_parse_bin()
    if not joern_slice or not joern_parse:
        return _data_flow_slice_result(
            [], [], ["joern_slice_binary_not_found"], available=False
        )
    if not source_root or not os.path.isdir(source_root):
        return _data_flow_slice_result(
            [], [], ["source_root_missing_for_joern_slice"], available=False
        )
    cpg_path, cpg_uncertainties = _ensure_cpg(
        source_root=source_root, joern_parse=joern_parse
    )
    if not cpg_path:
        return _data_flow_slice_result(
            [], [], cpg_uncertainties or ["joern_slice_cpg_build_failed"], available=False
        )

    output_prefix = ""
    output_path = ""
    try:
        with tempfile.NamedTemporaryFile(
            prefix="apr_joern_slice_", delete=False
        ) as tmp:
            output_prefix = tmp.name
        output_path = output_prefix + ".json"
        method_leaf = str(function_name or "").rsplit("::", 1)[-1]
        # joern-slice applies these regexes to qualified values rather than
        # consistently to the leaf/basename. Exact binding is enforced again
        # against method, file and line range when consuming its graph.
        method_filter = re.escape(method_leaf)
        file_filter = _joern_slice_file_filter(source_root, source_path)
        if not file_filter:
            return _data_flow_slice_result(
                [], [], ["source_path_missing_for_joern_slice"], available=False,
                cpg_path=cpg_path,
            )
        depth = max(1, min(int(slice_depth or 8), 64))
        cmd = [
            joern_slice,
            "data-flow",
            "--slice-depth",
            str(depth),
            "--method-name-filter",
            method_filter,
            "--file-filter",
            file_filter,
            "--parallelism",
            str(_joern_slice_parallelism()),
            "--out",
            output_prefix,
            cpg_path,
        ]
        completed = _run_joern_command(
            cmd, timeout=_joern_timeout(), cpg_path=cpg_path
        )
        if completed.returncode != 0:
            return _data_flow_slice_result(
                [],
                [],
                ["joern_slice_query_failed"],
                available=False,
                cpg_path=cpg_path,
                file_filter=file_filter,
                stderr_excerpt=clip_text(completed.stderr, 4000),
            )
        payload, output_status = _read_joern_slice_result(output_prefix, output_path)
        if output_status == "missing":
            command_output = "\n".join([
                str(completed.stdout or ""),
                str(completed.stderr or ""),
            ]).lower()
            if "empty slice" in command_output or "no file generated" in command_output:
                return _data_flow_slice_result(
                    [], [], [*list(cpg_uncertainties or []), "joern_slice_returned_no_nodes"],
                    available=True,
                    cpg_path=cpg_path,
                    slice_depth=depth,
                    file_filter=file_filter,
                    stdout_excerpt=clip_text(completed.stdout, 1000),
                    stderr_excerpt=clip_text(completed.stderr, 1000),
                )
            return _data_flow_slice_result(
                [], [], ["joern_slice_result_missing"], available=False,
                cpg_path=cpg_path,
                file_filter=file_filter,
                stdout_excerpt=clip_text(completed.stdout, 1000),
                stderr_excerpt=clip_text(completed.stderr, 1000),
            )
        if output_status == "unreadable":
            return _data_flow_slice_result(
                [], [], ["joern_slice_result_unreadable"], available=False,
                cpg_path=cpg_path,
                file_filter=file_filter,
            )
        nodes = [item for item in payload.get("nodes") or [] if isinstance(item, dict)]
        edges = [item for item in payload.get("edges") or [] if isinstance(item, dict)]
        uncertainties = list(cpg_uncertainties or [])
        if not nodes:
            uncertainties.append("joern_slice_returned_no_nodes")
        return _data_flow_slice_result(
            nodes, edges, uncertainties, available=True, cpg_path=cpg_path,
            slice_depth=depth, file_filter=file_filter,
        )
    except subprocess.TimeoutExpired:
        return _data_flow_slice_result(
            [], [], ["joern_slice_query_timeout"], available=False,
            cpg_path=cpg_path,
        )
    except Exception as exc:
        return _data_flow_slice_result(
            [], [], [f"joern_slice_query_exception:{type(exc).__name__}"],
            available=False, cpg_path=cpg_path,
        )
    finally:
        cleanup_candidates = [output_prefix, output_path]
        if output_prefix:
            try:
                prefix = Path(output_prefix)
                cleanup_candidates.extend(
                    str(path) for path in prefix.parent.glob(prefix.name + "*.json")
                )
            except OSError:
                pass
        for candidate in dict.fromkeys(cleanup_candidates):
            if not candidate:
                continue
            try:
                os.unlink(candidate)
            except OSError:
                pass


def joern_cpg_tool_query(
    *,
    source_root: str,
    source_path: str = "",
    function_name: str = "",
    function_signature: str = "",
    function_start_line: int = 0,
    tool: str,
    symbols: List[str],
    query: str = "",
    kinds: List[str] = None,
    region_ids: List[str] = None,
    region_spans: List[Dict[str, Any]] = None,
    limit: int = 12,
    allow_source_scan_fallback: bool = True,
) -> Dict[str, Any]:
    """Run a focused live Joern CPG query for an APR semantic-context request."""
    joern = _joern_bin()
    joern_parse = _joern_parse_bin()
    if not joern or not joern_parse:
        return _tool_query_result(tool, [], ["joern_binary_not_found"], available=False)
    if not source_root or not os.path.isdir(source_root):
        return _tool_query_result(tool, [], ["source_root_missing_for_joern"], available=False)
    cpg_path, cpg_uncertainties = _ensure_cpg(source_root=source_root, joern_parse=joern_parse)
    if not cpg_path:
        return _tool_query_result(tool, [], cpg_uncertainties or ["joern_cpg_build_failed"], available=False)

    output_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="apr_joern_tool_", suffix=".json", delete=False) as tmp:
            output_path = tmp.name
        script_path = str(Path(__file__).resolve().parent / "queries" / "cpg_tool_query.sc")
        result_limit = max(1, min(int(limit or 12), 256 if tool == "get_target_behavior_analysis" else 64))
        cmd = [
            joern,
            "--script",
            script_path,
            "--param",
            f"cpgPath={cpg_path}",
            "--param",
            f"tool={tool}",
            "--param",
            f"symbols={_join_param(symbols)}",
            "--param",
            f"query={query}",
            "--param",
            f"kinds={_join_param(kinds or [])}",
            "--param",
            f"regionIds={_join_param(region_ids or [])}",
            "--param",
            f"regionSpans={_join_param(_encode_region_spans(region_spans or []))}",
            "--param",
            f"sourcePath={source_path}",
            "--param",
            f"functionName={function_name}",
            "--param",
            f"functionSignature={function_signature}",
            "--param",
            f"functionStartLine={int(function_start_line or 0)}",
            "--param",
            f"limit={result_limit}",
            "--param",
            f"outputPath={output_path}",
        ]
        completed = _run_joern_command(cmd, timeout=_joern_timeout(), cpg_path=cpg_path)
        if completed.returncode != 0:
            return _tool_query_result(
                tool,
                [],
                ["joern_cpg_tool_query_failed"],
                available=False,
                cpg_path=cpg_path,
                stderr_excerpt=clip_text(completed.stderr, 4000),
            )
        payload = _read_joern_tool_result(output_path)
        results = payload.get("results") or []
        if tool == "get_type_or_macro_definition" and allow_source_scan_fallback:
            results = _merge_tool_results(
                results,
                _source_macro_fallback_results(
                    source_root=source_root,
                    symbols=symbols,
                    limit=max(1, min(int(limit or 12), 64)),
                ),
                limit=max(1, min(int(limit or 12), 64)),
            )
        return {
            "engine": {
                **JOERN_ENGINE,
                "query": "cpg_tool_query",
                "available": True,
                "cpg_path": cpg_path,
            },
            "tool": tool,
            "results": results,
            "uncertainties": list(cpg_uncertainties or []) + list(payload.get("uncertainties") or []),
            "raw_result_count": int(payload.get("raw_result_count") or len(results)),
        }
    except subprocess.TimeoutExpired:
        return _tool_query_result(tool, [], ["joern_cpg_tool_query_timeout"], available=False, cpg_path=cpg_path)
    except Exception as exc:
        return _tool_query_result(
            tool,
            [],
            [f"joern_cpg_tool_query_exception:{type(exc).__name__}"],
            available=False,
            cpg_path=cpg_path,
        )
    finally:
        if output_path:
            try:
                os.unlink(output_path)
            except OSError:
                pass


def analyze_target_operations_joern(request: TargetAnalysisRequest) -> TargetOperationAnalysis:
    joern = _joern_bin()
    joern_parse = _joern_parse_bin()
    if not joern or not joern_parse:
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": False},
            operations=[],
            uncertainties=["joern_binary_not_found"],
        )
    source_root = request.source_root or _source_root_from_request(request)
    source_path = request.source_path or replacement_source_path(request.replacement_target)
    if not source_root or not os.path.isdir(source_root):
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": False},
            operations=[],
            uncertainties=["source_root_missing_for_joern"],
        )
    if not source_path:
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": False},
            operations=[],
            uncertainties=["source_path_missing_for_joern"],
        )

    cpg_path, cpg_uncertainties = _ensure_cpg(
        source_root=source_root,
        joern_parse=joern_parse,
    )
    if not cpg_path:
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": False},
            operations=[],
            uncertainties=cpg_uncertainties or ["joern_cpg_build_failed"],
        )

    output_path = ""
    try:
        with tempfile.NamedTemporaryFile(prefix="apr_joern_ops_", suffix=".json", delete=False) as tmp:
            output_path = tmp.name
        script_path = str(Path(__file__).resolve().parent / "queries" / "target_ops.sc")
        cmd = [
            joern,
            "--script",
            script_path,
            "--param",
            f"cpgPath={cpg_path}",
            "--param",
            f"sourcePath={source_path}",
            "--param",
            f"functionName={request.function_name or replacement_function_name(request.replacement_target)}",
            "--param",
            f"functionSignature={replacement_function_signature(request.replacement_target)}",
            "--param",
            f"startLine={replacement_start_line(request.replacement_target)}",
            "--param",
            f"outputPath={output_path}",
        ]
        completed = _run_joern_command(cmd, timeout=_joern_timeout(), cpg_path=cpg_path)
        if completed.returncode != 0:
            return TargetOperationAnalysis(
                engine={
                    **JOERN_ENGINE,
                    "available": False,
                    "cpg_path": cpg_path,
                    "stderr_excerpt": clip_text(completed.stderr, 800),
                },
                operations=[],
                uncertainties=["joern_query_failed"],
            )
        operation_payload = _read_joern_operations_result(output_path)
        operations = operation_payload.get("operations") or []
        query_uncertainties = operation_payload.get("uncertainties") or []
        if not operations:
            return TargetOperationAnalysis(
                engine={**JOERN_ENGINE, "available": False, "cpg_path": cpg_path},
                operations=[],
                uncertainties=list(cpg_uncertainties or []) + list(query_uncertainties or []) + ["joern_query_returned_no_operations"],
            )
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": True, "cpg_path": cpg_path},
            operations=operations[:220],
            uncertainties=list(cpg_uncertainties or []) + list(query_uncertainties or []),
        )
    except subprocess.TimeoutExpired:
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": False, "cpg_path": cpg_path},
            operations=[],
            uncertainties=["joern_query_timeout"],
        )
    except Exception as exc:
        return TargetOperationAnalysis(
            engine={**JOERN_ENGINE, "available": False, "cpg_path": cpg_path},
            operations=[],
            uncertainties=[f"joern_query_exception:{type(exc).__name__}"],
        )
    finally:
        if output_path:
            try:
                os.unlink(output_path)
            except OSError:
                pass


def _run_joern_command(cmd: List[str], *, timeout: int, cpg_path: str) -> subprocess.CompletedProcess:
    lock_path = _joern_lock_path(cpg_path)
    fd = -1
    deadline = time.time() + max(timeout, 1)
    while True:
        try:
            fd = os.open(lock_path, os.O_CREAT | os.O_EXCL | os.O_RDWR)
            _write_joern_lock_metadata(fd, cpg_path=cpg_path)
            break
        except FileExistsError:
            if _remove_stale_joern_lock(lock_path, timeout=timeout):
                continue
            if time.time() >= deadline:
                raise subprocess.TimeoutExpired(cmd, timeout)
            time.sleep(0.25)
    try:
        return subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=timeout,
        )
    finally:
        _release_joern_lock(fd, lock_path)


def _joern_slice_file_filter(source_root: str, source_path: str) -> str:
    """Return the repository-relative filename stored in CPG ``parentFile``."""
    root = os.path.realpath(str(source_root or ""))
    raw_path = str(source_path or "").strip()
    if not root or not raw_path:
        return ""

    if os.path.isabs(raw_path):
        absolute_path = os.path.realpath(raw_path)
    else:
        absolute_path = os.path.realpath(os.path.join(root, raw_path))
    try:
        relative_path = os.path.relpath(absolute_path, root)
    except ValueError:
        relative_path = raw_path
    normalized = os.path.normpath(relative_path).replace("\\", "/")
    if normalized in {"", "."}:
        return ""
    if normalized == ".." or normalized.startswith("../"):
        return os.path.normpath(raw_path).replace("\\", "/")
    return normalized[2:] if normalized.startswith("./") else normalized


def _read_joern_slice_result(output_prefix: str, output_path: str) -> tuple:
    """Read the mode-suffixed Joern output without mislabelling an empty slice."""
    candidates = [output_path, output_prefix]
    parent = Path(output_prefix).parent
    prefix_name = Path(output_prefix).name
    try:
        candidates.extend(str(path) for path in sorted(parent.glob(prefix_name + "*.json")))
    except OSError:
        pass

    saw_nonempty_output = False
    for candidate in dict.fromkeys(candidates):
        try:
            if not candidate or os.path.getsize(candidate) <= 0:
                continue
            saw_nonempty_output = True
            with open(candidate, "r", encoding="utf-8") as handle:
                payload = json.load(handle)
        except OSError:
            continue
        except (ValueError, TypeError):
            continue
        if isinstance(payload, dict):
            return payload, "ok"
    return None, "unreadable" if saw_nonempty_output else "missing"


def _joern_lock_path(cpg_path: str) -> str:
    lock_dir = os.getenv("APR_JOERN_LOCK_DIR", "").strip()
    if not lock_dir:
        lock_dir = os.path.join(tempfile.gettempdir(), "unified_debugging_joern_locks")
    os.makedirs(lock_dir, exist_ok=True)
    digest = hashlib.sha256(str(cpg_path or "joern").encode("utf-8", errors="replace")).hexdigest()[:24]
    return os.path.join(lock_dir, f"{digest}.lock")


def _write_joern_lock_metadata(fd: int, *, cpg_path: str) -> None:
    payload = {
        "pid": os.getpid(),
        "created_at": time.time(),
        "cpg_path": cpg_path,
    }
    try:
        os.write(fd, json.dumps(payload, sort_keys=True).encode("utf-8"))
        os.fsync(fd)
    except OSError:
        pass


def _release_joern_lock(fd: int, lock_path: str) -> None:
    same_lock = False
    if fd >= 0:
        try:
            held = os.fstat(fd)
            current = os.stat(lock_path)
            same_lock = held.st_ino == current.st_ino and held.st_dev == current.st_dev
        except OSError:
            same_lock = False
        try:
            os.close(fd)
        except OSError:
            pass
    if same_lock:
        try:
            os.unlink(lock_path)
        except OSError:
            pass


def _remove_stale_joern_lock(lock_path: str, *, timeout: int) -> bool:
    metadata = _read_joern_lock_metadata(lock_path)
    pid = _int_or_zero(metadata.get("pid"))
    created_at = _lock_created_at(lock_path, metadata)
    age = time.time() - created_at if created_at > 0 else float("inf")
    stale_after = _joern_stale_lock_seconds(timeout)
    stale = False
    if pid > 0:
        stale = (not _pid_is_alive(pid)) or age >= stale_after
    else:
        stale = age >= stale_after
    if not stale:
        return False
    try:
        os.unlink(lock_path)
        return True
    except FileNotFoundError:
        return True
    except OSError:
        return False


def _read_joern_lock_metadata(lock_path: str) -> Dict[str, Any]:
    try:
        with open(lock_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except (OSError, ValueError):
        return {}
    return payload if isinstance(payload, dict) else {}


def _pid_is_alive(pid: int) -> bool:
    if pid <= 0:
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    except OSError:
        return False


def _float_or_zero(value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        return 0.0


def _int_or_zero(value: Any) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return 0


def _lock_created_at(lock_path: str, metadata: Dict[str, Any]) -> float:
    created_at = _float_or_zero(metadata.get("created_at"))
    if created_at > 0:
        return created_at
    return _lock_file_mtime(lock_path)


def _lock_file_mtime(lock_path: str) -> float:
    try:
        return os.path.getmtime(lock_path)
    except OSError:
        return 0.0


def _joern_stale_lock_seconds(timeout: int) -> int:
    try:
        configured = int(
            os.getenv("APR_JOERN_STALE_LOCK_SEC")
            or os.getenv("APR_JOERN_LOCK_STALE_SEC")
            or "0"
        )
    except ValueError:
        configured = 0
    return max(configured, max(timeout * 2, 300))


def _joern_bin() -> str:
    configured = os.getenv("APR_JOERN_BIN", "").strip()
    return configured if configured and os.path.isfile(configured) else shutil.which(configured or "joern") or ""


def _joern_parse_bin() -> str:
    configured = os.getenv("APR_JOERN_PARSE_BIN", "").strip()
    return configured if configured and os.path.isfile(configured) else shutil.which(configured or "joern-parse") or ""


def _joern_slice_bin() -> str:
    configured = os.getenv("APR_JOERN_SLICE_BIN", "").strip()
    return configured if configured and os.path.isfile(configured) else shutil.which(configured or "joern-slice") or ""


def _joern_slice_parallelism() -> int:
    try:
        return max(1, min(int(os.getenv("APR_JOERN_SLICE_PARALLELISM", "2")), 32))
    except (TypeError, ValueError):
        return 2


def _joern_timeout() -> int:
    try:
        return int(os.getenv("APR_JOERN_TIMEOUT_SEC", "90"))
    except ValueError:
        return 90


def _source_root_from_request(request: TargetAnalysisRequest) -> str:
    source_path = request.source_path or replacement_source_path(request.replacement_target)
    if source_path:
        return os.path.dirname(source_path)
    return ""


def _ensure_cpg(*, source_root: str, joern_parse: str) -> tuple:
    cache_dir = os.getenv("APR_JOERN_CACHE_DIR", "").strip()
    if not cache_dir:
        cache_dir = os.path.join(tempfile.gettempdir(), "unified_debugging_joern_cpg")
    os.makedirs(cache_dir, exist_ok=True)
    cpg_path = os.path.join(cache_dir, _source_root_cache_key(source_root) + ".bin")
    if os.path.isfile(cpg_path):
        return cpg_path, []
    try:
        cmd = [joern_parse, source_root, "--output", cpg_path]
        completed = _run_joern_command(cmd, timeout=_joern_timeout(), cpg_path=cpg_path)
        if completed.returncode != 0 or not os.path.isfile(cpg_path):
            return "", ["joern_parse_failed", clip_text(completed.stderr, 500)]
        return cpg_path, []
    except subprocess.TimeoutExpired:
        return "", ["joern_parse_timeout"]
    except Exception as exc:
        return "", [f"joern_parse_exception:{type(exc).__name__}"]


def _source_root_cache_key(source_root: str) -> str:
    root = os.path.abspath(source_root)
    # Prefer git commit hash plus dirty worktree fingerprint. Correctness repair
    # often analyzes uncommitted candidate edits, so HEAD alone can reuse a stale CPG.
    git_hash = _git_commit_hash(root)
    if git_hash:
        dirty = _git_worktree_fingerprint(root)
        seed = f"{root}:git:{git_hash}:dirty:{dirty}"
    else:
        try:
            stat = os.stat(root)
            seed = f"{root}:mtime:{int(stat.st_mtime)}"
        except OSError:
            seed = root
    return hashlib.sha256(seed.encode("utf-8", errors="replace")).hexdigest()[:24]


def _git_commit_hash(source_root: str) -> str:
    """Return the current HEAD commit hash of the git repo containing source_root.

    Returns an empty string if git is unavailable, the directory is not in a
    git repo, or the command fails for any reason. Never raises.
    """
    try:
        completed = subprocess.run(
            ["git", "-C", source_root, "rev-parse", "HEAD"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            timeout=8,
        )
        if completed.returncode == 0:
            return completed.stdout.strip()[:40]
    except Exception:
        pass
    return ""


def _git_worktree_fingerprint(source_root: str) -> str:
    """Return a short fingerprint for uncommitted tracked/untracked changes."""
    parts = []
    commands = [
        ["git", "-C", source_root, "status", "--porcelain=v1", "--untracked-files=all"],
        ["git", "-C", source_root, "diff", "--no-ext-diff", "--binary"],
        ["git", "-C", source_root, "diff", "--cached", "--no-ext-diff", "--binary"],
    ]
    for cmd in commands:
        try:
            completed = subprocess.run(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.DEVNULL,
                text=False,
                timeout=12,
            )
            if completed.returncode == 0 and completed.stdout:
                parts.append(completed.stdout)
        except Exception:
            return "unknown"
    if not parts:
        return "clean"
    digest = hashlib.sha256(b"\0".join(parts)).hexdigest()[:16]
    return digest


def _read_joern_operations_result(output_path: str) -> Dict[str, Any]:
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return {"operations": [], "uncertainties": ["joern_operations_result_unreadable"]}
    raw_ops = payload.get("operations") if isinstance(payload, dict) else payload
    if not isinstance(raw_ops, list):
        return {"operations": [], "uncertainties": ["joern_operations_result_invalid"]}
    uncertainties = payload.get("uncertainties") if isinstance(payload, dict) and isinstance(payload.get("uncertainties"), list) else []
    out = []
    for idx, op in enumerate(raw_ops, start=1):
        if not isinstance(op, dict):
            continue
        code = str(op.get("code") or "").strip()
        kind = str(op.get("kind") or op.get("nodeType") or "operation")
        max_code_chars = 8000 if kind in {"method_definition", "type_definition"} else 1200
        line = _int_or_default(op.get("line"), -1)
        roles = _provenance_roles(op.get("roles") if isinstance(op.get("roles"), list) else [])
        out.append(
            {
                "id": op.get("id") or f"joern_op_{idx}",
                "kind": kind,
                "source": str(op.get("source") or op.get("filename") or ""),
                "line": line,
                "line_end": _int_or_default(op.get("line_end") or op.get("lineEnd"), line),
                "code": clip_text(code, max_code_chars),
                "symbols": op.get("symbols") if isinstance(op.get("symbols"), dict) else {},
                "method": str(op.get("method") or ""),
                "call_name": str(op.get("call_name") or op.get("callName") or ""),
                "method_full_name": str(op.get("method_full_name") or op.get("methodFullName") or ""),
                "arguments": op.get("arguments") if isinstance(op.get("arguments"), list) else [],
                "roles": roles,
                "control_ancestors": op.get("control_ancestors") if isinstance(op.get("control_ancestors"), list) else [],
                "dependency_paths": op.get("dependency_paths") if isinstance(op.get("dependency_paths"), list) else [],
                "semantic_symbols": op.get("semantic_symbols") if isinstance(op.get("semantic_symbols"), list) else [],
                "provider": "joern",
            }
        )
    return {"operations": out, "uncertainties": uncertainties}


def _read_joern_tool_result(output_path: str) -> Dict[str, Any]:
    try:
        with open(output_path, "r", encoding="utf-8") as f:
            payload = json.load(f)
    except Exception:
        return {"results": [], "uncertainties": ["joern_cpg_tool_result_unreadable"]}
    if not isinstance(payload, dict):
        return {"results": [], "uncertainties": ["joern_cpg_tool_result_invalid"]}
    raw_results = payload.get("results") if isinstance(payload.get("results"), list) else []
    results = []
    for idx, item in enumerate(raw_results, start=1):
        if not isinstance(item, dict):
            continue
        line = _int_or_default(item.get("line"), -1)
        line_end = _int_or_default(item.get("line_end") or item.get("lineEnd"), line)
        result = {
            "id": str(item.get("id") or f"cpg_result_{idx:04d}"),
            "kind": str(item.get("kind") or "cpg_result"),
            "symbol": str(item.get("symbol") or ""),
            "source": str(item.get("source") or item.get("filename") or ""),
            "line": line,
            "line_end": line_end if line_end >= line else line,
            "method": str(item.get("method") or ""),
            "caller": str(item.get("caller") or ""),
            "callee": str(item.get("callee") or ""),
            "code": clip_text(item.get("code") or "", 8000),
            "arguments": item.get("arguments") if isinstance(item.get("arguments"), list) else [],
            "control_context": item.get("control_context") if isinstance(item.get("control_context"), list) else [],
            "dependency_paths": item.get("dependency_paths") if isinstance(item.get("dependency_paths"), list) else [],
            "full_name": str(item.get("full_name") or item.get("fullName") or ""),
            "signature": str(item.get("signature") or ""),
            "roles": item.get("roles") if isinstance(item.get("roles"), list) else [],
            "provider": "joern",
        }
        results.append(result)
    return {
        "results": results,
        "uncertainties": payload.get("uncertainties") if isinstance(payload.get("uncertainties"), list) else [],
        "raw_result_count": _int_or_default(payload.get("raw_result_count"), len(results)),
    }


def _source_macro_fallback_results(*, source_root: str, symbols: List[str], limit: int) -> List[Dict[str, Any]]:
    wanted = {str(item).strip() for item in symbols or [] if str(item).strip()}
    if not wanted or not source_root or not os.path.isdir(source_root):
        return []
    results: List[Dict[str, Any]] = []
    scanned_files = 0
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [
            item for item in dirs
            if item not in {".git", ".hg", ".svn", "build", "dist", "node_modules", "__pycache__"}
        ]
        for filename in files:
            if not _macro_candidate_file(filename):
                continue
            scanned_files += 1
            if scanned_files > 1200:
                return results[:limit]
            path = os.path.join(root, filename)
            results.extend(_macro_definitions_in_file(path=path, source_root=source_root, wanted=wanted, limit=limit))
            if len(results) >= limit:
                return results[:limit]
    return results[:limit]


def _macro_definitions_in_file(*, path: str, source_root: str, wanted: set, limit: int) -> List[Dict[str, Any]]:
    macro_re = re.compile(r"^\s*#\s*define\s+([A-Za-z_][A-Za-z0-9_]*)\b(.*)$")
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except OSError:
        return []
    out: List[Dict[str, Any]] = []
    idx = 0
    while idx < len(lines):
        raw = lines[idx].rstrip("\n")
        match = macro_re.match(raw)
        if not match:
            idx += 1
            continue
        name = match.group(1)
        start_line = idx + 1
        definition_lines = [raw]
        while definition_lines[-1].rstrip().endswith("\\") and idx + 1 < len(lines):
            idx += 1
            definition_lines.append(lines[idx].rstrip("\n"))
        if name in wanted:
            rel = os.path.relpath(path, source_root).replace(os.sep, "/")
            code = "\n".join(definition_lines)
            out.append(
                {
                    "id": f"source_macro_{hashlib.sha1((rel + ':' + name + ':' + str(start_line)).encode('utf-8', errors='replace')).hexdigest()[:12]}",
                    "kind": "macro_definition",
                    "symbol": name,
                    "source": rel,
                    "line": start_line,
                    "line_end": start_line + len(definition_lines) - 1,
                    "method": "",
                    "caller": "",
                    "callee": "",
                    "code": clip_text(code, 4000),
                    "arguments": [],
                    "control_context": [],
                    "dependency_paths": [],
                    "full_name": name,
                    "signature": "",
                    "provider": "source_scan",
                }
            )
            if len(out) >= limit:
                return out
        idx += 1
    return out


def _macro_candidate_file(filename: str) -> bool:
    lower = filename.lower()
    return lower.endswith((".h", ".hh", ".hpp", ".hxx", ".c", ".cc", ".cpp", ".cxx", ".inc"))


def _merge_tool_results(primary: List[Dict[str, Any]], fallback: List[Dict[str, Any]], limit: int) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    seen = set()
    for item in list(primary or []) + list(fallback or []):
        if not isinstance(item, dict):
            continue
        key = (
            str(item.get("kind") or ""),
            str(item.get("symbol") or ""),
            str(item.get("source") or ""),
            str(item.get("line") or ""),
            str(item.get("code") or ""),
        )
        if key in seen:
            continue
        seen.add(key)
        out.append(item)
        if len(out) >= limit:
            break
    return out


def _tool_query_result(
    tool: str,
    results: List[Dict[str, Any]],
    uncertainties: List[str],
    *,
    available: bool,
    cpg_path: str = "",
    stderr_excerpt: str = "",
) -> Dict[str, Any]:
    engine = {
        **JOERN_ENGINE,
        "query": "cpg_tool_query",
        "available": available,
    }
    if cpg_path:
        engine["cpg_path"] = cpg_path
    if stderr_excerpt:
        engine["stderr_excerpt"] = stderr_excerpt
    return {
        "engine": engine,
        "tool": tool,
        "results": results,
        "uncertainties": uncertainties,
    }


def _data_flow_slice_result(
    nodes: List[Dict[str, Any]],
    edges: List[Dict[str, Any]],
    uncertainties: List[str],
    *,
    available: bool,
    cpg_path: str = "",
    slice_depth: int = 0,
    file_filter: str = "",
    stdout_excerpt: str = "",
    stderr_excerpt: str = "",
) -> Dict[str, Any]:
    engine = {
        **JOERN_ENGINE,
        "query": "joern-slice:data-flow",
        "available": available,
    }
    if cpg_path:
        engine["cpg_path"] = cpg_path
    if slice_depth:
        engine["slice_depth"] = slice_depth
    if file_filter:
        engine["file_filter"] = file_filter
    if stdout_excerpt:
        engine["stdout_excerpt"] = stdout_excerpt
    if stderr_excerpt:
        engine["stderr_excerpt"] = stderr_excerpt
    return {
        "engine": engine,
        "nodes": nodes,
        "edges": edges,
        "uncertainties": list(uncertainties or []),
    }


def _join_param(values: List[Any]) -> str:
    return "|".join(str(value).replace("|", " ") for value in values or [] if str(value).strip())


def _encode_region_spans(regions: List[Dict[str, Any]]) -> List[str]:
    out = []
    for region in regions or []:
        if not isinstance(region, dict):
            continue
        region_id = str(region.get("id") or "").replace(",", "_")
        try:
            start_line = int(region.get("start_line") or 0)
            end_line = int(region.get("end_line") or start_line)
        except (TypeError, ValueError):
            continue
        if not region_id or start_line <= 0:
            continue
        code_hash = str(region.get("code_hash") or "").replace(",", "_")
        out.append(f"{region_id},{start_line},{max(start_line, end_line)},{code_hash}")
    return out[:24]


def _provenance_roles(roles: List[Any]) -> List[str]:
    allowed = {"target_method", "direct_callee_method", "caller_method", "related_method"}
    return [str(role) for role in roles or [] if str(role) in allowed]


def _int_or_default(value: Any, default: int) -> int:
    try:
        return int(value)
    except Exception:
        return default
