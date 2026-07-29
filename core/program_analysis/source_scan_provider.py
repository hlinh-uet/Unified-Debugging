"""Deterministic lexical/AST evidence fallback independent of Joern."""

import hashlib
import os
import re
from typing import Any, Dict, Iterable, List

from .source_utils import SOURCE_EXTS, clip_text


def query_source_evidence(
    *,
    source_root: str,
    source_path: str,
    function_name: str,
    tool: str,
    symbols: List[str],
    limit: int,
) -> Dict[str, Any]:
    if not source_root or not os.path.isdir(source_root):
        return _result(tool, [], ["source_scan_root_missing"])
    wanted = _wanted_symbols(symbols, function_name if tool in {"get_callers", "get_callees"} else "")
    if not wanted:
        return _result(tool, [], ["source_scan_requires_symbol"])
    results = []
    for path in _candidate_paths(source_root, source_path):
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as handle:
                lines = handle.readlines()
        except OSError:
            continue
        rel = os.path.relpath(path, source_root).replace(os.sep, "/")
        for line_number, raw in enumerate(lines, start=1):
            if len(results) >= limit:
                return _result(tool, results, ["source_scan_bounded"])
            line = raw.rstrip("\n")
            for symbol in wanted:
                if not re.search(r"(?<![A-Za-z0-9_])" + re.escape(symbol) + r"(?![A-Za-z0-9_])", line):
                    continue
                kind = _kind(tool, line, symbol)
                if not kind:
                    continue
                start = max(0, line_number - 3)
                end = min(len(lines), line_number + 2)
                code = "".join(lines[start:end]).rstrip()
                results.append({
                    "id": "source_scan_" + hashlib.sha1(f"{tool}:{rel}:{line_number}:{symbol}".encode()).hexdigest()[:12],
                    "kind": kind,
                    "symbol": symbol,
                    "source": rel,
                    "line": line_number,
                    "line_end": line_number,
                    "method": "",
                    "caller": "",
                    "callee": symbol if kind in {"method_definition", "direct_callee_context"} else "",
                    "code": clip_text(code, 2400),
                    "arguments": _call_arguments(line, symbol),
                    "control_context": [],
                    "dependency_paths": [],
                    "full_name": symbol,
                    "signature": line.strip() if kind in {"method_definition", "type_definition"} else "",
                    "provider": "source_scan",
                })
    return _result(tool, results, [] if results else ["source_scan_no_results"])


def _candidate_paths(root: str, preferred: str) -> Iterable[str]:
    yielded = set()
    if preferred and os.path.isfile(preferred):
        yielded.add(os.path.abspath(preferred))
        yield preferred
    scanned = 0
    for directory, dirs, files in os.walk(root):
        dirs[:] = [item for item in dirs if item not in {".git", "build", "dist", "node_modules", "__pycache__", ".venv"}]
        for filename in files:
            if os.path.splitext(filename)[1].lower() not in SOURCE_EXTS:
                continue
            path = os.path.join(directory, filename)
            if os.path.abspath(path) in yielded:
                continue
            yield path
            scanned += 1
            if scanned >= 600:
                return


def _kind(tool: str, line: str, symbol: str) -> str:
    stripped = line.strip()
    if tool == "get_type_or_macro_definition":
        if re.match(r"#\s*define\s+" + re.escape(symbol) + r"\b", stripped):
            return "macro_definition"
        if re.search(r"\b(?:struct|class|union|enum|typedef)\b[^;{]*\b" + re.escape(symbol) + r"\b", stripped):
            return "type_definition"
        return ""
    call = re.search(re.escape(symbol) + r"\s*\(", line)
    if tool == "get_callees":
        if call and ("{" in line or re.search(r"\)\s*(?:const\s*)?\{?\s*$", line)):
            return "method_definition"
        return ""
    if tool == "get_callers":
        return "caller_context" if call else ""
    if tool in {"get_symbol_usages", "search_cpg_evidence"}:
        return "usage_example"
    return ""


def _call_arguments(line: str, symbol: str) -> List[str]:
    match = re.search(re.escape(symbol) + r"\s*\(([^()]*)\)", line)
    if not match:
        return []
    return [part.strip() for part in match.group(1).split(",") if part.strip()][:16]


def _wanted_symbols(symbols: List[str], fallback: str) -> List[str]:
    out = []
    for value in list(symbols or []) + ([fallback] if fallback else []):
        leaf = str(value or "").split("::")[-1].strip()
        if leaf and leaf not in out:
            out.append(leaf)
    return out[:16]


def _result(tool: str, results: List[Dict[str, Any]], uncertainties: List[str]) -> Dict[str, Any]:
    return {
        "engine": {"name": "source_scan_program_analysis", "provider": "source_scan", "query": tool, "available": bool(results)},
        "tool": tool,
        "results": results,
        "uncertainties": uncertainties,
    }
