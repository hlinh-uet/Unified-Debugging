from __future__ import annotations

import argparse
import json
import os
import re
import time
from dataclasses import dataclass
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

from core.fl_dstar import calculate_dstar, spectrum_counts
from data_loaders.defects4c_loader import (
    FAIL_OUTCOMES,
    PASS_OUTCOMES,
    Defects4CLoadConfig,
    default_defects4c_root,
    load_defects4c_bugs,
)

try:  # pragma: no cover - optional convenience for CLI runs.
    import requests
except Exception:  # pragma: no cover
    requests = None

try:  # pragma: no cover - optional convenience for CLI runs.
    from dotenv import load_dotenv
except Exception:  # pragma: no cover
    load_dotenv = None


DEFAULT_OPENROUTER_URL = "https://openrouter.ai/api/v1/chat/completions"
DEFAULT_OPENROUTER_MODEL = "openai/gpt-oss-120b"
EVAL_TOP_KS = (1, 3, 5, 10, 20, 30)


@dataclass
class LocalizationAgentConfig:
    dataset: str = "fmt"
    metadata_dir: str = ""
    defects4c_root: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    top_k: int = 10
    inspect_top_k: int = 0
    code_mode: str = "signature"
    max_code_lines: int = 120
    context_lines: int = 3
    exclude_fixed_fail_tests: bool = True


@dataclass
class LocalizationAgentLlmConfig:
    dataset: str = "fmt"
    payload_file: str = ""
    output_file: str = ""
    bug_id_filter: str = ""
    model: str = ""
    api_url: str = DEFAULT_OPENROUTER_URL
    api_key_env: str = "OPENROUTER_API_KEY"
    timeout_seconds: int = 120
    max_tokens: int = 4096
    temperature: float = 0.0
    candidate_limit: int = 15
    inspected_limit: int = 10
    max_code_lines_per_function: int = 80
    dry_run: bool = False
    resume: bool = False
    request_interval_seconds: float = 0.0


CODE_MODES = {"signature", "executed_lines", "windowed", "skeleton", "full"}
SOURCE_EXTENSIONS = (".c", ".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx")
PRUNE_DIRS = {
    ".git",
    ".hg",
    ".svn",
    "__pycache__",
    "build",
    "build_meta_fmt",
    "CMakeFiles",
    ".pytest_cache",
}
SEMANTIC_STOPWORDS = {
    "test",
    "tests",
    "case",
    "failure",
    "failed",
    "actual",
    "expected",
    "value",
    "values",
    "line",
    "file",
    "type",
    "with",
    "from",
    "this",
    "that",
    "then",
    "than",
    "into",
    "nothing",
    "pass",
    "fail",
}


def _outcome(value: object) -> str:
    return str(value or "").strip().upper()


def _covered_functions(test: dict) -> List[str]:
    covered = test.get("covered_functions")
    if covered is None:
        covered = test.get("covered_methods", [])
    if not isinstance(covered, list):
        return []
    return [str(item) for item in covered if item]


def _sort_ranked(rows: Sequence[dict]) -> List[dict]:
    return sorted(rows, key=lambda item: (-float(item.get("score", 0.0)), item.get("function_id", "")))


def _normalize_scores(scores: Dict[str, float]) -> Dict[str, float]:
    if not scores:
        return {}
    values = list(scores.values())
    min_score = min(values)
    max_score = max(values)
    if max_score == min_score:
        return {key: (1.0 if max_score > 0 else 0.0) for key in scores}
    return {key: (value - min_score) / (max_score - min_score) for key, value in scores.items()}


def _split_function_key(function_id: str) -> Tuple[str, str]:
    match = re.search(r"(?<!:):(?!:)", str(function_id or ""))
    if not match:
        return "", str(function_id or "")
    return function_id[: match.start()], function_id[match.end() :]


def _function_tail(function_id: str) -> str:
    _, name = _split_function_key(function_id)
    return name.split("::")[-1] if name else str(function_id or "")


def _tokenize(text: object) -> List[str]:
    text = str(text or "")
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", text)
    text = text.replace("::", " ")
    text = re.sub(r"[_\-/\\.:{}()<>\"',;=\[\]]+", " ", text)
    tokens = []
    for token in re.findall(r"[A-Za-z][A-Za-z0-9]+|[0-9]+", text):
        lowered = _normalize_token(token.lower())
        if len(lowered) > 1 and lowered not in SEMANTIC_STOPWORDS:
            tokens.append(lowered)
    return tokens


def _normalize_token(token: str) -> str:
    aliases = {
        "args": "arg",
        "arguments": "argument",
        "params": "param",
        "parameters": "parameter",
        "errors": "error",
        "exceptions": "exception",
        "throws": "throw",
        "thrown": "throw",
        "checks": "check",
        "checked": "check",
        "parses": "parse",
        "parsed": "parse",
        "names": "name",
    }
    return aliases.get(token, token)


def _read_metadata(bug: dict) -> dict:
    path = bug.get("metadata_path") or ""
    if not path:
        return {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _true_failing_tests(tests: Sequence[dict]) -> List[dict]:
    return [test for test in tests if _outcome(test.get("outcome")) in FAIL_OUTCOMES]


def _passing_tests(tests: Sequence[dict]) -> List[dict]:
    return [test for test in tests if _outcome(test.get("outcome")) in PASS_OUTCOMES]


def _failure_summary(test: dict) -> dict:
    failure = test.get("failure") or {}
    runtime = test.get("runtime") or {}
    if not isinstance(failure, dict):
        failure = {}
    if not isinstance(runtime, dict):
        runtime = {}
    return {
        "test_id": test.get("test_id", ""),
        "outcome": test.get("outcome", ""),
        "outcome_fixed": test.get("outcome_fixed", ""),
        "failure_type": failure.get("type", ""),
        "oracle": failure.get("oracle", ""),
        "assertion_location": failure.get("assertion_location", ""),
        "expected_value": failure.get("expected_value", ""),
        "actual_value": failure.get("actual_value", ""),
        "observed_expression": failure.get("observed_expression", ""),
        "signal_lines": failure.get("signal_lines", [])[:8],
        "covered_function_count": len(_covered_functions(test)),
        "replay_command": runtime.get("replay_command", ""),
        "cwd": runtime.get("cwd", ""),
    }


def build_case_card(bug: dict, metadata: Optional[dict] = None) -> dict:
    metadata = metadata or _read_metadata(bug)
    tests = bug.get("tests", [])
    failing = _true_failing_tests(tests)
    covered_functions = set()
    for test in tests:
        covered_functions.update(_covered_functions(test))

    return {
        "bug_id": bug.get("bug_id", ""),
        "metadata_bug_id": bug.get("metadata_bug_id", ""),
        "dataset": bug.get("dataset", ""),
        "project": bug.get("project", metadata.get("project", "")),
        "language": metadata.get("language", ""),
        "type_name": metadata.get("type_name", ""),
        "metadata_path": bug.get("metadata_path", ""),
        "test_counts": {
            "total": len(tests),
            "failing": len(failing),
            "passing": len(_passing_tests(tests)),
            "covered_functions": len(covered_functions),
        },
        "failing_tests": [_failure_summary(test) for test in failing],
        "available_tools": [
            "rank_functions",
            "compare_fail_pass_coverage",
            "expand_function_neighbors",
            "get_test_source_context",
            "collect_line_coverage",
            "get_function_code",
            "get_executed_code",
            "get_candidate_slice",
            "submit_localization",
        ],
        "notes": [
            "ground_truth is intentionally omitted from the agent-facing case card",
            "code is fetched only through code/slice tools for selected candidates",
        ],
    }


def build_localization_graph_summary(bug: dict, metadata: Optional[dict] = None) -> dict:
    metadata = metadata or _read_metadata(bug)
    tests = bug.get("tests", [])
    functions = set()
    files = set()
    coverage_edges = 0

    for test in tests:
        covered = set(_covered_functions(test))
        coverage_edges += len(covered)
        functions.update(covered)
        for function_id in covered:
            file_part, _ = _split_function_key(function_id)
            if file_part:
                files.add(file_part)

    return {
        "nodes": {
            "bug_cases": 1,
            "failures": len(_true_failing_tests(tests)),
            "test_cases": len(tests),
            "functions": len(functions),
            "files": len(files),
        },
        "edges": {
            "bug_to_failure": len(_true_failing_tests(tests)),
            "bug_to_test": len(tests),
            "test_to_function_coverage": coverage_edges,
            "function_to_file": len(functions),
        },
        "coverage_scope": (metadata.get("phase_info") or {}).get("coverage_scope", ""),
    }


def _case_tokens(bug: dict, metadata: dict) -> set:
    chunks: List[str] = [
        str(metadata.get("type_name", "")),
        str(metadata.get("source_basename", "")),
    ]
    for test in _true_failing_tests(bug.get("tests", [])):
        chunks.append(str(test.get("test_id", "")))
        failure = test.get("failure") or {}
        if isinstance(failure, dict):
            chunks.extend(
                [
                    str(failure.get("expected_value", "")),
                    str(failure.get("actual_value", "")),
                    str(failure.get("observed_expression", "")),
                    " ".join(str(line) for line in failure.get("signal_lines", [])[:8]),
                ]
            )
        chunks.append(str(test.get("fail_reason", ""))[:1200])
    return set(_tokenize(" ".join(chunks)))


def _name_relevance(function_id: str, case_tokens: set) -> float:
    function_tokens = set(_tokenize(function_id))
    if not function_tokens or not case_tokens:
        return 0.0
    overlap = function_tokens & case_tokens
    return min(1.0, len(overlap) / max(3.0, float(len(function_tokens))))


def _role_relevance(function_id: str, case_tokens: set) -> float:
    tokens = set(_tokenize(function_id))
    if not tokens:
        return 0.0
    score = 0.0
    if {"named", "arg"} <= case_tokens and {"named", "arg"} <= tokens:
        score += 0.45
    if "arg" in case_tokens and "arg" in tokens and "id" in tokens:
        score += 0.35
    if ("exception" in case_tokens or "throw" in case_tokens or "error" in case_tokens) and (
        tokens & {"error", "throw", "check", "invalid"}
    ):
        score += 0.30
    if "format" in case_tokens and "parse" in tokens:
        score += 0.15
    if "actual" in case_tokens and tokens & {"return", "value"}:
        score += 0.10
    return min(1.0, score)


def _generic_function_penalty(function_id: str) -> float:
    _, name = _split_function_key(function_id)
    parts = [part for part in name.split("::") if part]
    if not parts:
        return 0.0
    tail = parts[-1]
    owner = parts[-2] if len(parts) >= 2 else ""
    tokens = set(_tokenize(function_id))
    penalty = 0.0
    if owner and (tail == owner or tail == f"~{owner}"):
        penalty += 0.12
    if tail.startswith("~"):
        penalty += 0.10
    if tail in {
        "begin",
        "end",
        "data",
        "size",
        "reserve",
        "resize",
        "set",
        "args",
        "arg",
        "type",
        "operator bool",
        "decltype",
        "v7",
        "do",
    }:
        penalty += 0.08
    if "operator" in tail and not (tokens & {"arg", "id", "error", "parse", "format"}):
        penalty += 0.05
    return min(0.25, penalty)


def _line_signal_for_function(function_id: str, tests: Sequence[dict]) -> float:
    file_part, _ = _split_function_key(function_id)
    if not file_part:
        return 0.0
    file_part = file_part.replace("\\", "/")
    basename = os.path.basename(file_part)
    for test in _true_failing_tests(tests):
        line_keys, _ = line_keys_from_test(test)
        for line_key in line_keys:
            line_file, _ = _split_line_key(line_key)
            if line_file and (line_file.endswith(file_part) or os.path.basename(line_file) == basename):
                return 1.0
    return 0.0


def compare_fail_pass_coverage(function_id: str, tests: Sequence[dict]) -> dict:
    failing_tests = []
    passing_tests = []
    for test in tests:
        covered = set(_covered_functions(test))
        if function_id not in covered:
            continue
        row = {
            "test_id": test.get("test_id", ""),
            "covered_function_count": len(covered),
        }
        outcome = _outcome(test.get("outcome"))
        if outcome in FAIL_OUTCOMES:
            failing_tests.append(row)
        elif outcome in PASS_OUTCOMES:
            passing_tests.append(row)
    return {
        "function_id": function_id,
        "failing_count": len(failing_tests),
        "passing_count": len(passing_tests),
        "failing_tests": failing_tests[:20],
        "passing_tests_sample": passing_tests[:20],
    }


def rank_functions(bug: dict, metadata: Optional[dict] = None, top_k: int = 30) -> List[dict]:
    metadata = metadata or _read_metadata(bug)
    tests = bug.get("tests", [])
    total_passed, total_failed, passed_by_function, failed_by_function = spectrum_counts(tests)
    dstar_scores = calculate_dstar(tests, star=2)
    normalized_dstar = _normalize_scores(dstar_scores)
    all_functions = sorted(set(passed_by_function) | set(failed_by_function) | set(dstar_scores))
    case_tokens = _case_tokens(bug, metadata)
    rows = []

    for function_id in all_functions:
        failed = failed_by_function.get(function_id, 0)
        passed = passed_by_function.get(function_id, 0)
        failing_coverage = failed / total_failed if total_failed else 0.0
        passing_coverage = passed / total_passed if total_passed else 0.0
        fail_pass_contrast = failing_coverage * (1.0 - passing_coverage)
        name_relevance = _name_relevance(function_id, case_tokens)
        role_relevance = _role_relevance(function_id, case_tokens)
        line_signal = _line_signal_for_function(function_id, tests)
        generic_penalty = _generic_function_penalty(function_id)
        score = (
            0.38 * normalized_dstar.get(function_id, 0.0)
            + 0.24 * fail_pass_contrast
            + 0.13 * failing_coverage
            + 0.12 * name_relevance
            + 0.08 * role_relevance
            + 0.05 * line_signal
            - generic_penalty
        )
        score = max(0.0, score)
        file_part, name = _split_function_key(function_id)
        reasons = []
        if failed:
            reasons.append(f"covered by {failed}/{total_failed} failing tests")
        if failed and passed == 0:
            reasons.append("not covered by passing tests")
        elif passed:
            reasons.append(f"also covered by {passed}/{total_passed} passing tests")
        if name_relevance:
            reasons.append("function name overlaps failure/test vocabulary")
        if role_relevance:
            reasons.append("function role matches failure behavior/input pattern")
        if generic_penalty:
            reasons.append("generic constructor/accessor penalty applied")
        if line_signal:
            reasons.append("has failing line-level signal")

        rows.append(
            {
                "function_id": function_id,
                "file": file_part,
                "name": name,
                "score": round(score, 6),
                "features": {
                    "dstar": dstar_scores.get(function_id, 0.0),
                    "normalized_dstar": round(normalized_dstar.get(function_id, 0.0), 6),
                    "failing_coverage": round(failing_coverage, 6),
                    "passing_coverage": round(passing_coverage, 6),
                    "fail_pass_contrast": round(fail_pass_contrast, 6),
                    "name_relevance": round(name_relevance, 6),
                    "role_relevance": round(role_relevance, 6),
                    "line_signal": line_signal,
                    "generic_penalty": round(generic_penalty, 6),
                },
                "covered_by": {
                    "failing_count": failed,
                    "passing_count": passed,
                    "total_failing": total_failed,
                    "total_passing": total_passed,
                },
                "reasons": reasons,
            }
        )

    return _sort_ranked(rows)[:top_k]


def _container_to_host_path(path: str, metadata: dict, defects4c_root: str) -> str:
    if not path:
        return ""
    normalized = str(path).replace("\\", "/")
    if os.path.exists(path):
        return os.path.abspath(path)

    match = re.search(r"/out/(?P<project>[^/]+)/(?P<repo>git_repo_dir_[^/]+)(?P<rest>/.*)$", normalized)
    if match:
        candidate = os.path.join(
            defects4c_root,
            "out_tmp_dirs",
            match.group("project"),
            match.group("repo"),
            *[part for part in match.group("rest").split("/") if part],
        )
        if os.path.exists(candidate):
            return os.path.abspath(candidate)

    source_file = str(metadata.get("source_file") or "").replace("\\", "/")
    source_match = re.search(r"/out/(?P<project>[^/]+)/(?P<repo>git_repo_dir_[^/]+)/", source_file)
    if source_match and normalized.startswith("/out/"):
        parts = [part for part in normalized.split("/") if part]
        if len(parts) >= 4:
            rest = parts[3:]
            candidate = os.path.join(
                defects4c_root,
                "out_tmp_dirs",
                source_match.group("project"),
                source_match.group("repo"),
                *rest,
            )
            if os.path.exists(candidate):
                return os.path.abspath(candidate)

    return path


def resolve_repo_root(metadata: dict, defects4c_root: str = "") -> str:
    defects4c_root = defects4c_root or default_defects4c_root()
    source_file = str(metadata.get("source_file") or "")
    host_source = _container_to_host_path(source_file, metadata, defects4c_root)
    if host_source and os.path.exists(host_source):
        relative_parts = str(source_file).replace("\\", "/").split("/git_repo_dir_", 1)
        if len(relative_parts) == 2:
            after_repo = relative_parts[1].split("/", 1)
            if len(after_repo) == 2:
                suffix_parts = [part for part in after_repo[1].split("/") if part]
                repo_root = host_source
                for _ in suffix_parts:
                    repo_root = os.path.dirname(repo_root)
                if os.path.isdir(repo_root):
                    return os.path.abspath(repo_root)
        return os.path.abspath(os.path.dirname(host_source))

    project = metadata.get("project", "")
    commit = metadata.get("commit_after", "")
    candidate = os.path.join(defects4c_root, "out_tmp_dirs", str(project), f"git_repo_dir_{commit}")
    if os.path.isdir(candidate):
        return os.path.abspath(candidate)
    return ""


def _walk_source_files(repo_root: str, basename: str) -> List[str]:
    if not repo_root or not os.path.isdir(repo_root):
        return []
    matches = []
    for dirpath, dirnames, filenames in os.walk(repo_root):
        dirnames[:] = [name for name in dirnames if name not in PRUNE_DIRS and not name.startswith("build")]
        if basename not in filenames:
            continue
        path = os.path.join(dirpath, basename)
        if path.endswith(SOURCE_EXTENSIONS):
            matches.append(path)
    return matches


def resolve_function_file(
    function_id: str,
    metadata: dict,
    defects4c_root: str = "",
) -> dict:
    file_part, _ = _split_function_key(function_id)
    basename = os.path.basename(file_part.replace("\\", "/")) if file_part else ""
    repo_root = resolve_repo_root(metadata, defects4c_root)

    source_file = _container_to_host_path(str(metadata.get("source_file") or ""), metadata, defects4c_root or default_defects4c_root())
    if basename and source_file and os.path.exists(source_file) and os.path.basename(source_file) == basename:
        return {
            "resolved": True,
            "file_path": source_file,
            "repo_root": repo_root,
            "strategy": "metadata_source_file",
        }

    candidates = _walk_source_files(repo_root, basename) if basename else []
    if candidates:
        def priority(path: str) -> Tuple[int, int, str]:
            normalized = path.replace("\\", "/")
            production_bonus = 0 if "/include/" in normalized or "/src/" in normalized else 1
            test_penalty = 1 if "/test/" in normalized or "/tests/" in normalized else 0
            return (test_penalty, production_bonus, normalized)

        chosen = sorted(candidates, key=priority)[0]
        return {
            "resolved": True,
            "file_path": os.path.abspath(chosen),
            "repo_root": repo_root,
            "strategy": "repo_basename_search",
            "candidate_count": len(candidates),
        }

    return {
        "resolved": False,
        "file_path": "",
        "repo_root": repo_root,
        "strategy": "unresolved",
        "reason": f"could not resolve source file for {function_id}",
    }


def _strip_line_for_braces(line: str) -> str:
    line = re.sub(r"//.*$", "", line)
    line = re.sub(r'"(?:\\.|[^"\\])*"', '""', line)
    line = re.sub(r"'(?:\\.|[^'\\])*'", "''", line)
    return line


def _target_regex(target: str) -> re.Pattern:
    target = target.strip()
    if target == "operator()":
        return re.compile(r"\boperator\s*\(\s*\)\s*\(")
    if target.startswith("operator "):
        op_name = re.escape(target.split(" ", 1)[1])
        return re.compile(rf"\boperator\s+{op_name}\s*\(")
    escaped = re.escape(target)
    return re.compile(rf"(?<![A-Za-z0-9_~.>]){escaped}\s*\(")


def _find_body_start(lines: Sequence[str], start_index: int, max_lookahead: int = 10) -> Optional[int]:
    for idx in range(start_index, min(len(lines), start_index + max_lookahead)):
        stripped = lines[idx].strip()
        if not stripped or stripped.startswith("//"):
            continue
        brace_pos = stripped.find("{")
        semi_pos = stripped.find(";")
        if semi_pos >= 0 and (brace_pos < 0 or semi_pos < brace_pos):
            return None
        if brace_pos >= 0:
            return idx
    return None


def _find_body_end(lines: Sequence[str], body_start_index: int) -> int:
    depth = 0
    seen_open = False
    for idx in range(body_start_index, len(lines)):
        cleaned = _strip_line_for_braces(lines[idx])
        for char in cleaned:
            if char == "{":
                depth += 1
                seen_open = True
            elif char == "}":
                depth -= 1
                if seen_open and depth <= 0:
                    return idx
    return min(len(lines) - 1, body_start_index)


def _signature_start(lines: Sequence[str], target_index: int) -> int:
    start = target_index
    while start > 0:
        previous = lines[start - 1].strip()
        if not previous:
            break
        if previous.startswith(("template", "FMT_", "inline", "constexpr")):
            start -= 1
            continue
        if previous.endswith(",") or previous.endswith("("):
            start -= 1
            continue
        break
    return start


def find_function_range(file_path: str, function_id: str) -> dict:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as exc:
        return {"found": False, "reason": f"read_error: {exc}"}

    _, function_name = _split_function_key(function_id)
    target = function_name.split("::")[-1] if function_name else _function_tail(function_id)
    if not target:
        return {"found": False, "reason": "empty_function_name"}
    pattern = _target_regex(target)

    for idx, line in enumerate(lines):
        if not pattern.search(line):
            continue
        body_start = _find_body_start(lines, idx)
        if body_start is None:
            continue
        start = _signature_start(lines, idx)
        end = _find_body_end(lines, body_start)
        return {
            "found": True,
            "file_path": os.path.abspath(file_path),
            "start_line": start + 1,
            "body_start_line": body_start + 1,
            "end_line": end + 1,
            "line_count": end - start + 1,
        }

    return {"found": False, "reason": f"function signature not found for target {target}"}


def _read_numbered_lines(file_path: str, start_line: int, end_line: int) -> List[dict]:
    try:
        with open(file_path, "r", encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception:
        return []
    start = max(1, start_line)
    end = min(len(lines), end_line)
    return [
        {"line": line_no, "text": lines[line_no - 1].rstrip("\n")}
        for line_no in range(start, end + 1)
    ]


def _merge_windows(line_numbers: Iterable[int], start_line: int, end_line: int, context_lines: int) -> List[Tuple[int, int]]:
    windows = []
    for line_no in sorted(set(line_numbers)):
        if line_no < start_line or line_no > end_line:
            continue
        windows.append((max(start_line, line_no - context_lines), min(end_line, line_no + context_lines)))
    if not windows:
        return []
    merged = [windows[0]]
    for start, end in windows[1:]:
        last_start, last_end = merged[-1]
        if start <= last_end + 1:
            merged[-1] = (last_start, max(last_end, end))
        else:
            merged.append((start, end))
    return merged


def _interesting_lines(lines: Sequence[dict], case_tokens: Optional[set] = None) -> List[int]:
    case_tokens = case_tokens or set()
    interesting = []
    pattern = re.compile(r"\b(if|else|switch|case|for|while|return|throw|assert|on_error|error)\b")
    for row in lines:
        text = row.get("text", "")
        tokens = set(_tokenize(text))
        if pattern.search(text) or (case_tokens and tokens & case_tokens):
            interesting.append(int(row["line"]))
    return interesting


def _skeleton_lines(lines: Sequence[dict], max_lines: int) -> List[dict]:
    keep = []
    pattern = re.compile(
        r"\b(if|else|switch|case|default|for|while|return|throw|break|continue|"
        r"on_error|error|check|parse|get|set)\b|[{}]"
    )
    for row in lines:
        text = row.get("text", "")
        stripped = text.strip()
        if len(keep) < 4 or pattern.search(stripped):
            keep.append(row)
        if len(keep) >= max_lines:
            break
    return keep


def _line_key_from_value(value: object) -> Optional[str]:
    if isinstance(value, str):
        text = value.replace("\\", "/").strip()
        match = re.match(r"(?P<file>.+):(?P<line>\d+)(?::\d+)?$", text)
        if match:
            return f"{match.group('file')}:{int(match.group('line'))}"
        return None
    if isinstance(value, dict):
        if value.get("line_key"):
            return _line_key_from_value(value.get("line_key"))
        file_value = value.get("file") or value.get("source") or value.get("relative_file")
        line_value = value.get("line") or value.get("lineno")
        try:
            if file_value and line_value:
                normalized_file = str(file_value).replace("\\", "/")
                return f"{normalized_file}:{int(line_value)}"
        except (TypeError, ValueError):
            return None
    return None


def _add_line_values(values: object, source: str, line_keys: set, sources: set) -> None:
    if not isinstance(values, list):
        return
    for value in values:
        line_key = _line_key_from_value(value)
        if line_key:
            line_keys.add(line_key)
            sources.add(source)


def line_keys_from_test(test: dict, prefer_slice: bool = False) -> Tuple[set, List[str]]:
    line_keys = set()
    sources = set()
    fields = ["covered_lines", "executed_lines", "line_coverage"]
    for field in fields:
        _add_line_values(test.get(field), field, line_keys, sources)
    function_lines = test.get("covered_function_lines") or {}
    if isinstance(function_lines, dict):
        for values in function_lines.values():
            _add_line_values(values, "covered_function_lines", line_keys, sources)

    llvm_slice = test.get("llvm_slice") or {}
    if isinstance(llvm_slice, dict):
        ordered = ["dynamic_slice_lines", "slice_lines", "line_keys", "executed_lines", "lines"]
        if not prefer_slice:
            ordered = ["executed_lines", "line_keys", "lines", "dynamic_slice_lines", "slice_lines"]
        for field in ordered:
            _add_line_values(llvm_slice.get(field), f"llvm_slice.{field}", line_keys, sources)

    dynamic_trace = test.get("dynamic_trace") or {}
    if isinstance(dynamic_trace, dict):
        for field in ("executed_lines", "last_lines_before_failure", "line_keys"):
            _add_line_values(dynamic_trace.get(field), f"dynamic_trace.{field}", line_keys, sources)

    return line_keys, sorted(sources)


def _split_line_key(line_key: str) -> Tuple[str, Optional[int]]:
    match = re.match(r"(?P<file>.+):(?P<line>\d+)$", str(line_key or "").replace("\\", "/"))
    if not match:
        return "", None
    return match.group("file"), int(match.group("line"))


def collect_line_coverage(test: dict) -> dict:
    line_keys, sources = line_keys_from_test(test)
    runtime = test.get("runtime") or {}
    if not isinstance(runtime, dict):
        runtime = {}
    return {
        "test_id": test.get("test_id", ""),
        "available": bool(line_keys),
        "line_count": len(line_keys),
        "sources": sources,
        "sample": sorted(line_keys)[:20],
        "replay_command": runtime.get("replay_command", ""),
        "note": "" if line_keys else "no line coverage fields found in metadata; use external gcov/LLVM collection to populate them",
    }


def get_function_code(
    bug: dict,
    function_id: str,
    mode: str = "signature",
    max_lines: int = 120,
    context_lines: int = 3,
    test_id: str = "",
    metadata: Optional[dict] = None,
    defects4c_root: str = "",
) -> dict:
    if mode not in CODE_MODES:
        raise ValueError(f"Unknown code mode {mode!r}; expected one of {sorted(CODE_MODES)}")
    metadata = metadata or _read_metadata(bug)
    resolved = resolve_function_file(function_id, metadata, defects4c_root)
    if not resolved.get("resolved"):
        return {
            "function_id": function_id,
            "mode": mode,
            "available": False,
            "resolver": resolved,
            "reason": resolved.get("reason", "source file unresolved"),
        }

    file_path = resolved["file_path"]
    function_range = find_function_range(file_path, function_id)
    if not function_range.get("found"):
        return {
            "function_id": function_id,
            "mode": mode,
            "available": False,
            "resolver": resolved,
            "range": function_range,
            "reason": function_range.get("reason", "function range unresolved"),
        }

    start_line = int(function_range["start_line"])
    end_line = int(function_range["end_line"])
    body_start = int(function_range["body_start_line"])
    all_lines = _read_numbered_lines(file_path, start_line, end_line)
    truncated = False

    if mode == "signature":
        rendered = _read_numbered_lines(file_path, start_line, body_start)
    elif mode == "full":
        rendered = all_lines[:max_lines]
        truncated = len(all_lines) > max_lines
    elif mode == "skeleton":
        rendered = _skeleton_lines(all_lines, max_lines)
        truncated = len(all_lines) > len(rendered)
    else:
        rendered = []
        selected_test = _find_test(bug.get("tests", []), test_id)
        line_numbers = _executed_line_numbers_for_function(selected_test, function_id, function_range) if selected_test else []
        if not line_numbers and mode == "executed_lines":
            return {
                "function_id": function_id,
                "mode": mode,
                "available": False,
                "resolver": resolved,
                "range": function_range,
                "line_coverage": collect_line_coverage(selected_test) if selected_test else {"available": False},
                "reason": "line coverage is unavailable for this function/test",
                "fallback_hint": "retry with mode='windowed' or mode='skeleton'",
            }
        if not line_numbers:
            case_tokens = _case_tokens(bug, metadata)
            line_numbers = _interesting_lines(all_lines, case_tokens)[: max(1, max_lines // (context_lines * 2 + 1))]
        windows = _merge_windows(line_numbers, start_line, end_line, context_lines)
        for window_start, window_end in windows:
            rendered.extend(_read_numbered_lines(file_path, window_start, window_end))
        if len(rendered) > max_lines:
            rendered = rendered[:max_lines]
            truncated = True

    return {
        "function_id": function_id,
        "mode": mode,
        "available": True,
        "resolver": resolved,
        "range": function_range,
        "line_count": len(rendered),
        "truncated": truncated,
        "lines": rendered,
    }


def _find_test(tests: Sequence[dict], test_id: str) -> Optional[dict]:
    if test_id:
        for test in tests:
            if str(test.get("test_id") or "") == test_id:
                return test
    failing = _true_failing_tests(tests)
    return failing[0] if failing else None


def _executed_line_numbers_for_function(test: Optional[dict], function_id: str, function_range: dict) -> List[int]:
    if not test:
        return []
    function_lines = test.get("covered_function_lines") or {}
    if isinstance(function_lines, dict):
        direct_line_numbers = []
        for key, values in function_lines.items():
            if key != function_id:
                continue
            if not isinstance(values, list):
                continue
            for value in values:
                _, line_no = _split_line_key(str(value))
                if line_no is not None:
                    direct_line_numbers.append(line_no)
        if direct_line_numbers:
            return sorted(set(direct_line_numbers))
    file_part, _ = _split_function_key(function_id)
    basename = os.path.basename(file_part.replace("\\", "/")) if file_part else ""
    start_line = int(function_range.get("start_line", 0))
    end_line = int(function_range.get("end_line", 0))
    line_keys, _ = line_keys_from_test(test)
    line_numbers = []
    for line_key in line_keys:
        line_file, line_no = _split_line_key(line_key)
        if line_no is None:
            continue
        if file_part and not (line_file.endswith(file_part.replace("\\", "/")) or os.path.basename(line_file) == basename):
            continue
        if start_line <= line_no <= end_line:
            line_numbers.append(line_no)
    return sorted(set(line_numbers))


def get_candidate_slice(
    bug: dict,
    function_id: str,
    mode: str = "mixed",
    max_lines: int = 120,
    context_lines: int = 3,
    test_id: str = "",
    metadata: Optional[dict] = None,
    defects4c_root: str = "",
) -> dict:
    selected_test = _find_test(bug.get("tests", []), test_id)
    metadata = metadata or _read_metadata(bug)
    if not selected_test:
        return {
            "function_id": function_id,
            "available": False,
            "reason": "no failing test available for slicing",
        }
    prefer_slice = mode in {"data", "control", "mixed"}
    line_keys, sources = line_keys_from_test(selected_test, prefer_slice=prefer_slice)
    code = get_function_code(
        bug,
        function_id,
        mode="executed_lines" if line_keys else "windowed",
        max_lines=max_lines,
        context_lines=context_lines,
        test_id=str(selected_test.get("test_id") or ""),
        metadata=metadata,
        defects4c_root=defects4c_root,
    )
    return {
        "function_id": function_id,
        "test_id": selected_test.get("test_id", ""),
        "mode": mode,
        "available": bool(code.get("available")),
        "line_sources": sources,
        "fallback": "executed/windowed code view; no DDG object is built here",
        "code": code,
    }


def get_test_source_context(
    bug: dict,
    test_id: str = "",
    context_lines: int = 10,
    metadata: Optional[dict] = None,
    defects4c_root: str = "",
) -> dict:
    metadata = metadata or _read_metadata(bug)
    test = _find_test(bug.get("tests", []), test_id)
    if not test:
        return {"available": False, "reason": "test not found"}
    failure = test.get("failure") or {}
    if not isinstance(failure, dict):
        failure = {}
    location = str(failure.get("assertion_location") or "")
    match = re.match(r"(?P<path>.*):(?P<line>\d+)$", location.replace("\\", "/"))
    if not match:
        return {"available": False, "test_id": test.get("test_id", ""), "reason": "assertion location missing"}
    source_path = _container_to_host_path(match.group("path"), metadata, defects4c_root or default_defects4c_root())
    if not os.path.exists(source_path):
        return {
            "available": False,
            "test_id": test.get("test_id", ""),
            "assertion_location": location,
            "reason": "assertion source file unresolved",
        }
    line_no = int(match.group("line"))
    return {
        "available": True,
        "test_id": test.get("test_id", ""),
        "assertion_location": location,
        "file_path": os.path.abspath(source_path),
        "line": line_no,
        "lines": _read_numbered_lines(source_path, line_no - context_lines, line_no + context_lines),
    }


def expand_function_neighbors(
    bug: dict,
    function_id: str,
    metadata: Optional[dict] = None,
    defects4c_root: str = "",
    limit: int = 20,
) -> dict:
    metadata = metadata or _read_metadata(bug)
    tests = bug.get("tests", [])
    all_functions = sorted({fn for test in tests for fn in _covered_functions(test)})
    code = get_function_code(
        bug,
        function_id,
        mode="full",
        max_lines=300,
        metadata=metadata,
        defects4c_root=defects4c_root,
    )
    if not code.get("available"):
        return {
            "function_id": function_id,
            "available": False,
            "reason": "function code unavailable",
            "calls": [],
            "referenced_by": [],
        }

    code_text = "\n".join(row.get("text", "") for row in code.get("lines", []))
    calls = []
    for candidate in all_functions:
        if candidate == function_id:
            continue
        tail = _function_tail(candidate)
        if not tail:
            continue
        if _target_regex(tail).search(code_text):
            calls.append(candidate)
    return {
        "function_id": function_id,
        "available": True,
        "relation": "same-bug-covered-functions referenced in extracted body",
        "calls": calls[:limit],
        "referenced_by": [],
        "note": "referenced_by is intentionally not scanned globally in this lightweight tool",
    }


def run_localization_agent_tools(config: LocalizationAgentConfig) -> Dict[str, dict]:
    if config.code_mode not in CODE_MODES:
        raise ValueError(f"Unknown code mode {config.code_mode!r}; expected one of {sorted(CODE_MODES)}")
    loader_config = Defects4CLoadConfig(
        dataset=config.dataset,
        metadata_dir=config.metadata_dir,
        defects4c_root=config.defects4c_root,
        bug_id_filter=config.bug_id_filter,
        exclude_fixed_fail_tests=config.exclude_fixed_fail_tests,
    )
    bugs = load_defects4c_bugs(loader_config)
    output: Dict[str, dict] = {}
    defects4c_root = config.defects4c_root or default_defects4c_root()

    for bug in bugs:
        metadata = _read_metadata(bug)
        ranked = rank_functions(bug, metadata, top_k=max(config.top_k, config.inspect_top_k, 1))
        ground_truth = bug.get("ground_truth", [])
        initial_hit_rank = _hit_rank_for_function_ids(
            [row.get("function_id", "") for row in ranked],
            ground_truth,
        )
        failing = _true_failing_tests(bug.get("tests", []))
        default_test_id = str(failing[0].get("test_id") or "") if failing else ""
        inspected = []
        for row in ranked[: config.inspect_top_k]:
            inspected.append(
                get_function_code(
                    bug,
                    row["function_id"],
                    mode=config.code_mode,
                    max_lines=config.max_code_lines,
                    context_lines=config.context_lines,
                    test_id=default_test_id,
                    metadata=metadata,
                    defects4c_root=defects4c_root,
                )
            )

        output[bug["bug_id"]] = {
            "case_card": build_case_card(bug, metadata),
            "graph_summary": build_localization_graph_summary(bug, metadata),
            "ranked_functions": ranked[: config.top_k],
            "failing_line_coverage": [collect_line_coverage(test) for test in failing],
            "test_source_context": get_test_source_context(
                bug,
                default_test_id,
                context_lines=10,
                metadata=metadata,
                defects4c_root=defects4c_root,
            ),
            "inspected_functions": inspected,
            "agent_policy": {
                "ground_truth_visible_to_agent": False,
                "code_fetch_order": ["signature", "executed_lines", "windowed", "skeleton", "full"],
                "default_stop_budget_tool_calls": 12,
            },
            "evaluation_only": {
                "ground_truth": ground_truth,
                "initial_hit_rank": initial_hit_rank,
                "initial_topk": _topk_flags(initial_hit_rank),
            },
        }

    output_file = config.output_file or default_output_file(config)
    config.output_file = output_file
    os.makedirs(os.path.dirname(output_file), exist_ok=True)
    with open(output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def default_output_file(config: LocalizationAgentConfig) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    experiments_dir = os.path.abspath(os.path.join(here, "..", "experiments"))
    dataset_dir = os.path.join(experiments_dir, config.dataset)
    return os.path.join(dataset_dir, "localization_agent_tools.json")


def print_localization_agent_summary(results: Dict[str, dict], output_file: str = "") -> None:
    print("\nLocalization agent tool-pack summary:")
    print(f"  bugs: {len(results)}")
    for bug_id, entry in sorted(results.items()):
        card = entry.get("case_card", {})
        counts = card.get("test_counts", {})
        ranked = entry.get("ranked_functions", [])
        top = ranked[0]["function_id"] if ranked else ""
        print(
            f"  {bug_id}: failing={counts.get('failing', 0)} "
            f"covered_functions={counts.get('covered_functions', 0)} top={top}"
        )
    _print_topk_metrics(results, "initial_hit_rank", "initial-ranking eval")
    if output_file:
        print(f"  output: {output_file}")


def _default_dataset_dir(dataset: str) -> str:
    here = os.path.dirname(os.path.abspath(__file__))
    experiments_dir = os.path.abspath(os.path.join(here, "..", "experiments"))
    return os.path.join(experiments_dir, dataset)


def default_llm_payload_file(config: LocalizationAgentLlmConfig) -> str:
    return os.path.join(_default_dataset_dir(config.dataset), "localization_agent_tools.json")


def default_llm_output_file(config: LocalizationAgentLlmConfig) -> str:
    return os.path.join(_default_dataset_dir(config.dataset), "localization_agent_llm_results.json")


def _write_json_file(path: str, data: dict) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=4, ensure_ascii=False)


def _llm_entry_complete(entry: object) -> bool:
    if not isinstance(entry, dict) or entry.get("error"):
        return False
    if entry.get("dry_run"):
        return True
    llm_result = entry.get("llm_result")
    return isinstance(llm_result, dict) and bool(llm_result.get("top_locations"))


def _filter_bug_ids(value: str) -> set:
    return {item.strip() for item in str(value or "").split(",") if item.strip()}


def _safe_json_load(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _extract_json_object(text: str) -> dict:
    cleaned = str(text or "").strip()
    if cleaned.startswith("```"):
        cleaned = re.sub(r"^```(?:json)?\s*", "", cleaned, flags=re.IGNORECASE)
        cleaned = re.sub(r"\s*```$", "", cleaned)
    start = cleaned.find("{")
    end = cleaned.rfind("}")
    if start >= 0 and end >= start:
        cleaned = cleaned[start : end + 1]
    data = json.loads(cleaned)
    if not isinstance(data, dict):
        raise ValueError("LLM response JSON root must be an object")
    return data


def _compact_code_lines(lines: object, limit: int) -> List[dict]:
    if not isinstance(lines, list):
        return []
    out = []
    for row in lines[: max(0, limit)]:
        if not isinstance(row, dict):
            continue
        out.append(
            {
                "line": row.get("line"),
                "text": row.get("text", ""),
            }
        )
    return out


def _code_behavior_features(lines: object) -> dict:
    compact = _compact_code_lines(lines, 200)
    texts = [str(row.get("text") or "").strip() for row in compact]
    meaningful = [
        text
        for text in texts
        if text and text not in {"{", "}"} and not text.startswith("//")
    ]
    joined = "\n".join(meaningful)
    lowered = joined.lower()
    has_branch = bool(re.search(r"\b(if|switch|case)\b", joined))
    has_loop = bool(re.search(r"\b(for|while)\b", joined))
    has_return = "return" in lowered
    has_throw_or_error = bool(re.search(r"\b(throw|on_error|format_error|error)\b", joined))
    returns_minus_one = bool(re.search(r"\breturn\s+-1\s*;", joined))
    returns_empty = bool(re.search(r"\breturn\s+\{\}\s*;", joined))
    mentions_named_args = "named_arg" in lowered or "named args" in lowered
    mentions_id_lookup = bool(re.search(r"\b(get_id|arg_id|id)\b", joined))
    is_thin_accessor = (
        len(meaningful) <= 2
        and has_return
        and not has_branch
        and not has_loop
        and not returns_minus_one
    )
    is_wrapper = (
        len(meaningful) <= 2
        and has_return
        and "(" in joined
        and ")" in joined
        and not has_branch
        and not has_loop
    )
    suspicious_logic_markers = []
    if has_branch:
        suspicious_logic_markers.append("branch")
    if has_loop:
        suspicious_logic_markers.append("loop")
    if has_throw_or_error:
        suspicious_logic_markers.append("throw_or_error")
    if returns_minus_one:
        suspicious_logic_markers.append("returns_minus_one")
    if returns_empty:
        suspicious_logic_markers.append("returns_empty")
    if mentions_named_args:
        suspicious_logic_markers.append("mentions_named_args")
    if mentions_id_lookup:
        suspicious_logic_markers.append("mentions_id_lookup")
    return {
        "executed_meaningful_line_count": len(meaningful),
        "is_thin_accessor": is_thin_accessor,
        "is_wrapper": is_wrapper,
        "has_branch": has_branch,
        "has_loop": has_loop,
        "has_throw_or_error": has_throw_or_error,
        "returns_minus_one": returns_minus_one,
        "returns_empty": returns_empty,
        "mentions_named_args": mentions_named_args,
        "mentions_id_lookup": mentions_id_lookup,
        "suspicious_logic_markers": suspicious_logic_markers,
    }


def _failure_mechanism_hints(card: dict) -> List[str]:
    hints = []
    for test in card.get("failing_tests", []) or []:
        expected = str(test.get("expected_value") or "").lower()
        actual = str(test.get("actual_value") or "").lower()
        text = f"{expected}\n{actual}"
        if "throw" in expected and ("throws nothing" in actual or "no exception" in actual):
            hints.append(
                "Expected an exception but observed no throw; prioritize functions that decide invalid argument lookup/checking or return sentinel values that suppress errors."
            )
        if "format_error" in text:
            hints.append("format_error is the expected failure behavior.")
        if "{" in text and "}" in text and any(token in text for token in ("named", "{a}", "arg")):
            hints.append("The failing input involves a named replacement field / named argument.")
    return sorted(dict.fromkeys(hints))


def _candidate_prompt_rows(entry: dict, config: LocalizationAgentLlmConfig) -> List[dict]:
    inspected_by_id = {
        item.get("function_id"): item
        for item in entry.get("inspected_functions", [])
        if isinstance(item, dict)
    }
    rows = []
    for rank, item in enumerate(entry.get("ranked_functions", [])[: config.candidate_limit], start=1):
        if not isinstance(item, dict):
            continue
        function_id = item.get("function_id", "")
        inspected = inspected_by_id.get(function_id, {})
        code_lines = inspected.get("lines", [])
        rows.append(
            {
                "initial_rank": rank,
                "function_id": function_id,
                "score": item.get("score", 0.0),
                "covered_by": item.get("covered_by", {}),
                "features": item.get("features", {}),
                "reasons": item.get("reasons", []),
                "inspected_code": {
                    "available": bool(inspected.get("available")),
                    "mode": inspected.get("mode", ""),
                    "range": inspected.get("range", {}),
                    "line_count": inspected.get("line_count", 0),
                    "reason": inspected.get("reason", ""),
                    "behavior_features": _code_behavior_features(code_lines),
                    "lines": _compact_code_lines(code_lines, config.max_code_lines_per_function),
                },
            }
        )
    return rows


def build_localization_llm_prompt_input(entry: dict, config: LocalizationAgentLlmConfig) -> dict:
    card = entry.get("case_card", {})
    return {
        "task": "Return top suspicious functions for function-level fault localization. Do not propose patches.",
        "case_card": {
            "bug_id": card.get("bug_id", ""),
            "metadata_bug_id": card.get("metadata_bug_id", ""),
            "dataset": card.get("dataset", ""),
            "project": card.get("project", ""),
            "language": card.get("language", ""),
            "type_name": card.get("type_name", ""),
            "test_counts": card.get("test_counts", {}),
            "failing_tests": card.get("failing_tests", []),
        },
        "graph_summary": entry.get("graph_summary", {}),
        "failing_line_coverage": entry.get("failing_line_coverage", []),
        "test_source_context": entry.get("test_source_context", {}),
        "failure_mechanism_hints": _failure_mechanism_hints(card),
        "candidates": _candidate_prompt_rows(entry, config),
        "ranking_guidance": [
            "Prefer functions that contain logic affecting the observed wrong behavior.",
            "Downrank thin accessors, constructors, wrappers, and generic helpers unless their body directly explains the failure.",
            "Use executed lines as stronger evidence than initial coverage score.",
            "If a function only forwards to another inspected function, rank the callee above the wrapper.",
            "For expected-exception-but-no-throw failures, prioritize functions that perform checks, lookup ids, return sentinel values, or decide error/no-error behavior.",
            "Do not copy initial ranking scores into confidence; confidence must reflect inspected executed code and failure mechanism fit.",
            f"Return as many ranked locations as possible, up to {max(1, config.candidate_limit)} candidates, ordered by suspicion.",
            "If later candidates are uncertain, keep them after the stronger candidates instead of omitting them.",
            "Return only function ids that appear in candidates unless there is a strong explicit reason.",
        ],
        "required_output_schema": {
            "top_locations": [
                {
                    "rank": 1,
                    "function_id": "file.h:qualified::function",
                    "confidence": 0.0,
                    "reason": "short reason",
                    "evidence": ["short evidence item"],
                    "risk_notes": ["short uncertainty note"],
                }
            ],
            "stop_reason": "why this top-k is sufficient or what evidence is missing",
            "global_notes": ["short note"],
        },
    }


def build_localization_llm_messages(prompt_input: dict) -> List[dict]:
    system = """
You are a fault-localization agent for C/C++ Defects4C bugs.
Your goal is to rank suspicious functions, not to repair code.
Use the failure behavior, fail/pass coverage, and executed source lines.
Be skeptical of functions that are only accessors, constructors, wrappers, or generic formatting helpers.
Return strict JSON only, following the requested schema.
""".strip()
    return [
        {"role": "system", "content": system},
        {"role": "user", "content": json.dumps(prompt_input, indent=2, ensure_ascii=False)},
    ]


def _call_openrouter_for_localization(messages: Sequence[dict], config: LocalizationAgentLlmConfig) -> Tuple[str, dict]:
    if requests is None:
        raise RuntimeError("requests is not installed")
    if load_dotenv:
        load_dotenv()
    api_key = os.environ.get(config.api_key_env, "")
    if not api_key:
        raise RuntimeError(f"missing API key in environment variable {config.api_key_env}")
    model = config.model or os.environ.get("OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    referer = os.environ.get("OPENROUTER_SITE_URL")
    title = os.environ.get("OPENROUTER_APP_NAME") or "Unified-Debugging Localization Agent"
    if referer:
        headers["HTTP-Referer"] = referer
    if title:
        headers["X-Title"] = title
    payload = {
        "model": model,
        "messages": list(messages),
        "temperature": config.temperature,
        "max_tokens": config.max_tokens,
    }
    response = requests.post(
        config.api_url,
        headers=headers,
        json=payload,
        timeout=config.timeout_seconds,
    )
    if response.status_code >= 400:
        raise RuntimeError(f"OpenRouter HTTP {response.status_code}: {response.text[:1000]}")
    data = response.json()
    choices = data.get("choices") or []
    if not choices:
        raise RuntimeError("OpenRouter response did not contain choices")
    message = choices[0].get("message") or {}
    return str(message.get("content") or ""), data


def _function_id_matches(candidate: str, target: object) -> bool:
    candidate = str(candidate or "")
    target_text = str(target or "")
    return bool(
        candidate
        and target_text
        and (
            candidate == target_text
            or candidate.endswith(target_text)
            or target_text.endswith(candidate)
        )
    )


def _rank_in_initial_candidates(function_id: object, ranked_functions: Sequence[dict]) -> Optional[int]:
    for index, item in enumerate(ranked_functions, start=1):
        if _function_id_matches(str(item.get("function_id") or ""), function_id):
            return index
    return None


def _has_seen_function(function_id: str, locations: Sequence[dict]) -> bool:
    return any(_function_id_matches(function_id, item.get("function_id", "")) for item in locations)


def _complete_llm_locations(entry: dict, llm_json: dict, candidate_limit: int) -> dict:
    if not isinstance(llm_json, dict):
        return {}
    completed = dict(llm_json)
    raw_locations = completed.get("top_locations") or []
    if not isinstance(raw_locations, list):
        raw_locations = []

    locations = []
    for item in raw_locations:
        if not isinstance(item, dict):
            continue
        function_id = str(item.get("function_id") or "")
        if not function_id or _has_seen_function(function_id, locations):
            continue
        locations.append(dict(item))

    llm_returned_count = len(locations)
    for candidate in entry.get("ranked_functions", [])[: max(1, candidate_limit)]:
        function_id = str(candidate.get("function_id") or "")
        if not function_id or _has_seen_function(function_id, locations):
            continue
        locations.append(
            {
                "function_id": function_id,
                "confidence": 0.0,
                "reason": "backfilled from initial function ranking because the LLM returned fewer candidates",
                "evidence": candidate.get("reasons", [])[:3],
                "risk_notes": ["postprocessed fallback candidate"],
            }
        )
        if len(locations) >= max(1, candidate_limit):
            break

    for rank, item in enumerate(locations, start=1):
        item["rank"] = rank
    completed["top_locations"] = locations
    completed["postprocess"] = {
        "llm_returned_locations": llm_returned_count,
        "backfilled_locations": max(0, len(locations) - llm_returned_count),
        "candidate_limit": max(1, candidate_limit),
    }
    return completed


def _hit_rank_for_function_ids(function_ids: Sequence[object], ground_truth: Sequence[object]) -> Optional[int]:
    for index, function_id in enumerate(function_ids, start=1):
        for gt in ground_truth:
            if _function_id_matches(str(function_id or ""), gt):
                return index
    return None


def _topk_flags(hit_rank: Optional[int], ks: Sequence[int] = EVAL_TOP_KS) -> Dict[str, bool]:
    return {f"top_{k}": hit_rank is not None and hit_rank <= k for k in ks}


def _topk_metrics(results: Dict[str, dict], rank_key: str, ks: Sequence[int] = EVAL_TOP_KS) -> Dict[int, dict]:
    hit_ranks = []
    for entry in results.values():
        eval_only = entry.get("evaluation_only") or {}
        if not eval_only.get("ground_truth"):
            continue
        hit_ranks.append(eval_only.get(rank_key))
    total = len(hit_ranks)
    metrics: Dict[int, dict] = {}
    for k in ks:
        hits = sum(1 for rank in hit_ranks if rank is not None and rank <= k)
        metrics[k] = {
            "hits": hits,
            "total": total,
            "accuracy": (hits / total) if total else 0.0,
        }
    return metrics


def _print_topk_metrics(results: Dict[str, dict], rank_key: str, label: str) -> None:
    metrics = _topk_metrics(results, rank_key)
    totals = {item["total"] for item in metrics.values()}
    total = next(iter(totals), 0) if totals else 0
    if not total:
        return
    print(f"  {label}:")
    for k in EVAL_TOP_KS:
        item = metrics[k]
        print(f"    Top@{k}: {item['hits']}/{item['total']} = {item['accuracy'] * 100:.1f}%")


def _evaluate_llm_locations(entry: dict, llm_json: dict) -> dict:
    ground_truth = entry.get("evaluation_only", {}).get("ground_truth", [])
    top_locations = llm_json.get("top_locations") or []
    if not isinstance(top_locations, list):
        top_locations = []
    hit_rank = _hit_rank_for_function_ids(
        [location.get("function_id", "") for location in top_locations if isinstance(location, dict)],
        ground_truth,
    )
    initial_ranks = [
        rank
        for gt in ground_truth
        for rank in [_rank_in_initial_candidates(gt, entry.get("ranked_functions", []))]
        if rank is not None
    ]
    return {
        "ground_truth": ground_truth,
        "llm_hit_rank": hit_rank,
        "llm_topk": _topk_flags(hit_rank),
        "initial_ground_truth_rank": min(initial_ranks) if initial_ranks else None,
    }


def run_localization_agent_llm(config: LocalizationAgentLlmConfig) -> Dict[str, dict]:
    if load_dotenv:
        load_dotenv()
    if not config.model:
        config.model = os.environ.get("OPENROUTER_MODEL") or DEFAULT_OPENROUTER_MODEL
    payload_file = config.payload_file or default_llm_payload_file(config)
    config.payload_file = payload_file
    if not os.path.exists(payload_file):
        raise FileNotFoundError(f"Localization agent payload not found: {payload_file}. Run --localization-agent first.")
    payload = _safe_json_load(payload_file)
    filters = _filter_bug_ids(config.bug_id_filter)
    output_file = config.output_file or default_llm_output_file(config)
    config.output_file = output_file
    results: Dict[str, dict] = {}
    if config.resume and os.path.exists(output_file):
        existing = _safe_json_load(output_file)
        if isinstance(existing, dict):
            results.update(existing)

    selected = []
    for bug_id, entry in sorted(payload.items()):
        metadata_bug_id = (entry.get("case_card") or {}).get("metadata_bug_id", "")
        if not filters or bug_id in filters or metadata_bug_id in filters:
            selected.append((bug_id, entry))

    for index, (bug_id, entry) in enumerate(selected, start=1):
        if config.resume and _llm_entry_complete(results.get(bug_id)):
            print(f"  [{index}/{len(selected)}] {bug_id}: skip existing LLM result", flush=True)
            continue
        prompt_input = build_localization_llm_prompt_input(entry, config)
        messages = build_localization_llm_messages(prompt_input)
        response_text = ""
        raw_response = {}
        parsed = {}
        error = ""
        interrupted = False
        mode = "building dry-run prompt" if config.dry_run else f"calling {config.model}"
        print(f"  [{index}/{len(selected)}] {bug_id}: {mode}", flush=True)
        if not config.dry_run:
            try:
                response_text, raw_response = _call_openrouter_for_localization(messages, config)
                parsed = _extract_json_object(response_text)
                parsed = _complete_llm_locations(entry, parsed, config.candidate_limit)
            except KeyboardInterrupt:
                error = "interrupted by user while waiting for OpenRouter response"
                interrupted = True
            except Exception as exc:
                error = str(exc)
        results[bug_id] = {
            "model": config.model,
            "dry_run": config.dry_run,
            "prompt_input": prompt_input,
            "llm_result": parsed,
            "raw_response_text": response_text,
            "openrouter_usage": raw_response.get("usage") if isinstance(raw_response, dict) else None,
            "error": error,
            "evaluation_only": _evaluate_llm_locations(entry, parsed) if parsed else entry.get("evaluation_only", {}),
        }
        _write_json_file(output_file, results)
        if interrupted:
            break
        if config.request_interval_seconds > 0:
            time.sleep(config.request_interval_seconds)
    _write_json_file(output_file, results)
    return results


def print_localization_agent_llm_summary(results: Dict[str, dict], output_file: str = "") -> None:
    print("\nLocalization agent LLM summary:")
    print(f"  bugs: {len(results)}")
    for bug_id, entry in sorted(results.items()):
        if entry.get("error"):
            print(f"  {bug_id}: ERROR {entry['error']}")
            continue
        top_locations = (entry.get("llm_result") or {}).get("top_locations") or []
        top = top_locations[0].get("function_id", "") if top_locations and isinstance(top_locations[0], dict) else ""
        eval_only = entry.get("evaluation_only") or {}
        hit_rank = eval_only.get("llm_hit_rank")
        suffix = f" hit_rank={hit_rank}" if hit_rank is not None else ""
        mode = "dry-run" if entry.get("dry_run") else "called"
        print(f"  {bug_id}: {mode} top={top}{suffix}")
    if any(not entry.get("dry_run") for entry in results.values()):
        _print_topk_metrics(results, "llm_hit_rank", "LLM eval")
    if output_file:
        print(f"  output: {output_file}")


def add_localization_agent_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--localization-agent", action="store_true", help="Build function-centric localization graph/tool payloads.")
    parser.add_argument("--localization-agent-llm", action="store_true", help="Run OpenRouter LLM reranking over localization agent payloads.")
    parser.add_argument("--loc-agent-dataset", default="fmt", help="Defects4C unified_debugging dataset.")
    parser.add_argument("--loc-agent-metadata-dir", default="", help="Directory containing Defects4C *_meta.json files.")
    parser.add_argument("--loc-agent-defects4c-root", default="", help="Path to the defects4c repository.")
    parser.add_argument("--loc-agent-output-file", default="", help="Output JSON path for localization agent payloads.")
    parser.add_argument("--loc-agent-bug-id", default="", help="Optional comma-separated bug ids to run.")
    parser.add_argument("--loc-agent-top-k", type=int, default=10, help="Number of ranked functions to emit.")
    parser.add_argument("--loc-agent-inspect-top-k", type=int, default=0, help="Extract code for the top N ranked functions.")
    parser.add_argument("--loc-agent-code-mode", default="signature", choices=sorted(CODE_MODES), help="Code extraction mode.")
    parser.add_argument("--loc-agent-max-code-lines", type=int, default=120, help="Maximum extracted code lines per function.")
    parser.add_argument("--loc-agent-context-lines", type=int, default=3, help="Context lines around executed/relevant lines.")
    parser.add_argument("--loc-agent-include-fixed-fail", action="store_true", help="Keep tests that also fail on the fixed version.")
    parser.add_argument("--loc-agent-llm-payload-file", default="", help="Input localization_agent_tools.json path.")
    parser.add_argument("--loc-agent-llm-output-file", default="", help="Output JSON path for LLM localization results.")
    parser.add_argument("--loc-agent-llm-model", default=os.environ.get("OPENROUTER_MODEL", DEFAULT_OPENROUTER_MODEL), help="OpenRouter model id.")
    parser.add_argument("--loc-agent-llm-api-url", default=DEFAULT_OPENROUTER_URL, help="OpenRouter chat completions endpoint.")
    parser.add_argument("--loc-agent-llm-api-key-env", default="OPENROUTER_API_KEY", help="Environment variable containing the OpenRouter API key.")
    parser.add_argument("--loc-agent-llm-timeout", type=int, default=120, help="HTTP timeout seconds for OpenRouter.")
    parser.add_argument("--loc-agent-llm-max-tokens", type=int, default=4096, help="Max response tokens.")
    parser.add_argument("--loc-agent-llm-temperature", type=float, default=0.0, help="LLM sampling temperature.")
    parser.add_argument("--loc-agent-llm-candidate-limit", type=int, default=15, help="Number of candidates sent to the LLM.")
    parser.add_argument("--loc-agent-llm-inspected-limit", type=int, default=10, help="Reserved for compatibility; payload controls inspected functions.")
    parser.add_argument("--loc-agent-llm-max-code-lines", type=int, default=80, help="Max code lines per inspected function sent to the LLM.")
    parser.add_argument("--loc-agent-llm-dry-run", action="store_true", help="Write prompt payload without calling OpenRouter.")
    parser.add_argument("--loc-agent-llm-resume", action="store_true", help="Skip completed bugs already present in the LLM output file.")
    parser.add_argument("--loc-agent-llm-request-interval", type=float, default=0.0, help="Seconds to sleep between OpenRouter requests.")


def localization_agent_config_from_args(args: argparse.Namespace) -> LocalizationAgentConfig:
    return LocalizationAgentConfig(
        dataset=args.loc_agent_dataset,
        metadata_dir=args.loc_agent_metadata_dir,
        defects4c_root=args.loc_agent_defects4c_root,
        output_file=args.loc_agent_output_file,
        bug_id_filter=args.loc_agent_bug_id,
        top_k=args.loc_agent_top_k,
        inspect_top_k=args.loc_agent_inspect_top_k,
        code_mode=args.loc_agent_code_mode,
        max_code_lines=args.loc_agent_max_code_lines,
        context_lines=args.loc_agent_context_lines,
        exclude_fixed_fail_tests=not args.loc_agent_include_fixed_fail,
    )


def localization_agent_llm_config_from_args(args: argparse.Namespace) -> LocalizationAgentLlmConfig:
    if load_dotenv:
        load_dotenv()
    model = args.loc_agent_llm_model
    if not model or model == DEFAULT_OPENROUTER_MODEL:
        model = os.environ.get("OPENROUTER_MODEL", model or DEFAULT_OPENROUTER_MODEL)
    return LocalizationAgentLlmConfig(
        dataset=args.loc_agent_dataset,
        payload_file=args.loc_agent_llm_payload_file,
        output_file=args.loc_agent_llm_output_file,
        bug_id_filter=args.loc_agent_bug_id,
        model=model,
        api_url=args.loc_agent_llm_api_url,
        api_key_env=args.loc_agent_llm_api_key_env,
        timeout_seconds=args.loc_agent_llm_timeout,
        max_tokens=args.loc_agent_llm_max_tokens,
        temperature=args.loc_agent_llm_temperature,
        candidate_limit=args.loc_agent_llm_candidate_limit,
        inspected_limit=args.loc_agent_llm_inspected_limit,
        max_code_lines_per_function=args.loc_agent_llm_max_code_lines,
        dry_run=args.loc_agent_llm_dry_run,
        resume=args.loc_agent_llm_resume,
        request_interval_seconds=args.loc_agent_llm_request_interval,
    )
