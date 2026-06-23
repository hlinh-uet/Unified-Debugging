"""
Dynamic failure-evidence reranking for function-level fault localization.

The module treats Tarantula as a statistical prior and only changes ranks when
there is runtime evidence collected from true failing tests. The evidence is
kept deliberately generic: failure type, stack proximity, hit-order proximity,
and timeout hotness. No project-specific function-name categories are used.
"""

from __future__ import annotations

import argparse
import glob
import json
import math
import os
import re
import shutil
import shlex
import subprocess
import tempfile
import time
from collections import Counter
from dataclasses import asdict, dataclass, field
from typing import Dict, Iterable, List, Optional, Sequence, Tuple


PASS_OUTCOMES = {"PASS", "PASSED"}
FAIL_OUTCOMES = {"FAIL", "FAILED"}


@dataclass
class DynamicRerankConfig:
    dataset: str = "fmt"
    experiments_dir: str = ""
    metadata_dir: str = ""
    results_file: str = ""
    output_file: str = ""
    evidence_dir: str = ""
    data_output_file: str = ""
    data_dir: str = ""
    bug_id_filter: str = ""
    rerun: bool = True
    use_stack: bool = True
    use_hit_order: bool = False
    use_hotness: bool = False
    use_gdb: bool = False
    candidate_limit: int = 100
    timeout_seconds: int = 60
    base_weight_assertion: float = 0.65
    base_weight_crash: float = 0.55
    base_weight_timeout: float = 0.50
    min_evidence_quality: float = 0.10


@dataclass
class RerunResult:
    test_id: str
    attempted: bool = False
    command: str = ""
    exit_code: Optional[int] = None
    timed_out: bool = False
    elapsed_seconds: float = 0.0
    stdout: str = ""
    stderr: str = ""
    error: str = ""


@dataclass
class RuntimeEvidence:
    test_id: str
    failure_type: str = "unknown"
    evidence_quality: float = 0.0
    signal_lines: List[str] = field(default_factory=list)
    stack_frames: List[str] = field(default_factory=list)
    candidate_hit_counts: Dict[str, int] = field(default_factory=dict)
    candidate_last_hit_order: Dict[str, int] = field(default_factory=dict)
    trace_debug: dict = field(default_factory=dict)
    rerun: Optional[RerunResult] = None


@dataclass
class DebugTarget:
    executable: str
    argv: List[str] = field(default_factory=list)
    cwd: Optional[str] = None
    env: Dict[str, str] = field(default_factory=dict)
    resolver: str = ""


def _outcome(value: object) -> str:
    return str(value or "").upper()


def _sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def _normalize_scores(scores: Dict[str, float]) -> Dict[str, float]:
    if not scores:
        return {}
    values = list(scores.values())
    min_score = min(values)
    max_score = max(values)
    if max_score == min_score:
        return {key: (1.0 if max_score > 0 else 0.0) for key in scores}
    return {
        key: (value - min_score) / (max_score - min_score)
        for key, value in scores.items()
    }


def _split_function_key(function_key: str) -> Tuple[str, str]:
    match = re.search(r"(?<!:):(?!:)", function_key)
    if not match:
        return "", function_key
    return function_key[: match.start()], function_key[match.end() :]


def _tokenize(text: str) -> List[str]:
    text = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", str(text or ""))
    text = text.replace("::", " ").replace("_", " ").replace("-", " ")
    text = text.replace("/", " ").replace("\\", " ")
    return [
        token.lower()
        for token in re.findall(r"[A-Za-z][A-Za-z0-9]+|[0-9]+", text)
        if len(token) > 1
    ]


def _true_failed_tests(tests: Sequence[dict]) -> List[dict]:
    return [
        test
        for test in tests
        if _outcome(test.get("outcome")) in FAIL_OUTCOMES
        and _outcome(test.get("outcome_fixed")) in PASS_OUTCOMES
    ]


def _covered_functions(test: dict) -> List[str]:
    covered = test.get("covered_functions")
    if covered is None:
        covered = test.get("covered_methods", [])
    return [item for item in covered if isinstance(item, str)]


def _signal_lines(text: str, limit: int = 60) -> List[str]:
    signal = re.compile(
        r"FAIL|FAILED|ERROR|Failure|Actual|Expected|AddressSanitizer|"
        r"SUMMARY|Segmentation|Assertion|assert|overflow|underflow|invalid|"
        r"terminate|Aborted|timeout|timed out|fatal|exception|Which is:",
        re.IGNORECASE,
    )
    out: List[str] = []
    seen = set()
    for line in str(text or "").splitlines():
        cleaned = line.strip()
        if cleaned and signal.search(cleaned) and cleaned not in seen:
            seen.add(cleaned)
            out.append(cleaned)
    return out[:limit]


def classify_failure(output: str, timed_out: bool = False, exit_code: Optional[int] = None) -> str:
    if timed_out:
        return "timeout"
    lowered = str(output or "").lower()
    crash_markers = (
        "segmentation fault",
        "addresssanitizer",
        "undefinedbehaviorsanitizer",
        "runtime error:",
        "assertion failed",
        "assert failed",
        "aborted",
        "terminate called",
        "core dumped",
        "bus error",
        "floating point exception",
    )
    if any(marker in lowered for marker in crash_markers):
        return "crash"
    assertion_markers = (
        "expected",
        "actual",
        "which is:",
        "failure",
        "expect_",
        "assert_eq",
        "assert_streq",
        "assertion",
    )
    if any(marker in lowered for marker in assertion_markers):
        return "assertion_output"
    if exit_code is not None and exit_code < 0:
        return "crash"
    return "unknown"


def _extract_stack_frames(output: str) -> List[str]:
    frames: List[str] = []
    patterns = [
        re.compile(r"^\s*#\d+\s+.*$"),
        re.compile(r"^\s*at\s+.+:\d+.*$", re.IGNORECASE),
        re.compile(r"^\s*frame\s+#?\d+.*$", re.IGNORECASE),
    ]
    for line in str(output or "").splitlines():
        stripped = line.strip()
        if any(pattern.search(stripped) for pattern in patterns):
            frames.append(stripped)
    return frames[:80]


def _stack_frame_raw_list(frames: object) -> List[str]:
    out: List[str] = []
    if not isinstance(frames, list):
        return out
    for frame in frames:
        if isinstance(frame, str):
            raw = frame
        elif isinstance(frame, dict):
            raw = str(frame.get("raw") or frame.get("function") or "")
        else:
            raw = ""
        raw = raw.strip()
        if raw:
            out.append(raw)
    return out[:80]


def _numeric_dict(value: object) -> Dict[str, int]:
    if not isinstance(value, dict):
        return {}
    out: Dict[str, int] = {}
    for key, item in value.items():
        try:
            out[str(key)] = int(item)
        except (TypeError, ValueError):
            continue
    return out


def _parse_stack_frame_records(output: str) -> List[dict]:
    records: List[dict] = []
    for raw in _extract_stack_frames(output):
        item = {"raw": raw}
        index_match = re.match(r"#(?P<index>\d+)\s+", raw)
        if index_match:
            item["index"] = int(index_match.group("index"))
        loc_match = re.search(r"\bat\s+(?P<file>[^:\s]+):(?P<line>\d+)", raw)
        if loc_match:
            item["file"] = loc_match.group("file")
            item["line"] = int(loc_match.group("line"))
        func = raw
        func = re.sub(r"^#\d+\s+", "", func)
        func = re.sub(r"^0x[0-9a-fA-F]+\s+in\s+", "", func)
        func = func.split(" at ", 1)[0].strip()
        if func:
            item["function"] = func
        records.append(item)
    return records


def parse_structured_failure(output: str, timed_out: bool = False, exit_code: Optional[int] = None) -> dict:
    text = str(output or "")
    failure_type = classify_failure(text, timed_out, exit_code)
    oracle = "unknown"
    if "Google Test" in text or "[  FAILED  ]" in text or "[ RUN      ]" in text:
        oracle = "gtest"
    elif "AddressSanitizer" in text:
        oracle = "sanitizer"
    elif "UndefinedBehaviorSanitizer" in text or "runtime error:" in text:
        oracle = "sanitizer"
    elif exit_code is not None and exit_code != 0:
        oracle = "process_exit"

    assertion_location = ""
    for line in text.splitlines():
        stripped = line.strip()
        match = re.match(
            r"(?P<path>(?:[A-Za-z]:)?[^:\n]+?\.(?:c|cc|cpp|cxx|h|hpp)):(?P<line>\d+):(?:\s|$)",
            stripped,
        )
        if match:
            assertion_location = f"{match.group('path')}:{match.group('line')}"
            break

    actual_value = ""
    expected_value = ""
    observed_expression = ""
    lines = text.splitlines()
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith("Value of:"):
            observed_expression = stripped.split("Value of:", 1)[1].strip()
        elif stripped.startswith("Actual:"):
            actual_value = stripped.split("Actual:", 1)[1].strip()
        elif stripped.startswith("Expected:"):
            expected_value = stripped.split("Expected:", 1)[1].strip()
        elif stripped == "Expected equality of these values:":
            if idx + 1 < len(lines):
                expected_value = lines[idx + 1].strip()
            if idx + 3 < len(lines):
                actual_value = lines[idx + 3].strip()

    crash_signal = ""
    signal_match = re.search(r"\b(SIG[A-Z0-9]+)\b", text)
    if signal_match:
        crash_signal = signal_match.group(1)
    else:
        lowered = text.lower()
        if "segmentation fault" in lowered:
            crash_signal = "SIGSEGV"
        elif "aborted" in lowered or "abort" in lowered:
            crash_signal = "SIGABRT"
        elif "floating point exception" in lowered:
            crash_signal = "SIGFPE"

    sanitizer_summary = ""
    for line in text.splitlines():
        if "SUMMARY:" in line and ("Sanitizer" in line or "runtime error" in line):
            sanitizer_summary = line.strip()
            break

    return {
        "type": failure_type,
        "oracle": oracle,
        "assertion_location": assertion_location,
        "observed_expression": observed_expression,
        "actual_value": actual_value,
        "expected_value": expected_value,
        "crash_signal": crash_signal,
        "crash_location": "",
        "sanitizer_summary": sanitizer_summary,
        "signal_lines": _signal_lines(text),
    }


def _render_test_command(template: str, test_id: str) -> str:
    return template.replace("{test_id}", shlex.quote(test_id))


def rerun_failed_test(test: dict, test_cmd_template: str, config: DynamicRerankConfig) -> RerunResult:
    test_id = str(test.get("test_id") or "")
    result = RerunResult(test_id=test_id)
    if not config.rerun:
        result.error = "rerun_disabled"
        return result
    if not test_cmd_template or "{test_id}" not in test_cmd_template:
        result.error = "test_cmd_template_missing"
        return result

    command = _render_test_command(test_cmd_template, test_id)
    result.command = command
    result.attempted = True
    started = time.monotonic()
    try:
        proc = subprocess.run(
            command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=config.timeout_seconds,
        )
        result.exit_code = proc.returncode
        result.stdout = proc.stdout or ""
        result.stderr = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        result.timed_out = True
        result.stdout = exc.stdout or ""
        result.stderr = exc.stderr or ""
        result.error = "timeout"
    except Exception as exc:  # pragma: no cover - defensive integration path.
        result.error = f"{type(exc).__name__}: {exc}"
    finally:
        result.elapsed_seconds = time.monotonic() - started
    return result


def _candidate_functions(scores: Dict[str, float], tests: Sequence[dict], limit: int) -> List[str]:
    failed_covered = set()
    for test in _true_failed_tests(tests):
        failed_covered.update(_covered_functions(test))
    ordered = [
        key
        for key, _ in sorted(scores.items(), key=lambda item: (-item[1], item[0]))
        if key in failed_covered
    ]
    return ordered[: max(1, limit)]


def _token_match_score(candidate: str, lines: Iterable[str]) -> float:
    candidate_tokens = set(_tokenize(candidate))
    if not candidate_tokens:
        return 0.0
    line_tokens = set(_tokenize(" ".join(lines)))
    return len(candidate_tokens & line_tokens) / len(candidate_tokens)


def _stack_score(candidate: str, frames: Sequence[str]) -> float:
    if not frames:
        return 0.0
    file_part, func_part = _split_function_key(candidate)
    candidate_tokens = set(_tokenize(" ".join([file_part, func_part])))
    if not candidate_tokens:
        return 0.0
    best = 0.0
    for depth, frame in enumerate(frames):
        frame_tokens = set(_tokenize(frame))
        overlap = len(candidate_tokens & frame_tokens) / len(candidate_tokens)
        if overlap <= 0:
            continue
        best = max(best, overlap / (1.0 + depth))
    return best


def _end_proximity_score(candidate: str, evidence: RuntimeEvidence) -> float:
    if not evidence.candidate_last_hit_order:
        return 0.0
    last = evidence.candidate_last_hit_order.get(candidate)
    if last is None:
        return 0.0
    max_order = max(evidence.candidate_last_hit_order.values() or [0])
    if max_order <= 0:
        return 0.0
    return last / max_order


def _hotness_score(candidate: str, evidence: RuntimeEvidence) -> float:
    if not evidence.candidate_hit_counts:
        return 0.0
    count = evidence.candidate_hit_counts.get(candidate, 0)
    if count <= 0:
        return 0.0
    max_count = max(evidence.candidate_hit_counts.values() or [0])
    if max_count <= 0:
        return 0.0
    return math.log1p(count) / math.log1p(max_count)


def _has_candidate_stack_match(candidates: Sequence[str], frames: Sequence[str]) -> bool:
    production_frames = [
        frame for frame in frames
        if _is_production_stack_frame(frame)
    ]
    if not production_frames:
        return False
    return any(_stack_score(candidate, production_frames) > 0.0 for candidate in candidates)


def _is_production_stack_frame(frame: str) -> bool:
    lowered = str(frame or "").replace("\\", "/").lower()
    if not lowered:
        return False
    non_production_markers = (
        "/test/",
        "gtest",
        "gmock",
        "testing::",
        "run_all_tests",
        "testbody",
        "test_info",
        "testcase",
    )
    return not any(marker in lowered for marker in non_production_markers)


def collect_runtime_evidence(
    test: dict,
    test_cmd_template: str,
    candidates: Sequence[str],
    config: DynamicRerankConfig,
    metadata: Optional[dict] = None,
) -> RuntimeEvidence:
    rerun = rerun_failed_test(test, test_cmd_template, config)
    stored_runtime = test.get("runtime") if isinstance(test.get("runtime"), dict) else {}
    stored_failure = test.get("failure") if isinstance(test.get("failure"), dict) else {}
    stored_stack = test.get("stack") if isinstance(test.get("stack"), dict) else {}
    stored_trace = test.get("dynamic_trace") if isinstance(test.get("dynamic_trace"), dict) else {}
    stored_output = "\n".join(
        str(value or "")
        for value in (
            test.get("test_id"),
            test.get("fail_reason"),
            test.get("actual_output"),
            stored_runtime.get("stdout"),
            stored_runtime.get("stderr"),
            "\n".join(stored_failure.get("signal_lines") or []),
        )
    )
    rerun_output = "\n".join([rerun.stdout, rerun.stderr]).strip()
    output = "\n".join(part for part in [rerun_output, stored_output] if part)
    failure_type = stored_failure.get("type") or classify_failure(output, rerun.timed_out, rerun.exit_code)
    stored_frames = _stack_frame_raw_list(stored_stack.get("frames"))
    frames = stored_frames if config.use_stack else []
    if config.use_stack and not frames:
        frames = _extract_stack_frames(output)
    lines = list(stored_failure.get("signal_lines") or [])
    if not lines:
        lines = _signal_lines(output)

    evidence = RuntimeEvidence(
        test_id=str(test.get("test_id") or ""),
        failure_type=failure_type,
        signal_lines=lines,
        stack_frames=frames,
        rerun=rerun,
    )
    evidence.candidate_hit_counts = _numeric_dict(stored_trace.get("function_hit_counts"))
    evidence.candidate_last_hit_order = _numeric_dict(stored_trace.get("function_last_hit_order"))
    if stored_trace:
        evidence.trace_debug = {
            "source": "metadata.dynamic_trace",
            "collector": stored_trace.get("collector", ""),
            "available": bool(stored_trace.get("available")),
            "error": stored_trace.get("error", ""),
        }

    # GDB evidence is optional. It is collected only when the replay command can
    # be resolved to a concrete executable without assuming a project layout.
    if (
        config.use_gdb
        and (config.use_hit_order or config.use_hotness)
        and not (evidence.candidate_hit_counts or evidence.candidate_last_hit_order)
    ):
        trace = collect_gdb_runtime_trace(
            rerun.command,
            candidates,
            config,
            test=test,
            metadata=metadata,
        )
        evidence.trace_debug = trace
        evidence.candidate_hit_counts = _numeric_dict(trace.get("function_hit_counts"))
        evidence.candidate_last_hit_order = _numeric_dict(trace.get("function_last_hit_order"))
        if config.use_stack and not evidence.stack_frames:
            evidence.stack_frames = _stack_frame_raw_list(trace.get("stack_frames"))

    if (
        evidence.failure_type == "assertion_output"
        and (evidence.candidate_hit_counts or evidence.candidate_last_hit_order)
        and not _has_candidate_stack_match(candidates, evidence.stack_frames)
    ):
        evidence.trace_debug = {
            **(evidence.trace_debug or {}),
            "ignored_reason": "assertion_output_hit_order_without_candidate_stack_match",
        }
        evidence.candidate_hit_counts = {}
        evidence.candidate_last_hit_order = {}

    quality = 0.0
    if evidence.stack_frames:
        quality += 0.45
    if evidence.candidate_last_hit_order:
        quality += 0.45
    if evidence.candidate_hit_counts:
        quality += 0.35
    if lines and not (evidence.stack_frames or evidence.candidate_last_hit_order or evidence.candidate_hit_counts):
        quality += 0.05
    evidence.evidence_quality = min(1.0, quality)
    return evidence


def _collect_gdb_breakpoint_evidence(
    command: str,
    candidates: Sequence[str],
    config: DynamicRerankConfig,
    test: Optional[dict] = None,
    metadata: Optional[dict] = None,
) -> Tuple[Dict[str, int], Dict[str, int]]:
    gdb = shutil.which("gdb")
    target = _resolve_debug_target(command, metadata=metadata, test=test)
    if not gdb or not target:
        return {}, {}

    if not candidates:
        return {}, {}

    counts: Dict[str, int] = {}
    last_order: Dict[str, int] = {}
    marker = "__UD_DYNAMIC_HIT__"
    commands = [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        "set print thread-events off",
        "set multiple-symbols all",
    ]
    for key, value in sorted(target.env.items()):
        safe_value = str(value).replace("\\", "\\\\").replace('"', '\\"')
        commands.append(f"set environment {key} {safe_value}")
    for candidate in candidates:
        _, func = _split_function_key(candidate)
        func = _safe_gdb_breakpoint_function(func)
        if not func:
            continue
        escaped_candidate = candidate.replace("\\", "\\\\").replace('"', '\\"')
        commands.extend([
            f"break {func}",
            "commands",
            "silent",
            f'printf "{marker} {escaped_candidate}\\n"',
            "continue",
            "end",
        ])
    commands.append("run")
    commands.append("bt 30")

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".gdb") as f:
        f.write("\n".join(commands))
        script_path = f.name
    try:
        proc = subprocess.run(
            [gdb, "--batch", "--nx", "-x", script_path, "--args", target.executable, *target.argv],
            cwd=target.cwd,
            env={**os.environ, **target.env},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(config.timeout_seconds, 5),
        )
    except Exception:
        return {}, {}
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass

    order = 0
    for line in (proc.stdout or "").splitlines():
        if marker not in line:
            continue
        candidate = line.split(marker, 1)[1].strip()
        if not candidate:
            continue
        order += 1
        counts[candidate] = counts.get(candidate, 0) + 1
        last_order[candidate] = order
        if order >= 5000:
            break
    return counts, last_order


def _safe_gdb_breakpoint_function(func: str) -> str:
    func = str(func or "").strip()
    if not func:
        return ""
    if func in {"if", "for", "while", "switch", "return", "sizeof", "case", "do"}:
        return ""
    if "FMT_EXPLICIT" in func or "::&" in func:
        return ""
    if func[0] in {"*", "&", "(", ")", "[", "]", "{", "}", ":", ";"}:
        return ""
    if func.endswith(":"):
        return ""
    if re.search(r"[{};]", func):
        return ""
    return func


def collect_gdb_runtime_trace(
    command: str,
    candidates: Sequence[str],
    config: DynamicRerankConfig,
    test: Optional[dict] = None,
    metadata: Optional[dict] = None,
) -> dict:
    gdb = shutil.which("gdb")
    if not gdb:
        return {
            "collector": "gdb",
            "available": False,
            "error": "gdb_not_found",
        }

    target = _resolve_debug_target(command, metadata=metadata, test=test)
    if not target:
        return {
            "collector": "gdb",
            "available": False,
            "error": "debug_target_not_resolved",
        }

    argv = list(target.argv)
    if any(arg.startswith("--gtest_filter=") for arg in argv) and not any(
        arg == "--gtest_break_on_failure" for arg in argv
    ):
        argv.append("--gtest_break_on_failure")

    marker = "__UD_DYNAMIC_HIT__"
    commands = [
        "set pagination off",
        "set confirm off",
        "set breakpoint pending on",
        "set print thread-events off",
        "set multiple-symbols all",
    ]
    for key, value in sorted(target.env.items()):
        safe_value = str(value).replace("\\", "\\\\").replace('"', '\\"')
        commands.append(f"set environment {key} {safe_value}")

    if config.use_hit_order or config.use_hotness:
        for candidate in candidates:
            _, func = _split_function_key(candidate)
            func = _safe_gdb_breakpoint_function(func)
            if not func:
                continue
            escaped_candidate = candidate.replace("\\", "\\\\").replace('"', '\\"')
            commands.extend([
                f"break {func}",
                "commands",
                "silent",
                f'printf "{marker} {escaped_candidate}\\n"',
                "continue",
                "end",
            ])
    commands.append("run")
    commands.append("bt 40")

    with tempfile.NamedTemporaryFile("w", delete=False, encoding="utf-8", suffix=".gdb") as f:
        f.write("\n".join(commands))
        script_path = f.name

    started = time.monotonic()
    try:
        proc = subprocess.run(
            [gdb, "--batch", "--nx", "-x", script_path, "--args", target.executable, *argv],
            cwd=target.cwd,
            env={**os.environ, **target.env},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=max(config.timeout_seconds, 5),
        )
        exit_code = proc.returncode
        stdout = proc.stdout or ""
        stderr = proc.stderr or ""
        timed_out = False
        error = ""
    except subprocess.TimeoutExpired as exc:
        exit_code = None
        stdout = exc.stdout or ""
        stderr = exc.stderr or ""
        timed_out = True
        error = "timeout"
    except Exception as exc:  # pragma: no cover - defensive integration path.
        exit_code = None
        stdout = ""
        stderr = ""
        timed_out = False
        error = f"{type(exc).__name__}: {exc}"
    finally:
        try:
            os.unlink(script_path)
        except OSError:
            pass

    combined = "\n".join([stdout, stderr])
    order = 0
    hit_counts: Dict[str, int] = {}
    first_hit_order: Dict[str, int] = {}
    last_hit_order: Dict[str, int] = {}
    hit_sequence: List[dict] = []
    for line in combined.splitlines():
        if marker not in line:
            continue
        candidate = line.split(marker, 1)[1].strip()
        if not candidate:
            continue
        order += 1
        hit_counts[candidate] = hit_counts.get(candidate, 0) + 1
        first_hit_order.setdefault(candidate, order)
        last_hit_order[candidate] = order
        if len(hit_sequence) < 5000:
            hit_sequence.append({"order": order, "function": candidate})

    stack_frames = _parse_stack_frame_records(combined) if config.use_stack else []
    tail_lines = [line for line in combined.splitlines() if line.strip()][-80:]
    return {
        "collector": "gdb",
        "available": True,
        "error": error,
        "resolver": target.resolver,
        "elapsed_seconds": time.monotonic() - started,
        "exit_code": exit_code,
        "timed_out": timed_out,
        "target": {
            "executable": target.executable,
            "argv": argv,
            "cwd": target.cwd,
            "env": target.env,
        },
        "candidate_scope_size": len(candidates),
        "failure_event_order": (order + 1) if stack_frames else None,
        "function_hit_counts": hit_counts,
        "function_first_hit_order": first_hit_order,
        "function_last_hit_order": last_hit_order,
        "last_functions_before_failure": [item["function"] for item in hit_sequence[-20:]],
        "stack_frames": stack_frames,
        "raw_output_tail": tail_lines,
    }


def _resolve_debug_target(
    command: str,
    *,
    metadata: Optional[dict] = None,
    test: Optional[dict] = None,
) -> Optional[DebugTarget]:
    if not command:
        return None
    if any(token in command for token in ("|", "&&", "||", ";", ">", "<", "$(", "`")):
        return None
    try:
        parts = shlex.split(command)
    except ValueError:
        return None
    if not parts:
        return None

    wrapper_target = _resolve_run_one_test_wrapper(parts, metadata=metadata, test=test)
    if wrapper_target:
        return wrapper_target

    wrappers = {"bash", "sh", "cmd", "powershell", "pwsh", "python", "python3", "perl", "ruby"}
    exe = parts[0]
    if os.path.basename(exe).lower() in wrappers or exe.lower().endswith((".sh", ".bat", ".cmd", ".ps1")):
        return None

    resolved = exe if os.path.exists(exe) else shutil.which(exe)
    if not resolved:
        return None
    return DebugTarget(resolved, parts[1:], resolver="direct")


def _resolve_run_one_test_wrapper(
    parts: Sequence[str],
    *,
    metadata: Optional[dict],
    test: Optional[dict],
) -> Optional[DebugTarget]:
    if len(parts) < 3:
        return None
    shell_name = os.path.basename(parts[0]).lower()
    if shell_name not in {"bash", "sh"}:
        return None

    script_path = parts[1]
    test_id = str((test or {}).get("test_id") or parts[-1])
    if os.path.basename(script_path) != "run_one_test.sh" or not test_id:
        return None

    repo_dir = os.path.dirname(script_path)
    script_text = _read_text_safe(script_path)

    case_target = _resolve_case_script_target(script_text, repo_dir, test_id)
    if case_target:
        return case_target

    mapping_target = _resolve_build_meta_mapping_target(repo_dir, test_id)
    if mapping_target:
        return mapping_target

    if "::" not in test_id:
        return None

    binary_name, selector = test_id.split("::", 1)
    if not binary_name or not selector:
        return None

    build_dirs = _infer_build_dirs(repo_dir, metadata or {})
    executable = _find_executable_by_name(build_dirs, binary_name)
    if not executable:
        return None

    lowered_script = script_text.lower()
    if "--gtest_filter" in lowered_script or "gtest_filter" in lowered_script:
        build_dir = _owning_build_dir(executable, build_dirs)
        return DebugTarget(
            executable=executable,
            argv=[f"--gtest_filter={selector}", "--gtest_color=no"],
            cwd=_infer_wrapper_cwd(script_text, build_dir),
            resolver="run_one_test:gtest",
        )

    env_name = _detect_env_filter_name(script_text)
    if env_name:
        return DebugTarget(
            executable=executable,
            argv=[],
            cwd=None,
            env={env_name: selector},
            resolver="run_one_test:env-filter",
        )
    return None


def _read_text_safe(path: str) -> str:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return f.read()
    except OSError:
        return ""


def _resolve_case_script_target(script_text: str, repo_dir: str, test_id: str) -> Optional[DebugTarget]:
    if not script_text:
        return None
    for line in script_text.splitlines():
        stripped = line.strip()
        if ")" not in stripped or test_id not in stripped:
            continue
        label = stripped.split(")", 1)[0].strip()
        try:
            label_parts = shlex.split(label)
            label = label_parts[0] if label_parts else label
        except ValueError:
            pass
        if label != test_id:
            continue
        command = _parse_shell_array_assignment(stripped, "TEST_CMD")
        exe_rel = _parse_shell_scalar_assignment(stripped, "EXE_REL")
        cwd_rel = _parse_shell_scalar_assignment(stripped, "TEST_CWD")
        cwd = _shell_path_to_host(cwd_rel, repo_dir) if cwd_rel else None

        if command:
            command = [_expand_shell_root(token, repo_dir) for token in command]
            executable = command[0]
            if os.path.exists(executable):
                return DebugTarget(
                    executable=executable,
                    argv=command[1:],
                    cwd=cwd,
                    resolver="run_one_test:case-command",
                )
        if exe_rel:
            executable = _shell_path_to_host(exe_rel, repo_dir)
            if os.path.exists(executable):
                return DebugTarget(
                    executable=executable,
                    argv=[],
                    cwd=cwd or os.path.dirname(executable),
                    resolver="run_one_test:case-exe",
                )
    return None


def _resolve_build_meta_mapping_target(repo_dir: str, test_id: str) -> Optional[DebugTarget]:
    for mapping_path in sorted(glob.glob(os.path.join(repo_dir, ".build_meta*_tests"))):
        for line in _read_text_safe(mapping_path).splitlines():
            if not line.strip():
                continue
            try:
                parts = shlex.split(line)
            except ValueError:
                continue
            if len(parts) < 2 or parts[0] != test_id:
                continue
            executable = _shell_path_to_host(parts[1], repo_dir)
            if os.path.exists(executable):
                return DebugTarget(
                    executable=executable,
                    argv=[],
                    cwd=os.path.dirname(executable),
                    resolver="run_one_test:mapping",
                )
    return None


def _parse_shell_scalar_assignment(line: str, name: str) -> str:
    match = re.search(rf"\b{name}=((?:'[^']*')|(?:\"[^\"]*\")|[^;\s]+)", line)
    if not match:
        return ""
    try:
        parts = shlex.split(match.group(1))
    except ValueError:
        return ""
    return parts[0] if parts else ""


def _parse_shell_array_assignment(line: str, name: str) -> List[str]:
    match = re.search(rf"\b{name}=\((.*?)\)", line)
    if not match:
        return []
    try:
        return shlex.split(match.group(1))
    except ValueError:
        return []


def _expand_shell_root(path: str, repo_dir: str) -> str:
    return (
        str(path)
        .replace("${ROOT}", repo_dir)
        .replace("$ROOT", repo_dir)
        .replace("${HERE}", repo_dir)
        .replace("$HERE", repo_dir)
    )


def _shell_path_to_host(path: str, repo_dir: str) -> str:
    expanded = _expand_shell_root(path, repo_dir)
    if os.path.isabs(expanded):
        return expanded
    return os.path.normpath(os.path.join(repo_dir, expanded))


def _infer_build_dirs(repo_dir: str, metadata: dict) -> List[str]:
    dirs: List[str] = []

    def add(path: str) -> None:
        if not path:
            return
        resolved = path if os.path.isabs(path) else os.path.join(repo_dir, path)
        resolved = os.path.normpath(resolved)
        if resolved not in dirs and os.path.isdir(resolved):
            dirs.append(resolved)

    compile_cmd = str(metadata.get("compile_cmd") or "")
    try:
        parts = shlex.split(compile_cmd)
    except ValueError:
        parts = []
    for idx, part in enumerate(parts):
        if part in {"-B", "--build", "--test-dir"} and idx + 1 < len(parts):
            add(parts[idx + 1])
        elif part.startswith("-B") and len(part) > 2:
            add(part[2:])

    if os.path.isdir(repo_dir):
        for name in sorted(os.listdir(repo_dir)):
            path = os.path.join(repo_dir, name)
            if name.startswith("build") and os.path.isdir(path):
                add(path)
    return dirs


def _find_executable_by_name(build_dirs: Sequence[str], binary_name: str) -> str:
    checked = set()
    common_subdirs = ("", "bin", "test", "tests")
    for build_dir in build_dirs:
        for subdir in common_subdirs:
            candidate = os.path.join(build_dir, subdir, binary_name)
            checked.add(os.path.normpath(candidate))
            if os.path.isfile(candidate):
                return candidate

    visited = 0
    for build_dir in build_dirs:
        for root, _, files in os.walk(build_dir):
            visited += len(files)
            if binary_name in files:
                candidate = os.path.join(root, binary_name)
                if os.path.normpath(candidate) not in checked and os.path.isfile(candidate):
                    return candidate
            if visited > 20000:
                return ""
    return ""


def _owning_build_dir(executable: str, build_dirs: Sequence[str]) -> str:
    executable = os.path.normpath(executable)
    for build_dir in build_dirs:
        build_dir_norm = os.path.normpath(build_dir)
        try:
            common = os.path.commonpath([executable, build_dir_norm])
        except ValueError:
            continue
        if common == build_dir_norm:
            return build_dir_norm
    return ""


def _infer_wrapper_cwd(script_text: str, build_dir: str) -> Optional[str]:
    if not build_dir:
        return None
    for subdir in ("test", "tests"):
        candidate = os.path.join(build_dir, subdir)
        if os.path.isdir(candidate) and f"$BUILD_DIR/{subdir}" in script_text:
            return candidate
    return None


def _detect_env_filter_name(script_text: str) -> str:
    for name in re.findall(r"\b([A-Z][A-Z0-9_]*(?:TEST_FILTER|TESTCASE|FILTER)[A-Z0-9_]*)=", script_text):
        if "GTEST" not in name:
            return name
    return ""


def _runtime_score(
    candidate: str,
    evidence_items: Sequence[RuntimeEvidence],
    enabled: DynamicRerankConfig,
) -> float:
    scores: List[float] = []
    for evidence in evidence_items:
        stack_component = _stack_score(candidate, evidence.stack_frames) if enabled.use_stack else 0.0
        end_component = _end_proximity_score(candidate, evidence) if enabled.use_hit_order else 0.0
        hot_component = _hotness_score(candidate, evidence) if enabled.use_hotness else 0.0
        token_component = _token_match_score(candidate, evidence.signal_lines)

        if evidence.failure_type == "crash":
            score = 0.80 * stack_component + 0.20 * end_component
        elif evidence.failure_type == "timeout":
            score = 0.60 * hot_component + 0.30 * stack_component + 0.10 * end_component
        elif evidence.failure_type == "assertion_output":
            score = 0.70 * end_component + 0.20 * stack_component + 0.10 * token_component
        else:
            score = 0.0
        scores.append(score)
    return max(scores or [0.0])


def _base_weight_for_failure(failure_types: Sequence[str], config: DynamicRerankConfig) -> float:
    if "timeout" in failure_types:
        return config.base_weight_timeout
    if "crash" in failure_types:
        return config.base_weight_crash
    if "assertion_output" in failure_types:
        return config.base_weight_assertion
    return 1.0


def rerank_scores_for_bug(
    bug_id: str,
    entry: dict,
    metadata: dict,
    config: DynamicRerankConfig,
) -> Tuple[Dict[str, float], dict]:
    tarantula_scores = entry.get("tarantula_scores") or {}
    if not tarantula_scores:
        return {}, {"bug_id": bug_id, "error": "missing_tarantula_scores"}

    tests = metadata.get("tests", [])
    true_failed = _true_failed_tests(tests)
    candidates = _candidate_functions(tarantula_scores, tests, config.candidate_limit)
    template = metadata.get("test_cmd_template") or ""

    evidence_items = [
        collect_runtime_evidence(test, template, candidates, config, metadata)
        for test in true_failed
    ]
    max_quality = max((item.evidence_quality for item in evidence_items), default=0.0)
    failure_types = [item.failure_type for item in evidence_items]

    if max_quality < config.min_evidence_quality:
        evidence_summary = {
            "bug_id": bug_id,
            "fallback": "tarantula",
            "fallback_reason": "runtime_evidence_below_threshold",
            "evidence_quality": max_quality,
            "failure_types": failure_types,
            "tests": [asdict(item) for item in evidence_items],
        }
        return _sort_scores(dict(tarantula_scores)), evidence_summary

    tarantula_norm = _normalize_scores({key: float(value) for key, value in tarantula_scores.items()})
    runtime_raw = {
        key: _runtime_score(key, evidence_items, config)
        for key in tarantula_scores
    }
    runtime_norm = _normalize_scores(runtime_raw)
    base_weight = _base_weight_for_failure(failure_types, config)
    runtime_weight = 1.0 - base_weight
    dynamic_scores = {
        key: base_weight * tarantula_norm.get(key, 0.0)
        + runtime_weight * runtime_norm.get(key, 0.0)
        for key in tarantula_scores
    }
    evidence_summary = {
        "bug_id": bug_id,
        "fallback": None,
        "evidence_quality": max_quality,
        "failure_types": failure_types,
        "base_weight": base_weight,
        "runtime_weight": runtime_weight,
        "enabled_evidence": {
            "rerun": config.rerun,
            "stack": config.use_stack,
            "hit_order": config.use_hit_order,
            "hotness": config.use_hotness,
            "gdb": config.use_gdb,
        },
        "runtime_raw_scores": _sort_scores(runtime_raw),
        "tests": [asdict(item) for item in evidence_items],
    }
    return _sort_scores(dynamic_scores), evidence_summary


def _metadata_path(metadata_dir: str, bug_id: str) -> Optional[str]:
    candidates = sorted(glob.glob(os.path.join(metadata_dir, f"{bug_id}*_meta.json")))
    return candidates[0] if candidates else None


def _default_experiment_path(config: DynamicRerankConfig) -> str:
    if config.experiments_dir:
        return config.experiments_dir
    here = os.path.dirname(os.path.abspath(__file__))
    return os.path.abspath(os.path.join(here, "..", "experiments"))


def _resolve_paths(config: DynamicRerankConfig) -> DynamicRerankConfig:
    experiments_dir = _default_experiment_path(config)
    dataset_dir = os.path.join(experiments_dir, config.dataset)
    if not config.results_file:
        config.results_file = os.path.join(dataset_dir, "fault_localization_function_results.json")
    if not config.output_file:
        config.output_file = os.path.join(dataset_dir, "dynamic_failure_function_results.json")
    if not config.evidence_dir:
        config.evidence_dir = os.path.join(dataset_dir, "dynamic_failure_evidence")
    if not config.data_output_file:
        config.data_output_file = os.path.join(dataset_dir, "dynamic_failure_data.json")
    if not config.data_dir:
        config.data_dir = os.path.join(dataset_dir, "dynamic_failure_data")
    if not config.metadata_dir:
        container_metadata_dir = os.path.join(
            os.sep,
            "out",
            "unified_debugging",
            config.dataset,
            "metadata",
        )
        root = os.path.abspath(os.path.join(experiments_dir, "..", ".."))
        host_metadata_dir = os.path.join(
            root,
            "defects4c",
            "out_tmp_dirs",
            "unified_debugging",
            config.dataset,
            "metadata",
        )
        config.metadata_dir = (
            container_metadata_dir
            if os.path.isdir(container_metadata_dir)
            else host_metadata_dir
        )
    config.experiments_dir = experiments_dir
    return config


def _bug_filter(config: DynamicRerankConfig) -> set:
    return {
        item.strip()
        for item in str(config.bug_id_filter or "").split(",")
        if item.strip()
    }


def _metadata_id_from_path(path: str) -> str:
    name = os.path.basename(path)
    return name[:-10] if name.endswith("_meta.json") else os.path.splitext(name)[0]


def _load_results_or_empty(results_file: str) -> Dict[str, dict]:
    if not results_file or not os.path.exists(results_file):
        return {}
    with open(results_file, "r", encoding="utf-8") as f:
        data = json.load(f)
    return data if isinstance(data, dict) else {}


def _candidate_functions_for_collection(
    entry: dict,
    tests: Sequence[dict],
    config: DynamicRerankConfig,
) -> List[str]:
    scores = entry.get("tarantula_scores") or {}
    if scores:
        return _candidate_functions(scores, tests, config.candidate_limit)

    covered: List[str] = []
    seen = set()
    for test in _true_failed_tests(tests):
        for function in _covered_functions(test):
            if function not in seen:
                seen.add(function)
                covered.append(function)
    return covered[: max(1, config.candidate_limit)]


def _runtime_record(rerun: RerunResult) -> dict:
    return {
        "replay_command": rerun.command,
        "attempted": rerun.attempted,
        "exit_code": rerun.exit_code,
        "timed_out": rerun.timed_out,
        "elapsed_seconds": rerun.elapsed_seconds,
        "stdout": rerun.stdout,
        "stderr": rerun.stderr,
        "error": rerun.error,
    }


def _top_candidate_from_stack(stack_frames: Sequence[dict], candidates: Sequence[str]) -> str:
    raw_frames = [str(frame.get("raw") or "") for frame in stack_frames]
    best_candidate = ""
    best_score = 0.0
    for candidate in candidates:
        score = _stack_score(candidate, raw_frames)
        if score > best_score:
            best_score = score
            best_candidate = candidate
    return best_candidate if best_score > 0 else ""


def collect_runtime_data_for_test(
    test: dict,
    test_cmd_template: str,
    candidates: Sequence[str],
    metadata: dict,
    config: DynamicRerankConfig,
) -> dict:
    rerun = rerun_failed_test(test, test_cmd_template, config)
    output_parts: List[str] = []
    for part in [rerun.stdout, rerun.stderr, str(test.get("fail_reason") or ""), str(test.get("actual_output") or "")]:
        if part and part not in output_parts:
            output_parts.append(part)
    output = "\n".join(output_parts)
    failure = parse_structured_failure(output, rerun.timed_out, rerun.exit_code)

    dynamic_trace = {
        "collector": "disabled",
        "available": False,
        "function_hit_counts": {},
        "function_first_hit_order": {},
        "function_last_hit_order": {},
        "last_functions_before_failure": [],
    }
    if config.use_gdb and (config.use_stack or config.use_hit_order or config.use_hotness):
        dynamic_trace = collect_gdb_runtime_trace(
            rerun.command,
            candidates,
            config,
            test=test,
            metadata=metadata,
        )

    stack_frames = dynamic_trace.get("stack_frames") or _parse_stack_frame_records(output)
    return {
        "test_id": str(test.get("test_id") or ""),
        "outcome": test.get("outcome"),
        "outcome_fixed": test.get("outcome_fixed"),
        "covered_functions": _covered_functions(test),
        "runtime": _runtime_record(rerun),
        "failure": failure,
        "stack": {
            "frames": stack_frames,
            "top_candidate_frame": _top_candidate_from_stack(stack_frames, candidates),
        },
        "dynamic_trace": dynamic_trace,
    }


def collect_dynamic_failure_data(config: DynamicRerankConfig) -> Dict[str, dict]:
    config = _resolve_paths(config)
    results = _load_results_or_empty(config.results_file)
    bug_filter = _bug_filter(config)

    if results:
        bug_ids = sorted(results)
    else:
        bug_ids = [
            _metadata_id_from_path(path)
            for path in sorted(glob.glob(os.path.join(config.metadata_dir, "*_meta.json")))
        ]
    if bug_filter:
        bug_ids = [bug_id for bug_id in bug_ids if bug_id in bug_filter]

    os.makedirs(os.path.dirname(config.data_output_file), exist_ok=True)
    os.makedirs(config.data_dir, exist_ok=True)

    output: Dict[str, dict] = {}
    for bug_id in bug_ids:
        meta_path = _metadata_path(config.metadata_dir, bug_id)
        if not meta_path:
            output[bug_id] = {
                "dataset": config.dataset,
                "collector": "dynamic_failure_data",
                "bug_id": bug_id,
                "error": "metadata_not_found",
            }
            continue

        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        tests = metadata.get("tests", [])
        true_failed = _true_failed_tests(tests)
        entry = results.get(bug_id, {})
        candidates = _candidate_functions_for_collection(entry, tests, config)
        template = metadata.get("test_cmd_template") or ""

        bug_record = {
            "dataset": config.dataset,
            "collector": "dynamic_failure_data",
            "bug_id": bug_id,
            "metadata_file": meta_path,
            "project": metadata.get("project", ""),
            "source_file": metadata.get("source_file", ""),
            "compile_cmd": metadata.get("compile_cmd", ""),
            "test_cmd_template": template,
            "ground_truth": metadata.get("ground_truth", []),
            "ground_truth_functions": metadata.get("ground_truth_functions", []),
            "candidate_functions": candidates,
            "true_failing_test_count": len(true_failed),
            "collection_config": {
                "use_gdb": config.use_gdb,
                "use_stack": config.use_stack,
                "use_hit_order": config.use_hit_order,
                "use_hotness": config.use_hotness,
                "candidate_limit": config.candidate_limit,
                "timeout_seconds": config.timeout_seconds,
            },
            "tests": [
                collect_runtime_data_for_test(test, template, candidates, metadata, config)
                for test in true_failed
            ],
        }
        output[bug_id] = bug_record
        with open(os.path.join(config.data_dir, f"{bug_id}.json"), "w", encoding="utf-8") as f:
            json.dump(bug_record, f, indent=2)

    with open(config.data_output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def run_dynamic_failure_rerank(config: DynamicRerankConfig) -> Dict[str, dict]:
    config = _resolve_paths(config)
    with open(config.results_file, "r", encoding="utf-8") as f:
        results = json.load(f)
    bug_filter = _bug_filter(config)

    os.makedirs(os.path.dirname(config.output_file), exist_ok=True)
    os.makedirs(config.evidence_dir, exist_ok=True)
    output: Dict[str, dict] = {}
    for bug_id, entry in results.items():
        if bug_filter and bug_id not in bug_filter:
            continue
        meta_path = _metadata_path(config.metadata_dir, bug_id)
        if not meta_path:
            output[bug_id] = {
                "dataset": entry.get("dataset", config.dataset),
                "formula": "tarantula",
                "reranker": "dynamic_failure",
                "tarantula_scores": entry.get("tarantula_scores") or {},
                "dynamic_failure_scores": entry.get("tarantula_scores") or {},
                "ground_truth": entry.get("ground_truth", []),
                "dynamic_failure_error": "metadata_not_found",
            }
            continue
        with open(meta_path, "r", encoding="utf-8") as f:
            metadata = json.load(f)
        dynamic_scores, evidence = rerank_scores_for_bug(bug_id, entry, metadata, config)
        output[bug_id] = {
            "dataset": entry.get("dataset", config.dataset),
            "formula": "tarantula",
            "reranker": "dynamic_failure",
            "tarantula_scores": entry.get("tarantula_scores") or {},
            "dynamic_failure_scores": dynamic_scores,
            "ground_truth": entry.get("ground_truth", []),
            "dynamic_failure_config": {
                "candidate_limit": config.candidate_limit,
                "timeout_seconds": config.timeout_seconds,
                "rerun": config.rerun,
                "use_stack": config.use_stack,
                "use_hit_order": config.use_hit_order,
                "use_hotness": config.use_hotness,
                "use_gdb": config.use_gdb,
                "min_evidence_quality": config.min_evidence_quality,
            },
        }
        evidence_path = os.path.join(config.evidence_dir, f"{bug_id}.json")
        with open(evidence_path, "w", encoding="utf-8") as f:
            json.dump(evidence, f, indent=2)

    with open(config.output_file, "w", encoding="utf-8") as f:
        json.dump(output, f, indent=4)
    return output


def _rank_ground_truth(scores: Dict[str, float], ground_truth: Sequence[str]) -> Optional[int]:
    for rank, (key, _) in enumerate(
        sorted((scores or {}).items(), key=lambda item: (-item[1], item[0])),
        start=1,
    ):
        for gt in ground_truth:
            if key == gt or key.endswith(f":{gt}") or key.endswith(f"::{gt}"):
                return rank
    return None


def summarize_dynamic_results(results: Dict[str, dict]) -> Dict[str, object]:
    rows = []
    for bug_id, entry in sorted(results.items()):
        ground_truth = entry.get("ground_truth", [])
        before = _rank_ground_truth(entry.get("tarantula_scores", {}), ground_truth)
        after = _rank_ground_truth(entry.get("dynamic_failure_scores", {}), ground_truth)
        rows.append({
            "bug_id": bug_id,
            "before_rank": before,
            "after_rank": after,
            "delta": (before - after) if before is not None and after is not None else None,
            "ground_truth": ground_truth,
        })

    total = len(rows)
    topk = {}
    for k in (3, 5, 10):
        before_count = sum(1 for row in rows if row["before_rank"] is not None and row["before_rank"] <= k)
        after_count = sum(1 for row in rows if row["after_rank"] is not None and row["after_rank"] <= k)
        topk[f"top{k}"] = {
            "before_count": before_count,
            "before_percent": (before_count / total * 100.0) if total else 0.0,
            "after_count": after_count,
            "after_percent": (after_count / total * 100.0) if total else 0.0,
        }

    return {
        "total": total,
        "topk": topk,
        "improved": sum(1 for row in rows if row["delta"] is not None and row["delta"] > 0),
        "same": sum(1 for row in rows if row["delta"] == 0),
        "worse": sum(1 for row in rows if row["delta"] is not None and row["delta"] < 0),
        "rows": rows,
    }


def print_dynamic_summary(results: Dict[str, dict]) -> None:
    summary = summarize_dynamic_results(results)
    total = summary["total"]
    print("\nDynamic failure rerank summary:")
    for label in ("top3", "top5", "top10"):
        item = summary["topk"][label]
        print(
            f"  {label}: "
            f"Tarantula {item['before_count']}/{total} ({item['before_percent']:.2f}%) | "
            f"Dynamic {item['after_count']}/{total} ({item['after_percent']:.2f}%)"
        )
    print(
        f"  rank delta: improved={summary['improved']} "
        f"same={summary['same']} worse={summary['worse']}"
    )


def print_dynamic_data_summary(results: Dict[str, dict]) -> None:
    total_bugs = len(results)
    total_tests = 0
    failure_types = Counter()
    gdb_available = 0
    with_hit_order = 0
    with_stack = 0
    errors = 0

    for record in results.values():
        if record.get("error"):
            errors += 1
            continue
        for test in record.get("tests", []):
            total_tests += 1
            failure_types[str((test.get("failure") or {}).get("type") or "unknown")] += 1
            trace = test.get("dynamic_trace") or {}
            if trace.get("available"):
                gdb_available += 1
            if trace.get("function_last_hit_order"):
                with_hit_order += 1
            if (test.get("stack") or {}).get("frames"):
                with_stack += 1

    print("\nDynamic failure data summary:")
    print(f"  bugs: {total_bugs} (errors={errors})")
    print(f"  true failing tests collected: {total_tests}")
    print(f"  failure types: {dict(failure_types)}")
    print(f"  with GDB trace: {gdb_available}/{total_tests}")
    print(f"  with hit-order: {with_hit_order}/{total_tests}")
    print(f"  with stack: {with_stack}/{total_tests}")


def add_dynamic_rerank_args(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--dynamic-rerank", action="store_true", help="Run dynamic failure-evidence function reranking.")
    parser.add_argument("--dynamic-collect-data", action="store_true", help="Collect replay/failure/stack/trace data for dynamic FL.")
    parser.add_argument("--dynamic-dataset", default="fmt", help="Experiment dataset folder, e.g. fmt or libyang.")
    parser.add_argument("--dynamic-results-file", default="", help="Path to function FL results JSON.")
    parser.add_argument("--dynamic-metadata-dir", default="", help="Path to metadata *_meta.json directory.")
    parser.add_argument("--dynamic-output-file", default="", help="Output JSON path for dynamic rerank results.")
    parser.add_argument("--dynamic-evidence-dir", default="", help="Directory for per-bug runtime evidence JSON.")
    parser.add_argument("--dynamic-data-output-file", default="", help="Output JSON path for collected dynamic failure data.")
    parser.add_argument("--dynamic-data-dir", default="", help="Directory for per-bug collected dynamic failure data.")
    parser.add_argument("--dynamic-bug-id", default="", help="Optional comma-separated bug ids to collect/rerank, e.g. A.2,B__...")
    parser.add_argument("--dynamic-no-rerun", action="store_true", help="Disable test rerun and use stored failure output only.")
    parser.add_argument("--dynamic-use-stack", action="store_true", default=True, help="Use stack-like lines as crash evidence.")
    parser.add_argument("--dynamic-no-stack", action="store_true", help="Disable stack evidence.")
    parser.add_argument("--dynamic-use-hit-order", action="store_true", help="Use candidate last-hit order evidence when available.")
    parser.add_argument("--dynamic-use-hotness", action="store_true", help="Use candidate hit-count evidence when available.")
    parser.add_argument("--dynamic-use-gdb", action="store_true", help="Attempt debugger-backed collection when executable resolution is supported.")
    parser.add_argument("--dynamic-candidate-limit", type=int, default=100, help="Top Tarantula failed-covered functions to consider for tracing.")
    parser.add_argument("--dynamic-timeout", type=int, default=60, help="Timeout seconds for each rerun failed test.")
    parser.add_argument("--dynamic-min-evidence-quality", type=float, default=0.10, help="Fallback to Tarantula below this evidence quality.")


def config_from_args(args: argparse.Namespace) -> DynamicRerankConfig:
    return DynamicRerankConfig(
        dataset=args.dynamic_dataset,
        results_file=args.dynamic_results_file,
        metadata_dir=args.dynamic_metadata_dir,
        output_file=args.dynamic_output_file,
        evidence_dir=args.dynamic_evidence_dir,
        data_output_file=args.dynamic_data_output_file,
        data_dir=args.dynamic_data_dir,
        bug_id_filter=args.dynamic_bug_id,
        rerun=not args.dynamic_no_rerun,
        use_stack=(args.dynamic_use_stack and not args.dynamic_no_stack),
        use_hit_order=args.dynamic_use_hit_order,
        use_hotness=args.dynamic_use_hotness,
        use_gdb=args.dynamic_use_gdb,
        candidate_limit=args.dynamic_candidate_limit,
        timeout_seconds=args.dynamic_timeout,
        min_evidence_quality=args.dynamic_min_evidence_quality,
    )
