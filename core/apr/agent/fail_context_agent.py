import json
import re
from typing import Any, Optional, Tuple

from data_loaders.base_loader import BugRecord

from core.apr.artifacts import write_llm_step_artifact
from core.apr.config import (
    APR_MAX_FAILURE_SIGNAL_LINE_CHARS,
    APR_MAX_FAILURE_SIGNAL_LINES,
)
from core.apr.llm import call_llm


MAX_TEXT_FIELD_CHARS = 4000
MAX_METADATA_CHARS = 30000
MAX_LIST_ITEMS = 80


FAIL_CONTEXT_SYSTEM_PROMPT = (
    "You are a C/C++ test-failure context agent for program repair. "
    "Read failed-test metadata from the buggy version and return concise structured failure context. "
    "Do not propose a patch and do not output code."
)


def _clip_text(value: Any, max_chars: int = MAX_TEXT_FIELD_CHARS) -> str:
    text = "" if value is None else str(value)
    text = text.rstrip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"


def _bounded_list(values: Any, max_items: int = MAX_LIST_ITEMS) -> list:
    if not isinstance(values, list):
        return []
    if len(values) <= max_items:
        return list(values)
    extra = len(values) - max_items
    return list(values[:max_items]) + [f"...(+{extra} more)"]


def _failure_signal_lines(text: Any) -> list:
    if not text:
        return []

    signal = re.compile(
        r"FAIL|FAILED|ERROR|Failure|Actual|Expected|AddressSanitizer|"
        r"SUMMARY|Segmentation|Assertion|assert|overflow|underflow|invalid|"
        r"not a directory|permission|crash|fatal|warning|SEGV|SIGSEGV|"
        r"NULL|null|heap|stack|use-after-free|buffer",
        re.IGNORECASE,
    )
    lines = []
    for line in str(text).splitlines():
        line = line.strip()
        if not line or not signal.search(line):
            continue
        if len(line) > APR_MAX_FAILURE_SIGNAL_LINE_CHARS:
            line = line[:APR_MAX_FAILURE_SIGNAL_LINE_CHARS].rstrip() + "..."
        lines.append(line)
        if len(lines) >= APR_MAX_FAILURE_SIGNAL_LINES:
            break
    return lines


def _output_summary(value: Any) -> dict:
    text = "" if value is None else str(value)
    raw_lines = text.splitlines()
    nonempty = [line.rstrip() for line in raw_lines if line.strip()]
    excerpt = nonempty[:4]
    if len(nonempty) > 8:
        excerpt += [f"... [skipped {len(nonempty) - 8} output lines]"]
    if len(nonempty) > 4:
        excerpt += nonempty[-4:]
    return {
        "line_count": len(raw_lines),
        "nonempty_line_count": len(nonempty),
        "signal_lines": _failure_signal_lines(text),
        "excerpt": [_clip_text(line, APR_MAX_FAILURE_SIGNAL_LINE_CHARS) for line in excerpt],
    }


def _failed_tests(tests: list) -> list:
    seen = set()
    out = []
    for test in tests or []:
        if not isinstance(test, dict):
            continue
        tid = str(test.get("test_id") or "").strip()
        if not tid or tid in seen:
            continue
        if str(test.get("outcome") or "").upper() in ("FAIL", "FAILED"):
            out.append(test)
            seen.add(tid)
    return out


def _safe_test_metadata(test: dict) -> dict:
    safe = {}
    for key, value in (test or {}).items():
        key_lc = str(key).lower()
        if "fixed" in key_lc:
            continue
        if key in ("covered_methods",):
            continue
        if key == "actual_output":
            safe["actual_output_summary"] = _output_summary(value)
            continue
        if key == "expected_output":
            safe["expected_output_summary"] = _output_summary(value)
            continue
        if key in ("covered_functions",):
            continue
        if isinstance(value, str):
            safe[key] = _clip_text(value)
        elif isinstance(value, list):
            safe[key] = _bounded_list(value)
        elif isinstance(value, dict):
            safe[key] = json.loads(json.dumps(value, ensure_ascii=False, default=str))
        else:
            safe[key] = value
    return safe


def _safe_bug_metadata(bug: Optional[BugRecord]) -> dict:
    if not bug:
        return {"bug_id": "", "dataset": "", "failed_tests": []}

    raw = bug.raw if isinstance(bug.raw, dict) else {}
    metadata = {
        "bug_id": bug.bug_id,
        "dataset": bug.dataset,
        "cve": raw.get("cve"),
        "type_name": raw.get("type_name"),
        "project": raw.get("project"),
        "language": raw.get("language"),
        "source_basename": raw.get("source_basename"),
        "test_cmd_template": raw.get("test_cmd_template") or bug.test_cmd_template,
        "failed_tests": [_safe_test_metadata(test) for test in _failed_tests(bug.tests)],
    }
    return {key: value for key, value in metadata.items() if value not in (None, "", [], {})}


def build_fail_context_prompt(*, bug: Optional[BugRecord]) -> str:
    metadata_json = json.dumps(_safe_bug_metadata(bug), ensure_ascii=False, indent=2, default=str)
    metadata_json = _clip_text(metadata_json, MAX_METADATA_CHARS)
    return f"""TEST FAIL CONTEXT TASK
Summarize the failed-test metadata below into concise context for a repair agent.
Use only the provided buggy-version test metadata. Do not infer facts from fixed-version behavior.
Do not propose a patch.

FAILED-TEST METADATA
BEGIN FAILED-TEST METADATA
{metadata_json}
END FAILED-TEST METADATA

TEST FAIL CONTEXT OUTPUT
Return concise structured notes with exactly these fields:
failure_summary:
test_evidence:

Rules:
- Do not output patched code.
- Do not propose a concrete patch or rewrite strategy.
- Keep only information directly supported by failed-test metadata.
- Under failure_summary, write 1-3 bullets summarizing the observed failure class, such as crash, assertion mismatch, wrong text output, exit-code failure, sanitizer report, or test harness error.
- Under test_evidence, summarize each distinct failed-test pattern. For each pattern include:
  - test IDs or a grouped test-ID list.
  - observed result from fail_reason and actual_output_summary: exit code, crash/sanitizer/assertion text, actual value, or actual output excerpt.
  - expected result from expected_output_summary if present: expected value, expected text excerpt, or expected successful/truncated output.
  - observed_vs_expected: one short sentence comparing actual vs expected when both are available.
- If actual_output_summary is only a generic harness failure, say that explicitly and rely on fail_reason/expected_output_summary only when they contain useful evidence.
- If expected_output_summary is missing or empty, write expected: <not available in metadata>.
- Do not mention covered functions, fault localization, repair strategy, root cause, or input contents unless they appear explicitly in the failed-test metadata.
- Prefer short grouped summaries over repeating the same failure pattern for many tests.
"""


def run_fail_context_agent(
    *,
    bug: Optional[BugRecord],
    bug_id: str,
    llm_provider: Optional[str],
) -> Tuple[Optional[str], dict]:
    prompt = build_fail_context_prompt(bug=bug)
    response = call_llm(
        prompt,
        provider=llm_provider,
        system_prompt=FAIL_CONTEXT_SYSTEM_PROMPT,
    )
    artifact = write_llm_step_artifact(
        bug_id=bug_id,
        attempt_index=0,
        qualified_name="test_fail_context",
        candidate_relpath="",
        llm_provider=llm_provider,
        step_name="fail_context_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "fail_context_agent_no_response",
    )
    return response, artifact
