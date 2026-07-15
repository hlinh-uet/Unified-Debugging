import json
import os
import re
from typing import Any, Optional, Tuple

from data_loaders.base_loader import BugRecord

from core.apr.artifacts import write_llm_step_artifact
from core.apr.llm import call_llm


# =============================================================================
# Cấu hình giới hạn prompt
# =============================================================================

# Giới hạn ký tự mặc định cho các trường text khi đưa vào prompt.
MAX_TEXT_FIELD_CHARS = 4000

# Giới hạn kích thước metadata JSON cuối cùng được nhúng vào prompt.
MAX_METADATA_CHARS = 18000

# Giới hạn ký tự cho một đoạn trích source của test case.
MAX_TEST_CASE_SOURCE_CHARS = 2400

# Giới hạn số dòng source test case được giữ trong một excerpt.
MAX_SOURCE_EXCERPT_LINES = 24


# =============================================================================
# Prompt và regex tín hiệu
# =============================================================================

# System prompt cho LLM: chỉ tóm tắt evidence lỗi, không tự phân loại/root-cause/đề xuất code.
FAIL_CONTEXT_SYSTEM_PROMPT = (
    "You are a security test-failure evidence summarizer for program repair. "
    "Read failed-test metadata from the buggy version and return concise structured evidence. "
    "Do not classify into a fixed failure taxonomy, infer root cause, propose a patch, or output code."
)

# Regex nhận diện các dòng có tín hiệu lỗi trong actual_output/fail_reason.
FAILURE_SIGNAL_RE = re.compile(
    r"AddressSanitizer|UndefinedBehaviorSanitizer|LeakSanitizer|ThreadSanitizer|"
    r"DEADLYSIGNAL|ERROR:|SUMMARY:|Segmentation fault|runtime error|"
    r"\bFailure\b|\bActual:|\bExpected:|\bWhich is:|"
    r"\[\s*FAILED\s*\]|FAILED TEST SUMMARY|^FAIL\b|TEST FAILED|exit_code=",
    re.IGNORECASE,
)

# Regex nhận diện các dòng đáng giữ trong expected_output dài.
EXPECTED_SIGNAL_RE = re.compile(
    r"\[\||invalid|bad|truncated|malformed|overflow|underflow|"
    r"AddressSanitizer|ERROR:|SUMMARY:|exception|length|parse|validate",
    re.IGNORECASE,
)

# Regex nhận diện các dòng source test có assertion hoặc input xử lý quan trọng.
SOURCE_SIGNAL_RE = re.compile(
    r"EXPECT_|ASSERT_|ck_assert|assert\(|fail_unless|fail_if|"
    r"failure|error|parse|format|validate",
    re.IGNORECASE,
)


# =============================================================================
# Nhóm 1: Lấy thông tin từ raw metadata
# =============================================================================

# Đọc toàn bộ thông tin thô cần cho fail-context từ BugRecord/raw metadata:
# project_info, failed tests, và test-info được index theo test_id.
def _read_raw_fail_context(bug: Optional[BugRecord]) -> dict:
    if not bug:
        return {
            "project_info": {"dataset_name": "", "language": ""},
            "failed_tests": [],
            "test_info_by_id": {},
        }

    raw = bug.raw if isinstance(bug.raw, dict) else {}
    source_ext = os.path.splitext(bug.source_file or "")[1].lower()
    if source_ext == ".c":
        source_language = "C"
    elif source_ext in (".cc", ".cpp", ".cxx", ".h", ".hh", ".hpp", ".hxx"):
        source_language = "C++"
    else:
        source_language = ""

    metadata_stem = str(raw.get("metadata_stem") or "").strip()
    metadata_file = os.path.abspath(str(raw.get("metadata_file") or ""))
    metadata_dir = os.path.dirname(metadata_file) if metadata_file else ""
    bug_id = str(raw.get("original_bug_id") or raw.get("bug_id") or "").strip()

    failed_tests = []
    seen_failed_test_ids = set()
    for test in bug.tests or []:
        if not isinstance(test, dict):
            continue
        test_id = str(test.get("test_id") or "").strip()
        if not test_id or test_id in seen_failed_test_ids:
            continue
        outcome = str(test.get("outcome") or "").upper()
        outcome_fixed = str(test.get("outcome_fixed") or "").upper()
        if outcome in ("FAIL", "FAILED") and outcome_fixed in ("PASS", "PASSED"):
            failed_tests.append(test)
            seen_failed_test_ids.add(test_id)

    test_info_by_id = {}
    embedded_records = raw.get("failed_test_info")
    if isinstance(embedded_records, list):
        for record in embedded_records:
            if not isinstance(record, dict):
                continue
            test_id = str(record.get("test_id") or "").strip()
            if test_id and test_id not in test_info_by_id:
                test_info_by_id[test_id] = record

    test_info_paths = []
    if metadata_dir and os.path.isdir(metadata_dir):
        data_folder = str(raw.get("data_folder") or raw.get("metadata_slug") or "").strip()
        if data_folder:
            test_info_paths.append(os.path.join(metadata_dir, f"{data_folder}_test_info.json"))
        project = str(raw.get("project") or "").strip()
        if project:
            test_info_paths.append(os.path.join(metadata_dir, f"{project}_test_info.json"))
        for filename in sorted(os.listdir(metadata_dir)):
            if filename.endswith("_test_info.json"):
                test_info_paths.append(os.path.join(metadata_dir, filename))

    seen_paths = set()
    for path in test_info_paths:
        if path in seen_paths or not os.path.isfile(path):
            continue
        seen_paths.add(path)
        try:
            with open(path, "r") as f:
                payload = json.load(f)
        except Exception:
            continue

        for record in payload.get("tests", []) or []:
            if not isinstance(record, dict):
                continue
            record_meta_id = str(record.get("metadata_id") or "").strip()
            record_meta_file = os.path.abspath(str(record.get("metadata_file") or ""))
            record_bug_id = str(record.get("bug_id") or "").strip()

            matched = False
            if metadata_stem and record_meta_id == metadata_stem:
                matched = True
            elif metadata_file and record_meta_file == metadata_file:
                matched = True
            elif bug_id and record_bug_id == bug_id and not metadata_stem:
                matched = True
            if matched:
                test_id = str(record.get("test_id") or "").strip()
                if test_id and test_id not in test_info_by_id:
                    test_info_by_id[test_id] = record

    return {
        "project_info": {
            "dataset_name": raw.get("dataset_name") or bug.dataset,
            "language": raw.get("language") or source_language,
        },
        "failed_tests": failed_tests,
        "test_info_by_id": test_info_by_id,
    }


# =============================================================================
# Nhóm 2: Cắt tỉa và chuẩn hóa dữ liệu đưa vào prompt
# =============================================================================

# Cắt mọi giá trị về chuỗi có giới hạn để prompt không phình quá lớn.
def _clip_text(value: Any, max_chars: int = MAX_TEXT_FIELD_CHARS) -> str:
    text = "" if value is None else str(value)
    text = text.rstrip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"


# Thêm một dòng vào excerpt, bỏ dòng rỗng và tránh lặp dòng giống hệt nhau.
def _append_unique_line(out: list, seen: set, line: str) -> None:
    line = line.rstrip()
    if not line:
        return
    key = line.strip()
    if key in seen:
        return
    out.append(line)
    seen.add(key)


# Tạo excerpt kiểu đầu/cuối khi không tìm được dòng tín hiệu cụ thể.
def _head_tail_excerpt(lines: list, head_count: int, tail_count: int) -> list:
    if len(lines) <= head_count + tail_count:
        return lines
    skipped = len(lines) - head_count - tail_count
    return lines[:head_count] + [f"... [skipped {skipped} lines]"] + lines[-tail_count:]


# Tạo excerpt quanh các dòng tín hiệu, có marker cho khoảng dòng bị bỏ qua.
def _window_excerpt(lines: list, indexes: list, before: int, after: int, max_lines: int) -> list:
    out = []
    seen = set()
    last_end = 0
    for index in sorted(set(indexes)):
        start = max(0, index - before)
        end = min(len(lines), index + after + 1)
        if out and start > last_end:
            out.append(f"... [skipped {start - last_end} lines]")
        for line in lines[start:end]:
            _append_unique_line(out, seen, line)
            if len(out) >= max_lines:
                out.append("... [additional signal lines omitted]")
                return out
        last_end = max(last_end, end)
    return out


# Trích actual_output/fail_reason theo các dòng khớp regex tín hiệu; fallback sang đầu/cuối.
def _signal_excerpt(
    value: Any,
    *,
    signal_re: re.Pattern,
    max_chars: int,
    head_count: int = 4,
    tail_count: int = 4,
    context_after: int = 4,
) -> str:
    text = "" if value is None else str(value).rstrip()
    if not text:
        return ""
    if len(text) <= max_chars:
        return text

    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    if not lines:
        return ""

    match_indexes = [idx for idx, line in enumerate(lines) if signal_re.search(line)]
    if match_indexes:
        excerpt_lines = _window_excerpt(
            lines,
            match_indexes,
            before=1,
            after=context_after,
            max_lines=MAX_SOURCE_EXCERPT_LINES,
        )
    else:
        excerpt_lines = _head_tail_excerpt(lines, head_count, tail_count)

    return _clip_text("\n".join(excerpt_lines), max_chars)


# Trích expected_output theo tín hiệu, giữ đầu/cuối để không mất marker quan trọng.
def _expected_output_excerpt(value: Any) -> str:
    text = "" if value is None else str(value).rstrip()
    if not text:
        return ""

    lines = [line.rstrip() for line in text.strip().splitlines() if line.strip()]
    if len(text) <= 1800:
        return text
    if not lines:
        return ""

    out = []
    seen = set()
    for line in lines[:4]:
        _append_unique_line(out, seen, line)
    for idx in [i for i, line in enumerate(lines) if EXPECTED_SIGNAL_RE.search(line)][:10]:
        if out and idx > 0:
            out.append(f"... [signal near expected_output line {idx + 1}]")
        for line in lines[max(0, idx - 1): min(len(lines), idx + 2)]:
            _append_unique_line(out, seen, line)
    if len(lines) > 4:
        out.append("... [expected_output tail]")
    for line in lines[-6:]:
        _append_unique_line(out, seen, line)

    return _clip_text("\n".join(out), 1800)


# Lấy actual/expected/error từ input_summary làm anchor để xếp hạng assertion/literal.
def _summary_anchors(summary: dict) -> list:
    anchors = []
    for key in ("failure_actual", "failure_expected", "failure_error", "failure_which_is"):
        value = summary.get(key)
        if isinstance(value, str):
            text = value.strip()
            if len(text) >= 2:
                anchors.append(text)
        elif isinstance(value, list):
            anchors.extend(str(item).strip() for item in value if len(str(item).strip()) >= 2)
    return anchors


# Xếp hạng list assertion/literal theo mức liên quan tới actual/expected/error.
def _ranked_summary_items(values: Any, *, summary: dict, max_items: int) -> list:
    if not isinstance(values, list):
        return []

    anchors = _summary_anchors(summary)
    ranked = []
    for index, item in enumerate(values):
        text = str(item)
        lowered = text.lower()
        score = 0
        for anchor in anchors:
            if anchor and anchor.lower() in lowered:
                score += 4
        if SOURCE_SIGNAL_RE.search(text):
            score += 3
        if any(token in lowered for token in ("actual", "expected", "error", "fail")):
            score += 2
        ranked.append((-score, index, item))

    selected = [item for _, _, item in sorted(ranked)[:max_items]]
    out = [_clip_text(item, 1200) for item in selected]
    if len(values) > max_items:
        out.append(f"...(+{len(values) - max_items} lower-signal item(s))")
    return out


# Tạo đoạn trích source test case quanh failure line, assertion, hoặc literal liên quan.
def _source_excerpt(record: dict) -> str:
    source = record.get("test_case_source", "") if isinstance(record, dict) else ""
    text = "" if source is None else str(source).strip()
    if not text:
        return ""
    lines = [line.rstrip() for line in text.splitlines()]
    if len(lines) <= MAX_SOURCE_EXCERPT_LINES:
        return _clip_text("\n".join(lines), MAX_TEST_CASE_SOURCE_CHARS)

    summary = record.get("input_summary") if isinstance(record, dict) else {}
    summary = summary if isinstance(summary, dict) else {}
    anchors = _summary_anchors(summary)
    match_indexes = []

    try:
        failure_line = int(record.get("failure_line") or 0)
        start_line = int(record.get("test_case_line_start") or 0)
    except (TypeError, ValueError):
        failure_line = 0
        start_line = 0
    if failure_line and start_line:
        relative_index = failure_line - start_line
        if 0 <= relative_index < len(lines):
            match_indexes.append(relative_index)

    for idx, line in enumerate(lines):
        if SOURCE_SIGNAL_RE.search(line):
            match_indexes.append(idx)
            continue
        lowered = line.lower()
        if any(anchor.lower() in lowered for anchor in anchors):
            match_indexes.append(idx)

    if match_indexes:
        excerpt = _window_excerpt(
            lines,
            match_indexes,
            before=2,
            after=3,
            max_lines=MAX_SOURCE_EXCERPT_LINES,
        )
    else:
        excerpt = _head_tail_excerpt(
            lines,
            MAX_SOURCE_EXCERPT_LINES // 2,
            MAX_SOURCE_EXCERPT_LINES // 2,
        )
    return _clip_text("\n".join(excerpt), MAX_TEST_CASE_SOURCE_CHARS)


# Làm sạch input_summary: chỉ giữ assertion, literal và giá trị actual/expected quan trọng.
def _safe_input_summary(summary: Any) -> dict:
    if not isinstance(summary, dict):
        return {}
    safe = {}
    keep_keys = (
        "assertions",
        "string_literals",
        "failure_actual",
        "failure_expected",
    )
    for key in keep_keys:
        value = summary.get(key)
        if isinstance(value, str):
            safe[key] = _clip_text(value)
        elif isinstance(value, list):
            item_limit = 20 if key == "string_literals" else 12
            safe[key] = _ranked_summary_items(value, summary=summary, max_items=item_limit)
        elif isinstance(value, dict):
            safe[key] = json.loads(json.dumps(value, ensure_ascii=False, default=str))
        else:
            safe[key] = value
    return {key: value for key, value in safe.items() if value not in (None, "", [], {})}


# Chuẩn hóa một failed test thành schema tests[]: test_id, input, output, fail_reason.
def _safe_test_metadata(test: dict, test_info: Optional[dict] = None) -> dict:
    test = test or {}
    test_info = test_info or {}
    input_payload = {
        "test_case_source_excerpt": _source_excerpt(test_info),
        "input_summary": _safe_input_summary(test_info.get("input_summary")),
    }
    output_payload = {
        "actual_output": _signal_excerpt(
            test.get("actual_output"),
            signal_re=FAILURE_SIGNAL_RE,
            max_chars=1800,
        ),
        "expected_output": _expected_output_excerpt(test.get("expected_output")),
    }
    safe = {
        "test_id": test.get("test_id"),
        "input": {
            key: value
            for key, value in input_payload.items()
            if value not in (None, "", [], {})
        },
        "output": {
            key: value
            for key, value in output_payload.items()
            if value not in (None, "", [], {})
        },
        "fail_reason": _signal_excerpt(
            test.get("fail_reason"),
            signal_re=FAILURE_SIGNAL_RE,
            max_chars=1800,
        ),
    }
    return {key: value for key, value in safe.items() if value not in (None, "", [], {})}


# =============================================================================
# Nhóm 3: Ghép metadata gọn và tạo prompt
# =============================================================================

# Ghép project_info và danh sách tests[] đã được lọc/cắt tỉa để nhúng vào prompt.
def _safe_bug_metadata(bug: Optional[BugRecord]) -> dict:
    raw_context = _read_raw_fail_context(bug)
    test_info_by_id = raw_context["test_info_by_id"]
    tests = []
    for test in raw_context["failed_tests"]:
        test_id = str(test.get("test_id") or "").strip()
        tests.append(_safe_test_metadata(test, test_info_by_id.get(test_id)))
    return {
        "project_info": raw_context["project_info"],
        "tests": tests,
    }


# Tạo prompt hoàn chỉnh cho fail-context LLM agent từ metadata đã làm sạch.
def build_fail_context_prompt(*, bug: Optional[BugRecord]) -> str:
    metadata_json = json.dumps(_safe_bug_metadata(bug), ensure_ascii=False, indent=2, default=str)
    metadata_json = _clip_text(metadata_json, MAX_METADATA_CHARS)
    return f"""TEST FAIL CONTEXT TASK
Summarize the failed-test metadata below into concise context for a repair agent.
Use only project_info and tests[].input/output/fail_reason from the metadata below.
Do not infer facts from fixed-version behavior.
Do not propose a patch.

FAILED-TEST METADATA
BEGIN FAILED-TEST METADATA
{metadata_json}
END FAILED-TEST METADATA

TEST FAIL CONTEXT OUTPUT
Return concise structured notes with exactly these fields:
failure_summary:
test_evidence:
failure_contract:
uncertainties:

Rules:
- Do not output patched code.
- Do not propose a concrete patch or rewrite strategy.
- Keep only information directly supported by failed-test metadata.
- Under failure_summary, write 1-3 bullets describing the raw observed oracle/evidence only.
- Do not assign fixed category labels such as bounds, lifetime, output mismatch, parser bug, or memory-safety bug unless that exact wording appears in metadata.
- Under test_evidence, summarize each distinct failed-test pattern. For each pattern include:
  - test IDs or a grouped test-ID list.
  - observed result from fail_reason, output.actual_output, or input.input_summary.failure_actual: exit code, crash/sanitizer/assertion text, actual value, or actual output excerpt.
  - expected result from output.expected_output, input.input_summary.assertions, or input.input_summary.failure_expected if present: expected value, expected text excerpt, expected successful parse, expected error log, or expected non-null/null condition.
  - concrete test input evidence from input.input_summary and input.test_case_source_excerpt, especially inline C string inputs passed to parsing/formatting APIs.
  - observed_vs_expected: one short sentence comparing actual vs expected when both are available.
- Use input.test_case_source_excerpt, assertions, and string_literals to identify the local test function, inline schema/data/path/string inputs, and checked assertions.
- Under failure_contract, summarize the behavior the failing tests require: expected return value, output text/format, parse/validation result, error handling, exception behavior, state change, or non-crash condition supported by the metadata.
- If output.actual_output is only a generic harness failure, say that explicitly and rely on fail_reason when it contains useful evidence.
- If output.expected_output and input.input_summary.failure_expected are missing or empty, write expected: <not available in metadata>.
- Under uncertainties, list missing or ambiguous failure details instead of inferring them.
- Do not mention covered functions, fault localization, repair strategy, or root cause.
- Only mention input contents that appear explicitly in tests[].input or tests[].output/fail_reason.
- Prefer short grouped summaries over repeating the same failure pattern for many tests.
"""


# =============================================================================
# Nhóm 4: Entry point chạy agent
# =============================================================================

# Gọi LLM fail-context, lưu artifact prompt/response, và trả response cho APR pipeline.
def run_security_fail_context_agent(
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
        step_name="security_fail_context_agent",
        prompt=prompt,
        response=response or "",
        status="generated" if response else "llm_failed",
        error="" if response else "security_fail_context_agent_no_response",
    )
    return response, artifact
