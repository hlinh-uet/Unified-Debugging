import os
import json
import re
import shutil
import time
from typing import Optional
import requests
from dotenv import load_dotenv

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR, LLM_PATCHES_DIR
from data_loaders.base_loader import get_loader, BugRecord
from data_loaders.sandbox_adapter import get_sandbox_adapter, defects4c_docker_ready
from core.utils import (
    extract_function_code,
    normalize_code_for_edit_distance,
    parse_sbfl_qualified_name,
    replace_source_range_bytes,
    resolve_fl_candidate_source_path,
    source_byte_range_to_char_range,
)

load_dotenv()

# Provider mặc định – đọc từ .env, có thể override qua CLI
_DEFAULT_LLM_PROVIDER = os.getenv("LLM_PROVIDER", "openrouter").strip().lower()
APR_TOP_K = int(os.getenv("APR_TOP_K", "3"))
# Giới hạn độ dài source đưa vào prompt.
APR_MAX_SOURCE_CHARS = int(os.getenv("APR_MAX_SOURCE_CHARS", "30000"))
# Giới hạn số test id được lưu vào apr_results.json.
APR_MAX_TEST_ID_STORE = int(os.getenv("APR_MAX_TEST_ID_STORE", "50"))
APR_MAX_FAILURE_SIGNAL_LINES = int(os.getenv("APR_MAX_FAILURE_SIGNAL_LINES", "20"))
APR_MAX_FAILURE_SIGNAL_LINE_CHARS = int(os.getenv("APR_MAX_FAILURE_SIGNAL_LINE_CHARS", "300"))
# Mặc định resume APR theo kiểu append-only: bug nào đã có record thì bỏ qua.
APR_SKIP_EXISTING = os.getenv("APR_SKIP_EXISTING", "1").strip().lower() not in ("0", "false", "no")
# Prompt
APR_REPAIR_SYSTEM_PROMPT = (
    "You are a professional C/C++ repair agent. Return ONLY the raw fixed C/C++ code. "
    "No markdown, no explanation, no backticks."
)


def _is_defects4c_dataset(dataset: str) -> bool:
    return (dataset or "").strip().lower() != "codeflaws"


def _source_language_from_path(path: str) -> str:
    ext = os.path.splitext(path or "")[1].lower()
    return "cpp" if ext in (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".h") else "c"


def _extract_chat_message_content(message) -> Optional[str]:
    if not isinstance(message, dict):
        return None

    content = message.get("content")
    if isinstance(content, str):
        return content

    if isinstance(content, list):
        text_parts = []
        for part in content:
            if isinstance(part, str):
                text_parts.append(part)
            elif isinstance(part, dict):
                part_text = part.get("text") or part.get("content")
                if isinstance(part_text, str):
                    text_parts.append(part_text)
        if text_parts:
            return "".join(text_parts)

    return None


def _is_transient_llm_error(code=None, metadata=None) -> bool:
    if code in (408, 409, 425, 429, 500, 502, 503, 504):
        return True
    error_type = ""
    if isinstance(metadata, dict):
        error_type = str(metadata.get("error_type") or "").lower()
    return error_type in {
        "provider_unavailable",
        "rate_limit_exceeded",
        "timeout",
        "server_error",
        "overloaded",
    }


# ---------------------------------------------------------------------------
# LLM – provider-specific helpers
# ---------------------------------------------------------------------------

def _call_openai(prompt: str, model: str = "gpt-4o-mini") -> Optional[str]:
    return _call_openai_compatible_chat(
        prompt,
        provider_label="OpenAI",
        api_key=os.getenv("OPENAI_API_KEY"),
        missing_key_message="OPENAI_API_KEY chưa được đặt trong .env.",
        base_url=os.getenv("OPENAI_BASE_URL", "https://api.openai.com/v1"),
        model=model,
    )


def _call_openrouter(prompt: str, model: str = "qwen/qwen3-coder-30b-a3b-instruct") -> Optional[str]:
    return _call_openai_compatible_chat(
        prompt,
        provider_label="OpenRouter",
        api_key=os.getenv("OPENROUTER_API_KEY"),
        missing_key_message="Không tìm thấy OPENROUTER_API_KEY trong môi trường.",
        base_url=os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1"),
        model=model,
        extra_headers={
            "HTTP-Referer": os.getenv("OPENROUTER_SITE_URL", "http://localhost:3000"),
            "X-Title": os.getenv("OPENROUTER_APP_NAME", "UET_APR_Research"),
        },
    )


def _call_openai_compatible_chat(
    prompt: str,
    *,
    provider_label: str,
    api_key: Optional[str],
    missing_key_message: str,
    base_url: str,
    model: str,
    extra_headers: Optional[dict] = None,
) -> Optional[str]:
    try:
        if not api_key:
            print(f"[LLM] LỖI: {missing_key_message}")
            return None

        url = f"{base_url.rstrip('/')}/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
        }
        if extra_headers:
            headers.update(extra_headers)

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system", 
                    "content": APR_REPAIR_SYSTEM_PROMPT
                },
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1,
            "max_tokens": int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "12000")),
        }

        timeout = int(os.getenv("LLM_REQUEST_TIMEOUT", "120"))
        retries = int(os.getenv("LLM_RETRIES", "3"))
        for attempt in range(1, retries + 1):
            try:
                response = requests.post(url, headers=headers, json=payload, timeout=timeout)
            except requests.exceptions.RequestException as exc:
                if attempt >= retries:
                    raise
                sleep_s = min(2 ** attempt, 15)
                print(
                    f"[LLM] {provider_label} lỗi kết nối lần {attempt}/{retries}: {exc}. "
                    f"Thử lại sau {sleep_s}s..."
                )
                time.sleep(sleep_s)
                continue

            if response.status_code != 200:
                if _is_transient_llm_error(response.status_code) and attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} HTTP {response.status_code} lần {attempt}/{retries}. "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(f"[LLM] Error {response.status_code}: {response.text[:1000]}")
                return None

            try:
                result = response.json()
            except ValueError as exc:
                print(f"[LLM] {provider_label} trả về JSON không hợp lệ: {exc}")
                return None

            choices = result.get("choices") or []
            if not choices:
                print(f"[LLM] {provider_label} response không có choices: {response.text[:1000]}")
                return None

            choice = choices[0] or {}
            choice_error = choice.get("error") or result.get("error")
            if choice_error:
                error_code = choice_error.get("code") if isinstance(choice_error, dict) else None
                try:
                    transient_code = int(error_code)
                except (TypeError, ValueError):
                    transient_code = None
                metadata = choice_error.get("metadata") if isinstance(choice_error, dict) else None
                message = choice_error.get("message") if isinstance(choice_error, dict) else str(choice_error)
                if _is_transient_llm_error(transient_code, metadata) and attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} provider lỗi {error_code} lần {attempt}/{retries}: {message}. "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(f"[LLM] {provider_label} provider error {error_code}: {message}")
                return None

            message = choice.get("message") or {}
            raw_content = _extract_chat_message_content(message)
            if raw_content is None:
                finish_reason = choice.get("finish_reason")
                reasoning = message.get("reasoning")
                reasoning_len = len(reasoning) if isinstance(reasoning, str) else 0
                if attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} trả về content=null lần {attempt}/{retries} "
                        f"(finish_reason={finish_reason}, reasoning_len={reasoning_len}). "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(
                    f"[LLM] {provider_label} không trả về code content "
                    f"(finish_reason={finish_reason}, reasoning_len={reasoning_len})."
                )
                return None

            if not raw_content.strip():
                if attempt < retries:
                    sleep_s = min(2 ** attempt, 15)
                    print(
                        f"[LLM] {provider_label} trả về content rỗng lần {attempt}/{retries}. "
                        f"Thử lại sau {sleep_s}s..."
                    )
                    time.sleep(sleep_s)
                    continue
                print(f"[LLM] {provider_label} trả về content rỗng.")
                return None

            return raw_content

        return None

    except Exception as e:
        print(f"[LLM] Exception khi gọi {provider_label}: {e}")
        return None


def call_llm(prompt: str, provider: Optional[str] = None) -> Optional[str]:
    """
    Gọi LLM để sinh bản vá.

    Args:
        prompt:   Nội dung prompt gửi đến LLM.
        provider: 'openai' | 'openrouter'.
                  Nếu None, đọc từ biến môi trường LLM_PROVIDER.

    Returns:
        Chuỗi mã nguồn do LLM trả về, hoặc None nếu lỗi.
    """
    chosen = (provider or _DEFAULT_LLM_PROVIDER).strip().lower()

    if chosen == "openai":
        openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        print(f"[LLM] Provider: OpenAI ({openai_model})")
        return _call_openai(prompt, model=openai_model)

    if chosen == "openrouter":
        openrouter_model = os.getenv("OPENROUTER_MODEL", "qwen/qwen3-coder-30b-a3b-instruct")
        print(f"[LLM] Provider: OpenRouter ({openrouter_model})")
        return _call_openrouter(prompt, model=openrouter_model)

    print(f"[LLM] Warning: Provider không hỗ trợ '{chosen}'. Chọn 'openai' hoặc 'openrouter'.")
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_patch(patched_file_path: str, bug_id: str, dataset: str = "codeflaws",
                   src_basename: Optional[str] = None,
                   src_relpath: Optional[str] = None):
    """Sử dụng Sandbox Adapter để kiểm chứng bản vá.

    ``src_relpath`` cho Defects4C biết chính xác file nào trong buggy version
    cần thay thế. ``src_basename`` chỉ còn dùng cho adapter cũ/tên hiển thị.
    """
    print(f"[APR] Validating patch cho {bug_id} với adapter '{dataset}'...")
    validate_patch.last_details = {}
    try:
        adapter = get_sandbox_adapter(dataset, bug_id)
        result = adapter.validate(
            patched_file_path,
            src_basename=src_basename,
            src_relpath=src_relpath,
        )
        validate_patch.last_details = getattr(adapter, "last_validation_details", {}) or {}
        return result
    except Exception as e:
        print(f"    [Error] Không thể validate: {e}")
        validate_patch.last_details = {
            "validation_error": f"validate_exception:{e}",
            "full_post_passed_tests": [],
            "full_post_failed_tests": [],
            "effective_post_passed_tests": [],
            "effective_post_failed_tests": [],
            "fixed_fail_excluded_tests": [],
        }
        return False, [], []


validate_patch.last_details = {}


def _candidate_relpath_from_buggy_tree(candidate_path: str, raw_meta: Optional[dict]) -> str:
    if not candidate_path or not raw_meta:
        return ""
    buggy_tree_dir = raw_meta.get("buggy_tree_dir") or ""
    if not buggy_tree_dir:
        return ""
    try:
        rel = os.path.relpath(candidate_path, buggy_tree_dir).replace(os.sep, "/")
    except ValueError:
        return ""
    if rel.startswith("../") or rel == ".." or os.path.isabs(rel):
        return ""
    return rel


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def _trim_source_for_prompt(source_code: str, start_idx: int, end_idx: int) -> str:
    """
    Rút gọn source đưa vào prompt khi file quá dài.

    Giữ phần đầu file (includes, typedef, hằng số) + neighborhood
    quanh hàm lỗi (để LLM thấy struct & macro liên quan). Đệm bằng comment
    "... [source truncated] ..." để LLM biết có cắt bỏ.
    """
    start_char, end_char = source_byte_range_to_char_range(source_code, start_idx, end_idx)
    if len(source_code) <= APR_MAX_SOURCE_CHARS or start_char < 0 or end_char < 0:
        return source_code

    head_budget = min(6000, APR_MAX_SOURCE_CHARS // 4)
    remaining   = APR_MAX_SOURCE_CHARS - head_budget
    neighborhood = max(2000, remaining // 2)

    head = source_code[:head_budget]
    func_lo = max(head_budget, start_char - neighborhood)
    func_hi = min(len(source_code), end_char + neighborhood)
    middle_skipped = func_lo > head_budget
    tail_skipped   = func_hi < len(source_code)

    parts = [head]
    if middle_skipped:
        parts.append("\n\n/* ... [source truncated – prelude shown above] ... */\n\n")
    parts.append(source_code[func_lo:func_hi])
    if tail_skipped:
        parts.append("\n\n/* ... [source truncated – tail omitted] ... */\n")
    return "".join(parts)


def _compact_test_list(test_ids):
    """
    Giới hạn số test IDs lưu vào JSON để tránh phình file (Defects4C có >400 test).
    Trả về list; nếu vượt giới hạn, giữ N đầu + marker "...(+K more)".
    """
    if not test_ids or APR_MAX_TEST_ID_STORE <= 0 or len(test_ids) <= APR_MAX_TEST_ID_STORE:
        return list(test_ids) if test_ids else []
    extra = len(test_ids) - APR_MAX_TEST_ID_STORE
    return list(test_ids[:APR_MAX_TEST_ID_STORE]) + [f"...(+{extra} more)"]


def _dedup_initial_test_ids(tests):
    """
    Return unique initial passed/failed test IDs.

    Metadata can contain duplicate rows for the same test case when a project
    runner reports parameterized/typed cases under the same external test ID.
    Treat a duplicated ID as failed if any row failed; otherwise passed once.
    """
    status_by_id = {}
    order = []
    for test in tests or []:
        if not isinstance(test, dict):
            continue
        tid = str(test.get("test_id") or "").strip()
        if not tid:
            continue
        if tid not in status_by_id:
            status_by_id[tid] = "PASS"
            order.append(tid)
        outcome = str(test.get("outcome") or "").upper()
        if outcome in ("FAIL", "FAILED"):
            status_by_id[tid] = "FAIL"
        elif outcome in ("PASS", "PASSED") and status_by_id.get(tid) != "FAIL":
            status_by_id[tid] = "PASS"

    failed = [tid for tid in order if status_by_id.get(tid) == "FAIL"]
    passed = [tid for tid in order if status_by_id.get(tid) == "PASS"]
    return passed, failed


def _failure_signal_lines(text: object) -> list:
    """Extract concise failure lines from actual output for APR prompt context."""
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


def _build_failed_test_context(bug: BugRecord) -> str:
    """Tóm tắt toàn bộ failed tests từ BugRecord (không đọc lại disk)."""
    seen = set()
    failed_tests = []
    for test in bug.tests:
        tid = str(test.get("test_id") or "").strip()
        if not tid or tid in seen:
            continue
        if str(test.get("outcome") or "").upper() in ("FAIL", "FAILED"):
            failed_tests.append(test)
            seen.add(tid)
    if not failed_tests:
        return "FAILED TESTS AND RUNTIME SIGNALS\nNo failed test details are available in metadata.\n"

    lines = [
        "FAILED TESTS AND RUNTIME SIGNALS",
    ]
    for idx, tc in enumerate(failed_tests, start=1):
        tc_name = str(tc.get("test_id") or "Unknown").strip()
        tc_reason = str(tc.get("fail_reason") or "Unknown").strip()
        lines.append(f"{idx}. test_id: {tc_name}")
        lines.append(f"   fail_reason: {tc_reason}")
        signal_lines = _failure_signal_lines(tc.get("actual_output", ""))
        if signal_lines:
            lines.append("   actual_output_signal_lines:")
            for signal_line in signal_lines:
                lines.append(f"   - {signal_line}")

    return "\n".join(lines) + "\n"


def _safe_artifact_part(value: object, max_len: int = 120) -> str:
    text = str(value or "").strip()
    text = re.sub(r"[^A-Za-z0-9._-]+", "_", text)
    text = text.strip("._-")
    return (text or "unknown")[:max_len]


def _rel_experiment_path(path: str) -> str:
    try:
        return os.path.relpath(path, EXPERIMENTS_DIR)
    except ValueError:
        return path


def _write_llm_patch_artifact(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    llm_provider: Optional[str],
    raw_patch: str,
    patched_function: str,
    patched_file: Optional[str] = None,
    status: str = "generated",
    validation_error: str = "",
) -> dict:
    """Luu patch LLM sinh ra de trace/debug, ke ca khi validate fail."""
    bug_part = _safe_artifact_part(bug_id, 80)
    bug_dir = os.path.join(LLM_PATCHES_DIR, bug_part)
    os.makedirs(bug_dir, exist_ok=True)
    func_part = _safe_artifact_part(qualified_name, 140)
    base_name = f"{attempt_index:02d}__{func_part}"

    response_path = os.path.join(bug_dir, f"{base_name}.response.txt")
    function_path = os.path.join(bug_dir, f"{base_name}.function.c")
    patched_file_path = os.path.join(bug_dir, f"{base_name}.patched.c")
    metadata_path = os.path.join(bug_dir, f"{base_name}.json")

    with open(response_path, "w") as f:
        f.write(raw_patch or "")
    with open(function_path, "w") as f:
        f.write(patched_function or "")

    artifact = {
        "bug_id": bug_id,
        "attempt_index": attempt_index,
        "function": qualified_name,
        "repair_target_relpath": candidate_relpath,
        "llm_provider": llm_provider or _DEFAULT_LLM_PROVIDER,
        "status": status,
        "validation_error": validation_error,
        "artifact_dir": _rel_experiment_path(bug_dir),
        "llm_response_path": _rel_experiment_path(response_path),
        "raw_patch_path": _rel_experiment_path(response_path),
        "patched_function_path": _rel_experiment_path(function_path),
        "patched_file_path": "",
        "metadata_path": _rel_experiment_path(metadata_path),
    }

    if patched_file:
        with open(patched_file_path, "w") as f:
            f.write(patched_file)
        artifact["patched_file_path"] = _rel_experiment_path(patched_file_path)

    with open(metadata_path, "w") as f:
        json.dump(artifact, f, indent=4)

    return artifact


def run_apr_pipeline(dataset: str = "codeflaws", llm_provider: Optional[str] = None):
    """
    Pipeline APR (LLM-based).
    Load dữ liệu qua get_loader() – không đọc lại file JSON thủ công.

    Args:
        dataset:      Tên dataset (mặc định 'codeflaws').
        llm_provider: 'openai' | 'openrouter'.
                      Nếu None, đọc từ LLM_PROVIDER trong .env.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    fl_results_file = os.path.join(EXPERIMENTS_DIR, "fault_localization_results.json")
    if not os.path.exists(fl_results_file):
        print(f"[APR] Lỗi: {fl_results_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(fl_results_file, "r") as f:
        fl_results = json.load(f)

    ds_lc = (dataset or "").lower()
    if _is_defects4c_dataset(ds_lc):
        ok_d, info_d = defects4c_docker_ready(dataset)
        if not ok_d:
            print(f"[APR] {info_d}")
            print("[APR] Dừng sớm — không gọi LLM khi chưa validate được trên Docker.")
            return
        os.environ["DEFECTS4C_CONTAINER"] = info_d
        print(f"[APR] Defects4C: dùng container '{info_d}' để validate patch.")

    # Load toàn bộ bug records một lần duy nhất → dùng chung cho FL context
    print(f"[APR] Đang load bug records từ dataset '{dataset}'...")
    loader  = get_loader(dataset)
    bug_map = {b.bug_id: b for b in loader.load_all()}
    dataset_key = (dataset or "").strip().lower()
    filtered_fl_results = {}
    skipped_other_dataset = 0
    skipped_missing_bug = 0
    for bug_id, result_data in fl_results.items():
        result_dataset = ""
        if isinstance(result_data, dict):
            result_dataset = str(result_data.get("dataset") or "").strip().lower()
        if result_dataset and result_dataset != dataset_key:
            skipped_other_dataset += 1
            continue
        if bug_id not in bug_map:
            skipped_missing_bug += 1
            continue
        filtered_fl_results[bug_id] = result_data
    fl_results = filtered_fl_results
    if skipped_other_dataset or skipped_missing_bug:
        print(
            f"[APR] Bỏ qua {skipped_other_dataset} FL records khác dataset và "
            f"{skipped_missing_bug} records không có trong loader '{dataset}'."
        )

    apr_results = {}
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_results.json")
    if os.path.exists(apr_results_file):
        try:
            with open(apr_results_file, "r") as f:
                apr_results = json.load(f)
        except Exception:
            pass
    apr_results = {
        bug_id: result
        for bug_id, result in apr_results.items()
        if bug_id in bug_map and (
            not isinstance(result, dict)
            or not result.get("dataset")
            or str(result.get("dataset")).strip().lower() == dataset_key
        )
    }

    print("[APR] Đang chạy Automated Program Repair (LLM)...")

    for bug_id, result_data in fl_results.items():
        if bug_id in apr_results:
            if APR_SKIP_EXISTING:
                print(f"[APR] Bỏ qua bug {bug_id} vì đã có record trong apr_results.json.")
                continue
            if apr_results[bug_id].get("status") == "success":
                print(f"[APR] Bỏ qua bug {bug_id} vì đã có status=success.")
                continue

        scores = result_data.get("scores", result_data) if isinstance(result_data, dict) else result_data
        if not scores:
            continue

        sorted_funcs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        top_funcs = sorted_funcs[:APR_TOP_K] if APR_TOP_K > 0 else sorted_funcs
        print(f"[APR] Xử lý bug {bug_id}... (top-{APR_TOP_K if APR_TOP_K > 0 else 'all'})")

        # Lấy source path qua Sandbox Adapter (nhất quán với validation)
        try:
            adapter        = get_sandbox_adapter(dataset, bug_id)
            bug_source_path = adapter.get_source_path()
        except Exception as e:
            print(f"    [Error] Không thể lấy adapter cho {bug_id}: {e}")
            continue

        if not os.path.exists(bug_source_path):
            print(f"    [Skip] File nguồn không tồn tại: {bug_source_path}")
            continue

        primary_base = os.path.basename(bug_source_path)
        _br = bug_map.get(bug_id)
        raw_meta = _br.raw if _br else None
        source_cache: dict = {}

        # Context test từ BugRecord đã load sẵn (không đọc thêm file)
        bug_record = bug_map.get(bug_id)
        failed_tests_context = _build_failed_test_context(bug_record) if bug_record else ""
        init_passed_all, init_failed_all = _dedup_initial_test_ids(
            bug_record.tests if bug_record else []
        )
        init_passed = _compact_test_list(init_passed_all)
        init_failed = _compact_test_list(init_failed_all)

        status        = "skipped"
        patched_func  = None
        patched_source = None   # toàn bộ nội dung file sau khi vá
        repair_target_file = None  # file .c đã vá (để đối chiếu ED)
        target_func   = None
        post_passed   = []
        post_failed   = []
        validation_details = {}
        attempted     = False   # đã thử ít nhất 1 hàm
        llm_attempted = False   # LLM đã thực sự sinh patch ít nhất 1 lần
        llm_patch_attempt_index = 0
        candidate_results = []
        best_candidate = None

        for qualified_name, score in top_funcs:
            if score == 0.0:
                continue

            file_hint, func_name = parse_sbfl_qualified_name(qualified_name)
            if not func_name:
                continue
            if _is_defects4c_dataset(ds_lc) and not file_hint:
                print(f"  - [Skip] FL key thiếu file hint cho dataset nhiều file: {qualified_name}")
                continue

            candidate_path = resolve_fl_candidate_source_path(
                dataset, bug_source_path, file_hint or "", raw_meta
            )
            if not os.path.isfile(candidate_path):
                print(
                    f"  - [Skip] Không tìm thấy file nguồn cho '{qualified_name}': {candidate_path}"
                )
                continue
            if candidate_path not in source_cache:
                with open(candidate_path, "r") as f:
                    source_cache[candidate_path] = f.read()
            source_code = source_cache[candidate_path]
            candidate_relpath = _candidate_relpath_from_buggy_tree(candidate_path, raw_meta)
            cand_base = os.path.basename(candidate_relpath or candidate_path)
            cand_label = candidate_relpath or cand_base

            print(f"  - Kiểm tra hàm '{func_name}' trong {cand_label} (Score: {score:.4f})")
            source_language = _source_language_from_path(candidate_path)
            func_code, start_idx, end_idx = extract_function_code(
                source_code,
                func_name,
                language=source_language,
            )
            if not func_code:
                print(f"    WARNING: Không thể trích xuất hàm {func_name}")
                continue

            target_func = qualified_name
            attempted = True

            prompt_source = _trim_source_for_prompt(source_code, start_idx, end_idx)
            prompt = f"""REPAIR TASK
Bug ID: {bug_id}
Repair only the target C/C++ function below. The defect may be a vulnerability or a general correctness bug.
The target function is the only code that will be replaced by your answer.

TARGET FUNCTION TO FIX
Function name: {func_name}
Source file: {cand_label}
BEGIN TARGET FUNCTION
{func_code}
END TARGET FUNCTION

FAILURE EVIDENCE
The next block may contain failed test IDs, fail reasons. It is observational evidence only and may be incomplete or unavailable.
{failed_tests_context}

SOURCE FILE CONTEXT
BEGIN SOURCE CONTEXT
{prompt_source}
END SOURCE CONTEXT

OUTPUT CONTRACT
1. Output exactly one complete fixed C/C++ definition of function {func_name}.
2. Preserve the existing function signature, coding style, macros, and helper APIs unless the bug fix strictly requires otherwise.
3. Keep the patch minimal and localized to function {func_name}.
4. Do not add includes, new global helpers, main functions, unrelated refactors, or changes outside the target function.
5. Do not include explanations, preface text, markdown, code fences, or backticks.

FIXED FUNCTION
"""

            raw_patch = call_llm(prompt, provider=llm_provider)
            if not raw_patch:
                print("    [ERROR] LLM trả về None. Bỏ qua hàm này.")
                continue

            llm_attempted = True
            candidate_patched_func = raw_patch.strip()
            if "```" in candidate_patched_func or "<fixed_code" in candidate_patched_func.lower():
                print("    [ERROR] LLM trả về markdown/XML wrapper thay vì raw function.")
                candidate_patched_func = ""
            llm_patch_attempt_index += 1
            reparsed_func, _, _ = extract_function_code(
                candidate_patched_func,
                func_name,
                language=source_language,
            )
            if not reparsed_func:
                print("    [ERROR] LLM trả về function không hoàn chỉnh/không parse được. Bỏ qua validate.")
                llm_patch_artifact = _write_llm_patch_artifact(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    llm_provider=llm_provider,
                    raw_patch=raw_patch,
                    patched_function=candidate_patched_func,
                    status="malformed_function",
                    validation_error="malformed_function",
                )
                candidate_results.append({
                    "function": qualified_name,
                    "score": score,
                    "status": "validation_error",
                    "status_scope": "patch_comparison_excluding_fixed_fail_tests",
                    "patch_comparison_status": "failed",
                    "real_status": "failed",
                    "validation_error": "malformed_function",
                    "repair_target_file": candidate_path,
                    "repair_target_relpath": candidate_relpath,
                    "patched_function": candidate_patched_func,
                    "patched_file": "",
                    "llm_patch_artifact": llm_patch_artifact,
                    "post_scope": "full_suite",
                    "post_passed_count": 0,
                    "post_failed_count": 0,
                    "post_passed_tests": [],
                    "post_failed_tests": [],
                    "full_post_passed_count": 0,
                    "full_post_failed_count": 0,
                    "full_post_passed_tests": [],
                    "full_post_failed_tests": [],
                    "patch_comparison_post_passed_count": 0,
                    "patch_comparison_post_failed_count": 0,
                    "patch_comparison_post_passed_tests": [],
                    "patch_comparison_post_failed_tests": [],
                    "fixed_fail_excluded_count": 0,
                    "fixed_fail_excluded_tests": [],
                    "validation_details": {
                        "validation_error": "malformed_function",
                        "full_post_passed_tests": [],
                        "full_post_failed_tests": [],
                        "effective_post_passed_tests": [],
                        "effective_post_failed_tests": [],
                        "fixed_fail_excluded_tests": [],
                    },
                })
                continue
            candidate_patched_func = reparsed_func

            candidate_patched_source = replace_source_range_bytes(
                source_code,
                start_idx,
                end_idx,
                candidate_patched_func,
            )

            # Chặn no-op tuyệt đối. Không bỏ qua chỉ vì normalized code bằng nhau,
            # vì normalizer có thể false-positive khi token C/C++ phụ thuộc whitespace.
            orig_norm = normalize_code_for_edit_distance(func_code)
            patched_norm = normalize_code_for_edit_distance(candidate_patched_func)
            if not patched_norm or candidate_patched_source == source_code:
                print("    [NO-OP] Patch không thay đổi hàm nguồn, bỏ qua candidate này.")
                llm_patch_artifact = _write_llm_patch_artifact(
                    bug_id=bug_id,
                    attempt_index=llm_patch_attempt_index,
                    qualified_name=qualified_name,
                    candidate_relpath=candidate_relpath,
                    llm_provider=llm_provider,
                    raw_patch=raw_patch,
                    patched_function=candidate_patched_func,
                    patched_file=candidate_patched_source,
                    status="no_op",
                    validation_error="no_op",
                )
                candidate_results.append({
                    "function": qualified_name,
                    "score": score,
                    "status": "no_op",
                    "status_scope": "patch_comparison_excluding_fixed_fail_tests",
                    "patch_comparison_status": "failed",
                    "real_status": "failed",
                    "validation_error": "no_op",
                    "repair_target_file": candidate_path,
                    "repair_target_relpath": candidate_relpath,
                    "patched_function": candidate_patched_func,
                    "patched_file": candidate_patched_source,
                    "llm_patch_artifact": llm_patch_artifact,
                    "post_scope": "full_suite",
                    "post_passed_count": 0,
                    "post_failed_count": 0,
                    "post_passed_tests": [],
                    "post_failed_tests": [],
                    "full_post_passed_count": 0,
                    "full_post_failed_count": 0,
                    "full_post_passed_tests": [],
                    "full_post_failed_tests": [],
                    "patch_comparison_post_passed_count": 0,
                    "patch_comparison_post_failed_count": 0,
                    "patch_comparison_post_passed_tests": [],
                    "patch_comparison_post_failed_tests": [],
                    "fixed_fail_excluded_count": 0,
                    "fixed_fail_excluded_tests": [],
                    "validation_details": {
                        "validation_error": "no_op",
                        "full_post_passed_tests": [],
                        "full_post_failed_tests": [],
                        "effective_post_passed_tests": [],
                        "effective_post_failed_tests": [],
                        "fixed_fail_excluded_tests": [],
                    },
                })
                continue
            if patched_norm == orig_norm:
                print("    [WARN] Patch chỉ khác theo normalized diff; vẫn validate để tránh bỏ nhầm.")

            patched_func = candidate_patched_func
            patched_source = candidate_patched_source
            repair_target_file = candidate_path

            safe_cand = cand_label.replace("/", "__").replace(" ", "_")
            tmp_path = os.path.join(EXPERIMENTS_DIR, f"tmp_{bug_id.replace('@', '__')}__{safe_cand}")
            with open(tmp_path, "w") as f:
                f.write(patched_source)

            # Truyền src_basename để Defects4CAdapter biết patch này nhằm file nào
            # (khi FL chỉ ra lỗi ở file phụ khác với file bug chính).
            is_valid, post_passed, post_failed = validate_patch(
                tmp_path,
                bug_id,
                dataset,
                src_basename=cand_base,
                src_relpath=candidate_relpath,
            )
            validation_details = getattr(validate_patch, "last_details", {}) or {}
            validation_error = validation_details.get("validation_error", "")
            full_post_passed = validation_details.get("full_post_passed_tests", post_passed)
            full_post_failed = validation_details.get("full_post_failed_tests", post_failed)
            patch_comparison_post_passed = validation_details.get("effective_post_passed_tests", post_passed)
            patch_comparison_post_failed = validation_details.get("effective_post_failed_tests", post_failed)
            fixed_fail_excluded = validation_details.get("fixed_fail_excluded_tests", [])
            patch_comparison_status = "success" if not patch_comparison_post_failed and not validation_error else "failed"
            real_status = "success" if not full_post_failed and not validation_error else "failed"
            candidate_result = {
                "function": qualified_name,
                "score": score,
                "status": "success" if is_valid else ("validation_error" if validation_error else "failed"),
                "status_scope": "patch_comparison_excluding_fixed_fail_tests",
                "patch_comparison_status": patch_comparison_status,
                "real_status": real_status,
                "validation_error": validation_error,
                "repair_target_file": candidate_path,
                "repair_target_relpath": candidate_relpath,
                "patched_function": candidate_patched_func,
                "patched_file": candidate_patched_source,
                "post_scope": "full_suite",
                "post_passed_count": len(full_post_passed),
                "post_failed_count": len(full_post_failed),
                "post_passed_tests": list(full_post_passed),
                "post_failed_tests": list(full_post_failed),
                "full_post_passed_count": len(full_post_passed),
                "full_post_failed_count": len(full_post_failed),
                "full_post_passed_tests": list(full_post_passed),
                "full_post_failed_tests": list(full_post_failed),
                "patch_comparison_post_passed_count": len(patch_comparison_post_passed),
                "patch_comparison_post_failed_count": len(patch_comparison_post_failed),
                "patch_comparison_post_passed_tests": list(patch_comparison_post_passed),
                "patch_comparison_post_failed_tests": list(patch_comparison_post_failed),
                "fixed_fail_excluded_count": len(fixed_fail_excluded),
                "fixed_fail_excluded_tests": list(fixed_fail_excluded),
                "validation_details": validation_details,
            }
            candidate_result["llm_patch_artifact"] = _write_llm_patch_artifact(
                bug_id=bug_id,
                attempt_index=llm_patch_attempt_index,
                qualified_name=qualified_name,
                candidate_relpath=candidate_relpath,
                llm_provider=llm_provider,
                raw_patch=raw_patch,
                patched_function=candidate_patched_func,
                patched_file=candidate_patched_source,
                status=candidate_result["status"],
                validation_error=validation_error,
            )
            candidate_results.append(candidate_result)

            if is_valid:
                print(f"    [SUCCESS] Bản vá hợp lệ cho {bug_id} trong hàm '{func_name}'!")
                patch_name = f"{bug_id}_patch.c" if cand_base == primary_base else f"{bug_id}_patch__{safe_cand}"
                patch_path = os.path.join(PATCHES_DIR, patch_name)
                os.makedirs(PATCHES_DIR, exist_ok=True)
                try:
                    shutil.move(tmp_path, patch_path)  # dùng move thay rename để an toàn cross-device
                except Exception as e_mv:
                    print(f"    [WARN] Không lưu được patch file: {e_mv}")
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                status = "success"
                best_candidate = candidate_result
                break
            else:
                print(f"    [FAIL] Bản vá không vượt qua kiểm tra.")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        if status != "success" and candidate_results:
            best_candidate = min(
                candidate_results,
                key=lambda c: (
                    1 if c.get("validation_error") else 0,
                    c["patch_comparison_post_failed_count"],
                    -c["patch_comparison_post_passed_count"],
                ),
            )
            patched_func = best_candidate["patched_function"]
            patched_source = best_candidate["patched_file"]
            repair_target_file = best_candidate["repair_target_file"]
            target_func = best_candidate["function"]
            post_passed = best_candidate["post_passed_tests"]
            post_failed = best_candidate["post_failed_tests"]
            validation_details = best_candidate.get("validation_details") or {
                "validation_error": best_candidate.get("validation_error", ""),
                "full_post_passed_tests": best_candidate.get("full_post_passed_tests", post_passed),
                "full_post_failed_tests": best_candidate.get("full_post_failed_tests", post_failed),
                "fixed_fail_excluded_tests": best_candidate.get("fixed_fail_excluded_tests", []),
            }
            print(
                f"    [BEST] Chọn candidate tốt nhất: {target_func} "
                f"(patch_failed={best_candidate['patch_comparison_post_failed_count']}, "
                f"full_failed={best_candidate['full_post_failed_count']})"
            )

        if attempted and status == "skipped":
            # Phân biệt: LLM không bao giờ sinh được patch vs. patch sinh ra nhưng fail test
            status = "failed" if llm_attempted else "llm_failed"

        full_post_passed = validation_details.get("full_post_passed_tests", post_passed)
        full_post_failed = validation_details.get("full_post_failed_tests", post_failed)
        patch_comparison_post_passed = validation_details.get("effective_post_passed_tests", post_passed)
        patch_comparison_post_failed = validation_details.get("effective_post_failed_tests", post_failed)
        fixed_fail_excluded = validation_details.get("fixed_fail_excluded_tests", [])
        validation_error = validation_details.get("validation_error", "")
        patch_comparison_status = (
            "success" if not patch_comparison_post_failed and not validation_error else "failed"
        )
        real_status = "success" if not full_post_failed and not validation_error else "failed"

        apr_results[bug_id] = {
            "dataset":            dataset,
            "status":             status,
            "status_scope":        "patch_comparison_excluding_fixed_fail_tests",
            "patch_comparison_status": patch_comparison_status,
            "real_status":         real_status,
            "patched_function":   patched_func,
            "patched_file":       patched_source,  # toàn bộ nội dung file đã vá (có thể khác file bug chính)
            "llm_patch_artifact": best_candidate.get("llm_patch_artifact") if best_candidate else {},
            "repair_target_file": repair_target_file,
            "repair_target_relpath": _candidate_relpath_from_buggy_tree(repair_target_file or "", raw_meta),
            "selected_function":  target_func,
            "init_passed_count":  len(init_passed_all),
            "init_failed_count":  len(init_failed_all),
            "init_passed_tests":  init_passed,
            "init_failed_tests":  init_failed,
            "post_scope":         "full_suite",
            "post_passed_count":  len(full_post_passed),
            "post_failed_count":  len(full_post_failed),
            "post_passed_tests":  list(full_post_passed),
            "post_failed_tests":  list(full_post_failed),
            "full_post_passed_count": len(full_post_passed),
            "full_post_failed_count": len(full_post_failed),
            "full_post_passed_tests": list(full_post_passed),
            "full_post_failed_tests": list(full_post_failed),
            "patch_comparison_post_passed_count": len(patch_comparison_post_passed),
            "patch_comparison_post_failed_count": len(patch_comparison_post_failed),
            "patch_comparison_post_passed_tests": list(patch_comparison_post_passed),
            "patch_comparison_post_failed_tests": list(patch_comparison_post_failed),
            "fixed_fail_excluded_count": len(fixed_fail_excluded),
            "fixed_fail_excluded_tests": list(fixed_fail_excluded),
            "validation_error": validation_error,
        }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)


if __name__ == "__main__":
    run_apr_pipeline()
