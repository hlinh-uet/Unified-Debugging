import os
import json
import re
import shutil
import subprocess
from typing import Optional
import requests
from dotenv import load_dotenv
from pathlib import Path

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR
from data_loaders.base_loader import get_loader, BugRecord
from data_loaders.sandbox_adapter import get_sandbox_adapter, defects4c_docker_ready
from core.utils import (
    extract_function_code,
    normalize_code_for_edit_distance,
    parse_sbfl_qualified_name,
    replace_source_range_bytes,
    resolve_fl_candidate_source_path,
    source_byte_range_to_char_range,
    get_codeflaws_accepted_cfile,
)

load_dotenv()

# Provider mặc định – đọc từ .env, có thể override qua CLI
_DEFAULT_LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").strip().lower()
APR_TOP_K = int(os.getenv("APR_TOP_K", "3"))
# Giới hạn độ dài source đưa vào prompt. Một số Defects4C project có file lớn,
# vượt context window của nhiều LLM và loãng tín hiệu. Nếu vượt mức này ta
# cắt giữa, giữ phần đầu file (includes/typedef) + neighborhood của hàm lỗi.
APR_MAX_SOURCE_CHARS = int(os.getenv("APR_MAX_SOURCE_CHARS", "30000"))
# Với Defects4C, một bug có hàng trăm test pass – lưu hết vào JSON gây bloat.
APR_MAX_TEST_ID_STORE = int(os.getenv("APR_MAX_TEST_ID_STORE", "50"))


def _is_defects4c_dataset(dataset: str) -> bool:
    return (dataset or "").strip().lower() != "codeflaws"


def _clean_code(raw_content: str) -> str:
    """
    Hàm làm sạch mã nguồn:
    1. Ưu tiên bóc tách nội dung trong thẻ <fixed_code>
    2. Xóa bỏ các ký tự Markdown (```c, ```)
    """
    # ==========================================
    # BƯỚC 1: TÌM VÀ CẮT THẺ XML
    # ==========================================
    # Lệnh re.search này sẽ tìm mọi thứ nằm giữa <fixed_code> và </fixed_code>
    # Cờ `re.DOTALL` cực kỳ quan trọng: Nó cho phép dấu chấm (.) đại diện cho cả ký tự xuống dòng (\n)
    # Nếu không có re.DOTALL, regex sẽ dừng lại ngay ở dòng code đầu tiên.
    xml_match = re.search(r'<fixed_code>\s*(.*?)\s*</fixed_code>', raw_content, re.DOTALL)
    
    if xml_match:
        # Nếu LLM dùng thẻ XML, ta lấy đúng phần ruột bên trong
        content = xml_match.group(1).strip()
    else:
        # Nếu LLM quên dùng thẻ (Fallback), ta lấy toàn bộ chuỗi ban đầu
        content = raw_content.strip()
    
    # ==========================================
    # BƯỚC 2: CẠO SẠCH MARKDOWN CHỐNG GCC BÁO LỖI
    # ==========================================
    # Xóa dòng mở đầu dạng ```c hoặc ```cpp hoặc ``` nằm ở ngay đầu chuỗi
    # Dấu ^ nghĩa là bắt đầu chuỗi.
    content = re.sub(r'^```[a-zA-Z]*\n', '', content) 
    
    content = re.sub(r'\n```$', '', content)           
    
    content = content.replace('```', '').strip()
    
    return content

# ---------------------------------------------------------------------------
# LLM – provider-specific helpers
# ---------------------------------------------------------------------------

def _call_gemini(prompt: str) -> Optional[str]:
    """Gọi Google Gemini (gemini-2.5-flash) để sinh bản vá."""
    try:
        import google.generativeai as genai
    except ImportError:
        print("[LLM] Thiếu thư viện 'google-generativeai'. Cài bằng: pip install google-generativeai")
        return None

    api_key = os.getenv("GEMINI_API_KEY")
    if not api_key:
        print("[LLM] Warning: GEMINI_API_KEY chưa được đặt trong .env.")
        return None

    try:
        genai.configure(api_key=api_key)
        model = genai.GenerativeModel("models/gemini-2.5-flash")
        response = model.generate_content(prompt)
        return response.text
    except Exception as e:
        error_msg = str(e)
        if "Quota" in error_msg or "quota" in error_msg or "limit" in error_msg:
            print("[LLM] Warning: Gemini API quota limit đã đạt. Thử lại sau.")
        else:
            print(f"[LLM] Error calling Gemini: {error_msg}")
        return None


def _call_openai(prompt: str, model: str = "gpt-4o-mini") -> Optional[str]:
    """Gọi OpenAI ChatCompletion để sinh bản vá."""
    try:
        from openai import OpenAI
    except ImportError:
        print("[LLM] Thiếu thư viện 'openai'. Cài bằng: pip install openai")
        return None

    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        print("[LLM] Warning: OPENAI_API_KEY chưa được đặt trong .env.")
        return None

    try:
        client = OpenAI(api_key=api_key)
        response = client.chat.completions.create(
            model=model,
            messages=[
                {
                    "role": "system",
                    "content": (
                        "You are an expert in fixing C/C++ program bugs. "
                        "Return ONLY the fixed C function source code, with no explanation."
                    ),
                },
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
        )
        return response.choices[0].message.content
    except Exception as e:
        error_msg = str(e)
        if "quota" in error_msg.lower() or "rate_limit" in error_msg.lower():
            print("[LLM] Warning: OpenAI API quota/rate limit đã đạt. Thử lại sau.")
        else:
            print(f"[LLM] Error calling OpenAI: {error_msg}")
        return None


def _call_claude(prompt: str, model: Optional[str] = None) -> Optional[str]:
    """Gọi API Claude qua Proxy Zunef bằng cURL, xử lý chuẩn SSE Stream."""
    try:
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://claude.zunef.com/v1/ai").rstrip("/")
        api_key = os.getenv("ANTHROPIC_AUTH_TOKEN") or os.getenv("ANTHROPIC_API_KEY")
        target_model = model or os.getenv("ANTHROPIC_MODEL", "anthropic/claude-sonnet-4.6")

        log_dir = Path(f"results/claude_logs/{target_model}")
        log_dir.mkdir(parents=True, exist_ok=True)
        
        if not api_key:
            print("[LLM] LỖI: Thiếu API Key cho Claude")
            return None

        payload = {
            "model": target_model,
            "max_tokens": 4096 * 10, # Bây giờ 4096 token sẽ chỉ dành cho kết quả
            "temperature": 0.2, # Lưu ý: Nếu bật Thinking, temperature mặc định bị ép về 1. Nên nếu bạn đặt 0.2, lý tưởng nhất là nó đang ở Standard mode.
            "stream": True,
            # XÓA HẲN DÒNG "reasoning": False
            "system": (
                "You are an expert C/C++ program repair system. "
                "CRITICAL RULE: You are strictly forbidden from outputting any reasoning, thinking process, or explanations. "
                "Do NOT use <thinking> tags. Output ONLY the raw, fixed C code enclosed EXACTLY within <fixed_code> tags. "
                "If you output anything other than the <fixed_code> block, the system will crash."
            ),
            "messages": [{"role": "user", "content": prompt}]
        }

        # SỬA LỖI 1: Bỏ .encode('utf-8') vì bạn đang dùng text=True trong subprocess
        body = json.dumps(payload, ensure_ascii=False)

        # Đổi tên biến thành 'process_result' cho đỡ nhầm lẫn với requests
        process_result = subprocess.run(
            [
                "curl",
                "-sS",
                f"{base_url}/messages",
                "-H", "Content-Type: application/json",
                "-H", "Accept: application/json",
                "-H", f"x-api-key: {api_key}",
                "--data-binary", "@-",
            ],
            input=body,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=300,
        )
        
        # SỬA LỖI 2: Check returncode của process thay vì status_code của HTTP
        if process_result.returncode != 0:
            print(f"[LLM] Error cURL: {process_result.stderr.strip()}")
            return None
        
        raw_log_path = log_dir / "raw_response.txt"
        raw_log_path.write_text(process_result.stdout, encoding="utf-8")
    
        # SỬA LỖI 3: Duyệt qua từng dòng của stdout (không dùng iter_lines)
        text_parts = []
        for line in process_result.stdout.splitlines():
            line = line.strip()
            if line.startswith("data: "):
                json_str = line[6:]
                if json_str == "[DONE]":
                    continue
                try:
                    data = json.loads(json_str)
                    delta = data.get("delta", {})
                    # Chỉ lấy text, lờ đi phần thinking nếu có
                    if delta.get("type") == "text_delta":
                        text_parts.append(delta.get("text", ""))
                except json.JSONDecodeError:
                    continue
        
        raw_text = "".join(text_parts)
        
        if not raw_text:
            print("[LLM] LỖI: Không bóc tách được text từ Claude Stream.")
            # In ra 200 ký tự đầu tiên để xem Zunef có chửi lỗi gì bằng JSON (ví dụ 400 Bad Request) không
            print(f"[LLM DEBUG] Server trả về: {process_result.stdout[:200]}")
            return None
            
        return _clean_code(raw_text)
        
    except Exception as e:
        print(f"[LLM] Exception Claude: {e}")
        return None
    

def _call_qwen(prompt: str, model: str = "qwen/qwen3-coder-30b-a3b-instruct") -> Optional[str]:
    try:
        # OpenRouter key is preferred; QWEN_API_KEY remains as a backward-compatible alias.
        api_key = os.getenv("OPENROUTER_API_KEY") or os.getenv("QWEN_API_KEY")
        base_url = os.getenv("OPENROUTER_BASE_URL", "https://openrouter.ai/api/v1").rstrip("/")
        referer = os.getenv("OPENROUTER_SITE_URL", "http://localhost:3000")
        app_title = os.getenv("OPENROUTER_APP_NAME", "UET_APR_Research")
        log_dir = Path(f"results/qwen_logs/{model}")
        log_dir.mkdir(parents=True, exist_ok=True)
        if not api_key:
            print("[LLM] LỖI: Không tìm thấy OPENROUTER_API_KEY trong môi trường.")
            return None

        url = f"{base_url}/chat/completions"
        
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "HTTP-Referer": referer,
            "X-Title": app_title,
        }

        payload = {
            "model": model,
            "messages": [
                {
                    "role": "system", 
                    "content": "You are a professional C repair agent. Return ONLY the raw fixed C code. No markdown, no explanation, no backticks."
                },
                {"role": "user", "content": prompt}
            ],
            "temperature": 0.1, # Để kết quả ổn định hơn (ít NoiseFix hơn)
            "max_tokens": int(os.getenv("LLM_MAX_OUTPUT_TOKENS", "12000")),
        }

        # 3. Gọi API với timeout để tránh treo máy như lúc nãy
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
        
        if response.status_code != 200:
            print(f"[LLM] Error {response.status_code}: {response.text}")
            return None
        
        raw_log_path = log_dir / "raw_response.txt"
        raw_log_path.write_text(response.text, encoding="utf-8")

        result = response.json()
        raw_content = result['choices'][0]['message']['content'].strip()

        # 4. HÀM QUAN TRỌNG: Xóa sạch Markdown (```c ... ```) 
        # Nếu không có đoạn này, GCC sẽ báo lỗi cú pháp và gây ra 100% Regression như bạn vừa bị.
        fixed_code = re.sub(r'^```[a-zA-Z]*\n', '', raw_content) # Xóa dòng mở đầu ```c
        fixed_code = re.sub(r'\n```$', '', fixed_code)           # Xóa dòng kết thúc ```
        fixed_code = fixed_code.replace('```', '').strip()

        return fixed_code

    except Exception as e:
        print(f"[LLM] Exception khi gọi OpenRouter: {e}")
        return None


def call_llm(prompt: str, provider: Optional[str] = None) -> Optional[str]:
    """
    Gọi LLM để sinh bản vá.

    Args:
        prompt:   Nội dung prompt gửi đến LLM.
        provider: 'gemini' | 'openai' | 'claude' | 'qwen' | 'openrouter'.
                  Nếu None, đọc từ biến môi trường LLM_PROVIDER.

    Returns:
        Chuỗi mã nguồn do LLM trả về, hoặc None nếu lỗi.
    """
    chosen = (provider or _DEFAULT_LLM_PROVIDER).strip().lower()

    if chosen == "openai":
        openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
        print(f"[LLM] Provider: OpenAI ({openai_model})")
        return _call_openai(prompt, model=openai_model)

    if chosen == "gemini":
        print("[LLM] Provider: Gemini (gemini-2.5-flash)")
        return _call_gemini(prompt)
    
    if chosen == "claude":
        claude_model = os.getenv("ANTHROPIC_MODEL", "anthropic/claude-sonnet-4.6")
        print(f"[LLM] Provider: Claude ({claude_model})")
        return _call_claude(prompt, model=claude_model)

    if chosen in ("qwen", "openrouter"):
        qwen_model = os.getenv("QWEN_MODEL", "qwen/qwen3-coder-30b-a3b-instruct")
        print(f"[LLM] Provider: Qwen ({qwen_model})")
        return _call_qwen(prompt, model=qwen_model)

    print(f"[LLM] Warning: Provider không hỗ trợ '{chosen}'. Chọn 'gemini', 'openai', 'claude', hoặc 'qwen'.")
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_patch(patched_file_path: str, bug_id: str, dataset: str = "codeflaws",
                   src_basename: Optional[str] = None,
                   src_relpath: Optional[str] = None):
    """Sử dụng Sandbox Adapter để kiểm chứng bản vá.

    ``src_relpath`` cho Defects4C biết chính xác file nào trong buggy version
    cần thay thế. ``src_basename`` chỉ còn là fallback/tên hiển thị.
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
    Rút gọn source đưa vào prompt khi file quá dài (thường gặp ở Defects4C).

    Chiến lược: giữ phần đầu file (includes, typedef, hằng số) + neighborhood
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


def _copy_accepted_patch(dataset: str, bug_id: str, bug_source_path: str,
                        bug_record: BugRecord) -> str:
    """
    Sao lưu accepted/ground-truth patch để evaluation so sánh về sau.

    - Codeflaws: đường dẫn được tính từ ``bug_id`` (``<prefix>-<accepted>.c``).
    - Defects4C: chỉ dùng ``bug_record.raw['accepted_file']`` do loader sinh
      từ đúng ``commit_after``. Không fallback sang thư mục khác.

    Returns:
        Chuỗi rỗng nếu thành công, hoặc mã lỗi rõ ràng nếu không copy được.
    """
    out_dir = os.path.join(EXPERIMENTS_DIR, "correct_patches")
    ds = (dataset or "").lower()
    accepted_src = None

    if ds == "codeflaws":
        accepted_cfile = get_codeflaws_accepted_cfile(bug_id)
        if accepted_cfile:
            accepted_src = os.path.join(os.path.dirname(bug_source_path), accepted_cfile)
        else:
            return "accepted_name_missing"

    elif _is_defects4c_dataset(ds):
        raw = bug_record.raw if bug_record else None
        if not raw:
            return "bug_record_missing"
        accepted_src = raw.get("accepted_file")
    else:
        return f"unsupported_dataset:{dataset}"

    if not accepted_src or not os.path.exists(accepted_src):
        return f"accepted_file_not_found:{accepted_src or '<empty>'}"
    os.makedirs(out_dir, exist_ok=True)
    safe_id = bug_id.replace("@", "__").replace("/", "__")
    try:
        shutil.copy2(accepted_src, os.path.join(out_dir, f"{safe_id}_accepted.c"))
    except Exception as exc:
        return f"accepted_copy_failed:{exc}"
    return ""


def _build_failed_test_context(bug: BugRecord) -> str:
    """Tóm tắt toàn bộ failed tests từ BugRecord (không đọc lại disk)."""
    failed_tests = [t for t in bug.tests if t.get("outcome") in ("FAIL", "FAILED")]
    if not failed_tests:
        return ""

    lines = [
        "### Failed test summary",
        "The following tests fail on the buggy version:",
    ]
    for idx, tc in enumerate(failed_tests, start=1):
        tc_name = str(tc.get("test_id") or "Unknown").strip()
        tc_reason = str(tc.get("fail_reason") or "Unknown").strip()
        lines.append(f"{idx}. test_id: {tc_name}")
        lines.append(f"   fail_reason: {tc_reason}")

    return "\n".join(lines) + "\n"


def _clean_llm_patch(patched_func: str) -> str:
    """Loại bỏ markdown wrapper mà LLM thêm vào nếu có."""
    patched_func = patched_func.strip()

    # Trường hợp LLM trả về text giải thích + code block
    code_block = re.search(r'```(?:c|cpp)?\s*\n([\s\S]*?)```', patched_func)
    if code_block:
        patched_func = code_block.group(1)

    lines = patched_func.split("\n")
    if lines and lines[0].strip().startswith("// Bắt đầu"):
        patched_func = "\n".join(lines[1:])

    return patched_func.strip()


def run_apr_pipeline(dataset: str = "codeflaws", llm_provider: Optional[str] = None):
    """
    Pipeline APR (LLM-based).
    Load dữ liệu qua get_loader() – không đọc lại file JSON thủ công.

    Args:
        dataset:      Tên dataset (mặc định 'codeflaws').
        llm_provider: 'gemini' | 'openai' | 'claude' | 'qwen' | 'openrouter'.
                      Nếu None, đọc từ LLM_PROVIDER trong .env.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    tarantula_results_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_results_file):
        print(f"[APR] Lỗi: {tarantula_results_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(tarantula_results_file, "r") as f:
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
        if bug_id in apr_results and apr_results[bug_id].get("status") == "success":
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

        defects4c_like = _is_defects4c_dataset(ds_lc)
        primary_base = os.path.basename(bug_source_path)
        _br = bug_map.get(bug_id)
        raw_meta = _br.raw if _br else None
        source_cache: dict = {}

        # Context test từ BugRecord đã load sẵn (không đọc thêm file)
        bug_record = bug_map.get(bug_id)
        failed_tests_context = _build_failed_test_context(bug_record) if bug_record else ""
        init_passed_all = [t.get("test_id") for t in (bug_record.tests if bug_record else []) if t.get("outcome") in ("PASS", "PASSED")]
        init_failed_all = [t.get("test_id") for t in (bug_record.tests if bug_record else []) if t.get("outcome") in ("FAIL", "FAILED")]
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
        candidate_results = []
        best_candidate = None

        # Sao lưu accepted patch một lần (cho evaluation sau này).
        # Logic tách theo dataset — tránh áp sai hàm codeflaws cho defects4c.
        accepted_patch_error = _copy_accepted_patch(dataset, bug_id, bug_source_path, bug_record)
        if accepted_patch_error:
            print(f"    [ERROR] Không copy được accepted patch: {accepted_patch_error}")

        for qualified_name, score in top_funcs:
            if score == 0.0:
                continue

            file_hint, func_name = parse_sbfl_qualified_name(qualified_name)
            if not func_name:
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
            func_code, start_idx, end_idx = extract_function_code(source_code, func_name)
            if not func_code:
                print(f"    WARNING: Không thể trích xuất hàm {func_name}")
                continue

            target_func = qualified_name
            attempted = True

            prompt_source = _trim_source_for_prompt(source_code, start_idx, end_idx)
            prompt = f"""You are an expert C/C++ maintenance engineer.
Your task is to repair the likely defect in function `{func_name}` from the code below (Bug ID: {bug_id}).
The defect may be a crash, memory-safety issue, bounds-checking error, parser edge case, undefined behavior, or incorrect error handling.

{failed_tests_context}

### Current source file (for scope, libraries, and struct context):
```c
{prompt_source}
```

### The buggy function to repair (`{func_name}` in `{cand_label}`):
```c
{func_code}
```

### Requirements:
1. Find and fix the bug inside function `{func_name}`.
2. Keep the patch minimal and preserve existing coding style, signatures, macros, and helper APIs.
3. Do not invent new global helpers, includes, or unrelated refactors.
4. RETURN ONLY the complete fixed C source code of function `{func_name}`.
5. Do NOT include any explanation or preface text, do NOT rewrite `#include` lines, and do NOT add `main()`.

```c
// Start rewriting function {func_name} here:
"""

            raw_patch = call_llm(prompt, provider=llm_provider)
            if not raw_patch:
                print("    [ERROR] LLM trả về None. Bỏ qua hàm này.")
                continue

            llm_attempted = True
            candidate_patched_func = _clean_llm_patch(raw_patch)
            reparsed_func, _, _ = extract_function_code(candidate_patched_func, func_name)
            if not reparsed_func:
                print("    [ERROR] LLM trả về function không hoàn chỉnh/không parse được. Bỏ qua validate.")
                candidate_results.append({
                    "function": qualified_name,
                    "score": score,
                    "status": "validation_error",
                    "validation_error": "malformed_function",
                    "repair_target_file": candidate_path,
                    "repair_target_relpath": candidate_relpath,
                    "patched_function": candidate_patched_func,
                    "patched_file": "",
                    "post_passed_count": 0,
                    "post_failed_count": 0,
                    "post_passed_tests": [],
                    "post_failed_tests": [],
                })
                continue

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
            "accepted_patch_error": accepted_patch_error,
        }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)


if __name__ == "__main__":
    run_apr_pipeline()
