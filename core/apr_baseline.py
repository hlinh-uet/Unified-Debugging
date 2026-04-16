import os
import json
import re
import shutil
import subprocess
from typing import Optional
import requests
from typing import Optional, Tuple



from dotenv import load_dotenv

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR
from data_loaders.base_loader import get_loader, BugRecord
from data_loaders.sandbox_adapter import get_sandbox_adapter
from core.utils import (
    extract_function_code,
    parse_qualified_func,
    get_codeflaws_accepted_cfile,
)

load_dotenv()

# Provider mặc định – đọc từ .env, có thể override qua CLI
_DEFAULT_LLM_PROVIDER = os.getenv("LLM_PROVIDER", "gemini").strip().lower()


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


def _call_claude(prompt: str, model: str = "claude-3-5-sonnet-20241022") -> Tuple[Optional[str], int, int]:
    """
    Calls Anthropic Claude API and returns the generated text along with token usage.
    Returns: (response_text, input_tokens, output_tokens)
    """
    input_tokens = 0
    output_tokens = 0
    
    try:
        base_url = os.getenv("ANTHROPIC_BASE_URL", "https://api.anthropic.com/v1").rstrip("/")
        api_key = os.getenv("ANTHROPIC_AUTH_TOKEN") or os.getenv("ANTHROPIC_API_KEY")
        
        if not api_key:
            print(f"[LLM] Error Claude ({model}): Missing API Key in environment variables.")
            return None, 0, 0
            
        payload = {
            "model": model,
            "max_tokens": 2048,
            "temperature": 0.2,
            "system": "You are an expert C developer. Return ONLY the fixed function code.",
            "stream": False,
            "messages": [
                {
                    "role": "user",
                    "content": prompt,
                }
            ],
        }

        body = json.dumps(payload, ensure_ascii=False)

        result = subprocess.run(
            [
                "curl",
                "-sS",
                f"{base_url}/messages",
                "-H", "Content-Type: application/json",
                "-H", "Accept: application/json",
                "-H", f"x-api-key: {api_key}",
                "-H", "anthropic-version: 2023-06-01",
                "--data-binary", "@-",
            ],
            input=body,
            capture_output=True,
            text=True,
            encoding="utf-8",
            check=False,
            timeout=500,
        )

        if result.returncode != 0:
            print(f"[LLM] Error Claude ({model}): Request failed - {result.stderr.strip()}")
            return None, 0, 0

        raw_output = result.stdout.strip()

        # Xử lý trường hợp Proxy ép trả về dạng Stream (SSE)
        if raw_output.startswith("event:") or "data:" in raw_output:
            text_parts = []
            for line in raw_output.splitlines():
                line = line.strip()
                if line.startswith("data: "):
                    json_str = line[6:]
                    if json_str == "[DONE]":
                        continue
                    try:
                        data = json.loads(json_str)
                        if data.get("type") == "error":
                            print(f"[LLM] Error Claude ({model}): API Stream Error - {data.get('error')}")
                            return None, 0, 0
                            
                        # Bắt thông tin token từ các event của Stream
                        if data.get("type") == "message_start":
                            input_tokens = data.get("message", {}).get("usage", {}).get("input_tokens", 0)
                        elif data.get("type") == "message_delta":
                            output_tokens = data.get("usage", {}).get("output_tokens", 0)
                            
                        delta = data.get("delta", {})
                        if delta.get("type") == "text_delta":
                            text_parts.append(delta.get("text", ""))
                    except json.JSONDecodeError:
                        continue
            
            response_text = "".join(text_parts).strip() if text_parts else None
            return response_text, input_tokens, output_tokens

        # Xử lý trường hợp trả về JSON tiêu chuẩn
        else:
            try:
                parsed = json.loads(raw_output)
                
                if "error" in parsed:
                    print(f"[LLM] Error Claude ({model}): API returned error: {parsed['error']}")
                    return None, 0, 0

                # Bắt thông tin token từ JSON object
                usage = parsed.get("usage", {})
                input_tokens = usage.get("input_tokens", 0)
                output_tokens = usage.get("output_tokens", 0)

                content = parsed.get("content", [])
                text_parts = []
                
                if isinstance(content, list):
                    for item in content:
                        if isinstance(item, dict) and item.get("type") == "text" and item.get("text"):
                            text_parts.append(item["text"])

                response_text = "".join(text_parts).strip() if text_parts else None
                return response_text, input_tokens, output_tokens
                
            except json.JSONDecodeError:
                print(f"[LLM] Error Claude ({model}): Không thể parse JSON. Raw output: {raw_output[:200]}")
                return None, 0, 0

    except Exception as e:
        print(f"[LLM] Error Claude ({model}): {e}")
        return None, 0, 0

def _call_qwen(prompt: str, model: str = "qwen/qwen-2.5-coder-32b-instruct") -> Optional[str]:
    try:
        # 1. Lấy Key và kiểm tra
        api_key = os.getenv("QWEN_API_KEY")
        if not api_key:
            print("[LLM] LỖI: Không tìm thấy API Key trong môi trường.")
            return None

        url = "https://openrouter.ai/api/v1/chat/completions"
        
        # 2. Ép Header chuẩn OpenRouter - Đây là chỗ sửa lỗi 401 của bạn
        headers = {
            "Authorization": f"Bearer {api_key.strip()}",
            "Content-Type": "application/json",
            "HTTP-Referer": "http://localhost:3000", # Bắt buộc cho OpenRouter
            "X-Title": "UET_APR_Research"
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
            "max_tokens": 4096
        }

        # 3. Gọi API với timeout để tránh treo máy như lúc nãy
        response = requests.post(url, headers=headers, data=json.dumps(payload), timeout=60)
        
        if response.status_code != 200:
            print(f"[LLM] Error {response.status_code}: {response.text}")
            return None

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
    
def call_llm(prompt: str, provider: Optional[str] = None) -> Tuple[Optional[str], int, int]:
    """
    Gọi LLM để sinh bản vá.

    Args:
        prompt:   Nội dung prompt gửi đến LLM.
        provider: 'gemini' | 'openai' | 'claude' | 'qwen'. Nếu None, dùng mặc định.

    Returns:
        Tuple chứa 3 giá trị:
        - response_text (Optional[str]): Chuỗi mã nguồn do LLM trả về, hoặc None nếu lỗi.
        - input_tokens (int): Số lượng token đầu vào (nếu provider có hỗ trợ đếm).
        - output_tokens (int): Số lượng token đầu ra (nếu provider có hỗ trợ đếm).
    """
    # Lấy _DEFAULT_LLM_PROVIDER từ biến global của bạn, hoặc dùng 'gemini' làm fallback
    default_provider = globals().get('_DEFAULT_LLM_PROVIDER', 'gemini')
    chosen = (provider or default_provider).strip().lower()
    
    result = None

    try:
        if chosen == "openai":
            openai_model = os.getenv("OPENAI_MODEL", "gpt-4o-mini")
            print(f"[LLM] Provider: OpenAI ({openai_model})")
            result = _call_openai(prompt, model=openai_model)

        elif chosen == "gemini":
            print("[LLM] Provider: Gemini (gemini-2.5-flash)")
            result = _call_gemini(prompt)
            
        elif chosen == "claude":
            claude_model = os.getenv("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022")
            print(f"[LLM] Provider: Claude ({claude_model})")
            result = _call_claude(prompt, model=claude_model)
        
        elif chosen == "qwen":
            qwen_model = os.getenv("QWEN_MODEL", "qwen/qwen3-coder-30b-a3b-instruct")
            print(f"[LLM] Provider: Qwen ({qwen_model})")
            result = _call_qwen(prompt, model=qwen_model)

        else:
            print(f"[LLM] Warning: Provider không hỗ trợ '{chosen}'. Chọn 'gemini', 'openai', 'claude' hoặc 'qwen'.")
            return None, 0, 0

        # --- Xử lý tương thích ngược ---
        # Nếu hàm _call_* đã trả về Tuple (text, in_tokens, out_tokens) như _call_claude mới
        if isinstance(result, tuple) and len(result) == 3:
            return result
        # Nếu hàm _call_* cũ vẫn chỉ trả về chuỗi str hoặc None (ví dụ: _call_openai chưa sửa)
        else:
            return result, 0, 0

    except Exception as e:
        print(f"[LLM] Error in call_llm (Provider: {chosen}): {e}")
        return None, 0, 0


def validate_patch(patched_file_path: str, bug_id: str, dataset: str = "codeflaws"):
    """Sử dụng Sandbox Adapter để kiểm chứng bản vá."""
    print(f"[APR] Validating patch cho {bug_id} với adapter '{dataset}'...")
    try:
        adapter = get_sandbox_adapter(dataset, bug_id)
        return adapter.validate(patched_file_path)
    except Exception as e:
        print(f"    [Error] Không thể validate: {e}")
        return False, [], []

def _build_failed_test_context(bug: BugRecord) -> str:
    """Trích xuất context test thất bại đầu tiên từ BugRecord (không đọc lại disk)."""
    failed_tests = [t for t in bug.tests if t.get("outcome") in ("FAIL", "FAILED")]
    if not failed_tests:
        return ""

    tc = failed_tests[0]
    tc_name     = tc.get("test_id", "Unknown")
    tc_reason   = tc.get("fail_reason", "Unknown")
    tc_expected = tc.get("expected_output", "N/A")
    tc_actual   = tc.get("actual_output", "N/A")

    if len(tc_expected) > 500:
        tc_expected = tc_expected[:500] + "\n...[truncated]"
    if len(tc_actual) > 500:
        tc_actual = tc_actual[:500] + "\n...[truncated]"

    return f"""
### Failed test information (Test Case: {tc_name})
- **Failure reason:** {tc_reason}
- **Expected output:**
```
{tc_expected.strip()}
```
- **Actual output:**
```
{tc_actual.strip()}
```
"""


def _clean_llm_patch(patched_func: str) -> str:
    """Loại bỏ markdown wrapper mà LLM thêm vào nếu có."""
    patched_func = patched_func.strip()

    # Trường hợp LLM trả về text giải thích + code block
    code_fence = re.search(r'```(?:c|cpp)?\s*\n', patched_func)
    if code_fence:
        start = code_fence.end()
        end_fence = patched_func.rfind("```")
        if end_fence > start:
            patched_func = patched_func[start:end_fence]
        else:
            patched_func = patched_func[start:]

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
        llm_provider: 'gemini' | 'openai'. Nếu None, đọc từ LLM_PROVIDER trong .env.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    tarantula_results_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_results_file):
        print(f"[APR] Lỗi: {tarantula_results_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(tarantula_results_file, "r") as f:
        fl_results = json.load(f)

    # Load toàn bộ bug records một lần duy nhất → dùng chung cho FL context
    print(f"[APR] Đang load bug records từ dataset '{dataset}'...")
    loader  = get_loader(dataset)
    bug_map = {b.bug_id: b for b in loader.load_all()}

    apr_results = {}
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_results.json")
    if os.path.exists(apr_results_file):
        try:
            with open(apr_results_file, "r") as f:
                apr_results = json.load(f)
        except Exception:
            pass

    print("[APR] Đang chạy Automated Program Repair (LLM)...")

    for bug_id, result_data in fl_results.items():
        if bug_id in apr_results and apr_results[bug_id].get("status") != "skipped":
            continue

        scores = result_data.get("scores", result_data) if isinstance(result_data, dict) else result_data
        if not scores:
            continue

        sorted_funcs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        print(f"[APR] Xử lý bug {bug_id}...")

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

        with open(bug_source_path, "r") as f:
            source_code = f.read()

        # Context test từ BugRecord đã load sẵn (không đọc thêm file)
        bug_record = bug_map.get(bug_id)
        failed_tests_context = _build_failed_test_context(bug_record) if bug_record else ""
        init_passed = [t.get("test_id") for t in (bug_record.tests if bug_record else []) if t.get("outcome") in ("PASS", "PASSED")]
        init_failed = [t.get("test_id") for t in (bug_record.tests if bug_record else []) if t.get("outcome") in ("FAIL", "FAILED")]

        status        = "skipped"
        patched_func  = None
        patched_source = None   # toàn bộ nội dung file sau khi vá
        target_func   = None
        post_passed   = []
        post_failed   = []
        attempted     = False   # đã thử ít nhất 1 hàm
        llm_attempted = False   # LLM đã thực sự sinh patch ít nhất 1 lần

        # Sao lưu accepted patch một lần (cho evaluation sau này)
        bug_dir = os.path.dirname(bug_source_path)
        accepted_cfile = get_codeflaws_accepted_cfile(bug_id)
        if accepted_cfile:
            accepted_src = os.path.join(bug_dir, accepted_cfile)
            os.makedirs(os.path.join(EXPERIMENTS_DIR, "correct_patches"), exist_ok=True)
            if os.path.exists(accepted_src):
                shutil.copy2(accepted_src, os.path.join(EXPERIMENTS_DIR, "correct_patches", f"{bug_id}_accepted.c"))

        for qualified_name, score in sorted_funcs:
            if score == 0.0:
                continue

            _, func_name = parse_qualified_func(qualified_name)
            print(f"  - Kiểm tra hàm '{func_name}' (Score: {score:.4f})")
            func_code, start_idx, end_idx = extract_function_code(source_code, func_name)
            if not func_code:
                print(f"    WARNING: Không thể trích xuất hàm {func_name}")
                continue

            target_func = qualified_name
            attempted = True

            prompt = f"""You are an expert in fixing C/C++ bugs.
Your task is to fix an algorithmic or compilation bug in function `{func_name}` from the code below (Bug ID: {bug_id}).

{failed_tests_context}

### Full current source file (for scope, libraries, and struct context):
```c
{source_code}
```

### Requirements:
1. Find and fix the bug inside function `{func_name}`.
2. RETURN ONLY the fixed C source code of function `{func_name}` (so I can parse and replace it directly using regex).
3. Do NOT include any explanation or preface text, do NOT rewrite `#include` lines, and do NOT add `main()` if you are fixing another function.

```c
// Start rewriting function {func_name} here:
"""

            raw_patch = call_llm(prompt, provider=llm_provider)
            if not raw_patch:
                print("    [ERROR] LLM trả về None. Bỏ qua hàm này.")
                continue

            llm_attempted = True
            patched_func   = _clean_llm_patch(raw_patch)
            patched_source = source_code[:start_idx] + patched_func + source_code[end_idx:]

            tmp_path = os.path.join(EXPERIMENTS_DIR, f"tmp_{bug_id}.c")
            with open(tmp_path, "w") as f:
                f.write(patched_source)

            is_valid, post_passed, post_failed = validate_patch(tmp_path, bug_id, dataset)

            if is_valid:
                print(f"    [SUCCESS] Bản vá hợp lệ cho {bug_id} trong hàm '{func_name}'!")
                patch_path = os.path.join(PATCHES_DIR, f"{bug_id}_patch.c")
                os.makedirs(PATCHES_DIR, exist_ok=True)
                try:
                    shutil.move(tmp_path, patch_path)  # dùng move thay rename để an toàn cross-device
                except Exception as e_mv:
                    print(f"    [WARN] Không lưu được patch file: {e_mv}")
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)
                status = "success"
                break
            else:
                print(f"    [FAIL] Bản vá không vượt qua kiểm tra.")
                if os.path.exists(tmp_path):
                    os.remove(tmp_path)

        if attempted and status == "skipped":
            # Phân biệt: LLM không bao giờ sinh được patch vs. patch sinh ra nhưng fail test
            status = "failed" if llm_attempted else "llm_failed"

        apr_results[bug_id] = {
            "status":            status,
            "patched_function":  patched_func,
            "patched_file":      patched_source,   # toàn bộ file sau khi vá (để tính ED file-level)
            "selected_function": target_func,
            "init_passed_tests": init_passed,
            "init_failed_tests": init_failed,
            "post_passed_tests": post_passed,
            "post_failed_tests": post_failed,
        }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)


if __name__ == "__main__":
    run_apr_pipeline()