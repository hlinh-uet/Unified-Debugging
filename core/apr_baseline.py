import os
import json
import re
import shutil
import subprocess
from typing import Optional

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
                        "Bạn là một chuyên gia sửa lỗi chương trình C/C++. "
                        "CHỈ trả về mã nguồn C của hàm đã được sửa, không kèm lời giải thích."
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


def call_llm(prompt: str, provider: Optional[str] = None) -> Optional[str]:
    """
    Gọi LLM để sinh bản vá.

    Args:
        prompt:   Nội dung prompt gửi đến LLM.
        provider: 'gemini' | 'openai'. Nếu None, đọc từ biến môi trường
                  LLM_PROVIDER (mặc định: 'gemini').

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

    print(f"[LLM] Warning: Provider không hỗ trợ '{chosen}'. Chọn 'gemini' hoặc 'openai'.")
    return None


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_patch(patched_file_path: str, bug_id: str, dataset: str = "codeflaws"):
    """Sử dụng Sandbox Adapter để kiểm chứng bản vá."""
    print(f"[APR] Validating patch cho {bug_id} với adapter '{dataset}'...")
    try:
        adapter = get_sandbox_adapter(dataset, bug_id)
        return adapter.validate(patched_file_path)
    except Exception as e:
        print(f"    [Error] Không thể validate: {e}")
        return False, [], []


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

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
### Thông tin kiểm thử thất bại (Test Case: {tc_name})
- **Lý do lỗi:** {tc_reason}
- **Kết quả mong đợi (Expected Output):**
```
{tc_expected.strip()}
```
- **Kết quả thực tế (Actual Output):**
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

            prompt = f"""Bạn là một chuyên gia sửa lỗi chương trình C/C++.
Nhiệm vụ của bạn là sửa một lỗi thuật toán hoặc biên dịch trong hàm `{func_name}` của đoạn mã dưới đây (Bug ID: {bug_id}).

{failed_tests_context}

### Toàn bộ file mã nguồn hiện tại (để hiểu scope, thư viện, và struct):
```c
{source_code}
```

### Yêu cầu:
1. Hãy tìm và sửa lỗi bên trong hàm `{func_name}`.
2. CHỈ TRẢ VỀ mã nguồn C của HÀM `{func_name}` đã được sửa (để tôi có thể parse trực tiếp thay thế bằng Regex).
3. Tuyệt đối KHÔNG kèm theo lời giải thích mào đầu, KHÔNG viết lại các `#include`, KHÔNG thêm main() nếu đang sửa hàm khác.

```c
// Bắt đầu viết lại hàm {func_name} tại đây:
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
