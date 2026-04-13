import os
import json
import re

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR
from data_loaders.base_loader import get_loader, BugRecord
from data_loaders.sandbox_adapter import get_sandbox_adapter
from core.utils import extract_function_code


# ---------------------------------------------------------------------------
# Mutation Engine
# ---------------------------------------------------------------------------

def generate_mutants(func_code: str):
    """
    Sinh ra các biến thể (mutants) của một hàm nhằm tìm kiếm bản vá (Heuristic Search).
    Tập trung vào lỗi phổ biến trong Codeforces: sai điều kiện (<, >), sai dấu (+, -),
    sai index off-by-one.

    Returns:
        list of (mutant_code: str, description: str)
    """
    mutants = []

    rules = [
        # Quan hệ so sánh
        (r'(?<=\w)\s*<\s*(?=\w)',  [' <= ', ' > ', ' >= ', ' == ', ' != ']),
        (r'(?<=\w)\s*>\s*(?=\w)',  [' >= ', ' < ', ' <= ', ' == ', ' != ']),
        (r'(?<=\w)\s*<=\s*(?=\w)', [' < ', ' == ']),
        (r'(?<=\w)\s*>=\s*(?=\w)', [' > ', ' == ']),
        (r'(?<=\w)\s*==\s*(?=\w)', [' != ', ' <= ', ' >= ']),
        (r'(?<=\w)\s*!=\s*(?=\w)', [' == ']),
        # Toán tử số học
        (r'(?<=\w)\s*\+\s*(?=\w)', [' - ']),
        (r'(?<=\w)\s*-\s*(?=\w)',  [' + ']),
        # Off-by-one
        (r'(\+\s*1)\b', ['- 1', '']),
        (r'(-\s*1)\b',  ['+ 1', '']),
    ]

    for pattern, replacements in rules:
        for match in re.finditer(pattern, func_code):
            original = match.group(0)
            for rep in replacements:
                if rep.strip() != original.strip():
                    mutant = func_code[:match.start()] + rep + func_code[match.end():]
                    if mutant not in [m[0] for m in mutants]:
                        mutants.append((mutant, f"Đổi '{original.strip()}' → '{rep.strip()}'"))

    return mutants


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

def validate_patch(patched_file_path: str, bug_id: str, dataset: str = "codeflaws"):
    """Gọi Sandbox Adapter để kiểm chứng bản vá."""
    try:
        adapter = get_sandbox_adapter(dataset, bug_id)
        return adapter.validate(patched_file_path)
    except Exception as e:
        print(f"    [Error] Không thể validate: {e}")
        return False, [], []


# ---------------------------------------------------------------------------
# Pipeline
# ---------------------------------------------------------------------------

def run_mutation_pipeline(dataset: str = "codeflaws"):
    """
    Pipeline APR Heuristic Mutation (không cần LLM).
    Load dữ liệu qua get_loader() – không đọc lại file JSON thủ công.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)

    tarantula_results_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_results_file):
        print(f"[Mutation] Lỗi: {tarantula_results_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(tarantula_results_file, "r") as f:
        fl_results = json.load(f)

    # Load toàn bộ bug records một lần duy nhất
    print(f"[Mutation] Đang load bug records từ dataset '{dataset}'...")
    loader  = get_loader(dataset)
    bug_map = {b.bug_id: b for b in loader.load_all()}

    apr_results      = {}
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_mutation_results.json")
    if os.path.exists(apr_results_file):
        try:
            with open(apr_results_file, "r") as f:
                apr_results = json.load(f)
        except Exception:
            pass

    print("[Mutation] Đang chạy APR Heuristic Mutation (Local, No LLM)...")

    for bug_id, result_data in fl_results.items():
        if bug_id in apr_results and apr_results[bug_id].get("status") != "skipped":
            continue

        scores = result_data.get("scores", result_data) if isinstance(result_data, dict) else result_data
        if not scores:
            continue

        sorted_funcs = sorted(scores.items(), key=lambda x: x[1], reverse=True)
        print(f"\n[Mutation] Xử lý bug {bug_id}...")

        try:
            adapter         = get_sandbox_adapter(dataset, bug_id)
            bug_source_path = adapter.get_source_path()
        except Exception as e:
            print(f"    [Error] Lỗi khởi tạo Adapter cho {bug_id}: {e}")
            continue

        if not os.path.exists(bug_source_path):
            print(f"    [Skip] File nguồn không tồn tại: {bug_source_path}")
            continue

        with open(bug_source_path, "r") as f:
            source_code = f.read()

        # Lấy test context từ BugRecord đã load sẵn
        bug_record   = bug_map.get(bug_id)
        tests        = bug_record.tests if bug_record else []
        init_passed  = [t.get("test_id") for t in tests if t.get("outcome") in ("PASS", "PASSED")]
        init_failed  = [t.get("test_id") for t in tests if t.get("outcome") in ("FAIL", "FAILED")]

        status           = "failed"
        patched_func     = None
        target_func      = None
        best_post_passed = []
        best_post_failed = []
        best_mutant_desc = ""

        for func_name, score in sorted_funcs:
            if score == 0.0:
                continue

            print(f"  - Đang đột biến hàm '{func_name}' (Score: {score:.4f})")
            func_code, start_idx, end_idx = extract_function_code(source_code, func_name)
            if not func_code:
                continue

            target_func = func_name
            mutants     = generate_mutants(func_code)
            print(f"    → Tạo {len(mutants)} mutants để đưa vào Sandbox...")

            found_fix = False
            best_pass_count = -1
            for i, (m_code, m_desc) in enumerate(mutants):
                patched_source = source_code[:start_idx] + m_code + source_code[end_idx:]
                tmp_path = os.path.join(EXPERIMENTS_DIR, f"tmp_{bug_id}.c")

                with open(tmp_path, "w") as f:
                    f.write(patched_source)

                is_valid, post_passed, post_failed = validate_patch(tmp_path, bug_id, dataset)

                if is_valid:
                    print(f"    [SUCCESS] Mutant #{i} vượt qua test! ({m_desc})")
                    status           = "success"
                    patched_func     = m_code
                    best_mutant_desc = m_desc
                    best_post_passed = post_passed
                    best_post_failed = post_failed

                    patch_path = os.path.join(PATCHES_DIR, f"{bug_id}_mutation_patch.c")
                    os.makedirs(PATCHES_DIR, exist_ok=True)
                    os.rename(tmp_path, patch_path)
                    found_fix = True
                    break
                else:
                    if len(post_passed) > best_pass_count:
                        best_pass_count  = len(post_passed)
                        best_post_passed = post_passed
                        best_post_failed = post_failed
                    if os.path.exists(tmp_path):
                        os.remove(tmp_path)

            if found_fix:
                break

        apr_results[bug_id] = {
            "status":            status,
            "patched_function":  patched_func,
            "selected_function": target_func,
            "mutation_strategy": best_mutant_desc,
            "init_passed_tests": init_passed,
            "init_failed_tests": init_failed,
            "post_passed_tests": best_post_passed,
            "post_failed_tests": best_post_failed,
        }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)


if __name__ == "__main__":
    run_mutation_pipeline()
