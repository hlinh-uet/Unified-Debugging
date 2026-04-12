import os
import json
import re
import subprocess
import shutil

from configs.path import EXPERIMENTS_DIR, CODEFLAWS_SOURCE_DIR, PATCHES_DIR, CODEFLAWS_RESULTS_DIR
from core.sandbox_adapter import get_sandbox_adapter

def extract_function_code(source_code, func_name):
    pattern = re.compile(
        r'\b(?:int|void|char|double|float|long|unsigned|short|struct|static)?\s*\*?\s*' + 
        re.escape(func_name) + r'\s*\([^)]*\)\s*\{', 
        re.MULTILINE
    )
    match = pattern.search(source_code)
    if not match:
        if func_name == "main":
            pattern = re.compile(r'\bmain\s*\([^)]*\)\s*\{', re.MULTILINE)
            match = pattern.search(source_code)
            if not match:
                return None, -1, -1
        else:
            return None, -1, -1

    start_idx = match.start()
    open_braces = 0
    in_func = False
    
    for i in range(match.end() - 1, len(source_code)):
        char = source_code[i]
        if char == '{':
            open_braces += 1
            in_func = True
        elif char == '}':
            open_braces -= 1
            if in_func and open_braces == 0:
                return source_code[start_idx:i+1], start_idx, i+1
                
    return None, -1, -1

def generate_mutants(func_code):
    """
    Sinh ra các biến thể (mutants) của một hàm nhằm mò mẫm cách sửa lỗi (Heuristic Search).
    Tập trung vào lỗi phổ biến trong Codeforces: sai điều kiện (>, <), sai dấu (+, -), sai Index khởi tạo.
    """
    mutants = []
    
    # Định nghĩa các luật đột biến đơn giản bằng Regex (có thêm khoảng trắng để tránh dính vào ++, -- hoặc <=)
    rules = [
        # Đột biến toán tử quan hệ
        (r'(?<=\w)\s*<\s*(?=\w)', [' <= ', ' > ', ' >= ', ' == ', ' != ']),
        (r'(?<=\w)\s*>\s*(?=\w)', [' >= ', ' < ', ' <= ', ' == ', ' != ']),
        (r'(?<=\w)\s*<=\s*(?=\w)', [' < ', ' == ']),
        (r'(?<=\w)\s*>=\s*(?=\w)', [' > ', ' == ']),
        (r'(?<=\w)\s*==\s*(?=\w)', [' != ', ' <= ', ' >= ']),
        (r'(?<=\w)\s*!=\s*(?=\w)', [' == ']),
        # Đột biến toán tử số học
        (r'(?<=\w)\s*\+\s*(?=\w)', [' - ']),
        (r'(?<=\w)\s*-\s*(?=\w)', [' + ']),
        # Đột biến Off-by-one (Lỗi chênh lệch 1 đơn vị)
        (r'(\+\s*1)\b', ['- 1', '']),
        (r'(-\s*1)\b', ['+ 1', ''])
    ]
    
    for pattern, replacements in rules:
        for match in re.finditer(pattern, func_code):
            original = match.group(0)
            for rep in replacements:
                if rep.strip() != original.strip():
                    # Chỉ thay thế duy nhất khớp lệnh hiện tại để chia nhỏ mutant
                    mutant = func_code[:match.start()] + rep + func_code[match.end():]
                    if mutant not in [m[0] for m in mutants]:
                        mutants.append((mutant, f"Đổi '{original.strip()}' thành '{rep.strip()}'"))
                        
    return mutants

# Đã chuyển validation logic vào core/sandbox_adapter.py
def validate_patch(patched_file_path, bug_id, dataset="codeflaws"):
    """
    Sử dụng Adapter tương ứng với bộ dataset để kiểm chứng bản vá trong hộp cát (Sandbox).
    """
    try:
        adapter = get_sandbox_adapter(dataset, bug_id)
        return adapter.validate(patched_file_path)
    except Exception as e:
        print(f"    [Error] Cannot validate patch using adapter: {e}")
        return False, [], []

def run_mutation_pipeline(dataset="codeflaws"):
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)
    tarantula_results_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_results_file):
        print(f"Error: {tarantula_results_file} not found. Run FL first.")
        return

    with open(tarantula_results_file, "r") as f:
        fl_results = json.load(f)

    apr_results = {}
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_mutation_results.json")
    if os.path.exists(apr_results_file):
        try:
            with open(apr_results_file, "r") as f:
                apr_results = json.load(f)
        except Exception:
            pass

    print("Đang chạy quy trình APR bằng Heuristic Mutation (Local, No LLM)...")
    
    for bug_id, result_data in fl_results.items():
        if bug_id in apr_results and apr_results[bug_id].get("status") != "skipped":
            continue 
            
        scores = result_data.get('scores', {}) if isinstance(result_data, dict) else result_data
        if not scores:
            continue
            
        sorted_funcs = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        print(f"\nProcessing bug {bug_id}...")
        
        # Lấy file source qua Dataset Adapter thống nhất
        try:
            adapter = get_sandbox_adapter(dataset, bug_id)
            bug_source_path = adapter.get_source_path()
        except Exception as e:
            print(f"Lỗi khởi tạo Adapter cho bug {bug_id}: {e}")
            continue
        
        if not os.path.exists(bug_source_path):
            print(f"Source file not found for {bug_id}, skipping...")
            continue
            
        with open(bug_source_path, 'r') as f:
            source_code = f.read()

        status = "failed"
        patched_func = None
        target_func = None
        best_post_passed = []
        best_post_failed = []
        best_mutant_desc = ""

        # Lặp qua các hàm bị nghi ngờ
        for func_name, score in sorted_funcs:
            if score == 0.0: continue
            
            print(f"  - Đang đột biến hàm '{func_name}' (Điểm nghi ngờ: {score:.4f})")
            func_code, start_idx, end_idx = extract_function_code(source_code, func_name)
            if not func_code:
                continue
                
            target_func = func_name
            mutants = generate_mutants(func_code)
            print(f"    -> Đã tạo {len(mutants)} biến thể (mutants) để đưa vào Sandbox...")
            
            found_fix = False
            # Check từng mutant
            for i, (m_code, m_desc) in enumerate(mutants):
                patched_source = source_code[:start_idx] + m_code + source_code[end_idx:]
                tmp_source_path = os.path.join(EXPERIMENTS_DIR, f"tmp_{bug_id}.c")
                
                with open(tmp_source_path, 'w') as f:
                    f.write(patched_source)
                    
                is_valid, post_passed_tests, post_failed_tests = validate_patch(tmp_source_path, bug_id)
                
                if is_valid:
                    print(f"    [SUCCESS] Phiên bản thứ {i} ĐÃ VƯỢT QUA TEST! ({m_desc})")
                    status = "success"
                    patched_func = m_code
                    best_mutant_desc = m_desc
                    
                    patch_save_path = os.path.join(PATCHES_DIR, f"{bug_id}_mutation_patch.c")
                    os.makedirs(PATCHES_DIR, exist_ok=True)
                    os.rename(tmp_source_path, patch_save_path)
                    
                    best_post_passed = post_passed_tests
                    best_post_failed = []
                    found_fix = True
                    break
                else:
                    # Ghi nhận trạng thái compile error hoặc logic error
                    best_post_passed = post_passed_tests
                    best_post_failed = post_failed_tests
                    
                if os.path.exists(tmp_source_path):
                    os.remove(tmp_source_path)

            if found_fix:
                break # Đã fix xong một hàm, chuyển sang Bug khác

        # Lấy Test gốc để Log
        init_passed = []
        init_failed = []
        json_path = os.path.join(CODEFLAWS_RESULTS_DIR, f"{bug_id}.json")
        if os.path.exists(json_path):
            try:
                with open(json_path, 'r') as f:
                    data = json.load(f)
                tests = data.get("tests", [])
                init_passed = [t.get("test_id") for t in tests if t.get("outcome") == "PASS"]
                init_failed = [t.get("test_id") for t in tests if t.get("outcome") == "FAIL"]
            except Exception:
                pass

        apr_results[bug_id] = {
            "status": status,
            "patched_function": patched_func,
            "selected_function": target_func,
            "mutation_strategy": best_mutant_desc,
            "init_passed_tests": init_passed,
            "init_failed_tests": init_failed,
            "post_passed_tests": best_post_passed,
            "post_failed_tests": best_post_failed
        }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)

if __name__ == "__main__":
    run_mutation_pipeline()
