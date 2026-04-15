import os
import json
import re
import subprocess
import shutil

from configs.path import EXPERIMENTS_DIR, CODEFLAWS_SOURCE_DIR, PATCHES_DIR, CODEFLAWS_RESULTS_DIR

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

def validate_patch(patched_file_path, bug_id):
    bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, bug_id)
    bug_file_prefix = "-".join(bug_id.split("-bug-")[0].split("-"))
    bug_file_suffix = bug_id.split("-bug-")[1].split("-")[0]
    expected_name = f"{bug_file_prefix}-{bug_file_suffix}.c"
    
    original_file = os.path.join(bug_dir, expected_name)
    backup_file = os.path.join(bug_dir, f"{expected_name}.bak")
    
    if not os.path.exists(original_file):
        return False, [], []

    is_valid = False
    try:
        shutil.copy2(original_file, backup_file)
        shutil.copy2(patched_file_path, original_file)

        compile_cmd = ["make", f"FILENAME={expected_name.replace('.c', '')}"]
        compile_process = subprocess.run(compile_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if compile_process.returncode != 0:
            compile_cmd = ["gcc", expected_name, "-o", expected_name.replace(".c", "")]
            compile_process = subprocess.run(compile_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if compile_process.returncode != 0:
                return False, [], ["Compilation Error"]

        test_script_content = ""
        with open(os.path.join(bug_dir, "test-genprog.sh"), 'r') as f:
            test_script_content = f.read()

        import re
        test_cases = re.findall(r'^([np]\d+)\)', test_script_content, re.MULTILINE)
        
        all_passed = True
        failed_tests = []
        passed_tests = []
        for tc in test_cases:
            test_cmd = ["bash", "test-genprog.sh", tc]
            test_process = subprocess.run(test_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            
            if tc.startswith('p'):
                normalized_tc = "pos" + tc[1:]
            elif tc.startswith('n'):
                normalized_tc = "neg" + tc[1:]
            else:
                normalized_tc = tc
            
            if test_process.returncode != 0:
                all_passed = False
                failed_tests.append(normalized_tc)
            else:
                passed_tests.append(normalized_tc)

        if all_passed and len(test_cases) > 0:
            is_valid = True

    finally:
        shutil.move(backup_file, original_file)
        exe_file = os.path.join(bug_dir, expected_name.replace(".c", ""))
        a_out_path = os.path.join(bug_dir, "a.out")
        if os.path.exists(exe_file):
            os.remove(exe_file)
        if os.path.exists(a_out_path):
            os.remove(a_out_path)

    return is_valid, passed_tests if 'passed_tests' in locals() else [], failed_tests if 'failed_tests' in locals() else []

def run_mutation_pipeline():
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
        
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, bug_id)
        bug_file_prefix = "-".join(bug_id.split("-bug-")[0].split("-"))
        bug_file_suffix = bug_id.split("-bug-")[1].split("-")[0]
        bug_source_path = os.path.join(bug_dir, f"{bug_file_prefix}-{bug_file_suffix}.c")
        
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
