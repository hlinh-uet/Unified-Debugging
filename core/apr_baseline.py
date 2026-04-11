import os
import json
import re
import subprocess

from configs.path import EXPERIMENTS_DIR, CODEFLAWS_SOURCE_DIR, PATCHES_DIR

def extract_function_code(source_code, func_name):
    """
    Very basic heuristic to extract a C function by name using regex and brace matching.
    For production, consider using pycparser or tree-sitter.
    """
    pattern = re.compile(r'\b(?:int|void|char|double|float|long|unsigned|short|struct|static)\s+[\w\*\s]+\b' + func_name + r'\s*\([^)]*\)\s*\{', re.MULTILINE)
    match = pattern.search(source_code)
    if not match:
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

def call_llm(prompt):
    """
    Placeholder for LLM API call (e.g., OpenAI API, Claude, etc.)
    Returns the patched C code fragment.
    """
    # TODO: Implement actual LLM call here
    return "// PATCHED CODE FROM LLM\n"

def validate_patch(patched_file_path, bug_id):
    """
    Placeholder for validation logic.
    You can compile the patched_file_path and run tests manually, 
    or call the existing `data_collector.py` script.
    """
    print(f"Validating patch for {bug_id}...")
    
    # We will use the test-valid.sh script from codeflaws project to validate the patch
    import shutil
    
    bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, bug_id)
    bug_file_prefix = "-".join(bug_id.split("-bug-")[0].split("-"))
    bug_file_suffix = bug_id.split("-bug-")[1].split("-")[0]
    expected_name = f"{bug_file_prefix}-{bug_file_suffix}.c"
    
    original_file = os.path.join(bug_dir, expected_name)
    backup_file = os.path.join(bug_dir, f"{expected_name}.bak")
    
    if not os.path.exists(original_file):
        return False

    is_valid = False
    try:
        shutil.copy2(original_file, backup_file)
        shutil.copy2(patched_file_path, original_file)

        # Run compilation using Makefile inside the bug dir (since they have it)
        compile_cmd = ["make", f"FILENAME={expected_name.replace('.c', '')}"]
        compile_process = subprocess.run(compile_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        if compile_process.returncode != 0:
            # Fallback to gcc if make fails (sometimes makefile uses different format)
            compile_cmd = ["gcc", expected_name, "-o", expected_name.replace(".c", "")]
            compile_process = subprocess.run(compile_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            if compile_process.returncode != 0:
                return False

        # Build list of tests dynamically by looking at test-genprog.sh
        test_script_content = ""
        with open(os.path.join(bug_dir, "test-genprog.sh"), 'r') as f:
            test_script_content = f.read()

        import re
        # Find all test cases e.g., p1), p2), n1)
        test_cases = re.findall(r'^([np]\d+)\)', test_script_content, re.MULTILINE)
        
        all_passed = True
        for tc in test_cases:
            test_cmd = ["bash", "test-genprog.sh", tc]
            test_process = subprocess.run(test_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            # The script exits with 0 on success, >0 on failure
            if test_process.returncode != 0:
                all_passed = False
                break

        if all_passed and len(test_cases) > 0:
            is_valid = True

    finally:
        shutil.move(backup_file, original_file)
        # Cleanup binary
        exe_file = os.path.join(bug_dir, expected_name.replace(".c", ""))
        a_out_path = os.path.join(bug_dir, "a.out")
        if os.path.exists(exe_file):
            os.remove(exe_file)
        if os.path.exists(a_out_path):
            os.remove(a_out_path)

    return is_valid

def run_apr_pipeline():
    os.makedirs(PATCHES_DIR, exist_ok=True)
    
    tarantula_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_file):
        print(f"Tarantula results not found at {tarantula_file}")
        return

    with open(tarantula_file, 'r') as f:
        tarantula_results = json.load(f)

    for bug_id, scores in tarantula_results.items():
        if not scores:
            continue
            
        # 1. Sort functions by suspiciousness (descending)
        sorted_funcs = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        print(f"Processing bug {bug_id}...")
        
        # Load source code
        # Tìm file source logic thực tế của dataset codeflaws (đôi khi nằm dưới các sub-directories)
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, bug_id)
        
        # Format Codeflaws thường là source file giống ID
        # Ví dụ 104-A-bug-13890222-13890242.c -> 104-A-13890222.c
        bug_file_prefix = "-".join(bug_id.split("-bug-")[0].split("-"))
        bug_file_suffix = bug_id.split("-bug-")[1].split("-")[0]
        bug_source_path = os.path.join(bug_dir, f"{bug_file_prefix}-{bug_file_suffix}.c")
        
        if not os.path.exists(bug_source_path):
            print(f"Source file not found for {bug_id} at {bug_source_path}, skipping...")
            continue
            
        with open(bug_source_path, 'r') as f:
            source_code = f.read()

        for func_name, score in sorted_funcs:
            if score == 0.0:
                continue # Skip not suspicious functions
                
            print(f"  - Inspecting function '{func_name}' (Score: {score:.4f})")
            
            # 2. Extract function source
            func_code, start_idx, end_idx = extract_function_code(source_code, func_name)
            if not func_code:
                print(f"    WARNING: Could not extract function {func_name}")
                continue
                
            prompt = f"Đây là hàm C bị lỗi trong bug {bug_id}, hãy sửa nó:\n\n{func_code}\n\nChỉ trả về mã C đã sửa, không giải thích."
            
            # 3. Call LLM to get patch
            patched_func = call_llm(prompt)
            
            # 4. Integrate patch into temporary source code
            patched_source = source_code[:start_idx] + patched_func + source_code[end_idx:]
            
            tmp_source_path = os.path.join(EXPERIMENTS_DIR, f"tmp_{bug_id}.c")
            with open(tmp_source_path, 'w') as f:
                f.write(patched_source)
                
            # 5. Validation
            is_valid = validate_patch(tmp_source_path, bug_id)
            
            if is_valid:
                print(f"    [SUCCESS] Found valid patch for {bug_id} in function {func_name}!")
                patch_save_path = os.path.join(PATCHES_DIR, f"{bug_id}_patch.c")
                os.rename(tmp_source_path, patch_save_path)
                break # Move to next bug once fixed
            else:
                print(f"    [FAIL] Patch failed validation.")
                if os.path.exists(tmp_source_path):
                    os.remove(tmp_source_path)

if __name__ == "__main__":
    run_apr_pipeline()
