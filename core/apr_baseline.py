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
    # Example logic (mocked):
    # cmd = ["python3", "../codeflaws/data_collector.py", "--compile", patched_file_path]
    # result = subprocess.run(cmd, capture_output=True, text=True)
    # return "All tests passed" in result.stdout
    print(f"Validating patch for {bug_id}...")
    # For now, randomly return a success or failure, or just return false
    return False # Default to False for safety in baseline

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
        # Vì đây chỉ là structure mẫu, giả định ta tìm thấy file .c của nó.
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, bug_id)
        
        # Format Codeflaws thường là source file giống ID
        # Ví dụ 104-A-bug-13890222-13890242.c
        bug_source_path = os.path.join(bug_dir, f"{bug_id.split('-bug-')[0]}-{bug_id.split('-')[-1]}.c") 
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
