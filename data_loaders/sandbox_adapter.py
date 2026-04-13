import os
import shutil
import subprocess
import re
from configs.path import CODEFLAWS_SOURCE_DIR

class SandboxAdapter:
    """Class Cầu nối cơ sở để chuẩn hoá mọi dataset (Codeflaws, Defects4C, Defects4J)"""
    def __init__(self, bug_id):
        self.bug_id = bug_id

    def get_source_path(self):
        """Trả về đường dẫn tuyệt đối đến file mã nguồn đang chứa lỗi"""
        raise NotImplementedError("Phải trả về đường dẫn tuyệt đối đến file mã nguồn cần sửa")

    def validate(self, patched_file_path):
        """
        Nhận vào đường dẫn file tạm đã được vá:
        1. Backup file gốc.
        2. Dán đè file vá rỗi biên dịch / chạy test.
        3. Phục hồi file gốc và xóa rác.
        Trả về tupple: (is_valid: bool, passed_tests: list, failed_tests: list)
        """
        raise NotImplementedError("Phải trả về (is_valid, post_passed_tests, post_failed_tests)")

class CodeflawsAdapter(SandboxAdapter):
    """Adapter xử lý thư mục và kịch bản Bash đặc thù của Codeflaws"""
    def get_source_path(self):
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, self.bug_id)
        bug_file_prefix = "-".join(self.bug_id.split("-bug-")[0].split("-"))
        bug_file_suffix = self.bug_id.split("-bug-")[1].split("-")[0]
        return os.path.join(bug_dir, f"{bug_file_prefix}-{bug_file_suffix}.c")
        
    def validate(self, patched_file_path):
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, self.bug_id)
        original_file = self.get_source_path()
        expected_name = os.path.basename(original_file)
        backup_file = os.path.join(bug_dir, f"{expected_name}.bak")
        
        if not os.path.exists(original_file):
            return False, [], []

        is_valid = False
        failed_tests = []
        passed_tests = []
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

            test_cases = re.findall(r'^([np]\d+)\)', test_script_content, re.MULTILINE)
            all_passed = True
            
            for tc in test_cases:
                test_cmd = ["bash", "test-genprog.sh", tc]
                test_process = subprocess.run(test_cmd, cwd=bug_dir, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                
                normalized_tc = "pos" + tc[1:] if tc.startswith('p') else ("neg" + tc[1:] if tc.startswith('n') else tc)
                
                if test_process.returncode != 0:
                    all_passed = False
                    failed_tests.append(normalized_tc)
                else:
                    passed_tests.append(normalized_tc)

            if all_passed and len(test_cases) > 0:
                is_valid = True
                
        finally:
            if os.path.exists(backup_file):
                shutil.move(backup_file, original_file)
            exe_file = os.path.join(bug_dir, expected_name.replace(".c", ""))
            a_out_path = os.path.join(bug_dir, "a.out")
            if os.path.exists(exe_file): os.remove(exe_file)
            if os.path.exists(a_out_path): os.remove(a_out_path)

        return is_valid, passed_tests, failed_tests

def get_sandbox_adapter(dataset_name, bug_id):
    """Factory để cấp phát Adapter tùy theo dataset_name truyền vào"""
    if dataset_name.lower() == "codeflaws":
        return CodeflawsAdapter(bug_id)
    
    # elif dataset_name.lower() == "defects4c":
    #    return StandardJSONAdapter(bug_id)
        
    raise ValueError(f"Dataset '{dataset_name}' chưa có Adapter tương ứng hỗ trợ!")
