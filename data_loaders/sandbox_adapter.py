import os
import shutil
import subprocess
import re
import glob
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
        2. Dán đè file vá rồi biên dịch / chạy test.
        3. Phục hồi file gốc và xóa rác.
        Trả về tuple: (is_valid: bool, passed_tests: list, failed_tests: list)
        """
        raise NotImplementedError("Phải trả về (is_valid, post_passed_tests, post_failed_tests)")

class CodeflawsAdapter(SandboxAdapter):
    """
    Adapter xử lý thư mục và kịch bản đặc thù của Codeflaws.

    Thay vì gọi test-genprog.sh (phụ thuộc GNU time/diff, không chạy trên macOS),
    adapter tự compile bằng Makefile, chạy chương trình, và so sánh output bằng Python.
    """
    def get_source_path(self):
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, self.bug_id)
        bug_file_prefix = "-".join(self.bug_id.split("-bug-")[0].split("-"))
        bug_file_suffix = self.bug_id.split("-bug-")[1].split("-")[0]
        return os.path.join(bug_dir, f"{bug_file_prefix}-{bug_file_suffix}.c")

    def _parse_test_cases(self, bug_dir):
        """
        Phát hiện tất cả test cases có sẵn trong thư mục bug dựa trên file input-*/output-*.
        Trả về list of (test_id, input_file, expected_output_file).
        """
        test_cases = []
        for inp in sorted(glob.glob(os.path.join(bug_dir, "input-pos*"))):
            basename = os.path.basename(inp)
            num = basename.replace("input-pos", "")
            out = os.path.join(bug_dir, f"output-pos{num}")
            if os.path.exists(out):
                test_cases.append((f"pos{num}", inp, out))

        for inp in sorted(glob.glob(os.path.join(bug_dir, "input-neg*"))):
            basename = os.path.basename(inp)
            num = basename.replace("input-neg", "")
            out = os.path.join(bug_dir, f"output-neg{num}")
            if os.path.exists(out):
                test_cases.append((f"neg{num}", inp, out))

        for inp in sorted(glob.glob(os.path.join(bug_dir, "input-heldout-pos*"))):
            basename = os.path.basename(inp)
            tag = basename.replace("input-", "")
            out = os.path.join(bug_dir, f"output-{tag}")
            if os.path.exists(out):
                test_cases.append((tag, inp, out))

        for inp in sorted(glob.glob(os.path.join(bug_dir, "input-heldout-neg*"))):
            basename = os.path.basename(inp)
            tag = basename.replace("input-", "")
            out = os.path.join(bug_dir, f"output-{tag}")
            if os.path.exists(out):
                test_cases.append((tag, inp, out))

        return test_cases

    def validate(self, patched_file_path):
        bug_dir = os.path.join(CODEFLAWS_SOURCE_DIR, self.bug_id)
        original_file = self.get_source_path()
        expected_name = os.path.basename(original_file)
        exe_name = expected_name.replace(".c", "")
        backup_file = os.path.join(bug_dir, f"{expected_name}.bak")

        if not os.path.exists(original_file):
            return False, [], []

        is_valid = False
        failed_tests = []
        passed_tests = []
        try:
            shutil.copy2(original_file, backup_file)
            patched_file_path = os.path.abspath(patched_file_path)
            if patched_file_path != os.path.abspath(original_file):
                shutil.copy2(patched_file_path, original_file)

            compile_ok = self._compile(bug_dir, expected_name, exe_name)
            if not compile_ok:
                return False, [], ["Compilation Error"]

            exe_path = os.path.join(bug_dir, exe_name)
            test_cases = self._parse_test_cases(bug_dir)

            if not test_cases:
                return False, [], ["No test cases found"]

            for tc_id, input_file, expected_output_file in test_cases:
                passed = self._run_one_test(exe_path, input_file, expected_output_file)
                if passed:
                    passed_tests.append(tc_id)
                else:
                    failed_tests.append(tc_id)

            if not failed_tests and len(passed_tests) > 0:
                is_valid = True

        finally:
            if os.path.exists(backup_file):
                shutil.move(backup_file, original_file)
            exe_file = os.path.join(bug_dir, exe_name)
            obj_file = os.path.join(bug_dir, f"{exe_name}.o")
            for f in [exe_file, obj_file]:
                if os.path.exists(f):
                    os.remove(f)

        return is_valid, passed_tests, failed_tests

    def _compile(self, bug_dir, source_name, exe_name):
        """Compile sử dụng Makefile, fallback sang gcc trực tiếp."""
        makefile = os.path.join(bug_dir, "Makefile")

        if os.path.exists(makefile):
            result = subprocess.run(
                ["make", f"FILENAME={exe_name}"],
                cwd=bug_dir,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30
            )
            if result.returncode == 0:
                return True

        result = subprocess.run(
            [
                "gcc",
                "-fno-optimize-sibling-calls", "-fno-strict-aliasing",
                "-fno-asm", "-std=c99",
                "-Wno-error=implicit-function-declaration",
                "-O0",
                source_name, "-o", exe_name, "-lm"
            ],
            cwd=bug_dir,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30
        )
        return result.returncode == 0

    def _run_one_test(self, exe_path, input_file, expected_output_file, timeout=10):
        """
        Chạy exe với input, so sánh stdout với expected output.
        So sánh ignore trailing whitespace mỗi dòng (tương đương diff --ignore-trailing-space).
        """
        try:
            with open(input_file, "r") as f_in:
                proc = subprocess.run(
                    [exe_path],
                    stdin=f_in,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                    timeout=timeout
                )
        except subprocess.TimeoutExpired:
            return False
        except Exception:
            return False

        actual = proc.stdout or ""

        try:
            with open(expected_output_file, "r") as f:
                expected = f.read()
        except Exception:
            return False

        return _compare_output(actual, expected)


def _compare_output(actual: str, expected: str) -> bool:
    """
    So sánh output giống diff --brief --ignore-trailing-space:
    bỏ qua trailing whitespace mỗi dòng, bỏ qua trailing newlines cuối file.
    """
    actual_lines = [line.rstrip() for line in actual.splitlines()]
    expected_lines = [line.rstrip() for line in expected.splitlines()]

    while actual_lines and actual_lines[-1] == "":
        actual_lines.pop()
    while expected_lines and expected_lines[-1] == "":
        expected_lines.pop()

    return actual_lines == expected_lines


def get_sandbox_adapter(dataset_name, bug_id):
    """Factory để cấp phát Adapter tùy theo dataset_name truyền vào"""
    if dataset_name.lower() == "codeflaws":
        return CodeflawsAdapter(bug_id)

    raise ValueError(f"Dataset '{dataset_name}' chưa có Adapter tương ứng hỗ trợ!")
