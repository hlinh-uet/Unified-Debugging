import os
import signal
import shutil
import shlex
import subprocess
from typing import Optional, Tuple
import re
import glob
import hashlib
from configs.path import CODEFLAWS_SOURCE_DIR, DEFECTS4C_OUT_DIR, DEFECTS4C_PATCHES_DIR
from core.utils import get_codeflaws_buggy_cfile
from data_loaders.defects4c_loader import (
    get_defects4c_raw_record,
    get_defects4c_source_path,
    parse_defects4c_bug_id,
)

class SandboxAdapter:
    """Class Cầu nối cơ sở để chuẩn hoá mọi dataset (Codeflaws, Defects4C, Defects4J)"""
    def __init__(self, bug_id):
        self.bug_id = bug_id

    def get_source_path(self):
        """Trả về đường dẫn tuyệt đối đến file mã nguồn đang chứa lỗi"""
        raise NotImplementedError("Phải trả về đường dẫn tuyệt đối đến file mã nguồn cần sửa")

    def validate(self, patched_file_path, src_basename=None):
        """
        Nhận vào đường dẫn file tạm đã được vá:
        1. Backup file gốc.
        2. Dán đè file vá rồi biên dịch / chạy test.
        3. Phục hồi file gốc và xóa rác.

        Args:
            patched_file_path: Đường dẫn file đã được vá (host).
            src_basename:      Basename của file mã nguồn mà patch này nhằm
                               thay thế (vd: ``print-isakmp.c``). Cần thiết
                               khi FL chỉ ra lỗi ở một file phụ thay vì file
                               chính. Nếu None, adapter dùng file chính.

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
        bug_dir   = os.path.join(CODEFLAWS_SOURCE_DIR, self.bug_id)
        cfilename = get_codeflaws_buggy_cfile(self.bug_id)
        return os.path.join(bug_dir, cfilename)

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

    def validate(self, patched_file_path, src_basename=None):
        # Codeflaws chỉ có 1 file .c cho mỗi bug → bỏ qua src_basename.
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
                print(f"    [Sandbox] Compilation failed cho {self.bug_id}.")
                return False, [], []   # không đưa 'Compilation Error' vào post_failed_tests để tránh sai metrics

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

        Dùng stdin=PIPE + communicate(input=data) để Python quản lý cả stdin/stdout
        qua pipe — timeout mới hoạt động đúng trên mọi nền tảng (kể cả macOS Python 3.9).
        Dùng start_new_session=True + os.killpg(SIGKILL) để kill toàn process group.
        """
        try:
            with open(input_file, "r") as f:
                input_data = f.read()
            with open(expected_output_file, "r") as f:
                expected = f.read()
        except Exception:
            return False

        try:
            proc = subprocess.Popen(
                [exe_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                start_new_session=True,  # proc.pid == pgid khi dùng start_new_session
            )
            try:
                stdout, _ = proc.communicate(input=input_data, timeout=timeout)
            except subprocess.TimeoutExpired:
                # SIGKILL toàn bộ process group
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError):
                    proc.kill()
                # Drain pipes với timeout ngắn để tránh block vô hạn
                try:
                    proc.communicate(timeout=2)
                except subprocess.TimeoutExpired:
                    pass
                return False
        except Exception:
            try:
                proc.kill()
                proc.wait()
            except Exception:
                pass
            return False

        return _compare_output(stdout or "", expected)


class Defects4CAdapter(SandboxAdapter):
    """Adapter validate patch Defects4C qua Docker/local service đã warmup."""

    def get_source_path(self):
        return get_defects4c_source_path(self.bug_id)

    def validate(self, patched_file_path, src_basename=None):
        raw = get_defects4c_raw_record(self.bug_id)
        if not raw:
            return False, [], ["metadata_not_found"]

        project, sha = parse_defects4c_bug_id(self.bug_id)
        bug_meta = raw.get("raw", raw)
        # Chọn basename từ caller nếu có; nếu không, fallback về src chính
        # của bug. Việc này bắt buộc để helper trong container áp patch vào
        # đúng file khi FL/APR nhắm tới file phụ thay vì file bug chính.
        if not src_basename:
            src_file = bug_meta.get("files", {}).get("src", ["patched.c"])[0]
            src_basename = os.path.basename(src_file)

        commit_before = bug_meta.get("commit_before") or bug_meta.get("sha_before")
        if not commit_before:
            return False, [], ["missing_commit_before"]

        test_ids = self._collect_defects4c_test_ids(project, sha)
        try:
            with open(patched_file_path, "rb") as f:
                content = f.read()
        except Exception:
            return False, [], ["patch_read_error"]

        # Giữ artifact patch như luồng cũ để tiện trace/debug.
        md5 = hashlib.md5(content).hexdigest()
        host_patch_dir = os.path.join(DEFECTS4C_PATCHES_DIR, project, "unified_debugging")
        os.makedirs(host_patch_dir, exist_ok=True)
        host_patch_path = os.path.join(host_patch_dir, f"{md5}@{sha}___{src_basename}")
        with open(host_patch_path, "wb") as f:
            f.write(content)

        # Phase A cho APR:
        #   1) reset về buggy commit
        #   2) checkout tests từ commit_after
        #   3) chép patch vào file buggy
        #   4) build ASAN + chạy full TESTrun.sh
        if not self._prepare_phase_a_workspace(project, sha, commit_before):
            return False, [], ["phase_a_prepare_failed"]

        host_repo = os.path.join(DEFECTS4C_OUT_DIR, project, f"git_repo_dir_{sha}")
        target_src = self._resolve_source_path_in_repo(host_repo, src_basename)
        if not target_src:
            self._reset_defects4c_repo(project, sha)
            return False, [], [f"source_not_found:{src_basename}"]

        try:
            shutil.copy2(patched_file_path, target_src)
        except Exception:
            self._reset_defects4c_repo(project, sha)
            return False, [], [f"patch_copy_failed:{src_basename}"]

        full_ok = self._run_phase_a_full_suite(project, sha)
        self._reset_defects4c_repo(project, sha)
        if full_ok:
            return True, (test_ids or ["defects4c_full_suite"]), []
        return False, [], (test_ids or ["defects4c_full_suite"])

    @staticmethod
    def _defects4c_fix_shell(project: str, sha: str, container_patch: str) -> str:
        """
        Bash một dòng: chọn Python trong container (venv nếu có, không thì python3/python).
        Cho phép override: docker exec -e DEFECTS4C_PYTHON=/path/to/python
        """
        bug_id = f"{project}@{sha}"
        return (
            "cd /src && "
            "PY=''; "
            'if [ -n "$DEFECTS4C_PYTHON" ] && [ -x "$DEFECTS4C_PYTHON" ]; then PY="$DEFECTS4C_PYTHON"; '
            "elif [ -x /src/.venv/bin/python ]; then PY=/src/.venv/bin/python; "
            "elif command -v python3 >/dev/null 2>&1; then PY=$(command -v python3); "
            "elif command -v python >/dev/null 2>&1; then PY=$(command -v python); fi; "
            'if [ -z "$PY" ]; then echo "Defects4C: khong tim thay python trong /src" >&2; exit 127; fi; '
            f'exec "$PY" bug_helper_v1_out2.py fix {bug_id} {container_patch}'
        )

    def _resolve_defects4c_python_binary(self) -> Optional[str]:
        override = (os.getenv("DEFECTS4C_PYTHON") or "").strip()
        if override and os.path.isfile(override) and os.access(override, os.X_OK):
            return override
        venv_py = "/src/.venv/bin/python"
        if os.path.isfile(venv_py) and os.access(venv_py, os.X_OK):
            return venv_py
        return shutil.which("python3") or shutil.which("python")

    def _run_defects4c_fix(self, project, sha, host_patch_path):
        container = os.getenv("DEFECTS4C_CONTAINER", "my_defects4c_tcpdump")
        container_patch = self._container_patch_path(host_patch_path)
        inner = self._defects4c_fix_shell(project, sha, container_patch)

        if shutil.which("docker") and self._docker_container_running(container):
            cmd = ["docker", "exec"]
            py_host = (os.getenv("DEFECTS4C_PYTHON") or "").strip()
            if py_host:
                cmd.extend(["-e", f"DEFECTS4C_PYTHON={py_host}"])
            cmd.extend([container, "bash", "-lc", inner])
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60 * 30)
            if result.returncode != 0:
                err = result.stderr.decode("utf-8", errors="ignore")
                if err.strip():
                    print(err[-1000:])
            return result.returncode == 0

        if os.path.exists("/src/bug_helper_v1_out2.py"):
            py = self._resolve_defects4c_python_binary()
            if not py:
                print("    [Defects4C] Không tìm thấy python để chạy bug_helper (đặt DEFECTS4C_PYTHON).")
                return False
            cmd = [
                py,
                "bug_helper_v1_out2.py",
                "fix",
                f"{project}@{sha}",
                container_patch,
            ]
            result = subprocess.run(cmd, cwd="/src", stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=60 * 30)
            return result.returncode == 0

        print(
            "    [Defects4C] Không tìm thấy container Defects4C đang chạy. "
            "Hãy chạy Docker theo README hoặc đặt DEFECTS4C_CONTAINER."
        )
        return False

    def _reset_defects4c_repo(self, project: str, sha: str) -> bool:
        repo_rel = f"/out/{project}/git_repo_dir_{sha}"
        container = os.getenv("DEFECTS4C_CONTAINER", "my_defects4c_tcpdump")
        reset_cmd = (
            f"repo={repo_rel}; "
            "if [ -d \"$repo/.git\" ]; then "
            "cd \"$repo\" && git reset --hard && git clean -ffdx; "
            "fi"
        )
        if shutil.which("docker") and self._docker_container_running(container):
            cmd = ["docker", "exec", container, "bash", "-lc", reset_cmd]
            result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return result.returncode == 0

        host_repo = os.path.join(DEFECTS4C_OUT_DIR, project, f"git_repo_dir_{sha}")
        if os.path.isdir(os.path.join(host_repo, ".git")):
            r1 = subprocess.run(["git", "-C", host_repo, "reset", "--hard"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            r2 = subprocess.run(["git", "-C", host_repo, "clean", "-ffdx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            return r1.returncode == 0 and r2.returncode == 0
        return False

    def _prepare_phase_a_workspace(self, project: str, sha: str, commit_before: str) -> bool:
        container = os.getenv("DEFECTS4C_CONTAINER", "my_defects4c_tcpdump")
        repo_rel = f"/out/{project}/git_repo_dir_{sha}"
        prep_cmd = (
            f"repo={shlex.quote(repo_rel)}; "
            f"before={shlex.quote(commit_before)}; "
            "if [ ! -d \"$repo/.git\" ]; then exit 2; fi; "
            "git -C \"$repo\" reset --hard && "
            "git -C \"$repo\" clean -ffdx && "
            "git -C \"$repo\" checkout -f \"$before\" && "
            f"git -C \"$repo\" checkout {shlex.quote(sha)} -- tests"
        )
        if shutil.which("docker") and self._docker_container_running(container):
            result = subprocess.run(
                ["docker", "exec", container, "bash", "-lc", prep_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            return result.returncode == 0

        host_repo = os.path.join(DEFECTS4C_OUT_DIR, project, f"git_repo_dir_{sha}")
        if not os.path.isdir(os.path.join(host_repo, ".git")):
            return False
        r1 = subprocess.run(["git", "-C", host_repo, "reset", "--hard"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r2 = subprocess.run(["git", "-C", host_repo, "clean", "-ffdx"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r3 = subprocess.run(["git", "-C", host_repo, "checkout", "-f", commit_before], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        r4 = subprocess.run(["git", "-C", host_repo, "checkout", sha, "--", "tests"], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        return all(x.returncode == 0 for x in (r1, r2, r3, r4))

    def _resolve_source_path_in_repo(self, host_repo: str, src_basename: str) -> Optional[str]:
        direct = os.path.join(host_repo, src_basename)
        if os.path.isfile(direct):
            return direct
        matches = []
        for root, dirs, files in os.walk(host_repo):
            if ".git" in dirs:
                dirs.remove(".git")
            if src_basename in files:
                matches.append(os.path.join(root, src_basename))
        if not matches:
            return None
        if len(matches) > 1:
            print(f"    [Defects4C] WARN multiple candidates for {src_basename}, chọn {matches[0]}")
        return matches[0]

    def _run_phase_a_full_suite(self, project: str, sha: str) -> bool:
        container = os.getenv("DEFECTS4C_CONTAINER", "my_defects4c_tcpdump")
        repo_rel = f"/out/{project}/git_repo_dir_{sha}"
        cflags = "-O0 -g -fno-omit-frame-pointer -fno-common -fsanitize=address"
        ldflags = "-fsanitize=address"
        run_cmd = (
            f"repo={shlex.quote(repo_rel)}; "
            "if [ ! -d \"$repo/tests\" ]; then exit 2; fi; "
            "cd \"$repo\" && "
            f"CFLAGS={shlex.quote(cflags)} LDFLAGS={shlex.quote(ldflags)} ./configure --prefix=\"$repo\" >/dev/null 2>&1 && "
            "make -j\"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 4)\" >/dev/null 2>&1 && "
            "cd tests && timeout 1800 ./TESTrun.sh > \"$repo/apr_phaseA_fullsuite.log\" 2>&1; "
            "rc=$?; "
            "if [ $rc -ne 0 ]; then exit 1; fi; "
            "if grep -q \"TEST FAILED\" \"$repo/apr_phaseA_fullsuite.log\"; then exit 1; fi; "
            "exit 0"
        )
        if shutil.which("docker") and self._docker_container_running(container):
            result = subprocess.run(
                ["docker", "exec", container, "bash", "-lc", run_cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60 * 50,
            )
            return result.returncode == 0

        host_repo = os.path.join(DEFECTS4C_OUT_DIR, project, f"git_repo_dir_{sha}")
        if not os.path.isdir(os.path.join(host_repo, "tests")):
            return False
        try:
            subprocess.run(
                ["bash", "-lc", f"CFLAGS={shlex.quote(cflags)} LDFLAGS={shlex.quote(ldflags)} ./configure --prefix={shlex.quote(host_repo)} >/dev/null 2>&1 && make -j4 >/dev/null 2>&1"],
                cwd=host_repo,
                timeout=60 * 20,
                check=True,
            )
            log_path = os.path.join(host_repo, "apr_phaseA_fullsuite.log")
            with open(log_path, "w") as log_f:
                result = subprocess.run(
                    ["bash", "-lc", "timeout 1800 ./TESTrun.sh"],
                    cwd=os.path.join(host_repo, "tests"),
                    stdout=log_f,
                    stderr=log_f,
                    timeout=60 * 50,
                )
            if result.returncode != 0:
                return False
            with open(log_path, "r", errors="ignore") as f:
                return "TEST FAILED" not in f.read()
        except Exception:
            return False

    def _run_defects4c_full_suite(self, project: str, sha: str) -> Tuple[bool, list, list]:
        test_ids = self._collect_defects4c_test_ids(project, sha)
        container = os.getenv("DEFECTS4C_CONTAINER", "my_defects4c_tcpdump")
        repo_rel = f"/out/{project}/git_repo_dir_{sha}"
        cmd = (
            f"repo={repo_rel}; "
            "if [ ! -d \"$repo/tests\" ]; then exit 2; fi; "
            "cd \"$repo/tests\" && timeout 1800 ./TESTrun.sh > \"$repo/apr_fullsuite.log\" 2>&1; "
            "rc=$?; "
            "if [ $rc -ne 0 ]; then exit 1; fi; "
            "if grep -q \"TEST FAILED\" \"$repo/apr_fullsuite.log\"; then exit 1; fi; "
            "exit 0"
        )

        if shutil.which("docker") and self._docker_container_running(container):
            result = subprocess.run(
                ["docker", "exec", container, "bash", "-lc", cmd],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=60 * 40,
            )
            if result.returncode == 0:
                return True, (test_ids or ["defects4c_full_suite"]), []
            return False, [], (test_ids or ["defects4c_full_suite"])

        host_repo = os.path.join(DEFECTS4C_OUT_DIR, project, f"git_repo_dir_{sha}")
        tests_dir = os.path.join(host_repo, "tests")
        if not os.path.isdir(tests_dir):
            return False, [], (test_ids or ["defects4c_full_suite"])
        try:
            log_path = os.path.join(host_repo, "apr_fullsuite.log")
            with open(log_path, "w") as log_f:
                result = subprocess.run(
                    ["bash", "-lc", "timeout 1800 ./TESTrun.sh"],
                    cwd=tests_dir,
                    stdout=log_f,
                    stderr=log_f,
                    timeout=60 * 40,
                )
            if result.returncode == 0:
                try:
                    with open(log_path, "r", errors="ignore") as f:
                        if "TEST FAILED" in f.read():
                            return False, [], (test_ids or ["defects4c_full_suite"])
                except Exception:
                    pass
                return True, (test_ids or ["defects4c_full_suite"]), []
            return False, [], (test_ids or ["defects4c_full_suite"])
        except Exception:
            return False, [], (test_ids or ["defects4c_full_suite"])

    def _collect_defects4c_test_ids(self, project: str, sha: str) -> list:
        host_testlist = os.path.join(
            DEFECTS4C_OUT_DIR,
            project,
            f"git_repo_dir_{sha}",
            "tests",
            "TESTLIST",
        )
        if not os.path.isfile(host_testlist):
            return []
        ids = []
        try:
            with open(host_testlist, "r", errors="ignore") as f:
                for line in f:
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    parts = s.split()
                    if parts:
                        ids.append(parts[0])
        except Exception:
            return []
        return ids

    def _docker_container_running(self, container):
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", container],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return result.returncode == 0 and result.stdout.decode().strip() == "true"

    def _container_patch_path(self, host_patch_path):
        rel = os.path.relpath(host_patch_path, DEFECTS4C_PATCHES_DIR)
        return "/patches/" + rel.replace(os.sep, "/")

    def _read_status_values(self, project, sha, md5):
        status_paths = [
            os.path.join(os.path.dirname(DEFECTS4C_PATCHES_DIR), "out_tmp_dirs", project, "logs", f"patch_{sha}_{md5}.status"),
            f"/out/{project}/logs/patch_{sha}_{md5}.status",
        ]
        for path in status_paths:
            if os.path.exists(path):
                try:
                    with open(path, "r") as f:
                        return [line.strip() for line in f if line.strip()]
                except Exception:
                    return []
        return []


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


def defects4c_docker_ready() -> Tuple[bool, str]:
    """
    Kiểm tra APR/validate Defects4C có thể chạy không (Docker + container đang Running).

    Returns:
        (True, container_name) nếu tìm được container phù hợp.
        (False, message) nếu thiếu Docker hoặc không có container nào đang chạy.
    """
    if not shutil.which("docker"):
        return False, "Docker không có trong PATH — validate patch Defects4C cần Docker."

    candidates = []
    env_c = (os.getenv("DEFECTS4C_CONTAINER") or "").strip()
    if env_c:
        candidates.append(env_c)
    for name in ("my_defects4c_tcpdump", "my_defects4c"):
        if name not in candidates:
            candidates.append(name)

    for name in candidates:
        result = subprocess.run(
            ["docker", "inspect", "-f", "{{.State.Running}}", name],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
        )
        if result.returncode == 0 and result.stdout.decode().strip() == "true":
            return True, name

    tried = ", ".join(candidates)
    hint = env_c or "my_defects4c_tcpdump"
    return (
        False,
        f"Không có container Defects4C đang chạy (đã thử: {tried}). "
        f"Khởi container rồi chạy lại, hoặc đặt DEFECTS4C_CONTAINER và docker start <tên>. "
        f"Ví dụ: docker start {hint}",
    )


def get_sandbox_adapter(dataset_name, bug_id):
    """Factory để cấp phát Adapter tùy theo dataset_name truyền vào"""
    if dataset_name.lower() == "codeflaws":
        return CodeflawsAdapter(bug_id)

    if dataset_name.lower() in ("defects4c", "defects4c-tcpdump", "tcpdump"):
        return Defects4CAdapter(bug_id)

    raise ValueError(f"Dataset '{dataset_name}' chưa có Adapter tương ứng hỗ trợ!")
