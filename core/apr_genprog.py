"""
core/apr_genprog.py
--------------------
Pipeline APR sử dụng công cụ GenProg (Genetic Programming-based APR).

Tham chiếu:
  - codeflaws/all-script/run-version-genprog.sh   → cách chuẩn bị và gọi GenProg
  - codeflaws/all-script/validate-fix-genprog.sh  → cách đọc .revlog và validate patch
  - codeflaws/all-script/configuration-default    → tham số mặc định của GenProg
  - codeflaws/all-script/compile.pl               → script compile wrapper cho GenProg

Sơ đồ hoạt động:
  1. Đọc FL results (tarantula_results.json) để lấy danh sách bug.
  2. Với mỗi bug:
     a. Load BugRecord qua get_loader() → không đọc disk thêm lần nào.
     b. Parse .revlog để lấy số pos/neg tests.
     c. Copy thư mục bug sang thư mục làm việc tạm (sandbox).
     d. Sinh file configuration-<bug_id> và bugged-program.txt.
     e. Gọi make với cilly để sinh file .cil.c (preprocessed/).
     f. Gọi `genprog configuration-<bug_id>` với timeout.
     g. Đọc output GenProg: phát hiện "Repair Found" / "no repair" / "Timeout".
     h. Nếu tìm được bản vá: làm sạch booo-artifacts, copy sang experiments/patches/.
     i. Chạy test-genprog.sh trên toàn bộ test case để xác nhận (validation).
  3. Ghi kết quả incremental vào experiments/apr_genprog_results.json.

Yêu cầu hệ thống:
  - GenProg binary (genprog hoặc ocaml repair binary) đã được install.
  - cilly (CIL preprocessor) đã được install (thường đi kèm genprog-source).
  - Dataset Codeflaws với thư mục benchmark/ chứa Makefile, test-genprog.sh, *.revlog.
  - Biến môi trường GENPROG_BIN trỏ đến binary GenProg (hoặc set trong .env).
"""

import os
import re
import json
import glob
import signal
import shutil
import subprocess
import tempfile
from typing import Dict, List, Optional, Tuple

from dotenv import load_dotenv

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR, CODEFLAWS_SOURCE_DIR
from data_loaders.base_loader import get_loader, BugRecord
from core.utils import extract_function_code, qualify_func

load_dotenv()

# ---------------------------------------------------------------------------
# Cấu hình
# ---------------------------------------------------------------------------

GENPROG_BIN         = os.getenv("GENPROG_BIN", "repair")        # binary GenProg
GENPROG_TIMEOUT     = int(os.getenv("GENPROG_TIMEOUT", "3600"))  # giây (mặc định 1 giờ)
TEST_TIMEOUT        = int(os.getenv("GENPROG_TEST_TIMEOUT", "50"))  # giây mỗi test case
GENPROG_POPSIZE     = os.getenv("GENPROG_POPSIZE")     # None = dùng giá trị trong configuration-default
GENPROG_GENERATIONS = os.getenv("GENPROG_GENERATIONS") # None = dùng giá trị trong configuration-default

# Thư mục chứa file configuration-default và compile.pl (copy từ all-script)
_BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
GENPROG_SCRIPTS_DIR = os.path.join(_BASE_DIR, "codeflaws", "all-script")

# Thư mục tạm để GenProg chạy (workdir)
# Phải là path KHÔNG có khoảng trắng vì GenProg truyền path này qua shell
# (compile.pl nhận __EXE_NAME__ chưa được quote → shell split tại space)
_default_run_dir = os.path.join(EXPERIMENTS_DIR, "genprog-run")
GENPROG_RUN_DIR = os.getenv("GENPROG_RUN_DIR") or (
    "/tmp/genprog-run" if " " in _default_run_dir else _default_run_dir
)


# ---------------------------------------------------------------------------
# Helpers: parse .revlog
# ---------------------------------------------------------------------------

def parse_revlog(revlog_path: str) -> Tuple[int, int]:
    """
    Đọc file .revlog của Codeflaws để lấy số test POSITIVE và DIFF (negative).

    Format của .revlog (ví dụ):
        -
        -
        Diff Cases: Tot 1
        5000
        Positive Cases: Tot 2
        1 2
        Regression Cases: Tot 0

    Returns:
        (pos_count, neg_count)
    """
    pos_count = 0
    neg_count = 0

    if not os.path.exists(revlog_path):
        return pos_count, neg_count

    try:
        with open(revlog_path, "r") as f:
            content = f.read()

        m_pos = re.search(r"Positive Cases:\s*Tot\s+(\d+)", content)
        m_neg = re.search(r"Diff Cases:\s*Tot\s+(\d+)", content)

        if m_pos:
            pos_count = int(m_pos.group(1))
        if m_neg:
            neg_count = int(m_neg.group(1))
    except Exception as e:
        print(f"    [WARN] Không đọc được .revlog tại {revlog_path}: {e}")

    return pos_count, neg_count


def get_cfile_name(bug_id: str) -> str:
    """
    Tính tên file .c lỗi từ bug_id Codeflaws.
    Ví dụ: '476-A-bug-16608008-16608059' → '476-A-16608008.c'
    """
    try:
        parts      = bug_id.split("-bug-")
        contest    = parts[0]                     # '476-A'
        versions   = parts[1].split("-")          # ['16608008', '16608059']
        buggy_ver  = versions[0]                  # '16608008'
        return f"{contest}-{buggy_ver}.c"
    except (IndexError, ValueError):
        return ""


# ---------------------------------------------------------------------------
# Helpers: chuẩn bị sandbox
# ---------------------------------------------------------------------------

def _prepare_workdir(bug_id: str, source_dir: str, run_dir: str) -> Optional[str]:
    """
    Copy thư mục bug vào run_dir/tempworkdir-<bug_id> (sandbox sạch).
    Trả về đường dẫn workdir hoặc None nếu thư mục nguồn không tồn tại.
    """
    bug_dir  = os.path.join(source_dir, bug_id)
    work_dir = os.path.join(run_dir, f"tempworkdir-{bug_id}")

    if not os.path.isdir(bug_dir):
        print(f"    [ERROR] Không tìm thấy thư mục bug: {bug_dir}")
        return None

    # Dọn dẹp workdir cũ (nếu còn)
    if os.path.exists(work_dir):
        shutil.rmtree(work_dir, ignore_errors=True)

    shutil.copytree(bug_dir, work_dir)
    return work_dir


def _write_genprog_config(work_dir: str, bug_id: str,
                           cfile: str, pos_count: int, neg_count: int,
                           scripts_dir: str) -> str:
    """
    Sinh file configuration-<bug_id> trong work_dir dựa trên configuration-default.
    Trả về đường dẫn file config.
    """
    config_default = os.path.join(scripts_dir, "configuration-default")
    config_out     = os.path.join(work_dir, f"configuration-{bug_id}")

    # Đọc default config
    base_lines: List[str] = []
    if os.path.exists(config_default):
        with open(config_default, "r") as f:
            base_lines = f.readlines()

    # Các key bị override — lọc bỏ khỏi default để tránh trùng
    override_keys = {"--pos-tests", "--neg-tests"}
    if GENPROG_POPSIZE:
        override_keys.add("--popsize")
    if GENPROG_GENERATIONS:
        override_keys.add("--generations")

    filtered = [ln for ln in base_lines
                if not any(ln.startswith(k) for k in override_keys)]

    # Thêm pos/neg tests từ .revlog
    filtered.append(f"--pos-tests {pos_count}\n")
    filtered.append(f"--neg-tests {neg_count}\n")

    # Override popsize / generations nếu được set trong .env
    if GENPROG_POPSIZE:
        filtered.append(f"--popsize {GENPROG_POPSIZE}\n")
    if GENPROG_GENERATIONS:
        filtered.append(f"--generations {GENPROG_GENERATIONS}\n")

    with open(config_out, "w") as f:
        f.writelines(filtered)

    # Ghi bugged-program.txt
    with open(os.path.join(work_dir, "bugged-program.txt"), "w") as f:
        f.write(cfile + "\n")

    return config_out


def _copy_compile_pl(work_dir: str, scripts_dir: str):
    """Copy compile.pl vào workdir (GenProg cần nó để compile)."""
    src = os.path.join(scripts_dir, "compile.pl")
    dst = os.path.join(work_dir, "compile.pl")
    if os.path.exists(src):
        shutil.copy2(src, dst)
    else:
        print(f"    [WARN] Không tìm thấy compile.pl tại {src}")


# ---------------------------------------------------------------------------
# Helpers: chạy GenProg
# ---------------------------------------------------------------------------

_CILLY_FLAGS = (
    "--save-temps -std=c99 "
    "-fno-optimize-sibling-calls "
    "-fno-strict-aliasing "
    "-fno-asm"
)
_CILLY_DOCKER_IMAGE = "squareslab/genprog"
_CILLY_IN_DOCKER    = "/root/.opam/system/bin/cilly"

# Dòng gốc trong test-genprog.sh dùng `/usr/bin/time` không có trong Docker image
_TEST_SCRIPT_OLD_LINE = (
    'if ! `which time` -o time.out -f "(%es)" ./$EXEFILE < $test_case'
    " | sed -e '/^$/d' -e 's/^[ \\t]*//' > $MY_NAME$test_case; then"
)
# Replacement: chạy trực tiếp + dùng PIPESTATUS để bắt exit code của executable
_TEST_SCRIPT_NEW_LINES = (
    './$EXEFILE < $test_case 2>/dev/null'
    " | sed -e '/^$/d' -e 's/^[ \\t]*//' > $MY_NAME$test_case\n"
    "_exe_rc=${PIPESTATUS[0]}\n"
    "touch time.out\n"
    "if [ $_exe_rc -ne 0 ]; then"
)


def _patch_test_script(work_dir: str) -> None:
    """
    Patch test-genprog.sh trong work_dir để không dùng `/usr/bin/time`.
    Docker image squareslab/genprog không có /usr/bin/time → script bị lỗi ngay.
    Thay bằng cách chạy exe trực tiếp và dùng PIPESTATUS để bắt exit code.
    """
    script_path = os.path.join(work_dir, "test-genprog.sh")
    if not os.path.exists(script_path):
        return
    with open(script_path, "r") as f:
        content = f.read()
    if _TEST_SCRIPT_OLD_LINE in content:
        content = content.replace(_TEST_SCRIPT_OLD_LINE, _TEST_SCRIPT_NEW_LINES)
        with open(script_path, "w") as f:
            f.write(content)


def _cilly_build(work_dir: str) -> bool:
    """
    Chạy `make CC="cilly"` để sinh file .cil.c.

    Thứ tự ưu tiên:
    1. Nếu `cilly` có sẵn trên host → chạy trực tiếp.
    2. Nếu không (macOS) và Docker khả dụng → chạy cilly bên trong
       container squareslab/genprog (nơi cilly nằm ở _CILLY_IN_DOCKER).

    Không fallback sang plain `make` vì sẽ tạo binary sai kiến trúc
    (macOS) khiến GenProg Docker không thể chạy sanity check.
    """
    if shutil.which("cilly"):
        result = subprocess.run(
            ["make", "CC=cilly", f"CFLAGS={_CILLY_FLAGS}"],
            cwd=work_dir,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return result.returncode == 0

    if shutil.which("docker"):
        make_cmd = (
            f"make CC={_CILLY_IN_DOCKER} "
            f"CFLAGS='{_CILLY_FLAGS}'"
        )
        docker_cmd = [
            "docker", "run", "--rm",
            "--platform", "linux/amd64",
            "-v", f"{work_dir}:{work_dir}",
            "-w", work_dir,
            _CILLY_DOCKER_IMAGE,
            "bash", "-c", make_cmd,
        ]
        result = subprocess.run(
            docker_cmd,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        return result.returncode == 0

    return False


def _clean_compiled_artifacts(work_dir: str, cfile: str) -> None:
    """
    Xóa binary và object file đã compile trên host (macOS).

    Cần thiết khi GenProg chạy qua Docker: nếu còn binary macOS trong work_dir,
    `make` bên trong container sẽ thấy file đã up-to-date và không recompile,
    dẫn đến sanity check thất bại vì binary sai kiến trúc (macOS vs Linux).
    """
    exe_name = cfile.replace(".c", "")
    for artifact in [exe_name, exe_name + ".o"]:
        fpath = os.path.join(work_dir, artifact)
        if os.path.exists(fpath):
            try:
                os.remove(fpath)
            except OSError:
                pass


def _move_cil_to_preprocessed(work_dir: str, cfile: str) -> bool:
    """
    Sau khi cilly build, copy file .cil.c vào preprocessed/<cfile>.
    Nếu không có .cil.c thì copy .c gốc làm fallback.
    """
    preprocessed_dir = os.path.join(work_dir, "preprocessed")
    os.makedirs(preprocessed_dir, exist_ok=True)

    cil_file = os.path.join(work_dir, cfile.replace(".c", ".cil.c"))
    src_file = os.path.join(work_dir, cfile)
    dst_file = os.path.join(preprocessed_dir, cfile)

    if os.path.exists(cil_file):
        shutil.copy2(cil_file, dst_file)
        shutil.copy2(cil_file, src_file)   # GenProg cũng đọc file gốc
        return True
    elif os.path.exists(src_file):
        shutil.copy2(src_file, dst_file)
        return True

    return False


def _run_genprog(work_dir: str, config_path: str,
                 bug_id: str, run_dir: str) -> Tuple[str, str]:
    """
    Chạy GenProg với timeout. Trả về (stdout+stderr, log_path).

    Khi timeout: kill toàn bộ process group (bao gồm Docker container bên trong
    wrapper script), thu thập partial output đã có, append marker "Timeout".
    """
    log_path = os.path.join(run_dir, f"temp-{bug_id}.out")
    output = ""

    try:
        proc = subprocess.Popen(
            [GENPROG_BIN, os.path.basename(config_path)],
            cwd=work_dir,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            start_new_session=True,   # tạo process group riêng để killpg an toàn
        )
        try:
            stdout, _ = proc.communicate(timeout=GENPROG_TIMEOUT)
            output = stdout or ""
        except subprocess.TimeoutExpired:
            # Kill toàn bộ process group (Docker wrapper + container bên trong)
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            stdout, _ = proc.communicate()
            output = (stdout or "") + "\nTimeout"

    except FileNotFoundError:
        output = (
            f"ERROR: GenProg binary '{GENPROG_BIN}' không tìm thấy. "
            f"Hãy set GENPROG_BIN trong .env"
        )

    with open(log_path, "w") as f:
        f.write(output)

    return output, log_path


def _determine_status(output: str) -> str:
    """
    Phân tích output GenProg để xác định kết quả.
    Trả về: 'repair_found' | 'no_repair' | 'timeout' | 'build_failed' | 'error'
    Kiểm tra theo thứ tự: timeout → error → repair_found → build_failed → no_repair.
    """
    # Timeout được set thủ công là string chính xác "Timeout" hoặc xuất hiện trong log GenProg
    if output.strip() == "Timeout" or "Timeout" in output:
        return "timeout"
    if "ERROR" in output and ("not found" in output or "không tìm thấy" in output):
        return "error"
    if "Repair Found" in output:
        return "repair_found"
    if "Failed to make" in output or "BUILDFAILED" in output:
        return "build_failed"
    if "no repair" in output.lower():
        return "no_repair"
    return "no_repair"


# ---------------------------------------------------------------------------
# Helpers: validate và lưu patch
# ---------------------------------------------------------------------------

def _extract_changed_function(work_dir: str, cfile: str) -> Tuple[Optional[str], Optional[str]]:
    """
    So sánh file gốc và file repair để tìm hàm bị thay đổi bởi GenProg.
    Trả về (patched_function_code, function_name) hoặc (None, None).
    """
    orig_file   = os.path.join(work_dir, cfile + ".bak")
    repair_file = os.path.join(work_dir, "repair", cfile)

    if not os.path.exists(orig_file):
        orig_file = os.path.join(work_dir, cfile)
    if not os.path.exists(repair_file):
        return None, None

    try:
        with open(orig_file, "r") as f:
            orig_code = f.read()
        with open(repair_file, "r") as f:
            repair_code = f.read()
    except Exception:
        return None, None

    func_pattern = re.compile(
        r'\b(?:(?:int|void|char|double|float|long|unsigned|short|struct|static|inline|const)\s+)*'
        r'\**\s*(\w+)\s*\([^)]*\)\s*\{',
        re.MULTILINE
    )

    for m in func_pattern.finditer(repair_code):
        func_name = m.group(1)
        if func_name in ("if", "while", "for", "switch", "sizeof"):
            continue
        repaired_func, _, _ = extract_function_code(repair_code, func_name)
        original_func, _, _ = extract_function_code(orig_code, func_name)
        if repaired_func and original_func and repaired_func != original_func:
            return repaired_func, func_name
        if repaired_func and not original_func:
            return repaired_func, func_name

    main_func, _, _ = extract_function_code(repair_code, "main")
    if main_func:
        return main_func, "main"

    return None, None


def _save_patch(work_dir: str, bug_id: str, cfile: str) -> Optional[str]:
    """
    Lấy file patch từ repair/ directory của GenProg, làm sạch booo artifacts,
    lưu vào experiments/patches/. Trả về đường dẫn patch hoặc None.
    """
    repair_dir  = os.path.join(work_dir, "repair")
    repair_file = os.path.join(repair_dir, cfile)

    if not os.path.exists(repair_file):
        return None

    # Làm sạch: xóa dòng chứa 'booo' (GenProg artifact)
    try:
        with open(repair_file, "r") as f:
            lines = f.readlines()
        cleaned = [ln for ln in lines if "booo" not in ln]
        with open(repair_file, "w") as f:
            f.writelines(cleaned)
    except Exception as e:
        print(f"    [WARN] Không làm sạch được repair file: {e}")

    # Copy sang patches/
    os.makedirs(PATCHES_DIR, exist_ok=True)
    patch_save_path = os.path.join(PATCHES_DIR, f"{bug_id}_genprog_patch.c")
    shutil.copy2(repair_file, patch_save_path)
    return patch_save_path


def _validate_patch(work_dir: str, cfile: str, bug_id: str) -> Tuple[List[str], List[str]]:
    """
    Validate bản vá GenProg bằng cách compile và chạy test trực tiếp (không dùng
    test-genprog.sh vì script đó phụ thuộc GNU time/diff, không chạy trên macOS).

    1. Copy repair/<cfile> đè lên <cfile> trong workdir.
    2. Make lại.
    3. Chạy exe với từng input file, so sánh output.

    Trả về (passed_tests, failed_tests).
    """
    import glob as globmod

    repair_dir  = os.path.join(work_dir, "repair")
    repair_file = os.path.join(repair_dir, cfile)
    orig_file   = os.path.join(work_dir, cfile)
    exe_name    = cfile.replace(".c", "")
    exe_path    = os.path.join(work_dir, exe_name)

    if not os.path.exists(repair_file):
        return [], []

    backup = orig_file + ".bak"
    passed, failed = [], []
    try:
        shutil.copy2(orig_file, backup)
        shutil.copy2(repair_file, orig_file)

        subprocess.run(
            ["make", "clean"], cwd=work_dir,
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        build_res = subprocess.run(
            ["make", f"FILENAME={exe_name}"], cwd=work_dir,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            timeout=30
        )
        if build_res.returncode != 0:
            build_res = subprocess.run(
                [
                    "gcc",
                    "-fno-optimize-sibling-calls", "-fno-strict-aliasing",
                    "-fno-asm", "-std=c99",
                    "-Wno-error=implicit-function-declaration",
                    "-O0", cfile, "-o", exe_name, "-lm"
                ],
                cwd=work_dir,
                stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                timeout=30
            )
            if build_res.returncode != 0:
                return [], ["Build failed after patch injection"]

        for inp in sorted(globmod.glob(os.path.join(work_dir, "input-pos*"))):
            basename = os.path.basename(inp)
            num = basename.replace("input-pos", "")
            out = os.path.join(work_dir, f"output-pos{num}")
            tc_id = f"pos{num}"
            if os.path.exists(out):
                if _run_one_test(exe_path, inp, out):
                    passed.append(tc_id)
                else:
                    failed.append(tc_id)

        for inp in sorted(globmod.glob(os.path.join(work_dir, "input-neg*"))):
            basename = os.path.basename(inp)
            num = basename.replace("input-neg", "")
            out = os.path.join(work_dir, f"output-neg{num}")
            tc_id = f"neg{num}"
            if os.path.exists(out):
                if _run_one_test(exe_path, inp, out):
                    passed.append(tc_id)
                else:
                    failed.append(tc_id)

        # Bao gồm cả heldout tests (nhất quán với CodeflawsAdapter.validate())
        for inp in sorted(globmod.glob(os.path.join(work_dir, "input-heldout-pos*"))):
            tag = os.path.basename(inp).replace("input-", "")
            out = os.path.join(work_dir, f"output-{tag}")
            if os.path.exists(out):
                if _run_one_test(exe_path, inp, out):
                    passed.append(tag)
                else:
                    failed.append(tag)

        for inp in sorted(globmod.glob(os.path.join(work_dir, "input-heldout-neg*"))):
            tag = os.path.basename(inp).replace("input-", "")
            out = os.path.join(work_dir, f"output-{tag}")
            if os.path.exists(out):
                if _run_one_test(exe_path, inp, out):
                    passed.append(tag)
                else:
                    failed.append(tag)

    finally:
        if os.path.exists(backup):
            shutil.move(backup, orig_file)
        for artifact in [exe_path, os.path.join(work_dir, f"{exe_name}.o")]:
            if os.path.exists(artifact):
                os.remove(artifact)

    return passed, failed


def _run_one_test(exe_path: str, input_file: str, expected_output_file: str,
                  timeout: int = 10) -> bool:
    """Chạy exe với input, so sánh stdout với expected output (ignore trailing space)."""
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
    except (subprocess.TimeoutExpired, Exception):
        return False

    actual = proc.stdout or ""
    try:
        with open(expected_output_file, "r") as f:
            expected = f.read()
    except Exception:
        return False

    actual_lines = [line.rstrip() for line in actual.splitlines()]
    expected_lines = [line.rstrip() for line in expected.splitlines()]
    while actual_lines and actual_lines[-1] == "":
        actual_lines.pop()
    while expected_lines and expected_lines[-1] == "":
        expected_lines.pop()
    return actual_lines == expected_lines


# ---------------------------------------------------------------------------
# Pipeline chính
# ---------------------------------------------------------------------------

def run_genprog_pipeline(dataset: str = "codeflaws",
                          source_dir: str = CODEFLAWS_SOURCE_DIR,
                          scripts_dir: str = GENPROG_SCRIPTS_DIR):
    """
    Pipeline APR sử dụng GenProg.

    Args:
        dataset:     Tên dataset (mặc định 'codeflaws').
        source_dir:  Thư mục chứa các bug trong benchmark (CODEFLAWS_SOURCE_DIR).
        scripts_dir: Thư mục chứa configuration-default và compile.pl.
    """
    os.makedirs(EXPERIMENTS_DIR, exist_ok=True)
    os.makedirs(GENPROG_RUN_DIR, exist_ok=True)

    # Kiểm tra có file FL results không
    tarantula_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_file):
        print(f"[GenProg] Lỗi: {tarantula_file} chưa tồn tại. Hãy chạy FL trước.")
        return

    with open(tarantula_file, "r") as f:
        fl_results = json.load(f)

    # Load toàn bộ BugRecord một lần duy nhất
    print(f"[GenProg] Đang load bug records từ dataset '{dataset}'...")
    loader  = get_loader(dataset)
    bug_map = {b.bug_id: b for b in loader.load_all()}

    # Load kết quả đã có (incremental save)
    results_file = os.path.join(EXPERIMENTS_DIR, "apr_genprog_results.json")
    genprog_results: Dict = {}
    if os.path.exists(results_file):
        try:
            with open(results_file, "r") as f:
                genprog_results = json.load(f)
        except Exception:
            pass

    print(f"[GenProg] Bắt đầu GenProg APR Pipeline trên {len(fl_results)} bugs...")
    print(f"[GenProg] GenProg binary: '{GENPROG_BIN}' | Timeout: {GENPROG_TIMEOUT}s")
    print(f"[GenProg] Scripts dir: {scripts_dir}\n")

    # Kiểm tra binary tồn tại trước khi chạy (early-exit để tránh loop vô ích)
    import shutil as _shutil
    if not _shutil.which(GENPROG_BIN):
        print(f"[GenProg] Lỗi: Không tìm thấy binary '{GENPROG_BIN}' trong PATH.")
        print(f"          Hãy cài GenProg hoặc set biến môi trường GENPROG_BIN trong .env.")
        return

    for bug_id in fl_results:
        # Bỏ qua nếu đã xử lý (trừ khi bị skipped)
        if bug_id in genprog_results and genprog_results[bug_id].get("status") not in ("skipped", "error"):
            print(f"  [SKIP] {bug_id} (đã có kết quả)")
            continue

        print(f"\n[GenProg] ⟹ Xử lý bug: {bug_id}")

        bug_record = bug_map.get(bug_id)
        if not bug_record:
            print(f"    [WARN] Không tìm thấy BugRecord cho {bug_id}")
            _write_result(genprog_results, results_file, bug_id, "skipped", bug_record)
            continue

        # --- Bước 1: Tính tên file và đọc revlog ---
        cfile = get_cfile_name(bug_id)
        if not cfile:
            print(f"    [ERROR] Không parse được cfile từ bug_id: {bug_id}")
            _write_result(genprog_results, results_file, bug_id, "error", bug_record)
            continue

        revlog_path = os.path.join(source_dir, bug_id, f"{cfile}.revlog")
        pos_count, neg_count = parse_revlog(revlog_path)

        if pos_count == 0 and neg_count == 0:
            print(f"    [WARN] .revlog trống hoặc không đọc được: {revlog_path}")
            # Fallback: đếm từ BugRecord
            pos_count = sum(1 for t in bug_record.tests if t.get("outcome") in ("PASS", "PASSED"))
            neg_count = sum(1 for t in bug_record.tests if t.get("outcome") in ("FAIL", "FAILED"))
            print(f"    [INFO] Dùng fallback từ BugRecord: pos={pos_count}, neg={neg_count}")

        print(f"    cfile={cfile} | pos_tests={pos_count} | neg_tests={neg_count}")

        # --- Bước 2: Chuẩn bị workdir ---
        work_dir = _prepare_workdir(bug_id, source_dir, GENPROG_RUN_DIR)
        if not work_dir:
            _write_result(genprog_results, results_file, bug_id, "error", bug_record)
            continue

        # Patch test-genprog.sh: /usr/bin/time không có trong Docker image
        _patch_test_script(work_dir)

        # --- Bước 3: Ghi config ---
        config_path = _write_genprog_config(
            work_dir, bug_id, cfile, pos_count, neg_count, scripts_dir
        )
        _copy_compile_pl(work_dir, scripts_dir)

        # --- Bước 4: Tạo thư mục preprocessed + cilly build ---
        cilly_ok = _cilly_build(work_dir)
        if not cilly_ok:
            print(f"    [WARN] cilly build thất bại → dùng .c gốc làm preprocessed")

        _move_cil_to_preprocessed(work_dir, cfile)

        # Xóa binary/object do host compile ra (nếu có), tránh Docker dùng nhầm
        # binary sai kiến trúc → make trong container sẽ recompile từ đầu
        _clean_compiled_artifacts(work_dir, cfile)

        # Dọn dẹp các file coverage cũ để GenProg không bị nhầm cache
        for pattern in ["repair.cache", "repair.debug.*", "coverage.path.*"]:
            for fp in glob.glob(os.path.join(work_dir, pattern)):
                try:
                    os.remove(fp)
                except OSError:
                    pass

        # --- Bước 5: Gọi GenProg ---
        print(f"    [RUN] Gọi GenProg (timeout={GENPROG_TIMEOUT}s)...")
        output, log_path = _run_genprog(work_dir, config_path, bug_id, GENPROG_RUN_DIR)

        # In vài dòng log để theo dõi
        for line in output.splitlines()[-5:]:
            if line.strip():
                print(f"         {line.strip()}")

        genprog_status = _determine_status(output)
        print(f"    [STATUS] GenProg → {genprog_status}")

        # --- Bước 6: Xử lý kết quả ---
        patch_path      = None
        passed_tests: List[str] = []
        failed_tests: List[str] = []
        final_status    = genprog_status
        patched_func    = None
        selected_func   = None
        patched_file_content: Optional[str] = None  # toàn bộ file sau khi vá

        if genprog_status in ("repair_found", "timeout"):
            repair_file = os.path.join(work_dir, "repair", cfile)

            if genprog_status == "timeout" and not os.path.exists(repair_file):
                # Timeout và không có candidate nào trong repair/ → thực sự không có patch
                final_status = "timeout"
                print(f"    [TIMEOUT] Không tìm thấy candidate trong repair/")

            else:
                # Có file trong repair/ (dù là repair_found hay timeout best-effort)
                if genprog_status == "timeout":
                    print(f"    [TIMEOUT-BESTFIT] Tìm thấy candidate trong repair/ → thử validate...")

                patch_path = _save_patch(work_dir, bug_id, cfile)

                # Đọc nội dung file đã vá (cần cho file-level edit distance)
                if os.path.exists(repair_file):
                    try:
                        with open(repair_file, "r") as f:
                            patched_file_content = f.read()
                    except Exception:
                        pass

                patched_func, raw_func_name = _extract_changed_function(work_dir, cfile)
                if patched_func and raw_func_name:
                    selected_func = qualify_func(bug_record.source_file, raw_func_name)
                    print(f"    [INFO] Trích xuất patched_function: hàm '{raw_func_name}'")
                elif raw_func_name:
                    selected_func = qualify_func(bug_record.source_file, raw_func_name)

                if patch_path:
                    print(f"    [VALIDATE] Đang xác nhận bản vá...")
                    passed_tests, failed_tests = _validate_patch(work_dir, cfile, bug_id)
                    if not failed_tests:
                        final_status = "timeout_repaired" if genprog_status == "timeout" else "success"
                        print(f"    [SUCCESS] Bản vá hợp lệ! pass={len(passed_tests)} fail=0"
                              + (" (from timeout best-fit)" if genprog_status == "timeout" else ""))
                    else:
                        final_status = "timeout_plausible" if genprog_status == "timeout" else "plausible_only"
                        print(f"    [PLAUSIBLE] Patch có nhưng fail {len(failed_tests)} tests"
                              + (" (from timeout best-fit)" if genprog_status == "timeout" else ""))
                else:
                    final_status = "repair_found_no_file"
                    print(f"    [WARN] GenProg báo 'Repair Found' nhưng không tìm được repair file")

        # --- Bước 7: Lưu incremental ---
        _write_result(
            genprog_results, results_file, bug_id, final_status, bug_record,
            patch_path=patch_path,
            passed_tests=passed_tests,
            failed_tests=failed_tests,
            genprog_log=log_path,
            pos_count=pos_count,
            neg_count=neg_count,
            patched_function=patched_func,
            selected_function=selected_func,
            patched_file=patched_file_content,
        )

        # Tuỳ chọn: giữ lại workdir để debug, bỏ comment dòng dưới để xoá
        # shutil.rmtree(work_dir, ignore_errors=True)

    print("\n[GenProg] Pipeline hoàn thành.")
    _print_summary(genprog_results)


# ---------------------------------------------------------------------------
# Helpers: ghi kết quả
# ---------------------------------------------------------------------------

def _write_result(results: Dict, results_file: str, bug_id: str, status: str,
                  bug_record: Optional[BugRecord],
                  patch_path: Optional[str] = None,
                  passed_tests: Optional[List[str]] = None,
                  failed_tests: Optional[List[str]] = None,
                  genprog_log: Optional[str] = None,
                  pos_count: int = 0,
                  neg_count: int = 0,
                  patched_function: Optional[str] = None,
                  selected_function: Optional[str] = None,
                  patched_file: Optional[str] = None):
    """Ghi kết quả một bug vào dict và flush xuống file JSON."""
    tests = bug_record.tests if bug_record else []
    init_passed = [t.get("test_id") for t in tests if t.get("outcome") in ("PASS", "PASSED")]
    init_failed = [t.get("test_id") for t in tests if t.get("outcome") in ("FAIL", "FAILED")]

    results[bug_id] = {
        "status":             status,
        "patched_function":   patched_function,
        "patched_file":       patched_file,   # toàn bộ file sau khi vá (để tính ED file-level)
        "selected_function":  selected_function,
        "patch_file":         patch_path,
        "init_passed_tests":  init_passed,
        "init_failed_tests":  init_failed,
        "post_passed_tests":  passed_tests or [],
        "post_failed_tests":  failed_tests or [],
        "genprog_log":        genprog_log,
        "pos_tests_revlog":   pos_count,
        "neg_tests_revlog":   neg_count,
    }

    with open(results_file, "w") as f:
        json.dump(results, f, indent=4)


def _print_summary(results: Dict):
    """In bảng tóm tắt kết quả GenProg."""
    total           = len(results)
    success         = sum(1 for v in results.values() if v.get("status") == "success")
    plausible       = sum(1 for v in results.values() if v.get("status") == "plausible_only")
    no_repair       = sum(1 for v in results.values() if v.get("status") == "no_repair")
    timeout         = sum(1 for v in results.values() if v.get("status") == "timeout")
    to_repaired     = sum(1 for v in results.values() if v.get("status") == "timeout_repaired")
    to_plausible    = sum(1 for v in results.values() if v.get("status") == "timeout_plausible")
    error           = sum(1 for v in results.values() if v.get("status") in ("error", "build_failed", "skipped"))

    print("\n" + "=" * 60)
    print("  KẾT QUẢ GENPROG APR")
    print("=" * 60)
    print(f"  Tổng bugs đã xử lý:         {total}")
    print(f"  ✅ Success (100% pass):      {success}")
    print(f"  🟢 Timeout → Repaired:       {to_repaired}")
    print(f"  🟡 Plausible only:           {plausible}")
    print(f"  🟠 Timeout → Plausible:      {to_plausible}")
    print(f"  ❌ No repair:               {no_repair}")
    print(f"  ⏱  Timeout (no candidate):  {timeout}")
    print(f"  💥 Error/Skip:              {error}")
    if total > 0:
        repaired = success + to_repaired
        fix_rate = (repaired / total) * 100
        print(f"  Fix Rate (incl. timeout):   {fix_rate:.1f}%")
    print("=" * 60)


# ---------------------------------------------------------------------------
# Entry point độc lập
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    run_genprog_pipeline()
