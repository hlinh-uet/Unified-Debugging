import os
import json
import re
import time

from dotenv import load_dotenv

load_dotenv()

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR

# Timeout tổng cho mỗi bug (tính tổng thời gian validate tất cả mutants của bug đó)
# Nếu quá thời gian này, dừng sớm và lấy best-effort patch đã có.
# Set về 0 để tắt timeout.
MUTATION_BUG_TIMEOUT = int(os.getenv("MUTATION_BUG_TIMEOUT", "120"))
APR_MUTATION_TOP_K = int(os.getenv("APR_MUTATION_TOP_K", "5"))
from data_loaders.base_loader import get_loader, BugRecord
from data_loaders.sandbox_adapter import get_sandbox_adapter, defects4c_docker_ready
from core.utils import (
    extract_function_code,
    parse_sbfl_qualified_name,
    resolve_fl_candidate_source_path,
)


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

    ds_lc = (dataset or "").lower()
    if ds_lc in ("defects4c", "defects4c-tcpdump", "tcpdump"):
        ok_d, info_d = defects4c_docker_ready()
        if not ok_d:
            print(f"[Mutation] {info_d}")
            print("[Mutation] Dừng sớm — cần Docker Defects4C để validate.")
            return
        os.environ["DEFECTS4C_CONTAINER"] = info_d
        print(f"[Mutation] Defects4C: container '{info_d}'.")

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
        top_funcs = sorted_funcs[:APR_MUTATION_TOP_K] if APR_MUTATION_TOP_K > 0 else sorted_funcs
        print(f"\n[Mutation] Xử lý bug {bug_id}... (top-{APR_MUTATION_TOP_K if APR_MUTATION_TOP_K > 0 else 'all'})")

        try:
            adapter         = get_sandbox_adapter(dataset, bug_id)
            bug_source_path = adapter.get_source_path()
        except Exception as e:
            print(f"    [Error] Lỗi khởi tạo Adapter cho {bug_id}: {e}")
            continue

        if not os.path.exists(bug_source_path):
            print(f"    [Skip] File nguồn không tồn tại: {bug_source_path}")
            continue

        defects4c_like = ds_lc in ("defects4c", "defects4c-tcpdump", "tcpdump")
        primary_base = os.path.basename(bug_source_path)
        _br = bug_map.get(bug_id)
        raw_meta = _br.raw if _br else None
        source_cache: dict = {}

        # Lấy test context từ BugRecord đã load sẵn
        bug_record   = bug_map.get(bug_id)
        tests        = bug_record.tests if bug_record else []
        init_passed  = [t.get("test_id") for t in tests if t.get("outcome") in ("PASS", "PASSED")]
        init_failed  = [t.get("test_id") for t in tests if t.get("outcome") in ("FAIL", "FAILED")]

        status              = "skipped"
        attempted           = False
        patched_func        = None
        patched_source_best = None
        target_func         = None
        best_post_passed    = []
        best_post_failed    = []
        best_mutant_desc    = ""
        timed_out           = False

        bug_start = time.time()

        for qualified_name, score in top_funcs:
            if score == 0.0:
                continue

            # --- Kiểm tra timeout per-bug ---
            if MUTATION_BUG_TIMEOUT > 0:
                elapsed = time.time() - bug_start
                if elapsed >= MUTATION_BUG_TIMEOUT:
                    print(f"    [TIMEOUT] Đã dùng {elapsed:.0f}s / {MUTATION_BUG_TIMEOUT}s → dừng sớm, giữ best-effort patch.")
                    timed_out = True
                    break

            file_hint, func_name = parse_sbfl_qualified_name(qualified_name)
            if not func_name:
                continue

            candidate_path = resolve_fl_candidate_source_path(
                dataset, bug_source_path, file_hint or "", raw_meta
            )
            if not os.path.isfile(candidate_path):
                continue
            if candidate_path not in source_cache:
                with open(candidate_path, "r") as f:
                    source_cache[candidate_path] = f.read()
            source_code = source_cache[candidate_path]
            cand_base = os.path.basename(candidate_path)

            print(f"  - Đang đột biến hàm '{func_name}' trong {cand_base} (Score: {score:.4f})")
            func_code, start_idx, end_idx = extract_function_code(source_code, func_name)
            if not func_code:
                continue

            target_func = qualified_name
            mutants     = generate_mutants(func_code)
            if not mutants:
                print(f"    [WARN] Không sinh được mutant nào cho hàm '{func_name}'. Bỏ qua.")
                continue
            print(f"    → Tạo {len(mutants)} mutants để đưa vào Sandbox...")
            attempted = True

            found_fix       = False
            best_pass_count = -1
            for i, (m_code, m_desc) in enumerate(mutants):
                # --- Kiểm tra timeout giữa chừng trong vòng lặp mutant ---
                if MUTATION_BUG_TIMEOUT > 0 and (time.time() - bug_start) >= MUTATION_BUG_TIMEOUT:
                    print(f"    [TIMEOUT] Hết {MUTATION_BUG_TIMEOUT}s khi đang validate mutant #{i} → dừng.")
                    timed_out = True
                    break

                patched_source = source_code[:start_idx] + m_code + source_code[end_idx:]
                safe_cand = cand_base.replace("/", "_").replace(" ", "_")
                tmp_path = os.path.join(
                    EXPERIMENTS_DIR, f"tmp_{bug_id.replace('@', '__')}__{safe_cand}"
                )

                with open(tmp_path, "w") as f:
                    f.write(patched_source)

                is_valid, post_passed, post_failed = validate_patch(tmp_path, bug_id, dataset)

                if is_valid:
                    print(f"    [SUCCESS] Mutant #{i} vượt qua test! ({m_desc})")
                    status              = "success"
                    patched_func        = m_code
                    patched_source_best = patched_source
                    best_mutant_desc    = m_desc
                    best_post_passed    = post_passed
                    best_post_failed    = post_failed
                    try:
                        os.remove(tmp_path)
                    except FileNotFoundError:
                        pass
                    found_fix = True
                    break
                else:
                    if len(post_passed) > best_pass_count:
                        best_pass_count     = len(post_passed)
                        patched_func        = m_code
                        patched_source_best = patched_source
                        best_mutant_desc    = m_desc
                        best_post_passed    = post_passed
                        best_post_failed    = post_failed
                    try:
                        os.remove(tmp_path)
                    except FileNotFoundError:
                        pass

            if found_fix or timed_out:
                break

        if attempted and status == "skipped":
            status = "timeout" if timed_out else "failed"

        # --- Lưu file patch .c cho mọi trường hợp ---
        os.makedirs(PATCHES_DIR, exist_ok=True)
        patch_path = None
        if patched_source_best is not None:
            if status == "success":
                patch_filename = f"{bug_id}_mutation_patch.c"
            elif status == "timeout":
                patch_filename = f"{bug_id}_mutation_timeout.c"
            else:
                patch_filename = f"{bug_id}_mutation_best_effort.c"
            patch_path = os.path.join(PATCHES_DIR, patch_filename)
            with open(patch_path, "w") as f:
                f.write(patched_source_best)

        elapsed_total = time.time() - bug_start
        print(f"  → [{status.upper()}] Thời gian: {elapsed_total:.1f}s | "
              f"pass={len(best_post_passed)} fail={len(best_post_failed)}"
              + (f" | patch → {os.path.basename(patch_path)}" if patch_path else ""))

        apr_results[bug_id] = {
            "status":            status,
            "patched_function":  patched_func,
            "patched_file":      patched_source_best,
            "selected_function": target_func,
            "mutation_strategy": best_mutant_desc,
            "patch_file":        patch_path,
            "elapsed_seconds":   round(elapsed_total, 1),
            "init_passed_tests": init_passed,
            "init_failed_tests": init_failed,
            "post_passed_tests": best_post_passed,
            "post_failed_tests": best_post_failed,
        }

        with open(apr_results_file, "w") as f:
            json.dump(apr_results, f, indent=4)


if __name__ == "__main__":
    run_mutation_pipeline()
