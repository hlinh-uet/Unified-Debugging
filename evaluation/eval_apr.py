import os
import json

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR, CODEFLAWS_SOURCE_DIR
from core.utils import extract_function_code

try:
    import Levenshtein
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False


def evaluate_apr(dataset: str = "codeflaws"):
    """
    Đánh giá APR trên tất cả các kết quả APR có trong experiments/.

    Metrics:
      - Plausible Fix Rate
      - Fixed Initial Fails / Regression Rate
      - Edit Distance (function-level): patched_function vs accepted_function
    """
    print(f"\n{'='*70}")
    print(f"  BÁO CÁO ĐÁNH GIÁ AUTOMATED PROGRAM REPAIR (APR) — '{dataset}'")
    print(f"{'='*70}")

    if not HAS_LEVENSHTEIN:
        print("  [WARN] Thư viện 'python-Levenshtein' chưa cài. Edit Distance sẽ không được tính.")
        print("         Cài bằng: pip install python-Levenshtein")

    apr_files = [
        ("LLM-based APR",       "apr_results.json"),
        ("Mutation-based APR",  "apr_mutation_results.json"),
        ("GenProg APR",         "apr_genprog_results.json"),
    ]

    for label, filename in apr_files:
        filepath = os.path.join(EXPERIMENTS_DIR, filename)
        if os.path.exists(filepath):
            _evaluate_one_apr(label, filepath, dataset)

    print(f"{'='*70}\n")


def _evaluate_one_apr(label: str, apr_results_file: str, dataset: str):
    """Đánh giá một file kết quả APR."""
    print(f"\n--- {label} ({os.path.basename(apr_results_file)}) ---")

    with open(apr_results_file, "r") as f:
        apr_results = json.load(f)

    if not apr_results:
        print("  (Không có kết quả)")
        return

    total_bugs   = len(apr_results)
    attempted    = 0
    patched      = 0
    fixed_fails  = 0
    regressions  = 0

    edit_distances = []

    col_w = (35, 12, 12, 22, 10)
    header = (
        f"{'Bug ID':<{col_w[0]}} | "
        f"{'Init P/F':<{col_w[1]}} | "
        f"{'Post P/F':<{col_w[2]}} | "
        f"{'Fixed Init Fails?':<{col_w[3]}} | "
        f"{'Edit Dist':<{col_w[4]}}"
    )
    print(header)
    print("-" * (sum(col_w) + 12))

    for bug_id, bug_res in apr_results.items():
        status = bug_res.get("status", "skipped")

        init_passed_list = bug_res.get("init_passed_tests", [])
        init_failed_list = bug_res.get("init_failed_tests", [])
        init_pass = len(init_passed_list)
        init_fail = len(init_failed_list)

        post_pass = 0
        post_fail = 0
        fixed_label = "N/A"
        edit_dist = -1

        if status in ("skipped",):
            pass
        else:
            attempted += 1

            post_passed_tests = bug_res.get("post_passed_tests", [])
            post_failed_tests = bug_res.get("post_failed_tests", [])
            post_pass = len(post_passed_tests)
            post_fail = len(post_failed_tests)

            if status == "success":
                patched += 1
                post_pass = len(post_passed_tests) if post_passed_tests else (init_pass + init_fail)
                post_fail = len(post_failed_tests)

            still_failing_init = set(init_failed_list) & set(post_failed_tests)
            newly_failing = set(post_failed_tests) - set(init_failed_list)

            if init_failed_list and not still_failing_init:
                fixed_fails += 1
                if newly_failing:
                    fixed_label = "Yes (Regressions)"
                    regressions += 1
                else:
                    fixed_label = "Yes"
            elif init_failed_list:
                fixed_label = "No"

            edit_dist = _calc_edit_distance(bug_id, bug_res, dataset)
            if edit_dist >= 0:
                edit_distances.append(edit_dist)

        print(
            f"{bug_id:<{col_w[0]}} | "
            f"{f'{init_pass}/{init_fail}':<{col_w[1]}} | "
            f"{f'{post_pass}/{post_fail}':<{col_w[2]}} | "
            f"{fixed_label:<{col_w[3]}} | "
            f"{'N/A' if edit_dist < 0 else edit_dist:<{col_w[4]}}"
        )

    print("-" * (sum(col_w) + 12))
    print(f"  Tổng bugs:                {total_bugs}")
    print(f"  Đã thử sửa (attempted):  {attempted}")
    print(f"  Bỏ qua (skipped):        {total_bugs - attempted}")

    if attempted > 0:
        print(f"  Plausible patches (100% pass): {patched}/{attempted} ({patched/attempted*100:.2f}%)")
        print(f"  Sửa được fail ban đầu:   {fixed_fails}/{attempted} ({fixed_fails/attempted*100:.2f}%)")
        print(f"  Gây regression:          {regressions}/{attempted} ({regressions/attempted*100:.2f}%)")

    if edit_distances:
        _print_edit_distance_stats(edit_distances, attempted)
    elif HAS_LEVENSHTEIN:
        print(f"\n  Edit Distance: Không bug nào có patched_function để so sánh.")


def _print_edit_distance_stats(edit_distances, attempted):
    """In thống kê edit distance."""
    n = len(edit_distances)
    avg_dist = sum(edit_distances) / n
    sorted_d = sorted(edit_distances)
    median_dist = sorted_d[n // 2]
    min_dist = sorted_d[0]
    max_dist = sorted_d[-1]

    print(f"\n  --- Edit Distance (patched_function vs accepted_function) ---")
    print(f"  Số bugs có dữ liệu:   {n}/{attempted}")
    print(f"  Trung bình (Mean):     {avg_dist:.2f}")
    print(f"  Trung vị (Median):     {median_dist}")
    print(f"  Min:                   {min_dist}")
    print(f"  Max:                   {max_dist}")


def _get_accepted_path(bug_id: str) -> str:
    """
    Lấy đường dẫn file accepted từ benchmark.
    bug_id='104-A-bug-15369048-15370159' → benchmark/.../104-A-15370159.c
    """
    try:
        parts = bug_id.split("-bug-")
        prefix = parts[0]
        accepted_ver = parts[1].split("-")[1]
        return os.path.join(CODEFLAWS_SOURCE_DIR, bug_id, f"{prefix}-{accepted_ver}.c")
    except (IndexError, ValueError):
        return ""


def _calc_edit_distance(bug_id: str, bug_res: dict, dataset: str) -> int:
    """
    Tính Levenshtein edit distance giữa patched_function (hàm do APR tạo)
    và accepted_function (hàm tương ứng trích từ file accepted của benchmark).

    So sánh ở mức function-level: cùng hàm, cùng granularity.
    Trả về -1 nếu không tính được.
    """
    if not HAS_LEVENSHTEIN:
        return -1

    patched_func = bug_res.get("patched_function")
    if not patched_func or not patched_func.strip():
        return -1

    selected_func = bug_res.get("selected_function", "")
    if not selected_func:
        return -1

    accepted_path = _get_accepted_path(bug_id)
    if not accepted_path or not os.path.exists(accepted_path):
        return -1

    try:
        with open(accepted_path, "r") as f:
            accepted_code = f.read()
    except Exception:
        return -1

    accepted_func, _, _ = extract_function_code(accepted_code, selected_func)
    if not accepted_func:
        return -1

    return Levenshtein.distance(patched_func.strip(), accepted_func.strip())
