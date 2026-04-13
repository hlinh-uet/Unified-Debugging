import os
import json

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR

try:
    import Levenshtein
    HAS_LEVENSHTEIN = True
except ImportError:
    HAS_LEVENSHTEIN = False


def evaluate_apr(dataset: str = "codeflaws"):
    """
    Đánh giá APR trên tất cả các kết quả APR có trong experiments/:
      - apr_results.json        (LLM-based APR)
      - apr_mutation_results.json (Mutation-based APR)
      - apr_genprog_results.json  (GenProg APR)

    Metrics:
      - Plausible Fix Rate: % bugs mà patch pass 100% tests (trên bugs đã thực sự thử, không kể skipped)
      - Fixed Initial Fails: patch sửa được các test fail ban đầu (dù có thể tạo regression)
      - Regression Rate: % bugs mà patch sửa fail cũ nhưng gây fail test pass cũ
      - Edit Distance trung bình so với accepted patch (nếu có file accepted)
    """
    print(f"\n{'='*70}")
    print(f"  BÁO CÁO ĐÁNH GIÁ AUTOMATED PROGRAM REPAIR (APR) — '{dataset}'")
    print(f"{'='*70}")

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

    total_edit_dist = 0
    edit_dist_count = 0

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

            edit_dist = _calc_edit_distance(bug_id, bug_res)
            if edit_dist >= 0:
                total_edit_dist += edit_dist
                edit_dist_count += 1

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

    if edit_dist_count > 0:
        avg_dist = total_edit_dist / edit_dist_count
        print(f"  Edit Distance TB so với accepted: {avg_dist:.2f} ký tự ({edit_dist_count} bugs có dữ liệu)")


def _calc_edit_distance(bug_id: str, bug_res: dict) -> int:
    """
    Tính Levenshtein edit distance giữa patched code và accepted patch.
    So sánh toàn bộ file patched vs toàn bộ file accepted (cùng granularity).
    Trả về -1 nếu không tính được.
    """
    if not HAS_LEVENSHTEIN:
        return -1

    patched_code = bug_res.get("patched_function", "")
    if not patched_code or not patched_code.strip():
        return -1

    correct_patch_path = os.path.join(EXPERIMENTS_DIR, "correct_patches", f"{bug_id}_accepted.c")
    patch_file_path = bug_res.get("patch_file") or os.path.join(PATCHES_DIR, f"{bug_id}_patch.c")

    if os.path.exists(correct_patch_path) and os.path.exists(patch_file_path):
        try:
            with open(correct_patch_path, "r") as f:
                correct_code = f.read().strip()
            with open(patch_file_path, "r") as f:
                patched_full = f.read().strip()
            if correct_code and patched_full:
                return Levenshtein.distance(patched_full, correct_code)
        except Exception:
            pass

    if os.path.exists(correct_patch_path):
        try:
            with open(correct_patch_path, "r") as f:
                correct_code = f.read().strip()
            if correct_code:
                return Levenshtein.distance(patched_code.strip(), correct_code)
        except Exception:
            pass

    return -1
