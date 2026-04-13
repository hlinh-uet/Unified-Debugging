import os
import json
import Levenshtein

from configs.path import EXPERIMENTS_DIR, PATCHES_DIR


def evaluate_apr(dataset: str = "codeflaws"):
    """
    Đọc kết quả từ experiments/apr_results.json và in bảng báo cáo chi tiết.

    Chú ý: thông tin init_passed/init_failed được lấy trực tiếp từ trường
    đã lưu trong apr_results.json (do APR pipeline ghi vào từ BugRecord),
    không cần đọc lại file JSON gốc của dataset.
    """
    print(f"\n--- Báo cáo Đánh giá Automated Program Repair (APR) trên '{dataset}' ---")

    tarantula_file   = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_results.json")

    if not os.path.exists(tarantula_file):
        print(f"Không tìm thấy file kết quả FL: {tarantula_file}")
        return

    with open(tarantula_file, "r") as f:
        tarantula_results = json.load(f)

    apr_results = {}
    if os.path.exists(apr_results_file):
        with open(apr_results_file, "r") as f:
            apr_results = json.load(f)

    total_bugs              = len(tarantula_results)
    patched_bugs            = 0
    fixed_initial_fails_count = 0
    total_edit_distance     = 0
    distance_count          = 0

    print(f"{'Bug ID':<35} | {'Init P/F':<12} | {'Post P/F':<12} | {'Fixed Init Fails?':<22} | {'Edit Dist':<10}")
    print("-" * 100)

    for bug_id in tarantula_results:
        bug_res = apr_results.get(bug_id, {})
        status  = bug_res.get("status", "skipped")

        # Lấy thông tin test từ dữ liệu đã lưu trong apr_results.json (không đọc lại disk)
        init_passed_list = bug_res.get("init_passed_tests", [])
        init_failed_list = bug_res.get("init_failed_tests", [])
        init_pass = len(init_passed_list)
        init_fail = len(init_failed_list)

        post_pass            = 0
        post_fail            = 0
        fixed_initial_fails  = "N/A"
        edit_dist            = -1

        if status != "skipped":
            post_passed_tests = bug_res.get("post_passed_tests", [])
            post_failed_tests = bug_res.get("post_failed_tests", [])

            if status == "success":
                patched_bugs += 1
                post_pass           = init_pass + init_fail
                post_fail           = 0
                fixed_initial_fails = "Yes"
                fixed_initial_fails_count += 1
            else:
                post_pass = len(post_passed_tests)
                post_fail = len(post_failed_tests)

                still_failing_init = [t for t in init_failed_list if t in post_failed_tests]
                if init_failed_list and not still_failing_init:
                    fixed_initial_fails = "Yes (Regressions)"
                    fixed_initial_fails_count += 1
                elif init_failed_list:
                    fixed_initial_fails = "No"

            # Edit Distance so với accepted patch (nếu có)
            patched_code       = bug_res.get("patched_function", "")
            correct_patch_path = os.path.join(EXPERIMENTS_DIR, "correct_patches", f"{bug_id}_accepted.c")

            if patched_code and os.path.exists(correct_patch_path):
                with open(correct_patch_path, "r") as f:
                    correct_code = f.read()
                if patched_code.strip() and correct_code.strip():
                    edit_dist = Levenshtein.distance(patched_code.strip(), correct_code.strip())
                    total_edit_distance += edit_dist
                    distance_count      += 1

        print(
            f"{bug_id:<35} | "
            f"{f'{init_pass}/{init_fail}':<12} | "
            f"{f'{post_pass}/{post_fail}':<12} | "
            f"{fixed_initial_fails:<22} | "
            f"{'N/A' if edit_dist < 0 else edit_dist:<10}"
        )

    print("-" * 100)
    print(f"\nTổng số bugs đã phân tích qua FL: {total_bugs}")
    print(f"Số bản vá thành công (100% tests pass): {patched_bugs}")

    if total_bugs > 0:
        fix_rate = (patched_bugs / total_bugs) * 100
        print(f"Plausible Fix Rate: {fix_rate:.2f}%")

    print(f"Số bug mà APR sửa được ít nhất các test fail ban đầu: {fixed_initial_fails_count}")

    if distance_count > 0:
        avg_dist = total_edit_distance / distance_count
        print(f"Edit Distance trung bình so với accepted patch: {avg_dist:.2f} ký tự")

    print("--- Hoàn thành Evaluation APR ---\n")
