import os
import json
import Levenshtein
from configs.path import EXPERIMENTS_DIR, PATCHES_DIR, CODEFLAWS_RESULTS_DIR

def get_initial_tests_info(bug_id, results_dir=CODEFLAWS_RESULTS_DIR):
    json_path = os.path.join(results_dir, f"{bug_id}.json")
    if not os.path.exists(json_path):
        return 0, 0, []
        
    try:
        with open(json_path, 'r') as f:
            data = json.load(f)
            
        tests = data.get("tests", [])
        passed = sum(1 for t in tests if t.get("outcome") == "PASS")
        failed = sum(1 for t in tests if t.get("outcome") == "FAIL")
        failed_test_ids = [t.get("test_id") for t in tests if t.get("outcome") == "FAIL"]
        return passed, failed, failed_test_ids
    except Exception:
        return 0, 0, []

def evaluate_apr(dataset="codeflaws"):
    print(f"\n--- Báo cáo Đánh giá Automated Program Repair (APR) trên {dataset} ---")
    
    tarantula_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    apr_results_file = os.path.join(EXPERIMENTS_DIR, "apr_results.json")
    
    if not os.path.exists(tarantula_file):
        print(f"Không tìm thấy file kết quả định vị lỗi ở {tarantula_file}")
        return

    with open(tarantula_file, 'r') as f:
        tarantula_results = json.load(f)
        
    apr_results = {}
    if os.path.exists(apr_results_file):
        with open(apr_results_file, 'r') as f:
            apr_results = json.load(f)

    total_bugs = len(tarantula_results)
    patched_bugs = 0
    fixed_initial_fails_count = 0
    total_edit_distance = 0
    distance_count = 0
    
    print(f"{'Bug ID':<35} | {'Initial P/F':<15} | {'Post P/F':<15} | {'Fixed Init Fails?':<20} | {'Edit Dist':<10}")
    print("-" * 105)

    for bug_id in tarantula_results:
        # Nếu dùng dataset khác, có thể tự động lấy metadata path phù hợp ở đây
        # Ví dụ: results_dir = CODEFLAWS_RESULTS_DIR if dataset == 'codeflaws' else OTHER_DIR
        init_pass, init_fail, init_fail_ids = get_initial_tests_info(bug_id)
        
        post_pass = 0
        post_fail = 0
        fixed_initial_fails = "N/A"
        edit_dist = -1
        
        bug_res = apr_results.get(bug_id, {})
        status = bug_res.get("status", "skipped")
        post_failed_tests = bug_res.get("post_failed_tests", [])
        
        # Nếu đã chạy qua APR
        if status != "skipped":
            if status == "success":
                patched_bugs += 1
                post_pass = init_pass + init_fail
                post_fail = 0
                fixed_initial_fails = "Yes"
                fixed_initial_fails_count += 1
            else:
                post_passed_tests = bug_res.get("post_passed_tests", [])
                post_failed_tests = bug_res.get("post_failed_tests", [])
                
                # Tính tổng lượng test thực thi thành công/thất bại chính xác từ APR runtime
                post_pass = len(post_passed_tests)
                post_fail = len(post_failed_tests)
                
                # Check xem các test lỗi ban đầu giờ còn lỗi không (dùng list trực tiếp trong APR dict)
                init_fail_ids = bug_res.get("init_failed_tests", init_fail_ids)
                still_failing_init = [t for t in init_fail_ids if t in post_failed_tests]
                
                if len(init_fail_ids) > 0 and len(still_failing_init) == 0:
                    # FIX được lỗi ban đầu nhưng mọc ra test lỗi mới
                    fixed_initial_fails = "Yes (Regressions)"
                    fixed_initial_fails_count += 1
                elif len(init_fail_ids) > 0:
                    fixed_initial_fails = "No"

            # Calculate Edit distance nếu có thông tin generated patch
            patched_code = bug_res.get("patched_function", "")
            correct_patch_path = os.path.join(EXPERIMENTS_DIR, "correct_patches", f"{bug_id}_accepted.c")
            
            if patched_code and os.path.exists(correct_patch_path):
                with open(correct_patch_path, 'r') as f:
                    correct_code = f.read()
                
                # Để dễ so sánh, trích xuất hàm tương đương bên accepted_code (dùng logic regex đơn giản)
                # Tạm thời tính edit distance tổng thể trên raw chuỗi hàm mới sinh và hàm được accept
                # Dùng thư viện python-Levenshtein
                if patched_code.strip() and correct_code.strip():
                    edit_dist = Levenshtein.distance(patched_code.strip(), correct_code.strip())
                    total_edit_distance += edit_dist
                    distance_count += 1
                
        print(f"{bug_id:<35} | {f'{init_pass}/{init_fail}':<15} | {f'{post_pass}/{post_fail}':<15} | {fixed_initial_fails:<20} | {edit_dist if edit_dist >= 0 else 'N/A':<10}")

    print("-" * 105)
    print(f"\nTổng số bug đã phân tích qua định vị lỗi: {total_bugs}")
    print(f"Số bản vá thành công (Pass 100% tests): {patched_bugs}")
    
    if total_bugs > 0:
        fix_rate = (patched_bugs / total_bugs) * 100
        print(f"Tỉ lệ vá thành công hoàn toàn (Plausible Fix Rate): {fix_rate:.2f}%")
        
    print(f"Số bug mà AI sửa được test case fail ban đầu (dù có thể fail test khác): {fixed_initial_fails_count}")
    
    if distance_count > 0:
        avg_dist = total_edit_distance / distance_count
        print(f"Khoảng cách Edit Distance trung bình so với Ground Truth: {avg_dist:.2f} ký tự")

    print("--- Hoàn thành quá trình đánh giá Evaluation! ---\n")
