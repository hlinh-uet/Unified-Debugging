import os
import json
from configs.path import EXPERIMENTS_DIR

def evaluate_fl():
    print("\n--- Báo cáo Đánh giá Fault Localization (FL) ---")
    tarantula_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_file):
        print(f"Không tìm thấy file kết quả định vị lỗi {tarantula_file}")
        return

    with open(tarantula_file, 'r') as f:
        tarantula_results = json.load(f)

    total_bugs = len(tarantula_results)
    
    # Phân tích top-K
    top_1_suspicious_funcs = 0
    top_3_suspicious_funcs = 0

    for bug_id, scores in tarantula_results.items():
        if not scores:
            continue
            
        # Sắp xếp hàm giảm dần
        sorted_funcs = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        if not sorted_funcs:
            continue
            
        # Nếu hàm root có điểm tarantula > 0.0, coi như FL định vị được ít nhất 1 node
        if sorted_funcs[0][1] > 0.0:
            top_1_suspicious_funcs += 1
            
        # Kiểm tra top 3 (Chỉ mang tính chất tham khảo vì chưa có Ground Truth chính xác của hàm chứa lỗi)
        # Trong hệ thống thực tế: cần so sánh hàm nghi ngờ với hàm bị chỉnh sửa trong git diff (ground_truth_func)
        top_k_score = sum(1 for func, score in sorted_funcs[:3] if score > 0)
        if top_k_score > 0:
            top_3_suspicious_funcs += 1

    print(f"Tổng số bugs đã phân tích FL: {total_bugs}")
    print(f"Số lượng bug tìm thấy hàm nghi ngờ (Top 1 score > 0): {top_1_suspicious_funcs} / {total_bugs} ({top_1_suspicious_funcs/total_bugs*100:.2f}%)")
    print(f"Số lượng bug có hàm nghi ngờ tồn tại trong Top 3: {top_3_suspicious_funcs} / {total_bugs} ({top_3_suspicious_funcs/total_bugs*100:.2f}%)")
    print("--- (Lưu ý: Evaluation hiện tại chưa có Ground Truth để tính Recall/Precision tuyệt đối) ---\n")
