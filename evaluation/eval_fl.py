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
    
    # Phân tích top-K dựa trên Ground Truth
    top_1_suspicious_funcs = 0
    top_3_suspicious_funcs = 0
    top_5_suspicious_funcs = 0
    
    evaluated_bugs = 0

    for bug_id, result_data in tarantula_results.items():
        # Backward compatibility with old format
        if not isinstance(result_data, dict) or 'scores' not in result_data:
            continue
            
        scores = result_data.get('scores', {})
        ground_truth = result_data.get('ground_truth', [])
        
        if not scores or not ground_truth:
            continue
            
        evaluated_bugs += 1
            
        # Sắp xếp hàm giảm dần
        sorted_funcs = sorted(scores.items(), key=lambda item: item[1], reverse=True)
        if not sorted_funcs:
            continue
            
        # Kiểm tra xem hàm ground truth có xuất hiện ở Top N không
        sorted_func_names = [f[0] for f in sorted_funcs]
        
        # Nếu hàm root có điểm tarantula > 0.0, coi như FL định vị được ít nhất 1 node
        top1_funcs = sorted_func_names[:1]
        top3_funcs = sorted_func_names[:3]
        top5_funcs = sorted_func_names[:5]

        # Kiểm tra hit
        if any(gt in top1_funcs for gt in ground_truth):
            top_1_suspicious_funcs += 1
            
        if any(gt in top3_funcs for gt in ground_truth):
            top_3_suspicious_funcs += 1
            
        if any(gt in top5_funcs for gt in ground_truth):
            top_5_suspicious_funcs += 1

    print(f"Tổng số bugs đã phân tích qua FL (có đủ Ground Truth): {evaluated_bugs} / {total_bugs}")
    if evaluated_bugs > 0:
        print(f"Số lượng bug tìm thấy chính xác Ground Truth ở Top 1: {top_1_suspicious_funcs} / {evaluated_bugs} ({top_1_suspicious_funcs/evaluated_bugs*100:.2f}%)")
        print(f"Số lượng bug tìm thấy chính xác Ground Truth ở Top 3: {top_3_suspicious_funcs} / {evaluated_bugs} ({top_3_suspicious_funcs/evaluated_bugs*100:.2f}%)")
        print(f"Số lượng bug tìm thấy chính xác Ground Truth ở Top 5: {top_5_suspicious_funcs} / {evaluated_bugs} ({top_5_suspicious_funcs/evaluated_bugs*100:.2f}%)")
    print("--- Hoàn thành Đánh giá FL ---\n")
