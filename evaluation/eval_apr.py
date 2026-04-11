import os
import json
from configs.path import EXPERIMENTS_DIR, PATCHES_DIR

def evaluate_apr():
    print("\n--- Báo cáo Đánh giá Automated Program Repair (APR) ---")
    
    tarantula_file = os.path.join(EXPERIMENTS_DIR, "tarantula_results.json")
    if not os.path.exists(tarantula_file):
        print(f"Không tìm thấy file kết quả định vị lỗi ở {tarantula_file}")
        return

    with open(tarantula_file, 'r') as f:
        tarantula_results = json.load(f)

    total_bugs = len(tarantula_results)
    
    # Kiểm tra số lượng patch thành công
    patched_bugs = 0
    if os.path.exists(PATCHES_DIR):
        for patch_file in os.listdir(PATCHES_DIR):
            if patch_file.endswith(".c"):
                # Có thể trích xuất ID bug từ file `patch_id_patch.c`
                patched_bugs += 1

    print(f"Tổng số bug đem đi vá: {total_bugs}")
    print(f"Số lượng bản vá thành công sinh ra: {patched_bugs}")
    
    # Tỉ lệ vá (Fixing rate/Plausible patch rate)
    if total_bugs > 0:
        fix_rate = (patched_bugs / total_bugs) * 100
        print(f"Tỉ lệ vá thành công (Plausible Fix Rate): {fix_rate:.2f}%")
        
    print("--- (Lưu ý: Patch hiện tại đang là dummy test vì validate_patch trả về False) ---\n")
