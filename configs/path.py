import os

# 1. Lấy đường dẫn tuyệt đối đến thư mục chứa file path.py (thư mục configs)
CONFIGS_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Nhảy lên 1 cấp để ra thư mục gốc của dự án (Unified-Debugging)
# Đây là nơi VS Code đang mở và bạn muốn thấy file hiện ra ở đây
PROJECT_ROOT = os.path.dirname(CONFIGS_DIR)

# 3. Đường dẫn tới nơi chứa 100 file JSON (Giữ nguyên vì bạn đã trỏ đúng)
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CODEFLAWS_RESULTS_DIR = os.path.join(BASE_DIR, "codeflaws", "all_results")

# Directory source code (since results are json)
CODEFLAWS_SOURCE_DIR = os.path.join(BASE_DIR, "benchmark")

# 4. Đường dẫn để lưu kết quả thực nghiệm (Lưu ngay bên trong Unified-Debugging)
EXPERIMENTS_DIR = os.path.join(os.path.dirname(BASE_DIR), "Unified-Debugging", "experiments")

# 5. Đảm bảo thư mục experiments tồn tại
if not os.path.exists(EXPERIMENTS_DIR):
    os.makedirs(EXPERIMENTS_DIR)