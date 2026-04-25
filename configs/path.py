import os

# 1. Lấy đường dẫn tuyệt đối đến thư mục chứa file path.py (thư mục configs)
CONFIGS_DIR = os.path.dirname(os.path.abspath(__file__))

# 2. Nhảy lên 1 cấp để ra thư mục gốc của dự án (Unified-Debugging)
PROJECT_ROOT = os.path.dirname(CONFIGS_DIR)

# 3. Đường dẫn tới CODEFLAWS
BASE_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
CODEFLAWS_RESULTS_DIR = os.path.join(BASE_DIR, "codeflaws", "codeflaws", "all_results")
CODEFLAWS_SOURCE_DIR = os.path.join(BASE_DIR, "codeflaws", "benchmark")

# 3b. Đường dẫn tới Defects4C
DEFECTS4C_ROOT_DIR = os.path.join(BASE_DIR, "defects4c")
DEFECTS4C_TPL_DIR = os.path.join(DEFECTS4C_ROOT_DIR, "defectsc_tpl")
DEFECTS4C_PROJECTS_DIR = os.path.join(DEFECTS4C_TPL_DIR, "projects")
DEFECTS4C_OUT_DIR = os.path.join(DEFECTS4C_ROOT_DIR, "out_tmp_dirs")
DEFECTS4C_PATCHES_DIR = os.path.join(DEFECTS4C_ROOT_DIR, "patche_dirs")
DEFECTS4C_DATA_DIR = os.path.join(DEFECTS4C_TPL_DIR, "data")
DEFECTS4C_RAW_INFO_CSV = os.path.join(DEFECTS4C_DATA_DIR, "raw_info_step1.csv")
DEFECTS4C_SRC_CONTENT_JSONL = os.path.join(DEFECTS4C_DATA_DIR, "github_src_path.jsonl")
# Metadata chuẩn hiện được sinh vào out_tmp_dirs/unified_debugging/<slug>/metadata.
DEFECTS4C_UNIFIED_DIR = os.path.join(DEFECTS4C_OUT_DIR, "unified_debugging")

# 4. Đường dẫn để lưu kết quả thực nghiệm (Lưu ngay bên trong Unified-Debugging)
EXPERIMENTS_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "experiments")
DEFECTS4C_CACHE_DIR = os.path.join(EXPERIMENTS_DIR, "defects4c_cache")

# Đường dẫn để lưu các bản vá lỗi (patches)
PATCHES_DIR = os.path.join(EXPERIMENTS_DIR, "patches")

# 5. Đảm bảo thư mục experiments tồn tại
if not os.path.exists(EXPERIMENTS_DIR):
    os.makedirs(EXPERIMENTS_DIR)
