# Unified-Debugging Pipeline

Hệ thống tự động **Định vị lỗi (Fault Localization)** và **Sửa lỗi tự động (Automated Program Repair)** cho các chương trình C, hỗ trợ nhiều bộ dữ liệu (Codeflaws, Defects4C, ...) thông qua kiến trúc mở rộng Adapter.

---

## Cấu trúc dự án

```
Unified-Debugging/
├── main.py                    # Entry-point duy nhất – điều phối toàn bộ pipeline
├── requirements.txt
├── .env.example               # Mẫu biến môi trường (API Key)
│
├── configs/
│   └── path.py                # Cấu hình đường dẫn tập trung
│
├── data_loaders/              # Lớp tải dữ liệu thống nhất
│   ├── __init__.py
│   ├── base_loader.py         # Abstract BugLoader + BugRecord + factory get_loader()
│   ├── codeflaws_loader.py    # Concrete loader cho dataset Codeflaws
│   └── sandbox_adapter.py     # Sandbox Adapter (compile + chạy test) theo dataset
│
├── core/                      # Logic nghiệp vụ chính
│   ├── utils.py               # Tiện ích dùng chung (extract_function_code, qualify_func, ...)
│   ├── fl_tarantula.py        # Thuật toán Fault Localization – Tarantula
│   └── apr_baseline.py        # APR với LLM
│
├── evaluation/                # Đánh giá và báo cáo
│   ├── eval_fl.py             # Đánh giá FL: Top-1/3/5 Hit Rate
│   └── eval_apr.py            # Đánh giá APR: Fix Rate, Regression, Edit Distance
│
├── experiments/               # Sinh ra sau khi chạy – chứa kết quả
│   ├── tarantula_results.json          # Kết quả FL; mỗi record có dataset + scores
│   ├── apr_results.json                # Kết quả APR – chỉ lưu best candidate mỗi bug
│   ├── patches/                        # Bản vá thành công (status=success)
│   │   └── <bug_id>_patch.c            #   – từ LLM baseline
│   └── correct_patches/                # Bản vá tham chiếu
│
├── DATASET_STANDARDS.md       # Chuẩn định dạng dữ liệu để thêm dataset mới
├── INSTRUCTION.md             # Chi tiết kiến trúc và luồng hoạt động
└── README.md                  # Tài liệu này
```

---

## Luồng hoạt động

```
get_loader(dataset)
      │
      ▼
 [BugRecord list]
      │
      ├──► FL (Tarantula) ──────────────────────► tarantula_results.json
      │
      └──► APR ───► LLM                 ──────► apr_results.json
                         │
                         ▼
                Sandbox Adapter (compile + test)
                         │
                         ▼
                  experiments/patches/      ← bản vá thành công
                         │
                         ▼
                   Evaluation Report
                   (Fix Rate, Regression, ED func + file)
```

> **Điểm quan trọng:** APR đọc `tarantula_results.json`, nên cần chạy FL cho đúng dataset trước khi chạy APR. Kết quả FL/APR hiện có trường `dataset` và evaluation sẽ tự lọc theo dataset đang chạy.

---

## Thiết lập môi trường

### 1. Tạo và kích hoạt môi trường ảo

```bash
python3 -m venv .venv
source .venv/bin/activate        # Mac / Linux
# .venv\Scripts\activate         # Windows
```

### 2. Cài đặt thư viện

```bash
pip install -r requirements.txt
```

> Để tính Edit Distance, cần thêm: `pip install python-Levenshtein`

### 3. Cấu hình API Key và biến môi trường

```bash
cp .env.example .env
# Mở .env, điền các biến sau:
#   OPENROUTER_API_KEY=...     – OpenRouter API Key (cho Qwen APR)
#   LLM_PROVIDER=qwen
#   QWEN_MODEL=openai/gpt-oss-120b
#   LLM_MAX_OUTPUT_TOKENS=12000
```

Model OpenRouter có thể đổi bằng `QWEN_MODEL`. Một số lựa chọn:

```bash
# Rẻ, nên thử trước cho APR
QWEN_MODEL=openai/gpt-oss-120b

# Model đang dùng ban đầu
QWEN_MODEL=qwen/qwen3-coder-30b-a3b-instruct

# Mạnh hơn nhưng thường đắt hơn
QWEN_MODEL=deepseek/deepseek-v3.2
```

---

## Sử dụng

Tất cả lệnh chạy từ thư mục `Unified-Debugging/`.

### Chạy toàn bộ pipeline

```bash
python3 main.py                          # mặc định: dataset=codeflaws
python3 main.py --all --dataset codeflaws
python3 main.py --all --dataset tcpdump --llm qwen
```

### Chạy từng bước

```bash
# Bước 1 – Fault Localization.
# Lệnh này ghi experiments/tarantula_results.json cho dataset đang chọn.
python3 main.py --fl --dataset tcpdump

# Bước 2 – APR bằng LLM.
# Cần có tarantula_results.json từ bước FL cùng dataset.
python3 main.py --apr --dataset tcpdump --llm qwen
python3 main.py --apr --dataset defects4c --llm gemini
python3 main.py --apr --dataset defects4c --llm openai
python3 main.py --apr --dataset tcpdump           # dùng LLM_PROVIDER trong .env

# Bước 3 – Evaluation (FL + APR), lọc theo dataset.
python3 main.py --eval --dataset tcpdump
```

Nếu đổi dataset, hãy chạy lại `--fl` trước. Ví dụ không nên dùng `tarantula_results.json` sinh từ `tcpdump` để chạy APR cho `php`. Code hiện tại có filter bảo vệ, nhưng lệnh đúng vẫn là:

```bash
python3 main.py --fl  --dataset php
python3 main.py --apr --dataset php --llm qwen
python3 main.py --eval --dataset php
```

### Tham số dòng lệnh

| Tham số         | Mô tả                                              |
|-----------------|----------------------------------------------------|
| `--dataset`     | Tên dataset: `codeflaws`, `defects4c`, hoặc folder Defects4C như `tcpdump`, `php`, `cjson` |
| `--fl`          | Chỉ chạy Fault Localization                        |
| `--apr`         | Chỉ chạy APR với LLM; cần kết quả FL trước đó      |
| `--eval`        | Chỉ chạy Evaluation (FL + APR), lọc theo dataset   |
| `--all`         | Chạy FL → APR LLM → Evaluation                     |
| `--llm`         | Provider APR: `qwen`/`openrouter`, `gemini`, `openai`, `claude` |

### Kết quả APR

`experiments/apr_results.json` chỉ lưu **best candidate** cho mỗi bug. APR vẫn thử top-K function nội bộ, nhưng JSON cuối cùng chỉ chứa candidate được chọn:

1. Nếu có candidate pass ở scope `patch_comparison` (đã loại các test `outcome=FAIL` và `outcome_fixed=FAIL`): chọn candidate success đầu tiên.
2. Nếu không có success: chọn candidate có `patch_comparison_post_failed_count` nhỏ nhất.
3. Nếu hòa: chọn candidate có `patch_comparison_post_passed_count` lớn nhất.
4. Candidate có `validation_error` như `compile_failed`, `malformed_function`, `metadata_suite_failed` bị xếp sau candidate chạy test thật.

Các field chính:

| Field | Ý nghĩa |
|---|---|
| `selected_function` | Function best candidate được chọn |
| `patched_function` | Function LLM sinh ra |
| `patched_file` | Toàn bộ source file sau khi byte-range replace function |
| `repair_target_relpath` | File relative path trong buggy tree/container |
| `post_passed_tests`, `post_failed_tests` | Full-suite test IDs thật sau validate (`post_scope = full_suite`) |
| `patch_comparison_post_passed_tests`, `patch_comparison_post_failed_tests` | Test IDs dùng cho patch-comparison, đã loại các fixed-fail nền |
| `status_scope`, `patch_comparison_status`, `real_status` | Phân biệt status dùng để chọn patch với status full-suite |
| `validation_error` | Lỗi validate/build nếu không chạy được test suite; không phải test id |

Nếu `apr_results.json` được sinh từ code cũ, có thể còn `candidate_results` hoặc `compile_failed` trong `post_failed_tests`. Hãy chạy lại APR để sinh format mới.

---

## Tham số Defects4C

Unified-Debugging chọn Defects4C theo **tên folder data** trong:

```text
defects4c/out_tmp_dirs/unified_debugging/<data_folder>/metadata/
```

Mỗi file `*_meta.json` trong folder này phải chứa các trường chuẩn như `project`, `commit_before`, `commit_after`, `source_file`, `compile_cmd`, `test_cmd_template`, `tests`, và `ground_truth`.

### `--dataset`

| Giá trị | Ý nghĩa |
|---|---|
| `--dataset defects4c` | Load tất cả folder có `metadata/` dưới `out_tmp_dirs/unified_debugging/`. |
| `--dataset <data_folder>` | Load đúng folder `out_tmp_dirs/unified_debugging/<data_folder>/metadata/`. |
| `--dataset defects4c-<data_folder>` | Alias tiện dụng, tương đương `--dataset <data_folder>`. |

Ví dụ với dữ liệu hiện có:

```bash
python3 main.py --fl --dataset cjson
python3 main.py --fl --dataset tcpdump
python3 main.py --fl --dataset defects4c      # cjson + tcpdump + các folder khác nếu có
```

Khi thêm project mới, không cần sửa loader/config nếu metadata đã theo schema chuẩn. Chỉ cần đặt data vào đúng folder, ví dụ:

```text
defects4c/out_tmp_dirs/unified_debugging/thetcp/metadata/*.json
```

rồi chạy:

```bash
python3 main.py --fl --dataset thetcp
python3 main.py --apr --dataset thetcp --llm qwen
```

### Container cho APR Defects4C

APR Defects4C cần Docker container đang chạy để validate patch. Adapter sẽ chọn container theo thứ tự:

1. `DEFECTS4C_CONTAINER` nếu biến môi trường này được đặt.
2. `my_defects4c_<data_folder>` nếu chạy theo một folder cụ thể.
3. `my_defects4c` làm fallback.

Ví dụ:

```bash
# Dùng container mặc định theo data folder, ví dụ my_defects4c_cjson
python3 main.py --apr --dataset cjson --llm qwen

# Override container thủ công
DEFECTS4C_CONTAINER=my_defects4c_custom \
python3 main.py --apr --dataset thetcp --llm qwen
```

Lưu ý: `compile_cmd` và `test_cmd_template` trong metadata nên dùng đường dẫn container dạng `/out/...`, vì validation chạy bên trong container.

Với Defects4C, loader tạo cache workspace ở:

```text
Unified-Debugging/experiments/defects4c_cache/<data_folder>/<bug_id>/
├── buggy_ver/   # commit_after + overlay src_files từ commit_before
└── fixed_ver/   # commit_after
```

APR extract function từ `buggy_ver`, ghép patch vào file tương ứng trong buggy version rồi validate trong container. Evaluation lấy accepted code từ `fixed_ver`.

---

## Thêm dataset mới

Xem chi tiết tại [`DATASET_STANDARDS.md`](./DATASET_STANDARDS.md). Tóm tắt:

1. **Tạo Loader** – kế thừa `BugLoader` trong `data_loaders/base_loader.py`, implement `load_all()` trả về `List[BugRecord]`.
2. **Tạo Adapter** – kế thừa `SandboxAdapter` trong `data_loaders/sandbox_adapter.py`, implement `get_source_path()` và `validate()`.
3. **Đăng ký** cả hai trong `get_loader()` và `get_sandbox_adapter()`.

```python
# data_loaders/base_loader.py  →  get_loader()
if name == "defects4c":
    from data_loaders.defects4c_loader import Defects4CLoader
    return Defects4CLoader()

# data_loaders/sandbox_adapter.py → get_sandbox_adapter()
if ds_lc == "mydataset":
    return MyDatasetAdapter(bug_id)
```

---

## Evaluation

### Fault Localization (`eval_fl.py`)

| Chỉ số           | Mô tả                                                  |
|------------------|--------------------------------------------------------|
| **Top-1 Hit Rate** | % bug có hàm lỗi thực sự nằm ở vị trí nghi ngờ số 1 |
| **Top-3 Hit Rate** | % bug có hàm lỗi nằm trong Top 3                     |
| **Top-5 Hit Rate** | % bug có hàm lỗi nằm trong Top 5                     |

> Chỉ tính trên các bug có `ground_truth` trong dữ liệu.

### Automated Program Repair (`eval_apr.py`)

| Chỉ số                            | Mô tả                                                          |
|-----------------------------------|----------------------------------------------------------------|
| **Plausible Fix Rate**            | % bug được vá vượt qua 100% test case                         |
| **Fixed Initial Fails**           | APR có sửa được các test fail ban đầu không                   |
| **Regressions**                   | Bản vá sửa được lỗi gốc nhưng làm hỏng test khác             |
| **Edit Distance (function-level)**| Levenshtein: `patched_function` vs hàm tương ứng trong accepted file |
| **Edit Distance (file-level)**    | Levenshtein: `patched_file` (toàn bộ file) vs accepted file   |

---

## Giới hạn & Hướng phát triển

| Vấn đề | Hướng giải quyết |
|---|---|
| Context window LLM bị giới hạn với function C lớn | Tăng `LLM_MAX_OUTPUT_TOKENS`, hoặc chia nhỏ prompt/repair region |
| `google-generativeai` đã deprecated | Chuyển sang `google.genai` (SDK mới) |
| Edit Distance file-level tốn bộ nhớ với file lớn | Dùng diff-based distance hoặc AST-level comparison |
