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
│   ├── tarantula_results.json          # Kết quả FL (Tarantula scores)
│   ├── apr_results.json                # Kết quả APR – LLM
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

> **Điểm quan trọng:** FL và APR đều dùng **một lần load dữ liệu duy nhất** thông qua `get_loader()` → trả về `List[BugRecord]`. Không module nào đọc lại file JSON gốc sau bước này.

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
#   GEMINI_API_KEY=...         – Gemini API Key (cho LLM baseline)
```

---

## Sử dụng

Tất cả lệnh chạy từ thư mục `Unified-Debugging/`.

### Chạy toàn bộ pipeline

```bash
python3 main.py                          # mặc định: dataset=codeflaws
python3 main.py --all --dataset codeflaws
```

### Chạy từng bước

```bash
# Bước 1 – Fault Localization
python3 main.py --fl --dataset defects4c

# Bước 2a – APR bằng LLM (cần GEMINI_API_KEY)
python3 main.py --apr --dataset defects4c --llm gemini      # dùng gemini-2.5-flash
python3 main.py --apr --dataset defects4c --llm openai # dùng gpt-4o-mini
python main.py --apr # dùng LLM_PROVIDER trong .env


# Bước 3 – Evaluation (FL + APR)
python3 main.py --eval
```

### Tham số dòng lệnh

| Tham số         | Mô tả                                              |
|-----------------|----------------------------------------------------|
| `--dataset`     | Tên dataset: `codeflaws` (mặc định), `defects4c`, ... |
| `--fl`          | Chỉ chạy Fault Localization                        |
| `--apr`         | Chỉ chạy APR với LLM (Gemini)                      |
| `--eval`        | Chỉ chạy Evaluation (FL + APR)                     |
| `--all`         | Chạy FL → APR LLM → Evaluation                     |

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
python3 main.py --apr --dataset thetcp --llm gemini
```

### Container cho APR Defects4C

APR Defects4C cần Docker container đang chạy để validate patch. Adapter sẽ chọn container theo thứ tự:

1. `DEFECTS4C_CONTAINER` nếu biến môi trường này được đặt.
2. `my_defects4c_<data_folder>` nếu chạy theo một folder cụ thể.
3. `my_defects4c` làm fallback.

Ví dụ:

```bash
# Dùng container mặc định theo data folder, ví dụ my_defects4c_cjson
python3 main.py --apr --dataset cjson --llm gemini

# Override container thủ công
DEFECTS4C_CONTAINER=my_defects4c_custom \
python3 main.py --apr --dataset thetcp --llm gemini
```

Lưu ý: `compile_cmd` và `test_cmd_template` trong metadata nên dùng đường dẫn container dạng `/out/...`, vì validation chạy bên trong container.

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

# data_loaders/sandbox_adapter.py  →  get_sandbox_adapter()
if dataset_name.lower() == "defects4c":
    return Defects4CAdapter(bug_id)
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
| Trích xuất hàm C bằng Regex dễ sai với macro/comment chứa `{}` | Dùng `pycparser`, Clang AST hoặc `tree-sitter` |
| Context window LLM bị giới hạn với file C lớn | Nén prompt, chỉ truyền hàm liên quan thay vì toàn bộ file |
| `google-generativeai` đã deprecated | Chuyển sang `google.genai` (SDK mới) |
| Edit Distance file-level tốn bộ nhớ với file lớn | Dùng diff-based distance hoặc AST-level comparison |
