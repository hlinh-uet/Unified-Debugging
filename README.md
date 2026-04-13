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
│   ├── utils.py               # Tiện ích dùng chung (extract_function_code, ...)
│   ├── fl_tarantula.py        # Thuật toán Fault Localization – Tarantula
│   ├── apr_baseline.py        # APR với LLM (Gemini)
│   └── apr_mutation.py        # APR với Heuristic Mutation (không cần LLM)
│
├── evaluation/                # Đánh giá và báo cáo
│   ├── eval_fl.py             # Đánh giá FL: Top-1/3/5 Hit Rate
│   └── eval_apr.py            # Đánh giá APR: Fix Rate, Regression, Edit Distance
│
├── experiments/               # Sinh ra sau khi chạy – chứa kết quả
│   ├── tarantula_results.json
│   ├── apr_results.json
│   ├── apr_mutation_results.json
│   └── correct_patches/       # Bản vá tham chiếu (accepted patches)
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
      ├──► FL (Tarantula) ──► tarantula_results.json
      │
      └──► APR ─┬─► LLM (Gemini)       ──► apr_results.json
                └─► Heuristic Mutation  ──► apr_mutation_results.json
                        │
                        ▼
                Sandbox Adapter (compile + test)
                        │
                        ▼
                  Evaluation Report
```

**Điểm quan trọng:** FL và APR đều dùng **một lần load dữ liệu duy nhất** thông qua `get_loader()` → trả về `List[BugRecord]`. Không module nào đọc lại file JSON gốc sau bước này.

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

### 3. Cấu hình API Key

```bash
cp .env.example .env
# Mở .env, thay YOUR_KEY_HERE bằng Gemini API Key thực tế
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
python3 main.py --fl --dataset codeflaws

# Bước 2a – APR bằng LLM (cần GEMINI_API_KEY)
python3 main.py --apr --dataset codeflaws

# Bước 2b – APR bằng Heuristic Mutation 
python3 main.py --apr-mutation --dataset codeflaws

# Bước 2c – APR bằng GenProg (Cần cài đặt GenProg)
python3 main.py --apr-genprog --dataset codeflaws

# Bước 3 – Evaluation
python3 main.py --eval
```

### Tham số dòng lệnh

| Tham số | Mô tả |
|---|---|
| `--dataset` | Tên dataset: `codeflaws` (mặc định), `defects4c`, ... |
| `--fl` | Chỉ chạy Fault Localization |
| `--apr` | Chỉ chạy APR với LLM |
| `--apr-mutation` | Chỉ chạy APR với Heuristic Mutation |
| `--apr-mutation` | Chỉ chạy APR với Genprog |
| `--eval` | Chỉ chạy Evaluation |
| `--all` | Chạy FL → APR LLM → Evaluation |

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

| Chỉ số | Mô tả |
|---|---|
| **Top-1 Hit Rate** | % bug có hàm lỗi thực sự nằm ở vị trí nghi ngờ số 1 |
| **Top-3 Hit Rate** | % bug có hàm lỗi nằm trong Top 3 |
| **Top-5 Hit Rate** | % bug có hàm lỗi nằm trong Top 5 |

> Chỉ tính trên các bug có `ground_truth` trong dữ liệu.

### Automated Program Repair (`eval_apr.py`)

| Chỉ số | Mô tả |
|---|---|
| **Plausible Fix Rate** | % bug được vá vượt qua 100% test case |
| **Fixed Initial Fails** | APR có sửa được các test fail ban đầu không |
| **Regressions** | Bản vá sửa được lỗi gốc nhưng làm hỏng test khác |
| **Edit Distance** | Khoảng cách Levenshtein giữa bản vá AI và accepted patch |

---

## Giới hạn & Hướng phát triển

| Vấn đề | Hướng giải quyết |
|---|---|
| Trích xuất hàm C bằng Regex dễ sai với macro/comment chứa `{}` | Dùng `pycparser`, Clang AST hoặc `tree-sitter` |
| Context window LLM bị giới hạn với file C lớn | Nén prompt, chỉ truyền hàm liên quan thay vì toàn bộ file |
| `google-generativeai` đã deprecated | Chuyển sang `google.genai` (SDK mới) |


## Cài đặt GenProg (tool APR)
### Cách 1: Dùng Docker: 
```bash
# Pull image có sẵn GenProg + CIL
docker pull squareslab/genprog

# Chạy container, mount workspace vào
docker run -it \
  -v "/Users/linhnh/Documents/Fault Localization:/workspace" \
  squareslab/genprog \
  /bin/bash

# Trong container, kiểm tra GenProg binary
which repair
# => /root/genprog-code/src/repair (hoặc tương tự)
```

Sau khi biết path của binary `repair` trong container, bạn có thể chạy pipeline từ trong container, hoặc set `GENPROG_BIN` trong file `.env`: 
```bash
GENPROG_BIN=/root/genprog-code/src/repair
```

### Cách 2: Build từ source

```bash
# 1. Cài OCaml + opam
brew install opam ocaml
opam init -y
eval $(opam env)

# 2. Cài CIL (C Intermediate Language) - GenProg phụ thuộc vào nó
opam install cil

# 3. Clone GenProg source v3.0
cd ~/
git clone https://github.com/squaresLab/genprog-code.git
cd genprog-code/src

# 4. Build
make

# 5. Kiểm tra binary
./repair --help
```

Nếu build thành công, set trong file `.env` ở thư mục `Unified-Debugging/`: 

```bash
GENPROG_BIN=/Users/linhnh/genprog-code/src/repair
```

