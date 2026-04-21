# Unified-Debugging Pipeline

Hệ thống tự động **Định vị lỗi (Fault Localization)** và **Sửa lỗi tự động (Automated Program Repair)** cho các chương trình C, hỗ trợ nhiều bộ dữ liệu (Codeflaws, Defects4C, ...) thông qua kiến trúc mở rộng Adapter.

---

## Cấu trúc dự án

```
Unified-Debugging/
├── main.py                    # Entry-point duy nhất – điều phối toàn bộ pipeline
├── requirements.txt
├── .env.example               # Mẫu biến môi trường (API Key, GenProg config)
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
│   ├── apr_baseline.py        # APR với LLM (Gemini)
│   ├── apr_mutation.py        # APR với Heuristic Mutation (không cần LLM)
│   └── apr_genprog.py         # APR với GenProg (Genetic Programming)
│
├── evaluation/                # Đánh giá và báo cáo
│   ├── eval_fl.py             # Đánh giá FL: Top-1/3/5 Hit Rate
│   └── eval_apr.py            # Đánh giá APR: Fix Rate, Regression, Edit Distance
│
├── experiments/               # Sinh ra sau khi chạy – chứa kết quả
│   ├── tarantula_results.json          # Kết quả FL (Tarantula scores)
│   ├── apr_results.json                # Kết quả APR – LLM (Gemini)
│   ├── apr_mutation_results.json       # Kết quả APR – Heuristic Mutation
│   ├── apr_genprog_results.json        # Kết quả APR – GenProg
│   ├── patches/                        # Bản vá thành công (status=success)
│   │   ├── <bug_id>_patch.c            #   – từ LLM baseline
│   │   ├── <bug_id>_mutation_patch.c   #   – từ Mutation
│   │   └── <bug_id>_genprog_patch.c    #   – từ GenProg
│   ├── correct_patches/                # Bản vá tham chiếu (accepted patches, Codeflaws)
│   └── genprog-run/                    # Workdir tạm của GenProg (mỗi bug một thư mục)
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
      └──► APR ─┬─► LLM (Gemini)       ──────► apr_results.json
                ├─► Heuristic Mutation  ──────► apr_mutation_results.json
                └─► GenProg             ──────► apr_genprog_results.json
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
#   GENPROG_BIN=...            – Đường dẫn tới binary GenProg (cho apr_genprog)
#   GENPROG_TIMEOUT=3600       – Timeout (giây) mỗi lần chạy GenProg
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


# Bước 2b – APR bằng Heuristic Mutation 
python3 main.py --apr-mutation --dataset codeflaws

# Bước 2c – APR bằng GenProg (cần cài GenProg binary)
python3 main.py --apr-genprog --dataset codeflaws

# Bước 3 – Evaluation (FL + APR)
python3 main.py --eval
```

### Tham số dòng lệnh

| Tham số         | Mô tả                                              |
|-----------------|----------------------------------------------------|
| `--dataset`     | Tên dataset: `codeflaws` (mặc định), `defects4c`, ... |
| `--fl`          | Chỉ chạy Fault Localization                        |
| `--apr`         | Chỉ chạy APR với LLM (Gemini)                      |
| `--apr-mutation`| Chỉ chạy APR với Heuristic Mutation                |
| `--apr-genprog` | Chỉ chạy APR với GenProg                           |
| `--eval`        | Chỉ chạy Evaluation (FL + APR)                     |
| `--all`         | Chạy FL → APR LLM → APR Mutation → Evaluation     |

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

---

## Cài đặt GenProg (tool APR)

> **macOS (khuyến nghị):** Dùng Docker wrapper — chạy lệnh Python bình thường trên macOS, không cần vào container.

### Cách 1: Docker Wrapper (macOS, không cần vào container)

GenProg binary là Linux x86-64 nên không chạy native trên macOS. Pipeline đã có sẵn wrapper script `scripts/genprog-docker.sh` tự động gọi Docker trong suốt — bạn chỉ cần Docker Desktop đang chạy.

**Bước 1: Pull image (một lần duy nhất)**
```bash
docker pull squareslab/genprog
```

**Bước 2: Set `GENPROG_BIN` trong `.env` trỏ đến wrapper script**
```bash
# Trong file Unified-Debugging/.env:
GENPROG_BIN=/Users/linhnh/Documents/Fault Localization/Unified-Debugging/scripts/genprog-docker.sh
```

**Bước 3: Chạy pipeline bình thường từ macOS terminal**
```bash
cd "Unified-Debugging"
source .venv/bin/activate
python3 main.py --apr-genprog --dataset codeflaws
```

Wrapper script sẽ tự động mount đúng thư mục làm việc và gọi binary GenProg bên trong container, hoàn toàn trong suốt với `main.py`.

---

### Cách 2: Chạy trực tiếp trong container (không dùng wrapper)

Nếu muốn debug hoặc thử nghiệm thủ công trong container:

```bash
# Pull image
docker pull squareslab/genprog

# Vào container, mount workspace
docker run -it \
  -v "/Users/linhnh/Documents/Fault Localization:/workspace" \
  squareslab/genprog \
  /bin/bash
```

Trong container, cài Python environment và chạy pipeline:
```bash
cd /workspace/Unified-Debugging
apt-get install -y python3-venv python3-pip
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
python3 main.py --apr-genprog --dataset codeflaws
```

Set trong `.env` (khi chạy trong container):
```bash
GENPROG_BIN=/opt/genprog/bin/genprog
```

### Cách 3: Build từ source (Linux/macOS với Rosetta)

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

Set trong `.env`:
```bash
GENPROG_BIN=/Users/linhnh/genprog-code/src/repair
```
