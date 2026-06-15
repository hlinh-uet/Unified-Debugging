# Unified-Debugging Pipeline

## Luồng hoạt động
```
get_loader(dataset)
      │
      ▼
 [BugRecord list]
      │
      ├──► FL (Tarantula + IR reranker) ────────► fault_localization_results.json
      │
      └──► APR ───► LLM                 ──────► apr_results.json
                         │
                         ▼
                Sandbox Adapter (compile + test)
                         │
                         ├──► ReFix (optional)
                         │        đọc llm_patches fail → LLM sửa lại → validate lại
                         │
                         ▼
                  experiments/patches/      ← bản vá thành công
                         │
                         ▼
                   Evaluation Report
                   (Fix Rate, Regression, ED func + file)
```

---

## Guideline for Starts

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
```

---

## Sử dụng

Tất cả lệnh chạy từ thư mục `Unified-Debugging/`.

### Chạy toàn bộ pipeline

```bash
python3 main.py --all --dataset codeflaws
python3 main.py --all --dataset tcpdump --llm openrouter
```

Mặc định, các mode FL/APR/APR-validate/all đều loại khỏi quy trình những test có
`outcome=FAIL` và `outcome_fixed=FAIL`.
Nếu cần chạy theo hành vi cũ để so sánh, thêm `--include-fixed-fail-tests`.

### Chạy từng bước

```bash
# Bước 1 – Fault Localization.
python3 main.py --fl --dataset tcpdump

# Bước 2 – APR
python3 main.py --apr --dataset tcpdump --llm openrouter
python3 main.py --apr --dataset tcpdump --llm openai
python3 main.py --apr --dataset tcpdump    # dùng LLM_PROVIDER trong .env

# Bước 3 (optional) Validate riêng lại patch do APR sinh ra 
python3 main.py --apr-validate --dataset php
python3 main.py --apr-validate --dataset php --bug-id CVE-2018-7584

# Bước 4 (optional) – ReFix: sửa lại các patch APR đã fail từ artifact đã lưu.
python3 main.py --refix --dataset fmt --llm openrouter
python3 main.py --refix --dataset fmt --bug-id D.2__c1d430e61ab3 --llm openrouter

# Bước 5 (optional) – Evaluation (FL + APR), lọc theo dataset.
python3 main.py --eval --dataset tcpdump
python3 main.py --eval --dataset tcpdump --fl-eval-level function
python3 main.py --eval --dataset tcpdump --fl-eval-level file
python3 main.py --eval --dataset tcpdump --fl-eval-level class
python3 main.py --eval --dataset tcpdump --fl-eval-level all
```

### Chạy APR kèm ReFix

ReFix có thể chạy liền mạch ngay sau APR. Pipeline sẽ sinh patch APR như cũ,
validate, rồi ReFix các candidate đã fail trong `experiments/llm_patches/`.

```bash
python3 main.py --apr --dataset fmt --llm openrouter --with-refix
python3 main.py --apr --dataset fmt --bug-id D.2__c1d430e61ab3 --llm openrouter --with-refix
python3 main.py --all --dataset fmt --llm openrouter --with-refix
```

### ReFix hoạt động như thế nào

ReFix đọc lại artifact APR đã lưu:

```text
experiments/llm_patches/<bug-id>/
```

Với mỗi candidate fail, ReFix dùng:

- function gốc trước APR;
- function đã được APR patch nhưng fail;
- `validation_details`, gồm `validation_error`, failed tests và `validation_log_tail` nếu có;
- context cũ từ FailContext/Retrieval/Fix agent.

ReFix tạo artifact mới dạng `__refix01.*` và không ghi đè artifact APR gốc:

```text
experiments/llm_patches/<bug-id>/
  02__chrono.h_chrono_formatter_chrono_formatter.json
  02__chrono.h_chrono_formatter_chrono_formatter__refix01.json
  02__chrono.h_chrono_formatter_chrono_formatter__refix01.response.txt
  02__chrono.h_chrono_formatter_chrono_formatter__refix01.function.c
  02__chrono.h_chrono_formatter_chrono_formatter__refix01.patched.c
```

Nếu ReFix pass, patch cuối được lưu vào `experiments/patches/` và
`experiments/apr_results.json` được cập nhật. Nếu đang phân tích kết quả cũ
trong `experiments/Results/...`, cần copy đúng `llm_patches/` của experiment đó
về `experiments/llm_patches/` trước khi chạy ReFix độc lập.


### Tham số dòng lệnh

| Tham số         | Mô tả                                              |
|-----------------|----------------------------------------------------|
| `--dataset`     | Tên dataset: `codeflaws`, `defects4c`, hoặc folder Defects4C như `tcpdump`, `php`, `cjson` |
| `--fl`          | Chỉ chạy Fault Localization                        |
| `--apr`         | Chỉ chạy APR với LLM; cần kết quả FL trước đó      |
| `--apr-validate` | Chỉ validate lại patch artifact đã lưu, không gọi LLM |
| `--refix`       | Chạy ReFix từ `experiments/llm_patches/` đã lưu    |
| `--bug-id`      | Giới hạn một bug khi dùng `--apr-validate` hoặc `--refix`, ví dụ `CVE-2018-7584` |
| `--with-refix`  | Sau APR hoặc `--all`, chạy thêm ReFix trước Evaluation |
| `--eval`        | Chỉ chạy Evaluation (FL + APR), lọc theo dataset   |
| `--all`         | Chạy FL → APR LLM → Evaluation                     |
| `--include-fixed-fail-tests` | Không loại test có `outcome=FAIL` và `outcome_fixed=FAIL`; mặc định các test này bị loại khỏi FL/APR/validation |
| `--fl-eval-level` | Chọn file FL để tính Top-K: `combined`, `function`, `file`, `class`, hoặc `all` |
| `--llm`         | Provider APR: `openai` hoặc `openrouter` |


---

## Guideline for Defects4C

Unified-Debugging chọn Defects4C theo **tên folder data** trong:

```text
defects4c/out_tmp_dirs/unified_debugging/<data_folder>/metadata/
```

### `--dataset`

| Giá trị | Ý nghĩa |
|---|---|
| `--dataset defects4c` | Load tất cả folder có `metadata/` dưới `out_tmp_dirs/unified_debugging/`. |
| `--dataset <data_folder>` | Load đúng folder `out_tmp_dirs/unified_debugging/<data_folder>/metadata/`. |
| `--dataset defects4c-<data_folder>` | Alias tiện dụng, tương đương `--dataset <data_folder>`. |

Khi thêm project mới, không cần sửa loader/config nếu metadata đã theo schema chuẩn. Chỉ cần đặt data vào đúng folder, ví dụ:

```text
defects4c/out_tmp_dirs/unified_debugging/thetcp/metadata/*.json
```

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
