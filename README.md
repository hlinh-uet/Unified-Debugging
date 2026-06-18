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
      └──► APR
             │
             ├──► FailContextAgent
             ├──► CodeContextCollectorAgent
             │        gom function lỗi, include/header/helper, symbol/API liên quan
             │
             ├──► FixAgent
             │        sinh patch hàm từ fail context + code evidence
             │
             ├──► Sandbox Adapter
             │        apply patch → compile/test → lưu validation context
             │
             ├──► PatchValidationAgent nếu FixAgent chưa success
             │        phân tích patch fail: giữ gì, revert gì, tránh đổi gì
             │
             ├──► ReFixAgent nếu FixAgent chưa success
             │        sửa tiếp từ best FixAgent candidate + validation feedback + patch critique
             │
             ├──► Chọn kết quả tốt hơn giữa Fix best và ReFix result
             │
             ├──► experiments/llm_patches/<bug-id>/  ← mọi artifact/log/context
             ├──► experiments/patches/               ← bản vá success
             └──► apr_results.json                   ← manifest/kết quả tổng hợp
                         │
                         ▼
                  Evaluation Report
                  (patch-comparison + real/full metrics, ED func + file)
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

`--all` chạy theo thứ tự:

```text
FL → APR pipeline mới → Evaluation
```

Trong APR pipeline mới, ReFix đã được gọi tự động nếu best FixAgent candidate
chưa success. Vì vậy, bình thường không cần thêm `--with-refix`.

Mặc định, các mode FL/APR/APR-validate/ReFix/all đều loại khỏi quy trình những test có
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

# APR trên một bug cụ thể chưa được hỗ trợ trực tiếp bởi --apr.
# Nếu muốn chạy một bug, lọc FL input/result trước hoặc chạy ReFix/APR-validate với --bug-id.

# Bước 3 (optional) Validate riêng lại patch do APR sinh ra 
python3 main.py --apr-validate --dataset php
python3 main.py --apr-validate --dataset php --bug-id CVE-2018-7584

# Bước 4 (optional) – ReFix standalone: sửa lại best failed FixAgent artifact đã lưu.
python3 main.py --refix --dataset fmt --llm openrouter
python3 main.py --refix --dataset fmt --bug-id D.2__c1d430e61ab3 --llm openrouter

# Bước 5 (optional) – Evaluation (FL + APR), lọc theo dataset.
python3 main.py --eval --dataset tcpdump
python3 main.py --eval --dataset tcpdump --fl-eval-level function
python3 main.py --eval --dataset tcpdump --fl-eval-level file
python3 main.py --eval --dataset tcpdump --fl-eval-level class
python3 main.py --eval --dataset tcpdump --fl-eval-level all
```

### Chạy APR kèm ReFix standalone sau pipeline

APR pipeline hiện đã tự gọi ReFix nội tuyến nếu FixAgent chưa success.
Flag `--with-refix` chỉ dùng khi muốn chạy thêm một lượt ReFix standalone
sau khi APR kết thúc, dựa trên artifact đã lưu trong `experiments/llm_patches/`.

```bash
python3 main.py --apr --dataset fmt --llm openrouter --with-refix
python3 main.py --all --dataset fmt --llm openrouter --with-refix
```

### ReFix hoạt động như thế nào

Có hai cách ReFix chạy:

1. **ReFix nội tuyến trong APR pipeline**
   - chạy tự động khi best FixAgent candidate chưa success;
   - chỉ nhận best FixAgent candidate, không sửa lại toàn bộ failed artifacts;
   - so sánh Fix best và ReFix result bằng quality key rồi chọn kết quả tốt hơn.

2. **ReFix standalone bằng `--refix` hoặc `--with-refix`**
   - đọc artifact đã lưu;
   - chọn best failed FixAgent artifact của bug;
   - chạy ReFix và cập nhật `apr_results.json` kể cả khi ReFix không được chọn.

Artifact được đọc từ:

```text
experiments/llm_patches/<bug-id>/
```

ReFix dùng:

- function gốc trước APR;
- function đã được FixAgent patch nhưng fail;
- validation context/log của patch đó;
- PatchValidationAgent critique về patch fail nếu có;
- `validation_error`, failed tests, full failed tests nếu có;
- context cũ từ FailContextAgent, CodeContextCollectorAgent, FixAgent và PatchValidationAgent.

ReFix tạo artifact mới dạng `__refix01.*` và không ghi đè artifact FixAgent gốc:

```text
experiments/llm_patches/<bug-id>/
  02__file.c_function.json
  02__file.c_function.response.txt
  02__file.c_function.function.c
  02__file.c_function.patched.c
  02__file.c_function.validation.json
  02__file.c_function__patch_validation_agent.json
  02__file.c_function__patch_validation_agent.response.txt

  02__file.c_function__refix01.json
  02__file.c_function__refix01.response.txt
  02__file.c_function__refix01.function.c
  02__file.c_function__refix01.patched.c
  02__file.c_function__refix01.validation.json
```

Nếu ReFix pass hoặc tốt hơn Fix best, patch cuối được lưu vào `experiments/patches/`
và `experiments/apr_results.json` được cập nhật. Nếu ReFix không tốt hơn,
`apr_results.json` vẫn lưu `refix_agent_result`, `refix_attempted=true`,
`refix_selected=false`, `refix_applied=false` để trace.

Nếu đang phân tích kết quả cũ trong `experiments/Results/...`, cần copy đúng
`llm_patches/` của experiment đó về `experiments/llm_patches/` trước khi chạy
ReFix độc lập.

### Output được lưu

#### `experiments/llm_patches/<bug-id>/`

Lưu toàn bộ output/log/context của từng lần sinh patch:

| File | Nội dung |
|------|----------|
| `*.response.txt` | Raw response từ LLM |
| `*.function.c` | Hàm đã sửa |
| `*.patched.c` | Full source file sau khi thay hàm sửa vào file gốc |
| `*.validation.json` | Validation context, log, failed tests, agent context |
| `*.json` | Metadata artifact: status, path, agent artifact, evaluation snapshot |
| `*__patch_validation_agent.response.txt` | Critique JSON cho patch FixAgent fail, dùng làm input cho ReFix |

#### `experiments/apr_results.json`

Đây là manifest/kết quả tổng hợp cuối cho từng bug. Các field quan trọng:

| Field | Ý nghĩa |
|-------|---------|
| `selected_agent` | Kết quả cuối đến từ `fix_agent` hay `refix_agent` |
| `selected_candidate` | Candidate cuối được chọn |
| `llm_patch_artifact` | Artifact của patch cuối |
| `fix_agent_candidates` | Tất cả candidate FixAgent đã thử |
| `fix_agent_best_candidate` | Best candidate của FixAgent |
| `refix_agent_result` | Kết quả ReFix nếu đã chạy |
| `evaluation_history` | Evaluation của FixAgent và ReFixAgent |
| `status` | Kết quả theo patch-comparison scope, có exclude fixed-fail tests |
| `real_status` | Kết quả full scope, không bỏ qua fixed-fail tests |
| `post_failed_tests` | Failed tests sau patch ở comparison scope |
| `full_post_failed_tests` | Failed tests sau patch ở full scope |
| `fixed_fail_excluded_tests` | Các test bị loại vì buggy+fixed đều fail |


### Tham số dòng lệnh

| Tham số         | Mô tả                                              |
|-----------------|----------------------------------------------------|
| `--dataset`     | Tên dataset: `codeflaws`, `defects4c`, hoặc folder Defects4C như `tcpdump`, `php`, `cjson` |
| `--fl`          | Chỉ chạy Fault Localization                        |
| `--apr`         | Chạy APR pipeline mới với LLM; cần kết quả FL trước đó |
| `--apr-validate` | Chỉ validate lại patch artifact đã lưu, không gọi LLM |
| `--refix`       | Chạy ReFix standalone từ `experiments/llm_patches/` đã lưu |
| `--bug-id`      | Giới hạn một bug khi dùng `--apr-validate`, `--refix`, hoặc `--with-refix`, ví dụ `CVE-2018-7584` |
| `--with-refix`  | Sau APR hoặc `--all`, chạy thêm ReFix standalone từ artifact đã lưu |
| `--eval`        | Chỉ chạy Evaluation (FL + APR), lọc theo dataset   |
| `--all`         | Chạy FL → APR pipeline mới → Evaluation            |
| `--include-fixed-fail-tests` | Không loại test có `outcome=FAIL` và `outcome_fixed=FAIL`; mặc định các test này bị loại khỏi FL/APR/validation |
| `--fl-eval-level` | Chọn file FL để tính Top-K: `combined`, `apr_feedback`, `function`, `file`, `class`, hoặc `all` |
| `--llm`         | Provider APR: `openai` hoặc `openrouter` |

### Biến môi trường APR

| Biến | Mặc định | Mô tả |
|------|----------|-------|
| `APR_TOP_K` | `3` | Số candidate FL được APR thử cho mỗi bug |
| `APR_SKIP_EXISTING` | `1` | Bỏ qua bug đã có trong `apr_results.json`; đặt `0` để chạy lại |


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
