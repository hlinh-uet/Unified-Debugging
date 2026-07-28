# Unified-Debugging Pipeline

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

### Chạy unified pipeline theo từng bug

```bash
# Với từng bug: FL → APR → Update FL → ... đến plausible hoặc hết 2 vòng;
# hoàn tất bug hiện tại rồi mới chuyển sang bug kế tiếp.
python3 main.py --full --dataset fmt --llm openrouter

# Tối đa 4 vòng APR cho mỗi bug.
python3 main.py --full --dataset libyang --rounds 4 --llm openrouter

# Chạy unified pipeline cho đúng một bug.
python3 main.py --full --dataset fmt --bug-id A.2 --llm openrouter
```

Mỗi lần chạy tạo một thư mục độc lập:

```text
experiments/full_pipeline_runs/<dataset>/<run-id>/
├── run_manifest.json
├── apr_results_cumulative.json
├── fault_localization_results.json
├── fault_localization_apr_feedback_results.json
├── evaluation.txt
├── bugs/
│   ├── bug_001__A.2/
│   │   ├── bug_manifest.json
│   │   ├── apr_results_cumulative.json
│   │   ├── fault_localization_apr_feedback_results.json
│   │   ├── round_01/
│   │   │   ├── fault_localization_results.json
│   │   │   ├── fault_localization_apr_feedback_results.json
│   │   │   ├── apr_results.json
│   │   │   ├── apr_results_cumulative.json
│   │   │   ├── llm_patches/
│   │   │   ├── patches/
│   │   │   ├── evaluation.txt
│   │   │   └── round_manifest.json
│   │   └── round_02/
│   │       └── ...
│   └── bug_002__A.3/
│       └── ...
└── ...
```

### Chạy từng bước

```bash
# Bước 1 – Fault Localization.
python3 main.py --fl --dataset tcpdump

# Bước 2 – APR
python3 main.py --apr --dataset tcpdump --llm openrouter
python3 main.py --apr --dataset tcpdump --llm openai
python3 main.py --apr --dataset tcpdump    # dùng LLM_PROVIDER trong .env
# APR-valid: giả định FL đúng 100%
python3 main.py --apr --dataset fmt --llm openrouter --valid

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
# tính evaluation cho valid mode
python3 main.py --eval --dataset fmt --valid
```

### Chạy APR kèm ReFix standalone sau pipeline

APR pipeline hiện đã tự gọi ReFix nội tuyến nếu FixAgent chưa success.
Flag `--with-refix` chỉ dùng khi muốn chạy thêm một lượt ReFix standalone
sau khi APR kết thúc, dựa trên artifact đã lưu trong `experiments/llm_patches/`.

```bash
python3 main.py --apr --dataset fmt --llm openrouter --with-refix
python3 main.py --all --dataset fmt --llm openrouter --with-refix

# Chỉ chạy bug chưa có thư mục experiments/llm_patches/<bug-id>.
# Không retry các bug đã có artifact (kể cả negfix/invalid).
python3 main.py --apr --dataset libyang --valid --only-missing --llm openrouter
```


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
| `*__security_patch_validation_agent.response.txt` | Critique LLM riêng cho nhánh security repair |
| `*__correctness_validation_router.context.json` | Phân loại deterministic từ compile/test để chọn ReFix, causal re-diagnosis hoặc plausible pool |

#### APR-valid (`--valid`)

`--valid` dùng cho kịch bản thiết kế riêng APR khi biết FL ban đầu đã hoàn toàn
chính xác:

- tạo `experiments/fault_localization_results_valid.json`;
- mỗi bug có `scores` chỉ gồm ground-truth function ở top 1 với score `1.0`;
- APR đọc file valid này và ép `top-k = 1`;
- manifest APR được ghi riêng vào `experiments/apr_results_valid.json`.

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
| `--only-missing` | Với APR, chỉ chạy bug chưa có thư mục `experiments/llm_patches/<bug-id>`; không retry artifact cũ |
| `--valid`       | Dùng oracle FL: ground-truth top 1, APR chỉ thử top 1; đọc/ghi `fault_localization_results_valid.json` và `apr_results_valid.json` |
| `--eval`        | Chỉ chạy Evaluation (FL + APR), lọc theo dataset   |
| `--all`         | Chạy FL → APR pipeline mới → Evaluation            |
| `--full`        | Chạy trọn FL → APR → Update FL → ... theo từng bug; xong bug hiện tại mới sang bug kế |
| `--rounds`, `--full-rounds` | Số vòng APR tối đa cho mỗi bug trong `--full`; mặc định `2` |
| `--full-apr-strength` | Trọng số APR feedback khi Update FL; mặc định `1.0` |
| `--full-same-file-weight` | Trọng số lan truyền feedback sang function cùng file; mặc định `0.0` |
| `--include-fixed-fail-tests` | Không loại test có `outcome=FAIL` và `outcome_fixed=FAIL`; mặc định các test này bị loại khỏi FL/APR/validation |
| `--fl-eval-level` | Chọn file FL để tính Top-K: `combined`, `valid`, `apr_feedback`, `function`, `file`, `class`, hoặc `all` |
| `--llm`         | Provider APR: `openai` hoặc `openrouter` |
| `--fl-llm-guide` | Cho LLM lập Input/Expected/Actual boundary trace plan; mặc định bật, alias tương thích: `--fl-llm-rerank` |
| `--no-fl-llm-guide` | Tắt LLM của FL và dùng deterministic trace plan |
| `--refresh-runtime-traces` | Bỏ cache và build/chạy lại regression trace |
| `--fl-cache-only` | Chỉ tổng hợp và evaluation các bug đã có runtime cache; không chạy bug còn thiếu |

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
