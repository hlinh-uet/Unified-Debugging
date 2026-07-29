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
Regression test → Shared Fail Context → FL → APR (reuse Fail Context) → Evaluation
```

### Chạy unified pipeline theo từng bug

```bash
# Với từng bug: FL → APR → Update FL → ... đến plausible hoặc hết 2 vòng;
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

Các round APR không reset về cùng top-k. Mỗi bug lưu exact FL function keys
đã được xét; round sau loại các key này trước khi lấy `APR_TOP_K`, rồi tự lấp
slot bằng các hàm chưa thử ở phía dưới ranking mới. Nếu không còn candidate
chưa thử, bug dừng với `candidate_space_exhausted` thay vì gọi lại agent/LLM.
`round_manifest.json` lưu selection của round, danh sách đã thử và selection
dự kiến cho round tiếp theo.

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

### Shared Fail Context

FL và APR dùng chung một Fail Context bất biến theo `context_id`:

- regression/census run cung cấp fresh `stdout/stderr`, return code và artifact;
- builder ánh xạ output về đúng failing assertion, rồi lấy test input bằng
  dependency slice của scenario đó; với stdin-style test, builder đọc đúng
  fixture `input-<test-id>` và expected-output tương ứng;
- Shared `FailContextAgent` chọn/thu regression evidence, ghi context tại
  `experiments/runtime_traces/<dataset>/<bug-id>/fail_context.json` và dùng nó
  làm nguồn failure semantics cho cả FL lẫn APR;
- FL và APR đọc cùng canonical context/context artifact. APR standalone ưu
  tiên cache của shared agent; nếu không có fresh regression context thì APR
  dừng bug thay vì giả lập context từ metadata cũ;
- `ground_truth` và FL candidate không được dùng để dựng Fail Context.

### Shared Program Analysis

Tree-sitter, Clang và Joern là các provider dùng chung tại
`core/program_analysis/`, không còn thuộc riêng correctness APR:

- FailContext/FL dùng cùng helper Tree-sitter để truy test input, assertion và
  source dossier; FL dùng shared Clang provider khi có
  `compile_commands.json`;
- correctness APR dùng Tree-sitter cho SyntaxIR, Clang cho semantic binding và
  chỉ gọi Joern khi có proof gap; security APR dùng cùng Joern/Tree-sitter
  service cho operation/context evidence;
- `core.apr.program_analysis` và module Clang cũ chỉ là compatibility alias,
  nên caller cũ và mới dùng đúng cùng function object và cache;
- shared evidence store chỉ giữ static result đã bounded hoặc compact index
  tới FL source artifact. Nó không lưu bản sao full runtime trace và không
  quyết định ranking, hypothesis hay patch.

Runtime trace của FL tự thích ứng theo từng bug/test:

- Sau build, FL chạy một lượt **count/edge census**: hook chỉ đếm số lần vào
  hàm và cạnh gọi aggregate, không ghi từng E/X. Function thực sự xuất hiện
  trong fresh census là candidate universe; coverage metadata chỉ còn là hint
  để audit/tối ưu và không được phép loại function đã chạy.
- Từ census, FL tìm exact producer roots trong assertion, xếp hạng
  output/error sinks bằng source-contract specificity, rồi lấy các đường gọi
  đã execute từ producer tới sink. Static call edges chỉ dùng để nối chỗ thiếu
  dynamic edge; dynamic-only edges được đánh dấu là callback/indirect dispatch
  liên quan; không còn lấy toàn bộ caller/callee neighborhood.
- Chỉ function trên producer→sink paths và một frontier nhỏ mới được cân nhắc
  cho detailed E/X. Hard budget áp dụng cho mọi function, kể cả root/sink:
  function quá nóng trở thành aggregate-only thay vì được phép vượt trần.
- Sau census và trước probe build, shared investigation query broker hợp nhất
  deterministic `TraceQuery` và information-needs của LLM cho từng câu hỏi producer/path,
  argument boundary, return boundary, relevant write và branch outcome. Probe
  được đặt trên toàn producer→sink path, kể cả function nóng bị loại khỏi
  ordered E/X; mỗi probe có quota mẫu riêng.
  Nếu probe rebuild lỗi, source được khôi phục từ snapshot trong container và
  FL rebuild lại ở chế độ control-only; không bỏ cả bug chỉ vì probe phụ lỗi.
- Detailed chỉ chạy một scenario-window pass; không tự tăng 300.000 →
  600.000 → 1.200.000. Nếu `nm` không tạo được scope, FL giữ census evidence
  thay vì vô tình fallback sang full ordered trace.
- Nếu ordered slice chạm budget trước khi trả lời hết `TraceQuery`, FL chạy
  đúng một **probe-only recovery pass** với probe reserve; không tăng global
  E/X limit. Evidence thiếu được ghi `incomplete_overflow`/`unknown`, không
  được hiểu là function hay boundary không liên quan.
- Probe ở loop nóng vượt sample quota được ghi `observed_*_sampled` và tạo
  follow-up `invocation_window_refinement`; sample đầu không được nâng thành
  causal support hoàn chỉnh.
- Census, detailed và recovery output được so bằng immutable Fail Context ID.
  Evidence từ một rerun không tái hiện cùng failure signature sẽ bị đánh dấu
  `signature_mismatch` và không được nhập vào localization.
- Tổng ngân sách detailed mặc định là 260.000 event, gồm E/X và 40.000 event
  dự phòng cho source probes. Có thể chỉnh bằng
  `UDBG_TRACE_DETAILED_EVENT_BUDGET` và
  `UDBG_TRACE_SLICE_PROBE_EVENT_RESERVE`.
- Raw census/detailed/probe stream được gzip ngay sau post-process; cache đầy
  đủ cũng là JSON gzip. Pipeline mới không để lại raw `.trace` chưa nén.
- Câu hỏi, câu trả lời và completeness được lưu riêng tại
  `runtime_trace_queries.json`; probe-only recovery chỉ nhập observations, không
  nhân đôi ordered trace vào runtime evidence.
- Một bảng function coverage nhẹ được ghi độc lập với ordered-event limit. Vì
  vậy hàm đã chạy trước khi trace bị cắt vẫn còn trong candidate set, nhưng
  không bị xem nhầm là failure boundary.
- Lỗi hạ tầng như thiếu `run_one_test.sh`, exit code 126/127 hoặc trace rỗng
  không còn được tính là regression failure hợp lệ.
- Không còn causal targeted-probe build thứ hai. Mọi probe được cài trong cùng
  slice-probe build; sau ranking không được clean/build/chạy regression lại.
  Câu hỏi vượt budget giữ trạng thái `unknown`. Function-level
  invocation identity chỉ giữ 128 mẫu audit; tổng count và ordered events vẫn
  được bảo toàn.

Source AST được index theo `(realpath, mtime_ns, size)` và structural dossier
được dùng lại giữa các failed test/scenario. Persistent source cache còn mang
digest của nội dung source để không reuse nhầm worktree đã đổi. Causal evidence
và compilation database được lưu content-addressed; các file score giữ
`causal_evidence_ref`, còn source dossiers tham chiếu source-evidence cache.
Checkpoint nằm trong output của từng run và manifest chỉ ghi đường dẫn per-bug,
thay vì serialize lại bốn map kết quả đang tăng dần.

Có thể điều chỉnh trần mà không sửa mã:

| Biến | Mặc định | Mô tả |
|------|----------|-------|
| `UDBG_TRACE_INITIAL_MAX_EVENTS` | `300000` | Giới hạn ordered event lần đầu |
| `UDBG_TRACE_MAX_RETRY_EVENTS` | `1200000` | Giới hạn ordered event tối đa |
| `UDBG_TRACE_MAX_ATTEMPTS` | `3` | Số lần chạy tối đa cho mỗi regression test |
| `UDBG_TRACE_DETAILED_EVENT_BUDGET` | `260000` | Tổng hard budget cho detailed E/X và slice probes |
| `UDBG_TRACE_SLICE_PROBE_EVENT_RESERVE` | `40000` | Phần budget dành cho branch/argument/return/write probes |

Sau thay đổi instrumentation, chạy `--refresh-runtime-traces` nếu muốn chủ
động tạo lại ngay. Một lượt FL/full bình thường cũng tự loại cache instrumentation
cũ và thu trace mới; `--fl-cache-only` thì không chạy lại test.

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
