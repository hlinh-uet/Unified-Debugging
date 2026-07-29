# Kiến trúc và Luồng hoạt động – Unified-Debugging

---

## 1. Tổng quan kiến trúc

```
┌─────────────────────── main.py ────────────────────────────┐
│  python3 main.py --dataset <name> [--fl|--apr|--eval|--all] │
└─────────────────────┬──────────────────────────────────────┘
                      │
          ┌───────────▼────────────┐
          │   data_loaders/        │   ← Entry-point duy nhất để nạp dữ liệu
          │   get_loader(dataset)  │
          │   → List[BugRecord]    │
          └───────┬────────────────┘
                  │  (một lần duy nhất, dùng chung cho FL + APR)
        ┌─────────┴───────────────────┐
        │                             │
┌───────▼──────────────┐  ┌─────────────▼──────────────────────────┐
│ core/                │  │  core/                                 │
│ fault_localization/  │  │  apr/ + apr_baseline.py wrapper        │
│ package              │  │                                      │
└───────┬──────────────┘  │                                      │
        │                └─────────────┬──────────────────────────┘
        │                              │
        │                ┌─────────────▼───────────────────────────┐
        │                │  data_loaders/sandbox_adapter.py         │
        │                │  SandboxAdapter.validate()               │
        │                │  → compile + chạy test                   │
        │                └──────────────────────────────────────────┘
        │
┌───────▼──────────────────────────────┐
│  experiments/                         │
│  fault_localization_results.json      │
│  apr_results.json                     │
│  patches/  correct_patches/           │
└───────┬──────────────────────────────┘
        │
┌───────▼──────────────────────────┐
│  evaluation/                     │
│  eval_fl.py   eval_apr.py        │
│  (ED func-level + file-level)    │
└──────────────────────────────────┘
```

---

## 2. Lớp Data Loader (Thống nhất)

### 2.1 Tại sao cần lớp này?

Trước đây FL và APR mỗi bước tự đọc lại file JSON riêng, gây rời rạc và khó mở rộng sang dataset mới. Giờ toàn bộ đi qua một interface duy nhất:

```python
from data_loaders.base_loader import get_loader

loader = get_loader("codeflaws")   # hoặc "defects4c", ...
bugs   = loader.load_all()         # → List[BugRecord]
```

### 2.2 BugRecord – Chuẩn dữ liệu dùng chung

```python
@dataclass
class BugRecord:
    bug_id            : str           # ID của bug
    dataset           : str           # tên dataset
    tests             : List[dict]    # danh sách test case (PASS/FAIL)
    ground_truth      : List[str]     # hàm lỗi thực sự (nếu có)
    source_file       : str           # đường dẫn tuyệt đối file .c
    compile_cmd       : Optional[str] # lệnh compile (nếu cần)
    test_cmd_template : Optional[str] # template lệnh chạy test
    raw               : Optional[dict]# raw JSON gốc
```

Cấu trúc `tests` bên trong mỗi `BugRecord` tuân theo chuẩn trong `DATASET_STANDARDS.md`:

```json
{
  "test_id": "neg1",
  "outcome": "FAIL",
  "expected_output": "10",
  "actual_output": "0",
  "fail_reason": "Output mismatch"
}
```

### 2.3 Thêm dataset mới

**Bước 1 – Tạo Loader** (`data_loaders/<dataset>_loader.py`):

```python
from data_loaders.base_loader import BugLoader, BugRecord

class Defects4CLoader(BugLoader):
    def load_all(self) -> List[BugRecord]:
        # Đọc file JSON / thư mục dataset của bạn
        # Trả về List[BugRecord] theo chuẩn
        ...
```

**Bước 2 – Tạo Sandbox Adapter** (`data_loaders/sandbox_adapter.py`):

```python
class Defects4CAdapter(SandboxAdapter):
    def get_source_path(self) -> str:
        # Đường dẫn tuyệt đối đến file .c cần sửa
        ...

    def validate(self, patched_file_path: str):
        # 1. Backup file gốc
        # 2. Ghi đè bằng bản vá
        # 3. Compile → test
        # 4. Phục hồi file gốc
        # 5. return (is_valid, passed_tests, failed_tests)
        ...
```

**Bước 3 – Đăng ký** vào factory:

```python
# data_loaders/base_loader.py → get_loader()
if name == "defects4c":
    from data_loaders.defects4c_loader import Defects4CLoader
    return Defects4CLoader()

# data_loaders/sandbox_adapter.py → get_sandbox_adapter()
if dataset_name.lower() == "defects4c":
    return Defects4CAdapter(bug_id)
```

---

## 3. Fault Localization (FL)

**Package:** `core/fault_localization/`

- `runtime.py` – build instrumented và thu ordered regression trace
- `markers.py` – chèn stable scenario marker và bounded slice probes
- `scenario.py` – tách assertion, fingerprint và chọn scenario sai đầu tiên
- `investigation.py` – cached source index/dossier và kiểm chứng dynamic causal chain
- `trace_plan.py` – lập source/runtime-supported investigation plan
- `query_broker.py` – hợp nhất deterministic/LLM questions trước probe build duy nhất
- `probes.py` – resolve information-needs và concrete branch observations
- `artifacts.py` – cache/checkpoint nguyên tử theo bug và identity
- `semantic.py` – source/Clang semantic evidence
- `causal.py` – producer slicing và evidence-driven proof ranking
- `keys.py` – chuẩn hóa key function/file/class tương thích APR
- `update.py` – cập nhật ranking bằng APR feedback
- `__init__.py` – API công khai của FL

**Input:** `List[BugRecord]` từ `get_loader()`  
**Output:**
- `experiments/fault_localization_results.json` – combined score
- `experiments/fault_localization_function_results.json` – function-level score
- `experiments/fault_localization_file_results.json` – file-level score
- `experiments/fault_localization_class_results.json` – class/scope-level score cho C++ keys dạng `file:class::function`

### Thuật toán evidence-driven dynamic FL v9

1. Parse đúng definition của regression test đang fail thành scenario với
   fingerprint ổn định. Marker được chèn cùng dòng trước producer/assertion
   trong disposable build workspace; preprocessor, macro và constexpr helper
   không bị xem là assertion.
2. Map fresh failure output vào assertion và chọn scenario sai đầu tiên.
3. Ghép input test, assertion, Expected và Actual; tạo edit-script mô tả phần
   dữ liệu mâu thuẫn.
4. Resolve producer call trong scenario vào exact function key đã executed.
5. Dùng scenario marker, invocation/parent/callsite identity và dynamic edges
   để khóa đúng concrete invocation.
6. Trích source dossier cho mọi executed function: signature, branch, return,
   assignment, call, throw và quan hệ caller/callee.
7. LLM lập causal hypothesis và information-needs. Hypothesis chỉ được nhận
   nếu exact keys, source observation và dynamic causal chain đều kiểm chứng.
8. Query broker nhập branch questions vào cùng slice-probe plan trước detailed
   run. Không có targeted build/test pass sau ranking; evidence không thu được
   phải giữ trạng thái unknown.
9. Xếp hạng lexicographic theo proof tier; không dùng fitted coefficient.

Không có coefficient được fit theo dataset hoặc rule riêng cho một benchmark.
LLM trace guide được bật mặc định và dùng OpenRouter/
`OPENROUTER_API_KEY` nếu không truyền `--llm`. Nó chỉ lập kế hoạch trace từ
Input/Expected/Actual, source dossier và runtime chain; nó chỉ được tham chiếu
exact function key có trong runtime inventory và không được đề xuất patch.
Dùng
`--no-fl-llm-guide` để chạy deterministic-only.

Mỗi bug có một control-trace build và tối đa một slice-probe rebuild. Concrete
branch questions được lập sau census và cài trong rebuild này; không có build
probe độc lập thứ hai. Chỉ test buggy=FAIL, fixed=PASS được chạy. `covered_methods`
cũ và passing tests không tham gia candidate hay score. Nếu build/trace thất
bại, FL ghi score rỗng cùng diagnostics; không fallback sang baseline.

Runtime artifacts được giữ bền vững tại
`experiments/runtime_traces/<dataset>/<bug>/` và dùng chung cho FL-only lẫn
`--full`.
Nếu schema, bug identity, tập regression tests, output log, raw trace và
ordered events đều hợp lệ thì FL load cache theo từng bug, không build/chạy
lại. Lần trace mới lưu full events ở `runtime_evidence.full.json.gz`; dùng
`--refresh-runtime-traces` để chủ động vô hiệu cache.

Normal FL run còn kiểm tra generation của source instrumentation: cache cũ
chưa có `scenario_marker_instrumentation` sẽ được trace lại đúng một lần.
`--fl-cache-only` vẫn đọc cache legacy nhằm phục vụ đánh giá offline.

Cache legacy chỉ giữ tail của ordered events vẫn được tái sử dụng, nhưng nếu
producer invocation đã bị cắt khỏi tail thì FL chuyển sang aggregate dynamic
graph và ghi diagnostic `full_events_unavailable_used_aggregate_graph`.
Fallback này không được giả là một invocation chính xác.

Producer slicing không rút output xuống một function duy nhất. FL vẫn ghi
toàn bộ function scores theo thứ tự giảm dần; APR mặc định lấy ba phần tử đầu
qua `APR_TOP_K=3`.

Trong `--full`, candidate đã được APR xét ở round trước được carry-forward
bằng exact FL function key. Round tiếp theo lọc các key này trước khi cắt
`APR_TOP_K`, vì vậy top-k trùng sẽ được thay bằng các hàm chưa thử phía dưới.
Nếu không còn hàm có score khác 0 chưa thử, pipeline dừng bug với
`candidate_space_exhausted`.

### Output format

```json
{
	  "476-A-bug-16608008-16608059": {
	    "formula": "evidence_driven_causal_proofs_v8",
	    "reranker": "scenario+deterministic_trace_plan+causal_tiers",
	    "scores": {
	      "solve": 1.0,
	      "main": 0.5
	    },
	    "ground_truth": ["solve"],
	    "causal_evidence_ref": {
	      "schema": "unified_debugging.causal_evidence_ref.v1",
	      "path": "experiments/runtime_traces/.../causal_evidence.json.gz"
	    },
	    "causal_evidence_summary": {
	      "ground_truth_used": false
	    }
	  }
}
```

---

## 4. Automated Program Repair (APR)

APR đọc `fault_localization_results.json` để lấy thứ tự ưu tiên hàm, đồng thời nạp lại `BugRecord` (qua `get_loader()`) để lấy thông tin test context mà **không cần đọc file disk thêm lần nào**.

Ba APR engine đều lưu vào JSON kết quả các trường:
- `patched_function` – mã nguồn hàm được sửa (function-level)
- `patched_file` – toàn bộ nội dung file sau khi vá (file-level)
- Cả hai trường được lưu **kể cả khi không thành công** (status ≠ success), để evaluation file-level luôn có dữ liệu.

### 4.1 APR bằng LLM (`core/apr/`, wrapper `core/apr_baseline.py`)

```
Với mỗi bug:
  1. Lấy danh sách hàm nghi ngờ từ fault_localization_results.json (sắp xếp giảm dần)
  2. extract_function_code() → trích xuất mã nguồn hàm (từ core/utils.py)
  3. RetrievalContextAgent đọc target function + failure evidence + source context để sinh retrieval context ngắn gọn
  4. FixAgent dùng target function + failure evidence + retrieval context để sinh đúng một fixed C/C++ function
  5. Ghép patched_function vào source gốc → patched_source (= patched_file)
  6. SandboxAdapter.validate() → compile + chạy test
  7. Nếu pass 100%: lưu vào experiments/patches/<bug_id>_patch.c
  8. Ghi kết quả vào experiments/apr_results.json (incremental)
     → Luôn lưu patched_function + patched_file kể cả khi FAIL
```

### 4.2 Sandbox Adapter

`data_loaders/sandbox_adapter.py` thực hiện kiểm chứng an toàn:

1. **Backup** file gốc (`*.bak`)
2. **Ghi đè** bản vá lên file gốc
3. **Compile** (make hoặc gcc)
4. **Chạy test** (`bash test-genprog.sh <test_id>`)
5. **Phục hồi** file gốc từ backup
6. Trả về `(is_valid, passed_tests, failed_tests)`

File gốc **luôn được phục hồi** ngay cả khi có exception (`finally` block).

---

## 5. Tiện ích dùng chung (`core/utils.py`)

### `qualify_func(source_file, func_name) → str`

Tạo tên hàm đầy đủ dạng `<path>::<func_name>`. Dùng làm key trong FL results và APR results.

### `parse_qualified_func(qualified) → (source_file, func_name)`

Tách ngược `<path>::<func_name>` thành tuple.

### `extract_function_code(source_code, func_name) → (code, start, end)`

Trích xuất mã nguồn của một hàm C từ chuỗi source:
- Ưu tiên parse bằng `tree-sitter` (`tree-sitter-c` / `tree-sitter-cpp`)
- Duyệt node `function_definition`, match tên hàm, trả về `start_byte/end_byte`
- APR thay function bằng byte-range replacement để tránh lệch offset khi source có non-ASCII
- Fallback về Regex + đếm ngoặc nếu tree-sitter chưa khả dụng hoặc không match được hàm

> **Giới hạn:** Tree-sitter vẫn có thể cần thêm line/signature hint nếu C++ overload hoặc macro tạo function khiến chỉ `func_name` không đủ phân biệt.

### Defects4C source versions

Loader materialize hai workspace trong `experiments/defects4c_cache/<folder>/<bug_id>/`:

- `fixed_ver/`: checkout `commit_after`.
- `buggy_ver/`: checkout `commit_after`, sau đó overlay `src_files` từ `commit_before`.

APR luôn extract và ghép patch trên `buggy_ver/<relpath>`. Evaluation đọc accepted code từ `fixed_ver/<relpath>`.

---

## 6. Evaluation

### FL – `evaluation/eval_fl.py`

Mặc định đọc `fault_localization_results.json`, so ground truth với Top-K hàm nghi ngờ:

```bash
python3 main.py --eval --dataset tcpdump --fl-eval-level combined
python3 main.py --eval --dataset tcpdump --fl-eval-level function
python3 main.py --eval --dataset tcpdump --fl-eval-level file
python3 main.py --eval --dataset tcpdump --fl-eval-level class
python3 main.py --eval --dataset tcpdump --fl-eval-level all
```

`--fl-eval-level` chọn file kết quả FL dùng để tính Top-K:
- `combined` → `fault_localization_results.json`
- `function` → `fault_localization_function_results.json`
- `file` → `fault_localization_file_results.json`
- `class` → `fault_localization_class_results.json`
- `all` → chạy lần lượt tất cả các mức

- **Top-1 Hit Rate**: hàm lỗi thực sự nằm ở vị trí #1
- **Top-3 Hit Rate**: nằm trong Top 3
- **Top-5 Hit Rate**: nằm trong Top 5

### APR – `evaluation/eval_apr.py`

Đọc file JSON kết quả `apr_results.json`:

| Chỉ số | Mô tả |
|---|---|
| **Plausible Fix Rate** | % bug pass 100% test sau vá |
| **Fixed Initial Fails** | APR đã sửa được các test fail ban đầu chưa |
| **Yes (Regressions)** | Sửa được lỗi gốc nhưng làm hỏng test khác |
| **Edit Distance (func-level)** | Levenshtein: `patched_function` vs hàm tương ứng trong accepted file |
| **Edit Distance (file-level)** | Levenshtein: `patched_file` vs toàn bộ accepted file |

> ED file-level vẫn có giá trị ngay cả khi FL xác định sai function (ED func-level = N/A).

---

## 7. Cấu hình đường dẫn (`configs/path.py`)

Tất cả đường dẫn được định nghĩa một chỗ duy nhất. Nếu muốn thay đổi vị trí dataset hoặc thư mục kết quả, chỉ cần sửa file này:

```python
CODEFLAWS_RESULTS_DIR  # Thư mục chứa file JSON kết quả test (all_results/)
CODEFLAWS_SOURCE_DIR   # Thư mục chứa mã nguồn C của benchmark (benchmark/)
EXPERIMENTS_DIR        # Thư mục lưu kết quả pipeline (experiments/)
PATCHES_DIR            # Thư mục lưu các bản vá thành công (experiments/patches/)
LLM_PATCHES_DIR        # Thư mục lưu mọi patch LLM sinh ra (experiments/llm_patches/)
```
