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
┌───────▼──────┐        ┌─────────────▼──────────────────────────┐
│  core/        │        │  core/                                 │
│  fl_tarantula │        │  apr_baseline.py  (LLM – Gemini)       │
│  .py          │        │  apr_mutation.py  (Heuristic Mutation)  │
└───────┬──────┘        │  apr_genprog.py   (GenProg)             │
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
│  tarantula_results.json               │
│  apr_results.json                     │
│  apr_mutation_results.json            │
│  apr_genprog_results.json             │
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

**File:** `core/fl_tarantula.py`  
**Input:** `List[BugRecord]` từ `get_loader()`  
**Output:** `experiments/tarantula_results.json`

### Thuật toán Tarantula

Với mỗi hàm $m$, điểm số nghi ngờ được tính:

$$\text{score}(m) = \frac{ \frac{f_m}{T_f} }{ \frac{f_m}{T_f} + \frac{p_m}{T_p} }$$

Trong đó:
- $f_m$ = số test FAIL có cover hàm $m$
- $p_m$ = số test PASS có cover hàm $m$
- $T_f$, $T_p$ = tổng số test FAIL / PASS

### Output format

```json
{
  "476-A-bug-16608008-16608059": {
    "scores": {
      "solve": 1.0,
      "main": 0.5
    },
    "ground_truth": ["solve"]
  }
}
```

---

## 4. Automated Program Repair (APR)

APR đọc `tarantula_results.json` để lấy thứ tự ưu tiên hàm, đồng thời nạp lại `BugRecord` (qua `get_loader()`) để lấy thông tin test context mà **không cần đọc file disk thêm lần nào**.

Ba APR engine đều lưu vào JSON kết quả các trường:
- `patched_function` – mã nguồn hàm được sửa (function-level)
- `patched_file` – toàn bộ nội dung file sau khi vá (file-level)
- Cả hai trường được lưu **kể cả khi không thành công** (status ≠ success), để evaluation file-level luôn có dữ liệu.

### 4.1 APR bằng LLM (`core/apr_baseline.py`)

```
Với mỗi bug:
  1. Lấy danh sách hàm nghi ngờ từ tarantula_results.json (sắp xếp giảm dần)
  2. extract_function_code() → trích xuất mã nguồn hàm (từ core/utils.py)
  3. Xây dựng prompt với context test FAIL từ BugRecord.tests
  4. Gọi call_llm() → Gemini sinh bản vá
  5. Ghép patched_function vào source gốc → patched_source (= patched_file)
  6. SandboxAdapter.validate() → compile + chạy test
  7. Nếu pass 100%: lưu vào experiments/patches/<bug_id>_patch.c
  8. Ghi kết quả vào experiments/apr_results.json (incremental)
     → Luôn lưu patched_function + patched_file kể cả khi FAIL
```

### 4.2 APR bằng Heuristic Mutation (`core/apr_mutation.py`)

Không cần LLM. Sinh các biến thể (mutants) bằng Regex trên mã nguồn hàm:

| Loại đột biến | Ví dụ |
|---|---|
| Quan hệ so sánh | `<` → `<=`, `>`, `>=`, `==`, `!=` |
| Toán tử số học | `+` → `-` và ngược lại |
| Off-by-one | `+ 1` → `- 1` hoặc bỏ hẳn |

Mỗi mutant được nạp vào `SandboxAdapter.validate()`. Lưu **mutant tốt nhất** (nhiều test pass nhất) vào `patched_file`, kể cả khi không có mutant nào pass 100%. Mutant thành công lưu vào `experiments/patches/<bug_id>_mutation_patch.c`.

### 4.3 APR bằng GenProg (`core/apr_genprog.py`)

Sử dụng GenProg binary để tìm bản vá bằng Genetic Programming:

```
Với mỗi bug:
  1. Parse .revlog → lấy số pos/neg tests
  2. Copy thư mục bug vào workdir sandbox (experiments/genprog-run/)
  3. Sinh file configuration-<bug_id> và bugged-program.txt
  4. Chạy cilly build → tạo file .cil.c (preprocessed/)
  5. Gọi `genprog configuration-<bug_id>` với timeout
  6. Nếu "Repair Found":
     a. Đọc repair/<cfile> → patched_file_content
     b. Trích xuất hàm thay đổi → patched_function
     c. Validate: compile repair + chạy tất cả test
     d. Lưu patch vào experiments/patches/<bug_id>_genprog_patch.c
  7. Ghi kết quả vào experiments/apr_genprog_results.json (incremental)
     → Luôn lưu patched_file nếu GenProg tìm được repair file
```

**Trạng thái kết quả GenProg:**

| Status | Ý nghĩa |
|---|---|
| `success` | Repair found + validate 100% pass |
| `plausible_only` | Repair found nhưng còn test fail |
| `repair_found_no_file` | GenProg báo found nhưng không có file |
| `no_repair` | GenProg không tìm được bản vá |
| `timeout` | Quá thời gian cho phép |
| `build_failed` | Lỗi biên dịch (cilly/make) |
| `error` | Lỗi hệ thống / không có binary |

### 4.4 Sandbox Adapter

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
- Dùng Regex để tìm điểm bắt đầu (signature + `{`)
- Đếm ngoặc nhọn để tìm điểm kết thúc
- Có fallback riêng cho hàm `main`

> **Giới hạn:** Hoạt động không đúng nếu `{` / `}` xuất hiện trong macro không chuẩn. Hướng nâng cấp: dùng `pycparser` hoặc `tree-sitter`.

---

## 6. Evaluation

### FL – `evaluation/eval_fl.py`

Đọc `tarantula_results.json`, so ground truth với Top-K hàm nghi ngờ:

- **Top-1 Hit Rate**: hàm lỗi thực sự nằm ở vị trí #1
- **Top-3 Hit Rate**: nằm trong Top 3
- **Top-5 Hit Rate**: nằm trong Top 5

### APR – `evaluation/eval_apr.py`

Đọc từng file JSON kết quả (`apr_results.json`, `apr_mutation_results.json`, `apr_genprog_results.json`):

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
```
