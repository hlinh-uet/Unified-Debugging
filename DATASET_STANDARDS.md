# Tiêu chuẩn Hoá Dữ liệu (Dataset Standardization) cho Unified-Debugging

Để hệ thống định vị lỗi (FL) và sửa lỗi tự động (APR) có thể chạy trên **bất kỳ bộ dữ liệu nào** (Codeflaws, Defects4C, Defects4J, v.v.), hệ thống sử dụng kiến trúc **Adapter Pattern**.

Kiến trúc này yêu cầu mỗi bộ dữ liệu mới cung cấp cấu trúc thông tin (Metadata) theo một định dạng chuẩn, để mô-đun cốt lõi không cần quan tâm đến cách lệnh compile (gcc, cmake, maven) hay lệnh test (bash, pytest) hoạt động như thế nào ở phía dưới.

---

## 1. Cấu trúc Metadata Chuẩn (`meta.json`)

Mỗi bug trong bộ dữ liệu cần có riêng một tệp `{bug_id}_meta.json` cung cấp đủ các thông tin tĩnh cho luồng chạy:

```json
{
  "bug_id": "Defects4C-Bug-Name",
  "dataset_name": "defects4c",
  "language": "C",
  "source_file": "/absolute/path/to/bug/src/main.c",
  "compile_cmd": "make build",
  "test_cmd_template": "./run_tests.sh {test_id}",
  "tests": [
    {
      "test_id": "pos1",
      "outcome": "PASS"
    },
    {
      "test_id": "neg1",
      "outcome": "FAIL",
      "expected_output": "10",
      "actual_output": "0",
      "fail_reason": "Output mismatch"
    }
  ]
}
```

### Giải thích các trường

| Trường | Bắt buộc | Mô tả |
|---|---|---|
| `bug_id` | ✅ | ID duy nhất của bug, dùng làm key trong toàn bộ pipeline |
| `dataset_name` | ✅ | Tên dataset (ví dụ: `codeflaws`, `defects4c`) |
| `language` | ✅ | Ngôn ngữ lập trình (`C`, `Java`, ...) |
| `source_file` | ✅ | Đường dẫn **tuyệt đối** tới file lỗi — FL và APR đọc từ đây |
| `compile_cmd` | ⚠️ | Lệnh shell biên dịch (nếu ngôn ngữ cần compile) |
| `test_cmd_template` | ⚠️ | Template lệnh chạy test; `{test_id}` sẽ được thay bằng ID thực tế |
| `tests` | ✅ | Danh sách tất cả test case với trạng thái gốc (PASS/FAIL) |

### Cấu trúc một test case

| Trường | Bắt buộc | Mô tả |
|---|---|---|
| `test_id` | ✅ | ID test, ví dụ: `pos1`, `neg1` |
| `outcome` | ✅ | `"PASS"` hoặc `"FAIL"` |
| `expected_output` | ❌ | Output mong đợi (dùng cho LLM prompt context) |
| `actual_output` | ❌ | Output thực tế của bug (dùng cho LLM prompt context) |
| `fail_reason` | ❌ | Mô tả lý do fail ngắn gọn |

---

## 2. Chuẩn Format Kết quả APR (`apr_results.json`)

LLM APR lưu kết quả theo schema dưới đây để `eval_apr.py` đọc thống nhất:

```json
{
  "<bug_id>": {
    "status": "success | failed | skipped | plausible_only | ...",
    "patched_function": "<mã nguồn hàm đã vá>",
    "patched_file": "<toàn bộ nội dung file sau khi vá>",
    "selected_function": "<source_file>::<func_name>",
    "init_passed_tests": ["pos1", "pos2"],
    "init_failed_tests": ["neg1"],
    "post_passed_tests": ["pos1", "pos2", "neg1"],
    "post_failed_tests": []
  }
}
```

### Các trường quan trọng cho evaluation

| Trường | Mô tả |
|---|---|
| `patched_function` | Mã nguồn của **hàm** được sửa — dùng tính **Edit Distance function-level** |
| `patched_file` | Toàn bộ nội dung **file** sau khi vá — dùng tính **Edit Distance file-level** |
| `selected_function` | Qualified name dạng `<path>::<func_name>` — dùng để trích hàm tương ứng từ accepted file |

> **Quan trọng:** Cả `patched_function` và `patched_file` được lưu **kể cả khi status ≠ success**. Điều này để `eval_apr.py` tính Edit Distance ngay cả với bản vá không thành công hoặc khi FL xác định sai function.

---

## 3. Adapter cho APR (Sandbox Adapter)

`data_loaders/sandbox_adapter.py` đóng vai trò là "cầu nối". Khi có bộ dữ liệu mới, chỉ cần định nghĩa một Python Class kế thừa từ `SandboxAdapter`:

```python
class Defects4CAdapter(SandboxAdapter):
    def get_source_path(self) -> str:
        # Trả về đường dẫn tuyệt đối đến file .c cần sửa
        pass

    def validate(self, patched_file_path: str):
        # 1. Sao lưu mã nguồn gốc (*.bak)
        # 2. Ghi đè patched_file_path lên file gốc
        # 3. Chạy compile_cmd
        # 4. Duyệt qua tất cả test case, gọi test_cmd_template
        # 5. Phục hồi mã nguồn gốc (finally block)
        # 6. Trả về: (is_valid: bool, passed_tests: List[str], failed_tests: List[str])
        pass
```

Kiến trúc này cho phép gắn bất cứ bộ dữ liệu nào (dù dùng Makefile, CMake, Shell, Python, Docker) vào `Unified-Debugging` mà không cần sửa các module cốt lõi.

---

## 4. Qualified Function Name

Trong toàn bộ pipeline, tên hàm được biểu diễn theo format **qualified**:

```
<absolute_source_file_path>::<func_name>
```

Ví dụ:
```
/path/to/benchmark/104-A-bug-15369048-15370159/104-A-15369048.c::main
```

Sử dụng `"::"` làm separator vì ký tự này không xuất hiện trong tên file Unix.

```python
from core.utils import qualify_func, parse_qualified_func

qname = qualify_func("/path/to/file.c", "solve")
# → "/path/to/file.c::solve"

source_file, func_name = parse_qualified_func(qname)
# → ("/path/to/file.c", "solve")
```
