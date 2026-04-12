# Tiêu chuẩn Hoá Dữ liệu (Dataset Standadization) cho Unified-Debugging

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

* **`source_file`**: Đường dẫn tuyệt đối trỏ tới file lỗi. Hệ thống FL, APR sẽ đọc mã nguồn từ file này.
* **`compile_cmd`**: Câu lệnh shell cần thiết để biên dịch file mã nguồn (nếu ngôn ngữ yêu cầu).
* **`test_cmd_template`**: Kịch bản thực thi một test case. Hệ thống Pipeline sẽ thay chuỗi `{test_id}` bằng ID thực tế (như `neg1`, `pos1`) để gọi validation sandbox.
* **`tests`**: Danh sách tất cả các test của bug này và thông tin trạng thái lỗi gốc (để Pipeline LLM tham chiếu cho prompt).

---

## 2. Adapter cho APR (Sandbox Adapter)

Bên trong project, thư mục `core/sandbox_adapter.py` đóng vai trò là "Cầu nối". Khi có một bộ dữ liệu mới, bạn không cần sửa code cốt lõi (`apr_baseline.py`), mà chỉ cần định nghĩa một Python Class kế thừa từ `SandboxAdapter`. Lớp này nhận vào chuỗi file tạm đã sửa lỗi, tiến hành đắp file tạm đè vào file gốc, chạy lệnh compile và duyệt qua các `test_cmd`.

```python
class Defects4CAdapter(SandboxAdapter):
    def get_source_path(self):
        # Trả về đường dẫn lấy từ meta.json
        pass

    def validate(self, patched_file_path):
        # 1. Sao lưu mã nguồn gốc
        # 2. Dán patched_file_path đè lên
        # 3. Chạy `compile_cmd`
        # 4. Quét qua mảng test cases vạy gọi `test_cmd_template` từng lệnh một
        # 5. Phục hồi mã nguồn gốc
        # 6. Trả về kết quả: is_valid, passed_tests, failed_tests
```

Kiến trúc này giúp bạn gắn bất cứ bộ dữ liệu nào (dù dùng Makefile, CMake, Shell, Python, Docker) vào `Unified-Debugging` mà không cần phá vỡ pipeline của LLM và Heuristic Mutation!
