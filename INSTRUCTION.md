# Hướng dẫn Quy trình Hoạt động của Dự án Unified-Debugging

Tài liệu này mô tả chi tiết quy trình hoạt động của hệ thống Unified-Debugging, bao gồm hai giai đoạn chính là Định vị lỗi (Fault Localization - FL) và Sửa lỗi tự động (Automated Program Repair - APR), cũng như cách hệ thống giao tiếp với bộ dữ liệu Codeflaws.

---

## 1. Tổng quan luồng hệ thống (Pipeline)

Hệ thống được thiết kế dưới dạng một pipeline nối tiếp nhau, thực thi theo luồng:
**Data Loader** ➔ **Fault Localization (FL)** ➔ **Automated Program Repair (APR)** ➔ **Evaluation**

*   **Chạy toàn bộ pipeline:** `python3 main.py --all` (hoặc `python3 main.py`)
*   **Chỉ chạy FL:** `python3 main.py --fl`
*   **Chỉ chạy APR:** `python3 main.py --apr`
*   **Chỉ thống kê/đánh giá:** `python3 main.py --eval`

---

## 2. Giao tiếp với dữ liệu

Dự án tương tác với module dữ liệu `codeflaws` nằm ở cấp độ thư mục ngang hàng/cha. Các đường dẫn được tự động map qua `configs/path.py`:

*   **Đầu vào của FL (Coverage Info):** Hệ thống đọc các file `*.json` lưu tại `codeflaws/codeflaws/all_results`. Những file này chứa thông tin test (pass/fail) cùng với độ bao phủ lệnh (statement coverage) của từng file sinh ra từ trước.
*   **Đầu vào của APR (Source Code & Tests):** Hệ thống đọc mã nguồn gốc (các file `.c`), `Makefile`, và các script test (`test-genprog.sh`) tại thư mục Benchmark của Codeflaws `codeflaws/benchmark/`.
*   **Đầu ra của hệ thống:** Mọi kết quả phân tích và patch tự động sinh ra được lưu tại `Unified-Debugging/experiments/`.

---

## 3. Quá trình Định vị lỗi (Fault Localization - FL)

Mục tiêu của FL là tìm ra chính xác các dòng code hoặc hàm (function) có khả năng gây ra lỗi nhất, từ đó giảm không gian tìm kiếm cho APR.

**Cách hoạt động:**
1.  **Thu thập dữ liệu:** Đọc toàn bộ file kết quả trả về từ `CODEFLAWS_RESULTS_DIR` (thông qua `data_loaders/codeflaws_loader.py`).
2.  **Tính điểm nghi ngờ (Suspiciousness Score):** Module `core/fl_tarantula.py` sử dụng thuật toán Tarantula để chấm điểm từng hàm dựa trên thống kê mức độ bao phủ (coverage) trong quá trình pass/fail ở các bài test.
3.  **Lưu kết quả:** Kết quả (danh sách từng hàm tương ứng với số điểm) được sắp xếp giảm dần và ghi vào file `experiments/tarantula_results.json`.
4.  **Đánh giá (Evaluation):** Thống kê số lượng các bug mà hàm chứa lỗi nằm trong top-1 hoặc top-3 suspicious functions (thực hiện qua `eval_fl.py`).

---

## 4. Quá trình Sửa lỗi tự động (Automated Program Repair - APR)

Mục tiêu của APR là nhận vào vị trí lỗi từ FL, tự động tạo các bản vá (patch) và chèn lại thử nghiệm dưới một hộp cát giả lập (sandbox checking) để tìm ra bản vá đúng (Plausible Patch).

**Cách hoạt động (**`core/apr_baseline.py`**):**
1.  **Phân tích và trích xuất:** Đọc thứ tự hàm nghi ngờ từ `tarantula_results.json`. Cấu trúc lại tên file `.c` để tra cứu trong `codeflaws/benchmark/<bug-id>/`. Tiến hành trích xuất source code của hàm đang bị nghi ngờ.
2.  **Tạo bản vá (Patch Generation):** Đẩy thông tin text của function đến thuật toán sinh (hiện tại là `call_llm` Prompt giả định).
3.  **Hoán đổi và Biên dịch (Patch Validation):** 
    *   Tạo file dự phòng `.c.bak` cho file gốc.
    *   Thay thế bằng source code đã qua chỉnh sửa của LLM vào file gốc.
    *   Biên dịch lại mã nguồn tại thư mục đó bằng lệnh `make FILENAME=<tên-file>` (hoặc fallback `gcc`).
4.  **Chạy Test case nội bộ (Ground Truth test):** 
    *   Hệ thống đọc file `test-genprog.sh` của thư mục bug tương ứng để lấy danh sách các testcases (ví dụ `p1`, `p2`, `n1`,...).
    *   Chạy từng testcase thông qua bash script nội bộ của Codeflaws.
    *   Nếu tất cả chạy trả về "Accepted" (hoặc exit code trả về `0`), mã nguồn được coi là Passed Validation (Thành công). Bất kỳ case nào lỗi sẽ loại bỏ bản vá.
5.  **Dọn dẹp & Lưu trữ:** Revert (phục hồi) file `.c.bak` về trạng thái ban đầu, dọn các binary dư thừa như `a.out`. Các Patch thành công sẽ được extract nguyên bản ra thư mục `experiments/patches/`.
6.  **Đánh giá (Evaluation):** `eval_apr.py` tính toán tỷ lệ Fix rate (Số bug được sinh patch / Tổng số bug có sẵn).
