# Hướng dẫn Quy trình Hoạt động của Dự án Unified-Debugging

---

## 1. Tổng quan luồng hệ thống (Pipeline)

Hệ thống được thiết kế dưới dạng một pipeline nối tiếp nhau, thực thi theo luồng:
**Data Loader** ➔ **Fault Localization (FL)** ➔ **Automated Program Repair (APR)** ➔ **Evaluation**

*   **Chạy toàn bộ pipeline:** `python3 main.py --all` (hoặc `python3 main.py`)
*   **Chỉ chạy định vị lỗi (FL):** `python3 main.py --fl`
*   **Chỉ chạy sửa lỗi tự động (APR):** `python3 main.py --apr`
*   **Chỉ chạy đánh giá kết quả (Evaluation):** `python3 main.py --eval`

---

## 2. Giao tiếp với dữ liệu

Dự án tương tác với mã nguồn và dữ liệu test của các benchmark (như Codeflaws) thông qua cấu hình đường dẫn linh hoạt trong `configs/path.py`:

*   **Đầu vào của FL (Thông tin Độ bao phủ - Coverage Info):** Hệ thống đọc các file kết quả (metadata JSON) chứa thông tin test (P/F) cùng với độ bao phủ lệnh (statement coverage) tại môi trường gốc.
*   **Đầu vào của APR (Mã nguồn & kịch bản kiểm thử):** Đọc mã nguồn lỗi (ví dụ file `*.c`), các file bản vá đúng (nếu có để tham chiếu đánh giá) và mã lệnh thực thi test (`test-genprog.sh` hoặc framework tương đương).
*   **Đầu ra của hệ thống:** Mọi file kết quả JSON, log thực thi, kết hợp đánh giá và file bản vá thành công được lưu tại tập trung trong thư mục `experiments/`.

---

## 3. Định vị lỗi (Fault Localization - FL)

Mục tiêu của quá trình này là tìm ra chính xác các hàm (functions) có nguy cơ chứa lỗi cao nhất, rút gọn độ lớn ngữ cảnh cho LLM bước tiếp theo.

**Các bước thực hiện:**
1.  **Dữ liệu đầu vào:** Trích xuất ma trận thông tin bao phủ lệnh của từng test case bằng công cụ thu thập (`data_collector.py`).
2.  **Tính điểm nghi ngờ (Suspiciousness Score):** Module `core/fl_tarantula.py` chạy thuật toán Tarantula trên toàn bộ mã nguồn để chấm điểm. Hàm được bao phủ nhiều bởi failed-tests sẽ có điểm số cao.
3.  **Lưu trữ vị trí lỗi:** Danh sách các hàm sắp xếp theo điểm nghi ngờ từ cao xuống thấp được lưu trữ vào `experiments/tarantula_results.json`.
4.  **Đánh giá độ chính xác (FL Evaluation):** Scripts `evaluation/eval_fl.py` tra cứu tệp lỗi gốc (ground truth) có nằm trong Top-1, Top-3, Top-5 danh sách từ thuật toán hay không.

---

## 4. Sửa lỗi tự động (Automated Program Repair - APR)

Sau khi có trong tay các hàm dễ bị lỗi nhất, hệ thống tiến hành giao tiếp với mô hình ngôn ngữ lớn (LLM - Gemini) để sinh ra bản vá và kiểm chứng cục bộ hộp cát (Sandbox validation).

**Các bước thực hiện (**`core/apr_baseline.py`**):**
1.  **Trích xuất mã nguồn con:** Đọc `tarantula_results.json` để xác định C-function tiềm ẩn lỗi. Sử dụng Regex nội bộ để tách riêng phần mã nguồn của hàm đó.
2.  **Giao tiếp Mô hình LLM:** Tạo một prompt kết hợp code lỗi cùng thông tin báo cáo lỗi, gửi đến Google Gemini (thông qua `google-generativeai`). LLM trả về source code được kỳ vọng đã fix lỗi.
3.  **Hộp cát kiểm thử (Sandbox Validation):** 
    *   Tự động *backup* mã nguồn gốc.
    *   Bơm trực tiếp đoạn mã sửa lỗi của LLM đè lên nội dung hàm bị lỗi.
    *   Tiến hành biên dịch cục bộ bằng `make` hoặc `gcc`.
    *   Thực thi bộ test script nội bộ (`test-genprog.sh` hoặc tương tự) với các test case gốc.
    *   Thu thập log Pass/Fail mới nhất từ môi trường thực thi (so sánh cả `post_passed_tests` và `post_failed_tests`).
4.  **Xử lý hậu kỳ (Cleanup & Export):** 
    *   Lưu toàn bộ quá trình xác thực vào `experiments/apr_results.json` liên tục theo thời gian thực (đảm bảo an toàn khi Ctrl+C).
    *   Phục hồi (revert) source code file để tránh làm hỏng bộ Dữ liệu gốc.
    *   Nếu Plausible/Correct: Đẩy bản vá vào `experiments/correct_patches/`.

---

## 5. Đánh giá hệ thống (Evaluation)

Hệ thống có cơ chế tự động đánh giá sự hiệu quả của toàn bộ Pipeline để đưa ra báo cáo chi tiết. Toàn quyền thay đổi bởi `evaluation/eval_apr.py` & `evaluation/eval_fl.py`.

*   **Tỉ lệ sửa thành công (Plausible Fix Rate):** Tính tỉ lệ số lượng bugs được vá thành công vĩnh viễn chia cho tổng số bugs thực thi.
*   **Regression Tracking:** Đếm số lượng test cases thất bại (Fail) ban đầu có được vá hay không (Fixed Init Fails?), đồng thời báo cáo nếu patch làm vỡ logic của test cases đang chạy đúng (Regressions).
*   **Edit Distance (Levenshtein):** Với các bản code đã fix, đo đạc khoảng cách chuỗi (Levenshtein distance) so với đoạn code chuẩn mà nhà phát triển (developer) thực tế đã sửa (Ground-truth accepted patches). Giúp đánh giá độ "tự nhiên" và "ngắn gọn" của AI sinh ra.


