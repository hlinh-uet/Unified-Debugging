# Hướng dẫn Quy trình Hoạt động của Dự án Unified-Debugging

---

## 1. Tổng quan luồng hệ thống (Pipeline)

Hệ thống được thiết kế dưới dạng một pipeline nối tiếp nhau, thực thi theo luồng:
**Data Loader** ➔ **Fault Localization (FL)** ➔ **Automated Program Repair (APR)** ➔ **Evaluation**

*   **Chạy toàn bộ pipeline:** `python3 main.py --all` (hoặc `python3 main.py`)
*   **Chỉ chạy định vị lỗi (FL):** `python3 main.py --fl`
*   **Chỉ chạy APR sử dụng LLM:** `python3 main.py --apr`
*   **Chỉ chạy APR sử dụng Heuristic Mutation (Không LLM):** `python3 main.py --apr-mutation`
*   **Chỉ chạy đánh giá kết quả (Evaluation):** `python3 main.py --eval`

---

## 2. Giao tiếp với dữ liệu (Sandbox Adapter)

Dự án tương tác với mã nguồn và dữ liệu test của các benchmark thông qua kiến trúc **Sandbox Adapter** (khai báo tại `core/sandbox_adapter.py`). 
Điều này cho phép hệ thống làm việc với mọi bộ dữ liệu như Codeflaws, Defects4C,... mà không cần phải thay đổi mã nguồn cốt lõi (hardcode). Tham khảo File `DATASET_STANDARDS.md` để tự tạo File Adapter nếu bạn muốn cắm một bộ dữ liệu hoàn toàn mới vào.

*   **Đầu vào của FL (Thông tin Độ bao phủ - Coverage Info):** Hệ thống đọc các file kết quả (metadata JSON) chứa thông tin test (P/F) cùng với độ bao phủ lệnh (statement coverage) tại môi trường gốc.
*   **Đầu vào của APR (Mã nguồn & kịch bản kiểm thử):** Đọc mã nguồn lỗi (ví dụ file `*.c`), các file bản vá đúng (nếu có để tham chiếu đánh giá) thông qua Adapter được chỉ định.
*   **Đầu ra của hệ thống:** Mọi file kết quả JSON, log thực thi, kết hợp đánh giá và file bản vá thành công được lưu tập trung trong thư mục `experiments/`.

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

Hệ thống cung cấp **2 phương pháp (Baseline)** để tự động sinh ra bản vá dựa trên lỗi do FL truyền vào. Cả hai phương pháp đều tái sử dụng chung cơ chế kiểm chứng hộp cát (Sandbox Validation).

### Phương pháp 1: Sửa lỗi bằng Generative AI (LLM - Gemini)
**Tệp thực thi:** `core/apr_baseline.py`
1.  **Trích xuất mã nguồn:** Đọc `tarantula_results.json` để xác định C-function tiềm ẩn lỗi. Tách riêng phần mã nguồn của hàm đó.
2.  **Giao tiếp Mô hình LLM:** Tạo một prompt kết hợp toàn bộ code lỗi cùng thông tin File JSON Test-Case bị FAIL, gửi đến Google Gemini. LLM trả về source code được kỳ vọng đã fix lỗi.
3.  **Hộp cát kiểm thử (Adapter Sandbox Validation):** 
    *   Tự động *backup* mã nguồn gốc.
    *   Bơm trực tiếp đoạn mã sửa lỗi của LLM đè lên nội dung hàm bị lỗi.
    *   Adapter sẽ tùy biến lệnh Sandbox để gọi Compile và chạy từng script test của bộ dữ liệu đó.
    *   Thu thập log Pass/Fail mới nhất từ môi trường thực thi để lọc bản vá sai.
4.  **Xử lý hậu kỳ (Cleanup & Export):** 
    *   Lưu quá trình vào `experiments/apr_results.json`.
    *   Phục hồi (revert) source code file để tránh làm hỏng bộ dữ liệu. Nếu Plausible: Đẩy bản vá vào `experiments/correct_patches/`.

### Phương pháp 2: Sửa lỗi bằng Heuristic Mutation (Local, No LLM)
**Tệp thực thi:** `core/apr_mutation.py`
Đây là phương pháp học hỏi theo các Baseline kinh điển (như GenProg, SPR), hoạt động bằng 100% tài nguyên CPU thực tế cục bộ mà không sử dụng bất kỳ API Token nào.
1.  **Trích xuất mã nguồn:** Tương tự như dùng LLM.
2.  **Đột biến mã (Mutagenesis):** Bộ biểu thức chính quy (Regex) quét qua hàm bị lỗi để sinh ra hàng tá phiên bản thay thế (Mutants). Chẳng hạn: hoán đổi `<`, `>` thành `<=`, hoặc sửa dấu `+`, `-` để khắc phục lỗi biên ngụy (Off-by-one errors) rất hay gặp ở Codeforces.
3.  **Dò tìm (Heuristic Search):** Nạp toàn bộ Mutants vừa tạo vào Adapter Sandbox Validation để quét liên tục.
4.  **Xử lý hậu kỳ:** Mutant nào qua 100% Test Case sẽ được ghi nhận vào file báo cáo `experiments/apr_mutation_results.json`.

---

## 5. Đánh giá hệ thống (Evaluation)

Hệ thống có cơ chế tự động đánh giá sự hiệu quả của toàn bộ Pipeline để đưa ra báo cáo chi tiết. Toàn quyền thay đổi bởi `evaluation/eval_apr.py` & `evaluation/eval_fl.py`.

*   **Tỉ lệ sửa thành công (Plausible Fix Rate):** Tính tỉ lệ số lượng bugs được vá thành công vĩnh viễn chia cho tổng số bugs thực thi.
*   **Regression Tracking:** Đếm số lượng test cases thất bại (Fail) ban đầu có được vá hay không (Fixed Init Fails?), đồng thời báo cáo nếu patch làm vỡ logic của test cases đang chạy đúng (Regressions).
*   **Edit Distance (Levenshtein):** Với các bản code đã fix, đo đạc khoảng cách chuỗi (Levenshtein distance) so với đoạn code chuẩn mà nhà phát triển (developer) thực tế đã sửa (Ground-truth accepted patches). Giúp đánh giá độ "tự nhiên" và "ngắn gọn" của AI sinh ra.


