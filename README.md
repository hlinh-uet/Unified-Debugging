# Unified-Debugging Pipeline

Đây là công cụ tự động chẩn đoán lỗi (Fault Localization) và sửa lỗi tự động (Automated Program Repair) cơ bản dùng thuật toán Tarantula và LLM (Placeholder). Hệ thống được sử dụng cho bộ dữ liệu Codeflaws.

## Cấu trúc thư mục tương đối

- `core/`: Chứa các thuật toán xử lý chính
  - `fl_tarantula.py`: Thuật toán chấm điểm Tarantula.
  - `apr_baseline.py`: Bộ sinh bản vá tự động dựa trên LLM prompt.
- `evaluation/`: Module đánh giá và báo cáo.
  - `eval_fl.py`: Đánh giá Fault Localization (Ví dụ: tính toán Top-K suspicious functions).
  - `eval_apr.py`: Đánh giá Automatic Program Repair (Tỉ lệ sinh ra Plausible Patches).
- `data_loaders/`: Các module đọc kết quả JSON / nguồn C của bug.
- `configs/path.py`: Nơi thiết lập thư mục trỏ đến `codeflaws` repository (Tự động config)
- `experiments/`: Khởi tạo sau khi chạy test để lưu trữ kết quả phân tích Tarantula (`tarantula_results.json`) và nơi lưu Patch thành công (`patches/`).

## Đặc tả dữ liệu (Ground Truth Extraction)

Dự án tương tác với bộ dữ liệu Codeflaws thông qua bộ sinh dữ liệu json tự động (`data_collector.py` & `run_all_data.py`).
Hệ thống định vị lỗi (FL) sẽ lấy **Ground Truth** (dò hàm thực sự bị lỗi) bằng cách đọc module C của bài nộp sai (Buggy submission) và mã nguồn của bài nộp sửa được ban tổ chức accept (Accepted submission).
- Lệnh Unix `diff -u` được dùng để truy xuất các dòng bị thay đổi, ánh xạ trực tiếp sang Regex nhận dạng tên hàm trong ngôn ngữ C. 
- Mọi String input và stdout trong quá trình Codeflaws test-cases (pass/fail) đều được ghi nhận trực tiếp vào Output JSON (`expected_output` / `actual_output`) giúp dễ dàng theo dõi lỗi biên dịch hoặc thuật toán.
- Module đánh giá (Evaluation) `eval_fl.py` so sánh hàm đầu ra của FL Tarantula (ví dụ đứng Top-1, Top-3) với mảng `ground_truth_functions` để tính độ chính xác (% Hit Rate).

## Thiết lập môi trường

Hệ thống yêu cầu các thư viện để tương tác với các API Generative AI (LLM) và các dịch vụ khác. Hãy làm theo hướng dẫn dưới đây để chuẩn bị môi trường:

### 1. Tạo môi trường ảo (Khuyến nghị)
```bash
python3 -m venv .venv
```

### 2. Kích hoạt môi trường:
- Trên Mac/Linux:
```bash
source .venv/bin/activate
```
- Trên Windows:
```bash
.venv\Scripts\activate
```

### 3. Cài đặt thư viện:
```bash
pip install -r requirements.txt
```

### 4. Cấu hình biến môi trường (API Keys):
Sao chép file mẫu và cấu hình thư viện LLM mà bạn muốn.
```bash
cp .env.example .env
```
Mở tệp `.env` vừa sao chép, tìm biến `GEMINI_API_KEY=YOUR_KEY_HERE` hoặc `OPENAI_API_KEY` và thay thế giá trị ảo bằng khóa API thực tế của bạn. Dự án đã tự động `.gitignore` file `.env` để bảo mật thông tin này.

## Hướng dẫn sử dụng

Hệ thống cho phép bạn điều hướng từng quy trình một thông qua tham số dòng lệnh hoặc có thể chạy tự động tuần tự cả luồng.

```bash
# Di chuyển vào thư mục dự án
cd Unified-Debugging

# Cài đặt (nếu có các dependency sau này - ví dụ openai API)
# pip install -r requirements.txt
```

### 1. Chạy tất cả tự động (Automated Pipeline)
Mặc định nếu bạn không truyền argument hoặc truyền `--all` thì hệ thống sẽ thực hiện theo thứ tự: Loading Codeflaws Bugs -> Chạy Tarantula -> Ghi kết quả -> Chạy APR theo Tarantula Ranking -> Cố gắng compile kết quả rồi lưu patch thành công.

```bash
python3 main.py
# Hoặc
python3 main.py --all
```

### 2. Chạy từng bước (Step-by-Step)

#### Bước 1: Chạy Fault Localization
Nếu bạn chỉ muốn tính toán Suspiciousness Score (Tarantula) cho các hàm C trong tập Test Suite, truyền cờ `--fl`. Điểm số này sẽ lưu trữ trong file `experiments/tarantula_results.json`.

```bash
python3 main.py --fl
```

#### Bước 2: Chạy Automated Program Repair
Bạn cũng có thể chỉ chạy luồng sửa lỗi tự động (APR), phần này sẽ đọc trực tiếp từ `tarantula_results.json` có sẵn trước đó để lên thứ tự ưu tiên Fix bằng Prompt LLM. Vui lòng đảm bảo bạn đã cấu hình thư mục trỏ vào mã nguồn thực tế tại `configs/path.py` (biến `CODEFLAWS_SOURCE_DIR`).

```bash
python3 main.py --apr
```

#### Bước 3: Đánh giá quá trình (Evaluation)
In ra lại số điểm thống kê Fault Localization và Tỉ lệ thành công của các Patch APR mà không cần phải thực thi luồng tải mô hình lại.
```bash
python3 main.py --eval
```

## Các hạn chế và Hướng phát triển

Hệ thống đang ở mức Baseline để chứng minh khả năng ráp nối giữa Fault Localization và LLM APR. Các điểm thiếu sót cần được chuẩn hóa như sau:

### Phân tích và biên dịch (Compilation & Analysis)
- **Tính toán gcov/lcov:** Các phép đo Tarantula được gán dựa trên metadata trích xuất JSON. Hệ thống đã triển khai luồng chạy biên dịch gcov và load matrix test-case tự động đối với các file C (`data_collector.py`).
- **Sandbox Validation:** Sử dụng tự động script `test-genprog.sh` của tập lệnh codeflaws, tự động backup, dịch file `.c` (bằng `make` hoặc `gcc`) và check qua toàn bộ case P/N (positive / negative) pass in/out stdout để xác nhận patch có lỗi hay không (`validate_patch` trong `apr_baseline.py`).
- Mở rộng thêm Ground Truth Mapping an toàn hơn cho các trường hợp Code C++ rắc rối do Regex hiện tại bị giới hạn về xử lý block `{}` phức tạp.

### Chỉnh sửa Code C (Source Extraction & Injection)
- **Trích xuất bằng Regex:** Hàm `extract_function_code()` hiện vẫn sử dụng biểu thức chính quy tĩnh và tìm ngoặc ngẫu nhiên (`{`, `}`). Có thể hoạt động không đúng nếu C macro, strings, hoặc comment chứa các dấu ngoặc nhọn này.
- **Đề xuất công nghệ:** Cần áp dụng các thư viện như `pycparser`, Clang AST hay `tree-sitter` để trích xuất hoặc thay thế nguyên dòng (statement/function-level) chuẩn hóa hơn.

### Hệ thống Generative AI (LLM APIs)
- **API Placeholder:** Hàm `call_llm()` đã được kết nối thực tế thông qua SDK Google Generative AI (Gemini).
- **Hỗ trợ Model mới nhất:** Do sự thay đổi của Google API SDK, hệ thống sử dụng model `models/gemini-2.5-flash` mang lại tốc độ và độ chính xác cao khi xử lý mã nguồn C.
- **Tính toán Validation Distance:** Đã tích hợp thư viện `Levenshtein` trong module `eval_apr.py` nhằm đánh giá số khoảng cách Edit Distance nội suy giữa Source Code Benchmark (Accepted của bộ dữ liệu gốc) so sánh với Source Patch của LLM Generative AI cung cấp. Hệ thống đánh giá cả các test ban đầu bị Fail có thực sự được giải quyết - sinh ra Regressions hay không.
- **Ràng buộc mã (Context Windows):** Đối với các tệp C dung lượng siêu lớn, cần nén prompt tốt hơn là chèn nguyên mã hàm.