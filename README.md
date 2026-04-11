# Unified-Debugging Pipeline

## Cấu trúc 

- `core/`: Chứa các thuật toán xử lý chính
  - `fl_tarantula.py`
  - `apr_baseline.py`
- `evaluation/`: Module đánh giá và báo cáo.
  - `eval_fl.py`: Đánh giá Fault Localization 
  - `eval_apr.py`: Đánh giá Automatic Program Repair 
- `data_loaders/`: Các module đọc kết quả JSON / nguồn C của bug.
- `configs/path.py`: Nơi thiết lập thư mục trỏ đến `codeflaws` repository (Tự động config)
- `experiments/`: Khởi tạo sau khi chạy test để lưu trữ kết quả phân tích Tarantula (`tarantula_results.json`) và nơi lưu Patch thành công (`patches/`).

## Thiết lập môi trường
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
Sao chép file mẫu và cấu hình thư viện LLM.
```bash
cp .env.example .env
```
Mở tệp `.env` vừa sao chép, tìm biến `GEMINI_API_KEY=YOUR_KEY_HERE` hoặc `OPENAI_API_KEY` và thay thế giá trị ảo bằng khóa API thực tế.

## Hướng dẫn sử dụng

```bash
# Di chuyển vào thư mục dự án
cd Unified-Debugging

# Cài đặt 
pip install -r requirements.txt
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
Đây là bước nếu chỉ muốn chạy Fault Localization. Truyền `--fl`. Điểm số này sẽ lưu trữ trong file `experiments/tarantula_results.json`.

```bash
python3 main.py --fl
```

#### Bước 2: Chạy Automated Program Repair
Đây là bước chỉ chạy luồng sửa lỗi tự động (APR), phần này sẽ đọc trực tiếp từ `tarantula_results.json` có sẵn trước đó để lên thứ tự ưu tiên Fix bằng Prompt LLM. 

```bash
python3 main.py --apr
```

#### Bước 3: Đánh giá quá trình (Evaluation)
In ra lại số điểm thống kê Fault Localization và Tỉ lệ thành công của các Patch APR mà không cần phải thực thi luồng tải mô hình lại.
```bash
python3 main.py --eval
```

## Đánh giá hiệu suất (Evaluation)

Hệ thống triển khai 2 luồng đánh giá tự động dựa trên kết quả đầu ra tại mục `experiments/`:

### 1. Đánh giá Fault Localization (`eval_fl.py`)
Tiến hành tính toán độ chính xác của thuật toán Tarantula bằng cách đối soát danh sách hàm nghi ngờ (Suspicious functions) với **Ground Truth** (Hàm lỗi chuẩn, được xác định qua `diff -u` giữa mã lỗi và mã thành công). Kết quả trả về tỷ lệ hàm lỗi được xếp hạng đúng trong:
- **Top-1** Hit Rate
- **Top-3** Hit Rate
- **Top-5** Hit Rate

### 2. Đánh giá Automated Program Repair (`eval_apr.py`)
Mô phỏng bảng báo cáo dựa trên số liệu chi tiết mà Sandbox Validation đã sinh ra. Các độ đo bao gồm:
- **Plausible Fix Rate (%):** Tỷ lệ phần trăm các file báo lỗi (Bug ID) được vá thành công hoàn toàn sao cho *vượt qua 100% test cases* gốc.
- **Fixed Initial Fails / Regressions:** Theo dõi các tests bị Fail ở nguyên bản. Báo cáo "Yes" nếu AI đã sửa triệt để. Báo cáo "Yes (Regressions)" nếu AI sửa được lỗi gốc nhưng vô tình làm gãy một test-case khác vốn đang chạy đúng.
- **Edit Distance (Levenshtein):** Tính toán khoảng cách sửa lỗi ký tự giữa bản vá do AI (LLM) đề xuất và **Ground truth patch** (Bản patch đúng do con người làm). Từ đó suy ra mức độ hiệu quả và ngắn gọn của Prompt AI.

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