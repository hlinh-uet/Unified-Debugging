# Unified-Debugging Pipeline

Đây là công cụ tự động chẩn đoán lỗi (Fault Localization) và sửa lỗi tự động (Automated Program Repair) cơ bản dùng thuật toán Tarantula và LLM (Placeholder). Hệ thống được sử dụng cho bộ dữ liệu Codeflaws.

## Cấu trúc thư mục tương đối

- `core/`: Chứa các thuật toán xử lý chính
  - `fl_tarantula.py`: Thuật toán chấm điểm Tarantula.
  - `apr_baseline.py`: Bộ sinh bản vá tự động dựa trên LLM prompt.
- `data_loaders/`: Các module đọc kết quả JSON / nguồn C của bug.
- `configs/path.py`: Nơi thiết lập thư mục trỏ đến `codeflaws` repository (Tự động config)
- `experiments/`: Khởi tạo sau khi chạy test để lưu trữ kết quả phân tích Tarantula (`tarantula_results.json`) và nơi lưu Patch thành công (`patches/`).

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

## Các hạn chế và Hướng phát triển

Hệ thống đang ở mức Baseline để chứng minh khả năng ráp nối giữa Fault Localization và LLM APR. Các điểm thiếu sót cần được chuẩn hóa như sau:

### Phân tích và biên dịch (Compilation & Analysis)
- **Validation lỏng lẻo:** script xác thực (hàm `validate_patch` trong `apr_baseline.py`) hiện tại trả về kết quả giả (`False`). Cần gọi trình biên dịch (VD: `gcc patched.c -o program`), nối ghép đầu ra và gọi trực tiếp `tests/` để đánh giá Test Case cụ thể.
- **Tính toán gcov/lcov chưa được nhúng:** Các phép đo Tarantula bị phụ thuộc vào metadata trích xuất JSON. Hệ thống nên triển khai luồng chạy biên dịch gcov và load matrix test-case tự động đối với các file C mới.

### Chỉnh sửa Code C (Source Extraction & Injection)
- **Trích xuất bằng Regex:** Hàm `extract_function_code()` hiện vẫn sử dụng biểu thức chính quy tĩnh và tìm ngoặc ngẫu nhiên (`{`, `}`). Có thể hoạt động không đúng nếu C macro, strings, hoặc comment chứa các dấu ngoặc nhọn này.
- **Đề xuất công nghệ:** Cần áp dụng các thư viện như `pycparser`, Clang AST hay `tree-sitter` để trích xuất hoặc thay thế nguyên dòng (statement/function-level) chuẩn hóa hơn.

### Hệ thống Generative AI (LLM APIs)
- **API Placeholder:** Hàm `call_llm()` chưa được cắm Gemini hoặc OpenAI thực.
- **LLM Error Recovery:** Trường hợp API timeout hay mô hình không tuân thủ mẫu trả về (ví dụ, xuất lộn xộn các thẻ Markdown chung với C). Cần có bộ lọc parser cho đầu ra của LLM.
- **Ràng buộc mã (Context Windows):** Đối với các tệp C dung lượng siêu lớn, cần nén prompt tốt hơn là chèn nguyên mã hàm.