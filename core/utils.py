"""
core/utils.py
-------------
Tiện ích dùng chung cho toàn bộ pipeline (FL, APR, Mutation).
Tránh duplicate code giữa các module.
"""

import re
from typing import Tuple, Optional


def extract_function_code(
    source_code: str,
    func_name: str
) -> Tuple[Optional[str], int, int]:
    """
    Trích xuất mã nguồn của một hàm C/C++ từ chuỗi source_code.

    Sử dụng Regex để tìm điểm bắt đầu và đếm ngoặc nhọn để tìm điểm kết thúc.
    Hỗ trợ đa dạng kiểu khai báo (int, void, char*, struct, static, ...) và
    có fallback riêng cho hàm `main`.

    Args:
        source_code: Toàn bộ nội dung file mã nguồn (chuỗi).
        func_name:   Tên hàm cần trích xuất.

    Returns:
        Tuple (func_code, start_idx, end_idx):
            - func_code:  Chuỗi mã nguồn của hàm, hoặc None nếu không tìm thấy.
            - start_idx:  Vị trí byte bắt đầu trong source_code (-1 nếu không tìm thấy).
            - end_idx:    Vị trí byte kết thúc (exclusive) trong source_code (-1 nếu không tìm thấy).
    """
    pattern = re.compile(
        r'\b(?:int|void|char|double|float|long|unsigned|short|struct|static)?\s*\*?\s*'
        + re.escape(func_name)
        + r'\s*\([^)]*\)\s*\{',
        re.MULTILINE
    )
    match = pattern.search(source_code)

    if not match:
        if func_name == "main":
            # Fallback cho `main` thiếu kiểu trả về
            pattern = re.compile(r'\bmain\s*\([^)]*\)\s*\{', re.MULTILINE)
            match = pattern.search(source_code)
        if not match:
            return None, -1, -1

    start_idx = match.start()
    open_braces = 0
    in_func = False

    for i in range(match.end() - 1, len(source_code)):
        char = source_code[i]
        if char == '{':
            open_braces += 1
            in_func = True
        elif char == '}':
            open_braces -= 1
            if in_func and open_braces == 0:
                return source_code[start_idx:i + 1], start_idx, i + 1

    return None, -1, -1
