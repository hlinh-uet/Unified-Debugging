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

    Sử dụng Regex để tìm điểm bắt đầu và đếm ngoặc nhọn (bỏ qua braces
    trong comment, string literal, char literal) để tìm điểm kết thúc.

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
        r'\b(?:(?:int|void|char|double|float|long|unsigned|short|struct|static|inline|const)\s+)*'
        r'\**\s*'
        + re.escape(func_name)
        + r'\s*\([^)]*\)\s*\{',
        re.MULTILINE
    )
    match = pattern.search(source_code)

    if not match:
        if func_name == "main":
            pattern = re.compile(r'\bmain\s*\([^)]*\)\s*\{', re.MULTILINE)
            match = pattern.search(source_code)
        if not match:
            return None, -1, -1

    start_idx = match.start()
    end_idx = _find_matching_brace(source_code, match.end() - 1)
    if end_idx < 0:
        return None, -1, -1

    return source_code[start_idx:end_idx], start_idx, end_idx


def _find_matching_brace(source: str, open_brace_pos: int) -> int:
    """
    Tìm dấu } đóng tương ứng với { tại open_brace_pos, bỏ qua braces
    bên trong comments (/* */, //), string literals ("..."), và
    char literals ('...').

    Returns: vị trí ngay sau } (exclusive), hoặc -1 nếu không tìm thấy.
    """
    depth = 0
    i = open_brace_pos
    n = len(source)

    while i < n:
        c = source[i]

        if c == '/' and i + 1 < n:
            if source[i + 1] == '/':
                i = source.find('\n', i)
                if i < 0:
                    return -1
                i += 1
                continue
            if source[i + 1] == '*':
                end = source.find('*/', i + 2)
                if end < 0:
                    return -1
                i = end + 2
                continue

        if c == '"':
            i += 1
            while i < n and source[i] != '"':
                if source[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue

        if c == "'":
            i += 1
            while i < n and source[i] != "'":
                if source[i] == '\\':
                    i += 1
                i += 1
            i += 1
            continue

        if c == '{':
            depth += 1
        elif c == '}':
            depth -= 1
            if depth == 0:
                return i + 1

        i += 1

    return -1
