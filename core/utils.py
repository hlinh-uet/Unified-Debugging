"""
core/utils.py
-------------
Tiện ích dùng chung cho toàn bộ pipeline (FL, APR, Mutation).
Tránh duplicate code giữa các module.
"""

import re
from typing import Tuple, Optional

# ---------------------------------------------------------------------------
# Qualified function name helpers
# ---------------------------------------------------------------------------
# Format: "<absolute_source_file_path>::<func_name>"
# Ví dụ: "/path/to/benchmark/10-A-bug-.../10-A-5914564.c::main"
# Dùng "::" làm separator vì ký tự này không xuất hiện trong tên file Unix.

def qualify_func(source_file: str, func_name: str) -> str:
    """
    Tạo tên hàm đầy đủ bao gồm đường dẫn file nguồn.

    Args:
        source_file: Đường dẫn tuyệt đối đến file nguồn chứa hàm.
        func_name:   Tên hàm (identifier C/C++).

    Returns:
        Chuỗi dạng "<source_file>::<func_name>".
    """
    return f"{source_file}::{func_name}"


def parse_qualified_func(qualified: str) -> Tuple[str, str]:
    """
    Phân tách chuỗi tên hàm đầy đủ thành (source_file, func_name).

    Args:
        qualified: Chuỗi dạng "<source_file>::<func_name>" hoặc tên hàm đơn giản.

    Returns:
        Tuple (source_file, func_name).
        Nếu không chứa "::", trả về ("", qualified).
    """
    sep = "::"
    idx = qualified.rfind(sep)
    if idx < 0:
        return "", qualified
    return qualified[:idx], qualified[idx + len(sep):]


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


# ---------------------------------------------------------------------------
# Codeflaws-specific filename helpers (dùng chung cho tất cả modules)
# ---------------------------------------------------------------------------

def get_codeflaws_buggy_cfile(bug_id: str) -> str:
    """
    Tính tên file .c lỗi của Codeflaws từ bug_id.
    Ví dụ: '476-A-bug-16608008-16608059' → '476-A-16608008.c'
    """
    try:
        prefix    = bug_id.split("-bug-")[0]
        buggy_ver = bug_id.split("-bug-")[1].split("-")[0]
        return f"{prefix}-{buggy_ver}.c"
    except (IndexError, ValueError):
        return ""


def get_codeflaws_accepted_cfile(bug_id: str) -> str:
    """
    Tính tên file .c accepted (đúng) của Codeflaws từ bug_id.
    Ví dụ: '476-A-bug-16608008-16608059' → '476-A-16608059.c'
    """
    try:
        prefix       = bug_id.split("-bug-")[0]
        accepted_ver = bug_id.split("-bug-")[1].split("-")[1]
        return f"{prefix}-{accepted_ver}.c"
    except (IndexError, ValueError):
        return ""
