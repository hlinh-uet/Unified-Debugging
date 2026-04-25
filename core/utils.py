"""
core/utils.py
-------------
Tiện ích dùng chung cho toàn bộ pipeline (FL, APR).
Tránh duplicate code giữa các module.
"""

import os
import re
import subprocess
from typing import Any, Dict, Optional, Tuple


# ---------------------------------------------------------------------------
# Code normalization helpers
# ---------------------------------------------------------------------------

def normalize_code_for_edit_distance(source_code: str) -> str:
    """
    Chuẩn hóa C/C++ source trước khi tính edit distance:
    - Bỏ line comments (//...) và block comments (/*...*/).
    - Bỏ whitespace bên ngoài string/char literals.
    - Giữ nguyên nội dung string/char literals vì đó là dữ liệu có nghĩa.
    """
    normalized = []
    i = 0
    n = len(source_code)

    while i < n:
        c = source_code[i]

        if c == '/' and i + 1 < n:
            nxt = source_code[i + 1]
            if nxt == '/':
                i = source_code.find('\n', i + 2)
                if i < 0:
                    break
                continue
            if nxt == '*':
                end = source_code.find('*/', i + 2)
                if end < 0:
                    break
                i = end + 2
                continue

        if c.isspace():
            i += 1
            continue

        if c in ('"', "'"):
            i = _append_quoted_literal(source_code, i, normalized)
            continue

        normalized.append(c)
        i += 1

    return ''.join(normalized)


def _append_quoted_literal(source: str, start: int, out: list) -> int:
    """Append a quoted C/C++ string/char literal and return the next index."""
    quote = source[start]
    i = start
    n = len(source)

    out.append(source[i])
    i += 1

    while i < n:
        c = source[i]
        out.append(c)
        i += 1

        if c == '\\' and i < n:
            out.append(source[i])
            i += 1
            continue

        if c == quote:
            break

    return i

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


def parse_sbfl_qualified_name(qualified: str) -> Tuple[str, str]:
    """
    Tách khóa suspiciousness (FL) thành (file_hint, func_name).

    - Codeflaws / chuẩn cũ: ``/path/to/file.c::symbol`` → đường dẫn file + tên hàm.
    - Defects4C metadata: ``file.c:function`` (một dấu ``:``).

    Nếu không nhận dạng được, trả về ("", qualified) để tương thích hành vi cũ.
    """
    if not qualified:
        return "", ""
    sep = "::"
    if sep in qualified:
        idx = qualified.rfind(sep)
        return qualified[:idx], qualified[idx + len(sep) :]
    idx = qualified.rfind(":")
    if idx > 0:
        left, right = qualified[:idx], qualified[idx + 1 :]
        if re.match(r"^[A-Za-z_]\w*$", right):
            return left, right
    return "", qualified


def resolve_fl_candidate_source_path(
    dataset_name: str,
    bug_source_path: str,
    file_hint: str,
    raw_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Map FL key (file phần) sang đường dẫn .c thật để đọc/vá.

    - Defects4C: ưu tiên ``source_dir_buggy`` trong metadata + basename(file_hint).
    - Codeflaws: nếu file_hint là đường dẫn tuyệt đối tồn tại thì dùng luôn.
    - Fallback: cùng thư mục với file bug chính.
    """
    if not file_hint or not bug_source_path:
        return bug_source_path
    fh = file_hint.strip()
    if os.path.isabs(fh) and os.path.isfile(fh):
        return fh
    base = os.path.basename(fh)
    ds = (dataset_name or "").lower()
    defects4c_like = bool(raw_meta and (
        ds == "defects4c"
        or "data_folder" in raw_meta
        or "metadata_file" in raw_meta
        or "metadata_slug" in raw_meta
    ))
    if defects4c_like:
        cached = _resolve_defects4c_cached_source(bug_source_path, base, raw_meta)
        if cached:
            return cached
        src_dir = raw_meta.get("source_dir_buggy") or ""
        if src_dir:
            cand = os.path.join(src_dir, base)
            if os.path.isfile(cand):
                return cand
    parent = os.path.dirname(bug_source_path)
    cand = os.path.join(parent, base)
    if os.path.isfile(cand):
        return cand
    return bug_source_path


def _resolve_defects4c_cached_source(
    bug_source_path: str,
    basename: str,
    raw_meta: Dict[str, Any],
) -> str:
    """Return a cached buggy source file for a Defects4C FL file hint."""
    if not basename:
        return ""

    if os.path.basename(bug_source_path) == basename and os.path.isfile(bug_source_path):
        return bug_source_path

    repo_dir = raw_meta.get("source_repo_dir") or ""
    commit_before = raw_meta.get("commit_before") or ""
    cache_dir = raw_meta.get("source_cache_dir") or os.path.dirname(bug_source_path)
    if not repo_dir or not commit_before or not os.path.isdir(repo_dir):
        return ""

    relpath = _find_unique_relpath_by_basename(repo_dir, basename)
    if not relpath:
        return ""

    os.makedirs(cache_dir, exist_ok=True)
    cache_name = relpath.replace("/", "__")
    cache_path = os.path.join(cache_dir, cache_name)
    if os.path.isfile(cache_path):
        return cache_path

    try:
        result = subprocess.run(
            ["git", "-C", repo_dir, "show", f"{commit_before}:{relpath}"],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
        )
    except Exception:
        return ""

    if result.returncode != 0:
        return ""
    try:
        with open(cache_path, "w") as f:
            f.write(result.stdout)
    except Exception:
        return ""
    return cache_path


def _find_unique_relpath_by_basename(repo_dir: str, basename: str) -> str:
    matches = []
    for root, dirs, files in os.walk(repo_dir):
        dirs[:] = [
            d for d in dirs
            if d != ".git" and d != "CMakeFiles" and not d.startswith("build_meta_")
        ]
        if basename in files:
            full = os.path.join(root, basename)
            rel = os.path.relpath(full, repo_dir).replace(os.sep, "/")
            matches.append(rel)
    if not matches:
        return ""
    # Prefer top-level source files when there are generated/build duplicates.
    matches.sort(key=lambda p: (p.count("/"), p))
    return matches[0]


def extract_function_code(
    source_code: str,
    func_name: str
) -> Tuple[Optional[str], int, int]:
    """
    Trích xuất mã nguồn của một hàm C/C++ từ chuỗi source_code.

    Thuật toán:
      1. Tìm mọi lần xuất hiện ``<func_name>(`` (word-boundary).
      2. Tìm ngoặc tròn đóng tương ứng – có cân bằng paren lồng nhau
         (xử lý được function-pointer parameter, e.g. ``void (*cb)(int)``).
      3. Sau dấu ``)`` bỏ qua whitespace + attribute ``__attribute__((...))``,
         nếu gặp ``{`` thì coi đó là định nghĩa hàm; ngược lại là khai báo/gọi
         hàm – bỏ qua và tiếp tục tìm.
      4. Tìm ``}`` đóng bằng counter (bỏ qua comments / strings / chars).

    Args:
        source_code: Toàn bộ nội dung file mã nguồn.
        func_name:   Tên hàm cần trích xuất.

    Returns:
        Tuple (func_code, start_idx, end_idx):
            - func_code:  Chuỗi mã nguồn của hàm, hoặc None nếu không tìm thấy.
            - start_idx:  Vị trí byte bắt đầu (return type) trong source_code.
            - end_idx:    Vị trí ngay sau ``}`` đóng (exclusive).
    """
    pattern = re.compile(r'\b' + re.escape(func_name) + r'\s*\(')

    for m in pattern.finditer(source_code):
        name_start  = m.start()
        open_paren  = m.end() - 1
        close_paren = _find_matching_paren(source_code, open_paren)
        if close_paren < 0:
            continue

        i = close_paren + 1
        n = len(source_code)
        # Bỏ qua whitespace, newline, comment, và attribute specifier
        # trước khi gặp '{' mở hàm (GCC: __attribute__((...)), const, throw(),...).
        while i < n:
            c = source_code[i]
            if c.isspace():
                i += 1
                continue
            if c == '/' and i + 1 < n and source_code[i + 1] == '/':
                nl = source_code.find('\n', i)
                if nl < 0:
                    i = n
                    break
                i = nl + 1
                continue
            if c == '/' and i + 1 < n and source_code[i + 1] == '*':
                end = source_code.find('*/', i + 2)
                if end < 0:
                    i = n
                    break
                i = end + 2
                continue
            # __attribute__((...)) hoặc const/throw()... – nhảy qua token + paren
            if c.isalpha() or c == '_':
                j = i
                while j < n and (source_code[j].isalnum() or source_code[j] == '_'):
                    j += 1
                # Nếu token này là 'return' hoặc keyword khác, có nghĩa không phải def
                if source_code[i:j] in ("return", "sizeof", "if", "while", "for", "switch"):
                    break
                # Nhảy qua whitespace, nếu có '(' kế tiếp thì skip paren group
                k = j
                while k < n and source_code[k].isspace():
                    k += 1
                if k < n and source_code[k] == '(':
                    end_paren = _find_matching_paren(source_code, k)
                    if end_paren < 0:
                        break
                    i = end_paren + 1
                    continue
                i = j
                continue
            break

        if i >= n or source_code[i] != '{':
            continue

        start_idx = _find_function_def_start(source_code, name_start)
        end_idx   = _find_matching_brace(source_code, i)
        if end_idx < 0:
            continue

        return source_code[start_idx:end_idx], start_idx, end_idx

    return None, -1, -1


def _find_function_def_start(source: str, name_pos: int) -> int:
    """
    Đi lùi theo từng dòng từ vị trí ``name_pos`` để tìm dòng đầu của
    return-type/attribute specifier. Dừng khi gặp:

    - Dòng trống (chỉ whitespace).
    - Dòng bắt đầu bằng ``#`` (preprocessor directive).
    - Dòng kết thúc bằng ``;`` hoặc ``}`` (kết thúc construct trước đó).
    """
    line_start = source.rfind('\n', 0, name_pos) + 1
    while line_start > 0:
        prev_line_end   = line_start - 1
        prev_line_start = source.rfind('\n', 0, prev_line_end) + 1
        stripped = source[prev_line_start:prev_line_end].strip()
        if not stripped:
            break
        if stripped.startswith('#'):
            break
        if stripped.endswith(';') or stripped.endswith('}'):
            break
        line_start = prev_line_start
    return line_start


def _find_matching_paren(source: str, open_pos: int) -> int:
    """
    Tìm '(' đóng tương ứng với '(' tại open_pos, bỏ qua parens trong
    comments, string literals, char literals.

    Returns: vị trí của ')' đóng, hoặc -1 nếu không tìm thấy.
    """
    depth = 0
    i = open_pos
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

        if c == '(':
            depth += 1
        elif c == ')':
            depth -= 1
            if depth == 0:
                return i

        i += 1

    return -1


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
