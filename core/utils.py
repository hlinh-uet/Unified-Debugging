"""
core/utils.py
-------------
Tiện ích dùng chung cho toàn bộ pipeline (FL, APR).
Tránh duplicate code giữa các module.
"""

import os
import re
from typing import Any, Dict, Optional, Tuple

try:
    from tree_sitter import Language, Parser
except Exception:  # pragma: no cover - optional dependency
    Language = None
    Parser = None

try:
    import tree_sitter_c
except Exception:  # pragma: no cover - optional dependency
    tree_sitter_c = None

try:
    import tree_sitter_cpp
except Exception:  # pragma: no cover - optional dependency
    tree_sitter_cpp = None


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

    - Defects4C: ưu tiên metadata ``src_files``/``source_relpath``; nếu FL trỏ
      sang file khác thì chỉ nhận khi file hint resolve được duy nhất trong repo.
    - Codeflaws: nếu file_hint là đường dẫn tuyệt đối tồn tại thì dùng luôn.
    - Codeflaws fallback: cùng thư mục với file bug chính.
    """
    if not file_hint or not bug_source_path:
        return bug_source_path
    fh = file_hint.strip()
    base = os.path.basename(fh)
    ds = (dataset_name or "").lower()
    defects4c_like = bool(raw_meta and (
        ds == "defects4c"
        or "data_folder" in raw_meta
        or "metadata_file" in raw_meta
        or "metadata_slug" in raw_meta
    ))
    if defects4c_like:
        relpath = _resolve_defects4c_relpath_from_meta(fh, raw_meta)
        if not relpath:
            relpath = _resolve_defects4c_relpath_from_repo(fh, raw_meta)
        if not relpath:
            return ""
        cached = _resolve_defects4c_cached_source(bug_source_path, relpath, raw_meta)
        if cached:
            return cached
        src_dir = raw_meta.get("source_dir_buggy") or ""
        if src_dir:
            cand = os.path.join(src_dir, relpath)
            if os.path.isfile(cand):
                return cand
        return ""
    if os.path.isabs(fh) and os.path.isfile(fh):
        return fh
    parent = os.path.dirname(bug_source_path)
    cand = os.path.join(parent, base)
    if os.path.isfile(cand):
        return cand
    return bug_source_path


def _resolve_defects4c_relpath_from_meta(file_hint: str, raw_meta: Dict[str, Any]) -> str:
    """Resolve a Defects4C FL file hint to exactly one source relpath."""
    if not file_hint or not isinstance(raw_meta, dict):
        return ""
    normalized_hint = file_hint.strip().replace("\\", "/")
    hint_base = os.path.basename(normalized_hint)
    src_files = raw_meta.get("src_files")
    if not isinstance(src_files, list) or not src_files:
        files = raw_meta.get("files", {})
        if isinstance(files, dict):
            src_files = files.get("src", [])
    if not isinstance(src_files, list) or not src_files:
        rel = raw_meta.get("source_relpath")
        src_files = [rel] if rel else []

    candidates = []
    for rel in src_files:
        if not isinstance(rel, str):
            continue
        rel_norm = rel.strip().replace("\\", "/")
        if not rel_norm:
            continue
        if rel_norm == normalized_hint or os.path.basename(rel_norm) == hint_base:
            candidates.append(rel_norm)
    candidates = list(dict.fromkeys(candidates))
    return candidates[0] if len(candidates) == 1 else ""


def _resolve_defects4c_relpath_from_repo(file_hint: str, raw_meta: Dict[str, Any]) -> str:
    """Resolve a non-ground-truth Defects4C FL file hint without fallback."""
    if not file_hint or not isinstance(raw_meta, dict):
        return ""
    repo_dir = raw_meta.get("buggy_tree_dir") or raw_meta.get("source_repo_dir") or ""
    if not repo_dir or not os.path.isdir(repo_dir):
        return ""

    normalized_hint = file_hint.strip().replace("\\", "/")
    if os.path.isabs(normalized_hint) or ".." in normalized_hint.split("/"):
        return ""

    direct = os.path.join(repo_dir, normalized_hint)
    if "/" in normalized_hint and os.path.isfile(direct):
        return normalized_hint

    return _find_unique_relpath_by_basename(repo_dir, os.path.basename(normalized_hint))


def _resolve_defects4c_cached_source(
    bug_source_path: str,
    relpath: str,
    raw_meta: Dict[str, Any],
) -> str:
    """Return a materialized buggy-version source file for a Defects4C hint."""
    if not relpath:
        return ""

    relpath = relpath.strip().replace("\\", "/")
    if os.path.isabs(relpath) or ".." in relpath.split("/"):
        return ""

    buggy_tree_dir = raw_meta.get("buggy_tree_dir") or ""
    if buggy_tree_dir:
        cand = os.path.join(buggy_tree_dir, relpath)
        if os.path.isfile(cand):
            return cand

    if (
        raw_meta.get("source_relpath") == relpath
        and os.path.isfile(bug_source_path)
    ):
        return bug_source_path
    return ""


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
    return matches[0] if len(matches) == 1 else ""


def extract_function_code(
    source_code: str,
    func_name: str,
    language: str = "c",
) -> Tuple[Optional[str], int, int]:
    """
    Trích xuất mã nguồn của một hàm C/C++ từ chuỗi source_code.

    Thuật toán mặc định:
      1. Parse source bằng tree-sitter (C/C++).
      2. Duyệt các node ``function_definition``.
      3. Lấy tên hàm từ declarator và so khớp với ``func_name``.
      4. Trả về source slice theo ``start_byte``/``end_byte`` của node.

    Nếu tree-sitter không khả dụng hoặc không tìm thấy hàm, fallback về
    extractor cũ dựa trên regex + counter:
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
        language:    ``"c"`` hoặc ``"cpp"``/``"c++"``.

    Returns:
        Tuple (func_code, start_idx, end_idx):
            - func_code:  Chuỗi mã nguồn của hàm, hoặc None nếu không tìm thấy.
            - start_idx:  Vị trí byte bắt đầu (return type) trong source_code.
            - end_idx:    Vị trí ngay sau ``}`` đóng (exclusive).
    """
    ts_result = _extract_function_code_tree_sitter(source_code, func_name, language)
    if ts_result[0] is not None:
        return ts_result
    return _extract_function_code_regex(source_code, func_name)


def replace_source_range_bytes(
    source_code: str,
    start_byte: int,
    end_byte: int,
    replacement: str,
) -> str:
    """
    Thay một đoạn source theo byte range UTF-8.

    Tree-sitter trả ``start_byte``/``end_byte`` theo bytes, không phải chỉ số
    ký tự Python. Dùng helper này để tránh slice nhầm khi source có non-ASCII.
    """
    if start_byte < 0 or end_byte < start_byte:
        raise ValueError(f"Invalid byte range: {start_byte}:{end_byte}")
    source_bytes = source_code.encode("utf-8")
    patched = (
        source_bytes[:start_byte]
        + replacement.encode("utf-8")
        + source_bytes[end_byte:]
    )
    return patched.decode("utf-8", errors="replace")


def source_byte_range_to_char_range(
    source_code: str,
    start_byte: int,
    end_byte: int,
) -> Tuple[int, int]:
    """Chuyển byte range UTF-8 sang char range để dùng với string slicing."""
    if start_byte < 0 or end_byte < start_byte:
        return -1, -1
    source_bytes = source_code.encode("utf-8")
    if end_byte > len(source_bytes):
        return -1, -1
    start_char = len(source_bytes[:start_byte].decode("utf-8", errors="replace"))
    end_char = len(source_bytes[:end_byte].decode("utf-8", errors="replace"))
    return start_char, end_char


def _extract_function_code_tree_sitter(
    source_code: str,
    func_name: str,
    language: str,
) -> Tuple[Optional[str], int, int]:
    if Parser is None:
        return None, -1, -1
    lang = _tree_sitter_language(language)
    if lang is None:
        return None, -1, -1

    source_bytes = source_code.encode("utf-8")
    parser = Parser()
    try:
        parser.language = lang
    except Exception:
        try:
            parser.set_language(lang)
        except Exception:
            return None, -1, -1

    try:
        tree = parser.parse(source_bytes)
    except Exception:
        return None, -1, -1

    for node in _walk_tree_sitter_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        name = _tree_sitter_function_name(declarator, source_bytes)
        if name != func_name:
            continue
        code = source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8",
            errors="replace",
        )
        return code, node.start_byte, node.end_byte

    return None, -1, -1


def _tree_sitter_language(language: str):
    key = (language or "c").strip().lower()
    module = tree_sitter_cpp if key in ("cpp", "c++", "cc", "cxx") else tree_sitter_c
    if module is None or Language is None:
        return None
    try:
        return Language(module.language())
    except Exception:
        try:
            return module.language()
        except Exception:
            return None


def _walk_tree_sitter_nodes(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _tree_sitter_function_name(declarator, source_bytes: bytes) -> str:
    """
    Lấy tên function từ declarator tree-sitter.

    Với C thông thường declarator có ``identifier`` trực tiếp. Với C++ hoặc
    declarator phức tạp, tên có thể nằm trong ``qualified_identifier``,
    ``field_identifier``, ``operator_name`` hoặc lồng trong pointer declarator.
    """
    name_node = declarator.child_by_field_name("declarator")
    if name_node is not None:
        nested = _tree_sitter_function_name(name_node, source_bytes)
        if nested:
            return nested

    for field in ("name", "field", "operator"):
        try:
            child = declarator.child_by_field_name(field)
        except Exception:
            child = None
        if child is not None:
            text = source_bytes[child.start_byte:child.end_byte].decode(
                "utf-8",
                errors="replace",
            )
            return text.split("::")[-1].strip()

    if declarator.type in (
        "identifier",
        "field_identifier",
        "destructor_name",
        "operator_name",
    ):
        return source_bytes[declarator.start_byte:declarator.end_byte].decode(
            "utf-8",
            errors="replace",
        )

    if declarator.type in ("qualified_identifier", "template_function"):
        text = source_bytes[declarator.start_byte:declarator.end_byte].decode(
            "utf-8",
            errors="replace",
        )
        return text.split("::")[-1].split("<", 1)[0].strip()

    for child in declarator.children:
        name = _tree_sitter_function_name(child, source_bytes)
        if name:
            return name
    return ""


def _extract_function_code_regex(
    source_code: str,
    func_name: str
) -> Tuple[Optional[str], int, int]:
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

        start_byte = len(source_code[:start_idx].encode("utf-8"))
        end_byte = len(source_code[:end_idx].encode("utf-8"))
        return source_code[start_idx:end_idx], start_byte, end_byte

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
