"""
core/utils.py
-------------
Tiện ích dùng chung cho toàn bộ pipeline (FL, APR).
Tránh duplicate code giữa các module.
"""

import os
import re
from functools import lru_cache
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

    # Defects4C coverage keys use "file:function".  For C++ the function part
    # may itself contain scopes/operators, e.g. "format.h:foo::operator+=".
    # Parse this form before the legacy "::" separator.
    path_func = re.match(
        r"^(?P<file>.+\.(?:c|cc|cpp|cxx|h|hh|hpp|hxx|inl|inc)):(?!:)(?P<func>.+)$",
        qualified,
    )
    if path_func:
        return path_func.group("file"), path_func.group("func")

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
    func_name: str = "",
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
        repo_dir = raw_meta.get("buggy_tree_dir") or raw_meta.get("source_repo_dir") or ""
        if relpath and func_name and repo_dir and not _relpath_defines_function(repo_dir, relpath, func_name):
            repo_relpath = _resolve_defects4c_relpath_from_repo(
                fh,
                raw_meta,
                func_name=func_name,
            )
            if repo_relpath:
                relpath = repo_relpath
        if not relpath:
            relpath = _resolve_defects4c_relpath_from_repo(fh, raw_meta, func_name=func_name)
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


def source_function_name_for_extraction(
    func_name: str,
    candidate_path: str = "",
    raw_meta: Optional[Dict[str, Any]] = None,
) -> str:
    """
    Convert a build/coverage symbol to the spelling used in source, when the
    project has an explicit compatibility macro for that conversion.

    PHP's bundled GD is compiled with symbol-renaming macros from
    ``main/php_compat.h`` such as:

        #define gdAlphaBlend php_gd_gdAlphaBlend

    gcov reports the preprocessed symbol (right hand side), while source files
    define the left hand side.  This helper maps only those exact macro pairs.
    """
    repo_dir = _source_repo_dir_for_symbol_map(candidate_path, raw_meta)
    if repo_dir:
        mapped = _php_compat_compiled_to_source_map(repo_dir).get(func_name)
        if mapped:
            return mapped
    return func_name


def _source_repo_dir_for_symbol_map(
    candidate_path: str = "",
    raw_meta: Optional[Dict[str, Any]] = None,
) -> str:
    if isinstance(raw_meta, dict):
        for key in ("buggy_tree_dir", "source_repo_dir"):
            value = raw_meta.get(key)
            if value and os.path.isdir(value):
                return value
    path = candidate_path or ""
    while path and path != os.path.dirname(path):
        compat = os.path.join(path, "main", "php_compat.h")
        if os.path.isfile(compat):
            return path
        path = os.path.dirname(path)
    return ""


@lru_cache(maxsize=64)
def _php_compat_compiled_to_source_map(repo_dir: str) -> Dict[str, str]:
    compat_path = os.path.join(repo_dir, "main", "php_compat.h")
    if not os.path.isfile(compat_path):
        return {}
    try:
        with open(compat_path, "r", errors="ignore") as f:
            text = f.read()
    except Exception:
        return {}

    out: Dict[str, str] = {}
    for match in re.finditer(
        r'^\s*#\s*define\s+(?P<source>gd[A-Za-z_]\w*)\s+(?P<compiled>php_gd_[A-Za-z_]\w*)\b',
        text,
        re.MULTILINE,
    ):
        out[match.group("compiled")] = match.group("source")
    return out


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


def _resolve_defects4c_relpath_from_repo(
    file_hint: str,
    raw_meta: Dict[str, Any],
    func_name: str = "",
) -> str:
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
        if not func_name or _relpath_defines_function(repo_dir, normalized_hint, func_name):
            return normalized_hint
        relpath = _find_unique_relpath_by_basename(
            repo_dir,
            os.path.basename(normalized_hint),
            func_name=func_name,
        )
        return relpath or normalized_hint

    return _find_unique_relpath_by_basename(
        repo_dir,
        os.path.basename(normalized_hint),
        func_name=func_name,
    )


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


def _find_unique_relpath_by_basename(repo_dir: str, basename: str, func_name: str = "") -> str:
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
    if len(matches) == 1:
        return matches[0]
    if func_name:
        matches_with_func = [
            rel for rel in matches
            if _relpath_defines_function(repo_dir, rel, func_name)
        ]
        if len(matches_with_func) == 1:
            return matches_with_func[0]
    return ""


def _relpath_defines_function(repo_dir: str, relpath: str, func_name: str) -> bool:
    if not repo_dir or not relpath or not func_name:
        return False
    full_path = os.path.join(repo_dir, relpath)
    if not os.path.isfile(full_path):
        return False
    try:
        with open(full_path, "r", errors="ignore") as f:
            source = f.read()
    except Exception:
        return False
    language = "cpp" if os.path.splitext(relpath)[1].lower() in {
        ".cc", ".cpp", ".cxx", ".hpp", ".hh", ".hxx"
    } else "c"
    source_func_name = source_function_name_for_extraction(
        func_name,
        full_path,
        {"buggy_tree_dir": repo_dir},
    )
    func_code, _, _ = extract_function_code(source, source_func_name, language=language)
    return bool(func_code)


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
    if _is_scoped_cpp_name(func_name):
        scoped_result = _extract_scoped_function_code_regex(source_code, func_name)
        if scoped_result[0] is not None:
            return scoped_result

    ts_result = _extract_function_code_tree_sitter(source_code, func_name, language)
    if ts_result[0] is not None:
        return ts_result
    regex_result = _extract_function_code_regex(source_code, func_name)
    if regex_result[0] is not None:
        return regex_result
    leaf_name = _function_name_leaf(func_name)
    if leaf_name != func_name and _allow_unscoped_fallback(source_code, func_name):
        return _extract_function_code_regex(source_code, leaf_name)
    return regex_result


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
        if not _function_name_matches(name, func_name):
            continue
        code = source_bytes[node.start_byte:node.end_byte].decode(
            "utf-8",
            errors="replace",
        )
        return code, node.start_byte, node.end_byte

    return None, -1, -1


def _function_name_leaf(func_name: str) -> str:
    if not func_name:
        return ""
    return _normalize_function_symbol(func_name.rsplit("::", 1)[-1])


def _normalize_function_symbol(value: str) -> str:
    value = str(value or "").strip()
    value = re.sub(r'\[[^\]]+\]', '', value)
    value = value.split("<", 1)[0].strip()
    value = value.lstrip("*&").strip()
    return value


def _function_scope_parts(func_name: str) -> list:
    if not _is_scoped_cpp_name(func_name):
        return []
    return [
        _normalize_function_symbol(part)
        for part in func_name.split("::")[:-1]
        if part.strip()
    ]


def _is_scoped_cpp_name(func_name: str) -> bool:
    return bool(func_name and "::" in func_name)


def _function_name_matches(actual: str, requested: str) -> bool:
    if actual == requested:
        return True
    return not _is_scoped_cpp_name(requested) and actual == _function_name_leaf(requested)


def _allow_unscoped_fallback(source_code: str, func_name: str) -> bool:
    """
    Scoped FL keys must not silently bind to an unrelated free function in a full
    C++ file. The fallback is still useful for validating LLM-returned snippets,
    which normally no longer include the surrounding class body.
    """
    scopes = _function_scope_parts(func_name)
    if not scopes:
        return True
    if _scoped_name_pattern(scopes, _function_name_leaf(func_name)).search(source_code):
        return False
    return not any(_class_body_ranges(source_code, scope) for scope in scopes)


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


def _extract_scoped_function_code_regex(
    source_code: str,
    func_name: str,
) -> Tuple[Optional[str], int, int]:
    scopes = _function_scope_parts(func_name)
    leaf_name = _function_name_leaf(func_name)
    if not scopes or not leaf_name:
        return None, -1, -1

    out_of_class = _extract_function_code_regex(
        source_code,
        leaf_name,
        name_pattern=_scoped_name_pattern(scopes, leaf_name),
    )
    if out_of_class[0] is not None:
        return out_of_class

    for scope in reversed(scopes):
        for body_start, body_end in _class_body_ranges(source_code, scope):
            inline_method = _extract_function_code_regex(
                source_code,
                leaf_name,
                start=body_start,
                end=body_end,
            )
            if inline_method[0] is not None:
                return inline_method

    return None, -1, -1


def _scoped_name_pattern(scopes: list, leaf_name: str):
    scoped = []
    for scope in scopes:
        scoped.append(re.escape(scope) + r'\s*(?:<[^;{}()]*>)?\s*::\s*')
    return re.compile("".join(scoped) + _function_name_call_pattern(leaf_name))


def _function_name_call_pattern(func_name: str) -> str:
    if func_name.startswith("operator"):
        op = func_name[len("operator"):].strip()
        if op:
            return r'operator\s*' + re.escape(op) + r'\s*\('
        return r'operator\s*\('
    return r'\b' + re.escape(func_name) + r'\s*\('


def _php_macro_name_call_patterns(func_name: str):
    """Return source-level PHP extension macro spellings for generated symbols."""
    name = _normalize_function_symbol(func_name)
    patterns = []

    if name.startswith("zif_") and len(name) > 4:
        php_name = name[4:]
        macro_names = (
            "PHP_FUNCTION",
            "ZEND_FUNCTION",
            "ZEND_NAMED_FUNCTION",
            "PHP_NAMED_FUNCTION",
        )
        patterns.extend(
            r'\b' + macro + r'\s*\(\s*' + re.escape(php_name) + r'\s*\)'
            for macro in macro_names
        )

    if name.startswith("zim_") and len(name) > 4:
        rest = name[4:]
        parts = rest.split("_")
        for split_at in range(1, len(parts)):
            class_name = "_".join(parts[:split_at])
            method_name = "_".join(parts[split_at:])
            if not class_name or not method_name:
                continue
            macro_names = ("PHP_METHOD", "ZEND_METHOD", "SPL_METHOD")
            patterns.extend(
                r'\b' + macro + r'\s*\(\s*'
                + re.escape(class_name)
                + r'\s*,\s*'
                + re.escape(method_name)
                + r'\s*\)'
                for macro in macro_names
            )

    if name.startswith("zim_spl_") and len(name) > 8:
        rest = name[8:]
        parts = rest.split("_")
        for split_at in range(1, len(parts)):
            class_name = "_".join(parts[:split_at])
            method_name = "_".join(parts[split_at:])
            if not class_name or not method_name:
                continue
            patterns.append(
                r'\bSPL_METHOD\s*\(\s*'
                + re.escape(class_name)
                + r'\s*,\s*'
                + re.escape(method_name)
                + r'\s*\)'
            )

    return [re.compile(pattern) for pattern in patterns]


def _looks_like_php_extension_source(source_code: str) -> bool:
    return any(
        marker in source_code
        for marker in (
            "PHP_FUNCTION",
            "ZEND_FUNCTION",
            "PHP_METHOD",
            "ZEND_METHOD",
            "SPL_METHOD",
            "TSRMLS",
            "zend_",
        )
    )


def _class_body_ranges(source_code: str, class_name: str):
    if not class_name:
        return []

    ranges = []
    pattern = re.compile(r'\b(?:class|struct|union)\s+' + re.escape(class_name) + r'\b')
    for m in pattern.finditer(source_code):
        brace = source_code.find('{', m.end())
        semi = source_code.find(';', m.end())
        if brace < 0 or (semi >= 0 and semi < brace):
            continue
        end = _find_matching_brace(source_code, brace)
        if end < 0:
            continue
        ranges.append((brace + 1, end - 1))
    return ranges


def _extract_function_code_regex(
    source_code: str,
    func_name: str,
    *,
    start: int = 0,
    end: Optional[int] = None,
    name_pattern=None,
) -> Tuple[Optional[str], int, int]:
    end = len(source_code) if end is None else min(end, len(source_code))
    if name_pattern is not None:
        patterns = [name_pattern]
    else:
        patterns = [re.compile(_function_name_call_pattern(func_name))]
        if _looks_like_php_extension_source(source_code):
            patterns.extend(_php_macro_name_call_patterns(func_name))

    for pattern in patterns:
        for m in pattern.finditer(source_code, start, end):
            name_start = m.start()
            open_paren = source_code.find('(', m.start(), m.end())
            if open_paren < 0:
                continue
            if open_paren >= end:
                continue
            close_paren = _find_matching_paren(source_code, open_paren)
            if close_paren < 0 or close_paren >= end:
                continue

            i = close_paren + 1
            n = end
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
                    comment_end = source_code.find('*/', i + 2)
                    if comment_end < 0:
                        i = n
                        break
                    i = comment_end + 2
                    continue
                if c == '#' and _at_line_start_after_ws(source_code, i):
                    nl = source_code.find('\n', i)
                    if nl < 0:
                        i = n
                        break
                    i = nl + 1
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
                if c == ':':
                    body_open = _find_cpp_ctor_body_open(source_code, i)
                    if body_open >= 0:
                        i = body_open
                    break
                if c == '-' and i + 1 < n and source_code[i + 1] == '>':
                    body_open = _find_cpp_trailing_return_body_open(source_code, i + 2, n)
                    if body_open >= 0:
                        i = body_open
                    break
                break

            if i >= n or source_code[i] != '{':
                continue

            start_idx = _find_function_def_start(source_code, name_start)
            end_idx = _find_matching_brace(source_code, i)
            if end_idx < 0 or end_idx > end:
                end_idx = _find_php_fold_marker_function_end(source_code, i, end)
            if end_idx < 0 or end_idx > end:
                continue

            start_byte = len(source_code[:start_idx].encode("utf-8"))
            end_byte = len(source_code[:end_idx].encode("utf-8"))
            return source_code[start_idx:end_idx], start_byte, end_byte

    return None, -1, -1


def _find_php_fold_marker_function_end(source_code: str, body_open: int, end: int) -> int:
    """Fallback for PHP extension files where preprocessor branches confuse braces."""
    match = re.search(r'\n}\s*/\*\s*}}}', source_code[body_open:end])
    if not match:
        return -1
    return body_open + match.start() + 2


def _find_cpp_ctor_body_open(source: str, colon_pos: int) -> int:
    """Find the body ``{`` after a C++ constructor initializer list."""
    i = colon_pos + 1
    n = len(source)
    while i < n:
        c = source[i]
        if c == '/' and i + 1 < n and source[i + 1] == '/':
            nl = source.find('\n', i)
            if nl < 0:
                return -1
            i = nl + 1
            continue
        if c == '/' and i + 1 < n and source[i + 1] == '*':
            end = source.find('*/', i + 2)
            if end < 0:
                return -1
            i = end + 2
            continue
        if c == '(':
            end = _find_matching_paren(source, i)
            if end < 0:
                return -1
            i = end + 1
            continue
        if c == '{':
            end = _find_matching_brace(source, i)
            if end < 0:
                return -1
            j = end
            while j < n and source[j].isspace():
                j += 1
            if j >= n or source[j] not in (',', '{'):
                return i
            if source[j] == '{':
                return j
            i = j + 1
            continue
        if c == ';':
            return -1
        i += 1
    return -1


def _find_cpp_trailing_return_body_open(source: str, start_pos: int, limit: int) -> int:
    """Find the function body after a C++ trailing return type."""
    i = start_pos
    n = min(limit, len(source))
    while i < n:
        c = source[i]
        if c == '/' and i + 1 < n and source[i + 1] == '/':
            nl = source.find('\n', i)
            if nl < 0 or nl >= n:
                return -1
            i = nl + 1
            continue
        if c == '/' and i + 1 < n and source[i + 1] == '*':
            end = source.find('*/', i + 2)
            if end < 0 or end >= n:
                return -1
            i = end + 2
            continue
        if c == '(':
            end = _find_matching_paren(source, i)
            if end < 0 or end >= n:
                return -1
            i = end + 1
            continue
        if c == '{':
            return i
        if c == ';':
            return -1
        i += 1
    return -1


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
        if stripped.startswith('#') and not _is_signature_preprocessor_line(stripped):
            break
        if stripped in ("public:", "private:", "protected:"):
            break
        if stripped.endswith(';') or stripped.endswith('}'):
            break
        line_start = prev_line_start
    return line_start


def _is_signature_preprocessor_line(stripped_line: str) -> bool:
    return bool(re.match(r'^#\s*(if|ifdef|ifndef|elif|else|endif)\b', stripped_line))


def _at_line_start_after_ws(source: str, pos: int) -> bool:
    line_start = source.rfind('\n', 0, pos) + 1
    return not source[line_start:pos].strip()


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
