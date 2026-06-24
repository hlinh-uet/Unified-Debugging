import os
import re
from typing import Any, Dict, List, Optional, Tuple

from core.utils import (
    Language,
    Parser,
    source_byte_range_to_char_range,
    tree_sitter_c,
    tree_sitter_cpp,
)


SOURCE_EXTS = {
    ".c",
    ".cc",
    ".cpp",
    ".cxx",
    ".h",
    ".hh",
    ".hpp",
    ".hxx",
    ".inl",
    ".inc",
}


def clip_text(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value).rstrip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"


def dedup_keep_order(values: List[str]) -> List[str]:
    out = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        out.append(text)
        seen.add(text)
    return out


def source_language_from_path(path: str) -> str:
    ext = os.path.splitext(path or "")[1].lower()
    return "cpp" if ext in (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".h") else "c"


def is_source_like(path: str) -> bool:
    return os.path.splitext(path or "")[1].lower() in SOURCE_EXTS


def nearest_git_root(path: str) -> str:
    cur = path if os.path.isdir(path) else os.path.dirname(path)
    while cur and cur != os.path.dirname(cur):
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        cur = os.path.dirname(cur)
    return ""


def source_root(source_path: str, context_root: Optional[str]) -> str:
    if context_root and os.path.isdir(context_root):
        return os.path.normpath(context_root)
    return nearest_git_root(source_path) or os.path.normpath(os.path.dirname(source_path))


def relpath(path: str, root: str) -> str:
    try:
        value = os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path
    return value if not value.startswith("../") else path


def tree_sitter_language(language: str):
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


def parser_diagnostics(language: str) -> Dict[str, Any]:
    key = (language or "c").strip().lower()
    wants_cpp = key in ("cpp", "c++", "cc", "cxx")
    module = tree_sitter_cpp if wants_cpp else tree_sitter_c
    grammar = "tree_sitter_cpp" if wants_cpp else "tree_sitter_c"
    available = Parser is not None and Language is not None and module is not None
    lang = tree_sitter_language(language) if available else None
    return {
        "parser_package_available": Parser is not None and Language is not None,
        "grammar": grammar,
        "grammar_available": module is not None,
        "language_object_available": lang is not None,
        "ast_preferred": True,
        "fallback_policy": "Use regex only when tree-sitter grammar/parser is unavailable or the source fragment cannot be parsed.",
    }


def parse_tree(source: str, language: str):
    if Parser is None:
        return None, None
    lang = tree_sitter_language(language)
    if lang is None:
        return None, None
    parser = Parser()
    try:
        parser.language = lang
    except Exception:
        try:
            parser.set_language(lang)
        except Exception:
            return None, None
    source_bytes = source.encode("utf-8")
    try:
        return parser.parse(source_bytes), source_bytes
    except Exception:
        return None, None


def constructor_initializer_names(source: str, language: str = "cpp") -> List[str]:
    names = _constructor_initializer_names_ast(source, language)
    if names:
        return names
    initializer_text = _constructor_initializer_text(source)
    if not initializer_text:
        return []
    out = []
    for part in split_top_level_commas(initializer_text):
        match = re.match(r"\s*([A-Za-z_]\w*)\s*(?:\(|\{)", part)
        if match:
            out.append(match.group(1))
    return dedup_keep_order(out)


def signature_without_constructor_initializers(source: str) -> str:
    header = str(source or "").split("{", 1)[0]
    close = _find_first_parameter_list_close(header)
    if close >= 0:
        suffix = header[close + 1 :]
        colon = _find_top_level_constructor_colon(suffix)
        if colon >= 0:
            header = header[: close + 1] + suffix[:colon]
    return re.sub(r"\s+", " ", header).strip()


def split_top_level_commas(text: str) -> List[str]:
    parts = []
    start = 0
    depth = 0
    quote = ""
    escaped = False
    for idx, ch in enumerate(text or ""):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        elif ch == "," and depth == 0:
            parts.append(text[start:idx])
            start = idx + 1
    parts.append((text or "")[start:])
    return parts


def _constructor_initializer_names_ast(source: str, language: str) -> List[str]:
    tree, source_bytes = parse_tree(source or "", language)
    if tree is None or source_bytes is None:
        return []
    names = []
    for node in walk_nodes(tree.root_node):
        if node.type != "field_initializer":
            continue
        field = None
        try:
            field = node.child_by_field_name("field")
        except Exception:
            field = None
        if field is not None:
            text = node_text(field, source_bytes).strip()
            if text:
                names.append(text)
                continue
        for child in node.children:
            if child.type == "field_identifier":
                text = node_text(child, source_bytes).strip()
                if text:
                    names.append(text)
                    break
    return dedup_keep_order(names)


def _constructor_initializer_text(source: str) -> str:
    header = str(source or "").split("{", 1)[0]
    if not header:
        return ""
    close = _find_first_parameter_list_close(header)
    if close < 0:
        return ""
    suffix = header[close + 1 :]
    colon = _find_top_level_constructor_colon(suffix)
    return suffix[colon + 1 :].strip() if colon >= 0 else ""


def _find_first_parameter_list_close(header: str) -> int:
    open_idx = header.find("(")
    if open_idx < 0:
        return -1
    depth = 0
    quote = ""
    escaped = False
    for idx in range(open_idx, len(header)):
        ch = header[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return idx
    return -1


def _find_top_level_constructor_colon(text: str) -> int:
    depth = 0
    quote = ""
    escaped = False
    for idx, ch in enumerate(text or ""):
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch in "([{<":
            depth += 1
        elif ch in ")]}>":
            depth = max(0, depth - 1)
        elif ch == ":" and depth == 0:
            prev_ch = text[idx - 1] if idx > 0 else ""
            next_ch = text[idx + 1] if idx + 1 < len(text) else ""
            if prev_ch != ":" and next_ch != ":":
                return idx
    return -1


def walk_nodes(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def function_name_from_declarator(declarator, source_bytes: bytes) -> str:
    nested = declarator.child_by_field_name("declarator")
    if nested is not None:
        name = function_name_from_declarator(nested, source_bytes)
        if name:
            return name

    for field in ("name", "field", "operator"):
        try:
            child = declarator.child_by_field_name(field)
        except Exception:
            child = None
        if child is not None:
            return _clean_qualified_name(node_text(child, source_bytes))

    if declarator.type in (
        "identifier",
        "field_identifier",
        "destructor_name",
        "operator_name",
    ):
        return _clean_qualified_name(node_text(declarator, source_bytes))

    if declarator.type in ("qualified_identifier", "template_function"):
        return _clean_qualified_name(node_text(declarator, source_bytes))

    for child in declarator.children:
        name = function_name_from_declarator(child, source_bytes)
        if name:
            return name
    return ""


def call_name_from_node(function_node, source_bytes: bytes) -> str:
    text = node_text(function_node, source_bytes).strip()
    if not text:
        return ""
    text = text.split("::")[-1].split("<", 1)[0].strip()
    if "->" in text:
        text = text.rsplit("->", 1)[-1].strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1].strip()
    return text


def function_matches(actual: str, requested: str) -> bool:
    actual = _clean_qualified_name(actual)
    requested = _clean_qualified_name(requested)
    if actual == requested:
        return True
    if "::" not in requested and actual.rsplit("::", 1)[-1] == requested:
        return True
    return False


def find_function_node(source: str, func_name: str, language: str):
    tree, source_bytes = parse_tree(source, language)
    if tree is None or source_bytes is None:
        return None, None, None
    for node in walk_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        declarator = node.child_by_field_name("declarator")
        if declarator is None:
            continue
        actual = function_name_from_declarator(declarator, source_bytes)
        candidate_names = _function_candidate_names(node, actual, source_bytes)
        if any(function_matches(name, func_name) for name in candidate_names):
            return node, tree, source_bytes
    return None, tree, source_bytes


def _function_candidate_names(node, actual: str, source_bytes: bytes) -> List[str]:
    actual = _clean_qualified_name(actual)
    names = [actual] if actual else []
    if actual and "::" not in actual:
        scopes = _enclosing_cpp_scopes(node, source_bytes)
        if scopes:
            names.append("::".join([*scopes, actual]))
    return dedup_keep_order(names)


def _enclosing_cpp_scopes(node, source_bytes: bytes) -> List[str]:
    scopes = []
    cur = getattr(node, "parent", None)
    while cur is not None:
        if cur.type in ("class_specifier", "struct_specifier", "union_specifier"):
            name_node = cur.child_by_field_name("name")
            if name_node is not None:
                name = _clean_function_name(node_text(name_node, source_bytes))
                if name:
                    scopes.append(name)
        elif cur.type == "namespace_definition":
            name_node = cur.child_by_field_name("name")
            if name_node is not None:
                name = _clean_function_name(node_text(name_node, source_bytes))
                if name:
                    scopes.append(name)
        cur = getattr(cur, "parent", None)
    return list(reversed(scopes))


def source_slice_by_byte_range(source: str, start_byte: int, end_byte: int) -> str:
    start_char, end_char = source_byte_range_to_char_range(source, start_byte, end_byte)
    if start_char < 0 or end_char < start_char:
        return ""
    return source[start_char:end_char]


def line_number_for_byte(source: str, byte_index: int) -> int:
    char_index, _ = source_byte_range_to_char_range(source, byte_index, byte_index)
    if char_index < 0:
        return -1
    return source[:char_index].count("\n") + 1


def include_records_from_source(source: str, language: str, origin: str) -> List[dict]:
    records = []
    tree, source_bytes = parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        for node in walk_nodes(tree.root_node):
            if node.type != "preproc_include":
                continue
            raw = node_text(node, source_bytes).strip()
            name = ""
            kind = ""
            for child in node.children:
                if child.type == "system_lib_string":
                    name = node_text(child, source_bytes).strip()[1:-1]
                    kind = "system"
                    break
                if child.type == "string_literal":
                    name = node_text(child, source_bytes).strip().strip('"')
                    kind = "project"
                    break
            if name:
                records.append({"kind": kind, "name": name, "raw": raw, "origin": origin})
    if records:
        return records

    include_re = re.compile(r'^\s*#\s*include\s*([<"])([^>"]+)[>"]', re.MULTILINE)
    for match in include_re.finditer(source):
        opener, name = match.group(1), match.group(2).strip()
        records.append(
            {
                "kind": "system" if opener == "<" else "project",
                "name": name,
                "raw": match.group(0).strip(),
                "origin": origin,
            }
        )
    return records


def extract_symbols_from_code(source: str, language: str) -> dict:
    calls = []
    types = []
    fields = []
    identifiers = []
    tree, source_bytes = parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        for node in walk_nodes(tree.root_node):
            if node.type == "call_expression":
                function_node = node.child_by_field_name("function")
                if function_node is not None:
                    calls.append(call_name_from_node(function_node, source_bytes))
            elif node.type in ("type_identifier", "primitive_type", "sized_type_specifier"):
                types.append(node_text(node, source_bytes).strip())
            elif node.type == "field_identifier":
                fields.append(node_text(node, source_bytes).strip())
            elif node.type == "identifier":
                identifiers.append(node_text(node, source_bytes).strip())
    else:
        calls.extend(re.findall(r'\b([A-Za-z_]\w*)\s*\(', source))
        identifiers.extend(re.findall(r'\b[A-Za-z_]\w*\b', source))

    keywords = {
        "if",
        "for",
        "while",
        "switch",
        "return",
        "sizeof",
        "case",
        "break",
        "continue",
        "goto",
    }
    macro_like = re.findall(r'\b[A-Z_][A-Z0-9_]{2,}\b', source)
    return {
        "calls": [x for x in dedup_keep_order(calls) if x and x not in keywords],
        "types": [x for x in dedup_keep_order(types) if x],
        "fields": [x for x in dedup_keep_order(fields) if x],
        "identifiers": [x for x in dedup_keep_order(identifiers) if x and x not in keywords],
        "macro_like": dedup_keep_order(macro_like),
    }


def contains_symbol(text: str, symbols: set) -> bool:
    if not symbols:
        return False
    for symbol in symbols:
        if re.search(r'\b' + re.escape(symbol) + r'\b', text):
            return True
    return False


def iter_candidate_project_files(root: str, source_path: str, limit: int):
    source_dir = os.path.dirname(source_path)
    yielded = set()
    for cur_root in (source_dir, root):
        if not cur_root or not os.path.isdir(cur_root):
            continue
        for dirpath, dirs, files in os.walk(cur_root):
            dirs[:] = [
                d for d in dirs
                if d not in {".git", "build", "cmake-build-debug"} and not d.startswith("build_meta_")
            ]
            for filename in files:
                path = os.path.join(dirpath, filename)
                if path in yielded or path == source_path or not is_source_like(path):
                    continue
                yielded.add(path)
                yield path
                if len(yielded) >= limit:
                    return


def _clean_function_name(value: str) -> str:
    text = str(value or "").strip()
    text = text.split("<", 1)[0].strip()
    return text.split("::")[-1].strip()


def _clean_qualified_name(value: str) -> str:
    parts = []
    for part in str(value or "").strip().split("::"):
        part = part.strip()
        if not part:
            continue
        parts.append(part.split("<", 1)[0].strip())
    return "::".join(parts)
