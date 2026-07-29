"""Policy-free source parsing helpers used by shared analysis providers."""

from __future__ import annotations

import re
import os
from typing import Any, List

from core.utils import (
    Language,
    Parser,
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
    return text[:max_chars].rstrip() + (
        f"\n... [truncated {len(text) - max_chars} chars]"
    )


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
    return (
        "cpp"
        if ext in (
            ".cc",
            ".cpp",
            ".cxx",
            ".hh",
            ".hpp",
            ".hxx",
            ".h",
        )
        else "c"
    )


def tree_sitter_language(language: str):
    key = (language or "c").strip().lower()
    module = (
        tree_sitter_cpp
        if key in ("cpp", "c++", "cc", "cxx")
        else tree_sitter_c
    )
    if module is None or Language is None:
        return None
    try:
        return Language(module.language())
    except Exception:
        try:
            return module.language()
        except Exception:
            return None


def parser_diagnostics(language: str) -> dict:
    key = (language or "c").strip().lower()
    wants_cpp = key in ("cpp", "c++", "cc", "cxx")
    module = tree_sitter_cpp if wants_cpp else tree_sitter_c
    grammar = "tree_sitter_cpp" if wants_cpp else "tree_sitter_c"
    available = (
        Parser is not None
        and Language is not None
        and module is not None
    )
    lang = tree_sitter_language(language) if available else None
    return {
        "parser_package_available": (
            Parser is not None and Language is not None
        ),
        "grammar": grammar,
        "grammar_available": module is not None,
        "language_object_available": lang is not None,
        "ast_preferred": True,
        "fallback_policy": (
            "No parser fallback; callers must report tree-sitter "
            "resolution failures."
        ),
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


def walk_nodes(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8",
        errors="replace",
    )


def call_name_from_node(function_node, source_bytes: bytes) -> str:
    text = node_text(function_node, source_bytes).strip()
    if not text:
        return ""
    text = text.split("::")[-1].split("<", 1)[0].strip()
    if "->" in text:
        text = text.rsplit("->", 1)[-1].strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1].strip()
        text = text.rsplit(".", 1)[-1].strip()
    return text


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
                    calls.append(
                        call_name_from_node(function_node, source_bytes)
                    )
            elif node.type in (
                "type_identifier",
                "primitive_type",
                "sized_type_specifier",
            ):
                types.append(node_text(node, source_bytes).strip())
            elif node.type == "field_identifier":
                fields.append(node_text(node, source_bytes).strip())
            elif node.type == "identifier":
                identifiers.append(node_text(node, source_bytes).strip())
    else:
        calls.extend(re.findall(r"\b([A-Za-z_]\w*)\s*\(", source))
        identifiers.extend(re.findall(r"\b[A-Za-z_]\w*\b", source))

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
    macro_like = re.findall(r"\b[A-Z_][A-Z0-9_]{2,}\b", source)
    return {
        "calls": [
            value
            for value in dedup_keep_order(calls)
            if value and value not in keywords
        ],
        "types": [
            value for value in dedup_keep_order(types) if value
        ],
        "fields": [
            value for value in dedup_keep_order(fields) if value
        ],
        "identifiers": [
            value
            for value in dedup_keep_order(identifiers)
            if value and value not in keywords
        ],
        "macro_like": dedup_keep_order(macro_like),
    }
