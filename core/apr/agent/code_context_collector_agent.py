import os
import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_code_context_collector_artifact
from core.apr.config import APR_MAX_LOCAL_HEADER_CONTEXT_CHARS, APR_MAX_SOURCE_CHARS
from core.utils import (
    Language,
    Parser,
    source_byte_range_to_char_range,
    tree_sitter_c,
    tree_sitter_cpp,
)


MAX_RECURSIVE_HEADER_DEPTH = 2
MAX_PROJECT_HEADERS = 16
MAX_HEADER_SURFACE_ITEMS = 24
MAX_SOURCE_SURFACE_ITEMS = 40
MAX_USAGE_EXAMPLES = 8
MAX_USAGE_SEARCH_FILES = 80
MAX_DECLARATION_CHARS = 1600
MAX_USAGE_CHARS = 1400
MAX_REPAIR_EVIDENCE_CHARS = 30000


# =============================================================================
# Nhóm 1: Helper chung cho collector
# =============================================================================


def _clip_text(value: Any, max_chars: int) -> str:
    text = "" if value is None else str(value).rstrip()
    if len(text) <= max_chars:
        return text
    return text[:max_chars].rstrip() + f"\n... [truncated {len(text) - max_chars} chars]"


def _dedup_keep_order(values: List[str]) -> List[str]:
    out = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        out.append(text)
        seen.add(text)
    return out


def _source_language_from_path(path: str) -> str:
    ext = os.path.splitext(path or "")[1].lower()
    return "cpp" if ext in (".cc", ".cpp", ".cxx", ".hh", ".hpp", ".hxx", ".h") else "c"


def _nearest_git_root(path: str) -> str:
    cur = path if os.path.isdir(path) else os.path.dirname(path)
    while cur and cur != os.path.dirname(cur):
        if os.path.isdir(os.path.join(cur, ".git")):
            return cur
        cur = os.path.dirname(cur)
    return ""


def _source_root(source_path: str, context_root: Optional[str]) -> str:
    if context_root and os.path.isdir(context_root):
        return os.path.normpath(context_root)
    return _nearest_git_root(source_path) or os.path.normpath(os.path.dirname(source_path))


def _relpath(path: str, root: str) -> str:
    try:
        rel = os.path.relpath(path, root).replace(os.sep, "/")
    except ValueError:
        return path
    return rel if not rel.startswith("../") else path


def _is_source_like(path: str) -> bool:
    return os.path.splitext(path or "")[1].lower() in {
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


# =============================================================================
# Nhóm 2: Tree-sitter wrapper
# =============================================================================


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


def _parse_tree(source: str, language: str):
    if Parser is None:
        return None, None
    lang = _tree_sitter_language(language)
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


def _walk_nodes(root):
    stack = [root]
    while stack:
        node = stack.pop()
        yield node
        stack.extend(reversed(node.children))


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")


def _function_name_from_declarator(declarator, source_bytes: bytes) -> str:
    nested = declarator.child_by_field_name("declarator")
    if nested is not None:
        name = _function_name_from_declarator(nested, source_bytes)
        if name:
            return name

    for field in ("name", "field", "operator"):
        try:
            child = declarator.child_by_field_name(field)
        except Exception:
            child = None
        if child is not None:
            text = _node_text(child, source_bytes)
            return text.split("::")[-1].split("<", 1)[0].strip()

    if declarator.type in (
        "identifier",
        "field_identifier",
        "destructor_name",
        "operator_name",
    ):
        return _node_text(declarator, source_bytes).strip()

    if declarator.type in ("qualified_identifier", "template_function"):
        return _node_text(declarator, source_bytes).split("::")[-1].split("<", 1)[0].strip()

    for child in declarator.children:
        name = _function_name_from_declarator(child, source_bytes)
        if name:
            return name
    return ""


def _call_name_from_node(function_node, source_bytes: bytes) -> str:
    text = _node_text(function_node, source_bytes).strip()
    if not text:
        return ""
    text = text.split("::")[-1].split("<", 1)[0].strip()
    if "->" in text:
        text = text.rsplit("->", 1)[-1].strip()
    if "." in text:
        text = text.rsplit(".", 1)[-1].strip()
    return text


# =============================================================================
# Nhóm 3: Include inventory và recursive project headers
# =============================================================================


def _include_records_from_source(source: str, language: str, origin: str) -> List[dict]:
    records = []
    tree, source_bytes = _parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        for node in _walk_nodes(tree.root_node):
            if node.type != "preproc_include":
                continue
            raw = _node_text(node, source_bytes).strip()
            name = ""
            kind = ""
            for child in node.children:
                if child.type == "system_lib_string":
                    name = _node_text(child, source_bytes).strip()[1:-1]
                    kind = "system"
                    break
                if child.type == "string_literal":
                    name = _node_text(child, source_bytes).strip().strip('"')
                    kind = "project"
                    break
            if name:
                records.append({"kind": kind, "name": name, "raw": raw, "origin": origin})
    if records:
        return records

    # Fallback duy nhất cho include: preprocessor directive dễ nhận diện bằng regex
    # và tree-sitter có thể fail với source bị macro/preprocessor làm vỡ parse.
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


def _resolve_project_include(
    include_name: str,
    including_dir: str,
    source_root: str,
) -> str:
    candidates = [os.path.normpath(os.path.join(including_dir, include_name))]
    root_candidate = os.path.normpath(os.path.join(source_root, include_name))
    if root_candidate not in candidates:
        candidates.append(root_candidate)

    for candidate in candidates:
        try:
            inside_root = os.path.commonpath([source_root, candidate]) == source_root
        except ValueError:
            inside_root = False
        if inside_root and os.path.isfile(candidate):
            return candidate

    # Một số project include bằng path rút gọn. Chỉ fallback theo basename trong
    # source tree và chỉ nhận khi tìm được duy nhất một file.
    basename = os.path.basename(include_name)
    matches = []
    for root, dirs, files in os.walk(source_root):
        dirs[:] = [d for d in dirs if d not in {".git", "build", "cmake-build-debug"}]
        if basename in files:
            matches.append(os.path.join(root, basename))
            if len(matches) > 1:
                break
    return matches[0] if len(matches) == 1 else ""


def _collect_project_headers(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
) -> Tuple[List[dict], List[dict], List[str]]:
    queue = []
    unresolved = []
    seen_paths = set()
    headers = []

    source_origin = _relpath(source_path, source_root)
    for record in _include_records_from_source(source_code, language, source_origin):
        if record["kind"] != "project":
            continue
        queue.append((record["name"], os.path.dirname(source_path), 0, source_origin))

    while queue and len(headers) < MAX_PROJECT_HEADERS:
        include_name, including_dir, depth, included_from = queue.pop(0)
        header_path = _resolve_project_include(include_name, including_dir, source_root)
        if not header_path:
            unresolved.append(include_name)
            continue
        if header_path in seen_paths:
            continue
        seen_paths.add(header_path)

        try:
            with open(header_path, "r", errors="replace") as f:
                header_text = f.read()
        except OSError:
            unresolved.append(include_name)
            continue

        rel = _relpath(header_path, source_root)
        header_language = _source_language_from_path(header_path)
        headers.append(
            {
                "include": include_name,
                "path": header_path,
                "relpath": rel,
                "depth": depth,
                "included_from": included_from,
                "text": header_text,
                "language": header_language,
            }
        )

        if depth >= MAX_RECURSIVE_HEADER_DEPTH:
            continue
        for record in _include_records_from_source(header_text, header_language, rel):
            if record["kind"] == "project":
                queue.append((record["name"], os.path.dirname(header_path), depth + 1, rel))

    return headers, unresolved, [h["relpath"] for h in headers]


def _build_include_inventory(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
    headers: List[dict],
    unresolved: List[str],
) -> dict:
    system = []
    project = []

    source_origin = _relpath(source_path, source_root)
    for record in _include_records_from_source(source_code, language, source_origin):
        if record["kind"] == "system":
            system.append(record["name"])
        elif record["kind"] == "project":
            project.append(record["name"])

    for header in headers:
        for record in _include_records_from_source(
            header["text"],
            header["language"],
            header["relpath"],
        ):
            if record["kind"] == "system":
                system.append(record["name"])
            elif record["kind"] == "project":
                project.append(record["name"])

    return {
        "system_includes": _dedup_keep_order(system),
        "project_includes": _dedup_keep_order(project),
        "resolved_project_headers": _dedup_keep_order([h["relpath"] for h in headers]),
        "unresolved_project_includes": _dedup_keep_order(unresolved),
    }


# =============================================================================
# Nhóm 4: Symbol extraction bằng tree-sitter
# =============================================================================


def _extract_symbols_from_code(source: str, language: str) -> dict:
    calls = []
    types = []
    fields = []
    identifiers = []

    tree, source_bytes = _parse_tree(source, language)
    if tree is not None and source_bytes is not None:
        for node in _walk_nodes(tree.root_node):
            if node.type == "call_expression":
                function_node = node.child_by_field_name("function")
                if function_node is not None:
                    calls.append(_call_name_from_node(function_node, source_bytes))
            elif node.type in ("type_identifier", "primitive_type", "sized_type_specifier"):
                types.append(_node_text(node, source_bytes).strip())
            elif node.type == "field_identifier":
                fields.append(_node_text(node, source_bytes).strip())
            elif node.type == "identifier":
                identifiers.append(_node_text(node, source_bytes).strip())
    else:
        # Fallback tối thiểu để collector vẫn có tín hiệu khi tree-sitter không có.
        calls.extend(re.findall(r'\b([A-Za-z_]\w*)\s*\(', source))
        identifiers.extend(re.findall(r'\b[A-Za-z_]\w*\b', source))

    macro_like = re.findall(r'\b[A-Z_][A-Z0-9_]{2,}\b', source)
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
    return {
        "calls": [x for x in _dedup_keep_order(calls) if x and x not in keywords],
        "types": [x for x in _dedup_keep_order(types) if x],
        "fields": [x for x in _dedup_keep_order(fields) if x],
        "identifiers": [x for x in _dedup_keep_order(identifiers) if x and x not in keywords],
        "macro_like": _dedup_keep_order(macro_like),
    }


def _symbol_set(symbols: dict) -> set:
    out = set()
    for key in ("calls", "types", "fields", "identifiers", "macro_like"):
        out.update(symbols.get(key) or [])
    return {str(item) for item in out if item}


def _contains_relevant_symbol(text: str, symbols: set) -> bool:
    if not symbols:
        return False
    for symbol in symbols:
        if re.search(r'\b' + re.escape(symbol) + r'\b', text):
            return True
    return False


# =============================================================================
# Nhóm 5: Declaration/API surface từ source và project headers
# =============================================================================


def _surface_items_from_source(
    *,
    source: str,
    language: str,
    source_label: str,
    symbols: set,
    target_start: int = -1,
    target_end: int = -1,
    max_items: int,
) -> List[dict]:
    items = []
    seen = set()
    tree, source_bytes = _parse_tree(source, language)

    interesting_types = {
        "declaration",
        "type_definition",
        "struct_specifier",
        "enum_specifier",
        "preproc_def",
        "preproc_function_def",
        "function_declaration",
        "function_definition",
    }

    if tree is not None and source_bytes is not None:
        for node in _walk_nodes(tree.root_node):
            if node.type not in interesting_types:
                continue
            if target_start >= 0 and node.start_byte >= target_start and node.end_byte <= target_end:
                continue
            text = _node_text(node, source_bytes).strip()
            if not _contains_relevant_symbol(text, symbols):
                continue

            label = node.type
            if node.type == "function_definition":
                declarator = node.child_by_field_name("declarator")
                name = _function_name_from_declarator(declarator, source_bytes) if declarator else ""
                if name and name not in symbols:
                    continue
                label = f"function_definition:{name or '<unknown>'}"
            key = (source_label, label, text[:200])
            if key in seen:
                continue
            seen.add(key)
            items.append(
                {
                    "source": source_label,
                    "kind": label,
                    "text": _clip_text(text, MAX_DECLARATION_CHARS),
                }
            )
            if len(items) >= max_items:
                return items
        return items

    # Fallback theo line cho macro/prototype khi tree-sitter không parse được.
    declaration_re = re.compile(
        r'^\s*(?:#\s*define\b.*|typedef\b.*|(?:struct|enum)\b.*|[A-Za-z_][\w\s\*]*\b[A-Za-z_]\w*\s*\([^;{}]*\)\s*;)',
        re.MULTILINE,
    )
    for match in declaration_re.finditer(source):
        text = match.group(0).strip()
        if not _contains_relevant_symbol(text, symbols):
            continue
        key = (source_label, text)
        if key in seen:
            continue
        seen.add(key)
        items.append({"source": source_label, "kind": "regex_declaration", "text": text})
        if len(items) >= max_items:
            break
    return items


def _build_project_header_api_context(headers: List[dict], symbols: set) -> List[dict]:
    out = []
    total_chars = 0
    for header in headers:
        if total_chars >= APR_MAX_LOCAL_HEADER_CONTEXT_CHARS:
            out.append({"note": "project header API context truncated"})
            break

        surface = _surface_items_from_source(
            source=header["text"],
            language=header["language"],
            source_label=header["relpath"],
            symbols=symbols,
            max_items=MAX_HEADER_SURFACE_ITEMS,
        )
        payload = {
            "header": header["relpath"],
            "include": header["include"],
            "depth": header["depth"],
            "included_from": header["included_from"],
            "api_surface": [],
        }

        for item in surface:
            item_size = len(str(item))
            if total_chars + len(str(payload)) + item_size > APR_MAX_LOCAL_HEADER_CONTEXT_CHARS:
                payload["api_surface_truncated"] = True
                break
            payload["api_surface"].append(item)

        if surface and not payload["api_surface"]:
            payload["note"] = "matching header declarations omitted because context budget is exhausted"
        elif not payload["api_surface"]:
            excerpt = _clip_text(header["text"], 1200)
            if total_chars + len(str(payload)) + len(excerpt) <= APR_MAX_LOCAL_HEADER_CONTEXT_CHARS:
                payload["excerpt_when_no_symbol_match"] = excerpt
            else:
                payload["note"] = "header omitted because context budget is exhausted"

        total_chars += len(str(payload))
        out.append(payload)
    return out


# =============================================================================
# Nhóm 6: Usage examples cho API/helper lạ
# =============================================================================


def _snippet_from_function_for_calls(function_text: str, call_names: set) -> str:
    lines = function_text.splitlines()
    selected = []
    for idx, line in enumerate(lines):
        if any(re.search(r'\b' + re.escape(name) + r'\s*\(', line) for name in call_names):
            start = max(0, idx - 2)
            end = min(len(lines), idx + 3)
            if selected and selected[-1] != "...":
                selected.append("...")
            selected.extend(lines[start:end])
    if not selected:
        return _clip_text(function_text, MAX_USAGE_CHARS)
    return _clip_text("\n".join(selected), MAX_USAGE_CHARS)


def _usage_examples_from_source(
    *,
    source: str,
    source_path: str,
    source_root: str,
    language: str,
    call_names: set,
    target_start: int = -1,
    target_end: int = -1,
    limit: int,
) -> List[dict]:
    examples = []
    tree, source_bytes = _parse_tree(source, language)
    if tree is None or source_bytes is None:
        return examples

    for node in _walk_nodes(tree.root_node):
        if node.type != "function_definition":
            continue
        if target_start >= 0 and node.start_byte >= target_start and node.end_byte <= target_end:
            continue
        text = _node_text(node, source_bytes)
        declarator = node.child_by_field_name("declarator")
        function_name = _function_name_from_declarator(declarator, source_bytes) if declarator else ""
        used_calls = sorted(
            name
            for name in call_names
            if name != function_name and re.search(r'\b' + re.escape(name) + r'\s*\(', text)
        )
        if not used_calls:
            continue
        examples.append(
            {
                "source": _relpath(source_path, source_root),
                "function": function_name or "<unknown>",
                "calls": used_calls,
                "snippet": _snippet_from_function_for_calls(text, set(used_calls)),
            }
        )
        if len(examples) >= limit:
            break
    return examples


def _iter_candidate_project_files(source_root: str, source_path: str):
    source_dir = os.path.dirname(source_path)
    yielded = set()

    for root in (source_dir, source_root):
        if not root or not os.path.isdir(root):
            continue
        for dirpath, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d not in {".git", "build", "cmake-build-debug"}]
            for filename in files:
                path = os.path.join(dirpath, filename)
                if path in yielded or path == source_path or not _is_source_like(path):
                    continue
                yielded.add(path)
                yield path
            if len(yielded) >= MAX_USAGE_SEARCH_FILES:
                return


def _build_usage_examples(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
    symbols: dict,
    start_idx: int,
    end_idx: int,
) -> List[dict]:
    call_names = set(symbols.get("calls") or [])
    if not call_names:
        return []

    examples = _usage_examples_from_source(
        source=source_code,
        source_path=source_path,
        source_root=source_root,
        language=language,
        call_names=call_names,
        target_start=start_idx,
        target_end=end_idx,
        limit=MAX_USAGE_EXAMPLES,
    )
    if len(examples) >= MAX_USAGE_EXAMPLES:
        return examples

    for path in _iter_candidate_project_files(source_root, source_path):
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if not any(name in text for name in call_names):
            continue
        examples.extend(
            _usage_examples_from_source(
                source=text,
                source_path=path,
                source_root=source_root,
                language=_source_language_from_path(path),
                call_names=call_names,
                limit=MAX_USAGE_EXAMPLES - len(examples),
            )
        )
        if len(examples) >= MAX_USAGE_EXAMPLES:
            break
    return examples[:MAX_USAGE_EXAMPLES]


def _build_target_references(
    *,
    source_code: str,
    source_path: str,
    source_root: str,
    language: str,
    func_name: str,
    start_idx: int,
    end_idx: int,
) -> List[dict]:
    if not func_name:
        return []

    references = _usage_examples_from_source(
        source=source_code,
        source_path=source_path,
        source_root=source_root,
        language=language,
        call_names={func_name},
        target_start=start_idx,
        target_end=end_idx,
        limit=MAX_USAGE_EXAMPLES,
    )
    if len(references) >= MAX_USAGE_EXAMPLES:
        return references

    for path in _iter_candidate_project_files(source_root, source_path):
        try:
            with open(path, "r", errors="replace") as f:
                text = f.read()
        except OSError:
            continue
        if func_name not in text:
            continue
        references.extend(
            _usage_examples_from_source(
                source=text,
                source_path=path,
                source_root=source_root,
                language=_source_language_from_path(path),
                call_names={func_name},
                limit=MAX_USAGE_EXAMPLES - len(references),
            )
        )
        if len(references) >= MAX_USAGE_EXAMPLES:
            break
    return references[:MAX_USAGE_EXAMPLES]


# =============================================================================
# Nhóm 7: Source slice và entry point collector
# =============================================================================


def trim_source_for_retrieval_prompt(source_code: str, start_idx: int, end_idx: int) -> str:
    start_char, end_char = source_byte_range_to_char_range(source_code, start_idx, end_idx)
    if len(source_code) <= APR_MAX_SOURCE_CHARS or start_char < 0 or end_char < 0:
        return source_code

    head_budget = min(6000, APR_MAX_SOURCE_CHARS // 4)
    remaining = APR_MAX_SOURCE_CHARS - head_budget
    neighborhood = max(2000, remaining // 2)

    head = source_code[:head_budget]
    func_lo = max(head_budget, start_char - neighborhood)
    func_hi = min(len(source_code), end_char + neighborhood)
    middle_skipped = func_lo > head_budget
    tail_skipped = func_hi < len(source_code)

    parts = [head]
    if middle_skipped:
        parts.append("\n\n/* ... [source truncated - prelude shown above] ... */\n\n")
    parts.append(source_code[func_lo:func_hi])
    if tail_skipped:
        parts.append("\n\n/* ... [source truncated - tail omitted] ... */\n")
    return "".join(parts)


def _pack_size(pack: dict) -> int:
    return len(str(pack))


def _build_repair_evidence_pack(
    *,
    target_function: dict,
    source_context: str,
    include_inventory: dict,
    source_api_surface: List[dict],
    project_header_api_context: List[dict],
    usage_examples: List[dict],
    target_references: List[dict],
    uncertainties: List[str],
) -> dict:
    same_file_helpers = [
        item for item in source_api_surface
        if str(item.get("kind") or "").startswith("function_definition:")
    ]
    same_file_declarations = [
        item for item in source_api_surface
        if not str(item.get("kind") or "").startswith("function_definition:")
    ]

    pack = {
        "purpose": (
            "Raw code evidence for FixAgent. Treat this as source-of-truth for "
            "available APIs, helper signatures, macros, types, usage idioms, and caller contracts."
        ),
        "target_function": target_function,
        "include_inventory": include_inventory,
        "source_excerpt": source_context,
        "same_file_helper_definitions": same_file_helpers,
        "same_file_relevant_declarations": same_file_declarations,
        "project_header_declarations": project_header_api_context,
        "cross_file_usage_examples": usage_examples,
        "target_references": target_references,
        "uncertainties": uncertainties,
    }

    if _pack_size(pack) <= MAX_REPAIR_EVIDENCE_CHARS:
        return pack

    pack["source_excerpt"] = _clip_text(source_context, 9000)
    pack["cross_file_usage_examples"] = usage_examples[:6]
    pack["target_references"] = target_references[:6]
    if _pack_size(pack) <= MAX_REPAIR_EVIDENCE_CHARS:
        return pack

    compact_headers = []
    for header in project_header_api_context:
        compact = dict(header)
        if isinstance(compact.get("api_surface"), list):
            compact["api_surface"] = compact["api_surface"][:8]
            compact["api_surface_truncated_for_fix_prompt"] = True
        compact_headers.append(compact)
    pack["project_header_declarations"] = compact_headers
    pack["source_excerpt"] = _clip_text(source_context, 5000)
    pack["cross_file_usage_examples"] = usage_examples[:4]
    pack["target_references"] = target_references[:4]
    if _pack_size(pack) <= MAX_REPAIR_EVIDENCE_CHARS:
        return pack

    pack["source_excerpt"] = _clip_text(source_context, 2500)
    pack["same_file_relevant_declarations"] = same_file_declarations[:16]
    pack["same_file_helper_definitions"] = same_file_helpers[:8]
    pack["project_header_declarations"] = compact_headers[:8]
    pack["cross_file_usage_examples"] = usage_examples[:3]
    pack["target_references"] = target_references[:3]
    pack["truncated"] = True
    return pack


def collect_code_context(
    *,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    context_root: Optional[str] = None,
) -> Dict[str, Any]:
    language = _source_language_from_path(source_path)
    root = _source_root(source_path, context_root)
    source_label = _relpath(source_path, root)

    prompt_source = trim_source_for_retrieval_prompt(source_code, start_idx, end_idx)
    symbols = _extract_symbols_from_code(func_code, language)
    symbol_set = _symbol_set(symbols)
    headers, unresolved_headers, _ = _collect_project_headers(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
    )
    include_inventory = _build_include_inventory(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        headers=headers,
        unresolved=unresolved_headers,
    )
    source_api_surface = _surface_items_from_source(
        source=source_code,
        language=language,
        source_label=source_label,
        symbols=symbol_set,
        target_start=start_idx,
        target_end=end_idx,
        max_items=MAX_SOURCE_SURFACE_ITEMS,
    )
    project_header_api_context = _build_project_header_api_context(headers, symbol_set)
    usage_examples = _build_usage_examples(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        symbols=symbols,
        start_idx=start_idx,
        end_idx=end_idx,
    )
    target_references = _build_target_references(
        source_code=source_code,
        source_path=source_path,
        source_root=root,
        language=language,
        func_name=func_name,
        start_idx=start_idx,
        end_idx=end_idx,
    )

    uncertainties = []
    if Parser is None or _tree_sitter_language(language) is None:
        uncertainties.append("tree-sitter is unavailable; symbol extraction used regex fallback")
    if include_inventory["unresolved_project_includes"]:
        uncertainties.append(
            "some project includes could not be resolved: "
            + ", ".join(include_inventory["unresolved_project_includes"])
        )
    if len(headers) >= MAX_PROJECT_HEADERS:
        uncertainties.append(f"project header traversal stopped at {MAX_PROJECT_HEADERS} headers")

    target_function = {
        "name": func_name,
        "source_file": cand_label,
        "source_path": source_label,
        "language": language,
        "start_byte": start_idx,
        "end_byte": end_idx,
    }
    repair_evidence_pack = _build_repair_evidence_pack(
        target_function=target_function,
        source_context=prompt_source,
        include_inventory=include_inventory,
        source_api_surface=source_api_surface,
        project_header_api_context=project_header_api_context,
        usage_examples=usage_examples,
        target_references=target_references,
        uncertainties=uncertainties,
    )

    return {
        "target_function": target_function,
        "source_context": prompt_source,
        "include_inventory": include_inventory,
        "target_symbols": symbols,
        "source_api_surface": source_api_surface,
        "project_header_api_context": project_header_api_context,
        "usage_examples": usage_examples,
        "target_references": target_references,
        "repair_evidence_pack": repair_evidence_pack,
        "uncertainties": uncertainties,
    }


def run_code_context_collector_agent(
    *,
    bug_id: str,
    attempt_index: int,
    qualified_name: str,
    candidate_relpath: str,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    context_root: Optional[str] = None,
) -> Tuple[dict, dict]:
    collector_context = collect_code_context(
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        source_code=source_code,
        source_path=source_path,
        start_idx=start_idx,
        end_idx=end_idx,
        context_root=context_root,
    )
    repair_evidence_pack = collector_context.get("repair_evidence_pack") or {}
    artifact = write_code_context_collector_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        collector_context=collector_context,
        repair_evidence_pack=repair_evidence_pack,
    )
    return collector_context, artifact
