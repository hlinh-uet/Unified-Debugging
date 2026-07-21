"""Compiler-backed semantic enrichment for Tree-sitter source locations."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import subprocess
from functools import lru_cache
from pathlib import Path
from typing import Any, Dict, Iterable, List, Tuple

from .models import clip, stable_id


AST_TIMEOUT_SECONDS = 45
AST_OUTPUT_LIMIT = 20_000_000
SEMANTIC_RETRIEVAL_RELATIONS = {
    "CALLEE_CONTRACT", "CALL_RESULT_CONTRACT", "OVERLOAD_SET",
    "TYPE_DEFINITION", "ENUM_OR_SENTINEL_VALUES", "TEMPLATE_SPECIALIZATION",
    "CONVERSION_OPERATORS",
}


def resolve_target_semantics(
    *, source_root: str, target_contract: Dict[str, Any], syntax_ir: Dict[str, Any],
    compilation_context: Dict[str, Any] = None,
) -> Dict[str, Any]:
    """Resolve types and direct calls through Clang, never textual heuristics."""
    raw_source_path = str(target_contract.get("source_path") or "").strip()
    if not raw_source_path:
        return _unavailable("clang_target_source_path_missing")
    target_leaf = str(
        target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
    ).rsplit("::", 1)[-1]
    if not target_leaf:
        return _unavailable("clang_target_symbol_missing")
    source_path = os.path.realpath(raw_source_path)
    context_database = str((compilation_context or {}).get("database_path") or "")
    compile_db = (
        os.path.realpath(context_database) if context_database and os.path.isfile(context_database)
        else find_compilation_database(source_root, source_path)
    )
    if not compile_db:
        return _unavailable("clang_compilation_database_missing")
    command, command_status = _compile_command_for_source(
        compile_db, source_path=source_path, language=str(target_contract.get("language") or "c")
    )
    if not command:
        return {
            **_unavailable("clang_compile_command_missing_for_target"),
            "compile_database": compile_db,
            "command_status": command_status,
        }
    ast, diagnostics, invocation = _dump_target_ast(
        command,
        target_contract=target_contract,
        source_path=source_path,
    )
    if not ast:
        return {
            **_unavailable("clang_target_ast_unavailable"),
            "compile_database": compile_db,
            "command_status": command_status,
            "invocation": invocation,
            "diagnostics": ["clang_target_ast_unavailable", *diagnostics],
        }
    calls = _resolve_calls(ast, syntax_ir.get("records") or [])
    variables = _resolve_variables(ast, syntax_ir.get("records") or [])
    return {
        "version": 1,
        "provider": "clang_ast",
        "available": True,
        "compile_database": compile_db,
        "command_status": command_status,
        "invocation": invocation,
        "calls": calls,
        "variables": variables,
        "diagnostics": diagnostics,
        "semantic_resolution": "compiler_frontend",
    }


def retrieve_semantic_evidence(
    *, source_root: str, target_contract: Dict[str, Any], syntax_ir: Dict[str, Any],
    semantic_context: Dict[str, Any], information_needs: Iterable[Dict[str, Any]],
    compilation_context: Dict[str, Any] = None, round_index: int = 2,
    max_queries: int = 3, max_regions: int = 5, max_total_chars: int = 2400,
    max_region_chars: int = 800,
) -> Tuple[List[Dict[str, Any]], Dict[str, Any], List[str]]:
    """Retrieve small compiler-anchored declarations; never scan by textual name."""
    needs = [
        item for item in information_needs
        if isinstance(item, dict)
        and str(item.get("relation") or "").upper() in SEMANTIC_RETRIEVAL_RELATIONS
    ]
    if not needs:
        return [], _retrieval_record("not_applicable", 0, 0, 0), []
    source_path = os.path.realpath(str(target_contract.get("source_path") or ""))
    context_database = str((compilation_context or {}).get("database_path") or "")
    compile_db = (
        os.path.realpath(context_database) if context_database and os.path.isfile(context_database)
        else find_compilation_database(source_root, source_path)
    )
    if not compile_db:
        return [], _retrieval_record("unavailable", 0, 0, 0), [
            "semantic_retrieval_compilation_database_missing"
        ]
    command, command_status = _compile_command_for_source(
        compile_db,
        source_path=source_path,
        language=str(target_contract.get("language") or "c"),
    )
    if not command:
        return [], _retrieval_record("unavailable", 0, 0, 0), [
            f"semantic_retrieval_compile_command_missing:{command_status}"
        ]

    anchors, diagnostics = _retrieval_anchors(
        needs=needs,
        semantic_context=semantic_context,
        syntax_ir=syntax_ir,
    )
    query_budget = max(0, min(int(max_queries or 0), 5))
    region_budget = max(0, min(int(max_regions or 0), 8))
    char_budget = max(0, min(int(max_total_chars or 0), 6000))
    region_chars = max(120, min(int(max_region_chars or 0), 1200))
    facts: List[Dict[str, Any]] = []
    queries = 0
    used_chars = 0
    queried = set()
    allowed_roots = list(dict.fromkeys([
        os.path.realpath(str(value))
        for value in [
            source_root,
            *((compilation_context or {}).get("allowed_source_roots") or []),
        ]
        if str(value) and os.path.isdir(str(value))
    ]))
    for anchor in anchors:
        if queries >= query_budget or len(facts) >= region_budget or used_chars >= char_budget:
            diagnostics.append("semantic_retrieval_budget_exhausted")
            break
        key = (anchor["kind"], anchor["name"], anchor.get("signature") or "")
        if key in queried:
            continue
        queried.add(key)
        roots, query_diagnostics = _dump_named_asts(
            command,
            target_contract=target_contract,
            source_path=source_path,
            symbol_filter=anchor["name"],
        )
        queries += 1
        diagnostics.extend(query_diagnostics)
        declarations = _matching_declarations(roots, anchor)
        if not declarations:
            diagnostics.append(f"semantic_retrieval_declaration_unresolved:{anchor['name']}")
            continue
        for declaration in declarations:
            remaining = char_budget - used_chars
            if len(facts) >= region_budget or remaining <= 0:
                diagnostics.append("semantic_retrieval_budget_exhausted")
                break
            fact = _declaration_fact(
                declaration,
                anchor=anchor,
                default_source_path=source_path,
                allowed_roots=allowed_roots,
                query_round=round_index,
                excerpt_limit=min(region_chars, remaining),
            )
            if not fact:
                diagnostics.append(f"semantic_retrieval_source_unmapped:{anchor['name']}")
                continue
            facts.append(fact)
            used_chars += len(str(fact.get("source_excerpt") or ""))
    status = "evidence_returned" if facts else "empty"
    return _unique_semantic_facts(facts), {
        **_retrieval_record(status, queries, len(facts), used_chars),
        "compile_database": compile_db,
        "command_status": command_status,
        "queried_need_ids": list(dict.fromkeys(
            str(item.get("need_id") or "") for item in anchors if item.get("need_id")
        )),
        "budget": {
            "max_queries": query_budget,
            "max_regions": region_budget,
            "max_total_chars": char_budget,
            "max_region_chars": region_chars,
        },
    }, list(dict.fromkeys(str(item) for item in diagnostics if str(item)))


def find_compilation_database(source_root: str, source_path: str) -> str:
    configured = os.getenv("APR_COMPILE_COMMANDS", "").strip()
    if configured:
        candidate = Path(configured)
        if candidate.is_dir():
            candidate = candidate / "compile_commands.json"
        if candidate.is_file():
            return str(candidate.resolve())
    roots = []
    for value in (source_root, os.path.dirname(source_path)):
        if value and os.path.isdir(value):
            resolved = os.path.realpath(value)
            if resolved not in roots:
                roots.append(resolved)
    for root in roots:
        direct = Path(root) / "compile_commands.json"
        if direct.is_file():
            return str(direct.resolve())
        for dirname in ("build", "build-debug", "build-release", "cmake-build-debug"):
            candidate = Path(root) / dirname / "compile_commands.json"
            if candidate.is_file():
                return str(candidate.resolve())
    current = Path(source_path).resolve().parent if source_path else None
    while current and current != current.parent:
        candidate = current / "compile_commands.json"
        if candidate.is_file():
            return str(candidate.resolve())
        current = current.parent
    return ""


@lru_cache(maxsize=32)
def _load_compilation_database(path: str, mtime_ns: int) -> Tuple[Dict[str, Any], ...]:
    del mtime_ns
    try:
        with open(path, "r", encoding="utf-8") as stream:
            payload = json.load(stream)
    except (OSError, UnicodeError, json.JSONDecodeError):
        return ()
    return tuple(item for item in payload if isinstance(item, dict)) if isinstance(payload, list) else ()


def _compile_command_for_source(
    compile_db: str, *, source_path: str, language: str
) -> Tuple[Dict[str, Any], str]:
    try:
        mtime_ns = int(os.stat(compile_db).st_mtime_ns)
    except OSError:
        return {}, "compilation_database_unreadable"
    entries = list(_load_compilation_database(compile_db, mtime_ns))
    exact = [item for item in entries if _entry_source_path(item) == source_path]
    if exact:
        return exact[0], "exact_translation_unit_command"
    if not entries:
        return {}, "compilation_database_empty"
    # Headers are not normally entries in compile_commands.json. Reuse only the
    # nearest TU flags and mark that inference explicitly; Clang still performs
    # all language/type/overload resolution under those flags.
    source_dir = os.path.dirname(source_path)
    ranked = sorted(entries, key=lambda item: _path_distance(
        source_dir, os.path.dirname(_entry_source_path(item))
    ))
    return ranked[0], "inferred_header_command"


def _dump_target_ast(
    entry: Dict[str, Any], *, target_contract: Dict[str, Any], source_path: str
) -> Tuple[Dict[str, Any], List[str], Dict[str, Any]]:
    language = str(target_contract.get("language") or "c").lower()
    compiler = _clang_binary(language)
    if not compiler:
        return {}, ["clang_binary_unavailable"], {}
    working_dir = os.path.realpath(str(entry.get("directory") or os.path.dirname(source_path)))
    original = _entry_arguments(entry)
    if not original:
        return {}, ["clang_compile_arguments_missing"], {}
    entry_source = _entry_source_path(entry)
    args = _sanitize_compile_arguments(
        _compile_flag_arguments(original),
        entry_source=entry_source,
        source_path=source_path,
        language=language,
        working_dir=working_dir,
    )
    target_leaf = str(
        target_contract.get("resolved_name") or target_contract.get("requested_name") or ""
    ).rsplit("::", 1)[-1]
    command = [
        compiler,
        *args,
        "-fsyntax-only",
        "-Xclang", "-ast-dump=json",
        "-Xclang", f"-ast-dump-filter={target_leaf}",
        source_path,
    ]
    invocation = {
        "compiler": compiler,
        "working_directory": working_dir,
        "argument_count": len(command),
        "target_filter": target_leaf,
    }
    try:
        completed = subprocess.run(
            command,
            cwd=working_dir if os.path.isdir(working_dir) else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=AST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {}, ["clang_target_ast_timeout"], invocation
    except OSError as exc:
        return {}, [f"clang_target_ast_exception:{type(exc).__name__}"], invocation
    stderr = clip(completed.stderr, 4000)
    diagnostics = [f"clang_diagnostic:{line}" for line in stderr.splitlines()[:12] if line.strip()]
    if completed.returncode != 0:
        return {}, ["clang_target_ast_failed", *diagnostics], invocation
    if len(completed.stdout.encode("utf-8")) > AST_OUTPUT_LIMIT:
        return {}, ["clang_target_ast_output_limit_exceeded"], invocation
    roots = _decode_json_stream(completed.stdout)
    target_range = target_contract.get("source_range") or {}
    ast = _select_target_ast(roots, target_range=target_range, target_leaf=target_leaf)
    return ast, diagnostics, invocation


def _resolve_calls(ast: Dict[str, Any], records: List[Dict[str, Any]]) -> Dict[str, Dict[str, Any]]:
    call_nodes = [
        node for node in _walk_json(ast)
        if node.get("kind") in {"CallExpr", "CXXMemberCallExpr", "CXXOperatorCallExpr"}
    ]
    out = {}
    for record in records:
        if record.get("kind") != "call" or not record.get("id"):
            continue
        source_range = record.get("source_range") or {}
        node = _closest_ast_node(call_nodes, int(source_range.get("start_byte") or -1))
        if not node:
            out[str(record["id"])] = {"status": "semantic_call_unresolved"}
            continue
        reference = _call_reference(node)
        if not reference:
            out[str(record["id"])] = {
                "status": "semantic_call_unresolved",
                "result_type": ((node.get("type") or {}).get("qualType") or ""),
            }
            continue
        signature = str((reference.get("type") or {}).get("qualType") or "")
        resolved_name = str(reference.get("name") or "")
        out[str(record["id"])] = {
            "status": "compiler_resolved",
            "compiler_decl_id": str(reference.get("id") or ""),
            "symbol_id": stable_id("clang_symbol", {
                "kind": reference.get("kind"),
                "name": resolved_name,
                "signature": signature,
            }),
            "resolved_name": resolved_name,
            "symbol_kind": reference.get("kind"),
            "signature": signature,
            "result_type": str((node.get("type") or {}).get("qualType") or ""),
            "definition": _decl_location(reference),
            "resolution": "clang_overload_resolution",
        }
    return out


def _resolve_variables(
    ast: Dict[str, Any], records: List[Dict[str, Any]]
) -> Dict[str, Dict[str, Any]]:
    declarations = [
        node for node in _walk_json(ast)
        if node.get("kind") in {"ParmVarDecl", "VarDecl"} and node.get("name")
    ]
    out = {}
    for record in records:
        if record.get("kind") not in {"parameter", "declaration"} or not record.get("id"):
            continue
        names = set(str(item) for item in record.get("declared_names") or [] if str(item))
        source_range = record.get("source_range") or {}
        start = int(source_range.get("start_byte") or -1)
        end = int(source_range.get("end_byte") or -1)
        candidates = [
            node for node in declarations
            if str(node.get("name") or "") in names
            and start <= _node_offset(node) < end
        ]
        if len(candidates) != 1:
            continue
        node = candidates[0]
        out[str(record["id"])] = {
            "status": "compiler_resolved",
            "symbol_id": stable_id("clang_symbol", {
                "kind": node.get("kind"),
                "name": node.get("name"),
                "offset": _node_offset(node),
            }),
            "name": node.get("name"),
            "canonical_type": str((node.get("type") or {}).get("desugaredQualType") or ""),
            "type": str((node.get("type") or {}).get("qualType") or ""),
            "storage_class": node.get("storageClass"),
            "resolution": "clang_type_resolution",
        }
    return out


def _call_reference(node: Dict[str, Any]) -> Dict[str, Any]:
    for child in _walk_json(node):
        reference = child.get("referencedDecl")
        if isinstance(reference, dict) and reference.get("kind") in {
            "FunctionDecl", "CXXMethodDecl", "CXXConversionDecl",
            "CXXConstructorDecl", "FunctionTemplateDecl",
        }:
            return reference
        if child.get("kind") == "MemberExpr" and child.get("name"):
            return {
                "id": child.get("referencedMemberDecl"),
                "kind": "CXXMethodDecl",
                "name": child.get("name"),
                "type": child.get("type") or {},
            }
    return {}


def _select_target_ast(
    roots: List[Dict[str, Any]], *, target_range: Dict[str, Any], target_leaf: str
) -> Dict[str, Any]:
    target_start = int(target_range.get("start_byte") or -1)
    candidates = [
        node for root in roots for node in _walk_json(root)
        if node.get("kind") in {
            "FunctionDecl", "CXXMethodDecl", "FunctionTemplateDecl",
            "CXXConstructorDecl", "CXXConversionDecl",
        }
        and str(node.get("name") or "") == target_leaf
        and node.get("inner")
    ]
    if not candidates:
        return {}
    return min(candidates, key=lambda node: abs(_node_range_start(node) - target_start))


def _decode_json_stream(value: str) -> List[Dict[str, Any]]:
    decoder = json.JSONDecoder()
    index = 0
    out = []
    while index < len(value):
        while index < len(value) and value[index].isspace():
            index += 1
        if index >= len(value):
            break
        try:
            item, index = decoder.raw_decode(value, index)
        except json.JSONDecodeError:
            return []
        if isinstance(item, dict):
            out.append(item)
    return out


def _entry_arguments(entry: Dict[str, Any]) -> List[str]:
    arguments = entry.get("arguments")
    if isinstance(arguments, list):
        return [str(item) for item in arguments]
    command = str(entry.get("command") or "")
    try:
        return shlex.split(command) if command else []
    except ValueError:
        return []


def _compile_flag_arguments(arguments: List[str]) -> List[str]:
    """Drop the compiler and one common compiler-launcher prefix."""
    if not arguments:
        return []
    first = os.path.basename(str(arguments[0]))
    if first in {"ccache", "sccache", "distcc", "icecc"} and len(arguments) > 1:
        return arguments[2:]
    return arguments[1:]


def _sanitize_compile_arguments(
    arguments: List[str], *, entry_source: str, source_path: str,
    language: str, working_dir: str
) -> List[str]:
    out = []
    skip_next = False
    flags_with_value = {"-o", "-MF", "-MT", "-MQ", "-MJ", "--serialize-diagnostics"}
    for argument in arguments:
        if skip_next:
            skip_next = False
            continue
        if argument in flags_with_value:
            skip_next = True
            continue
        if any(
            argument.startswith(flag) and argument != flag
            for flag in ("-o", "-MF", "-MT", "-MQ", "-MJ")
        ):
            continue
        if argument in {"-c", "-fsyntax-only"} or argument.startswith("-Werror"):
            continue
        resolved_argument = _resolve_command_path(argument, base=working_dir)
        if resolved_argument in {entry_source, source_path}:
            continue
        if argument.startswith("-M") and argument not in {"-MD", "-MMD"}:
            continue
        if argument in {"-MD", "-MMD"}:
            continue
        out.append(argument)
    if Path(source_path).suffix.lower() in {".h", ".hh", ".hpp", ".hxx"}:
        out.extend(["-x", "c++-header" if language in {"cpp", "c++", "cc", "cxx"} else "c-header"])
    return out


def _entry_source_path(entry: Dict[str, Any]) -> str:
    directory = os.path.realpath(str(entry.get("directory") or "."))
    value = str(entry.get("file") or "")
    return os.path.realpath(value if os.path.isabs(value) else os.path.join(directory, value))


def _resolve_command_path(value: str, *, base: str) -> str:
    if not value or value.startswith("-"):
        return ""
    candidate = value if os.path.isabs(value) else os.path.join(base, value)
    return os.path.realpath(candidate)


def _clang_binary(language: str) -> str:
    configured = os.getenv("APR_CLANG_BIN", "").strip()
    if configured:
        return configured if os.path.isfile(configured) else shutil.which(configured) or ""
    name = "clang++" if language in {"cpp", "c++", "cc", "cxx"} else "clang"
    return shutil.which(name) or ""


def _walk_json(root: Dict[str, Any]) -> Iterable[Dict[str, Any]]:
    stack = [root]
    while stack:
        node = stack.pop()
        if not isinstance(node, dict):
            continue
        yield node
        stack.extend(reversed([
            item for item in node.get("inner") or [] if isinstance(item, dict)
        ]))


def _closest_ast_node(nodes: List[Dict[str, Any]], offset: int) -> Dict[str, Any]:
    if offset < 0 or not nodes:
        return {}
    exact = [node for node in nodes if _node_range_start(node) == offset]
    return exact[0] if len(exact) == 1 else {}


def _node_range_start(node: Dict[str, Any]) -> int:
    return _location_offset((node.get("range") or {}).get("begin") or {})


def _node_offset(node: Dict[str, Any]) -> int:
    return _location_offset(node.get("loc") or {})


def _location_offset(location: Dict[str, Any]) -> int:
    if not isinstance(location, dict):
        return -1
    if location.get("offset") is not None:
        try:
            return int(location["offset"])
        except (TypeError, ValueError):
            return -1
    for key in ("spellingLoc", "expansionLoc"):
        nested = location.get(key)
        if isinstance(nested, dict):
            value = _location_offset(nested)
            if value >= 0:
                return value
    return -1


def _decl_location(node: Dict[str, Any]) -> Dict[str, Any]:
    location = node.get("loc") or {}
    return {
        "file": location.get("file"),
        "line": location.get("line"),
        "column": location.get("col"),
        "offset": _location_offset(location),
    } if location else {}


def _retrieval_anchors(
    *, needs: List[Dict[str, Any]], semantic_context: Dict[str, Any],
    syntax_ir: Dict[str, Any],
) -> Tuple[List[Dict[str, Any]], List[str]]:
    calls = semantic_context.get("calls") or {}
    variables = semantic_context.get("variables") or {}
    records = {
        str(item.get("id")): item
        for item in syntax_ir.get("records") or []
        if isinstance(item, dict) and item.get("id")
    }
    out = []
    diagnostics = []
    for need in needs:
        need_id = str(need.get("id") or "")
        entity_id = str(need.get("subject_entity_id") or "")
        relation = str(need.get("relation") or "").upper()
        if relation in {"CALLEE_CONTRACT", "CALL_RESULT_CONTRACT", "OVERLOAD_SET", "CONVERSION_OPERATORS"}:
            resolved = calls.get(entity_id) or {}
            if resolved.get("status") != "compiler_resolved":
                diagnostics.append(f"semantic_retrieval_call_anchor_unresolved:{need_id}")
                continue
            out.append({
                "need_id": need_id,
                "relation": relation,
                "kind": "function",
                "name": str(resolved.get("resolved_name") or ""),
                "signature": str(resolved.get("signature") or ""),
                "symbol_id": str(resolved.get("symbol_id") or ""),
            })
            continue
        resolved = variables.get(entity_id) or {}
        if not resolved:
            wanted = {str(value) for value in need.get("symbols") or [] if str(value)}
            for record_id, value in variables.items():
                record = records.get(str(record_id)) or {}
                names = {str(item) for item in record.get("declared_names") or [] if str(item)}
                if wanted.intersection(names):
                    resolved = value
                    break
        type_name = str(resolved.get("canonical_type") or resolved.get("type") or "")
        leaf = _type_filter_name(type_name)
        if not leaf:
            diagnostics.append(f"semantic_retrieval_type_anchor_unresolved:{need_id}")
            continue
        out.append({
            "need_id": need_id,
            "relation": relation,
            "kind": "type",
            "name": leaf,
            "signature": type_name,
            "symbol_id": str(resolved.get("symbol_id") or ""),
        })
    return out, diagnostics


def _type_filter_name(type_name: str) -> str:
    value = str(type_name or "").strip()
    for prefix in ("const ", "volatile ", "struct ", "class ", "enum "):
        if value.startswith(prefix):
            value = value[len(prefix):].strip()
    value = value.rstrip(" *&")
    if value in {
        "", "void", "bool", "char", "signed char", "unsigned char", "short",
        "unsigned short", "int", "unsigned int", "long", "unsigned long",
        "long long", "unsigned long long", "float", "double", "long double",
    }:
        return ""
    leaf = value.rsplit("::", 1)[-1].split("<", 1)[0].strip()
    return leaf if leaf.replace("_", "").isalnum() else ""


def _dump_named_asts(
    entry: Dict[str, Any], *, target_contract: Dict[str, Any],
    source_path: str, symbol_filter: str,
) -> Tuple[List[Dict[str, Any]], List[str]]:
    language = str(target_contract.get("language") or "c").lower()
    compiler = _clang_binary(language)
    if not compiler:
        return [], ["semantic_retrieval_clang_binary_unavailable"]
    working_dir = os.path.realpath(str(entry.get("directory") or os.path.dirname(source_path)))
    original = _entry_arguments(entry)
    if not original:
        return [], ["semantic_retrieval_compile_arguments_missing"]
    args = _sanitize_compile_arguments(
        _compile_flag_arguments(original),
        entry_source=_entry_source_path(entry),
        source_path=source_path,
        language=language,
        working_dir=working_dir,
    )
    command = [
        compiler,
        *args,
        "-fsyntax-only",
        "-Xclang", "-ast-dump=json",
        "-Xclang", f"-ast-dump-filter={symbol_filter}",
        source_path,
    ]
    try:
        completed = subprocess.run(
            command,
            cwd=working_dir if os.path.isdir(working_dir) else None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=AST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return [], [f"semantic_retrieval_timeout:{symbol_filter}"]
    except OSError as exc:
        return [], [f"semantic_retrieval_exception:{type(exc).__name__}"]
    diagnostics = [
        f"clang_retrieval_diagnostic:{line}"
        for line in clip(completed.stderr, 2400).splitlines()[:8]
        if line.strip()
    ]
    if completed.returncode != 0:
        return [], [f"semantic_retrieval_clang_failed:{symbol_filter}", *diagnostics]
    if len(completed.stdout.encode("utf-8")) > AST_OUTPUT_LIMIT:
        return [], [f"semantic_retrieval_output_limit:{symbol_filter}"]
    return _decode_json_stream(completed.stdout), diagnostics


def _matching_declarations(
    roots: List[Dict[str, Any]], anchor: Dict[str, Any]
) -> List[Dict[str, Any]]:
    if anchor.get("kind") == "function":
        kinds = {
            "FunctionDecl", "CXXMethodDecl", "CXXConversionDecl",
            "CXXConstructorDecl", "FunctionTemplateDecl",
        }
    else:
        kinds = {
            "RecordDecl", "CXXRecordDecl", "EnumDecl", "TypedefDecl",
            "TypeAliasDecl", "ClassTemplateDecl", "ClassTemplateSpecializationDecl",
        }
    candidates = [
        node for root in roots for node in _walk_json(root)
        if node.get("kind") in kinds and str(node.get("name") or "") == anchor.get("name")
    ]
    signature = str(anchor.get("signature") or "")
    if (
        anchor.get("kind") == "function"
        and signature
        and anchor.get("relation") != "OVERLOAD_SET"
    ):
        exact = [
            node for node in candidates
            if str((node.get("type") or {}).get("qualType") or "") == signature
        ]
        candidates = exact
    candidates.sort(key=lambda node: (
        0 if _has_compound_body(node) else 1,
        _node_range_start(node) if _node_range_start(node) >= 0 else 1 << 60,
    ))
    if anchor.get("relation") == "OVERLOAD_SET":
        return candidates[:3]
    return candidates[:1]


def _has_compound_body(node: Dict[str, Any]) -> bool:
    return any(
        isinstance(child, dict) and child.get("kind") == "CompoundStmt"
        for child in node.get("inner") or []
    )


def _declaration_fact(
    node: Dict[str, Any], *, anchor: Dict[str, Any], default_source_path: str,
    allowed_roots: List[str], query_round: int, excerpt_limit: int,
) -> Dict[str, Any]:
    source_range = _ast_source_range(node, default_source_path=default_source_path)
    source_path = os.path.realpath(str(source_range.pop("source_path", "") or ""))
    if not source_path or not os.path.isfile(source_path):
        return {}
    if allowed_roots and not any(_path_is_within(source_path, root) for root in allowed_roots):
        return {}
    try:
        with open(source_path, "rb") as stream:
            raw = stream.read()
    except OSError:
        return {}
    start = max(0, int(source_range.get("start_byte") or 0))
    end = min(len(raw), int(source_range.get("end_byte") or start))
    if end <= start:
        return {}
    if int(source_range.get("start_line") or 0) <= 0:
        source_range["start_line"] = _line_for_offset(raw, start)
    if int(source_range.get("end_line") or 0) <= 0:
        source_range["end_line"] = _line_for_offset(raw, max(start, end - 1))
    excerpt = clip(raw[start:end].decode("utf-8", errors="replace"), excerpt_limit)
    is_function = anchor.get("kind") == "function"
    dependencies = _compiler_contract_dependencies(
        node, source_path=source_path, raw_source=raw,
    ) if is_function else []
    root = next((value for value in allowed_roots if _path_is_within(source_path, value)), "")
    relative = (
        os.path.relpath(source_path, root).replace(os.sep, "/") if root
        else os.path.basename(source_path)
    )
    kind = (
        "callee_definition" if is_function and _has_compound_body(node)
        else "callee_candidate" if is_function
        else "type_definition"
    )
    signature = str((node.get("type") or {}).get("qualType") or anchor.get("signature") or "")
    fact = {
        "kind": kind,
        "symbol": anchor.get("name"),
        "symbols": [anchor.get("name"), signature],
        "source_path": source_path,
        "source_file": relative,
        "source_range": source_range,
        "source_excerpt": excerpt,
        "semantic_summary": f"Compiler-resolved {node.get('kind')} {anchor.get('name')}: {signature}",
        "semantic_details": {
            "provider": "clang_budgeted_semantic_retrieval",
            "full_name": anchor.get("name"),
            "signature": signature,
            "semantic_symbol_id": anchor.get("symbol_id"),
            "compiler_decl_kind": node.get("kind"),
            "dependency_paths": dependencies,
            "control_context": [],
        },
        "query_round": query_round,
        "source_backing": "clang_ast_coordinate_to_exact_source_byte_range",
        "evidence_domain": "static_program_semantics",
        "epistemic_status": "compiler_resolved_source_fact",
        "runtime_observed": False,
        "interpretation_limit": (
            "Compiler-resolved declaration/definition only; no failing-run behavior is observed."
        ),
    }
    fact["id"] = stable_id("clang_evidence", {
        "file": source_path,
        "range": source_range,
        "kind": kind,
        "symbol": anchor.get("name"),
        "signature": signature,
    })
    return fact


def _compiler_contract_dependencies(
    node: Dict[str, Any], *, source_path: str, raw_source: bytes,
) -> List[Dict[str, Any]]:
    dependencies = []
    for child in node.get("inner") or []:
        if not isinstance(child, dict) or child.get("kind") != "ParmVarDecl":
            continue
        child_range = _ast_source_range(child, default_source_path=source_path)
        dependencies.append({
            "kind": "parameter",
            "symbol": child.get("name"),
            "code": " ".join(
                value for value in (
                    str((child.get("type") or {}).get("qualType") or ""),
                    str(child.get("name") or ""),
                ) if value
            ),
            "line": (
                _location_line(child.get("loc") or {})
                or _line_for_offset(raw_source, max(0, int(child_range.get("start_byte") or 0)))
            ),
        })
    for child in _walk_json(node):
        if child.get("kind") != "ReturnStmt":
            continue
        child_range = _ast_source_range(child, default_source_path=source_path)
        if os.path.realpath(str(child_range.pop("source_path", "") or "")) != source_path:
            continue
        start = max(0, int(child_range.get("start_byte") or 0))
        end = min(len(raw_source), int(child_range.get("end_byte") or start))
        dependencies.append({
            "kind": "callee_return",
            "symbol": "",
            "code": clip(raw_source[start:end].decode("utf-8", errors="replace"), 320),
            "line": (
                child_range.get("start_line")
                or _line_for_offset(raw_source, start)
            ),
        })
        if len(dependencies) >= 12:
            break
    return dependencies[:12]


def _ast_source_range(node: Dict[str, Any], *, default_source_path: str) -> Dict[str, Any]:
    ast_range = node.get("range") or {}
    begin = ast_range.get("begin") or node.get("loc") or {}
    end = ast_range.get("end") or begin
    source_path = _location_file(begin) or _location_file(node.get("loc") or {}) or default_source_path
    start = _location_offset(begin)
    end_offset = _location_offset(end)
    try:
        token_length = int(end.get("tokLen") or 0)
    except (TypeError, ValueError):
        token_length = 0
    return {
        "source_path": source_path,
        "start_byte": start,
        "end_byte": end_offset + max(0, token_length),
        "start_line": _location_line(begin),
        "end_line": _location_line(end),
    }


def _location_file(location: Dict[str, Any]) -> str:
    if not isinstance(location, dict):
        return ""
    if location.get("file"):
        return str(location["file"])
    for key in ("spellingLoc", "expansionLoc"):
        nested = location.get(key)
        if isinstance(nested, dict):
            value = _location_file(nested)
            if value:
                return value
    return ""


def _location_line(location: Dict[str, Any]) -> int:
    if not isinstance(location, dict):
        return 0
    try:
        if location.get("line") is not None:
            return int(location["line"])
    except (TypeError, ValueError):
        return 0
    for key in ("spellingLoc", "expansionLoc"):
        nested = location.get(key)
        if isinstance(nested, dict):
            value = _location_line(nested)
            if value:
                return value
    return 0


def _path_is_within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([os.path.realpath(path), os.path.realpath(root)]) == os.path.realpath(root)
    except ValueError:
        return False


def _line_for_offset(source: bytes, offset: int) -> int:
    return source[:max(0, min(len(source), int(offset)))].count(b"\n") + 1


def _unique_semantic_facts(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for value in values:
        marker = str(value.get("id") or "")
        if not marker or marker in seen:
            continue
        seen.add(marker)
        out.append(value)
    return out


def _retrieval_record(status: str, queries: int, regions: int, chars: int) -> Dict[str, Any]:
    return {
        "provider": "clang_budgeted_semantic_retrieval",
        "status": status,
        "query_count": queries,
        "region_count": regions,
        "source_char_count": chars,
    }


def _path_distance(left: str, right: str) -> int:
    left_parts = Path(left).resolve().parts
    right_parts = Path(right).resolve().parts
    shared = 0
    for lhs, rhs in zip(left_parts, right_parts):
        if lhs != rhs:
            break
        shared += 1
    return (len(left_parts) - shared) + (len(right_parts) - shared)


def _unavailable(reason: str) -> Dict[str, Any]:
    return {
        "version": 1,
        "provider": "clang_ast",
        "available": False,
        "calls": {},
        "variables": {},
        "diagnostics": [reason],
        "semantic_resolution": "unavailable",
    }
