"""Compiler/source-backed investigation evidence for initial FL.

This module deliberately contains no benchmark, project, API, or symbol-name
rules.  It converts the concrete executed inventory into auditable source
dossiers that an evidence planner can inspect and that the ranker can verify.
"""

from __future__ import annotations

import hashlib
import gzip
import json
import os
import re
import copy
from collections import OrderedDict, defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from core.program_analysis.source_utils import (
    node_text,
    parse_tree,
    source_language_from_path,
    walk_nodes,
)
from core.program_analysis.evidence import register_program_evidence

from .semantic import semantic_tokens
from .artifacts import (
    atomic_write_gzip_json,
    safe_artifact_component,
)


SOURCE_EVIDENCE_SCHEMA = "unified_debugging.source_evidence.v1"
_FUNCTION_TYPES = {"function_definition"}
_BRANCH_TYPES = {
    "if_statement",
    "switch_statement",
    "conditional_expression",
    "while_statement",
    "for_statement",
}
_RETURN_TYPES = {"return_statement", "co_return_statement"}
_ASSIGNMENT_TYPES = {
    "assignment_expression",
    "update_expression",
    "declaration",
}
_CALL_TYPES = {"call_expression"}
_THROW_TYPES = {"throw_statement"}
_SOURCE_FILE_CACHE_LIMIT = 128
_SOURCE_DOSSIER_CACHE_LIMIT = 4096
_SOURCE_FILE_INDEX_CACHE: OrderedDict = OrderedDict()
_SOURCE_DOSSIER_CACHE: OrderedDict = OrderedDict()


def load_or_build_source_evidence(
    *,
    bug: Any,
    runtime_evidence: Dict[str, Any],
    scenario: Dict[str, Any],
    invocation_keys: Iterable[str] = (),
    artifact_dir: str = "",
) -> Dict[str, Any]:
    """Reuse source dossiers when bug/scenario/executed inventory is unchanged."""
    request_identity = ""
    path = ""
    if artifact_dir:
        request_identity = _source_request_identity(
            bug=bug,
            runtime_evidence=runtime_evidence,
            scenario=scenario,
        )
        path = os.path.join(
            artifact_dir,
            "source_evidence",
            safe_artifact_component(request_identity)[:64] + ".json.gz",
        )
        try:
            with gzip.open(path, "rt", encoding="utf-8") as stream:
                cached = json.load(stream)
        except (OSError, UnicodeError, json.JSONDecodeError):
            cached = None
        if (
            isinstance(cached, dict)
            and cached.get("schema") == SOURCE_EVIDENCE_SCHEMA
            and cached.get("request_identity") == request_identity
        ):
            _apply_invocation_projection(
                cached,
                invocation_keys=invocation_keys,
            )
            cached["cache"] = {"hit": True, "source": path}
            _register_source_evidence_index(
                request_identity=request_identity,
                result=cached,
                path=path,
                bug=bug,
                cache_hit=True,
            )
            return cached
    result = build_source_evidence(
        bug=bug,
        runtime_evidence=runtime_evidence,
        scenario=scenario,
        invocation_keys=invocation_keys,
    )
    if not request_identity:
        # Transient per-test refinement has no persistent lookup to perform.
        # Its source-backed result identity avoids hashing every file again.
        request_identity = str(result.get("identity") or "")
    result["request_identity"] = request_identity
    result["cache"] = {"hit": False, "source": path}
    if path:
        atomic_write_gzip_json(path, result)
    _register_source_evidence_index(
        request_identity=request_identity,
        result=result,
        path=path,
        bug=bug,
        cache_hit=False,
    )
    return result


def _apply_invocation_projection(
    source_evidence: Dict[str, Any],
    *,
    invocation_keys: Iterable[str],
) -> None:
    """Refresh request-specific membership on cached structural dossiers."""
    members = {
        str(value) for value in invocation_keys if str(value)
    }
    for key, dossier in (
        source_evidence.get("dossiers") or {}
    ).items():
        if isinstance(dossier, dict):
            dossier["in_selected_invocation"] = (
                str(key) in members
            )


def _register_source_evidence_index(
    *,
    request_identity: str,
    result: Dict[str, Any],
    path: str,
    bug: Any,
    cache_hit: bool,
) -> None:
    """Publish a compact index, never a duplicate of every source dossier."""
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    try:
        register_program_evidence(
            namespace="fl_source_evidence",
            identity=request_identity,
            payload={
                "schema": result.get("schema"),
                "request_identity": request_identity,
                "artifact_path": path,
                "candidate_count": result.get("candidate_count"),
                "diagnostics": list(result.get("diagnostics") or []),
            },
            producer="fault_localization.source_investigation",
            source_root=str(
                raw.get("buggy_tree_dir")
                or raw.get("source_repo_dir")
                or ""
            ),
            parameters={
                "dataset": str(getattr(bug, "dataset", "") or ""),
                "bug_id": str(getattr(bug, "bug_id", "") or ""),
            },
            metadata={"cache_hit": cache_hit},
        )
    except Exception:
        # This registry is an audit/reuse layer, not FL ranking policy.
        return


def build_source_evidence(
    *,
    bug: Any,
    runtime_evidence: Dict[str, Any],
    scenario: Dict[str, Any],
    invocation_keys: Iterable[str] = (),
) -> Dict[str, Any]:
    """Build one source dossier for every executed production function."""
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    source_root = os.path.realpath(
        str(raw.get("buggy_tree_dir") or raw.get("source_repo_dir") or "")
    )
    runtime_functions = runtime_evidence.get("functions") or {}
    member_keys = {str(value) for value in invocation_keys if str(value)}
    dynamic_edges = runtime_evidence.get("dynamic_edges") or []
    callers: Dict[str, set] = defaultdict(set)
    callees: Dict[str, set] = defaultdict(set)
    for edge in dynamic_edges:
        caller = str(edge.get("caller") or "")
        callee = str(edge.get("callee") or "")
        if caller and callee:
            callers[callee].add(caller)
            callees[caller].add(callee)

    contract_tokens = semantic_tokens([
        str(scenario.get("source") or ""),
        str(scenario.get("producer_source") or ""),
        *(scenario.get("input_literals") or []),
        *((scenario.get("observed_output") or {}).get("expected") or []),
        *((scenario.get("observed_output") or {}).get("actual") or []),
    ])
    producer_calls = [
        _canonical_symbol(value)
        for value in scenario.get("producer_calls") or []
        if _canonical_symbol(value)
    ]
    file_cache: Dict[str, Dict[str, Any]] = {}
    dossiers = {}
    diagnostics = []
    for key, runtime in runtime_functions.items():
        if not isinstance(runtime, dict):
            continue
        path = _resolve_source_path(
            source_root=source_root,
            runtime_path=str(runtime.get("source_path") or ""),
        )
        dossier = _source_dossier(
            function_key=str(key),
            runtime=runtime,
            source_path=path,
            file_cache=file_cache,
            contract_tokens=contract_tokens,
            producer_calls=producer_calls,
        )
        dossier["in_selected_invocation"] = str(key) in member_keys
        dossier["dynamic_callers"] = sorted(callers.get(str(key), set()))
        dossier["dynamic_callees"] = sorted(callees.get(str(key), set()))
        dossiers[str(key)] = dossier
        diagnostics.extend(dossier.get("diagnostics") or [])

    identity_payload = {
        "scenario": str(
            scenario.get("scenario_fingerprint")
            or scenario.get("scenario_id")
            or ""
        ),
        "functions": [
            {
                "key": key,
                "source_digest": dossier.get("source_digest"),
            }
            for key, dossier in sorted(dossiers.items())
        ],
    }
    identity = hashlib.sha256(json.dumps(
        identity_payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()
    return {
        "schema": SOURCE_EVIDENCE_SCHEMA,
        "identity": identity,
        "source_root": source_root,
        "contract_tokens": contract_tokens,
        "candidate_count": len(dossiers),
        "dossiers": dossiers,
        "diagnostics": list(dict.fromkeys(diagnostics)),
        "ground_truth_used": False,
    }


def _source_request_identity(
    *,
    bug: Any,
    runtime_evidence: Dict[str, Any],
    scenario: Dict[str, Any],
) -> str:
    raw = bug.raw if isinstance(getattr(bug, "raw", None), dict) else {}
    source_root = os.path.realpath(
        str(
            raw.get("buggy_tree_dir")
            or raw.get("source_repo_dir")
            or ""
        )
    )
    resolved_paths: Dict[str, str] = {}
    source_revisions: Dict[str, str] = {}
    functions = []
    for key, value in sorted(
        (runtime_evidence.get("functions") or {}).items()
    ):
        runtime_path = str((value or {}).get("source_path") or "")
        if runtime_path not in resolved_paths:
            resolved_paths[runtime_path] = _resolve_source_path(
                source_root=source_root,
                runtime_path=runtime_path,
            )
        resolved_path = resolved_paths[runtime_path]
        if resolved_path not in source_revisions:
            source_revisions[resolved_path] = _source_revision(
                resolved_path
            )
        functions.append((
            str(key),
            runtime_path,
            int((value or {}).get("source_line") or 0),
            source_revisions[resolved_path],
        ))
    payload = {
        "schema": SOURCE_EVIDENCE_SCHEMA,
        "bug_id": str(getattr(bug, "bug_id", "") or ""),
        "dataset": str(getattr(bug, "dataset", "") or ""),
        "commit_before": str(raw.get("commit_before") or ""),
        "scenario": str(
            scenario.get("scenario_fingerprint")
            or scenario.get("scenario_id")
            or ""
        ),
        # Persistent source evidence must follow the actual worktree content,
        # not only commit/path metadata. APR validation may temporarily edit
        # a file without changing either of those fields.
        "functions": functions,
    }
    return hashlib.sha256(json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


def _source_revision(path: str) -> str:
    if not path or not os.path.isfile(path):
        return "missing"
    real_path = os.path.realpath(path)
    try:
        stat = os.stat(real_path)
        fingerprint = (
            real_path,
            int(stat.st_mtime_ns),
            int(stat.st_size),
        )
    except OSError:
        return "unreadable"
    indexed = _SOURCE_FILE_INDEX_CACHE.get(fingerprint)
    if isinstance(indexed, dict) and indexed.get("file_digest"):
        return str(indexed["file_digest"])
    digest = hashlib.sha256()
    try:
        with open(real_path, "rb") as stream:
            for chunk in iter(lambda: stream.read(1024 * 1024), b""):
                digest.update(chunk)
    except OSError:
        return "unreadable"
    return digest.hexdigest()


def compact_source_evidence(
    source_evidence: Dict[str, Any],
    *,
    include_full_source_for: Iterable[str] = (),
) -> List[Dict[str, Any]]:
    """Return prompt-safe semantic dossiers without losing exact identities."""
    full = {str(value) for value in include_full_source_for if str(value)}
    output = []
    for key, dossier in (
        (source_evidence or {}).get("dossiers") or {}
    ).items():
        item = {
            "function": key,
            "source_path": dossier.get("source_path"),
            "source_line": dossier.get("source_line"),
            "signature": dossier.get("signature"),
            "returns": (dossier.get("returns") or [])[:8],
            "conditions": _head_tail(
                dossier.get("conditions") or [], limit=12
            ),
            "assignments": _head_tail(
                dossier.get("assignments") or [], limit=10
            ),
            "calls": _head_tail(
                dossier.get("calls") or [], limit=16
            ),
            "throws": (dossier.get("throws") or [])[:8],
            "contract_token_matches": (
                dossier.get("contract_token_matches") or []
            ),
            "producer_symbol_match": bool(
                dossier.get("producer_symbol_match")
            ),
            "in_selected_invocation": bool(
                dossier.get("in_selected_invocation")
            ),
            "dynamic_callers": (
                dossier.get("dynamic_callers") or []
            )[:12],
            "dynamic_callees": (
                dossier.get("dynamic_callees") or []
            )[:12],
            "source_available": bool(dossier.get("source_available")),
        }
        if key in full:
            item["source"] = dossier.get("source") or ""
        output.append(item)
    return output


def hypothesis_support(
    *,
    hypothesis: Dict[str, Any],
    source_evidence: Dict[str, Any],
    invocation_keys: Iterable[str],
    dynamic_edges: Iterable[Dict[str, Any]],
) -> Dict[str, Any]:
    """Validate an LLM hypothesis against exact runtime and source evidence."""
    dossiers = (source_evidence or {}).get("dossiers") or {}
    members = {str(value) for value in invocation_keys if str(value)}
    candidate = str(
        hypothesis.get("candidate_function")
        or hypothesis.get("function")
        or ""
    )
    chain = [
        str(value)
        for value in hypothesis.get("causal_chain") or []
        if str(value)
    ]
    if candidate and candidate not in chain:
        chain.append(candidate)
    allowed = set(dossiers)
    exact_functions = bool(candidate and candidate in allowed) and all(
        value in allowed for value in chain
    )
    edge_set = {
        (
            str(edge.get("caller") or ""),
            str(edge.get("callee") or ""),
        )
        for edge in dynamic_edges
        if str(edge.get("caller") or "")
        and str(edge.get("callee") or "")
    }
    chain_edges = list(zip(chain, chain[1:]))
    graph: Dict[str, set] = defaultdict(set)
    for caller, callee in edge_set:
        graph[caller].add(callee)
    link_evidence = []
    for left, right in chain_edges:
        if (left, right) in edge_set:
            status = "direct"
        elif _graph_reachable(graph, left, right):
            status = "reachable"
        else:
            status = "unsupported"
        link_evidence.append({
            "caller": left,
            "callee": right,
            "status": status,
        })
    full_dynamic_chain = all(
        item["status"] != "unsupported" for item in link_evidence
    )
    candidate_index = (
        chain.index(candidate) if candidate in chain else -1
    )
    candidate_local_links = []
    if candidate_index > 0:
        left = chain[candidate_index - 1]
        candidate_local_links.append({
            "caller": left,
            "callee": candidate,
            "status": (
                "direct"
                if (left, candidate) in edge_set
                else (
                    "reachable"
                    if _graph_reachable(graph, left, candidate)
                    else "unsupported"
                )
            ),
        })
    if 0 <= candidate_index < len(chain) - 1:
        right = chain[candidate_index + 1]
        candidate_local_links.append({
            "caller": candidate,
            "callee": right,
            "status": (
                "direct"
                if (candidate, right) in edge_set
                else (
                    "reachable"
                    if _graph_reachable(graph, candidate, right)
                    else "unsupported"
                )
            ),
        })
    candidate_dynamic_support = bool(
        len(chain) <= 1
        or any(
            item["status"] != "unsupported"
            for item in candidate_local_links
        )
    )
    source_available = bool(
        candidate
        and (dossiers.get(candidate) or {}).get("source_available")
    )
    candidate_dossier = dossiers.get(candidate) or {}
    observation_tokens = set(semantic_tokens(
        str(hypothesis.get("source_observation") or "")
    ))
    dossier_tokens = set(semantic_tokens([
        str(candidate_dossier.get("signature") or ""),
        *(candidate_dossier.get("identifiers") or []),
        *(candidate_dossier.get("literals") or []),
        *(
            str(item.get("expression") or "")
            for field in (
                "returns", "conditions", "assignments", "calls", "throws"
            )
            for item in candidate_dossier.get(field) or []
        ),
    ]))
    source_observation_supported = bool(
        observation_tokens and observation_tokens & dossier_tokens
    )
    invocation_supported = bool(
        candidate in members
        or (
            candidate_dynamic_support
            and len(chain) > 1
            and candidate in allowed
        )
        or (not members and candidate in allowed)
    )
    requested_evidence = [
        item
        for item in hypothesis.get("information_needs") or []
        if isinstance(item, dict)
    ]
    valid_needs = [
        item
        for item in requested_evidence
        if str(item.get("function") or candidate) in allowed
        and str(item.get("kind") or "") in {
            "argument",
            "return_value",
            "branch_outcome",
            "output_write",
            "exception",
            "call_result",
            "source_definition",
        }
    ]
    supported = bool(
        exact_functions
        and source_available
        and source_observation_supported
        and invocation_supported
        and candidate_dynamic_support
    )
    return {
        "candidate_function": candidate,
        "exact_functions": exact_functions,
        "source_available": source_available,
        "source_observation_supported": source_observation_supported,
        "invocation_supported": invocation_supported,
        "dynamic_chain_supported": candidate_dynamic_support,
        "full_dynamic_chain_supported": (
            full_dynamic_chain or len(chain) <= 1
        ),
        "dynamic_link_evidence": link_evidence,
        "candidate_local_link_evidence": candidate_local_links,
        "valid_information_needs": valid_needs,
        "status": "source_runtime_supported" if supported else "unverified",
    }


def _graph_reachable(
    graph: Dict[str, set], start: str, target: str
) -> bool:
    """Return whether a concrete directed runtime path connects two keys."""
    if not start or not target:
        return False
    pending = [start]
    visited = {start}
    while pending:
        current = pending.pop()
        for child in graph.get(current, ()):
            if child == target:
                return True
            if child not in visited:
                visited.add(child)
                pending.append(child)
    return False


def _source_dossier(
    *,
    function_key: str,
    runtime: Dict[str, Any],
    source_path: str,
    file_cache: Dict[str, Dict[str, Any]],
    contract_tokens: List[str],
    producer_calls: List[str],
) -> Dict[str, Any]:
    base = {
        "function": function_key,
        "source_path": source_path or str(runtime.get("source_path") or ""),
        "source_line": int(runtime.get("source_line") or 0),
        "source_available": False,
        "signature": "",
        "source": "",
        "source_digest": "",
        "returns": [],
        "conditions": [],
        "assignments": [],
        "calls": [],
        "throws": [],
        "identifiers": [],
        "literals": [],
        "contract_token_matches": [],
        "producer_symbol_match": False,
        "diagnostics": [],
    }
    if not source_path:
        base["diagnostics"].append(
            f"source_definition_unavailable:{function_key}"
        )
        return base
    if source_path not in file_cache:
        file_cache[source_path] = _load_source_file_index(source_path)
    source_index = file_cache[source_path]
    source = str(source_index.get("source") or "")
    tree = source_index.get("tree")
    source_bytes = source_index.get("source_bytes")
    if tree is None or source_bytes is None:
        base["diagnostics"].append(
            f"source_ast_unavailable:{function_key}"
        )
        return base
    line = max(1, int(runtime.get("source_line") or 1))
    candidates = []
    for start, end, node in source_index.get("function_nodes") or []:
        if start <= line <= end:
            candidates.append((end - start, int(node.end_byte - node.start_byte), node))
    if not candidates:
        base["diagnostics"].append(
            f"source_function_at_line_unavailable:{function_key}:{line}"
        )
        return base
    function_node = min(candidates, key=lambda item: (item[0], item[1]))[2]
    dossier_cache_key = (
        source_index.get("fingerprint"),
        int(function_node.start_byte),
        int(function_node.end_byte),
        str(function_key),
    )
    cached_base = _SOURCE_DOSSIER_CACHE.get(dossier_cache_key)
    if cached_base is not None:
        _SOURCE_DOSSIER_CACHE.move_to_end(dossier_cache_key)
        base = copy.deepcopy(cached_base)
        return _project_scenario_source_facts(
            base=base,
            function_key=function_key,
            contract_tokens=contract_tokens,
            producer_calls=producer_calls,
        )
    function_source = node_text(function_node, source_bytes)
    declarator = function_node.child_by_field_name("declarator")
    body = function_node.child_by_field_name("body")
    signature = (
        node_text(declarator, source_bytes).strip()
        if declarator is not None else function_source.split("{", 1)[0].strip()
    )
    analysis_root = body or function_node
    returns = []
    conditions = []
    assignments = []
    calls = []
    throws = []
    identifiers = []
    literals = []
    for node in walk_nodes(analysis_root):
        text = node_text(node, source_bytes).strip()
        if not text:
            continue
        item = {
            "line": int(node.start_point[0]) + 1,
            "expression": _compact_text(text),
        }
        if node.type in _RETURN_TYPES:
            returns.append(item)
        elif node.type in _BRANCH_TYPES:
            condition = node.child_by_field_name("condition")
            conditions.append({
                "line": item["line"],
                "expression": _compact_text(
                    node_text(condition, source_bytes)
                    if condition is not None else text
                ),
            })
        elif node.type in _ASSIGNMENT_TYPES:
            assignments.append(item)
        elif node.type in _CALL_TYPES:
            function = node.child_by_field_name("function")
            calls.append({
                "line": item["line"],
                "expression": _compact_text(
                    node_text(function, source_bytes)
                    if function is not None else text
                ),
            })
        elif node.type in _THROW_TYPES:
            throws.append(item)
        elif node.type in {
            "identifier",
            "field_identifier",
            "type_identifier",
        }:
            identifiers.append(text)
        elif "literal" in node.type or node.type in {
            "string_content",
            "number_literal",
            "char_literal",
            "true",
            "false",
            "null",
            "nullptr",
        }:
            literals.append(text)
    base.update({
        "source_available": True,
        "signature": _compact_text(signature, limit=1000),
        "source": function_source[:12000],
        "source_digest": hashlib.sha256(
            function_source.encode("utf-8")
        ).hexdigest(),
        "returns": _unique_records(returns)[:24],
        "conditions": _unique_records(conditions)[:32],
        "assignments": _unique_records(assignments)[:32],
        "calls": _unique_records(calls)[:48],
        "throws": _unique_records(throws)[:16],
        "identifiers": list(dict.fromkeys(identifiers))[:120],
        "literals": list(dict.fromkeys(literals))[:80],
    })
    _SOURCE_DOSSIER_CACHE[dossier_cache_key] = copy.deepcopy(base)
    _SOURCE_DOSSIER_CACHE.move_to_end(dossier_cache_key)
    while len(_SOURCE_DOSSIER_CACHE) > _SOURCE_DOSSIER_CACHE_LIMIT:
        _SOURCE_DOSSIER_CACHE.popitem(last=False)
    return _project_scenario_source_facts(
        base=base,
        function_key=function_key,
        contract_tokens=contract_tokens,
        producer_calls=producer_calls,
    )


def _load_source_file_index(source_path: str) -> Dict[str, Any]:
    """Parse and index one immutable source revision once per process.

    The cache key includes the exact file stat fingerprint, so APR validation
    or another actor changing a source file cannot reuse a stale Tree-sitter
    tree.  Scenario-specific token matching remains outside this cache.
    """
    real_path = os.path.realpath(source_path)
    try:
        stat = os.stat(real_path)
        fingerprint = (
            real_path,
            int(stat.st_mtime_ns),
            int(stat.st_size),
        )
    except OSError:
        fingerprint = (real_path, 0, 0)
    cached = _SOURCE_FILE_INDEX_CACHE.get(fingerprint)
    if cached is not None:
        _SOURCE_FILE_INDEX_CACHE.move_to_end(fingerprint)
        return cached
    try:
        with open(real_path, "rb") as stream:
            source_raw = stream.read()
    except OSError:
        source_raw = b""
    source = source_raw.decode("utf-8", errors="replace")
    language = source_language_from_path(real_path)
    tree, source_bytes = parse_tree(source, language)
    function_nodes = []
    if tree is not None:
        function_nodes = [
            (
                int(node.start_point[0]) + 1,
                int(node.end_point[0]) + 1,
                node,
            )
            for node in walk_nodes(tree.root_node)
            if node.type in _FUNCTION_TYPES
        ]
    result = {
        "fingerprint": fingerprint,
        "file_digest": hashlib.sha256(source_raw).hexdigest(),
        "source": source,
        "tree": tree,
        "source_bytes": source_bytes,
        "function_nodes": function_nodes,
    }
    # Remove older revisions of the same path before installing the current
    # immutable index.
    for key in [
        key for key in _SOURCE_FILE_INDEX_CACHE
        if key[0] == real_path and key != fingerprint
    ]:
        _SOURCE_FILE_INDEX_CACHE.pop(key, None)
    _SOURCE_FILE_INDEX_CACHE[fingerprint] = result
    while len(_SOURCE_FILE_INDEX_CACHE) > _SOURCE_FILE_CACHE_LIMIT:
        _SOURCE_FILE_INDEX_CACHE.popitem(last=False)
    return result


def _project_scenario_source_facts(
    *,
    base: Dict[str, Any],
    function_key: str,
    contract_tokens: Iterable[str],
    producer_calls: Iterable[str],
) -> Dict[str, Any]:
    """Attach cheap failure-scenario facts to a cached structural dossier."""
    source_tokens = semantic_tokens([
        str(base.get("signature") or ""),
        str(base.get("source") or ""),
        *(base.get("identifiers") or []),
        *(base.get("literals") or []),
    ])
    qualified, leaf = _function_identity(function_key)
    base["contract_token_matches"] = [
        token for token in contract_tokens if token in source_tokens
    ][:40]
    base["producer_symbol_match"] = any(
        _symbol_equivalent(qualified, leaf, producer)
        for producer in producer_calls
    )
    return base


def _clear_source_analysis_caches() -> None:
    """Test/support hook for explicitly releasing source-analysis memory."""
    _SOURCE_FILE_INDEX_CACHE.clear()
    _SOURCE_DOSSIER_CACHE.clear()


def _resolve_source_path(*, source_root: str, runtime_path: str) -> str:
    normalized = str(runtime_path or "").replace("\\", "/")
    if normalized and os.path.isfile(normalized):
        return os.path.realpath(normalized)
    if not source_root or not os.path.isdir(source_root):
        return ""
    candidates = []
    if normalized and not normalized.startswith("/"):
        candidates.append(os.path.join(source_root, normalized))
    if normalized:
        parts = normalized.lstrip("/").split("/")
        for size in range(min(len(parts), 8), 0, -1):
            candidates.append(os.path.join(source_root, *parts[-size:]))
    for candidate in candidates:
        real = os.path.realpath(candidate)
        if _within(real, source_root) and os.path.isfile(real):
            return real
    basename = os.path.basename(normalized)
    if not basename:
        return ""
    matches = []
    for directory, _, files in os.walk(source_root):
        if basename in files:
            matches.append(os.path.join(directory, basename))
            if len(matches) > 1:
                break
    return os.path.realpath(matches[0]) if len(matches) == 1 else ""


def _function_identity(function_key: str) -> Tuple[str, str]:
    match = re.search(r"(?<!:):(?!:)", str(function_key or ""))
    value = function_key[match.end():] if match else str(function_key or "")
    canonical = _canonical_symbol(value)
    return canonical, canonical.rsplit("::", 1)[-1]


def _canonical_symbol(value: Any) -> str:
    text = str(value or "").strip()
    text = re.sub(r"\([^()]*\)\s*$", "", text)
    text = re.sub(r"\s*<[^;{}()]{1,200}>\s*$", "", text)
    text = re.sub(r"\s+", "", text)
    return text.lstrip("&*")


def _symbol_equivalent(
    qualified: str, leaf: str, observed: str
) -> bool:
    observed = _canonical_symbol(observed)
    observed_leaf = observed.rsplit("::", 1)[-1]
    if not observed or not leaf:
        return False
    return (
        qualified == observed
        or qualified.endswith("::" + observed)
        or observed.endswith("::" + qualified)
        or leaf == observed_leaf
    )


def _compact_text(value: str, *, limit: int = 500) -> str:
    return re.sub(r"\s+", " ", str(value or "")).strip()[:limit]


def _unique_records(values: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    output = []
    for value in values:
        key = (int(value.get("line") or 0), str(value.get("expression") or ""))
        if key in seen:
            continue
        seen.add(key)
        output.append(value)
    return output


def _head_tail(values: List[Any], *, limit: int) -> List[Any]:
    if len(values) <= limit:
        return list(values)
    head = max(1, limit // 2)
    return [*values[:head], *values[-(limit - head):]]


def _within(path: str, root: str) -> bool:
    try:
        return os.path.commonpath([path, root]) == root
    except ValueError:
        return False
