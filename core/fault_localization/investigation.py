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
from collections import defaultdict
from typing import Any, Dict, Iterable, List, Tuple

from core.apr.common import (
    node_text,
    parse_tree,
    source_language_from_path,
    walk_nodes,
)

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


def load_or_build_source_evidence(
    *,
    bug: Any,
    runtime_evidence: Dict[str, Any],
    scenario: Dict[str, Any],
    invocation_keys: Iterable[str] = (),
    artifact_dir: str = "",
) -> Dict[str, Any]:
    """Reuse source dossiers when bug/scenario/executed inventory is unchanged."""
    request_identity = _source_request_identity(
        bug=bug,
        runtime_evidence=runtime_evidence,
        scenario=scenario,
    )
    path = ""
    if artifact_dir:
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
            cached["cache"] = {"hit": True, "source": path}
            return cached
    result = build_source_evidence(
        bug=bug,
        runtime_evidence=runtime_evidence,
        scenario=scenario,
        invocation_keys=invocation_keys,
    )
    result["request_identity"] = request_identity
    result["cache"] = {"hit": False, "source": path}
    if path:
        atomic_write_gzip_json(path, result)
    return result


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
    file_cache: Dict[str, Tuple[str, Any, bytes | None]] = {}
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
        "functions": [
            (
                str(key),
                str((value or {}).get("source_path") or ""),
                int((value or {}).get("source_line") or 0),
            )
            for key, value in sorted(
                (runtime_evidence.get("functions") or {}).items()
            )
        ],
    }
    return hashlib.sha256(json.dumps(
        payload,
        sort_keys=True,
        ensure_ascii=False,
        separators=(",", ":"),
    ).encode("utf-8")).hexdigest()


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
    file_cache: Dict[str, Tuple[str, Any, bytes | None]],
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
        try:
            source = open(
                source_path, "r", encoding="utf-8", errors="replace"
            ).read()
        except OSError:
            source = ""
        language = source_language_from_path(source_path)
        tree, source_bytes = parse_tree(source, language)
        file_cache[source_path] = (source, tree, source_bytes)
    source, tree, source_bytes = file_cache[source_path]
    if tree is None or source_bytes is None:
        base["diagnostics"].append(
            f"source_ast_unavailable:{function_key}"
        )
        return base
    line = max(1, int(runtime.get("source_line") or 1))
    candidates = []
    for node in walk_nodes(tree.root_node):
        if node.type not in _FUNCTION_TYPES:
            continue
        start = int(node.start_point[0]) + 1
        end = int(node.end_point[0]) + 1
        if start <= line <= end:
            candidates.append((end - start, int(node.end_byte - node.start_byte), node))
    if not candidates:
        base["diagnostics"].append(
            f"source_function_at_line_unavailable:{function_key}:{line}"
        )
        return base
    function_node = min(candidates, key=lambda item: (item[0], item[1]))[2]
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
    source_tokens = semantic_tokens([
        signature,
        function_source,
        *identifiers,
        *literals,
    ])
    qualified, leaf = _function_identity(function_key)
    producer_symbol_match = any(
        _symbol_equivalent(qualified, leaf, producer)
        for producer in producer_calls
    )
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
        "contract_token_matches": [
            token for token in contract_tokens if token in source_tokens
        ][:40],
        "producer_symbol_match": producer_symbol_match,
    })
    return base


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
