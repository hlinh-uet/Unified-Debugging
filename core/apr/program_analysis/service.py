import copy
import json
import os
from collections import OrderedDict
from typing import Any, Dict

from .joern_provider import analyze_target_operations_joern, joern_cpg_tool_query
from .models import (
    TargetAnalysisRequest,
    TargetOperationAnalysis,
    replacement_function_name,
    replacement_language,
    replacement_source_path,
)
from .tree_sitter_provider import analyze_target_operations_tree_sitter
from .source_scan_provider import query_source_evidence


_CPG_TOOL_CACHE: "OrderedDict[str, Dict[str, Any]]" = OrderedDict()
_CPG_TOOL_CACHE_MAX = 256


def analyze_target_operations(
    *,
    func_code: str,
    replacement_target: Dict[str, Any],
    related_code_context: Dict[str, Any],
    source_path: str = "",
    source_root: str = "",
    function_name: str = "",
    language: str = "",
    require_joern: bool = False,
) -> TargetOperationAnalysis:
    request = TargetAnalysisRequest(
        func_code=func_code,
        replacement_target=replacement_target or {},
        related_code_context=related_code_context or {},
        source_path=source_path or replacement_source_path(replacement_target or {}),
        source_root=source_root or _source_root_from_context(related_code_context or {}),
        function_name=function_name or replacement_function_name(replacement_target or {}),
        language=language or replacement_language(replacement_target or {}),
    )
    provider = _provider_mode()
    if provider == "tree_sitter" and not require_joern:
        return analyze_target_operations_tree_sitter(request)
    joern_result = _joern_or_empty(request)
    if joern_result.operations:
        return joern_result
    if require_joern or _joern_required(provider):
        return joern_result
    return _tree_sitter_with_joern_fallback(request, joern_result)


def query_cpg_tool(
    *,
    source_root: str,
    source_path: str = "",
    function_name: str = "",
    function_signature: str = "",
    function_start_line: int = 0,
    tool: str,
    symbols: list,
    query: str = "",
    kinds: list = None,
    region_ids: list = None,
    region_spans: list = None,
    limit: int = 12,
    allow_source_scan_fallback: bool = True,
) -> Dict[str, Any]:
    cache_key = _cpg_tool_cache_key(
        source_root=source_root, source_path=source_path, function_name=function_name,
        function_signature=function_signature, function_start_line=function_start_line,
        tool=tool, symbols=symbols or [], query=query, kinds=kinds or [],
        region_ids=region_ids or [], region_spans=region_spans or [], limit=limit,
        allow_source_scan_fallback=allow_source_scan_fallback,
    )
    cached = _CPG_TOOL_CACHE.get(cache_key)
    if cached is not None:
        _CPG_TOOL_CACHE.move_to_end(cache_key)
        result = copy.deepcopy(cached)
        result.setdefault("engine", {})["cache_hit"] = True
        return result
    if (_provider_mode() == "tree_sitter" or not _joern_enabled()) and allow_source_scan_fallback:
        result = query_source_evidence(
            source_root=source_root,
            source_path=source_path,
            function_name=function_name,
            tool=tool,
            symbols=symbols or [],
            limit=limit,
        )
        return _cache_cpg_result(cache_key, result)
    if not _joern_enabled():
        return _cache_cpg_result(cache_key, {
            "engine": {
                "name": "joern_program_analysis",
                "provider": "joern",
                "available": False,
                "disabled": True,
            },
            "tool": tool,
            "results": [],
            "uncertainties": ["joern_disabled_and_source_scan_fallback_forbidden"],
        })
    joern_result = joern_cpg_tool_query(
        source_root=source_root,
        source_path=source_path,
        function_name=function_name,
        function_signature=function_signature,
        function_start_line=function_start_line,
        tool=tool,
        symbols=symbols or [],
        query=query,
        kinds=kinds or [],
        region_ids=region_ids or [],
        region_spans=region_spans or [],
        limit=limit,
        allow_source_scan_fallback=allow_source_scan_fallback,
    )
    if joern_result.get("results"):
        return _cache_cpg_result(cache_key, joern_result)
    if not allow_source_scan_fallback:
        return _cache_cpg_result(cache_key, joern_result)
    fallback = query_source_evidence(
        source_root=source_root,
        source_path=source_path,
        function_name=function_name,
        tool=tool,
        symbols=symbols or [],
        limit=limit,
    )
    fallback["uncertainties"] = list(joern_result.get("uncertainties") or []) + list(fallback.get("uncertainties") or [])
    fallback["engine"]["fallback_from"] = joern_result.get("engine") or {}
    return _cache_cpg_result(cache_key, fallback)


def query_cpg_tools(requests: list) -> list:
    """Coalesce compatible requests into fewer Joern CLI invocations."""
    requests = list(requests or [])
    grouped = OrderedDict()
    for index, request in enumerate(requests):
        group_payload = {
            key: value for key, value in request.items()
            if key not in {"symbols", "query", "region_ids", "region_spans", "limit", "reason"}
        }
        key = json.dumps(group_payload, sort_keys=True, ensure_ascii=True, default=str)
        grouped.setdefault(key, []).append((index, request))
    results = [None] * len(requests)
    for members in grouped.values():
        merged = dict(members[0][1])
        merged["symbols"] = list(dict.fromkeys(
            str(value) for _, request in members for value in request.get("symbols") or []
        ))[:24]
        merged["query"] = " | ".join(dict.fromkeys(
            str(request.get("query") or "") for _, request in members if str(request.get("query") or "")
        ))
        merged["region_ids"] = list(dict.fromkeys(
            str(value) for _, request in members for value in request.get("region_ids") or []
        ))[:24]
        span_by_id = {}
        for _, request in members:
            for span in request.get("region_spans") or []:
                if isinstance(span, dict) and span.get("id"):
                    span_by_id[str(span["id"])] = span
        merged["region_spans"] = list(span_by_id.values())[:24]
        merged["limit"] = min(64, max(int(request.get("limit") or 12) for _, request in members) * len(members))
        merged.pop("reason", None)
        shared = query_cpg_tool(**merged)
        for index, _ in members:
            result = copy.deepcopy(shared)
            result.setdefault("engine", {}).update({
                "batch_size": len(requests),
                "batch_group_size": len(members),
                "batch_coalesced": len(members) > 1,
            })
            results[index] = result
    return results


def _cpg_tool_cache_key(**payload: Any) -> str:
    root = os.path.realpath(str(payload.get("source_root") or ""))
    try:
        root_stamp = os.stat(root).st_mtime_ns
    except OSError:
        root_stamp = 0
    source_path = str(payload.get("source_path") or "")
    if source_path and not os.path.isabs(source_path):
        source_path = os.path.join(root, source_path)
    stamps = [root_stamp]
    query_script = os.path.join(os.path.dirname(__file__), "queries", "cpg_tool_query.sc")
    for path in (
        source_path,
        os.path.join(root, ".git", "HEAD"),
        os.path.join(root, ".git", "index"),
        query_script,
    ):
        try:
            stat = os.stat(path)
            stamps.extend([stat.st_mtime_ns, stat.st_size])
        except OSError:
            stamps.extend([0, 0])
    return json.dumps({
        **payload,
        "source_root": root,
        "revision_stamps": stamps,
        "provider_mode": _provider_mode(),
        "joern_enabled": _joern_enabled(),
    }, sort_keys=True, ensure_ascii=True, default=str)


def _cache_cpg_result(key: str, result: Dict[str, Any]) -> Dict[str, Any]:
    stored = copy.deepcopy(result)
    stored.setdefault("engine", {})["cache_hit"] = False
    _CPG_TOOL_CACHE[key] = stored
    _CPG_TOOL_CACHE.move_to_end(key)
    while len(_CPG_TOOL_CACHE) > _CPG_TOOL_CACHE_MAX:
        _CPG_TOOL_CACHE.popitem(last=False)
    return copy.deepcopy(stored)


def _tree_sitter_with_joern_fallback(
    request: TargetAnalysisRequest,
    joern_result: TargetOperationAnalysis,
) -> TargetOperationAnalysis:
    tree_result = analyze_target_operations_tree_sitter(request)
    if joern_result.uncertainties:
        tree_result.uncertainties = list(tree_result.uncertainties or []) + [
            f"joern_fallback:{item}" for item in joern_result.uncertainties[:4]
        ]
    tree_result.engine = {
        **(tree_result.engine or {}),
        "fallback_from": joern_result.engine,
    }
    return tree_result


def _joern_or_empty(request: TargetAnalysisRequest) -> TargetOperationAnalysis:
    if not _joern_enabled():
        return TargetOperationAnalysis(
            engine={
                "name": "joern_program_analysis",
                "provider": "joern",
                "available": False,
                "disabled": True,
            },
            operations=[],
            uncertainties=["joern_disabled"],
        )
    return analyze_target_operations_joern(request)


def _provider_mode() -> str:
    value = os.getenv("APR_PROGRAM_ANALYSIS_PROVIDER", "joern").strip().lower()
    if value in {"joern", "tree_sitter", "auto"}:
        return value
    return "joern"


def _joern_enabled() -> bool:
    value = os.getenv("APR_JOERN_ENABLED", "1").strip().lower()
    if value in {"0", "false", "no", "off"}:
        return False
    if value in {"1", "true", "yes", "on", "auto"}:
        return True
    return True


def _joern_required(provider: str) -> bool:
    required = os.getenv("APR_JOERN_REQUIRED", "").strip().lower()
    if required in {"1", "true", "yes", "on"}:
        return True
    fallback = os.getenv("APR_JOERN_FALLBACK", "1").strip().lower()
    return provider == "joern" and fallback in {"0", "false", "no", "off"}


def _source_root_from_context(context: Dict[str, Any]) -> str:
    return str((context or {}).get("source_root") or ((context or {}).get("related_code_map") or {}).get("source_root") or "")
