import re
from typing import Any, Dict, List, Optional, Tuple

from core.apr.artifacts import write_target_code_context_artifact
from core.apr.agent.context_common import (
    clip_text,
    extract_symbols_from_code,
    find_function_node,
    line_number_for_byte,
    node_text,
    parse_tree,
    source_slice_by_byte_range,
    walk_nodes,
)


MAX_STATEMENT_TEXT = 900
MAX_REPAIR_SITES = 8


def collect_target_code_context(
    *,
    func_name: str,
    cand_label: str,
    func_code: str,
    source_code: str,
    source_path: str,
    start_idx: int,
    end_idx: int,
    language: str,
    failed_tests_context: str = "",
) -> Dict[str, Any]:
    replacement_start, replacement_end, replacement_unit, envelope_notes = _replacement_envelope(
        source_code=source_code,
        func_name=func_name,
        language=language,
        fallback_start=start_idx,
        fallback_end=end_idx,
    )
    if not replacement_unit:
        replacement_start, replacement_end = start_idx, end_idx
        replacement_unit = func_code or ""
        envelope_notes.append("fallback_to_original_extracted_function_range")

    symbols = extract_symbols_from_code(replacement_unit or func_code or "", language)
    statements = _statement_inventory(
        source_code=source_code,
        func_code=replacement_unit or func_code or "",
        function_start_byte=replacement_start,
        language=language,
    )
    failure_links = _rank_failure_code_links(
        statements=statements,
        failed_tests_context=failed_tests_context,
        symbols=symbols,
    )
    local_contracts = _local_behavioral_contracts(replacement_unit or func_code or "", statements)
    guardrails = _repair_guardrails(
        func_name=func_name,
        replacement_start=replacement_start,
        original_start=start_idx,
        language=language,
        envelope_notes=envelope_notes,
        local_contracts=local_contracts,
    )

    return {
        "target_envelope": {
            "function_name": func_name,
            "source_file": cand_label,
            "source_path": source_path,
            "language": language,
            "original_function_range": {
                "start_byte": start_idx,
                "end_byte": end_idx,
                "start_line": line_number_for_byte(source_code, start_idx),
                "end_line": line_number_for_byte(source_code, end_idx),
            },
            "replacement_range": {
                "start_byte": replacement_start,
                "end_byte": replacement_end,
                "start_line": line_number_for_byte(source_code, replacement_start),
                "end_line": line_number_for_byte(source_code, replacement_end),
            },
            "replacement_includes_prefix": replacement_start != start_idx,
            "replacement_prefix": source_slice_by_byte_range(source_code, replacement_start, start_idx)
            if replacement_start != start_idx else "",
            "replacement_unit": replacement_unit,
            "output_contract": _output_contract(
                replacement_start=replacement_start,
                original_start=start_idx,
                language=language,
                replacement_unit=replacement_unit,
            ),
            "notes": envelope_notes,
        },
        "target_symbols": symbols,
        "statement_inventory": statements,
        "failure_code_links": failure_links,
        "local_behavioral_contracts": local_contracts,
        "local_repair_guardrails": guardrails,
    }


def run_target_code_context_agent(
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
    language: str,
    failed_tests_context: str = "",
) -> Tuple[dict, dict]:
    context = collect_target_code_context(
        func_name=func_name,
        cand_label=cand_label,
        func_code=func_code,
        source_code=source_code,
        source_path=source_path,
        start_idx=start_idx,
        end_idx=end_idx,
        language=language,
        failed_tests_context=failed_tests_context,
    )
    artifact = write_target_code_context_artifact(
        bug_id=bug_id,
        attempt_index=attempt_index,
        qualified_name=qualified_name,
        candidate_relpath=candidate_relpath,
        target_code_context=context,
    )
    return context, artifact


def _replacement_envelope(
    *,
    source_code: str,
    func_name: str,
    language: str,
    fallback_start: int,
    fallback_end: int,
) -> Tuple[int, int, str, List[str]]:
    notes = []
    node, _, source_bytes = find_function_node(source_code, func_name, language)
    if node is None or source_bytes is None:
        notes.append("tree_sitter_function_node_not_found")
        return fallback_start, fallback_end, "", notes

    start = node.start_byte
    end = node.end_byte
    parent = getattr(node, "parent", None)
    if parent is not None and parent.type in {"template_declaration", "template_declaration_repeat1"}:
        start = parent.start_byte
        end = parent.end_byte
        notes.append(f"replacement_range_expanded_to_parent:{parent.type}")

    start = _expand_to_adjacent_template_prefix(source_code, start)
    if start < node.start_byte and "replacement_range_expanded_to_adjacent_template_prefix" not in notes:
        notes.append("replacement_range_expanded_to_adjacent_template_prefix")

    replacement = source_bytes[start:end].decode("utf-8", errors="replace")
    return start, end, replacement, notes


def _expand_to_adjacent_template_prefix(source_code: str, start_byte: int) -> int:
    source_bytes = source_code.encode("utf-8")
    start_char = len(source_bytes[:start_byte].decode("utf-8", errors="replace"))
    prefix = source_code[:start_char]
    line_start = prefix.rfind("\n") + 1
    prev_end = line_start
    while prev_end > 0:
        prev_start = prefix.rfind("\n", 0, prev_end - 1) + 1
        line = prefix[prev_start:prev_end].strip()
        if not line:
            prev_end = prev_start
            continue
        if line.startswith("template"):
            return len(source_code[:prev_start].encode("utf-8"))
        break
    return start_byte


def _statement_inventory(
    *,
    source_code: str,
    func_code: str,
    function_start_byte: int,
    language: str,
) -> List[dict]:
    tree, source_bytes = parse_tree(func_code, language)
    statements = []
    if tree is not None and source_bytes is not None:
        interesting = {
            "if_statement",
            "for_statement",
            "while_statement",
            "do_statement",
            "switch_statement",
            "return_statement",
            "expression_statement",
            "declaration",
            "assignment_expression",
            "call_expression",
            "goto_statement",
        }
        seen = set()
        for node in walk_nodes(tree.root_node):
            if node.type not in interesting:
                continue
            text = node_text(node, source_bytes).strip()
            if not text:
                continue
            key = (node.start_byte, node.end_byte, node.type)
            if key in seen:
                continue
            seen.add(key)
            abs_start = function_start_byte + node.start_byte
            statements.append(
                {
                    "kind": node.type,
                    "line": line_number_for_byte(source_code, abs_start),
                    "text": clip_text(text, MAX_STATEMENT_TEXT),
                    "signals": _statement_signals(text),
                }
            )
        return statements[:80]

    for idx, line in enumerate(func_code.splitlines(), start=1):
        text = line.strip()
        if not text:
            continue
        if re.search(r"\b(if|for|while|switch|return|goto)\b|=|->|\.|\w+\s*\(", text):
            statements.append(
                {
                    "kind": "line_statement",
                    "line": idx,
                    "text": clip_text(text, MAX_STATEMENT_TEXT),
                    "signals": _statement_signals(text),
                }
            )
    return statements[:80]


def _statement_signals(text: str) -> List[str]:
    signals = []
    if "return" in text:
        signals.append("return")
    if "goto" in text or re.search(r"\bcleanup\b|\berror\b", text):
        signals.append("error_or_cleanup_path")
    if "->" in text or re.search(r"(?<!\w)\*\w+", text):
        signals.append("pointer_deref")
    if "[" in text and "]" in text:
        signals.append("index_or_array_access")
    if re.search(r"\b(memcpy|memmove|strcpy|strncpy|snprintf|sprintf|read|fread)\s*\(", text):
        signals.append("buffer_or_io_call")
    if re.search(r"\b(free|unlink|remove|apply|switch|insert|addchild)\w*\s*\(", text):
        signals.append("state_or_ownership_call")
    if re.search(r"\b[A-Z_][A-Z0-9_]{2,}\s*\(", text):
        signals.append("macro_call")
    if re.search(r"\b(if|while|for|switch)\b", text):
        signals.append("branch_or_loop")
    return signals


def _rank_failure_code_links(
    *,
    statements: List[dict],
    failed_tests_context: str,
    symbols: dict,
) -> List[dict]:
    failure = (failed_tests_context or "").lower()
    symbol_terms = _failure_terms(failure, symbols)
    ranked = []
    for statement in statements:
        text = str(statement.get("text") or "")
        text_lc = text.lower()
        score = 0
        reasons = []
        for term in symbol_terms:
            if term and term.lower() in text_lc:
                score += 4
                reasons.append(f"matches failure/symbol term '{term}'")
        signals = set(statement.get("signals") or [])
        if any(word in failure for word in ("segmentation", "segfault", "null", "crash")):
            if "pointer_deref" in signals:
                score += 5
                reasons.append("failure is crash/null-like and statement dereferences a pointer")
            if "state_or_ownership_call" in signals:
                score += 2
                reasons.append("failure is crash-like and statement mutates ownership/state")
        if any(word in failure for word in ("expected", "actual", "mismatch", "iterator", "out", "size")):
            if "return" in signals:
                score += 5
                reasons.append("failure is output/return mismatch and statement returns a value")
            if any(token in text_lc for token in ("out", "size", "format", "write", "buffer")):
                score += 4
                reasons.append("statement touches output/size/formatting state")
        if any(word in failure for word in ("schema", "ly_errno", "internal error", "not found")):
            if "state_or_ownership_call" in signals or "error_or_cleanup_path" in signals:
                score += 4
                reasons.append("schema/error failure and statement changes state or error path")
        if any(word in failure for word in ("overflow", "underflow", "bounds", "truncated", "length")):
            if "index_or_array_access" in signals or "buffer_or_io_call" in signals:
                score += 5
                reasons.append("bounds/length failure and statement handles buffer/indexing")
        if score > 0:
            ranked.append(
                {
                    "line": statement.get("line"),
                    "kind": statement.get("kind"),
                    "statement": text,
                    "score": score,
                    "reason": "; ".join(reasons[:4]),
                    "confidence": "high" if score >= 8 else "medium" if score >= 4 else "low",
                }
            )
    ranked.sort(key=lambda item: (-item["score"], item.get("line") or 10**9))
    return ranked[:MAX_REPAIR_SITES]


def _failure_terms(failure: str, symbols: dict) -> List[str]:
    terms = []
    for key in ("calls", "fields", "identifiers", "macro_like"):
        for value in symbols.get(key) or []:
            text = str(value or "").strip()
            if len(text) >= 3 and text.lower() in failure:
                terms.append(text)
    for token in re.findall(r"[A-Za-z_][A-Za-z0-9_]{2,}", failure):
        if token not in {"expected", "actual", "failure", "failed", "error", "test"}:
            terms.append(token)
    return list(dict.fromkeys(terms))[:24]


def _local_behavioral_contracts(func_code: str, statements: List[dict]) -> List[dict]:
    contracts = []
    returns = [
        statement.get("text")
        for statement in statements
        if "return" in (statement.get("signals") or [])
    ]
    if returns:
        contracts.append(
            {
                "kind": "return_convention",
                "summary": "Preserve the target function's existing return-value convention.",
                "evidence": returns[:8],
            }
        )
    if re.search(r"\bcleanup\s*:", func_code) or re.search(r"\berror\s*:", func_code):
        contracts.append(
            {
                "kind": "cleanup_convention",
                "summary": "Preserve cleanup/error labels and existing goto-based resource handling.",
                "evidence": [
                    line.strip()
                    for line in func_code.splitlines()
                    if re.search(r"\b(cleanup|error)\s*:|\bgoto\s+(cleanup|error)\b", line)
                ][:10],
            }
        )
    state_lines = [
        statement.get("text")
        for statement in statements
        if "state_or_ownership_call" in (statement.get("signals") or [])
    ]
    if state_lines:
        contracts.append(
            {
                "kind": "state_or_ownership_order",
                "summary": "Do not reorder state/ownership operations unless the failure evidence directly requires it.",
                "evidence": state_lines[:10],
            }
        )
    if re.search(r"\b(assert|LY_CHECK|LOG|FMT_THROW|on_error)\b", func_code):
        contracts.append(
            {
                "kind": "project_error_idiom",
                "summary": "Prefer existing project error macros/handlers already used by this function.",
                "evidence": [
                    line.strip()
                    for line in func_code.splitlines()
                    if re.search(r"\b(assert|LY_CHECK|LOG|FMT_THROW|on_error)\b", line)
                ][:10],
            }
        )
    return contracts


def _repair_guardrails(
    *,
    func_name: str,
    replacement_start: int,
    original_start: int,
    language: str,
    envelope_notes: List[str],
    local_contracts: List[dict],
) -> List[str]:
    guardrails = [
        f"Return exactly one complete replacement unit for {func_name}.",
        "Do not add unrelated helpers, includes, global declarations, tests, or broad refactors.",
        "Preserve the existing signature, template parameters, enclosing scope, and coding style unless the target envelope explicitly says otherwise.",
        "Prefer the smallest local change that satisfies the failure-code link and preserves existing success paths.",
    ]
    if replacement_start != original_start:
        guardrails.append(
            "The replacement range includes prefix text before the function body; include that prefix only as shown in target_envelope.replacement_unit."
        )
    elif language in {"cpp", "c++"}:
        guardrails.append(
            "Do not invent a new template prefix, return type, namespace, or class wrapper outside the shown replacement unit."
        )
    if any(item.get("kind") == "cleanup_convention" for item in local_contracts):
        guardrails.append("Preserve cleanup labels and goto cleanup/error flow.")
    if any(item.get("kind") == "state_or_ownership_order" for item in local_contracts):
        guardrails.append("Treat state/ownership call order as an invariant unless related-code contracts prove a different order.")
    guardrails.extend(envelope_notes)
    return list(dict.fromkeys(guardrails))


def _output_contract(
    *,
    replacement_start: int,
    original_start: int,
    language: str,
    replacement_unit: str,
) -> List[str]:
    rules = [
        "Output raw source only: no markdown, prose, XML, or code fences.",
        "The output will replace target_envelope.replacement_range exactly.",
    ]
    if replacement_start != original_start:
        rules.append("Output must preserve any template/declaration prefix included in target_envelope.replacement_unit.")
    elif language in {"cpp", "c++"} and "template" not in replacement_unit[:200]:
        rules.append("Do not add an external template prefix unless it appears in target_envelope.replacement_unit.")
    return rules
