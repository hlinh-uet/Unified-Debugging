"""Data contracts for target-anchored CPG behavior analysis repair."""

from __future__ import annotations

import hashlib
import json
from typing import Any, Dict, Iterable, List, Optional, Tuple


STATE_VERSION = 5


def new_repair_state(
    *,
    target_contract: Dict[str, Any],
    failure_contract: Dict[str, Any],
    target_inventory: Dict[str, Any],
) -> Dict[str, Any]:
    state = {
        "state_version": STATE_VERSION,
        "architecture": "target_anchored_cpg_behavior_analysis_apr",
        "status": "target_inventory_ready",
        "target_contract": target_contract,
        "failure_contract": failure_contract,
        "target_inventory": target_inventory,
        "behavior_state": {
            "context": {},
            "information_needs": [],
            "query_rounds": [],
            "diagnostics": [],
        },
        "hypothesis_ledger": [],
        "evidence_facts": [],
        "rejected_hypotheses": [],
        "plans": [],
        "validation_history": [],
        "warnings": [],
        "errors": [],
    }
    state["state_id"] = stable_id("repair_state", {
        "target": target_contract.get("target_id"),
        "source_hash": target_contract.get("source_hash"),
        "failure": failure_contract.get("contract_id"),
    })
    return state


def stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, ensure_ascii=True, default=str).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()[:16]}"


def parse_strict_json_object(response: Optional[str]) -> Tuple[Dict[str, Any], str]:
    """Parse an LLM contract without markdown stripping or recovery fallbacks."""
    if not response:
        return {}, "llm_response_empty"
    try:
        parsed = json.loads(response)
    except (TypeError, json.JSONDecodeError):
        return {}, "llm_response_not_strict_json"
    if not isinstance(parsed, dict):
        return {}, "llm_response_json_not_object"
    return parsed, ""


def parse_json_object_with_recovery(response: Optional[str]) -> Tuple[Dict[str, Any], str]:
    """Recover presentation-only LLM JSON defects before giving up on its content."""
    parsed, error = parse_strict_json_object(response)
    if not error:
        return parsed, ""
    if not response:
        return {}, error

    candidate = _strip_json_fence(response.strip())
    candidate = _escape_invalid_json_string_content(candidate)
    try:
        parsed = json.loads(candidate)
    except (TypeError, json.JSONDecodeError):
        return {}, error
    if not isinstance(parsed, dict):
        return {}, "llm_response_json_not_object"
    return parsed, ""


def _strip_json_fence(value: str) -> str:
    lines = value.splitlines()
    if (
        len(lines) >= 3
        and lines[0].strip().lower() in {"```", "```json"}
        and lines[-1].strip() == "```"
    ):
        return "\n".join(lines[1:-1]).strip()
    return value


def _escape_invalid_json_string_content(value: str) -> str:
    """Escape invalid backslashes/control bytes only while inside JSON strings."""
    out: List[str] = []
    in_string = False
    index = 0
    simple_escapes = {'"', "\\", "/", "b", "f", "n", "r", "t"}
    hex_digits = set("0123456789abcdefABCDEF")
    control_escapes = {"\b": "\\b", "\f": "\\f", "\n": "\\n", "\r": "\\r", "\t": "\\t"}

    while index < len(value):
        char = value[index]
        if not in_string:
            out.append(char)
            if char == '"':
                in_string = True
            index += 1
            continue

        if char == '"':
            out.append(char)
            in_string = False
            index += 1
            continue
        if char in control_escapes:
            out.append(control_escapes[char])
            index += 1
            continue
        if char != "\\":
            out.append(char)
            index += 1
            continue

        next_char = value[index + 1] if index + 1 < len(value) else ""
        if next_char in simple_escapes:
            out.extend((char, next_char))
            index += 2
            continue
        if (
            next_char == "u"
            and index + 5 < len(value)
            and all(item in hex_digits for item in value[index + 2:index + 6])
        ):
            out.append(value[index:index + 6])
            index += 6
            continue

        # Preserve the model's intended literal backslash (for example C/C++
        # grouping strings such as \3\2\1\0) by escaping it for JSON.
        out.append("\\\\")
        index += 1

    return "".join(out)


def compact_strings(values: Any, *, limit: int, chars: int) -> List[str]:
    if isinstance(values, str):
        values = [values]
    if not isinstance(values, (list, tuple, set)):
        return []
    out: List[str] = []
    seen = set()
    for value in values:
        text = str(value or "").strip()
        if not text or text in seen:
            continue
        out.append(clip(text, chars))
        seen.add(text)
        if len(out) >= limit:
            break
    return out


def unique_dicts(values: Iterable[Dict[str, Any]], key: str = "id") -> List[Dict[str, Any]]:
    out = []
    seen = set()
    for value in values or []:
        if not isinstance(value, dict):
            continue
        marker = str(value.get(key) or "")
        if not marker or marker in seen:
            continue
        out.append(value)
        seen.add(marker)
    return out


def clip(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return text[:limit].rstrip() + f"\n... [truncated {len(text) - limit} chars]"
