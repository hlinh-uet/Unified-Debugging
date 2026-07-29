"""Small serialization helpers owned by the shared context layer."""

from __future__ import annotations

import hashlib
import json
from typing import Any, List


def stable_id(prefix: str, value: Any) -> str:
    encoded = json.dumps(
        value,
        sort_keys=True,
        ensure_ascii=True,
        default=str,
    ).encode("utf-8")
    return f"{prefix}:{hashlib.sha256(encoded).hexdigest()[:16]}"


def clip(value: Any, limit: int) -> str:
    text = str(value or "").strip()
    if len(text) <= limit:
        return text
    return (
        text[:limit].rstrip()
        + f"\n... [truncated {len(text) - limit} chars]"
    )


def compact_strings(
    values: Any,
    *,
    limit: int,
    chars: int,
) -> List[str]:
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
