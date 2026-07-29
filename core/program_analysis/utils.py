"""Small deterministic helpers shared by analysis providers.

These implementations intentionally match the historical correctness-APR
helpers so moving the Clang provider does not change IDs or clipping.
"""

from __future__ import annotations

import hashlib
import json
from typing import Any


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
    return text[:limit].rstrip() + (
        f"\n... [truncated {len(text) - limit} chars]"
    )
