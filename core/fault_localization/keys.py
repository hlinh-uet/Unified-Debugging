"""Stable score-key helpers shared by FL, APR, and evaluation."""

from __future__ import annotations

import os
import re
from typing import Dict


def sort_scores(scores: Dict[str, float]) -> Dict[str, float]:
    return dict(sorted(scores.items(), key=lambda item: (-item[1], item[0])))


def extract_file_from_key(method_key: str) -> str:
    """Return the basename before the first non-scope ``:`` separator."""
    match = re.search(r"(?<!:):(?!:)", str(method_key or ""))
    if match:
        file_part = method_key[:match.start()]
        return os.path.basename(file_part) if file_part else method_key
    if "::" in method_key:
        return os.path.basename(method_key.rsplit("::", 1)[0])
    return method_key


def extract_class_from_key(method_key: str) -> str | None:
    """Return ``file:namespace::class`` for a scoped C++ function key."""
    match = re.search(r"(?<!:):(?!:)", str(method_key or ""))
    if not match:
        return None
    function_part = method_key[match.end():]
    if "::" not in function_part:
        return None
    class_part = function_part.rsplit("::", 1)[0]
    if not class_part:
        return None
    return f"{extract_file_from_key(method_key)}:{class_part}"


# Private aliases preserve the imports used by the existing APR/main code.
_sort_scores = sort_scores
_extract_file_from_key = extract_file_from_key
_extract_class_from_key = extract_class_from_key
