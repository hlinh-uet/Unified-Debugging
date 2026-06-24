import re
from typing import List, Set

from core.apr.config import APR_MAX_LOCAL_HEADER_CONTEXT_CHARS, APR_MAX_SOURCE_CHARS

MAX_RECURSIVE_HEADER_DEPTH = 2
MAX_PROJECT_HEADERS = 16
MAX_HEADER_SURFACE_ITEMS = 24
MAX_SOURCE_SURFACE_ITEMS = 40
MAX_USAGE_EXAMPLES = 8
MAX_USAGE_SEARCH_FILES = 80
MAX_DECLARATION_CHARS = 1600
MAX_USAGE_CHARS = 1400
MAX_SOURCE_EXCERPT_CHARS = APR_MAX_SOURCE_CHARS
MAX_API_CONTRACTS = 40
MAX_MACRO_CONTRACTS = 80
MAX_TYPE_CONTRACTS = 40
MAX_CONTRACT_GROUPS = 16

def _matching_brace_end(source: str, open_idx: int) -> int:
    depth = 0
    quote = ""
    escaped = False
    for idx in range(open_idx, len(source or "")):
        ch = source[idx]
        if quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == quote:
                quote = ""
            continue
        if ch in {"'", '"'}:
            quote = ch
        elif ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                return idx
    return -1

def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", " ", text or "", flags=re.S)
    text = re.sub(r"//.*", " ", text)
    return text

def _dedup_contracts(contracts: List[dict]) -> List[dict]:
    out = []
    seen = set()
    for contract in contracts:
        key = (contract.get("symbol"), contract.get("kind"), contract.get("contract"))
        if key in seen:
            continue
        seen.add(key)
        out.append(contract)
    return out

def _constant_family_key(name: str) -> str:
    tokens = [token for token in str(name or "").split("_") if token]
    if len(tokens) >= 2:
        return "_".join(tokens[:2])
    return tokens[0] if tokens else ""

def _symbol_relevance(name: str, target_symbols: Set[str]) -> int:
    if not name:
        return 0
    if name in target_symbols:
        return 20
    family = _constant_family_key(name)
    for target in target_symbols:
        if not target:
            continue
        if _constant_family_key(target) == family and family:
            return 8
        if name.startswith(target) or target.startswith(name):
            return 5
    return 0
