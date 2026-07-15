from dataclasses import dataclass, field
from typing import Any, Dict, List, Set


@dataclass
class TargetAnalysisRequest:
    func_code: str
    replacement_target: Dict[str, Any]
    related_code_context: Dict[str, Any]
    source_path: str = ""
    source_root: str = ""
    function_name: str = ""
    language: str = ""


@dataclass
class TargetOperationAnalysis:
    engine: Dict[str, Any]
    operations: List[Dict[str, Any]] = field(default_factory=list)
    uncertainties: List[str] = field(default_factory=list)


@dataclass
class RepairTargetSet:
    """Source-backed target candidates; ambiguity is explicit, never top-1 hidden."""
    requested_name: str
    candidates: List[Dict[str, Any]] = field(default_factory=list)
    status: str = "not_found"
    uncertainties: List[str] = field(default_factory=list)

    @property
    def resolved(self) -> bool:
        return self.status == "resolved" and len(self.candidates) == 1


def replacement_language(replacement_target: Dict[str, Any], fallback: str = "c") -> str:
    language = str(((replacement_target or {}).get("replacement_envelope") or {}).get("language") or fallback).lower()
    if language in ("c++", "cc", "cxx"):
        return "cpp"
    return "cpp" if language == "hpp" else language or fallback


def replacement_start_line(replacement_target: Dict[str, Any]) -> int:
    try:
        return int((((replacement_target or {}).get("replacement_envelope") or {}).get("replacement_range") or {}).get("start_line") or 1)
    except Exception:
        return 1


def replacement_source_path(replacement_target: Dict[str, Any]) -> str:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    identity = (replacement_target or {}).get("replacement_identity") or {}
    return str(envelope.get("source_path") or identity.get("source_path") or "")


def replacement_function_name(replacement_target: Dict[str, Any]) -> str:
    envelope = (replacement_target or {}).get("replacement_envelope") or {}
    identity = (replacement_target or {}).get("replacement_identity") or {}
    return str(identity.get("resolved_name") or identity.get("qualified_name") or envelope.get("resolved_function_name") or envelope.get("function_name") or "")


def replacement_function_signature(replacement_target: Dict[str, Any]) -> str:
    identity = (replacement_target or {}).get("replacement_identity") or {}
    return str(identity.get("signature") or "")


def semantic_names(context: Dict[str, Any]) -> Set[str]:
    names: Set[str] = set()
    vocab = (context or {}).get("semantic_vocabulary") or {}
    for section in ("macros", "enum_or_flags", "helpers", "fields", "types"):
        for item in vocab.get(section) or []:
            if not isinstance(item, dict):
                continue
            for key in ("name", "symbol"):
                value = str(item.get(key) or "").strip()
                if value:
                    names.add(value)
            for key in ("allowed_constants", "constants"):
                names.update(str(value) for value in (item.get(key) or []) if value)
    scope = (context or {}).get("scope_aware_symbol_contract") or {}
    for key in (
        "existing_calls",
        "existing_macros_or_enum_constants",
        "existing_types",
        "existing_member_fields",
        "introducible_functions",
        "introducible_macros_or_enum_constants",
        "introducible_types",
    ):
        names.update(str(value) for value in (scope.get(key) or []) if value)
    return names
