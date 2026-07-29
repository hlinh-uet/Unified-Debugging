"""Shared evidence contracts and an in-process evidence registry.

The registry stores provider output without interpreting it.  FL and APR keep
their own planning/ranking policies; this module only gives both stages a
common identity and transport contract.
"""

from __future__ import annotations

import copy
import threading
from collections import OrderedDict
from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional


EVIDENCE_RECORD_SCHEMA = "unified_debugging.program_evidence.v1"


@dataclass(frozen=True)
class EvidenceQuery:
    """Stable identity for one already-defined analysis request."""

    namespace: str
    identity: str
    source_root: str = ""
    source_path: str = ""
    symbol: str = ""
    parameters: Mapping[str, Any] = field(default_factory=dict)


@dataclass
class EvidenceRecord:
    """Provider payload plus provenance; the payload is never normalized."""

    query: EvidenceQuery
    payload: Any
    producer: str
    metadata: Dict[str, Any] = field(default_factory=dict)
    schema: str = EVIDENCE_RECORD_SCHEMA


class ProgramEvidenceStore:
    """Small process-wide LRU registry shared by FL and APR.

    Consumers receive deep copies so one stage cannot mutate evidence owned by
    another.  Capacity is per namespace and affects only this registry, not
    the providers' existing persistent-cache policies.
    """

    def __init__(self, *, max_records_per_namespace: int = 256) -> None:
        self._max_records = max(1, int(max_records_per_namespace))
        self._records: Dict[
            str, "OrderedDict[str, EvidenceRecord]"
        ] = {}
        self._lock = threading.RLock()

    def register(
        self,
        query: EvidenceQuery,
        payload: Any,
        *,
        producer: str,
        metadata: Optional[Mapping[str, Any]] = None,
        retain_payload_reference: bool = False,
    ) -> EvidenceRecord:
        record = EvidenceRecord(
            query=query,
            payload=(
                payload
                if retain_payload_reference
                else copy.deepcopy(payload)
            ),
            producer=str(producer or ""),
            metadata=copy.deepcopy(dict(metadata or {})),
        )
        with self._lock:
            namespace = self._records.setdefault(
                query.namespace,
                OrderedDict(),
            )
            namespace[query.identity] = record
            namespace.move_to_end(query.identity)
            while len(namespace) > self._max_records:
                namespace.popitem(last=False)
        return (
            copy.copy(record)
            if retain_payload_reference
            else copy.deepcopy(record)
        )

    def lookup(self, query: EvidenceQuery) -> Optional[EvidenceRecord]:
        with self._lock:
            namespace = self._records.get(query.namespace)
            record = (
                namespace.get(query.identity)
                if namespace is not None
                else None
            )
            if record is None:
                return None
            namespace.move_to_end(query.identity)
            return copy.deepcopy(record)

    def clear(self, namespace: str = "") -> None:
        """Clear registry state, primarily for deterministic test isolation."""
        with self._lock:
            if namespace:
                self._records.pop(namespace, None)
            else:
                self._records.clear()


PROGRAM_EVIDENCE_STORE = ProgramEvidenceStore()


def register_program_evidence(
    *,
    namespace: str,
    identity: str,
    payload: Any,
    producer: str,
    source_root: str = "",
    source_path: str = "",
    symbol: str = "",
    parameters: Optional[Mapping[str, Any]] = None,
    metadata: Optional[Mapping[str, Any]] = None,
    retain_payload_reference: bool = False,
) -> EvidenceRecord:
    """Register an existing provider result without changing that result."""
    query = EvidenceQuery(
        namespace=str(namespace),
        identity=str(identity),
        source_root=str(source_root or ""),
        source_path=str(source_path or ""),
        symbol=str(symbol or ""),
        parameters=dict(parameters or {}),
    )
    return PROGRAM_EVIDENCE_STORE.register(
        query,
        payload,
        producer=producer,
        metadata=metadata,
        retain_payload_reference=retain_payload_reference,
    )
