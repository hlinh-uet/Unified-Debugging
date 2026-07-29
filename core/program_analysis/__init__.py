"""Shared, policy-free program-analysis providers for FL and APR."""

from .joern_provider import joern_available
from .cpg_tool_schema import cpg_evidence_tool_definitions, cpg_evidence_tool_specs, normalize_cpg_tool_requests
from .clang_provider import resolve_target_semantics, retrieve_semantic_evidence
from .evidence import (
    EVIDENCE_RECORD_SCHEMA,
    PROGRAM_EVIDENCE_STORE,
    EvidenceQuery,
    EvidenceRecord,
    ProgramEvidenceStore,
    register_program_evidence,
)
from .service import analyze_target_operations, query_cpg_tool, query_cpg_tools

__all__ = [
    "EVIDENCE_RECORD_SCHEMA",
    "PROGRAM_EVIDENCE_STORE",
    "EvidenceQuery",
    "EvidenceRecord",
    "ProgramEvidenceStore",
    "analyze_target_operations",
    "cpg_evidence_tool_definitions",
    "cpg_evidence_tool_specs",
    "joern_available",
    "normalize_cpg_tool_requests",
    "query_cpg_tool",
    "query_cpg_tools",
    "register_program_evidence",
    "resolve_target_semantics",
    "retrieve_semantic_evidence",
]
