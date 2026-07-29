"""Compatibility namespace for the shared program-analysis layer.

New code should import :mod:`core.program_analysis`.
"""

from core.program_analysis import (
    EVIDENCE_RECORD_SCHEMA,
    PROGRAM_EVIDENCE_STORE,
    EvidenceQuery,
    EvidenceRecord,
    ProgramEvidenceStore,
    analyze_target_operations,
    cpg_evidence_tool_definitions,
    cpg_evidence_tool_specs,
    joern_available,
    normalize_cpg_tool_requests,
    query_cpg_tool,
    query_cpg_tools,
    register_program_evidence,
    resolve_target_semantics,
    retrieve_semantic_evidence,
)

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
