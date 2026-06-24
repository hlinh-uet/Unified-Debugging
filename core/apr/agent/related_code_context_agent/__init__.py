"""RelatedCodeContext package: related source/header retrieval and API contract evidence."""

from .orchestrator import collect_related_code_context, run_related_code_context_agent
from .retrieval import trim_source_for_context

__all__ = [
    "collect_related_code_context",
    "run_related_code_context_agent",
    "trim_source_for_context",
]
