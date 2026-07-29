"""Shared regression failure context consumed by FL and APR."""

from .builder import (
    FAIL_CONTEXT_SCHEMA,
    build_regression_fail_context,
    reusable_fail_context,
)
from .contract import (
    analyze_test_failure_source,
    build_failure_contract,
)
from .agent import (
    FAIL_CONTEXT_AGENT_SCHEMA,
    fail_context_runtime_dir,
    run_fail_context_agent,
)

__all__ = [
    "FAIL_CONTEXT_AGENT_SCHEMA",
    "FAIL_CONTEXT_SCHEMA",
    "analyze_test_failure_source",
    "build_failure_contract",
    "build_regression_fail_context",
    "fail_context_runtime_dir",
    "reusable_fail_context",
    "run_fail_context_agent",
]
