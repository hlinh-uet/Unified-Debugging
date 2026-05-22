"""Backward-compatible APR entrypoint.

Implementation lives in ``core.apr`` modules.
"""

from core.apr.llm import call_llm
from core.apr.pipeline import run_apr_pipeline
from core.apr.validation import validate_patch

__all__ = ["call_llm", "run_apr_pipeline", "validate_patch"]


if __name__ == "__main__":
    run_apr_pipeline()
