"""LLM-based APR package.

Public entrypoints stay small for backward compatibility. Implementation is
split by responsibility:
- agent/: CodeContext, FailContext, and FixAgent logic
- pipeline.py: APR orchestration
- llm.py: OpenAI/OpenRouter-compatible client
- apr_utils.py: source and candidate-result helpers
- artifacts.py/validation.py: output and sandbox helpers
"""

__all__ = ["call_llm", "run_apr_pipeline", "validate_patch"]


def __getattr__(name):
    if name == "call_llm":
        from core.apr.llm import call_llm
        return call_llm
    if name == "run_apr_pipeline":
        from core.apr.pipeline import run_apr_pipeline
        return run_apr_pipeline
    if name == "validate_patch":
        from core.apr.validation import validate_patch
        return validate_patch
    raise AttributeError(f"module 'core.apr' has no attribute {name!r}")
