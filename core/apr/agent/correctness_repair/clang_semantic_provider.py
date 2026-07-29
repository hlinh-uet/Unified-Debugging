"""Compatibility alias for the shared Clang semantic provider."""

import sys

from core.program_analysis import clang_provider as _shared_provider

sys.modules[__name__] = _shared_provider
