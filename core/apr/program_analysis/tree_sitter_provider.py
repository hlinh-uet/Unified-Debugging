"""Compatibility alias for :mod:`core.program_analysis.tree_sitter_provider`."""

import sys

from core.program_analysis import tree_sitter_provider as _shared_provider

sys.modules[__name__] = _shared_provider
