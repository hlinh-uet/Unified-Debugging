"""Compatibility alias for :mod:`core.program_analysis.cpg_tool_schema`."""

import sys

from core.program_analysis import cpg_tool_schema as _shared_schema

sys.modules[__name__] = _shared_schema
