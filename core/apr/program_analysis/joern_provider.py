"""Compatibility alias for :mod:`core.program_analysis.joern_provider`."""

import sys

from core.program_analysis import joern_provider as _shared_provider

sys.modules[__name__] = _shared_provider
