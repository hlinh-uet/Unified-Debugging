"""Compatibility alias for :mod:`core.program_analysis.source_scan_provider`."""

import sys

from core.program_analysis import source_scan_provider as _shared_provider

sys.modules[__name__] = _shared_provider
