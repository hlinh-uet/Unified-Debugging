"""Compatibility alias for :mod:`core.program_analysis.service`."""

import sys

from core.program_analysis import service as _shared_service

sys.modules[__name__] = _shared_service
