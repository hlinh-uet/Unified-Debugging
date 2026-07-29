"""Compatibility alias for :mod:`core.program_analysis.models`."""

import sys

from core.program_analysis import models as _shared_models

sys.modules[__name__] = _shared_models
