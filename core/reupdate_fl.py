"""Compatibility entrypoint for the relocated FL update module."""

import os
import sys

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from core.fault_localization.update import *  # noqa: F401,F403
from core.fault_localization.update import main


if __name__ == "__main__":
    main()
