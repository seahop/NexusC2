"""Shared fixtures for NexusC2 client tests.

Mocks PyQt6 and other GUI dependencies so tests can run headless
(no display server required).
"""

import sys
import types
from unittest.mock import MagicMock

# ---------------------------------------------------------------------------
# Mock PyQt6 before any project code tries to import it.
# ---------------------------------------------------------------------------


class _AutoMockModule(types.ModuleType):
    """A module that returns a MagicMock for any attribute not explicitly set.

    This avoids needing to enumerate every PyQt6 class name.
    ``from PyQt6.QtWidgets import QTabBar`` will get a MagicMock
    instead of raising ImportError.
    """

    def __getattr__(self, name):
        if name.startswith("__") and name.endswith("__"):
            raise AttributeError(name)
        return MagicMock


def _install_pyqt6_mocks():
    """Create comprehensive mock modules for PyQt6 so all imports succeed."""

    pyqt6 = _AutoMockModule("PyQt6")

    # QtWidgets
    qtwidgets = _AutoMockModule("PyQt6.QtWidgets")

    # QtCore -- need real-ish pyqtSlot / pyqtSignal for decorator usage
    qtcore = _AutoMockModule("PyQt6.QtCore")
    qtcore.pyqtSlot = lambda *a, **kw: (lambda fn: fn)
    qtcore.pyqtSignal = MagicMock

    # QtGui
    qtgui = _AutoMockModule("PyQt6.QtGui")

    # QtMultimedia (used by notifications widget)
    qtmultimedia = _AutoMockModule("PyQt6.QtMultimedia")

    for name, mod in [
        ("PyQt6", pyqt6),
        ("PyQt6.QtWidgets", qtwidgets),
        ("PyQt6.QtCore", qtcore),
        ("PyQt6.QtGui", qtgui),
        ("PyQt6.QtMultimedia", qtmultimedia),
    ]:
        sys.modules[name] = mod


# Install mocks at import time so conftest is loaded before test collection
_install_pyqt6_mocks()

# ---------------------------------------------------------------------------
# Path setup: allow ``from utils.xxx`` and ``from gui.xxx`` imports
# that mirror how the application itself resolves them.
# ---------------------------------------------------------------------------

_client_src = str(__import__("pathlib").Path(__file__).resolve().parent.parent / "src")
if _client_src not in sys.path:
    sys.path.insert(0, _client_src)

# ---------------------------------------------------------------------------
# Pre-mock the logger utility used across the application
# ---------------------------------------------------------------------------

sys.modules.setdefault(
    "utils.logger",
    MagicMock(get_logger=MagicMock(return_value=MagicMock())),
)
