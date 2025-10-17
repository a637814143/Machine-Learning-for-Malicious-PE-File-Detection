"""Application package bootstrap for the PE detection tool.

This file exists so that modules can reliably import the ``app`` package
when ``python app/main.py`` is executed directly. Without it, Python treats
``app`` as a namespace package which breaks ``from app.tasks import TASKS``
inside :mod:`app.ui.progress_dialog` on some environments.  By turning the
folder into a regular package we guarantee consistent imports across
platforms.
"""

from pathlib import Path
import sys

# Ensure the project root is on ``sys.path`` so that sibling packages such as
# ``scripts`` and ``core`` can be imported even when the application entry
# point is executed as a file.
_PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

__all__ = [
    "_PROJECT_ROOT",
]
