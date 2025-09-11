
"""Wrapper utilities around the LIEF PE parser.

This module provides a thin abstraction so the rest of the feature
extraction code only deals with a simple `parse_pe` function.  Using a
wrapper makes it easier to stub or mock during tests.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import lief


def parse_pe(path: str) -> Optional[lief.PE.Binary]:
    """Parse *path* using :mod:`lief` and return a PE ``Binary``.

    The function catches exceptions and returns ``None`` when the file cannot
    be parsed.  This mirrors the behaviour of many feature extraction
    pipelines where unparsable files are simply skipped.
    """

    file_path = Path(path)
    if not file_path.is_file():
        return None

    try:
        binary = lief.parse(str(file_path))
    except Exception:
        return None

    # Ensure we indeed parsed a PE file
    if not isinstance(binary, lief.PE.Binary):
        return None

    return binary
