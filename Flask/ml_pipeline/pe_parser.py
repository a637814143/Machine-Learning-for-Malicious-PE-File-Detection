"""Lightweight PE parser wrapper used by the bundled feature extractors."""

from __future__ import annotations

from pathlib import Path
from typing import Optional

import lief


def parse_pe(path: str) -> Optional[lief.PE.Binary]:
    """Parse ``path`` using :mod:`lief` and return a PE ``Binary`` instance."""

    file_path = Path(path)
    if not file_path.is_file():
        return None

    try:
        data = file_path.read_bytes()
        binary = lief.PE.parse(list(data))
    except Exception:
        return None

    if not isinstance(binary, lief.PE.Binary):
        return None

    return binary
