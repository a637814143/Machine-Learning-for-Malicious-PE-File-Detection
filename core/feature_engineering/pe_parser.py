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
        # Parsing from raw bytes avoids issues with non-ASCII paths on
        # some platforms (e.g. Windows).
        data = file_path.read_bytes()
        binary = lief.PE.parse(list(data))
    except Exception:
        return None

    # Ensure we indeed parsed a PE file
    if not isinstance(binary, lief.PE.Binary):
        return None

    return binary
