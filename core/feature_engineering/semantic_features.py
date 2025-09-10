"""Extraction of semantic features such as printable strings."""

from __future__ import annotations

import re
from typing import List


def extract_ascii_strings(data: bytes, min_length: int = 5) -> List[str]:
    """Extract ASCII strings from ``data`` with a minimum length."""

    pattern = re.compile(rb"[ -~]{%d,}" % min_length)
    return [m.decode("utf-8", errors="ignore") for m in pattern.findall(data)]


def get_string_features(pe_path: str, min_length: int = 5) -> List[str]:
    """Return a list of printable ASCII strings contained in the file."""

    with open(pe_path, "rb") as f:
        data = f.read()
    return extract_ascii_strings(data, min_length)

