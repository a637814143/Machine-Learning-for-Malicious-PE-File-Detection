from __future__ import annotations
from pathlib import Path
from typing import Optional
import lief


def parse_pe(path: str) -> Optional[lief.PE.Binary]:
    """
    PE 解析类
    :param path: pe path
    :return: binary
    """
    file_path = Path(path)
    if not file_path.is_file():
        return None

    try:
        data = file_path.read_bytes()
        binary = lief.PE.parse(list(data))
    except Exception as e:
        print(f'[ERROR] {e}')
        return None

    if not isinstance(binary, lief.PE.Binary):
        return None

    return binary
