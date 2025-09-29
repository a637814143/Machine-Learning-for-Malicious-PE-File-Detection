from __future__ import annotations

"""Simple data cleaning utilities for PE datasets."""

import hashlib
import shutil
from pathlib import Path
from typing import Dict, Iterator, List, Optional

PE_SUFFIXES = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}


class CleaningLog(Dict[str, object]):
    """Dictionary-based log used for streaming progress information."""


def _iter_files(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"指定路径不存在或不是目录: {target}")
    return [p for p in target.rglob("*") if p.is_file()]


def DATA_CLEAN(input_path: str, output_dir: str) -> Iterator[CleaningLog]:
    """Clean PE dataset by filtering invalid files and deduplicating content.

    Parameters
    ----------
    input_path:
        File or directory containing raw samples.
    output_dir:
        Destination directory where the cleaned files will be written.

    Yields
    ------
    CleaningLog
        Structured events describing the progress of the cleaning process.
    """

    src = Path(input_path).expanduser().resolve()
    dst_root = Path(output_dir).expanduser().resolve()
    dst_root.mkdir(parents=True, exist_ok=True)
    cleaned_dir = dst_root / f"cleaned_{src.name or 'dataset'}"
    cleaned_dir.mkdir(parents=True, exist_ok=True)

    files = _iter_files(src)
    total = len(files)
    yield CleaningLog(type="start", total=total, output=str(cleaned_dir))

    if total == 0:
        yield CleaningLog(
            type="finished",
            total=0,
            kept=0,
            skipped=0,
            duplicates=0,
            output=str(cleaned_dir),
        )
        return

    seen_hashes: set[str] = set()
    kept = 0
    skipped = 0
    duplicates = 0

    for idx, file_path in enumerate(files, 1):
        message: Optional[str] = None
        if file_path.suffix.lower() not in PE_SUFFIXES:
            skipped += 1
            message = f"跳过非PE文件: {file_path}"
        else:
            data = file_path.read_bytes()
            if not data:
                skipped += 1
                message = f"跳过空文件: {file_path}"
            else:
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen_hashes:
                    duplicates += 1
                    message = f"跳过重复文件: {file_path}"
                else:
                    seen_hashes.add(digest)
                    kept += 1
                    destination = cleaned_dir / file_path.name
                    shutil.copy2(file_path, destination)
                    message = f"复制 {file_path} -> {destination}"
        yield CleaningLog(
            type="progress",
            index=idx,
            total=total,
            message=message,
        )

    yield CleaningLog(
        type="finished",
        total=total,
        kept=kept,
        skipped=skipped,
        duplicates=duplicates,
        output=str(cleaned_dir),
    )
