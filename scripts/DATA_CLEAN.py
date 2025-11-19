
from __future__ import annotations

"""Simple data cleaning utilities for PE datasets."""

import hashlib
import time
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


def DATA_CLEAN(input_path: str, output_dir: Optional[str] = None) -> Iterator[CleaningLog]:
    """Clean PE dataset by 删除无效或重复的文件，直接在原目录中清理。

    Parameters
    ----------
    input_path:
        File or directory containing raw samples.
    output_dir:
        Optional directory used to 保存清洗日志。文件将被原地删除，而不是复制到新的目录。

    Yields
    ------
    CleaningLog
        Structured events describing the progress of the cleaning process.
    """

    src = Path(input_path).expanduser().resolve()
    log_root: Optional[Path] = None
    log_path: Optional[Path] = None
    log_file: Optional[Path] = None
    if output_dir:
        log_root = Path(output_dir).expanduser().resolve()
        log_root.mkdir(parents=True, exist_ok=True)
        log_path = log_root / f"clean_log_{time.strftime('%Y%m%d_%H%M%S')}"

    files = _iter_files(src)
    total = len(files)
    yield CleaningLog(type="start", total=total, log_target=str(log_path) if log_path else None)

    if total == 0:
        yield CleaningLog(
            type="finished",
            total=0,
            kept=0,
            removed=0,
            removed_empty=0,
            removed_non_pe=0,
            removed_duplicates=0,
            log=str(log_file) if log_file else None,
        )
        return

    seen_hashes: set[str] = set()
    kept = 0
    removed = 0
    removed_non_pe = 0
    removed_empty = 0
    removed_duplicates = 0
    errors = 0
    log_lines: List[str] = []

    for idx, file_path in enumerate(files, 1):
        message: Optional[str] = None
        action_detail: Optional[str] = None
        remove_reason: Optional[str] = None

        if file_path.suffix.lower() not in PE_SUFFIXES:
            remove_reason = "非PE文件"
            removed_non_pe += 1
        else:
            data = file_path.read_bytes()
            if not data:
                remove_reason = "空文件"
                removed_empty += 1
            else:
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen_hashes:
                    remove_reason = "重复文件"
                    removed_duplicates += 1
                else:
                    seen_hashes.add(digest)
                    kept += 1
                    message = f"保留 {file_path}"

        if remove_reason:
            try:
                file_path.unlink()
                removed += 1
                action_detail = f"删除 {file_path} ({remove_reason})"
            except OSError as exc:  # pragma: no cover - runtime issues
                errors += 1
                action_detail = f"删除失败 {file_path} ({remove_reason}) -> {exc}"

        log_entry = action_detail or message
        if log_entry:
            log_lines.append(log_entry)

        yield CleaningLog(
            type="progress",
            index=idx,
            total=total,
            message=action_detail or message,
        )

    if log_path and log_lines:
        log_file = log_path.with_suffix(".log")
        log_file.write_text("\n".join(log_lines), encoding="utf-8")

    yield CleaningLog(
        type="finished",
        total=total,
        kept=kept,
        removed=removed,
        removed_empty=removed_empty,
        removed_non_pe=removed_non_pe,
        removed_duplicates=removed_duplicates,
        errors=errors,
        log=str(log_file) if log_file else None,
    )
