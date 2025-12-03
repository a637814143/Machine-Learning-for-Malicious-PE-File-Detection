from __future__ import annotations

"""Simple data cleaning utilities for PE datasets."""

import hashlib
import struct
import time
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

IMAGE_DOS_SIGNATURE = b"MZ"
IMAGE_NT_SIGNATURE = b"PE\x00\x00"
IMAGE_OPTIONAL_MAGIC_PE32 = 0x10B
IMAGE_OPTIONAL_MAGIC_PE32_PLUS = 0x20B
IMAGE_FILE_DLL = 0x2000
IMAGE_SUBSYSTEM_NATIVE = 0x0001
SUFFIX_ALIASES = {
    ".ocx": ".dll",
    ".scr": ".exe",
    ".bin": ".exe",
}


class CleaningLog(Dict[str, object]):
    """Dictionary-based log used for streaming progress information."""


def _iter_files(target: Path) -> List[Path]:
    if target.is_file():
        return [target]
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"指定路径不存在或不是目录: {target}")
    return [p for p in target.rglob("*") if p.is_file()]


def _normalize_suffix(value: str) -> str:
    """Normalize suffixes so that .ocx/.scr/.bin map to canonical PE suffixes."""

    normalized = value.lower()
    return SUFFIX_ALIASES.get(normalized, normalized)


def _detect_pe_suffix(data: bytes) -> Optional[str]:
    """Return the canonical suffix that matches the PE characteristics, if any."""

    if len(data) < 64 or not data.startswith(IMAGE_DOS_SIGNATURE):
        return None
    try:
        pe_offset = struct.unpack_from("<I", data, 0x3C)[0]
    except struct.error:
        return None
    if pe_offset <= 0 or pe_offset + 24 > len(data):
        return None
    if data[pe_offset : pe_offset + 4] != IMAGE_NT_SIGNATURE:
        return None

    coff_offset = pe_offset + 4
    optional_header_offset = coff_offset + 20
    if optional_header_offset + 2 > len(data):
        return None
    try:
        characteristics = struct.unpack_from("<H", data, coff_offset + 18)[0]
        optional_header_size = struct.unpack_from("<H", data, coff_offset + 16)[0]
    except struct.error:
        return None

    if characteristics & IMAGE_FILE_DLL:
        return ".dll"

    if optional_header_size >= 70 and optional_header_offset + 70 <= len(data):
        try:
            magic = struct.unpack_from("<H", data, optional_header_offset)[0]
        except struct.error:
            magic = None
        if magic in (IMAGE_OPTIONAL_MAGIC_PE32, IMAGE_OPTIONAL_MAGIC_PE32_PLUS):
            try:
                subsystem = struct.unpack_from("<H", data, optional_header_offset + 68)[0]
            except struct.error:
                subsystem = None
            if subsystem == IMAGE_SUBSYSTEM_NATIVE:
                return ".sys"

    return ".exe"


def _ensure_suffix(file_path: Path, required_suffix: str) -> Tuple[Path, Optional[str]]:
    """Rename the file so that it uses the required suffix, avoiding collisions."""

    required_suffix = required_suffix.lower()
    candidate = file_path.with_suffix(required_suffix)
    if candidate == file_path:
        return file_path, None

    def _rename(target: Path) -> Tuple[Path, Optional[str]]:
        try:
            file_path.rename(target)
            return target, f"重命名为 {target.name}"
        except OSError as exc:
            return file_path, f"重命名失败: {exc}"

    if not candidate.exists():
        return _rename(candidate)

    parent = file_path.parent
    base_name = file_path.stem
    counter = 1
    while counter < 1000:
        alt = parent / f"{base_name}_{counter}{required_suffix}"
        if not alt.exists():
            return _rename(alt)
        counter += 1
    return file_path, "重命名失败: 没有可用的文件名"


def DATA_CLEAN(input_path: str, output_dir: Optional[str] = None) -> Iterator[CleaningLog]:
    """Clean PE dataset by removing invalid or duplicate files in place."""

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

        data = file_path.read_bytes()
        if not data:
            remove_reason = "空文件"
            removed_empty += 1
        else:
            detected_suffix = _detect_pe_suffix(data)
            if not detected_suffix:
                remove_reason = "非 PE 文件"
                removed_non_pe += 1
            else:
                digest = hashlib.sha256(data).hexdigest()
                if digest in seen_hashes:
                    remove_reason = "重复文件"
                    removed_duplicates += 1
                else:
                    seen_hashes.add(digest)
                    kept += 1
                    rename_info: Optional[str] = None
                    normalized_suffix = _normalize_suffix(file_path.suffix.lower())
                    if normalized_suffix != detected_suffix:
                        file_path, rename_info = _ensure_suffix(file_path, detected_suffix)

                    suffix_label = detected_suffix.lstrip(".").upper()
                    message = f"保留 {file_path} (识别为 {suffix_label})"
                    if rename_info:
                        message = f"{message}，{rename_info}"

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
