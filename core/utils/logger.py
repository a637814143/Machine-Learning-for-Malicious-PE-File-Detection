# core/utils/logger.py

"""Simple log helpers shared across the application.

This module centralises log handling so that the Qt GUI and the background
tasks interact with the same set of log files.  Logs are stored inside the
``logs`` directory at the project root by default.
"""

from __future__ import annotations

from pathlib import Path
from typing import List, Sequence

from scripts.ROOT_PATH import ROOT

# 默认日志目录和文件名
LOG_DIR = ROOT / "logs"
DEFAULT_LOG_NAME = "app.log"
LOG_PATH = LOG_DIR / DEFAULT_LOG_NAME

# 默认匹配的日志文件扩展名
DEFAULT_PATTERNS: Sequence[str] = ("*.log", "*.txt")


def _resolve_log_path(
    log_name: str | Path | None = None,
    log_dir: Path | None = None,
) -> Path:
    """Resolve the final path for a log file.

    ``log_name`` may be either an absolute path or a relative file name.  If it
    is relative (or ``None``) the value is joined with ``log_dir`` which in turn
    defaults to :data:`LOG_DIR`.
    """

    base_dir = Path(log_dir) if log_dir else LOG_DIR
    base_dir.mkdir(parents=True, exist_ok=True)

    if log_name is None:
        return base_dir / DEFAULT_LOG_NAME

    log_path = Path(log_name)
    if not log_path.is_absolute():
        log_path = base_dir / log_path
    return log_path


def set_log(
    log_info: str,
    log_name: str | Path | None = None,
    log_dir: Path | None = None,
) -> bool:
    """Write a log entry to ``log_name`` inside ``log_dir``.

    Parameters
    ----------
    log_info:
        The message to append.  A trailing newline is added automatically.
    log_name:
        Optional target file name.  Defaults to :data:`DEFAULT_LOG_NAME`.
    log_dir:
        Optional base directory.  Defaults to :data:`LOG_DIR`.
    """

    log_path = _resolve_log_path(log_name, log_dir)
    # ``rstrip`` avoids creating blank lines when the caller already appends
    # ``\n`` to the message.
    text = f"{log_info.rstrip()}\n"
    with open(log_path, "a", encoding="utf-8") as file:
        file.write(text)
    return True


def read_log(
    log_name: str | Path | None = None,
    log_dir: Path | None = None,
    max_lines: int | None = None,
) -> List[str]:
    """Return the content of a log file as a list of lines.

    Parameters
    ----------
    log_name, log_dir:
        See :func:`set_log`.
    max_lines:
        If provided and greater than zero, only the last ``max_lines`` entries
        are returned.
    """

    log_path = _resolve_log_path(log_name, log_dir)
    if not log_path.exists():
        return []

    with open(log_path, "r", encoding="utf-8") as file:
        lines = file.readlines()

    if max_lines is not None and max_lines > 0:
        return lines[-max_lines:]
    return lines


def list_logs(
    log_dir: Path | None = None,
    patterns: Sequence[str] | None = None,
) -> List[Path]:
    """List available log files in ``log_dir`` sorted by modification time."""

    base_dir = Path(log_dir) if log_dir else LOG_DIR
    base_dir.mkdir(parents=True, exist_ok=True)

    patterns = tuple(patterns) if patterns else tuple(DEFAULT_PATTERNS)
    matched: list[Path] = []
    seen: set[Path] = set()

    for pattern in patterns:
        for path in base_dir.glob(pattern):
            if path.is_file() and path not in seen:
                matched.append(path)
                seen.add(path)

    # 如果按照扩展名没有找到文件，则回退到列出所有文件
    if not matched:
        for path in base_dir.glob("*"):
            if path.is_file() and path not in seen:
                matched.append(path)
                seen.add(path)

    matched.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    return matched


__all__ = [
    "DEFAULT_LOG_NAME",
    "LOG_DIR",
    "LOG_PATH",
    "list_logs",
    "read_log",
    "set_log",
]
