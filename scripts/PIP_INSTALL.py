"""Utilities for installing Python dependencies used by the project."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path
from typing import Iterator, Optional

# Resolve the project root dynamically so the script works even when executed
# without installing ``scripts`` as a package.
ROOT = Path(__file__).resolve().parents[1]


def INSTALL(requirements_path: Optional[str] = None) -> Iterator[str]:
    """Install dependencies listed in ``requirements.txt``.

    Parameters
    ----------
    requirements_path:
        Optional custom path to a requirements file.  When omitted the
        project's default ``requirements.txt`` (at the repository root) is
        used.

    Yields
    ------
    str
        Incremental output lines produced by ``pip`` while installing the
        dependencies.  The caller can stream these lines to a log or GUI.

    Raises
    ------
    FileNotFoundError
        If the requirements file cannot be located.
    RuntimeError
        If the pip process exits with a non-zero status code.
    """

    path = Path(requirements_path) if requirements_path else ROOT / "requirements.txt"
    if not path.exists():
        raise FileNotFoundError(f"未找到依赖文件: {path}")

    cmd = [sys.executable, "-m", "pip", "install", "-r", str(path)]
    process = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        bufsize=1,
    )

    if not process.stdout:  # pragma: no cover - defensive, stdout should exist
        process.wait()
        raise RuntimeError("无法捕获 pip 输出")

    try:
        for line in process.stdout:
            yield line.rstrip()
    finally:
        process.stdout.close()
        process.wait()

    if process.returncode != 0:
        raise RuntimeError(f"pip install 返回非零状态码: {process.returncode}")

    yield "依赖安装完成"
