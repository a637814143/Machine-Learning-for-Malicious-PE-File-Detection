"""Utilities for importing LightGBM safely under NumPy 2.x."""

from __future__ import annotations

import contextlib
import importlib
import importlib.abc
import io
import sys
import traceback
import warnings
from types import ModuleType
from typing import Optional

# Reason string used in warning + failure message when matplotlib is disabled.
_MATPLOTLIB_BLOCK_REASON = (
    "检测到当前环境中的 Matplotlib 无法与 NumPy 2.x 协同工作，"
    "已自动禁用其导入以避免 LightGBM 在初始化阶段崩溃。"
    "如果需要绘图功能，请升级 Matplotlib 到支持 NumPy 2 的版本后重新启动程序。"
)

_MATPLOTLIB_BLOCKER: Optional["_MatplotlibBlocker"] = None


class _MatplotlibBlocker(importlib.abc.MetaPathFinder):
    """Meta path finder that forcefully blocks matplotlib imports."""

    def __init__(self, reason: str) -> None:
        self._reason = reason

    def find_spec(self, fullname: str, path, target=None):  # type: ignore[override]
        if fullname == "matplotlib" or fullname.startswith("matplotlib."):
            raise ModuleNotFoundError(self._reason)
        return None


def _should_block_matplotlib(exc: BaseException) -> bool:
    """Return True if the exception matches the known NumPy 2 / matplotlib ABI issue."""

    details = "".join(traceback.format_exception(exc)).lower()
    return "_array_api" in details and "matplotlib" in details


def _disable_matplotlib_imports() -> None:
    """Remove partially imported matplotlib modules and block future imports."""

    global _MATPLOTLIB_BLOCKER

    # Ensure we do not retain any half-initialised modules that would re-trigger crashes.
    for name in list(sys.modules):
        if name == "matplotlib" or name.startswith("matplotlib."):
            sys.modules.pop(name, None)

    if _MATPLOTLIB_BLOCKER is None:
        blocker = _MatplotlibBlocker(_MATPLOTLIB_BLOCK_REASON)
        sys.meta_path.insert(0, blocker)
        _MATPLOTLIB_BLOCKER = blocker

    warnings.warn(_MATPLOTLIB_BLOCK_REASON, RuntimeWarning, stacklevel=3)


def _emit_captured(stderr_buffer: str) -> None:
    """Replay suppressed stderr output when we re-raise other errors."""

    if stderr_buffer:
        sys.stderr.write(stderr_buffer)


def import_lightgbm() -> ModuleType:
    """Import LightGBM, auto-disabling matplotlib when encountering the NumPy 2 ABI crash."""

    buffer = io.StringIO()
    try:
        with contextlib.redirect_stderr(buffer):
            return importlib.import_module("lightgbm")
    except ModuleNotFoundError:
        _emit_captured(buffer.getvalue())
        # Propagate to caller so they can surface a friendly message when LightGBM truly missing.
        raise
    except Exception as exc:
        captured = buffer.getvalue()
        if _should_block_matplotlib(exc):
            _disable_matplotlib_imports()
            try:
                with contextlib.redirect_stderr(io.StringIO()):
                    return importlib.import_module("lightgbm")
            except Exception as retry_exc:  # pragma: no cover - defensive fallback
                raise RuntimeError(
                    "在禁用 Matplotlib 后仍无法导入 LightGBM，请确认依赖已完整安装。"
                ) from retry_exc
        _emit_captured(captured)
        raise

