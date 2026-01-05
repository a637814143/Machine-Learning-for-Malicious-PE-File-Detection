"""Task implementation for installing runtime dependencies."""

from typing import Callable, Tuple

from scripts.PIP_INSTALL import INSTALL as install_dependencies

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def install_dependencies_task(
    args: Tuple, progress: ProgressCallback, text: TextCallback
) -> None:
    """Install dependencies defined inside scripts/PIP_INSTALL."""
    progress(0)
    text("开始安装依赖环境")
    try:
        for idx, line in enumerate(install_dependencies(), 1):
            if line:
                text(str(line))
            if idx % 5 == 0:
                progress(min(95, 5 + idx))
    except Exception as exc:
        text(f"安装依赖失败: {exc}")
        progress(0)
        return

    progress(100)

