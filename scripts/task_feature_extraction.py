"""Task implementation for bulk feature extraction."""

from typing import Callable, Tuple

from core.feature_engineering import extract_from_directory

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def extract_features_task(
    args: Tuple, progress: ProgressCallback, text: TextCallback
) -> None:
    """Extract raw features for every PE file inside a directory."""
    if len(args) < 2:
        text("需要提供输入文件夹和输出路径")
        return

    src, dst = args[0], args[1]

    max_workers = int(args[2]) if len(args) > 2 and str(args[2]).isdigit() else None

    realtime_write = True
    if len(args) > 3:
        flag = str(args[3]).lower()
        if flag in {"false", "0", "no", "batch"}:
            realtime_write = False

    extract_from_directory(
        src,
        dst,
        progress_callback=progress,
        text_callback=text,
        max_workers=max_workers,
        realtime_write=realtime_write,
    )
    text("特征提取完成")

