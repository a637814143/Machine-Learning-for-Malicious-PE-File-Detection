"""Task implementation for transforming extracted features into vectors."""

from typing import Callable, Tuple

from core.feature_engineering import vectorize_feature_file

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def feature_vector_task(args: Tuple, progress: ProgressCallback, text: TextCallback) -> None:
    """Vectorise previously extracted feature files."""
    if len(args) < 2:
        text("需要提供特征文件路径和输出路径")
        return

    src, dst = args[0], args[1]

    max_workers = int(args[2]) if len(args) > 2 and str(args[2]).isdigit() else None

    realtime_write = True
    if len(args) > 3:
        flag = str(args[3]).lower()
        if flag in {"false", "0", "no", "batch"}:
            realtime_write = False

    vectorize_feature_file(
        src,
        dst,
        progress_callback=progress,
        text_callback=text,
        max_workers=max_workers,
        realtime_write=realtime_write,
    )
    text("特征转换完成")

