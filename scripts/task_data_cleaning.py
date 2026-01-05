"""Task implementation for cleaning raw PE corpora."""

from typing import Callable, Tuple

from scripts.DATA_CLEAN import DATA_CLEAN

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def data_cleaning_task(args: Tuple, progress: ProgressCallback, text: TextCallback) -> None:
    """Clean a directory of samples and emit streaming progress."""
    if not args:
        text("需要提供输入路径")
        return

    src = args[0]
    dst = next((a for a in args[1:] if a and not str(a).isdigit()), None)
    try:
        iterator = DATA_CLEAN(src, dst)
    except Exception as exc:
        text(f"数据清洗失败: {exc}")
        return

    total = 0
    try:
        for entry in iterator:
            entry_type = entry.get("type")
            if entry_type == "start":
                total = int(entry.get("total", 0))
                log_target = entry.get("log_target") or entry.get("log")
                intro = f"开始执行数据清洗，共 {total} 个待处理文件。"
                if log_target:
                    intro += f" 日志文件保存为: {log_target}"
                text(intro)
                if total == 0:
                    progress(100)
            elif entry_type == "progress":
                idx = int(entry.get("index", 0))
                total = int(entry.get("total", total)) or total
                message = entry.get("message")
                if message:
                    text(str(message))
                if total:
                    progress(int(idx / total * 100))
            elif entry_type == "finished":
                summary = (
                    "数据清洗完成，保留 {kept} 条，删除 {removed} 条，非 PE {removed_non_pe} 条，"
                    "零字节 {removed_empty} 条，重复 {removed_duplicates} 条。"
                ).format(
                    kept=entry.get("kept", 0),
                    removed=entry.get("removed", 0),
                    removed_non_pe=entry.get("removed_non_pe", 0),
                    removed_empty=entry.get("removed_empty", 0),
                    removed_duplicates=entry.get("removed_duplicates", 0),
                )
                text(summary)
                log_path = entry.get("log")
                if log_path:
                    text(f"清洗日志: {log_path}")
                errors = entry.get("errors", 0)
                if errors:
                    text(f"有 {errors} 个文件删除失败，请手动检查。")
                progress(100)
    except Exception as exc:  # pragma: no cover - defensive logging
        text(f"数据清洗失败: {exc}")
        progress(0)

