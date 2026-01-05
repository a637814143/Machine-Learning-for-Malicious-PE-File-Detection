"""Task implementation for displaying PE file information."""

from pathlib import Path
from typing import Iterable, Tuple, Callable

from core.utils.visualization import get_pe_info_html as FileInfo

try:  # pragma: no cover - optional dependency for runtime usage
    import pefile
except Exception:  # pragma: no cover - gracefully degrade when unavailable
    pefile = None

# Type aliases keep the callable signatures explicit
ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def file_info_task(args: Tuple, progress: ProgressCallback, text: TextCallback) -> None:
    """Parse a PE file and stream section/import information plus the HTML summary."""
    if not args:
        text("未提供文件路径")
        return

    path = Path(args[0])
    if pefile is None:
        text("缺少 pefile 库，无法解析")
        return

    try:
        pe = pefile.PE(str(path))
    except Exception as exc:  # pragma: no cover - propagate clear message
        text(f"解析 PE 失败: {exc}")
        return

    total_sections = len(pe.sections) or 1
    for idx, section in enumerate(pe.sections, 1):
        percent = int((idx / total_sections) * 50)
        progress(percent)
        name = section.Name.decode(errors="ignore")
        text(f"正在解析节区 {idx}/{total_sections}: {name}")

    imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) or []
    all_imports: Iterable = imports
    total_funcs = sum(len(imp.imports) for imp in all_imports) or 1
    counted = 0
    for imp in all_imports:
        for func in imp.imports:
            counted += 1
            percent = 50 + int((counted / total_funcs) * 50)
            progress(percent)
            name = func.name.decode(errors="ignore") if func.name else "None"
            text(f"正在解析导入函数 {counted}/{total_funcs}: {name}")

    html = FileInfo(path)
    text(html)

