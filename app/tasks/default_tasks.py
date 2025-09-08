"""Default task implementations and placeholders.

Each task function accepts three parameters:
    args: tuple of parameters from UI
    progress: function to update progress bar (int 0-100)
    text: function to send text/HTML to the UI

Use @register_task("任务名称") to register a function so that the UI
can find and execute it asynchronously.
"""

import time
from pathlib import Path
from .registry import register_task

# Importing directly to avoid circular import with app.ui
from core.utils.visualization import get_pe_info_html as FileInfo

try:
    import pefile
except Exception:  # pragma: no cover - pefile may be missing during tests
    pefile = None


@register_task("文件信息")
def file_info(args, progress, text):
    """Parse PE file and report sections/imports with progress."""
    if not args:
        text("未提供文件路径")
        return
    path = Path(args[0])
    if pefile is None:
        text("缺少pefile库，无法解析")
        return
    try:
        pe = pefile.PE(str(path))
    except Exception as e:  # pragma: no cover - runtime errors
        text(f"解析PE失败: {e}")
        return

    total_sections = len(pe.sections) or 1
    for idx, section in enumerate(pe.sections, 1):
        percent = int((idx / total_sections) * 50)
        progress(percent)
        text(f"解析节区 {idx}/{total_sections}: {section.Name.decode(errors='ignore')}")

    imports = getattr(pe, "DIRECTORY_ENTRY_IMPORT", [])
    total_funcs = sum(len(imp.imports) for imp in imports) or 1
    counted = 0
    for imp in imports:
        for func in imp.imports:
            counted += 1
            percent = 50 + int((counted / total_funcs) * 50)
            progress(percent)
            name = func.name.decode(errors="ignore") if func.name else "None"
            text(f"解析导入函数 {counted}/{total_funcs}: {name}")

    html = FileInfo(path)
    text(html)


def _placeholder_factory(task_name: str):
    @register_task(task_name)
    def _task(args, progress, text, _name=task_name):
        for i in range(1, 101):
            time.sleep(0.01)
            progress(i)
        text(f"{_name}：占位（未实现）")
    return _task

# Register placeholders for other buttons
for _name in [
    "数据清洗",
    "提取特征",
    "特征转换",
    "训练模型",
    "测试模型",
    "静态检测",
    "获取良性",
    "沙箱检测",
    "安装依赖",
]:
    _placeholder_factory(_name)