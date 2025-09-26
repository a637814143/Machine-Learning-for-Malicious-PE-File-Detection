
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
from core.feature_engineering import (
    extract_from_directory,
    vectorize_feature_file,
)
from core.modeling.trainer import train_ember_model

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

# Real implementations -------------------------------------------------------


@register_task("提取特征")
def extract_features_task(args, progress, text):
    """Extract raw features for all PE files in a folder with multithreading and real-time writing."""
    if len(args) < 2:
        text("需要提供输入文件夹和保存路径")
        return
    src, dst = args[0], args[1]
    
    # 支持自定义线程数（第三个参数）
    max_workers = int(args[2]) if len(args) > 2 and args[2].isdigit() else None
    
    # 支持实时写入控制（第四个参数）
    realtime_write = True
    if len(args) > 3:
        if args[3].lower() in ['false', '0', 'no', 'batch']:
            realtime_write = False
    
    extract_from_directory(src, dst, progress_callback=progress, text_callback=text, 
                          max_workers=max_workers, realtime_write=realtime_write)
    text("特征提取完成")


@register_task("特征转换")
def feature_vector_task(args, progress, text):
    """Vectorise previously extracted features with multithreading and real-time writing."""
    if len(args) < 2:
        text("需要提供特征文件路径和保存路径")
        return
    src, dst = args[0], args[1]
    
    # 支持自定义线程数（第三个参数）
    max_workers = int(args[2]) if len(args) > 2 and args[2].isdigit() else None
    
    # 支持实时写入控制（第四个参数）
    realtime_write = True
    if len(args) > 3:
        if args[3].lower() in ['false', '0', 'no', 'batch']:
            realtime_write = False
    
    vectorize_feature_file(src, dst, progress_callback=progress, text_callback=text, 
                          max_workers=max_workers, realtime_write=realtime_write)
    text("特征向量化完成")


# Training task --------------------------------------------------------------


@register_task("训练模型")
def train_model_task(args, progress, text):
    """Train a LightGBM model using EMBER-compatible vectors."""

    if len(args) < 3:
        text("需要提供训练向量文件、原始 JSONL 以及模型保存路径")
        return

    train_vectors = Path(args[0])
    train_jsonl = Path(args[1])
    model_output = Path(args[2])

    valid_vectors = Path(args[3]) if len(args) > 3 and args[3] else None
    valid_jsonl = Path(args[4]) if len(args) > 4 and args[4] else None

    if (valid_vectors is None) != (valid_jsonl is None):
        text("验证集路径需要同时提供向量文件和 JSONL 标签")
        return

    try:
        train_ember_model(
            train_vectors=train_vectors,
            train_jsonl=train_jsonl,
            model_output=model_output,
            valid_vectors=valid_vectors,
            valid_jsonl=valid_jsonl,
            progress_callback=progress,
            text_callback=text,
        )
        text("模型训练完成")
    except Exception as exc:  # pragma: no cover - runtime errors
        text(f"模型训练失败: {exc}")


# Register placeholders for remaining buttons -------------------------------
for _name in [
    "数据清洗",
    "测试模型",
    "静态检测",
    "获取良性",
    "沙箱检测",
    "安装依赖",
]:
    _placeholder_factory(_name)
