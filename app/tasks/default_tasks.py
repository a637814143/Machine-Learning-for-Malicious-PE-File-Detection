import time
from pathlib import Path
from .registry import register_task

from core.utils.visualization import get_pe_info_html as FileInfo
from core.feature_engineering import (
    extract_from_directory,
    vectorize_feature_file,
)
from core.modeling.trainer import train_ember_model_from_npy
from scripts.DATA_CLEAN import DATA_CLEAN
from scripts.D import MODEL_PREDICT, PredictionLog
from scripts.PIP_INSTALL import INSTALL as install_dependencies

try:
    import pefile
except Exception:
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
    except Exception as e:
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



@register_task("提取特征")
def extract_features_task(args, progress, text):
    """Extract raw features for all PE files in a folder with multithreading and real-time writing."""
    if len(args) < 2:
        text("需要提供输入文件夹和保存路径")
        return
    src, dst = args[0], args[1]

    # 支持自定义线程数
    max_workers = int(args[2]) if len(args) > 2 and args[2].isdigit() else None

    # 支持实时写入控制
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

    # 支持自定义线程数
    max_workers = int(args[2]) if len(args) > 2 and args[2].isdigit() else None

    # 支持实时写入控制
    realtime_write = True
    if len(args) > 3:
        if args[3].lower() in ['false', '0', 'no', 'batch']:
            realtime_write = False

    vectorize_feature_file(src, dst, progress_callback=progress, text_callback=text,
                          max_workers=max_workers, realtime_write=realtime_write)
    text("特征向量化完成")


@register_task("训练模型")
def train_model_task(args, progress, text):
    """Train an EMBER 兼容的 LightGBM 模型."""
    if len(args) < 2:
        text("需要提供特征向量 .npy 文件路径和模型保存目录")
        return

    npy_path, output_dir = args[0], args[1]
    thread_count = None
    if len(args) > 2:
        try:
            thread_count = int(args[2])
        except (TypeError, ValueError):
            thread_count = None

    lgbm_params = {}
    if thread_count is not None and thread_count > 0:
        lgbm_params["num_threads"] = thread_count

    progress(0)
    text("准备开始模型训练……")

    try:
        result = train_ember_model_from_npy(
            npy_path,
            output_dir,
            lgbm_params=lgbm_params or None,
            progress_callback=progress,
            status_callback=text,
        )
    except Exception as exc:
        text(f"模型训练失败: {exc}")
        progress(0)
        return

    metrics = result.get("metrics", {})
    lines = [
        "模型训练完成！",
        f"模型文件: {result.get('model_path', '未知')}",
        f"元数据: {result.get('metadata_path', '未知')}",
        "验证集指标:",
        f"  - AUC: {metrics.get('auc', 'N/A')}",
        f"  - Accuracy: {metrics.get('accuracy', 'N/A')}",
        f"  - F1-score: {metrics.get('f1', 'N/A')}",
        f"  - 最佳迭代: {metrics.get('best_iteration', 'N/A')}",
    ]
    text("\n".join(lines))


@register_task("安装依赖")
def install_dependencies_task(args, progress, text):

    progress(0)
    text("开始安装依赖……")
    try:
        for idx, line in enumerate(install_dependencies(), 1):
            if line:
                text(line)
            if idx % 5 == 0:
                progress(min(95, 5 + idx))
    except Exception as exc:
        text(f"安装依赖失败: {exc}")
        progress(0)
        return

    progress(100)


@register_task("数据清洗")
def data_cleaning_task(args, progress, text):

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
                intro = f"开始数据清洗，共 {total} 个候选文件。"
                if log_target:
                    intro += f" 日志文件将保存到: {log_target}"
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
                    "数据清洗完成：保留 {kept} 个，删除 {removed} 个，其中非PE {removed_non_pe} 个、"
                    "空文件 {removed_empty} 个、重复 {removed_duplicates} 个。"
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
    except Exception as exc:
        text(f"数据清洗失败: {exc}")
        progress(0)


@register_task("模型预测")
def model_prediction_task(args, progress, text):

    if not args:
        text("需要提供输入路径")
        return

    src = args[0]
    dst = next((a for a in args[1:] if a and not str(a).isdigit()), None)
    try:
        logs = MODEL_PREDICT(src, dst)
    except Exception as exc:
        text(f"模型预测失败: {exc}")
        return

    total = 0
    try:
        for log in logs:
            if isinstance(log, PredictionLog):
                entry_type = log.type
                message = log.message
                idx = log.index
                total = log.total or total
            else:  # pragma: no cover - defensive: unexpected type
                entry_type = getattr(log, "type", "progress")
                message = getattr(log, "message", str(log))
                idx = getattr(log, "index", 0)
                total = getattr(log, "total", total)

            if message:
                text(str(message))

            if entry_type in {"progress", "error"} and idx and total:
                progress(int(idx / total * 100))
            elif entry_type == "start" and total == 0:
                progress(0)
            elif entry_type == "finished":
                progress(100)
    except Exception as exc:
        text(f"模型预测失败: {exc}")
        progress(0)


for _name in [
    "测试模型",
    "获取良性",
    "沙箱检测",
]:
    _placeholder_factory(_name)
