
import time
from pathlib import Path
from .registry import register_task

from core.utils.visualization import get_pe_info_html as FileInfo
from core.feature_engineering import (
    extract_features,
    extract_from_directory,
    vectorize_feature_file,
    vectorize_features,
)
from core.modeling.trainer import train_ember_model_from_npy
from scripts.DATA_CLEAN import DATA_CLEAN
from scripts.D import MODEL_PREDICT, PredictionLog, DEFAULT_THRESHOLD, collect_pe_files

import numpy as np

try:  # pragma: no cover - optional dependency for runtime usage
    import lightgbm as lgb
except Exception as exc:  # pragma: no cover - mirror prediction module behaviour
    raise ImportError("缺少 lightgbm 库，请先安装: pip install lightgbm") from exc

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
        text("需要提供特征向量 .npz（推荐）或 .npy 文件路径和模型保存目录")
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


@register_task("测试模型")
def test_model_task(args, progress, text):
    """Evaluate the packaged model on the test PE corpus used by the GUI."""

    root_dir = Path(__file__).resolve().parents[2]
    default_dataset = root_dir / "data" / "raw" / "test"
    default_model = root_dir / "model.txt"

    # 从参数中提取自定义路径（忽略线程数等纯数字参数）
    custom_args = [a for a in args if a and not str(a).isdigit()]
    dataset_path = default_dataset
    model_path = default_model
    for candidate in custom_args:
        candidate_path = Path(candidate).expanduser().resolve()
        if candidate_path.is_dir() and dataset_path == default_dataset:
            dataset_path = candidate_path
        elif candidate_path.is_file() and model_path == default_model:
            model_path = candidate_path

    if not dataset_path.exists():
        text(f"测试数据集目录不存在: {dataset_path}")
        progress(0)
        return

    try:
        files = collect_pe_files(dataset_path)
    except Exception as exc:  # pragma: no cover - defensive fallback
        text(f"加载测试集失败: {exc}")
        progress(0)
        return

    total_files = len(files)
    if total_files == 0:
        text(f"测试集目录 {dataset_path} 中未找到任何 PE 文件。")
        progress(0)
        return

    if not model_path.exists():
        text(f"模型文件不存在: {model_path}")
        progress(0)
        return

    text(f"使用测试集目录: {dataset_path}")
    text(f"使用模型文件: {model_path}")
    progress(0)

    try:
        booster = lgb.Booster(model_file=str(model_path))
    except Exception as exc:
        text(f"加载模型失败: {exc}")
        progress(0)
        return

    correct = 0
    tp = tn = fp = fn = 0
    skipped = 0
    threshold = DEFAULT_THRESHOLD

    for idx, file_path in enumerate(files, 1):
        try:
            features = extract_features(file_path)
            vector = vectorize_features(features)
            arr = np.asarray(vector, dtype=np.float32).reshape(1, -1)
            prob = float(booster.predict(arr)[0])
        except Exception as exc:
            skipped += 1
            text(f"{idx}/{total_files} {file_path.name} -> 预测失败: {exc}")
            continue

        predicted_malicious = prob >= threshold
        actual_malicious = "virusshare" in file_path.name.lower()
        verdict = "恶意" if predicted_malicious else "良性"
        truth_label = "恶意" if actual_malicious else "良性"

        if predicted_malicious and actual_malicious:
            tp += 1
            correct += 1
        elif (not predicted_malicious) and (not actual_malicious):
            tn += 1
            correct += 1
        elif predicted_malicious and (not actual_malicious):
            fp += 1
        else:
            fn += 1

        status = "✓" if verdict == truth_label else "✗"
        text(
            f"{idx}/{total_files} {file_path.name} -> 预测: {verdict}"
            f" (概率 {prob:.4f}) | 实际: {truth_label} {status}"
        )

        progress(int(idx / total_files * 100))

    evaluated = tp + tn + fp + fn
    if evaluated == 0:
        text("未能完成任何预测，无法计算准确率。")
        progress(0)
        return

    accuracy = correct / evaluated
    precision = tp / (tp + fp) if (tp + fp) else None
    recall = tp / (tp + fn) if (tp + fn) else None

    summary_lines = [
        "模型测试完成！",
        f"样本总数: {evaluated}",
        f"预测准确率: {accuracy * 100:.2f}%",
        f"真阳性 (TP): {tp}",
        f"真阴性 (TN): {tn}",
        f"假阳性 (FP): {fp}",
        f"假阴性 (FN): {fn}",
    ]

    if skipped:
        summary_lines.append(f"预测失败（跳过）: {skipped}")

    if precision is not None:
        summary_lines.append(f"恶意精确率: {precision * 100:.2f}%")
    if recall is not None:
        summary_lines.append(f"恶意召回率: {recall * 100:.2f}%")

    text("\n".join(summary_lines))
    progress(100)


for _name in [
    "获取良性",
    "沙箱检测",
]:
    _placeholder_factory(_name)