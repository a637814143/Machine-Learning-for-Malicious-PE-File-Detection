"""Task implementation for evaluating the packaged model."""

from pathlib import Path
from typing import Callable, Tuple

import numpy as np

from core.feature_engineering import extract_features, vectorize_features
from core.utils.lightgbm_loader import import_lightgbm
from scripts.D import DEFAULT_THRESHOLD, collect_pe_files

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]

try:  # pragma: no cover - optional dependency for runtime usage
    lgb = import_lightgbm()
except ModuleNotFoundError as exc:  # pragma: no cover - mirror predictor behaviour
    raise ImportError("缺少 lightgbm 库，请先安装: pip install lightgbm") from exc


def test_model_task(args: Tuple, progress: ProgressCallback, text: TextCallback) -> None:
    """Evaluate the GUI bundled model with a test PE set."""
    root_dir = Path(__file__).resolve().parents[1]
    default_dataset = root_dir / "data" / "test"
    default_model = root_dir / "model.txt"

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
    except Exception as exc:
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
        actual_malicious = "benign" not in file_path.name.lower()
        actual_malicious = actual_malicious or "virusshare" in file_path.name.lower()
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
        "模型测试完成。",
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

