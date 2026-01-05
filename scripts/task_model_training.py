"""Task implementation for training the EMBER LightGBM model."""

from pathlib import Path
from typing import Any, Callable, Dict, Optional, Tuple

from core.modeling.trainer import TrainingResult, train_ember_model_from_npy

try:  # Keep threshold aligned with prediction task but remain robust to import issues
    from scripts.D import DEFAULT_THRESHOLD as _PREDICTION_THRESHOLD
except Exception:  # pragma: no cover - fallback if optional imports fail
    _PREDICTION_THRESHOLD = 0.0385

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def train_model_task(args: Tuple, progress: ProgressCallback, text: TextCallback) -> None:
    """Train an EMBER dataset LightGBM model."""
    if len(args) < 2:
        text("需要提供输入的 .npz/.npy 路径和模型输出目录")
        return

    npy_path, output_dir = args[0], args[1]
    thread_count: Optional[int] = None
    if len(args) > 2:
        try:
            thread_count = int(args[2])
        except (TypeError, ValueError):
            thread_count = None

    validation_vectors = None
    if len(args) > 3:
        candidate = str(args[3]).strip()
        if candidate:
            validation_vectors = candidate

    lgbm_params: Dict[str, Any] = {}
    if thread_count is not None and thread_count > 0:
        lgbm_params["num_threads"] = thread_count

    progress(0)
    text("准备开始模型训练任务")
    if validation_vectors:
        text(f"使用验证向量文件: {validation_vectors}")
    else:
        text("未指定验证集，将使用默认用户输入或训练数据自动划分")

    def _infer_model_output_path(target: str) -> Path:
        resolved = Path(target).expanduser()
        if resolved.exists() and resolved.is_dir():
            return resolved / "model.txt"
        if resolved.suffix:
            return resolved
        return resolved / "model.txt"

    def _format_metric_value(value: Any) -> str:
        try:
            return f"{float(value):.6f}"
        except (TypeError, ValueError):
            return str(value)

    def _format_percentage(value: Optional[float]) -> str:
        if value is None:
            return "N/A"
        try:
            return f"{float(value) * 100:.2f}%"
        except (TypeError, ValueError):
            return str(value)

    try:
        training_result = train_ember_model_from_npy(
            npy_path,
            output_dir,
            valid_vectors=validation_vectors,
            lgbm_params=lgbm_params or None,
            progress_callback=progress,
            status_callback=text,
            compute_eval_metrics=True,
            evaluation_threshold=_PREDICTION_THRESHOLD,
        )
    except Exception as exc:
        text(f"模型训练失败: {exc}")
        progress(0)
        return

    if isinstance(training_result, TrainingResult):
        booster = training_result.booster
        evaluation_metrics = training_result.evaluation_metrics
    else:
        booster = training_result
        evaluation_metrics = {}

    summary_lines = [
        "模型训练完成。",
        f"模型文件保存到: {_infer_model_output_path(output_dir)}",
    ]
    if validation_vectors:
        summary_lines.append(f"验证集: {validation_vectors}")
    else:
        summary_lines.append("验证集: 未指定，使用默认拆分")

    best_iteration = getattr(booster, "best_iteration", None)
    if isinstance(best_iteration, int) and best_iteration > 0:
        summary_lines.append(f"最佳迭代: {best_iteration}")

    best_scores = getattr(booster, "best_score", None)
    if isinstance(best_scores, dict) and best_scores:
        metric_lines = []
        for dataset_name, metrics in best_scores.items():
            if not metrics:
                continue
            formatted = ", ".join(
                f"{metric_name}={_format_metric_value(metric_value)}"
                for metric_name, metric_value in metrics.items()
            )
            metric_lines.append(f"  - {dataset_name}: {formatted}")
        if metric_lines:
            summary_lines.append("验证指标:")
            summary_lines.extend(metric_lines)

    if evaluation_metrics:
        summary_lines.append("分类指标:")
        for dataset_name, metrics in evaluation_metrics.items():
            accuracy = _format_percentage(metrics.get("accuracy"))
            precision = _format_percentage(metrics.get("precision"))
            recall = _format_percentage(metrics.get("recall"))
            f1_value = _format_percentage(metrics.get("f1_score"))
            summary_lines.append(
                f"  - {dataset_name}: "
                f"准确率{accuracy}, 精确率{precision}, 召回率{recall}, F1 {f1_value}"
            )
            summary_lines.append(
                "    样本总数: {samples} | TP={tp} TN={tn} FP={fp} FN={fn} | 阈值: {threshold}"
                .format(
                    samples=metrics.get("samples", 0),
                    tp=metrics.get("tp", 0),
                    tn=metrics.get("tn", 0),
                    fp=metrics.get("fp", 0),
                    fn=metrics.get("fn", 0),
                    threshold=_format_metric_value(metrics.get("threshold")),
                )
            )

    text("\n".join(summary_lines))
