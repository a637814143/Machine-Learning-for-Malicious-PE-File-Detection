"""Task implementation for batch model prediction."""

from html import escape
from pathlib import Path
from typing import Any, Callable, Dict, Tuple

from scripts.D import MODEL_PREDICT, PredictionLog, DEFAULT_THRESHOLD

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


def _format_prediction_summary_html(summary: Dict[str, Any]) -> str:
    processed = int(summary.get("processed", 0))
    malicious = int(summary.get("malicious", 0))
    failed = int(summary.get("failed", 0))
    threshold = float(summary.get("threshold", DEFAULT_THRESHOLD))
    detection_mode = summary.get("detection_mode") or {}
    mode_label = str(detection_mode.get("label", "默认模式"))
    mode_desc = str(detection_mode.get("description", ""))

    top_probability = float(summary.get("top_probability", 0.0) or 0.0)
    average_probability = float(summary.get("average_probability", 0.0) or 0.0)
    detection_strength = summary.get("detection_strength") or {}
    level = str(detection_strength.get("level", "未知"))
    score = float(detection_strength.get("score", 0.0) or 0.0)
    guidance = str(detection_strength.get("guidance", ""))
    top_suspicious = summary.get("top_suspicious") or []

    malicious_ratio = malicious / processed * 100 if processed else 0.0

    rows = [
        ("处理文件", f"{processed}"),
        ("判定为恶意", f"{malicious}"),
        ("恶意占比", f"{malicious_ratio:.1f}%"),
        ("预测失败", f"{failed}"),
        ("检测模式", f"{mode_label} (阈值 {threshold:.4f})"),
        ("阈值", f"{threshold:.4f}"),
        ("最高原始概率", f"{top_probability:.4f}"),
        ("平均原始概率", f"{average_probability:.4f}"),
    ]

    if mode_desc.strip():
        rows.insert(5, ("模式说明", mode_desc.strip()))

    html_lines = [
        "<html><body style='font-family:\"Microsoft YaHei\",Arial,sans-serif;'>",
        "<h2 style='margin-top:0;'>模型预测摘要</h2>",
        "<div style='background:#f7faff;border:1px solid #d0e3ff;border-radius:8px;padding:12px;margin-bottom:16px;'>",
        f"<p><strong>整体风险评级：</strong>{escape(level)} (得分 {score:.1f}/10)</p>",
    ]

    if guidance.strip():
        html_lines.append(f"<p style='color:#555;'>{escape(guidance)}</p>")

    html_lines.append("</div>")
    html_lines.append(
        "<table style='border-collapse:collapse;width:100%;margin-bottom:16px;'>"
        "<thead><tr style='background:#eef4ff;'>"
        "<th style='text-align:left;padding:6px;border:1px solid #d0e3ff;'>指标</th>"
        "<th style='text-align:left;padding:6px;border:1px solid #d0e3ff;'>数值</th>"
        "</tr></thead><tbody>"
    )

    for label, value in rows:
        html_lines.append(
            "<tr>"
            f"<td style='padding:6px;border:1px solid #d0e3ff;'>{escape(label)}</td>"
            f"<td style='padding:6px;border:1px solid #d0e3ff;'>{escape(value)}</td>"
            "</tr>"
        )

    html_lines.append("</tbody></table>")
    if top_suspicious:
        max_display = 20
        html_lines.append(
            "<h3 style='margin:18px 0 6px;'>恶意文件名单（按原始得分高到低）</h3>"
        )
        html_lines.append(
            "<table style='border-collapse:collapse;width:100%;margin-bottom:12px;'>"
            "<thead><tr style='background:#fff4f4;'>"
            "<th style='text-align:left;padding:6px;border:1px solid #f3c2c2;'>#</th>"
            "<th style='text-align:left;padding:6px;border:1px solid #f3c2c2;'>文件名</th>"
            "<th style='text-align:left;padding:6px;border:1px solid #f3c2c2;'>路径</th>"
            "<th style='text-align:left;padding:6px;border:1px solid #f3c2c2;'>原始得分</th>"
            "<th style='text-align:left;padding:6px;border:1px solid #f3c2c2;'>展示概率</th>"
            "</tr></thead><tbody>"
        )
        for idx, item in enumerate(top_suspicious[:max_display], 1):
            raw_path = str(item.get("file", "") or "")
            filename = Path(raw_path).name if raw_path else "未知文件"
            prob = float(item.get("probability", 0.0) or 0.0)
            display_prob = float(item.get("display_probability", 0.0) or 0.0)
            html_lines.append(
                "<tr>"
                f"<td style='padding:6px;border:1px solid #f3c2c2;'>{idx}</td>"
                f"<td style='padding:6px;border:1px solid #f3c2c2;'>{escape(filename)}</td>"
                f"<td style='padding:6px;border:1px solid #f3c2c2;color:#666;'>{escape(raw_path)}</td>"
                f"<td style='padding:6px;border:1px solid #f3c2c2;'>{prob:.6f}</td>"
                f"<td style='padding:6px;border:1px solid #f3c2c2;'>{display_prob:.4f}%</td>"
                "</tr>"
            )
        html_lines.append("</tbody></table>")
        if len(top_suspicious) > max_display:
            html_lines.append(
                f"<p style='color:#888;margin-top:4px;'>仅展示前 {max_display} 个恶意样本。</p>"
            )
    else:
        html_lines.append("<p style='color:#555;margin-top:12px;'>未检测到恶意文件。</p>")
    html_lines.append(
        "<p style='color:#888;margin-top:24px;'>以上结果基于当前加载的 LightGBM 模型，建议结合动态分析与人工复核。</p>"
    )
    html_lines.append("</body></html>")

    return "".join(html_lines)


def model_prediction_task(args: Tuple, progress: ProgressCallback, text: TextCallback) -> None:
    """Run the pre-trained model against a user supplied directory."""
    if not args:
        text("需要提供输入路径")
        return

    mode_key = None
    threshold_override = None
    model_override = None
    cleaned_args = []
    for arg in args:
        if isinstance(arg, str) and arg.startswith("MODE::"):
            mode_key = arg.split("MODE::", 1)[1] or None
            continue
        if isinstance(arg, str) and arg.startswith("THRESH::"):
            try:
                threshold_override = float(arg.split("THRESH::", 1)[1])
            except ValueError:
                threshold_override = None
            continue
        if isinstance(arg, str) and arg.startswith("MODEL::"):
            model_override = arg.split("MODEL::", 1)[1] or None
            continue
        cleaned_args.append(arg)

    args = tuple(cleaned_args)
    src = args[0]
    dst = next((a for a in args[1:] if a and not str(a).isdigit()), None)
    try:
        logs = MODEL_PREDICT(
            src,
            dst,
            model_path=model_override,
            threshold=threshold_override,
            mode_key=mode_key,
        )
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
            else:  # pragma: no cover - defensive programming
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
                if isinstance(log, PredictionLog) and log.extra:
                    try:
                        html = _format_prediction_summary_html(log.extra)
                    except Exception:
                        html = ""
                    if html:
                        text(html)
    except Exception as exc:
        text(f"模型预测失败: {exc}")
        progress(0)
