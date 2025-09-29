
#!/usr/bin/env python3
"""LightGBM-based model prediction utilities used by the GUI."""

from __future__ import annotations

import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterator, List, Optional, Tuple

# 将项目根加入 sys.path（以便脚本独立运行时也能 import core.*）
ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

try:  # pragma: no cover - optional dependency in tests
    import lightgbm as lgb
except Exception as exc:  # pragma: no cover - provide helpful guidance
    raise ImportError("请先安装 lightgbm: pip install lightgbm") from exc

import numpy as np

from core.feature_engineering import extract_features, vectorize_features

PE_SUFFIXES = {".exe", ".dll", ".sys", ".bin", ".scr", ".ocx"}
DEFAULT_MODEL = ROOT / "model.txt"
MAX_TO_SCAN = 1500
DEFAULT_THRESHOLD = 0.0385


@dataclass(frozen=True)
class PredictionLog:
    """Structured log emitted during prediction."""

    type: str
    message: str = ""
    index: int = 0
    total: int = 0
    extra: Dict[str, object] | None = None


def collect_pe_files(target: Path) -> List[Path]:
    """Collect PE files from a file or directory."""
    if target.is_file():
        return [target]
    if not target.exists() or not target.is_dir():
        raise FileNotFoundError(f"指定路径不存在或不是目录: {target}")

    files: List[Path] = []
    for p in target.rglob("*"):
        if p.is_file() and p.suffix.lower() in PE_SUFFIXES:
            files.append(p)
    return files


def _predict_single(booster: "lgb.Booster", file_path: Path, threshold: float) -> Tuple[float, str]:
    features = extract_features(file_path)
    vector = vectorize_features(features)
    arr = np.asarray(vector, dtype=np.float32).reshape(1, -1)
    prob = float(booster.predict(arr)[0])
    verdict = "恶意" if prob >= threshold else "良性"
    return prob, verdict


def MODEL_PREDICT(
    input_path: str,
    output_dir: Optional[str] = None,
    model_path: Optional[str] = None,
    threshold: float = DEFAULT_THRESHOLD,
    max_to_scan: int = MAX_TO_SCAN,
) -> Iterator[PredictionLog]:
    """Run model prediction for PE files under ``input_path``.

    Parameters
    ----------
    input_path:
        File or directory to scan.
    output_dir:
        Optional directory reserved for future extensions.  The current
        implementation keeps prediction results in memory only and does not
        write any files.
    model_path:
        Optional custom LightGBM model path.  Defaults to ``model.txt`` at the
        repository root.
    threshold:
        Probability threshold distinguishing malicious vs benign.
    max_to_scan:
        Maximum number of files to analyse in one run.

    Yields
    ------
    PredictionLog
        Structured log entries that describe progress for GUI display.
    """

    target = Path(input_path).expanduser().resolve()
    output_root: Optional[Path] = None
    if output_dir:
        output_root = Path(output_dir).expanduser().resolve()
        output_root.mkdir(parents=True, exist_ok=True)

    model_file = Path(model_path).expanduser().resolve() if model_path else DEFAULT_MODEL
    if not model_file.exists():
        raise FileNotFoundError(f"未找到模型文件: {model_file}")

    files = collect_pe_files(target)
    total_files = min(len(files), max_to_scan)
    files = files[:total_files]

    yield PredictionLog(
        type="start",
        message=f"开始扫描 {target}，使用模型 {model_file}",
        total=total_files,
        extra={"output_dir": str(output_root) if output_root else None},
    )

    if total_files == 0:
        yield PredictionLog(
            type="finished",
            message="未找到任何可识别的 PE 文件。",
            total=0,
            extra={"output": None, "processed": 0, "malicious": 0},
        )
        return

    booster = lgb.Booster(model_file=str(model_file))
    processed = 0
    malicious = 0

    for idx, file_path in enumerate(files, 1):
        try:
            prob, verdict = _predict_single(booster, file_path, threshold)
            processed += 1
            if verdict == "恶意":
                malicious += 1
            message = f"{idx}/{total_files} {file_path} -> {prob:.6f} ({verdict})"
            log_type = "progress"
        except Exception as exc:  # pragma: no cover - runtime feedback
            message = f"{idx}/{total_files} {file_path} -> 预测失败: {exc}"
            log_type = "error"
        yield PredictionLog(type=log_type, message=message, index=idx, total=total_files)

    if processed:
        summary_msg = (
            f"预测完成，共处理 {processed}/{total_files} 个文件，其中 {malicious} 个被判定为恶意。"
        )
    else:
        summary_msg = "没有成功的预测结果。"

    yield PredictionLog(
        type="finished",
        message=summary_msg,
        total=total_files,
        extra={
            "output": None,
            "processed": processed,
            "malicious": malicious,
            "failed": total_files - processed,
        },
    )


def main() -> None:  # pragma: no cover - manual execution helper
    import argparse

    parser = argparse.ArgumentParser(description="批量预测PE文件是否恶意")
    parser.add_argument("input", help="待扫描的文件或目录")
    parser.add_argument("output", help="结果保存目录")
    parser.add_argument("--model", help="LightGBM模型路径", default=None)
    parser.add_argument("--threshold", type=float, default=DEFAULT_THRESHOLD)
    parser.add_argument("--max", type=int, default=MAX_TO_SCAN)
    args = parser.parse_args()

    for log in MODEL_PREDICT(
        args.input,
        args.output,
        model_path=args.model,
        threshold=args.threshold,
        max_to_scan=args.max,
    ):
        if log.message:
            print(log.message)


if __name__ == "__main__":  # pragma: no cover - CLI entry
    main()
