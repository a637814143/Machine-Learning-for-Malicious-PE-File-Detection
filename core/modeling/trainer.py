"""Training utilities for EMBER-compatible models."""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any, List, Mapping, Optional, Sequence, Tuple

import numpy as np

try:  # pragma: no cover - optional dependency during tests
    import lightgbm as lgb  # type: ignore
except Exception:  # pragma: no cover
    lgb = None  # type: ignore

from core.feature_engineering.vectorization import VECTOR_SIZE
from .model_factory import LightGBMConfig, build_ember_lightgbm_config


@dataclass(frozen=True)
class DatasetBundle:
    """Container holding vectors and labels for a dataset split."""

    vectors: np.ndarray
    labels: np.ndarray

    def __post_init__(self) -> None:
        if self.vectors.shape[0] != self.labels.shape[0]:
            raise ValueError(
                "向量和标签数量不一致: "
                f"vectors={self.vectors.shape[0]} labels={self.labels.shape[0]}"
            )
        if self.vectors.shape[1] != VECTOR_SIZE:
            raise ValueError(
                f"特征维度与EMBER不匹配: got {self.vectors.shape[1]}, expected {VECTOR_SIZE}"
            )


def _load_vectors(vector_file: Path) -> np.ndarray:
    vectors = np.load(vector_file)
    if vectors.ndim != 2:
        raise ValueError(f"向量文件维度异常: {vector_file}")
    return vectors.astype(np.float32, copy=False)


def _load_labels(jsonl_path: Path) -> np.ndarray:
    labels: List[int] = []
    with jsonl_path.open("r", encoding="utf-8") as fh:
        for line_no, line in enumerate(fh, 1):
            record = json.loads(line)
            if "label" not in record:
                raise KeyError(f"第 {line_no} 行缺少 label 字段")
            labels.append(int(record["label"]))
    return np.asarray(labels, dtype=np.int8)


def load_dataset(vector_path: Path, jsonl_path: Path) -> DatasetBundle:
    """Load a vectorised dataset and its labels."""

    if not vector_path.exists():
        raise FileNotFoundError(f"向量文件不存在: {vector_path}")
    if not jsonl_path.exists():
        raise FileNotFoundError(f"标签文件不存在: {jsonl_path}")

    vectors = _load_vectors(vector_path)
    labels = _load_labels(jsonl_path)

    return DatasetBundle(vectors=vectors, labels=labels)


def _require_lightgbm() -> None:
    if lgb is None:  # pragma: no cover - runtime guard
        raise ImportError(
            "缺少 lightgbm 库，无法训练模型。请运行 'pip install lightgbm' 后重试。"
        )


def _prepare_valid_sets(
    valid_bundles: Sequence[Tuple[str, DatasetBundle]],
) -> Tuple[List[Any], List[str]]:
    _require_lightgbm()
    valid_sets: List[lgb.Dataset] = []
    valid_names: List[str] = []
    for name, bundle in valid_bundles:
        valid_sets.append(lgb.Dataset(bundle.vectors, label=bundle.labels, free_raw_data=False))
        valid_names.append(name)
    return valid_sets, valid_names


def _make_progress_callback(
    total_rounds: int,
    progress_callback: Optional[callable],
    text_callback: Optional[callable],
    report_every: int = 10,
) -> Optional[Any]:
    _require_lightgbm()
    if progress_callback is None and text_callback is None:
        return None

    def _callback(env) -> None:
        iteration = env.iteration + 1
        if progress_callback is not None:
            progress = int(min(iteration / max(total_rounds, 1), 1.0) * 100)
            progress_callback(progress)
        if text_callback is not None and iteration % report_every == 0:
            metrics = []
            for name, loss in env.evaluation_result_list:
                metrics.append(f"{name}={loss:.4f}")
            metric_str = ", ".join(metrics) if metrics else "迭代完成"
            text_callback(f"训练进度 {iteration}/{total_rounds}: {metric_str}")

    _callback.order = 10  # type: ignore[attr-defined]
    return _callback


def train_ember_model(
    train_vectors: Path,
    train_jsonl: Path,
    model_output: Optional[Path] = None,
    valid_vectors: Optional[Path] = None,
    valid_jsonl: Optional[Path] = None,
    *,
    overrides: Optional[Mapping[str, Any]] = None,
    num_boost_round: Optional[int] = None,
    progress_callback=None,
    text_callback=None,
) -> Any:
    """Train a LightGBM model using the EMBER configuration."""

    _require_lightgbm()

    train_bundle = load_dataset(train_vectors, train_jsonl)

    valid_bundles: List[Tuple[str, DatasetBundle]] = []
    if valid_vectors and valid_jsonl:
        valid_bundle = load_dataset(valid_vectors, valid_jsonl)
        valid_bundles.append(("valid", valid_bundle))

    config: LightGBMConfig = build_ember_lightgbm_config(
        overrides=overrides,
        num_boost_round=num_boost_round,
    )

    dtrain = lgb.Dataset(train_bundle.vectors, label=train_bundle.labels, free_raw_data=False)
    valid_sets, valid_names = _prepare_valid_sets(valid_bundles)

    callbacks = []
    progress_cb = _make_progress_callback(config.num_boost_round, progress_callback, text_callback)
    if progress_cb is not None:
        callbacks.append(progress_cb)

    booster = lgb.train(
        config.params,
        dtrain,
        num_boost_round=config.num_boost_round,
        valid_sets=valid_sets or None,
        valid_names=valid_names or None,
        callbacks=callbacks,
    )

    if model_output is not None:
        model_output.parent.mkdir(parents=True, exist_ok=True)
        booster.save_model(str(model_output))
        if text_callback is not None:
            text_callback(f"模型已保存到 {model_output}")

    if progress_callback is not None:
        progress_callback(100)

    return booster
