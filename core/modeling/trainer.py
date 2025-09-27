"""Model training utilities.

This module provides a high level function for training an EMBER compatible
LightGBM model from feature vectors stored in NumPy ``.npy`` files.  The
implementation is intentionally defensive so that it can ingest a variety of
array layouts that might be produced by different feature extraction
pipelines in this repository (for example direct ``(X, y)`` tuples, dicts with
multiple splits, or structured NumPy objects).

Example
-------

>>> from core.modeling.trainer import train_ember_model_from_npy
>>> result = train_ember_model_from_npy("features/train_vectors.npy", "models")
>>> print(result["model_path"])

The resulting ``model.txt`` can later be loaded either through LightGBM's
``Booster`` API or the same helper utilities that operate on the official
EMBER release.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime
import json
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Mapping, MutableMapping, Optional, Tuple

import lightgbm as lgb
import numpy as np
from sklearn.metrics import accuracy_score, f1_score, roc_auc_score
from sklearn.model_selection import train_test_split


@dataclass
class _DatasetSplits:
    """Container holding the arrays required for training.

    Attributes
    ----------
    x_train:
        Training feature matrix.
    y_train:
        Training labels.
    x_valid:
        Validation feature matrix.
    y_valid:
        Validation labels.
    """

    x_train: np.ndarray
    y_train: np.ndarray
    x_valid: np.ndarray
    y_valid: np.ndarray


def _normalise_key_lookup(keys: Iterable[str]) -> Dict[str, str]:
    """Create a case-insensitive lookup mapping for ``keys``."""

    return {key.lower(): key for key in keys}


def _ensure_2d(array: np.ndarray) -> np.ndarray:
    """Ensure ``array`` is two dimensional.

    Raises
    ------
    ValueError
        If the array cannot be interpreted as a matrix of feature vectors.
    """

    if array.ndim == 1:
        # Interpret a 1-D array as a single sample with ``n`` features.
        return array.reshape(1, -1)
    if array.ndim != 2:
        raise ValueError(f"期望特征矩阵是 2 维的，实际为 {array.ndim} 维")
    return array


def _ensure_1d(array: np.ndarray) -> np.ndarray:
    """Ensure ``array`` is a flat label vector."""

    if array.ndim == 1:
        return array
    if array.ndim == 2 and array.shape[1] == 1:
        return array.ravel()
    raise ValueError("标签向量必须是一维的")


def _as_numpy(array: Any) -> np.ndarray:
    """Convert ``array`` to a NumPy array with ``float32``/``int64`` dtype."""

    if isinstance(array, np.ndarray):
        return array
    return np.asarray(array)


def _extract_from_mapping(data: Mapping[str, Any]) -> Tuple[np.ndarray, np.ndarray, Optional[np.ndarray], Optional[np.ndarray]]:
    """Extract feature/label arrays from a mapping structure."""

    key_map = _normalise_key_lookup(data.keys())

    def pick(*candidates: str) -> Optional[Any]:
        for name in candidates:
            if name in key_map:
                return data[key_map[name]]
        return None

    x = pick("x", "x_train", "features", "vectors", "train_x", "train_features")
    y = pick("y", "y_train", "labels", "train_y", "train_labels")
    x_valid = pick("x_valid", "x_val", "valid_x", "validation_x")
    y_valid = pick("y_valid", "y_val", "valid_y", "validation_y")

    if x is None or y is None:
        raise ValueError("在提供的 npy 数据中未找到特征或标签字段")

    return _as_numpy(x), _as_numpy(y), (
        None if x_valid is None else _as_numpy(x_valid)
    ), (
        None if y_valid is None else _as_numpy(y_valid)
    )


def _extract_features_and_labels(obj: Any) -> Tuple[np.ndarray, np.ndarray, Optional[np.ndarray], Optional[np.ndarray]]:
    """Parse arbitrary objects produced by ``np.load``.

    The function supports several common storage conventions:

    * ``dict`` / ``Mapping`` objects with ``X``/``y`` like keys.
    * ``(X, y)`` tuples or lists.
    * Structured ``np.ndarray`` objects with a single element containing one of
      the above structures.
    """

    if isinstance(obj, np.ndarray) and obj.dtype == object:
        # Unwrap object arrays that are containers themselves (common when a
        # tuple/dict was saved via ``np.save``).
        if obj.ndim == 0:
            return _extract_features_and_labels(obj.item())
        if obj.ndim == 1 and obj.size == 1:
            return _extract_features_and_labels(obj[0])

    if isinstance(obj, Mapping):
        return _extract_from_mapping(obj)

    if isinstance(obj, (tuple, list)):
        if len(obj) < 2:
            raise ValueError("np.save 保存的序列需要至少包含特征和标签两部分")
        x = _as_numpy(obj[0])
        y = _as_numpy(obj[1])
        x_valid: Optional[np.ndarray] = None
        y_valid: Optional[np.ndarray] = None
        if len(obj) >= 4:
            x_valid = _as_numpy(obj[2])
            y_valid = _as_numpy(obj[3])
        return x, y, x_valid, y_valid

    if isinstance(obj, np.ndarray):
        raise ValueError(
            "无法直接从纯特征矩阵中恢复标签。请确保 .npy 文件同时保存了标签信息。"
        )

    raise ValueError("不支持的 npy 数据格式")


def _prepare_dataset_splits(
    raw_data: Any,
    *,
    validation_ratio: float,
    random_state: int,
) -> _DatasetSplits:
    """Prepare training/validation splits from ``raw_data``."""

    x, y, x_valid, y_valid = _extract_features_and_labels(raw_data)

    x = _ensure_2d(_as_numpy(x).astype(np.float32))
    y = _ensure_1d(_as_numpy(y))

    if x_valid is None or y_valid is None:
        x_train, x_valid, y_train, y_valid = train_test_split(
            x,
            y,
            test_size=validation_ratio,
            random_state=random_state,
            stratify=y if len(np.unique(y)) > 1 else None,
        )
    else:
        x_train = _ensure_2d(_as_numpy(x).astype(np.float32))
        y_train = _ensure_1d(_as_numpy(y))
        x_valid = _ensure_2d(_as_numpy(x_valid).astype(np.float32))
        y_valid = _ensure_1d(_as_numpy(y_valid))

    return _DatasetSplits(x_train, y_train, x_valid, y_valid)


def train_ember_model_from_npy(
    npy_path: str,
    model_dir: str,
    *,
    validation_ratio: float = 0.1,
    random_state: int = 42,
    num_boost_round: int = 1500,
    early_stopping_rounds: int = 100,
    lgbm_params: Optional[MutableMapping[str, Any]] = None,
    progress_callback: Optional[Callable[[int], None]] = None,
    status_callback: Optional[Callable[[str], None]] = None,
) -> Dict[str, Any]:
    """Train an EMBER-compatible LightGBM model from a ``.npy`` feature set.

    Parameters
    ----------
    npy_path:
        Path to the ``.npy`` file that contains both feature vectors and
        corresponding labels.
    model_dir:
        Directory where the trained model and accompanying metadata will be
        saved.  The directory will be created if it does not exist.
    validation_ratio:
        Fraction of the data to reserve for validation when the dataset does
        not already contain an explicit validation split.
    random_state:
        Random seed used for deterministic data splitting and LightGBM
        training.
    num_boost_round:
        Maximum number of boosting iterations.
    early_stopping_rounds:
        Stop training if the validation metric does not improve after this
        many rounds.
    lgbm_params:
        Optional dictionary overriding the default LightGBM parameters.

    Returns
    -------
    dict
        Contains paths to the saved model/metadata and the validation metrics
        observed during training.
    """

    def _emit_progress(value: int) -> None:
        if progress_callback is not None:
            progress_callback(int(max(0, min(100, value))))

    def _emit_status(message: str) -> None:
        if status_callback is not None:
            status_callback(message)

    npy_file = Path(npy_path)
    if not npy_file.exists():
        raise FileNotFoundError(f"未找到特征文件: {npy_path}")

    _emit_status("加载特征数据……")
    _emit_progress(5)
    raw_data = np.load(npy_file, allow_pickle=True)
    dataset = _prepare_dataset_splits(
        raw_data,
        validation_ratio=validation_ratio,
        random_state=random_state,
    )

    _emit_status("准备 LightGBM 数据集……")
    _emit_progress(15)

    default_params: Dict[str, Any] = {
        "objective": "binary",
        "metric": "auc",
        "boosting_type": "gbdt",
        "num_leaves": 64,
        "learning_rate": 0.05,
        "feature_fraction": 0.9,
        "bagging_fraction": 0.8,
        "bagging_freq": 5,
        "max_depth": -1,
        "min_data_in_leaf": 50,
        "lambda_l1": 0.0,
        "lambda_l2": 0.0,
        "verbose": -1,
        "force_col_wise": True,
        "seed": random_state,
        "num_threads": 0,
    }
    if lgbm_params:
        default_params.update(lgbm_params)

    train_dataset = lgb.Dataset(dataset.x_train, label=dataset.y_train)
    valid_dataset = lgb.Dataset(dataset.x_valid, label=dataset.y_valid, reference=train_dataset)

    _emit_status("开始训练 LightGBM 模型……")

    def _progress_updater(num_rounds: int):
        start, end = 20, 90

        def _callback(env: lgb.callback.CallbackEnv) -> None:  # type: ignore[name-defined]
            if env.iteration == 0:
                return
            fraction = min(env.iteration / max(1, num_rounds), 1.0)
            _emit_progress(start + int(fraction * (end - start)))

        return _callback

    booster = lgb.train(
        default_params,
        train_dataset,
        num_boost_round=num_boost_round,
        valid_sets=[train_dataset, valid_dataset],
        valid_names=["train", "valid"],
        early_stopping_rounds=early_stopping_rounds,
        verbose_eval=False,
        callbacks=[_progress_updater(num_boost_round)],
    )

    best_iteration = booster.best_iteration or num_boost_round
    _emit_progress(92)
    _emit_status("计算验证指标……")
    y_prob = booster.predict(dataset.x_valid, num_iteration=best_iteration)
    y_pred = (y_prob >= 0.5).astype(int)

    metrics = {
        "auc": float(roc_auc_score(dataset.y_valid, y_prob)),
        "accuracy": float(accuracy_score(dataset.y_valid, y_pred)),
        "f1": float(f1_score(dataset.y_valid, y_pred, zero_division=0)),
        "best_iteration": int(best_iteration),
    }

    output_dir = Path(model_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    model_path = output_dir / "ember_lightgbm_model.txt"
    booster.save_model(str(model_path), num_iteration=best_iteration)

    _emit_progress(96)
    _emit_status("写入模型元数据……")
    metadata = {
        "created_at": datetime.utcnow().isoformat(timespec="seconds") + "Z",
        "npy_path": str(npy_file.resolve()),
        "num_training_samples": int(dataset.x_train.shape[0]),
        "num_validation_samples": int(dataset.x_valid.shape[0]),
        "num_features": int(dataset.x_train.shape[1]),
        "metrics": metrics,
        "lightgbm_params": default_params,
    }

    metadata_path = output_dir / "metadata.json"
    with metadata_path.open("w", encoding="utf-8") as fh:
        json.dump(metadata, fh, ensure_ascii=False, indent=2)

    _emit_progress(100)
    _emit_status("模型训练完成！")
    return {
        "model_path": str(model_path),
        "metadata_path": str(metadata_path),
        "metrics": metrics,
    }


__all__ = ["train_ember_model_from_npy"]
