"""Training utilities for LightGBM models using EMBER-style features."""

from __future__ import annotations

import json
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Callable, Dict, Mapping, Optional

import lightgbm as lgb
import numpy as np
from sklearn.model_selection import train_test_split

from .evaluator import EvaluationResult, evaluate_binary_classifier
from .model_factory import LightGBMConfig, make_lightgbm_config
from .uncertainty import ProbabilitySummary, summarise_probabilities

ProgressCallback = Callable[[int], None]
TextCallback = Callable[[str], None]


@dataclass
class TrainingDataset:
    """Container holding train/validation/test splits."""

    train_x: np.ndarray
    train_y: np.ndarray
    valid_x: Optional[np.ndarray] = None
    valid_y: Optional[np.ndarray] = None
    test_x: Optional[np.ndarray] = None
    test_y: Optional[np.ndarray] = None

    def ensure_float32(self) -> "TrainingDataset":
        self.train_x = np.asarray(self.train_x, dtype=np.float32)
        if self.valid_x is not None:
            self.valid_x = np.asarray(self.valid_x, dtype=np.float32)
        if self.test_x is not None:
            self.test_x = np.asarray(self.test_x, dtype=np.float32)
        self.train_y = np.asarray(self.train_y, dtype=np.float32)
        if self.valid_y is not None:
            self.valid_y = np.asarray(self.valid_y, dtype=np.float32)
        if self.test_y is not None:
            self.test_y = np.asarray(self.test_y, dtype=np.float32)
        return self


_KEY_ALIASES = {
    "x_train": "train_x",
    "train_x": "train_x",
    "trainfeatures": "train_x",
    "train_features": "train_x",
    "trainfeature": "train_x",
    "features_train": "train_x",
    "train": "train_x",
    "x_valid": "valid_x",
    "valid_x": "valid_x",
    "x_val": "valid_x",
    "val_x": "valid_x",
    "validation_x": "valid_x",
    "validfeatures": "valid_x",
    "val_features": "valid_x",
    "valid_features": "valid_x",
    "x_test": "test_x",
    "test_x": "test_x",
    "testfeatures": "test_x",
    "test_features": "test_x",
    "features_test": "test_x",
    "y_train": "train_y",
    "train_y": "train_y",
    "trainlabels": "train_y",
    "train_labels": "train_y",
    "labels_train": "train_y",
    "y_valid": "valid_y",
    "valid_y": "valid_y",
    "y_val": "valid_y",
    "val_y": "valid_y",
    "validation_y": "valid_y",
    "valid_labels": "valid_y",
    "val_labels": "valid_y",
    "y_test": "test_y",
    "test_y": "test_y",
    "testlabels": "test_y",
    "test_labels": "test_y",
    "labels_test": "test_y",
}


def _normalise_key(name: str) -> Optional[str]:
    clean = name.lower().replace("-", "_").replace(" ", "_")
    clean = clean.replace(".npy", "").replace(".npz", "")
    clean = clean.replace(".", "_")
    return _KEY_ALIASES.get(clean)


def _load_from_np_archive(path: Path) -> Dict[str, np.ndarray]:
    arrays: Dict[str, np.ndarray] = {}
    with np.load(path, allow_pickle=True) as data:
        for key in data.files:
            normalised = _normalise_key(key)
            if normalised:
                arrays[normalised] = data[key]
    return arrays


def _load_from_npy(path: Path) -> Dict[str, np.ndarray]:
    data = np.load(path, allow_pickle=True)
    arrays: Dict[str, np.ndarray] = {}
    if isinstance(data, np.lib.npyio.NpzFile):
        return _load_from_np_archive(path)
    if isinstance(data, np.ndarray) and data.dtype == object:
        try:
            obj = data.item()
            if isinstance(obj, Mapping):
                for key, value in obj.items():
                    normalised = _normalise_key(str(key))
                    if normalised:
                        arrays[normalised] = np.asarray(value)
                return arrays
        except Exception:
            pass
    # Otherwise treat it as a single feature matrix (train_x)
    arrays["train_x"] = np.asarray(data)
    return arrays


def _load_from_directory(path: Path) -> Dict[str, np.ndarray]:
    arrays: Dict[str, np.ndarray] = {}
    for file in path.iterdir():
        if not file.is_file():
            continue
        if file.suffix.lower() == ".npz":
            arrays.update(_load_from_np_archive(file))
        elif file.suffix.lower() == ".npy":
            arrays.update(_load_from_npy(file))
    return arrays


def load_numpy_dataset(path: str | Path, text_callback: Optional[TextCallback] = None) -> TrainingDataset:
    """Load train/valid/test arrays from a directory or numpy file."""

    callback = text_callback or (lambda *_: None)
    location = Path(path)
    if not location.exists():
        raise FileNotFoundError(f"找不到数据文件: {path}")

    callback(f"加载数据: {location}")

    if location.is_dir():
        arrays = _load_from_directory(location)
    else:
        if location.suffix.lower() == ".npz":
            arrays = _load_from_np_archive(location)
        elif location.suffix.lower() == ".npy":
            arrays = _load_from_npy(location)
        else:
            raise ValueError("仅支持 .npy 或 .npz 文件")

    train_x = arrays.get("train_x")
    train_y = arrays.get("train_y")

    if train_x is None or train_y is None:
        raise ValueError("数据中缺少 train_x 或 train_y。请提供包含特征和标签的 .npy/.npz 文件。")

    dataset = TrainingDataset(
        train_x=train_x,
        train_y=train_y,
        valid_x=arrays.get("valid_x"),
        valid_y=arrays.get("valid_y"),
        test_x=arrays.get("test_x"),
        test_y=arrays.get("test_y"),
    )
    return dataset.ensure_float32()


class LightGBMTrainer:
    """High level helper that mirrors the official EMBER training recipe."""

    def __init__(self, config: Optional[LightGBMConfig] = None):
        self.config = config or LightGBMConfig()

    def _split_validation(
        self,
        dataset: TrainingDataset,
        config: LightGBMConfig,
        random_state: int,
        text_callback: TextCallback,
    ) -> TrainingDataset:
        if dataset.valid_x is not None and dataset.valid_y is not None:
            return dataset
        if config.validation_fraction <= 0:
            return dataset
        text_callback(f"创建 {config.validation_fraction:.0%} 验证集用于早停")
        train_x, valid_x, train_y, valid_y = train_test_split(
            dataset.train_x,
            dataset.train_y,
            test_size=config.validation_fraction,
            random_state=random_state,
            stratify=dataset.train_y if len(np.unique(dataset.train_y)) > 1 else None,
        )
        dataset.train_x = train_x
        dataset.train_y = train_y
        dataset.valid_x = valid_x
        dataset.valid_y = valid_y
        return dataset

    def train_from_path(
        self,
        dataset_path: str | Path,
        output_dir: str | Path,
        progress_callback: Optional[ProgressCallback] = None,
        text_callback: Optional[TextCallback] = None,
        overrides: Optional[Mapping[str, float]] = None,
    ) -> Path:
        dataset = load_numpy_dataset(dataset_path, text_callback)
        return self.train(dataset, output_dir, progress_callback, text_callback, overrides=overrides)

    def train(
        self,
        dataset: TrainingDataset,
        output_dir: str | Path,
        progress_callback: Optional[ProgressCallback] = None,
        text_callback: Optional[TextCallback] = None,
        overrides: Optional[Mapping[str, float]] = None,
    ) -> Path:
        progress = progress_callback or (lambda *_: None)
        text = text_callback or (lambda *_: None)

        config = make_lightgbm_config(overrides) if overrides else self.config
        progress(5)
        text("初始化 LightGBM 训练器")

        dataset = self._split_validation(dataset, config, config.random_state, text).ensure_float32()
        progress(15)
        text("构建 LightGBM 数据集")

        train_data = lgb.Dataset(dataset.train_x, label=dataset.train_y)
        valid_sets = [train_data]
        valid_names = ["train"]
        if dataset.valid_x is not None and dataset.valid_y is not None:
            valid_data = lgb.Dataset(dataset.valid_x, label=dataset.valid_y, reference=train_data)
            valid_sets.append(valid_data)
            valid_names.append("valid")

        num_rounds = config.num_boost_round
        train_start = time.time()

        def _progress_callback(total_rounds: int, start: int, end: int) -> Callable[[lgb.callback.CallbackEnv], None]:
            span = max(end - start, 1)

            def _callback(env: lgb.callback.CallbackEnv) -> None:
                iteration = env.iteration
                frac = min(iteration / float(total_rounds), 1.0)
                progress_value = start + int(frac * span)
                progress(min(progress_value, end))
                if env.evaluation_result_list and (iteration % 50 == 0 or iteration == total_rounds):
                    parts = [
                        f"{name}-{metric}:{value:.5f}"
                        for name, metric, value, _ in env.evaluation_result_list
                    ]
                    text(f"迭代 {iteration}: {' | '.join(parts)}")

            return _callback

        text("开始训练 LightGBM 模型（参考 EMBER 官方配置）")
        booster = lgb.train(
            config.params,
            train_data,
            num_boost_round=num_rounds,
            valid_sets=valid_sets,
            valid_names=valid_names,
            callbacks=[
                _progress_callback(num_rounds, 15, 85),
                lgb.early_stopping(config.early_stopping_rounds, verbose=False),
                lgb.log_evaluation(period=50),
            ],
        )

        best_iteration = booster.best_iteration or booster.current_iteration()
        train_duration = time.time() - train_start
        text(f"训练完成，最佳迭代次数: {best_iteration}，耗时 {train_duration:.1f} 秒")
        progress(90)

        metrics: Dict[str, EvaluationResult] = {}
        summaries: Dict[str, ProbabilitySummary] = {}

        def _evaluate(split_name: str, features: Optional[np.ndarray], labels: Optional[np.ndarray]) -> None:
            if features is None or labels is None:
                return
            scores = booster.predict(features, num_iteration=best_iteration)
            metrics[split_name] = evaluate_binary_classifier(labels, scores)
            summaries[split_name] = summarise_probabilities(scores)
            text(
                f"{split_name} 集: 准确率 {metrics[split_name].accuracy:.4f}, "
                f"AUC {metrics[split_name].auc if metrics[split_name].auc is not None else float('nan'):.4f}"
            )

        _evaluate("train", dataset.train_x, dataset.train_y)
        _evaluate("valid", dataset.valid_x, dataset.valid_y)
        _evaluate("test", dataset.test_x, dataset.test_y)

        progress(95)
        output_path = Path(output_dir)
        output_path.mkdir(parents=True, exist_ok=True)

        model_file = output_path / "lightgbm_model.txt"
        booster.save_model(str(model_file))

        feature_importance = booster.feature_importance(importance_type="gain")
        report = {
            "config": {
                "params": config.params,
                "num_boost_round": num_rounds,
                "early_stopping_rounds": config.early_stopping_rounds,
                "validation_fraction": config.validation_fraction,
                "random_state": config.random_state,
            },
            "best_iteration": best_iteration,
            "train_duration_sec": train_duration,
            "metrics": {split: result.to_dict() for split, result in metrics.items()},
            "probability_summary": {split: summary.to_dict() for split, summary in summaries.items()},
            "feature_importance": feature_importance.tolist(),
        }

        report_file = output_path / "training_report.json"
        with report_file.open("w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2, ensure_ascii=False)

        text(f"模型已保存至 {model_file}")
        text(f"训练报告已保存至 {report_file}")
        progress(100)
        return model_file


__all__ = ["TrainingDataset", "LightGBMTrainer", "load_numpy_dataset"]
