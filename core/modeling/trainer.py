
"""Training utilities that operate on NumPy vector files."""

from __future__ import annotations

import contextlib
from dataclasses import dataclass
import pickle
import inspect
import numbers
import os
from os import PathLike
from pathlib import Path
from typing import (
    TYPE_CHECKING,
    Any,
    Callable,
    Dict,
    Iterable,
    List,
    Mapping,
    Optional,
    Sequence,
    Tuple,
    Union,
    cast,
)
import warnings

import numpy as np
from numpy.lib.npyio import NpzFile

if TYPE_CHECKING:  # pragma: no cover - type hints only
    import lightgbm as lgb  # type: ignore

_LIGHTGBM_MODULE: Optional["lgb"] = None

from core.feature_engineering.vectorization import VECTOR_SIZE
from .model_factory import LightGBMConfig, build_ember_lightgbm_config
from core.utils.lightgbm_loader import import_lightgbm as _load_lightgbm


@dataclass(frozen=True)
class DatasetBundle:
    """Container holding vectors and labels for a dataset split."""

    vectors: np.ndarray
    labels: np.ndarray

    def __post_init__(self) -> None:
        if self.vectors.ndim != 2:
            raise ValueError(
                "向量文件维度异常: 期望二维数组, got "
                f"{self.vectors.ndim}-d"
            )
        if self.vectors.shape[0] != self.labels.shape[0]:
            raise ValueError(
                "向量和标签数量不一致: "
                f"vectors={self.vectors.shape[0]} labels={self.labels.shape[0]}"
            )
        if self.vectors.shape[1] != VECTOR_SIZE:
            raise ValueError(
                f"特征维度与 EMBER 不匹配: "
                f"got {self.vectors.shape[1]}, expected {VECTOR_SIZE}"
            )


def _import_lightgbm() -> lgb:
    """Import LightGBM lazily and provide actionable error messages."""

    global _LIGHTGBM_MODULE
    if _LIGHTGBM_MODULE is not None:
        return _LIGHTGBM_MODULE

    try:  # pragma: no cover - exercised in integration
        lgb_module = cast("lgb", _load_lightgbm())
    except ModuleNotFoundError as exc:  # pragma: no cover - optional dependency missing
        raise ImportError(
            "缺少 lightgbm 库，无法训练模型。请运行 'pip install lightgbm' 后重试。"
        ) from exc

    _LIGHTGBM_MODULE = lgb_module
    return lgb_module


def _lightgbm_train_supports_parameter(name: str) -> bool:
    """Return whether ``lgb.train`` accepts the given keyword argument."""

    lgb_module = _import_lightgbm()
    try:
        signature = inspect.signature(lgb_module.train)
    except (TypeError, ValueError):  # pragma: no cover - CPython internal error
        return True
    return name in signature.parameters


def _normalise_vector_array(array: np.ndarray) -> np.ndarray:
    if array.ndim != 2:
        raise ValueError("向量数组维度异常，应为二维数组")
    return array.astype(np.float32, copy=False)


def _normalise_label_array(array: np.ndarray) -> np.ndarray:
    if array.ndim != 1:
        raise ValueError("标签数组维度异常，应为一维数组")
    return array.astype(np.int64, copy=False)


def _extract_from_saved_object(obj: Any) -> Tuple[np.ndarray, np.ndarray]:
    """Convert the object produced by ``np.load`` into feature/label arrays."""

    if isinstance(obj, np.ndarray) and obj.dtype != object:
        # Legacy format that only stores features. Labels must be provided
        # elsewhere so raise an informative error.
        raise ValueError(
            "加载到的向量文件缺少标签信息，请重新生成或升级数据文件。"
        )

    if isinstance(obj, NpzFile):
        if "x" not in obj or "y" not in obj:
            raise ValueError("保存的 npz 文件缺少 'x' 或 'y' 数组")
        return _normalise_vector_array(obj["x"]), _normalise_label_array(obj["y"])

    if isinstance(obj, np.ndarray) and obj.dtype == object:
        if obj.shape == ():
            obj = obj.item()
        else:
            obj = obj.tolist()

    if isinstance(obj, dict):
        features = obj.get("x")
        labels = obj.get("y")
        if features is None or labels is None:
            raise ValueError("保存的字典缺少 'x' 或 'y' 键")
        return _normalise_vector_array(np.asarray(features)), _normalise_label_array(
            np.asarray(labels)
        )

    if isinstance(obj, (list, tuple)) and len(obj) == 2:
        features, labels = obj
        return _normalise_vector_array(np.asarray(features)), _normalise_label_array(
            np.asarray(labels)
        )

    raise TypeError(
        "不支持的向量文件格式，请使用最新的向量化脚本重新生成数据。"
    )


Pathish = Union[str, Path, PathLike[str]]

DEFAULT_MODEL_FILENAME = "model.txt"
try:
    _PROJECT_ROOT = Path(__file__).resolve().parents[2]
except IndexError:  # pragma: no cover - defensive fallback
    _PROJECT_ROOT = Path(__file__).resolve().parent
_DEFAULT_VALIDATION_VECTORS = (
    _PROJECT_ROOT / "data" / "npz" / "v.npz"
)


def _coerce_path(value: Pathish) -> Path:
    if isinstance(value, Path):
        return value
    return Path(value)


def _resolve_vector_file(path: Path) -> Path:
    """Return a concrete vector file path, supporting directory inputs."""

    if path.exists() and path.is_dir():
        patterns = ("*.npy", "*.npz")

        def _collect_candidates(search: Callable[[str], Iterable[Path]]) -> List[Path]:
            files: List[Path] = []
            for pattern in patterns:
                files.extend(candidate for candidate in search(pattern) if candidate.is_file())
            return files

        candidates = _collect_candidates(path.glob)
        if not candidates:
            candidates = _collect_candidates(path.rglob)

        candidates.sort(key=lambda p: p.stat().st_mtime)

        if not candidates:
            raise FileNotFoundError(
                f"指定的目录中未找到向量文件: {path}"
            )
        return candidates[-1]
    if not path.exists() and not path.suffix:
        for extension in (".npy", ".npz"):
            candidate = path.with_suffix(extension)
            if candidate.exists():
                return candidate
    return path


def _load_dataset_bundle(vector_file: Pathish) -> DatasetBundle:
    path = _resolve_vector_file(_coerce_path(vector_file))
    if not path.exists():
        raise FileNotFoundError(f"向量文件不存在: {path}")

    try:
        loaded = np.load(path, allow_pickle=False)
        used_pickle = False
    except (ValueError, pickle.UnpicklingError):
        loaded = np.load(path, allow_pickle=True)
        used_pickle = True

    try:
        features, labels = _extract_from_saved_object(loaded)
    finally:
        if isinstance(loaded, NpzFile):
            loaded.close()

    if used_pickle:
        warnings.warn(
            "向量文件依赖 pickle 反序列化，建议使用最新的向量化脚本重新生成以获得 .npz 格式。",
            RuntimeWarning,
            stacklevel=2,
        )
    return DatasetBundle(features, labels)


def _resolve_model_output_path(model_output: Pathish) -> Path:
    output_path = _coerce_path(model_output)

    if output_path.exists():
        if output_path.is_dir():
            return output_path / DEFAULT_MODEL_FILENAME
        return output_path

    if output_path.suffix:
        return output_path

    return output_path / DEFAULT_MODEL_FILENAME


def _describe_model_output_path(output_path: Path) -> str:
    """Return a human readable description for debugging model persistence."""

    description_parts = [f"目标文件: {output_path}"]

    parent = output_path.parent
    try:
        parent_exists = parent.exists()
    except OSError:
        parent_exists = False
    description_parts.append(
        f"父目录: {parent} (存在: {'是' if parent_exists else '否'})"
    )

    try:
        if output_path.exists():
            try:
                size = output_path.stat().st_size
            except OSError:
                size = None
            if size is not None:
                description_parts.append(f"已存在文件 (大小: {size} 字节)")
            else:
                description_parts.append("已存在文件 (大小未知)")
        else:
            description_parts.append("文件不存在，将在保存时创建")
    except OSError:
        description_parts.append("无法确定文件是否存在")

    return ", ".join(description_parts)


def _ensure_model_path_writable(output_path: Path) -> Path:
    """Ensure the final LightGBM model path is writable before saving."""

    parent = output_path.parent
    try:
        parent.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        raise PermissionError(f"无法创建模型保存目录: {parent}") from exc

    pre_existing = output_path.exists()
    try:
        with output_path.open("a+b"):
            pass
    except OSError as exc:
        raise PermissionError(f"无法写入模型文件: {output_path}") from exc
    else:
        if not pre_existing:
            try:
                output_path.unlink()
            except OSError:
                pass

    return output_path


def _prepare_valid_sets(
    valid_bundles: Sequence[Tuple[str, DatasetBundle]]
) -> Tuple[List[Any], List[str]]:
    lgb_module = _import_lightgbm()
    valid_sets: List[Any] = []
    valid_names: List[str] = []
    for name, bundle in valid_bundles:
        valid_sets.append(
            lgb_module.Dataset(bundle.vectors, label=bundle.labels, free_raw_data=False)
        )
        valid_names.append(name)
    return valid_sets, valid_names


def _make_progress_callback(
    total_rounds: int,
    progress_callback: Optional[callable],
    text_callback: Optional[callable],
    report_every: int = 10,
) -> Optional[Any]:
    if progress_callback is None and text_callback is None:
        return None

    def _format_metric_value(value: Any) -> str:
        if isinstance(value, numbers.Real):
            return f"{float(value):.4f}"
        try:
            numeric = float(value)
        except (TypeError, ValueError):
            return str(value)
        else:
            return f"{numeric:.4f}"

    def _callback(env) -> None:
        iteration = env.iteration + 1
        if progress_callback is not None:
            progress = int(min(iteration / max(total_rounds, 1), 1.0) * 100)
            progress_callback(progress)
        if text_callback is not None and iteration % report_every == 0:
            metrics = []
            for name, loss, *_ in env.evaluation_result_list:
                metrics.append(f"{name}={_format_metric_value(loss)}")
            metric_str = ", ".join(metrics) if metrics else "迭代完成"
            # text_callback(f"训练进度 {iteration}/{total_rounds}: {metric_str}")

    _callback.order = 10  # type: ignore[attr-defined]
    return _callback


def _resolve_default_validation_vectors() -> Optional[Path]:
    """Return the default validation vector file if it exists."""

    candidate = _DEFAULT_VALIDATION_VECTORS
    try:
        if candidate.exists():
            return candidate
    except OSError:
        return None
    return None


def train_ember_model_from_npy(
    train_vectors: Pathish,
    model_output: Optional[Pathish] = None,
    valid_vectors: Optional[Pathish] = None,
    *,
    lgbm_params: Optional[Mapping[str, Any]] = None,
    overrides: Optional[Mapping[str, Any]] = None,
    num_boost_round: Optional[int] = None,
    early_stopping_rounds: Optional[int] = 50,
    progress_callback=None,
    text_callback=None,
    status_callback=None,
) -> Any:
    """Train a LightGBM model using feature/label arrays stored in ``.npz``
    archives (legacy ``.npy`` pickle files remain supported)."""

    lgb_module = _import_lightgbm()

    # ``status_callback`` was used by earlier UI code as the textual channel while
    # ``text_callback`` is the modern equivalent.  Support both to remain
    # backwards compatible, mirroring messages to either callback when provided.
    if text_callback is None and status_callback is not None:
        text_callback = status_callback
    elif text_callback is not None and status_callback is not None:
        original_text_callback = text_callback

        def _fanout(message: str) -> None:
            original_text_callback(message)
            status_callback(message)

        text_callback = _fanout

    train_bundle = _load_dataset_bundle(train_vectors)

    unique_labels = np.unique(train_bundle.labels)
    if unique_labels.size < 2:
        message = (
            "训练数据集中仅包含单一类别，无法训练模型。"
            " 请检查标注或重新生成包含正负样本的数据。"
        )
        if text_callback is not None:
            text_callback(message)
        raise ValueError(message)

    resolved_valid_vectors: Optional[Pathish]
    if isinstance(valid_vectors, str):
        stripped = valid_vectors.strip()
        resolved_valid_vectors = stripped or None
    else:
        resolved_valid_vectors = valid_vectors

    if resolved_valid_vectors is None:
        fallback_valid = _resolve_default_validation_vectors()
        if fallback_valid is not None:
            resolved_valid_vectors = fallback_valid
            if text_callback is not None:
                text_callback(f"未指定验证集，使用默认路径 {fallback_valid}")
        elif text_callback is not None:
            text_callback("未提供验证集，将仅使用训练数据监控损失")

    valid_bundles: List[Tuple[str, DatasetBundle]] = []
    if resolved_valid_vectors is not None:
        valid_bundle = _load_dataset_bundle(resolved_valid_vectors)
        valid_bundles.append(("valid", valid_bundle))

    combined_overrides: Optional[Mapping[str, Any]] = overrides
    if overrides is not None and lgbm_params is not None:
        merged: Dict[str, Any] = dict(lgbm_params)
        merged.update(overrides)
        combined_overrides = merged
    elif overrides is None and lgbm_params is not None:
        combined_overrides = lgbm_params

    config: LightGBMConfig = build_ember_lightgbm_config(
        overrides=combined_overrides,
        num_boost_round=num_boost_round,
        early_stopping_rounds=early_stopping_rounds,
    )

    dtrain = lgb_module.Dataset(
        train_bundle.vectors, label=train_bundle.labels, free_raw_data=False
    )
    valid_sets, valid_names = _prepare_valid_sets(valid_bundles)

    callbacks: List[Any] = []
    progress_cb = _make_progress_callback(
        config.num_boost_round,
        progress_callback,
        text_callback,
    )
    if progress_cb is not None:
        callbacks.append(progress_cb)

    train_kwargs: Dict[str, Any] = {
        "num_boost_round": config.num_boost_round,
        "callbacks": callbacks,
    }
    if valid_sets:
        train_kwargs["valid_sets"] = valid_sets
        train_kwargs["valid_names"] = valid_names

    fallback_callback: Optional[Any] = None
    fallback_applied = False
    if config.early_stopping_rounds is not None:
        if hasattr(lgb_module, "early_stopping"):
            fallback_callback = lgb_module.early_stopping(config.early_stopping_rounds)

        if _lightgbm_train_supports_parameter("early_stopping_rounds"):
            train_kwargs["early_stopping_rounds"] = config.early_stopping_rounds
        elif fallback_callback is not None:
            callbacks.append(fallback_callback)
            fallback_applied = True
            if text_callback is not None:
                text_callback(
                    "当前 LightGBM 版本不支持 early_stopping_rounds 参数，已改用回调实现提前停止。"
                )
        elif text_callback is not None:
            text_callback(
                "当前 LightGBM 版本不支持提前停止参数，将继续训练直至最大轮次。"
            )

    with _redirect_lightgbm_logs(text_callback):
        try:
            booster = lgb_module.train(
                config.params,
                dtrain,
                **train_kwargs,
            )
        except TypeError as exc:
            should_retry = (
                config.early_stopping_rounds is not None
                and "early_stopping_rounds" in str(exc)
            )
            if not should_retry:
                raise

            train_kwargs.pop("early_stopping_rounds", None)
            if fallback_callback is not None and not fallback_applied:
                callbacks.append(fallback_callback)
                fallback_applied = True
                if text_callback is not None:
                    text_callback(
                        "当前 LightGBM 版本不支持 early_stopping_rounds 参数，已改用回调实现提前停止。"
                    )
            elif text_callback is not None and not fallback_applied:
                text_callback(
                    "当前 LightGBM 版本不支持提前停止参数，将继续训练直至最大轮次。"
                )

            booster = lgb_module.train(
                config.params,
                dtrain,
                **train_kwargs,
            )

    if model_output is not None:
        resolved_output = _resolve_model_output_path(model_output)
        if text_callback is not None:
            text_callback(
                "模型保存路径分析: "
                f"{_describe_model_output_path(resolved_output)}"
            )
        try:
            output_path = _ensure_model_path_writable(resolved_output)
        except PermissionError as exc:
            if text_callback is not None:
                text_callback(f"模型保存路径不可写: {exc}")
            raise
        else:
            if text_callback is not None:
                text_callback(
                    f"模型保存路径可写: {output_path}"
                )
        try:
            booster.save_model(os.fspath(output_path))
        except Exception as exc:
            message = f"模型保存失败: {exc}"
            if text_callback is not None:
                text_callback(message)
            raise
        else:
            if text_callback is not None:
                text_callback(f"模型已保存到 {output_path}")

    if progress_callback is not None:
        progress_callback(100)

    return booster


@contextlib.contextmanager
def _redirect_lightgbm_logs(text_callback):
    """Route LightGBM 的日志到回调，并禁止其直接输出到控制台。"""

    lgb_module = _import_lightgbm()

    try:
        previous_logger = lgb_module.basic._LOGGER
        previous_info = lgb_module.basic._INFO_METHOD_NAME
        previous_warning = lgb_module.basic._WARNING_METHOD_NAME
    except AttributeError:  # pragma: no cover - unexpected LightGBM internals
        yield
        return

    class _CallbackLogger:
        def __init__(self, callback):
            self._callback = callback

        def info(self, message: str) -> None:
            if self._callback is not None:
                self._callback(message)

        def warning(self, message: str) -> None:
            if self._callback is not None:
                self._callback(message)

    logger = _CallbackLogger(text_callback)
    lgb_module.register_logger(logger)
    try:
        yield
    finally:
        try:
            lgb_module.register_logger(previous_logger, previous_info, previous_warning)
        except TypeError:  # pragma: no cover - fallback for unexpected logger
            lgb_module.basic._LOGGER = previous_logger
            lgb_module.basic._INFO_METHOD_NAME = previous_info
            lgb_module.basic._WARNING_METHOD_NAME = previous_warning
