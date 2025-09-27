"""Factory helpers for creating LightGBM training configurations."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, Mapping, Optional

import multiprocessing

# Default LightGBM hyper-parameters taken from the official EMBER pipeline.
# See https://github.com/elastic/ember/blob/master/train_model_lightgbm.py
_EMBER_LIGHTGBM_BASE_PARAMS: Dict[str, Any] = {
    "boosting_type": "gbdt",
    "objective": "binary",
    "metric": "auc",
    "num_leaves": 2048,
    "learning_rate": 0.05,
    "feature_fraction": 0.1,
    "bagging_fraction": 0.5,
    "bagging_freq": 1,
    "min_data_in_leaf": 50,
    "lambda_l1": 1.0,
    "lambda_l2": 1.0,
    "max_bin": 255,
}


@dataclass(frozen=True)
class LightGBMConfig:
    """Configuration for training a LightGBM model."""

    params: Dict[str, Any]
    num_boost_round: int = 600
    early_stopping_rounds: Optional[int] = None


def build_ember_lightgbm_config(
    overrides: Optional[Mapping[str, Any]] = None,
    num_boost_round: Optional[int] = None,
    early_stopping_rounds: Optional[int] = 50,
) -> LightGBMConfig:
    """Return the LightGBM configuration that replicates the EMBER setup.

    Parameters
    ----------
    overrides:
        Optional dictionary to tweak the default LightGBM parameters. This is
        applied on top of the official EMBER defaults.
    num_boost_round:
        Number of boosting rounds. EMBER uses 600 by default.
    early_stopping_rounds:
        Number of rounds with no improvement before stopping. Set ``None`` to
        disable early stopping.
    """

    params = dict(_EMBER_LIGHTGBM_BASE_PARAMS)

    # Align thread usage with the current machine if not explicitly overridden.
    if "num_threads" not in params and "num_threads" not in (overrides or {}):
        params["num_threads"] = multiprocessing.cpu_count() or 1

    if overrides:
        params.update(overrides)

    rounds = num_boost_round if num_boost_round is not None else 600

    return LightGBMConfig(
        params=params,
        num_boost_round=rounds,
        early_stopping_rounds=early_stopping_rounds,
    )
