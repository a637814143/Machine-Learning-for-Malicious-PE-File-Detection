"""Model factory for LightGBM classifiers used throughout the project.

The project follows the public EMBER dataset reference implementation which
trains a gradient boosting decision tree model using LightGBM.  This module
collects the default parameters and helper utilities so that other parts of the
codebase (GUI tasks, trainers, evaluators) can import a single location for
model configuration.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, Mapping, Optional


_DEFAULT_EMBER_PARAMS: Dict[str, Any] = {
    "boosting_type": "gbdt",
    "objective": "binary",
    "metric": "auc",
    "max_depth": -1,
    "num_leaves": 153,
    "learning_rate": 0.05,
    "feature_fraction": 1.0,
    "bagging_fraction": 0.7,
    "bagging_freq": 1,
    "min_data_in_leaf": 20,
    "lambda_l1": 0.0,
    "lambda_l2": 0.0,
    "max_bin": 255,
    "verbose": -1,
}


@dataclass
class LightGBMConfig:
    """Configuration container mirroring the official EMBER training setup."""

    params: Dict[str, Any] = field(default_factory=lambda: dict(_DEFAULT_EMBER_PARAMS))
    num_boost_round: int = 1000
    early_stopping_rounds: int = 50
    validation_fraction: float = 0.1
    random_state: int = 2018

    def merged_params(self, overrides: Optional[Mapping[str, Any]] = None) -> Dict[str, Any]:
        """Return a dictionary of training parameters with overrides applied."""

        merged: Dict[str, Any] = dict(self.params)
        if overrides:
            for key, value in overrides.items():
                if value is None:
                    continue
                merged[key] = value
        return merged


def make_lightgbm_config(overrides: Optional[Mapping[str, Any]] = None) -> LightGBMConfig:
    """Construct a :class:`LightGBMConfig` applying optional overrides."""

    cfg = LightGBMConfig()
    if overrides:
        cfg.params.update({k: v for k, v in overrides.items() if k in cfg.params})
        # Allow overriding basic training hyper-parameters as well.
        if "num_boost_round" in overrides:
            cfg.num_boost_round = int(overrides["num_boost_round"])
        if "early_stopping_rounds" in overrides:
            cfg.early_stopping_rounds = int(overrides["early_stopping_rounds"])
        if "validation_fraction" in overrides:
            cfg.validation_fraction = float(overrides["validation_fraction"])
        if "random_state" in overrides:
            cfg.random_state = int(overrides["random_state"])
    return cfg


__all__ = ["LightGBMConfig", "make_lightgbm_config"]
