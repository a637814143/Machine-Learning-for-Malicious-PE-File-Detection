"""Utility helpers to summarise prediction uncertainty."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

import numpy as np


@dataclass
class ProbabilitySummary:
    """Summary statistics for a list of probability predictions."""

    mean: float
    std: float
    percentile_05: float
    percentile_95: float

    def to_dict(self) -> dict[str, float]:
        return {
            "mean": self.mean,
            "std": self.std,
            "percentile_05": self.percentile_05,
            "percentile_95": self.percentile_95,
        }


def summarise_probabilities(probs: Iterable[float]) -> ProbabilitySummary:
    """Return simple uncertainty statistics for probability predictions."""

    arr = np.asarray(list(probs), dtype=float)
    if arr.size == 0:
        return ProbabilitySummary(mean=float("nan"), std=float("nan"), percentile_05=float("nan"), percentile_95=float("nan"))

    return ProbabilitySummary(
        mean=float(arr.mean()),
        std=float(arr.std(ddof=0)),
        percentile_05=float(np.percentile(arr, 5)),
        percentile_95=float(np.percentile(arr, 95)),
    )


__all__ = ["ProbabilitySummary", "summarise_probabilities"]
