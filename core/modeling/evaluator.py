"""Evaluation helpers for LightGBM models."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, Iterable, Optional

import numpy as np
from sklearn.metrics import accuracy_score, precision_recall_fscore_support, roc_auc_score


@dataclass
class EvaluationResult:
    """Container holding common binary classification metrics."""

    accuracy: float
    auc: Optional[float]
    precision: float
    recall: float
    f1: float
    threshold: float = 0.5

    def to_dict(self) -> Dict[str, float]:
        return {
            "accuracy": self.accuracy,
            "auc": self.auc if self.auc is not None else float("nan"),
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "threshold": self.threshold,
        }


def evaluate_binary_classifier(
    y_true: Iterable[int] | np.ndarray,
    y_scores: Iterable[float] | np.ndarray,
    threshold: float = 0.5,
) -> EvaluationResult:
    """Compute accuracy, ROC-AUC and PR metrics for binary classifiers."""

    y_true_arr = np.asarray(y_true)
    scores = np.asarray(y_scores)
    preds = (scores >= threshold).astype(int)

    accuracy = float(accuracy_score(y_true_arr, preds))

    try:
        auc = float(roc_auc_score(y_true_arr, scores))
    except ValueError:
        auc = None

    precision, recall, f1, _ = precision_recall_fscore_support(
        y_true_arr, preds, average="binary", zero_division=0
    )

    return EvaluationResult(
        accuracy=accuracy,
        auc=auc,
        precision=float(precision),
        recall=float(recall),
        f1=float(f1),
        threshold=threshold,
    )


__all__ = ["EvaluationResult", "evaluate_binary_classifier"]
