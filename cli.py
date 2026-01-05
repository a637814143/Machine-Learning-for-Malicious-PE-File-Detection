#!/usr/bin/env python3
"""Command line entry point for training the EMBER LightGBM model."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Any, Dict

# Ensure local imports work when running as a standalone script.
ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.modeling import trainer
from core.modeling.trainer import TrainingResult


def _resolve_threshold(user_threshold: float | None) -> float:
    """Pick a decision threshold, defaulting to the project constant."""
    if user_threshold is not None:
        return float(user_threshold)
    try:
        from scripts.D import DEFAULT_THRESHOLD
    except Exception:
        return 0.5
    return float(DEFAULT_THRESHOLD)


def _format_metric_value(value: Any, *, percentage: bool = False) -> str:
    if value is None:
        return "N/A"
    try:
        numeric = float(value)
    except (TypeError, ValueError):
        return str(value)
    if percentage:
        return f"{numeric * 100:.2f}%"
    return f"{numeric:.6f}"


def _print_metric_block(name: str, metrics: Dict[str, Any]) -> None:
    """Print a concise, single-line metric summary for one dataset."""
    accuracy = _format_metric_value(metrics.get("accuracy"), percentage=True)
    precision = _format_metric_value(metrics.get("precision"), percentage=True)
    recall = _format_metric_value(metrics.get("recall"), percentage=True)
    f1_score = _format_metric_value(metrics.get("f1_score"), percentage=True)
    threshold = _format_metric_value(metrics.get("threshold"))

    samples = metrics.get("samples", "N/A")
    tp = metrics.get("tp", "N/A")
    tn = metrics.get("tn", "N/A")
    fp = metrics.get("fp", "N/A")
    fn = metrics.get("fn", "N/A")

    print(
        f"[{name}] acc={accuracy} precision={precision} recall={recall} f1={f1_score} "
        f"| samples={samples} tp={tp} tn={tn} fp={fp} fn={fn} threshold={threshold}"
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description=(
            "Train an EMBER LightGBM model using train/validation/test vector files "
            "and report evaluation metrics."
        )
    )
    parser.add_argument("train_vectors", help="Training vectors (.npz/.npy file or directory).")
    parser.add_argument("valid_vectors", help="Validation vectors (.npz/.npy file or directory).")
    parser.add_argument("test_vectors", help="Test vectors (.npz/.npy file or directory).")
    parser.add_argument(
        "--model-out",
        default=str(ROOT / "model.txt"),
        help="Where to save the trained LightGBM model (default: ./model.txt).",
    )
    parser.add_argument(
        "--threads",
        type=int,
        default=None,
        help="Optional LightGBM num_threads override.",
    )
    parser.add_argument(
        "--num-rounds",
        type=int,
        default=None,
        help="Number of boosting rounds (default aligns with EMBER).",
    )
    parser.add_argument(
        "--early-stopping",
        type=int,
        default=50,
        help="Early stopping rounds; set to 0 to disable.",
    )
    parser.add_argument(
        "--threshold",
        type=float,
        default=None,
        help="Decision threshold for metric calculation.",
    )
    args = parser.parse_args()

    threshold = _resolve_threshold(args.threshold)
    lgbm_params: Dict[str, Any] = {}
    if args.threads is not None and args.threads > 0:
        lgbm_params["num_threads"] = args.threads

    num_rounds = args.num_rounds if args.num_rounds and args.num_rounds > 0 else None
    early_stopping = args.early_stopping
    if early_stopping is not None and early_stopping <= 0:
        early_stopping = None

    print(f"Training started. Model will be saved to {args.model_out}")
    print(f"Metrics threshold: {threshold}")

    try:
        training_result = trainer.train_ember_model_from_npy(
            args.train_vectors,
            args.model_out,
            valid_vectors=args.valid_vectors,
            lgbm_params=lgbm_params or None,
            num_boost_round=num_rounds,
            early_stopping_rounds=early_stopping,
            compute_eval_metrics=True,
            evaluation_threshold=threshold,
            text_callback=lambda msg: print(msg),
        )
    except Exception as exc:
        print(f"Training failed: {exc}", file=sys.stderr)
        sys.exit(1)

    if isinstance(training_result, TrainingResult):
        booster = training_result.booster
        evaluation_metrics: Dict[str, Dict[str, Any]] = dict(training_result.evaluation_metrics)
    else:
        booster = training_result
        evaluation_metrics = {}

    # Always compute test-set metrics explicitly.
    test_bundle = trainer._load_dataset_bundle(args.test_vectors)
    test_reports = trainer._generate_evaluation_reports(
        booster,
        [("test", test_bundle)],
        threshold=threshold,
    )
    evaluation_metrics.update(test_reports)

    # Ensure validation metrics exist even if training skipped their computation.
    if "valid" not in evaluation_metrics:
        try:
            valid_bundle = trainer._load_dataset_bundle(args.valid_vectors)
            validation_reports = trainer._generate_evaluation_reports(
                booster,
                [("valid", valid_bundle)],
                threshold=threshold,
            )
            evaluation_metrics.update(validation_reports)
        except Exception:
            pass

    best_iteration = getattr(booster, "best_iteration", None)
    best_scores = getattr(booster, "best_score", None)

    print("\nTraining complete.")
    if best_iteration:
        print(f"Best iteration: {best_iteration}")
    if isinstance(best_scores, dict) and best_scores:
        print("Validation scores from LightGBM:")
        for dataset_name, metrics in best_scores.items():
            formatted = ", ".join(f"{k}={_format_metric_value(v)}" for k, v in metrics.items())
            print(f"  - {dataset_name}: {formatted}")

    if evaluation_metrics:
        print("\nEvaluation metrics (threshold applied to probabilities):")
        for key in ("train", "valid", "test"):
            if key in evaluation_metrics:
                _print_metric_block(key, evaluation_metrics[key])
        # Print any additional metric sets that may exist.
        for name, metrics in evaluation_metrics.items():
            if name not in {"train", "valid", "test"}:
                _print_metric_block(name, metrics)
    else:
        print("No evaluation metrics were produced.")


if __name__ == "__main__":
    main()
