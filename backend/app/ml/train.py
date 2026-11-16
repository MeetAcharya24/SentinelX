"""Trains the baseline detectors and reports test-split metrics: `python -m app.ml.train`."""

import sys
from collections.abc import Sequence
from datetime import UTC, datetime
from pathlib import Path

import sklearn

from app.core.config import get_settings
from app.ml.dataset import DatasetError, FlowDataset, load_split
from app.ml.persistence import ModelMetadata, save_model
from app.ml.schema import FEATURE_COLUMNS, TESTING_SPLIT, TRAINING_SPLIT, SplitFile
from app.ml.training import (
    Baseline,
    BaselineResult,
    isolation_forest,
    random_forest,
    train_and_evaluate,
)


def _describe_split(name: str, dataset: FlowDataset) -> str:
    attack_share = dataset.labels.mean()
    return f"{name}: {len(dataset.labels):,} rows, {attack_share:.1%} attacks"


def _describe_result(result: BaselineResult) -> list[str]:
    metrics = result.metrics
    lines = [
        "",
        result.name,
        f"  Precision {metrics.precision:.4f}   Recall {metrics.recall:.4f}   "
        f"F1 {metrics.f1:.4f}   Accuracy {metrics.accuracy:.4f}   "
        f"False positive rate {metrics.false_positive_rate:.4f}",
        "  Confusion matrix (rows: actual, columns: predicted)",
        f"    {'':8}{'normal':>10}{'attack':>10}",
        f"    {'normal':8}{metrics.true_negatives:>10,}{metrics.false_positives:>10,}",
        f"    {'attack':8}{metrics.false_negatives:>10,}{metrics.true_positives:>10,}",
        "  Share of each category flagged as an attack",
    ]
    return lines + [f"    {name:16}{rate:>8.1%}" for name, rate in result.detection_rates.items()]


def _save_supervised_model(
    results: Sequence[BaselineResult], train: FlowDataset, test: FlowDataset, model_dir: Path
) -> None:
    """Saves the first supervised model: only those can report attack probabilities."""
    saved = next((result for result in results if result.supervised), None)
    if saved is None:
        print("\nNo supervised model was trained, so nothing was saved.")
        return
    metrics = saved.metrics
    save_model(
        model_dir,
        saved.model,
        ModelMetadata(
            model_name=saved.name,
            trained_at=datetime.now(UTC).isoformat(timespec="seconds"),
            training_rows=len(train.labels),
            feature_columns=list(FEATURE_COLUMNS),
            sklearn_version=sklearn.__version__,
            test_metrics={
                "precision": metrics.precision,
                "recall": metrics.recall,
                "f1": metrics.f1,
                "accuracy": metrics.accuracy,
                "false_positive_rate": metrics.false_positive_rate,
                "test_rows": len(test.labels),
                "test_attack_share": float(test.labels.mean()),
            },
        ),
    )
    print(f"\nSaved {saved.name} to {model_dir}")


def main(
    data_dir: Path | None = None,
    training: SplitFile = TRAINING_SPLIT,
    testing: SplitFile = TESTING_SPLIT,
    baselines: Sequence[Baseline] | None = None,
    model_dir: Path | None = None,
) -> int:
    data_dir = data_dir or get_settings().data_dir
    try:
        train = load_split(data_dir, training)
        test = load_split(data_dir, testing)
    except DatasetError as error:
        print(error)
        return 1
    print(_describe_split("Training split", train))
    print(_describe_split("Testing split", test))
    if baselines is None:
        baselines = [random_forest(), isolation_forest()]
    results = train_and_evaluate(baselines, train, test)
    for result in results:
        print("\n".join(_describe_result(result)))
    if model_dir is not None:
        _save_supervised_model(results, train, test, model_dir)
    return 0


if __name__ == "__main__":
    sys.exit(main(model_dir=get_settings().model_dir))
