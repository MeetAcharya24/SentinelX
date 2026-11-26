"""Trains the phishing classifier, reports held-out metrics: `python -m app.ml.phishing_train`."""

import sys
from datetime import UTC, datetime
from pathlib import Path

import sklearn
from sklearn.model_selection import train_test_split

from app.core.config import get_settings
from app.ml.evaluation import BinaryMetrics, evaluate
from app.ml.persistence import ModelMetadata
from app.ml.phishing_data import PhishingCorpusError, load_corpus
from app.ml.phishing_model import (
    DECISION_THRESHOLD,
    PHISHING_MODEL_NAME,
    TEXT_FEATURE,
    build_pipeline,
    save_phishing_model,
)

TEST_SHARE = 0.2
SEED = 42


def _describe(metrics: BinaryMetrics) -> list[str]:
    return [
        f"  Precision {metrics.precision:.4f}   Recall {metrics.recall:.4f}   "
        f"F1 {metrics.f1:.4f}   Accuracy {metrics.accuracy:.4f}   "
        f"False positive rate {metrics.false_positive_rate:.4f}",
        "  Confusion matrix (rows: actual, columns: predicted)",
        f"    {'':12}{'legitimate':>12}{'phishing':>10}",
        f"    {'legitimate':12}{metrics.true_negatives:>12,}{metrics.false_positives:>10,}",
        f"    {'phishing':12}{metrics.false_negatives:>12,}{metrics.true_positives:>10,}",
    ]


def _metadata(metrics: BinaryMetrics, training_rows: int, test_labels: list[int]) -> ModelMetadata:
    return ModelMetadata(
        model_name=PHISHING_MODEL_NAME,
        trained_at=datetime.now(UTC).isoformat(timespec="seconds"),
        training_rows=training_rows,
        feature_columns=[TEXT_FEATURE],
        sklearn_version=sklearn.__version__,
        test_metrics={
            "precision": metrics.precision,
            "recall": metrics.recall,
            "f1": metrics.f1,
            "accuracy": metrics.accuracy,
            "false_positive_rate": metrics.false_positive_rate,
            "test_rows": len(test_labels),
            "test_attack_share": sum(test_labels) / len(test_labels),
        },
    )


def main(data_dir: Path | None = None, model_dir: Path | None = None) -> int:
    try:
        corpus = load_corpus(data_dir or get_settings().data_dir)
    except PhishingCorpusError as error:
        print(error)
        return 1
    texts, labels = list(corpus.texts), list(corpus.labels)
    print(
        f"Corpus: {len(texts):,} messages, {sum(labels) / len(labels):.1%} phishing "
        f"({corpus.duplicates_removed:,} duplicates removed, {corpus.unreadable:,} unreadable)"
    )
    train_texts, test_texts, train_labels, test_labels = train_test_split(
        texts, labels, test_size=TEST_SHARE, stratify=labels, random_state=SEED
    )
    pipeline = build_pipeline().fit(train_texts, train_labels)
    probabilities = pipeline.predict_proba(test_texts)[:, 1]
    metrics = evaluate(test_labels, (probabilities >= DECISION_THRESHOLD).astype(int))
    held_out_share = sum(test_labels) / len(test_labels)
    print(f"Held-out split: {len(test_labels):,} messages, {held_out_share:.1%} phishing")
    print("\n".join(_describe(metrics)))
    if model_dir is not None:
        save_phishing_model(model_dir, pipeline, _metadata(metrics, len(train_labels), test_labels))
        print(f"\nSaved {PHISHING_MODEL_NAME} to {model_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(model_dir=get_settings().phishing_model_dir))
