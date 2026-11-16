"""Baseline detectors for network flows, trained and scored on fixed splits."""

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.base import clone
from sklearn.ensemble import IsolationForest, RandomForestClassifier
from sklearn.pipeline import Pipeline

from app.ml.dataset import FlowDataset
from app.ml.evaluation import BinaryMetrics, detection_rate_by_category, evaluate
from app.ml.preprocessing import build_preprocessor

RANDOM_SEED = 42
DEFAULT_TREES = 100

# Isolation Forest marks the rows it considers anomalous with -1.
_ANOMALY = -1


@dataclass(frozen=True)
class Baseline:
    """An unfitted pipeline and whether it learns from the labels."""

    name: str
    estimator: Pipeline
    uses_labels: bool


@dataclass(frozen=True)
class BaselineResult:
    name: str
    uses_labels: bool
    model: Pipeline
    metrics: BinaryMetrics
    detection_rates: dict[str, float]


def _pipeline(model: object) -> Pipeline:
    return Pipeline([("preprocess", build_preprocessor()), ("model", model)])


def random_forest(n_estimators: int = DEFAULT_TREES) -> Baseline:
    model = RandomForestClassifier(n_estimators=n_estimators, random_state=RANDOM_SEED, n_jobs=-1)
    return Baseline(name="Random Forest", estimator=_pipeline(model), uses_labels=True)


def isolation_forest(n_estimators: int = DEFAULT_TREES) -> Baseline:
    """Unsupervised: sees the features only and flags the rows it finds unusual."""
    model = IsolationForest(n_estimators=n_estimators, random_state=RANDOM_SEED, n_jobs=-1)
    return Baseline(name="Isolation Forest", estimator=_pipeline(model), uses_labels=False)


def fit(baseline: Baseline, dataset: FlowDataset) -> Pipeline:
    """Returns a fitted copy; the baseline itself stays unfitted."""
    model = clone(baseline.estimator)
    if baseline.uses_labels:
        return model.fit(dataset.features, dataset.labels)
    return model.fit(dataset.features)


def predict_attacks(baseline: Baseline, model: Pipeline, features: pd.DataFrame) -> np.ndarray:
    """Returns 1 for rows the model flags as attacks, otherwise 0."""
    raw = model.predict(features)
    if baseline.uses_labels:
        return raw.astype("int64")
    return (raw == _ANOMALY).astype("int64")


def train_and_evaluate(
    baselines: Sequence[Baseline], train: FlowDataset, test: FlowDataset
) -> list[BaselineResult]:
    results = []
    for baseline in baselines:
        model = fit(baseline, train)
        predictions = predict_attacks(baseline, model, test.features)
        results.append(
            BaselineResult(
                name=baseline.name,
                uses_labels=baseline.uses_labels,
                model=model,
                metrics=evaluate(test.labels, predictions),
                detection_rates=detection_rate_by_category(test.attack_categories, predictions),
            )
        )
    return results
