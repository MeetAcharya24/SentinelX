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
NORMAL_LABEL = 0

# Isolation Forest marks the rows it considers anomalous with -1.
_ANOMALY = -1


@dataclass(frozen=True)
class Baseline:
    """An unfitted pipeline and how it learns.

    A supervised baseline learns to predict the label. Any other is a novelty
    detector: the labels only pick out the normal training rows, and it flags
    rows that do not look like them.
    """

    name: str
    estimator: Pipeline
    supervised: bool


@dataclass(frozen=True)
class BaselineResult:
    name: str
    supervised: bool
    model: Pipeline
    metrics: BinaryMetrics
    detection_rates: dict[str, float]


def _pipeline(model: object) -> Pipeline:
    return Pipeline([("preprocess", build_preprocessor()), ("model", model)])


def random_forest(n_estimators: int = DEFAULT_TREES) -> Baseline:
    model = RandomForestClassifier(n_estimators=n_estimators, random_state=RANDOM_SEED, n_jobs=-1)
    return Baseline(name="Random Forest", estimator=_pipeline(model), supervised=True)


def isolation_forest(n_estimators: int = DEFAULT_TREES) -> Baseline:
    """Novelty detection: learns from normal flows only and flags rows unlike them."""
    model = IsolationForest(n_estimators=n_estimators, random_state=RANDOM_SEED, n_jobs=-1)
    return Baseline(name="Isolation Forest", estimator=_pipeline(model), supervised=False)


def fit(baseline: Baseline, dataset: FlowDataset) -> Pipeline:
    """Returns a fitted copy; the baseline itself stays unfitted."""
    model = clone(baseline.estimator)
    if baseline.supervised:
        return model.fit(dataset.features, dataset.labels)
    normal = dataset.features[dataset.labels == NORMAL_LABEL]
    if normal.empty:
        raise ValueError(f"{baseline.name} needs normal rows to train on, and there are none")
    return model.fit(normal)


def predict_attacks(baseline: Baseline, model: Pipeline, features: pd.DataFrame) -> np.ndarray:
    """Returns 1 for rows the model flags as attacks, otherwise 0."""
    raw = model.predict(features)
    if baseline.supervised:
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
                supervised=baseline.supervised,
                model=model,
                metrics=evaluate(test.labels, predictions),
                detection_rates=detection_rate_by_category(test.attack_categories, predictions),
            )
        )
    return results
