from collections.abc import Callable

import numpy as np
import pandas as pd
import pytest

from app.ml.dataset import FlowDataset, to_dataset
from app.ml.training import (
    fit,
    isolation_forest,
    predict_attacks,
    random_forest,
    train_and_evaluate,
)

MakeFlows = Callable[..., pd.DataFrame]


def _separable(make_flows: MakeFlows, rows: int = 200, **columns: object) -> FlowDataset:
    """Attacks are exactly the rows with a large `sbytes`."""
    labels = np.arange(rows) % 2
    sbytes = np.where(labels == 1, 50_000, 10)
    return to_dataset(make_flows(rows=rows, label=labels, sbytes=sbytes, **columns))


def test_random_forest_learns_a_separable_pattern(make_flows: MakeFlows) -> None:
    dataset = _separable(make_flows)
    baseline = random_forest(n_estimators=10)

    model = fit(baseline, dataset)
    predictions = predict_attacks(baseline, model, dataset.features)

    assert predictions.tolist() == dataset.labels.tolist()


def test_training_is_reproducible(make_flows: MakeFlows) -> None:
    flows = to_dataset(make_flows(rows=200))
    baseline = random_forest(n_estimators=10)

    first = predict_attacks(baseline, fit(baseline, flows), flows.features)
    second = predict_attacks(baseline, fit(baseline, flows), flows.features)

    assert first.tolist() == second.tolist()


def test_fitting_leaves_the_baseline_unfitted_for_reuse(make_flows: MakeFlows) -> None:
    baseline = random_forest(n_estimators=10)

    fit(baseline, _separable(make_flows))

    assert not hasattr(baseline.estimator[-1], "estimators_")


def test_isolation_forest_flags_extreme_rows_as_attacks(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=200, label=0)
    outliers = [3, 77, 150]
    flows.loc[outliers, ["sbytes", "dbytes", "spkts", "dpkts", "rate"]] = 10**9
    dataset = to_dataset(flows)
    baseline = isolation_forest(n_estimators=50)

    predictions = predict_attacks(baseline, fit(baseline, dataset), dataset.features)

    assert set(predictions.tolist()) <= {0, 1}
    assert predictions[outliers].tolist() == [1, 1, 1]
    assert predictions.mean() < 0.5


def test_isolation_forest_is_trained_on_normal_rows_only(make_flows: MakeFlows) -> None:
    mixed = _separable(make_flows)
    normal = mixed.labels == 0
    normal_only = FlowDataset(
        features=mixed.features[normal],
        labels=mixed.labels[normal],
        attack_categories=mixed.attack_categories[normal],
    )
    baseline = isolation_forest(n_estimators=20)

    from_mixed = predict_attacks(baseline, fit(baseline, mixed), mixed.features)
    from_normal = predict_attacks(baseline, fit(baseline, normal_only), mixed.features)

    assert from_mixed.tolist() == from_normal.tolist()


def test_isolation_forest_flags_what_the_normal_rows_do_not_look_like(
    make_flows: MakeFlows,
) -> None:
    labels = np.arange(200) % 2
    flows = make_flows(rows=200, label=labels)
    flows.loc[labels == 1, ["sbytes", "dbytes", "spkts", "dpkts", "rate"]] = 10**9
    dataset = to_dataset(flows)
    baseline = isolation_forest(n_estimators=50)

    predictions = predict_attacks(baseline, fit(baseline, dataset), dataset.features)

    # Half the rows are attacks, so a model trained on all of them would not find them unusual.
    assert predictions[labels == 1].mean() > 0.9
    assert predictions[labels == 0].mean() < 0.5


def test_isolation_forest_needs_normal_rows_to_train_on(make_flows: MakeFlows) -> None:
    attacks_only = to_dataset(make_flows(rows=50, label=1))

    with pytest.raises(ValueError, match="normal"):
        fit(isolation_forest(n_estimators=5), attacks_only)


def test_models_accept_categories_unseen_in_training(make_flows: MakeFlows) -> None:
    baseline = random_forest(n_estimators=10)
    model = fit(baseline, _separable(make_flows))
    unseen = _separable(make_flows, rows=10, state="ACC")

    predictions = predict_attacks(baseline, model, unseen.features)

    assert predictions.tolist() == unseen.labels.tolist()


def test_train_and_evaluate_scores_each_baseline_on_the_test_split(make_flows: MakeFlows) -> None:
    train = _separable(make_flows, rows=200)
    # A quarter of the test rows are attacks, unlike the half in training.
    labels = (np.arange(40) % 4 == 0).astype(int)
    test = to_dataset(make_flows(rows=40, label=labels, sbytes=np.where(labels == 1, 50_000, 10)))

    results = train_and_evaluate(
        [random_forest(n_estimators=10), isolation_forest(n_estimators=10)], train, test
    )

    assert [result.name for result in results] == ["Random Forest", "Isolation Forest"]
    forest, isolation = results
    assert (forest.metrics.true_negatives, forest.metrics.true_positives) == (30, 10)
    assert (forest.metrics.false_positives, forest.metrics.false_negatives) == (0, 0)
    assert forest.detection_rates == {"Generic": 1.0, "Normal": 0.0}
    assert (
        sum(
            (
                isolation.metrics.true_negatives,
                isolation.metrics.false_positives,
                isolation.metrics.false_negatives,
                isolation.metrics.true_positives,
            )
        )
        == 40
    )
    assert set(isolation.detection_rates) == {"Generic", "Normal"}


def test_baselines_declare_how_they_learn() -> None:
    assert random_forest().supervised is True
    assert isolation_forest().supervised is False
