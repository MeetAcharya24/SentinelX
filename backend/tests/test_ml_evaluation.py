import pytest

from app.ml.evaluation import detection_rate_by_category, evaluate

# Four distinct counts (TN 5, FP 1, FN 2, TP 3) so a swapped cell or formula shows up.
LABELS = [0] * 6 + [1] * 5
PREDICTIONS = [0] * 5 + [1] + [0] * 2 + [1] * 3


def test_confusion_counts_and_derived_metrics() -> None:
    metrics = evaluate(labels=LABELS, predictions=PREDICTIONS)

    assert metrics.true_negatives == 5
    assert metrics.false_positives == 1
    assert metrics.false_negatives == 2
    assert metrics.true_positives == 3
    assert metrics.precision == pytest.approx(3 / 4)
    assert metrics.recall == pytest.approx(3 / 5)
    assert metrics.f1 == pytest.approx(2 * 3 / (2 * 3 + 1 + 2))
    assert metrics.accuracy == pytest.approx(8 / 11)
    assert metrics.false_positive_rate == pytest.approx(1 / 6)


def test_swapping_labels_and_predictions_swaps_false_positives_and_negatives() -> None:
    metrics = evaluate(labels=PREDICTIONS, predictions=LABELS)

    assert (metrics.false_positives, metrics.false_negatives) == (2, 1)


def test_empty_input_is_rejected() -> None:
    with pytest.raises(ValueError, match="no rows"):
        evaluate(labels=[], predictions=[])


def test_metrics_are_zero_rather_than_undefined_when_nothing_is_flagged() -> None:
    metrics = evaluate(labels=[0, 1, 1], predictions=[0, 0, 0])

    assert metrics.precision == 0.0
    assert metrics.recall == 0.0
    assert metrics.f1 == 0.0


def test_false_positive_rate_is_zero_without_normal_rows() -> None:
    assert evaluate(labels=[1, 1], predictions=[1, 0]).false_positive_rate == 0.0


def test_mismatched_lengths_are_rejected() -> None:
    with pytest.raises(ValueError, match="same length"):
        evaluate(labels=[0, 1], predictions=[0])


def test_values_other_than_zero_or_one_are_rejected() -> None:
    with pytest.raises(ValueError, match="0 or 1"):
        evaluate(labels=[0, 1], predictions=[-1, 1])


def test_detection_rate_is_the_share_of_each_category_flagged() -> None:
    rates = detection_rate_by_category(
        categories=["Normal", "Normal", "DoS", "DoS", "Worms"],
        predictions=[0, 1, 1, 0, 1],
    )

    assert rates == {"DoS": 0.5, "Normal": 0.5, "Worms": 1.0}
