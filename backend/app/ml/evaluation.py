"""Binary detection metrics computed from labels and predictions."""

from collections.abc import Sequence
from dataclasses import dataclass

import numpy as np
from numpy.typing import ArrayLike


def _ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


@dataclass(frozen=True)
class BinaryMetrics:
    """Confusion counts with attack (1) as the positive class."""

    true_negatives: int
    false_positives: int
    false_negatives: int
    true_positives: int

    @property
    def precision(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_positives)

    @property
    def recall(self) -> float:
        return _ratio(self.true_positives, self.true_positives + self.false_negatives)

    @property
    def f1(self) -> float:
        return _ratio(
            2 * self.true_positives,
            2 * self.true_positives + self.false_positives + self.false_negatives,
        )

    @property
    def accuracy(self) -> float:
        total = (
            self.true_negatives + self.false_positives + self.false_negatives + self.true_positives
        )
        return _ratio(self.true_negatives + self.true_positives, total)

    @property
    def false_positive_rate(self) -> float:
        return _ratio(self.false_positives, self.false_positives + self.true_negatives)


def _as_binary(values: ArrayLike, name: str) -> np.ndarray:
    array = np.asarray(values)
    if not np.isin(array, (0, 1)).all():
        raise ValueError(f"{name} must contain only 0 or 1")
    return array.astype(bool)


def evaluate(labels: ArrayLike, predictions: ArrayLike) -> BinaryMetrics:
    if np.shape(labels) != np.shape(predictions):
        raise ValueError("labels and predictions must have the same length")
    if np.size(labels) == 0:
        raise ValueError("Cannot evaluate: no rows")
    actual = _as_binary(labels, "labels")
    flagged = _as_binary(predictions, "predictions")
    return BinaryMetrics(
        true_negatives=int((~actual & ~flagged).sum()),
        false_positives=int((~actual & flagged).sum()),
        false_negatives=int((actual & ~flagged).sum()),
        true_positives=int((actual & flagged).sum()),
    )


def detection_rate_by_category(
    categories: Sequence[str] | ArrayLike, predictions: ArrayLike
) -> dict[str, float]:
    """Share of each category flagged as an attack.

    For attack categories this is recall; for the normal category it is the
    false positive rate.
    """
    names = np.asarray(categories)
    flagged = _as_binary(predictions, "predictions")
    if names.shape != flagged.shape:
        raise ValueError("categories and predictions must have the same length")
    return {str(name): float(flagged[names == name].mean()) for name in sorted(set(names))}
