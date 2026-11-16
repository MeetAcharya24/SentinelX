"""Scoring flows with a trained detector."""

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

from app.ml.schema import CATEGORICAL_FEATURES

# A flow is reported as an attack at or above this probability. It is the
# default of the trained model, not a value tuned for any particular network.
DECISION_THRESHOLD = 0.5

_ATTACK_CLASS = 1


def attack_probabilities(model: Pipeline, features: pd.DataFrame) -> np.ndarray:
    """Probability that each flow is an attack, in row order."""
    classes = list(model.classes_)
    return model.predict_proba(features)[:, classes.index(_ATTACK_CLASS)]


def unseen_categories(model: Pipeline, features: pd.DataFrame) -> list[list[str]]:
    """For each flow, the categorical features whose value the model never saw in training.

    Such values are scored as if rare, so callers should show this alongside
    the probability. Matching is exact: `TCP` is not `tcp`.
    """
    encoder = model.named_steps["preprocess"].named_transformers_["categorical"]
    known = dict(zip(CATEGORICAL_FEATURES, encoder.categories_, strict=True))
    return [
        [name for name in CATEGORICAL_FEATURES if row[name] not in known[name]]
        for row in features.to_dict("records")
    ]
