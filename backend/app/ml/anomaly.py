"""Anomaly scores from the saved Isolation Forest (novelty detector)."""

import numpy as np
import pandas as pd
from sklearn.pipeline import Pipeline

# The Isolation Forest is saved in this folder inside the network model folder.
ANOMALY_DIRNAME = "isolation_forest"

# A flow is flagged when its score is above this, the library's own cut-off for the
# forest as trained (the configuration behind the reported recall and false positive rate).
FLAG_THRESHOLD = 0.0


def anomaly_scores(model: Pipeline, features: pd.DataFrame) -> np.ndarray:
    """Higher means less like the normal training flows; above FLAG_THRESHOLD is flagged.

    The scale is the forest's own and is not a probability.
    """
    return -model.decision_function(features)
