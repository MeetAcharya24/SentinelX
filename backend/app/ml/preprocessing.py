"""Feature preprocessing shared by training and inference."""

from sklearn.compose import ColumnTransformer
from sklearn.preprocessing import OneHotEncoder

from app.ml.schema import CATEGORICAL_FEATURES, NUMERIC_FEATURES

# `proto` has over 130 values, most seen only a few hundred times; values rarer
# than this in the training split share a single "infrequent" column.
RARE_CATEGORY_MIN_COUNT = 500


def build_preprocessor(min_category_count: int = RARE_CATEGORY_MIN_COUNT) -> ColumnTransformer:
    """Returns an unfitted transformer; fit it on the training split only.

    Categorical features are one-hot encoded, and a value never seen in
    training maps to the infrequent column (or all zeros when there is none)
    instead of failing. Numeric features pass through unscaled, which suits the
    tree-based baseline models.
    """
    encoder = OneHotEncoder(
        handle_unknown="infrequent_if_exist",
        min_frequency=min_category_count,
        sparse_output=False,
    )
    return ColumnTransformer(
        [
            ("categorical", encoder, list(CATEGORICAL_FEATURES)),
            ("numeric", "passthrough", list(NUMERIC_FEATURES)),
        ],
        verbose_feature_names_out=False,
    )
