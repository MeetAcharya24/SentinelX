"""Loading and validating UNSW-NB15 flow records."""

from dataclasses import dataclass
from pathlib import Path

import numpy as np
import pandas as pd
from pandas.api.types import is_numeric_dtype, is_string_dtype

from app.ml.schema import (
    ATTACK_CATEGORY_COLUMN,
    CATEGORICAL_FEATURES,
    DATASET_DIRNAME,
    FEATURE_COLUMNS,
    LABEL_COLUMN,
    NORMAL_CATEGORY,
    NUMERIC_FEATURES,
    REQUIRED_COLUMNS,
    SplitFile,
)

_TEXT_COLUMNS: tuple[str, ...] = CATEGORICAL_FEATURES + (ATTACK_CATEGORY_COLUMN,)


class DatasetError(ValueError):
    """The dataset is absent or does not match the expected schema."""


@dataclass(frozen=True)
class FlowDataset:
    """Model inputs kept separate from the targets used to train and evaluate."""

    features: pd.DataFrame
    labels: pd.Series
    attack_categories: pd.Series


def _reject(problem: str, columns: list[str]) -> None:
    if columns:
        raise DatasetError(f"{problem}: {', '.join(columns)}")


def _validate_columns(flows: pd.DataFrame) -> None:
    _reject("Missing required columns", [c for c in REQUIRED_COLUMNS if c not in flows.columns])
    if flows.empty:
        raise DatasetError("The dataset has no rows")
    _reject("Missing values in columns", [c for c in REQUIRED_COLUMNS if flows[c].isna().any()])
    _reject(
        "Non-numeric values in columns",
        [c for c in NUMERIC_FEATURES if not is_numeric_dtype(flows[c])],
    )
    _reject(
        "Infinite values in columns",
        [c for c in NUMERIC_FEATURES if not np.isfinite(flows[c].to_numpy(dtype="float64")).all()],
    )
    _reject(
        "Non-text values in columns", [c for c in _TEXT_COLUMNS if not is_string_dtype(flows[c])]
    )


def _validate_targets(flows: pd.DataFrame) -> None:
    labels = flows[LABEL_COLUMN]
    if not labels.isin([0, 1]).all():
        raise DatasetError(f"Column '{LABEL_COLUMN}' must contain only 0 (normal) or 1 (attack)")
    is_normal_category = flows[ATTACK_CATEGORY_COLUMN].str.strip() == NORMAL_CATEGORY
    if ((labels == 0) != is_normal_category).any():
        raise DatasetError(
            f"Column '{ATTACK_CATEGORY_COLUMN}' must be '{NORMAL_CATEGORY}' "
            f"exactly when '{LABEL_COLUMN}' is 0"
        )


def to_dataset(flows: pd.DataFrame) -> FlowDataset:
    """Validates raw rows and separates features from targets.

    The row id is dropped: it follows the class ordering of the published files.
    """
    _validate_columns(flows)
    _validate_targets(flows)
    return FlowDataset(
        features=flows[list(FEATURE_COLUMNS)].reset_index(drop=True),
        labels=flows[LABEL_COLUMN].astype("int64").reset_index(drop=True),
        attack_categories=flows[ATTACK_CATEGORY_COLUMN].str.strip().reset_index(drop=True),
    )


def split_path(data_dir: Path, split: SplitFile) -> Path:
    return data_dir / DATASET_DIRNAME / split.filename


def load_split(data_dir: Path, split: SplitFile) -> FlowDataset:
    path = split_path(data_dir, split)
    if not path.is_file():
        raise DatasetError(
            f"{split.filename} not found in {path.parent}. "
            "See 'Dataset' in the README for the download step."
        )
    # The published files start with a byte-order mark.
    flows = pd.read_csv(path, encoding="utf-8-sig")
    if len(flows) != split.rows:
        raise DatasetError(
            f"{split.filename} has {len(flows):,} rows, expected {split.rows:,}. "
            "Download it again; see 'Dataset' in the README."
        )
    return to_dataset(flows)
