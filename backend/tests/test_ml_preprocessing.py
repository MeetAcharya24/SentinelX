from collections.abc import Callable
from pathlib import Path

import numpy as np
import pandas as pd
import pytest

from app.ml.dataset import load_split, to_dataset
from app.ml.preprocessing import build_preprocessor
from app.ml.schema import DATASET_DIRNAME, NUMERIC_FEATURES, TESTING_SPLIT, TRAINING_SPLIT

MakeFlows = Callable[..., pd.DataFrame]


def test_output_is_fully_numeric_with_named_columns(make_flows: MakeFlows) -> None:
    features = to_dataset(make_flows(rows=60)).features
    preprocessor = build_preprocessor(min_category_count=1)

    matrix = preprocessor.fit_transform(features)
    names = list(preprocessor.get_feature_names_out())

    assert matrix.shape == (60, len(names))
    assert np.isfinite(matrix).all()
    assert "proto_tcp" in names
    assert names[-len(NUMERIC_FEATURES) :] == list(NUMERIC_FEATURES)


def test_numeric_values_pass_through_unchanged(make_flows: MakeFlows) -> None:
    features = to_dataset(make_flows(rows=30)).features
    preprocessor = build_preprocessor(min_category_count=1)

    matrix = preprocessor.fit_transform(features)
    expected = features[list(NUMERIC_FEATURES)].to_numpy(dtype="float64")

    np.testing.assert_array_equal(matrix[:, -len(NUMERIC_FEATURES) :], expected)


def test_category_unseen_in_training_does_not_break_transform(make_flows: MakeFlows) -> None:
    train = to_dataset(make_flows(rows=60)).features
    test = to_dataset(make_flows(rows=5, state="ACC")).features
    preprocessor = build_preprocessor(min_category_count=1).fit(train)

    matrix = preprocessor.transform(test)
    names = list(preprocessor.get_feature_names_out())
    state_columns = [index for index, name in enumerate(names) if name.startswith("state_")]

    assert matrix.shape == (5, len(names))
    assert (matrix[:, state_columns] == 0).all()


def test_unseen_category_joins_the_rare_group_when_one_exists(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=60, state="FIN")
    flows.loc[0, "state"] = "RST"
    preprocessor = build_preprocessor(min_category_count=5).fit(to_dataset(flows).features)

    matrix = preprocessor.transform(to_dataset(make_flows(rows=5, state="ACC")).features)
    names = list(preprocessor.get_feature_names_out())

    assert (matrix[:, names.index("state_infrequent_sklearn")] == 1).all()
    assert (matrix[:, names.index("state_FIN")] == 0).all()


def test_rare_categories_are_grouped_together(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=60, proto="tcp")
    flows.loc[0, "proto"] = "ospf"
    flows.loc[1, "proto"] = "gre"
    preprocessor = build_preprocessor(min_category_count=5)

    preprocessor.fit(to_dataset(flows).features)
    proto_names = [n for n in preprocessor.get_feature_names_out() if n.startswith("proto_")]

    assert proto_names == ["proto_tcp", "proto_infrequent_sklearn"]


def test_fitting_does_not_modify_the_input(make_flows: MakeFlows) -> None:
    features = to_dataset(make_flows(rows=30)).features
    before = features.copy(deep=True)

    build_preprocessor(min_category_count=1).fit_transform(features)

    pd.testing.assert_frame_equal(features, before)


def test_published_splits_preprocess_to_matching_finite_matrices(data_dir: Path) -> None:
    folder = data_dir / DATASET_DIRNAME
    if not all((folder / split.filename).is_file() for split in (TRAINING_SPLIT, TESTING_SPLIT)):
        pytest.skip("UNSW-NB15 files are not downloaded")
    train = load_split(data_dir, TRAINING_SPLIT).features
    test = load_split(data_dir, TESTING_SPLIT).features
    preprocessor = build_preprocessor()

    train_matrix = preprocessor.fit_transform(train)
    test_matrix = preprocessor.transform(test)

    assert train_matrix.shape[1] == test_matrix.shape[1]
    assert np.isfinite(train_matrix).all()
    assert np.isfinite(test_matrix).all()
