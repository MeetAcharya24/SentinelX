from collections.abc import Callable
from pathlib import Path

import pandas as pd
import pytest

from app.ml.dataset import DatasetError, load_split, to_dataset
from app.ml.schema import (
    DATASET_DIRNAME,
    FEATURE_COLUMNS,
    TESTING_SPLIT,
    TRAINING_SPLIT,
    SplitFile,
)

MakeFlows = Callable[..., pd.DataFrame]


def test_features_exclude_row_id_and_targets(make_flows: MakeFlows) -> None:
    dataset = to_dataset(make_flows(rows=20))

    assert tuple(dataset.features.columns) == FEATURE_COLUMNS
    assert len(dataset.features) == len(dataset.labels) == len(dataset.attack_categories) == 20


def test_labels_and_categories_are_kept_aligned(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=6, label=[0, 1, 0, 1, 1, 0])
    flows["attack_cat"] = ["Normal", " DoS ", "Normal", "Exploits", "Generic", "Normal"]

    dataset = to_dataset(flows)

    assert dataset.labels.tolist() == [0, 1, 0, 1, 1, 0]
    assert dataset.attack_categories.tolist()[:2] == ["Normal", "DoS"]


def test_missing_columns_are_named(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5).drop(columns=["sbytes", "state"])

    with pytest.raises(DatasetError, match="state, sbytes"):
        to_dataset(flows)


def test_missing_values_are_rejected(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5)
    flows.loc[2, "dur"] = None

    with pytest.raises(DatasetError, match="dur"):
        to_dataset(flows)


def test_non_numeric_feature_values_are_rejected(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5).astype({"spkts": "object"})
    flows.loc[1, "spkts"] = "many"

    with pytest.raises(DatasetError, match="spkts"):
        to_dataset(flows)


def test_labels_other_than_zero_or_one_are_rejected(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5, label=[0, 1, 2, 0, 1])

    with pytest.raises(DatasetError, match="label"):
        to_dataset(flows)


def test_infinite_values_are_rejected(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5)
    flows.loc[3, "dur"] = float("inf")

    with pytest.raises(DatasetError, match="dur"):
        to_dataset(flows)


def test_attack_row_labelled_normal_is_rejected(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=4, label=[0, 1, 0, 1])
    flows["attack_cat"] = ["Normal", "Normal", "Normal", "DoS"]

    with pytest.raises(DatasetError, match="attack_cat"):
        to_dataset(flows)


def test_non_text_category_columns_are_rejected(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5, state=3)

    with pytest.raises(DatasetError, match="state"):
        to_dataset(flows)


def test_empty_input_is_rejected(make_flows: MakeFlows) -> None:
    with pytest.raises(DatasetError, match="no rows"):
        to_dataset(make_flows(rows=5).iloc[0:0])


def test_load_split_rejects_an_unexpected_row_count(make_flows: MakeFlows, tmp_path: Path) -> None:
    split = SplitFile(filename="flows.csv", rows=12, sha256="")
    folder = tmp_path / DATASET_DIRNAME
    folder.mkdir()
    make_flows(rows=9).to_csv(folder / split.filename, index=False)

    with pytest.raises(DatasetError, match="9 rows"):
        load_split(tmp_path, split)


def test_validation_does_not_modify_the_input(make_flows: MakeFlows) -> None:
    flows = make_flows(rows=5)
    before = flows.copy(deep=True)

    to_dataset(flows)

    pd.testing.assert_frame_equal(flows, before)


def test_load_split_reads_a_csv_with_a_byte_order_mark(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    split = SplitFile(filename="flows.csv", rows=12, sha256="")
    folder = tmp_path / DATASET_DIRNAME
    folder.mkdir()
    make_flows(rows=12).to_csv(folder / split.filename, index=False, encoding="utf-8-sig")

    dataset = load_split(tmp_path, split)

    assert dataset.features.shape == (12, len(FEATURE_COLUMNS))


def test_load_split_explains_how_to_get_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(DatasetError, match="README"):
        load_split(tmp_path, TRAINING_SPLIT)


@pytest.mark.parametrize("split", [TRAINING_SPLIT, TESTING_SPLIT], ids=["training", "testing"])
def test_published_split_matches_the_documented_shape(split: SplitFile, data_dir: Path) -> None:
    if not (data_dir / DATASET_DIRNAME / split.filename).is_file():
        pytest.skip("UNSW-NB15 files are not downloaded")

    dataset = load_split(data_dir, split)

    assert dataset.features.shape == (split.rows, len(FEATURE_COLUMNS))
    assert set(dataset.labels.unique()) == {0, 1}
