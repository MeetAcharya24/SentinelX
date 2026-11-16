import hashlib
import json
from collections.abc import Callable
from dataclasses import asdict, replace
from pathlib import Path

import joblib
import pandas as pd
import pytest
import sklearn

from app.ml.dataset import to_dataset
from app.ml.persistence import (
    MODEL_FILENAME,
    ModelMetadata,
    ModelUnavailableError,
    load_model,
    save_model,
)
from app.ml.schema import FEATURE_COLUMNS
from app.ml.training import fit, predict_attacks, random_forest

MakeFlows = Callable[..., pd.DataFrame]


def _metadata(**overrides: object) -> ModelMetadata:
    values: dict[str, object] = {
        "model_name": "Random Forest",
        "trained_at": "2026-11-16T10:00:00+00:00",
        "training_rows": 200,
        "feature_columns": list(FEATURE_COLUMNS),
        "sklearn_version": sklearn.__version__,
        "test_metrics": {"f1": 0.9},
    }
    return ModelMetadata(**{**values, **overrides})  # type: ignore[arg-type]


def test_saved_model_predicts_the_same_after_loading(make_flows: MakeFlows, tmp_path: Path) -> None:
    dataset = to_dataset(make_flows(rows=120))
    baseline = random_forest(n_estimators=5)
    pipeline = fit(baseline, dataset)

    save_model(tmp_path, pipeline, _metadata())
    loaded = load_model(tmp_path)

    expected = predict_attacks(baseline, pipeline, dataset.features)
    assert (
        predict_attacks(baseline, loaded.pipeline, dataset.features).tolist() == expected.tolist()
    )
    assert loaded.metadata.model_sha256
    assert replace(loaded.metadata, model_sha256="") == _metadata()


def test_save_creates_the_directory_and_a_readable_metadata_file(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))
    target = tmp_path / "nested" / "model"

    save_model(target, pipeline, _metadata())

    stored = json.loads((target / "model.json").read_text(encoding="utf-8"))
    assert stored["model_name"] == "Random Forest"
    assert stored["training_rows"] == 200


def test_loading_without_a_trained_model_explains_how_to_train(tmp_path: Path) -> None:
    with pytest.raises(ModelUnavailableError, match="python -m app.ml.train"):
        load_model(tmp_path)


def test_loading_rejects_a_model_built_with_another_scikit_learn(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))
    save_model(tmp_path, pipeline, _metadata(sklearn_version="0.0.1"))

    with pytest.raises(ModelUnavailableError, match="0.0.1"):
        load_model(tmp_path)


def test_loading_rejects_a_model_with_a_different_feature_layout(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))
    save_model(tmp_path, pipeline, _metadata(feature_columns=["dur"]))

    with pytest.raises(ModelUnavailableError, match="feature"):
        load_model(tmp_path)


def test_loading_a_corrupt_metadata_file_is_a_clear_error(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))
    save_model(tmp_path, pipeline, _metadata())
    (tmp_path / "model.json").write_text("{not json", encoding="utf-8")

    with pytest.raises(ModelUnavailableError, match="metadata"):
        load_model(tmp_path)


def test_loading_a_damaged_model_file_is_a_clear_error(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))
    save_model(tmp_path, pipeline, _metadata())
    (tmp_path / MODEL_FILENAME).write_bytes(b"not a model")

    with pytest.raises(ModelUnavailableError, match="does not match"):
        load_model(tmp_path)


def test_loading_a_file_that_is_not_a_pickle_is_a_clear_error(tmp_path: Path) -> None:
    (tmp_path / MODEL_FILENAME).write_bytes(b"not a model")
    digest = hashlib.sha256(b"not a model").hexdigest()
    (tmp_path / "model.json").write_text(
        json.dumps({**asdict(_metadata()), "model_sha256": digest}), encoding="utf-8"
    )

    with pytest.raises(ModelUnavailableError, match="could not be read"):
        load_model(tmp_path)


def test_loading_a_missing_model_file_is_a_clear_error(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))
    save_model(tmp_path, pipeline, _metadata())
    (tmp_path / MODEL_FILENAME).unlink()

    with pytest.raises(ModelUnavailableError, match="python -m app.ml.train"):
        load_model(tmp_path)


def test_loading_rejects_a_model_file_that_does_not_match_its_metadata(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    first, second = tmp_path / "first", tmp_path / "second"
    flows = to_dataset(make_flows(rows=60))
    save_model(first, fit(random_forest(n_estimators=3), flows), _metadata())
    save_model(second, fit(random_forest(n_estimators=4), flows), _metadata())
    (second / MODEL_FILENAME).write_bytes((first / MODEL_FILENAME).read_bytes())

    with pytest.raises(ModelUnavailableError, match="does not match"):
        load_model(second)


def test_loading_rejects_a_file_that_is_not_a_fitted_pipeline(tmp_path: Path) -> None:
    joblib.dump({"not": "a pipeline"}, tmp_path / MODEL_FILENAME)
    digest = hashlib.sha256((tmp_path / MODEL_FILENAME).read_bytes()).hexdigest()
    (tmp_path / "model.json").write_text(
        json.dumps({**asdict(_metadata()), "model_sha256": digest}), encoding="utf-8"
    )

    with pytest.raises(ModelUnavailableError, match="not a trained pipeline"):
        load_model(tmp_path)


def test_errors_keep_server_detail_out_of_the_public_message(tmp_path: Path) -> None:
    with pytest.raises(ModelUnavailableError) as raised:
        load_model(tmp_path / "somewhere")

    assert "somewhere" in str(raised.value)
    assert "somewhere" not in raised.value.public_message
    assert "python -m app.ml.train" in raised.value.public_message


def test_saving_leaves_no_temporary_files(make_flows: MakeFlows, tmp_path: Path) -> None:
    pipeline = fit(random_forest(n_estimators=3), to_dataset(make_flows(rows=60)))

    save_model(tmp_path, pipeline, _metadata())

    assert sorted(path.name for path in tmp_path.iterdir()) == ["model.joblib", "model.json"]
