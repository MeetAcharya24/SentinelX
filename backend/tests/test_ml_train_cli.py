from collections.abc import Callable
from pathlib import Path

import pandas as pd
import pytest

from app.ml.anomaly import ANOMALY_DIRNAME
from app.ml.persistence import load_model
from app.ml.schema import DATASET_DIRNAME, TESTING_SPLIT, TRAINING_SPLIT, SplitFile
from app.ml.train import main
from app.ml.training import isolation_forest, random_forest

MakeFlows = Callable[..., pd.DataFrame]


def _write_split(data_dir: Path, flows: pd.DataFrame, filename: str) -> SplitFile:
    folder = data_dir / DATASET_DIRNAME
    folder.mkdir(parents=True, exist_ok=True)
    flows.to_csv(folder / filename, index=False)
    return SplitFile(filename=filename, rows=len(flows), sha256="")


def test_main_reports_metrics_for_each_baseline(
    make_flows: MakeFlows, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    training = _write_split(tmp_path, make_flows(rows=120), "train.csv")
    testing = _write_split(tmp_path, make_flows(rows=40), "test.csv")

    exit_code = main(tmp_path, training, testing, baselines=[random_forest(n_estimators=5)])

    output = capsys.readouterr().out
    assert exit_code == 0
    assert "Random Forest" in output
    assert "Precision" in output
    assert "Confusion matrix" in output
    assert "Training split: 120 rows" in output
    assert "Testing split: 40 rows" in output


def test_main_scores_a_separable_dataset_perfectly(
    make_flows: MakeFlows, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def separable(rows: int) -> pd.DataFrame:
        labels = [index % 2 for index in range(rows)]
        sbytes = [50_000 if label else 10 for label in labels]
        return make_flows(rows=rows, label=labels, sbytes=sbytes)

    training = _write_split(tmp_path, separable(120), "train.csv")
    testing = _write_split(tmp_path, separable(40), "test.csv")

    main(tmp_path, training, testing, baselines=[random_forest(n_estimators=5)])

    assert "F1 1.0000" in capsys.readouterr().out


def test_main_saves_the_random_forest_with_its_test_metrics(
    make_flows: MakeFlows, tmp_path: Path
) -> None:
    train_flows = make_flows(rows=120)
    flows_labels = train_flows["label"]
    training = _write_split(tmp_path, train_flows, "train.csv")
    testing = _write_split(tmp_path, make_flows(rows=40), "test.csv")
    model_dir = tmp_path / "model"

    main(
        tmp_path,
        training,
        testing,
        baselines=[isolation_forest(n_estimators=5), random_forest(n_estimators=5)],
        model_dir=model_dir,
    )

    saved = load_model(model_dir)
    assert saved.metadata.model_name == "Random Forest"
    assert saved.metadata.training_rows == 120
    assert saved.metadata.test_metrics["test_rows"] == 40
    assert 0.0 <= saved.metadata.test_metrics["f1"] <= 1.0

    anomaly = load_model(model_dir / ANOMALY_DIRNAME)
    assert anomaly.metadata.model_name == "Isolation Forest"
    assert anomaly.metadata.training_rows == int((flows_labels == 0).sum())


def test_main_saves_nothing_when_only_unsupervised_models_were_trained(
    make_flows: MakeFlows, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    training = _write_split(tmp_path, make_flows(rows=60), "train.csv")
    testing = _write_split(tmp_path, make_flows(rows=20), "test.csv")

    main(
        tmp_path,
        training,
        testing,
        baselines=[isolation_forest(n_estimators=3)],
        model_dir=tmp_path / "model",
    )

    assert not (tmp_path / "model").exists()
    assert "nothing was saved" in capsys.readouterr().out


def test_main_without_a_model_dir_saves_nothing(make_flows: MakeFlows, tmp_path: Path) -> None:
    training = _write_split(tmp_path, make_flows(rows=60), "train.csv")
    testing = _write_split(tmp_path, make_flows(rows=20), "test.csv")

    main(tmp_path, training, testing, baselines=[random_forest(n_estimators=3)])

    assert not (tmp_path / "model").exists()


def test_main_with_an_empty_baseline_list_trains_nothing(
    make_flows: MakeFlows, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    training = _write_split(tmp_path, make_flows(rows=20), "train.csv")
    testing = _write_split(tmp_path, make_flows(rows=10), "test.csv")

    main(tmp_path, training, testing, baselines=[])

    assert "Precision" not in capsys.readouterr().out


def test_main_fails_and_points_to_the_readme_without_the_dataset(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    exit_code = main(tmp_path, TRAINING_SPLIT, TESTING_SPLIT)

    assert exit_code == 1
    assert "README" in capsys.readouterr().out
