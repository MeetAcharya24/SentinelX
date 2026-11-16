import json
import shutil
from collections.abc import Callable
from pathlib import Path

import numpy as np
import pandas as pd
import pytest
import sklearn
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.ml.dataset import to_dataset
from app.ml.persistence import ModelMetadata, save_model
from app.ml.schema import FEATURE_COLUMNS
from app.ml.training import fit, random_forest

MakeFlows = Callable[..., pd.DataFrame]
MakeSettings = Callable[..., Settings]
URL = "/api/v1/network/score"
METRICS = {
    "precision": 0.8,
    "recall": 0.9,
    "f1": 0.85,
    "accuracy": 0.8,
    "false_positive_rate": 0.25,
    "test_rows": 40,
    "test_attack_share": 0.5,
}


def _separable_flows(make_flows: MakeFlows, rows: int = 200) -> pd.DataFrame:
    labels = np.arange(rows) % 2
    return make_flows(rows=rows, label=labels, sbytes=np.where(labels == 1, 50_000, 10))


def _flow(frame: pd.DataFrame, index: int) -> dict[str, object]:
    row = frame.loc[index, list(FEATURE_COLUMNS)]
    return {name: value.item() if hasattr(value, "item") else value for name, value in row.items()}


@pytest.fixture
def model_dir(make_flows: MakeFlows, tmp_path: Path) -> Path:
    flows = _separable_flows(make_flows)
    pipeline = fit(random_forest(n_estimators=10), to_dataset(flows))
    metadata = ModelMetadata(
        model_name="Random Forest",
        trained_at="2026-11-16T10:00:00+00:00",
        training_rows=len(flows),
        feature_columns=list(FEATURE_COLUMNS),
        sklearn_version=sklearn.__version__,
        test_metrics=METRICS,
    )
    save_model(tmp_path / "model", pipeline, metadata)
    return tmp_path / "model"


@pytest.fixture
def scoring_client(make_settings: MakeSettings, model_dir: Path) -> TestClient:
    return TestClient(create_app(make_settings(model_dir=model_dir)), raise_server_exceptions=False)


def test_scores_flows_in_the_success_envelope(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flows = _separable_flows(make_flows)

    response = scoring_client.post(URL, json={"flows": [_flow(flows, 0), _flow(flows, 1)]})

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    data = body["data"]
    assert data["model"]["name"] == "Random Forest"
    assert data["threshold"] == 0.5
    normal, attack = data["scores"]
    assert normal["is_attack"] is False
    assert attack["is_attack"] is True
    assert 0.0 <= normal["attack_probability"] < 0.5 <= attack["attack_probability"] <= 1.0


def test_reports_a_503_with_instructions_when_no_model_is_trained(
    make_settings: MakeSettings, make_flows: MakeFlows, tmp_path: Path
) -> None:
    client = TestClient(create_app(make_settings(model_dir=tmp_path / "absent")))
    flow = _flow(_separable_flows(make_flows), 0)

    response = client.post(URL, json={"flows": [flow]})

    assert response.status_code == 503
    error = response.json()["error"]
    assert error["code"] == "model_unavailable"
    assert "python -m app.ml.train" in error["message"]


def test_rejects_a_flow_with_a_missing_feature(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)
    del flow["sbytes"]

    response = scoring_client.post(URL, json={"flows": [flow]})

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "validation_error"


def test_rejects_non_numeric_and_non_finite_values(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    text = scoring_client.post(URL, json={"flows": [{**flow, "dur": "fast"}]})
    infinite = scoring_client.post(URL, content=_with_infinity(flow), headers=_JSON)

    assert text.status_code == 422
    assert infinite.status_code == 422


def test_rejects_empty_and_oversized_requests(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    assert scoring_client.post(URL, json={"flows": []}).status_code == 422
    assert scoring_client.post(URL, json={"flows": [flow] * 101}).status_code == 422


def test_rejects_unknown_fields_such_as_the_label_or_row_id(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    response = scoring_client.post(URL, json={"flows": [{**flow, "label": 1, "id": 7}]})

    assert response.status_code == 422


_JSON = {"content-type": "application/json"}


def _with_infinity(flow: dict[str, object]) -> str:
    # Python's json module writes the non-standard literal `Infinity`.
    return json.dumps({"flows": [{**flow, "dur": float("inf")}]})


def test_model_metrics_are_typed_with_an_integer_row_count(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    response = scoring_client.post(URL, json={"flows": [flow]})

    metrics = response.json()["data"]["model"]["test_metrics"]
    assert metrics["false_positive_rate"] == 0.25
    assert '"test_rows":40,' in response.text


def test_rejects_finite_numbers_too_large_for_the_model(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    for huge in (1e39, 1e300):
        response = scoring_client.post(URL, json={"flows": [{**flow, "dur": huge}]})
        assert response.status_code == 422


def test_whitespace_around_categories_is_ignored(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    plain = scoring_client.post(URL, json={"flows": [flow]}).json()["data"]["scores"][0]
    padded = scoring_client.post(URL, json={"flows": [{**flow, "proto": f" {flow['proto']} "}]})

    assert padded.json()["data"]["scores"][0] == plain


def test_categories_unknown_to_the_model_are_reported_per_flow(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    flow = _flow(_separable_flows(make_flows), 0)

    response = scoring_client.post(
        URL, json={"flows": [flow, {**flow, "proto": "zzz", "state": "ACC"}]}
    )

    known, unknown = response.json()["data"]["scores"]
    assert known["unseen_categories"] == []
    assert unknown["unseen_categories"] == ["proto", "state"]


def test_the_503_message_does_not_reveal_server_paths(
    make_settings: MakeSettings, make_flows: MakeFlows, tmp_path: Path
) -> None:
    missing = tmp_path / "private-folder" / "absent"
    client = TestClient(create_app(make_settings(model_dir=missing)))

    message = client.post(URL, json={"flows": [_flow(_separable_flows(make_flows), 0)]}).json()[
        "error"
    ]["message"]

    assert "private-folder" not in message
    assert str(tmp_path) not in message
    assert "python -m app.ml.train" in message


def test_the_model_is_loaded_once_and_reused(
    scoring_client: TestClient, make_flows: MakeFlows, monkeypatch: pytest.MonkeyPatch
) -> None:
    from app.api import network

    calls = []
    real_load = network.load_model
    monkeypatch.setattr(network, "load_model", lambda path: calls.append(path) or real_load(path))
    body = {"flows": [_flow(_separable_flows(make_flows), 0)]}

    for _ in range(3):
        assert scoring_client.post(URL, json=body).status_code == 200

    assert len(calls) == 1


def test_a_failed_load_is_not_cached(
    make_settings: MakeSettings, make_flows: MakeFlows, model_dir: Path, tmp_path: Path
) -> None:
    target = tmp_path / "later"
    client = TestClient(create_app(make_settings(model_dir=target)))
    body = {"flows": [_flow(_separable_flows(make_flows), 0)]}
    assert client.post(URL, json=body).status_code == 503

    shutil.copytree(model_dir, target)

    assert client.post(URL, json=body).status_code == 200


def test_the_served_model_predicts_on_a_single_thread(
    scoring_client: TestClient, make_flows: MakeFlows
) -> None:
    scoring_client.post(URL, json={"flows": [_flow(_separable_flows(make_flows), 0)]})

    served = scoring_client.app.state.network_model

    assert served.loaded.pipeline[-1].n_jobs == 1
