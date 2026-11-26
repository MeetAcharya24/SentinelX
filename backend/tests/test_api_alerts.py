"""Alert generation endpoints and the alert list, end to end with small trained models."""

import shutil
from collections.abc import Callable
from pathlib import Path

import pandas as pd
import pytest
import sklearn
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app
from app.ml.anomaly import ANOMALY_DIRNAME
from app.ml.dataset import to_dataset
from app.ml.persistence import ModelMetadata as Metadata
from app.ml.persistence import save_model
from app.ml.phishing_model import build_pipeline, save_phishing_model
from app.ml.schema import FEATURE_COLUMNS
from app.ml.training import fit, isolation_forest, random_forest
from tests.test_api_network import METRICS, _flow, _separable_flows
from tests.test_phishing import (
    LEGIT_EMAIL,
    LEGIT_TEXTS,
    PHISH_TEXTS,
    PHISHING_EMAIL,
    _metadata,
)

MakeFlows = Callable[..., pd.DataFrame]
MakeSettings = Callable[..., Settings]
DEMO_LOG = Path(__file__).resolve().parents[2] / "samples" / "demo_security_log.csv"


@pytest.fixture
def settings(make_settings: MakeSettings, make_flows: MakeFlows, tmp_path: Path) -> Settings:
    flows = _separable_flows(make_flows)
    dataset = to_dataset(flows)
    network_dir = tmp_path / "network"

    def metadata(name: str, rows: int) -> Metadata:
        return Metadata(
            model_name=name,
            trained_at="2026-11-26T10:00:00+00:00",
            training_rows=rows,
            feature_columns=list(FEATURE_COLUMNS),
            sklearn_version=sklearn.__version__,
            test_metrics=METRICS,
        )

    save_model(
        network_dir,
        fit(random_forest(n_estimators=10), dataset),
        metadata("Random Forest", len(flows)),
    )
    save_model(
        network_dir / ANOMALY_DIRNAME,
        fit(isolation_forest(n_estimators=10), dataset),
        metadata("Isolation Forest", int((flows["label"] == 0).sum())),
    )
    texts = PHISH_TEXTS + LEGIT_TEXTS
    classifier = build_pipeline().fit(texts, [1] * len(PHISH_TEXTS) + [0] * len(LEGIT_TEXTS))
    save_phishing_model(tmp_path / "phishing", classifier, _metadata())

    blocklists = tmp_path / "blocklists"
    blocklists.mkdir()
    (blocklists / "bad_ips.txt").write_text("203.0.113.45\n", encoding="utf-8")
    (blocklists / "bad_domains.txt").write_text("evil.example\n", encoding="utf-8")
    return make_settings(
        model_dir=network_dir,
        phishing_model_dir=tmp_path / "phishing",
        blocklist_dir=blocklists,
        database_url=f"sqlite:///{tmp_path / 'alerts.db'}",
    )


@pytest.fixture
def client(settings: Settings) -> TestClient:
    return TestClient(create_app(settings), raise_server_exceptions=False)


def _post_log(client: TestClient, path: str = "/api/v1/analyze/logs", body: bytes | None = None):
    return client.post(
        path, content=body or DEMO_LOG.read_bytes(), headers={"content-type": "text/csv"}
    )


def test_log_analysis_stores_rule_alerts_with_evidence_and_timestamps(client: TestClient) -> None:
    response = _post_log(client)

    data = response.json()["data"]
    assert response.status_code == 200
    assert data["analyzed"] == 30
    by_category = {a["category"]: a for a in data["alerts"]}
    assert set(by_category) == {"known_bad_source", "brute_force", "suspicious_activity"}
    brute = by_category["brute_force"]
    assert brute["severity"] == "high"
    assert brute["source"] == "203.0.113.45"
    assert brute["occurred_at"].startswith("2026-01-12T09:15:00")
    assert brute["created_at"]
    assert brute["evidence"][0]["name"] == "failed_login_burst"
    assert by_category["known_bad_source"]["severity"] == "high"


def test_analysed_alerts_appear_in_the_list_and_by_id(client: TestClient) -> None:
    created = _post_log(client).json()["data"]["alerts"]

    listing = client.get("/api/v1/alerts").json()["data"]
    detail = client.get(f"/api/v1/alerts/{created[0]['id']}")

    assert listing["total"] == len(created) == len(listing["alerts"])
    assert detail.json()["data"] == created[0]


def test_list_filters_by_severity_category_source_and_confidence(client: TestClient) -> None:
    _post_log(client)

    def ids(query: str) -> list[str]:
        data = client.get(f"/api/v1/alerts?{query}").json()["data"]
        return [a["category"] for a in data["alerts"]]

    assert ids("category=brute_force") == ["brute_force"]
    assert set(ids("severity=high&severity=medium")) == {
        "known_bad_source",
        "brute_force",
        "suspicious_activity",
    }
    assert ids("severity=critical") == []
    assert set(ids("source=203.0.113.45&sort=severity")) == {"known_bad_source", "brute_force"}
    assert ids("min_confidence=95") == []
    assert ids("status=resolved") == []


def test_list_pages_and_sorts(client: TestClient) -> None:
    _post_log(client)

    page = client.get("/api/v1/alerts?limit=1&offset=1&sort=severity").json()["data"]

    assert (page["total"], page["limit"], page["offset"], len(page["alerts"])) == (3, 1, 1, 1)


@pytest.mark.parametrize(
    "query",
    ["severity=urgent", "limit=0", "limit=500", "offset=-1", "min_confidence=101", "sort=random"],
)
def test_list_rejects_invalid_parameters(client: TestClient, query: str) -> None:
    response = client.get(f"/api/v1/alerts?{query}")

    assert response.status_code == 422
    assert response.json()["success"] is False


def test_unknown_alert_is_404(client: TestClient) -> None:
    response = client.get("/api/v1/alerts/12345")

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "alert_not_found"


def test_demo_flag_marks_alerts_and_filters(client: TestClient) -> None:
    _post_log(client, "/api/v1/analyze/logs?demo=true")

    demo = client.get("/api/v1/alerts?demo=true").json()["data"]
    real = client.get("/api/v1/alerts?demo=false").json()["data"]

    assert demo["total"] == 3
    assert all(alert["demo"] for alert in demo["alerts"])
    assert real["total"] == 0


def test_invalid_log_is_rejected_and_nothing_is_stored(client: TestClient) -> None:
    response = _post_log(client, body=b"timestamp,event_type\n2026-01-01T00:00:00Z,x\n")

    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_log_file"
    assert client.get("/api/v1/alerts").json()["data"]["total"] == 0


def test_a_clean_log_stores_no_alerts(client: TestClient) -> None:
    body = b"timestamp,event_type,source_ip,status\n2026-01-12T09:00:00Z,access,192.0.2.1,success\n"

    data = _post_log(client, body=body).json()["data"]

    assert data == {"analyzed": 1, "alerts": []}


def test_flow_analysis_scores_with_both_models(client: TestClient, make_flows: MakeFlows) -> None:
    flows = _separable_flows(make_flows)
    # Rows 1 and 3 are attacks in the separable data (odd index), rows 0 and 2 are normal.
    body = {"flows": [_flow(flows, index) for index in (0, 1, 2, 3)]}

    response = client.post("/api/v1/analyze/network", json=body)

    data = response.json()["data"]
    assert response.status_code == 200
    assert data["analyzed"] == 4
    sources = {alert["source"] for alert in data["alerts"]}
    assert {"flow 2", "flow 4"} <= sources, "the attack flows should be flagged"
    for alert in data["alerts"]:
        names = [e["name"] for e in alert["evidence"]]
        assert names[:2] == ["random_forest_attack_probability", "isolation_forest_anomaly_score"]
        assert alert["category"] == "network_anomaly"


def test_flow_analysis_is_503_without_the_anomaly_model(
    make_settings: MakeSettings, settings: Settings, make_flows: MakeFlows, tmp_path: Path
) -> None:
    broken = tmp_path / "no_anomaly"
    shutil.copytree(settings.model_dir, broken)
    shutil.rmtree(broken / ANOMALY_DIRNAME)
    client = TestClient(create_app(settings.model_copy(update={"model_dir": broken})))
    body = {"flows": [_flow(_separable_flows(make_flows), 1)]}

    response = client.post("/api/v1/analyze/network", json=body)

    assert response.status_code == 503
    assert response.json()["error"]["code"] == "model_unavailable"
    assert "app.ml.train" in response.json()["error"]["message"]


def _post_email(client: TestClient, raw: bytes, query: str = ""):
    return client.post(
        f"/api/v1/analyze/phishing{query}",
        content=raw,
        headers={"content-type": "message/rfc822"},
    )


def test_phishing_email_becomes_an_alert_with_signals_and_terms(client: TestClient) -> None:
    response = _post_email(client, PHISHING_EMAIL)

    [alert] = response.json()["data"]["alerts"]
    kinds = {e["kind"] for e in alert["evidence"]}
    assert alert["category"] == "phishing"
    assert alert["source"] == "support@paypa1-secure.example"
    assert alert["severity"] in {"medium", "high"}
    assert kinds == {"model_score", "phishing_signal", "model_term"}


def test_a_legitimate_email_stores_no_alert(client: TestClient) -> None:
    data = _post_email(client, LEGIT_EMAIL).json()["data"]

    assert data["alerts"] == []
    assert client.get("/api/v1/alerts").json()["data"]["total"] == 0


def test_a_link_to_a_known_bad_domain_adds_a_rule_match_and_raises_severity(
    client: TestClient,
) -> None:
    raw = LEGIT_EMAIL.replace(b"Thursday.", b"Thursday http://login.evil.example/x")

    [alert] = _post_email(client, raw).json()["data"]["alerts"]

    assert alert["severity"] == "medium"
    rule = next(e for e in alert["evidence"] if e["kind"] == "rule_match")
    assert (rule["name"], rule["examples"]) == ("known_bad_domain", ["evil.example"])


def test_email_endpoint_rejects_bad_type_and_empty_input(client: TestClient) -> None:
    wrong = client.post(
        "/api/v1/analyze/phishing", content=b"{}", headers={"content-type": "application/json"}
    )
    empty = _post_email(client, b"  ")

    assert wrong.status_code == 415
    assert empty.status_code == 422
