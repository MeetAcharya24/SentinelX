from fastapi.testclient import TestClient

from app import __version__
from app.core.logging import REQUEST_ID_HEADER
from app.main import create_app


def test_health_reports_ok_in_success_envelope(client: TestClient) -> None:
    response = client.get("/health")

    assert response.status_code == 200
    body = response.json()
    assert body["success"] is True
    assert body["error"] is None
    assert body["data"]["status"] == "ok"
    assert body["data"]["version"] == __version__
    assert body["data"]["environment"] == "test"


def test_health_reports_deterministic_analyst_when_no_key_configured(client: TestClient) -> None:
    data = client.get("/health").json()["data"]

    assert data["analyst"] == {"mode": "deterministic", "provider": None}
    assert data["threatfox_configured"] is False


def test_health_reports_llm_analyst_when_key_configured(make_settings) -> None:
    client = TestClient(create_app(make_settings(groq_api_key="test-key")))

    response = client.get("/health")

    assert response.json()["data"]["analyst"] == {"mode": "llm", "provider": "groq"}
    assert "test-key" not in response.text


def test_responses_carry_request_id_header(client: TestClient) -> None:
    response = client.get("/health")

    assert len(response.headers[REQUEST_ID_HEADER]) == 32


def test_cors_allows_configured_origin_only(client: TestClient) -> None:
    allowed = client.get("/health", headers={"Origin": "http://localhost:3000"})
    denied = client.get("/health", headers={"Origin": "http://evil.example"})

    assert allowed.headers["access-control-allow-origin"] == "http://localhost:3000"
    assert "access-control-allow-origin" not in denied.headers
