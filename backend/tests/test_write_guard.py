"""Optional write-protection token on the mutating and expensive endpoints."""

from collections.abc import Callable
from pathlib import Path

import pytest
from fastapi.routing import APIRoute
from fastapi.testclient import TestClient
from pydantic import ValidationError

from app.core.config import Settings
from app.core.writeguard import WRITE_TOKEN_HEADER, require_write_token
from app.main import create_app

MakeSettings = Callable[..., Settings]

TOKEN = "t" * 24

# (method, path, body kwargs) for every gated route. The requests are deliberately minimal:
# past the gate they fail validation or find no alert, which is all these tests need.
GATED = [
    ("POST", "/api/v1/analyze/network", {"json": {"flows": []}}),
    (
        "POST",
        "/api/v1/analyze/logs",
        {"content": b"x", "headers_extra": {"content-type": "text/csv"}},
    ),
    (
        "POST",
        "/api/v1/analyze/phishing",
        {"content": b"x", "headers_extra": {"content-type": "text/plain"}},
    ),
    ("PATCH", "/api/v1/alerts/1", {"json": {"note": "n"}}),
    ("POST", "/api/v1/alerts/1/analysis/refresh", {}),
]

# Mutating or model-running routes that are not gated, each a deliberate decision recorded in
# THREAT_MODEL.md: they are side-effect free and only rate limited.
UNGATED = {
    ("POST", "/api/v1/network/score"),
    ("POST", "/api/v1/phishing/classify"),
    ("POST", "/api/v1/logs/validate"),
}


def _send(client: TestClient, method: str, path: str, options: dict, token: str | None = None):
    options = dict(options)
    headers = dict(options.pop("headers_extra", {}))
    if token is not None:
        headers[WRITE_TOKEN_HEADER] = token
    return client.request(method, path, headers=headers, **options)


@pytest.fixture
def protected(make_settings: MakeSettings, tmp_path) -> TestClient:
    settings = make_settings(
        database_url=f"sqlite:///{tmp_path / 'alerts.db'}", demo_write_token=TOKEN
    )
    return TestClient(create_app(settings))


@pytest.fixture
def open_client(make_settings: MakeSettings, tmp_path) -> TestClient:
    settings = make_settings(database_url=f"sqlite:///{tmp_path / 'alerts.db'}")
    return TestClient(create_app(settings))


@pytest.mark.parametrize(("method", "path", "options"), GATED)
def test_a_gated_route_refuses_a_missing_token(protected, method, path, options) -> None:
    response = _send(protected, method, path, options)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "write_protected"


@pytest.mark.parametrize(("method", "path", "options"), GATED)
def test_a_gated_route_refuses_a_wrong_token(protected, method, path, options) -> None:
    response = _send(protected, method, path, options, token="w" * 24)

    assert response.status_code == 403
    assert response.json()["error"]["code"] == "write_protected"


@pytest.mark.parametrize(("method", "path", "options"), GATED)
def test_a_gated_route_accepts_the_right_token(protected, method, path, options) -> None:
    response = _send(protected, method, path, options, token=TOKEN)

    assert response.status_code != 403


@pytest.mark.parametrize(("method", "path", "options"), GATED)
def test_nothing_is_gated_when_no_token_is_configured(open_client, method, path, options) -> None:
    response = _send(open_client, method, path, options)

    assert response.status_code != 403


def test_a_token_that_differs_only_in_case_is_refused(protected) -> None:
    response = _send(protected, "PATCH", "/api/v1/alerts/1", {"json": {"note": "n"}}, TOKEN.upper())

    assert response.status_code == 403


def test_a_non_ascii_token_is_refused_not_a_server_error(protected) -> None:
    response = protected.patch(
        "/api/v1/alerts/1",
        json={"note": "n"},
        headers={WRITE_TOKEN_HEADER: "tökén".encode("latin-1")},
    )

    assert response.status_code == 403


def test_reads_and_health_need_no_token_when_one_is_configured(protected) -> None:
    for path in ("/health", "/api/v1/alerts", "/api/v1/network/model"):
        assert protected.get(path).status_code != 403, path


def test_a_refused_upload_stores_nothing(protected) -> None:
    log = Path("../samples/demo_security_log.csv").read_bytes()

    refused = protected.post(
        "/api/v1/analyze/logs?demo=true", content=log, headers={"content-type": "text/csv"}
    )
    accepted = protected.post(
        "/api/v1/analyze/logs?demo=true",
        content=log,
        headers={"content-type": "text/csv", WRITE_TOKEN_HEADER: TOKEN},
    )

    assert refused.status_code == 403
    assert accepted.status_code == 200
    # Only the authorised upload's alerts exist: the refused one did not run the pipeline.
    stored = protected.get("/api/v1/alerts").json()["data"]["total"]
    assert stored == len(accepted.json()["data"]["alerts"]) > 0


def test_the_refusal_never_echoes_the_configured_token(protected) -> None:
    response = _send(protected, "PATCH", "/api/v1/alerts/1", {"json": {"note": "n"}}, "w" * 24)

    assert TOKEN not in response.text


def _api_routes(app) -> list[APIRoute]:
    """Every APIRoute, looking inside the lazily included routers of this FastAPI version."""
    found: list[APIRoute] = []
    for route in app.routes:
        nested = getattr(route, "original_router", None)
        found += _api_routes(nested) if nested is not None else []
        if isinstance(route, APIRoute):
            found.append(route)
    return found


def test_every_mutating_route_is_either_gated_or_a_recorded_exception(open_client) -> None:
    mutating = {"POST", "PATCH", "PUT", "DELETE"}
    ungated: set[tuple[str, str]] = set()
    gated: set[tuple[str, str]] = set()
    for route in _api_routes(open_client.app):
        calls = {dep.call for dep in route.dependant.dependencies}
        for method in route.methods & mutating:
            (gated if require_write_token in calls else ungated).add((method, route.path))

    assert ungated == UNGATED
    assert {path for _, path in gated} == {
        "/api/v1/analyze/network",
        "/api/v1/analyze/logs",
        "/api/v1/analyze/phishing",
        "/api/v1/alerts/{alert_id}",
        "/api/v1/alerts/{alert_id}/analysis/refresh",
    }


def test_a_blank_token_means_not_configured(make_settings: MakeSettings) -> None:
    assert make_settings(demo_write_token="  ").demo_write_token is None


def test_a_short_token_is_rejected_at_startup(make_settings: MakeSettings) -> None:
    with pytest.raises(ValidationError, match="at least 16"):
        make_settings(demo_write_token="short")


def test_a_rejected_token_is_not_echoed_in_the_startup_error(make_settings: MakeSettings) -> None:
    with pytest.raises(ValidationError) as caught:
        make_settings(demo_write_token="hunter2short")

    assert "hunter2short" not in str(caught.value)


def test_the_token_is_not_shown_when_settings_are_printed(make_settings: MakeSettings) -> None:
    assert TOKEN not in repr(make_settings(demo_write_token=TOKEN))
