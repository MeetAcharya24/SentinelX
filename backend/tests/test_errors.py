import logging

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from app.core.errors import INTERNAL_ERROR_MESSAGE, AppError


@pytest.fixture(autouse=True)
def failing_routes(app: FastAPI) -> None:
    @app.get("/_test/app-error")
    def raise_app_error() -> None:
        raise AppError("dataset_too_large", "Upload exceeds the size limit.", status_code=413)

    @app.get("/_test/crash")
    def crash() -> None:
        raise RuntimeError("secret internal detail")

    @app.get("/_test/items/{item_id}")
    def read_item(item_id: int) -> dict[str, int]:
        return {"item_id": item_id}


def test_unknown_route_returns_error_envelope(client: TestClient) -> None:
    response = client.get("/does-not-exist")

    assert response.status_code == 404
    assert response.json() == {
        "success": False,
        "data": None,
        "error": {"code": "http_404", "message": "Not Found", "details": None},
    }


def test_app_error_maps_to_its_status_and_code(client: TestClient) -> None:
    response = client.get("/_test/app-error")

    assert response.status_code == 413
    assert response.json()["error"] == {
        "code": "dataset_too_large",
        "message": "Upload exceeds the size limit.",
        "details": None,
    }


def test_validation_error_lists_offending_fields(client: TestClient) -> None:
    response = client.get("/_test/items/not-a-number")

    assert response.status_code == 422
    error = response.json()["error"]
    assert error["code"] == "validation_error"
    assert error["details"][0]["field"] == "path.item_id"


def test_unhandled_error_is_logged_but_not_leaked(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.ERROR, logger="sentinelx.errors"):
        response = client.get("/_test/crash")

    assert response.status_code == 500
    assert response.json()["error"]["message"] == INTERNAL_ERROR_MESSAGE
    assert "secret internal detail" not in response.text
    assert "secret internal detail" in caplog.text


def test_unhandled_error_keeps_request_id_and_cors_headers(client: TestClient) -> None:
    response = client.get("/_test/crash", headers={"Origin": "http://localhost:3000"})

    assert response.status_code == 500
    assert response.json()["error"]["code"] == "internal_error"
    assert response.headers["x-request-id"]
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_unhandled_error_is_access_logged(
    client: TestClient, caplog: pytest.LogCaptureFixture
) -> None:
    with caplog.at_level(logging.INFO, logger="sentinelx.request"):
        client.get("/_test/crash")

    assert "GET /_test/crash -> 500" in caplog.text


def test_http_error_keeps_its_headers(client: TestClient) -> None:
    response = client.post("/health")

    assert response.status_code == 405
    assert response.json()["error"]["code"] == "http_405"
    assert response.headers["allow"] == "GET"
