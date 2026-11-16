from collections.abc import Callable, Iterator

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.main import create_app

MakeSettings = Callable[..., Settings]
URL = "/api/v1/network/score"
JSON = {"content-type": "application/json"}
LIMIT = 1_000


@pytest.fixture
def client(make_settings: MakeSettings) -> TestClient:
    return TestClient(create_app(make_settings(max_request_bytes=LIMIT)))


def _chunks(total: int, size: int) -> Iterator[bytes]:
    for _ in range(total // size):
        yield b"x" * size


def test_declared_oversized_body_is_refused_in_the_envelope(client: TestClient) -> None:
    response = client.post(URL, content=b"x" * (LIMIT + 1), headers=JSON)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "http_413"
    assert response.json()["success"] is False


def test_streamed_oversized_body_is_refused_without_a_declared_length(client: TestClient) -> None:
    response = client.post(URL, content=_chunks(total=LIMIT * 3, size=200), headers=JSON)

    assert response.status_code == 413
    assert response.json()["error"]["code"] == "http_413"


def test_refusal_keeps_the_request_id_and_cors_headers(client: TestClient) -> None:
    response = client.post(
        URL,
        content=b"x" * (LIMIT + 1),
        headers={**JSON, "origin": "http://localhost:3000"},
    )

    assert response.status_code == 413
    assert response.headers["x-request-id"]
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_body_within_the_limit_reaches_the_route(client: TestClient) -> None:
    response = client.post(URL, json={"flows": []})

    assert response.status_code == 422


def test_requests_without_a_body_are_unaffected(client: TestClient) -> None:
    assert client.get("/health").status_code == 200
