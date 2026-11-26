"""Per-client rate limiting: token bucket, 429 envelope, Retry-After, exemptions."""

import asyncio
from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app.core.config import Settings
from app.core.ratelimit import MAX_TRACKED_CLIENTS, POST_COST, RateLimitMiddleware
from app.main import create_app

MakeSettings = Callable[..., Settings]


class Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _call(app, scope) -> tuple[int, dict[bytes, bytes]]:
    return asyncio.run(_asgi_call(app, scope))


def _limited_app(clock: Clock, **overrides: object):
    async def ok(scope, receive, send):
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    options = {"per_minute": 60, "burst": 3, **overrides}
    return RateLimitMiddleware(ok, clock=clock, **options)  # type: ignore[arg-type]


def _scope(method: str = "GET", path: str = "/x", client: str = "1.1.1.1", headers=()):
    return {
        "type": "http",
        "method": method,
        "path": path,
        "client": (client, 5000),
        "headers": list(headers),
    }


async def _asgi_call(app, scope) -> tuple[int, dict[bytes, bytes]]:
    sent: list[dict] = []

    async def receive():
        return {"type": "http.request", "body": b""}

    async def send(message):
        sent.append(message)

    await app(scope, receive, send)
    start = sent[0]
    return start["status"], dict(start["headers"])


def test_requests_within_the_burst_pass_then_429_with_retry_after() -> None:
    app = _limited_app(Clock())

    statuses = [(_call(app, _scope()))[0] for _ in range(4)]
    status, headers = _call(app, _scope())

    assert statuses == [200, 200, 200, 429]
    assert status == 429 and headers[b"retry-after"] == b"1"


def test_tokens_refill_over_time() -> None:
    clock = Clock()
    app = _limited_app(clock)
    for _ in range(3):
        _call(app, _scope())
    assert (_call(app, _scope()))[0] == 429

    clock.now += 1.0  # 60 per minute refills one token a second

    assert (_call(app, _scope()))[0] == 200
    assert (_call(app, _scope()))[0] == 429


def test_a_post_costs_more_and_waits_proportionally_longer() -> None:
    app = _limited_app(Clock(), per_minute=60, burst=10)

    first = _call(app, _scope("POST"))
    second = _call(app, _scope("POST"))
    third = _call(app, _scope("POST"))

    assert (first[0], second[0], third[0]) == (200, 200, 429)
    # Tokens left: 0, needing POST_COST at one a second.
    assert third[1][b"retry-after"] == str(POST_COST).encode()


def test_each_client_has_its_own_bucket() -> None:
    app = _limited_app(Clock())
    for _ in range(3):
        _call(app, _scope(client="1.1.1.1"))

    assert (_call(app, _scope(client="1.1.1.1")))[0] == 429
    assert (_call(app, _scope(client="2.2.2.2")))[0] == 200


def test_health_and_preflight_are_never_limited() -> None:
    app = _limited_app(Clock(), burst=1)
    for _ in range(3):
        _call(app, _scope())

    assert (_call(app, _scope(path="/health")))[0] == 200
    assert (_call(app, _scope("OPTIONS")))[0] == 200


def test_forwarded_header_is_ignored_unless_the_proxy_is_trusted() -> None:
    forged = [(b"x-forwarded-for", b"9.9.9.9, 8.8.8.8")]
    plain = _limited_app(Clock())
    for _ in range(3):
        _call(plain, _scope(headers=forged))
    assert (_call(plain, _scope(headers=[(b"x-forwarded-for", b"7.7.7.7")])))[0] == 429

    trusted = _limited_app(Clock(), trust_proxy_headers=True)
    for _ in range(3):
        _call(trusted, _scope(headers=forged))
    # Keyed by the last entry (8.8.8.8), so a different client behind the proxy is fresh.
    assert (_call(trusted, _scope(headers=[(b"x-forwarded-for", b"7.7.7.7")])))[0] == 200
    assert (_call(trusted, _scope(headers=forged)))[0] == 429


def test_the_client_table_stays_bounded() -> None:
    app = _limited_app(Clock())

    for index in range(MAX_TRACKED_CLIENTS + 50):
        _call(app, _scope(client=f"10.{index // 65536}.{(index // 256) % 256}.{index % 256}"))

    assert len(app._buckets) == MAX_TRACKED_CLIENTS


# --- through the real application -------------------------------------------


@pytest.fixture
def client(make_settings: MakeSettings) -> TestClient:
    return TestClient(create_app(make_settings(rate_limit_per_minute=60, rate_limit_burst=3)))


def test_the_api_answers_429_in_the_envelope_with_retry_after_and_request_id(
    client: TestClient,
) -> None:
    for _ in range(3):
        assert client.get("/api/v1/alerts").status_code == 200

    response = client.get("/api/v1/alerts", headers={"Origin": "http://localhost:3000"})

    assert response.status_code == 429
    assert int(response.headers["retry-after"]) >= 1
    body = response.json()
    assert body["success"] is False and body["error"]["code"] == "http_429"
    assert response.headers["x-request-id"]
    assert response.headers["access-control-allow-origin"] == "http://localhost:3000"


def test_health_stays_available_while_the_api_is_limited(client: TestClient) -> None:
    for _ in range(5):
        client.get("/api/v1/alerts")

    assert client.get("/health").status_code == 200


def test_a_limit_of_zero_turns_limiting_off(make_settings: MakeSettings) -> None:
    client = TestClient(create_app(make_settings(rate_limit_per_minute=0, rate_limit_burst=1)))

    assert all(client.get("/api/v1/alerts").status_code == 200 for _ in range(10))
