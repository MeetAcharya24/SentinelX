"""The optional startup threat-intelligence refresh."""

from collections.abc import Callable

import pytest
from fastapi.testclient import TestClient

from app import main
from app.core.config import Settings


@pytest.fixture
def refreshes(monkeypatch: pytest.MonkeyPatch) -> list[Settings]:
    calls: list[Settings] = []
    monkeypatch.setattr(main, "run_intel_refresh", lambda settings: calls.append(settings) or 0)
    monkeypatch.setattr(
        main,
        "_start_intel_refresh",
        lambda settings: main._refresh_intel_quietly(settings),  # noqa: SLF001 - run inline
    )
    return calls


def test_refresh_runs_at_startup_when_enabled(
    refreshes: list[Settings], make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(startup_intel_refresh=True)

    with TestClient(main.create_app(settings)):
        pass

    assert refreshes == [settings]


def test_refresh_does_not_run_by_default(
    refreshes: list[Settings], make_settings: Callable[..., Settings]
) -> None:
    with TestClient(main.create_app(make_settings())):
        pass

    assert refreshes == []


def test_a_failing_refresh_never_stops_the_server(
    monkeypatch: pytest.MonkeyPatch, make_settings: Callable[..., Settings]
) -> None:
    def explode(_: Settings) -> int:
        raise RuntimeError("feed down")

    monkeypatch.setattr(main, "run_intel_refresh", explode)
    monkeypatch.setattr(main, "_start_intel_refresh", main._refresh_intel_quietly)  # noqa: SLF001

    with TestClient(main.create_app(make_settings(startup_intel_refresh=True))) as client:
        assert client.get("/health").status_code == 200
