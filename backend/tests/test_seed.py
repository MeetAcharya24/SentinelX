"""The demo seed loads only the synthetic data the repository ships."""

import sqlite3
from collections.abc import Callable
from pathlib import Path

import pytest

from app import seed
from app.core.config import Settings


@pytest.fixture
def settings(tmp_path: Path, make_settings: Callable[..., Settings]) -> Settings:
    return make_settings(database_url=f"sqlite:///{tmp_path / 'seed.db'}")


def _rows(settings: Settings) -> list[sqlite3.Row]:
    with sqlite3.connect(settings.sqlite_path) as connection:
        connection.row_factory = sqlite3.Row
        return connection.execute("SELECT * FROM alerts").fetchall()


def test_seed_stores_only_alerts_labelled_as_demo(settings: Settings) -> None:
    from_log, from_flows = seed.seed(settings)

    rows = _rows(settings)
    assert from_log > 0
    assert from_flows > 0
    assert len(rows) == from_log + from_flows
    assert all(row["demo"] == 1 for row in rows)


def test_seed_is_repeatable(settings: Settings) -> None:
    seed.seed(settings)
    first = len(_rows(settings))

    seed.seed(settings)

    assert len(_rows(settings)) == first


def test_seed_uses_the_shipped_blocklist_not_the_configured_one(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    elsewhere = tmp_path / "other-lists"
    elsewhere.mkdir()
    (elsewhere / "bad_ips.txt").write_text("198.51.100.0/24\n", encoding="utf-8")
    settings = make_settings(
        database_url=f"sqlite:///{tmp_path / 'seed.db'}", blocklist_dir=elsewhere
    )

    seed.seed(settings)

    sources = " ".join(row["source"] for row in _rows(settings))
    assert "203.0.113.45" in sources


def test_seed_reads_nothing_from_the_data_directory() -> None:
    sources = [seed.DEMO_LOG, seed.DEMO_BLOCKLISTS]
    assert all(seed.SAMPLES_DIR in path.parents for path in sources)


def test_seed_reports_missing_models_instead_of_crashing(
    tmp_path: Path, make_settings: Callable[..., Settings]
) -> None:
    settings = make_settings(
        database_url=f"sqlite:///{tmp_path / 'seed.db'}", model_dir=tmp_path / "no-model"
    )

    with pytest.raises(seed.ModelUnavailableError):
        seed.seed(settings)
