"""SQLite alert persistence: round trip, filters, ordering and paging."""

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from app.detection.alerts import (
    AlertCandidate,
    AlertCategory,
    AlertSeverity,
    Evidence,
    EvidenceKind,
)
from app.storage.alerts import AlertFilter, AlertStore

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _candidate(
    severity: AlertSeverity = AlertSeverity.MEDIUM,
    category: AlertCategory = AlertCategory.BRUTE_FORCE,
    source: str = "203.0.113.45",
    confidence: int = 80,
    occurred_at: datetime | None = None,
) -> AlertCandidate:
    return AlertCandidate(
        severity=severity,
        confidence=confidence,
        category=category,
        source=source,
        asset="vpn",
        title="title",
        evidence=(
            Evidence(EvidenceKind.RULE_MATCH, "rule", "matched", 5.0, ("a", "b")),
            Evidence(EvidenceKind.MODEL_SCORE, "score", "scored"),
        ),
        occurred_at=occurred_at,
    )


@pytest.fixture
def store(tmp_path: Path) -> AlertStore:
    return AlertStore(tmp_path / "alerts.db")


def test_an_alert_round_trips_with_its_evidence_and_timestamps(store: AlertStore) -> None:
    occurred = NOW - timedelta(hours=3)

    [saved] = store.add_many([_candidate(occurred_at=occurred)], demo=False, now=NOW)
    loaded = store.get(saved.id)

    assert loaded == saved
    assert loaded is not None
    assert loaded.created_at == NOW
    assert loaded.occurred_at == occurred
    assert loaded.status == "open"
    assert loaded.demo is False
    assert loaded.evidence[0].examples == ("a", "b")
    assert loaded.evidence[1].value is None


def test_alerts_survive_reopening_the_database(tmp_path: Path) -> None:
    path = tmp_path / "nested" / "alerts.db"
    AlertStore(path).add_many([_candidate()], demo=True)

    [reloaded], total = AlertStore(path).query(AlertFilter())

    assert total == 1
    assert reloaded.demo is True


def test_an_unknown_id_is_none(store: AlertStore) -> None:
    assert store.get(999) is None


def test_the_demo_flag_is_stored_and_filterable(store: AlertStore) -> None:
    store.add_many([_candidate(source="real")], demo=False)
    store.add_many([_candidate(source="demo")], demo=True)

    demo, _ = store.query(AlertFilter(demo=True))
    real, _ = store.query(AlertFilter(demo=False))

    assert [a.source for a in demo] == ["demo"]
    assert [a.source for a in real] == ["real"]


@pytest.fixture
def populated(store: AlertStore) -> AlertStore:
    store.add_many(
        [_candidate(AlertSeverity.LOW, AlertCategory.NETWORK_ANOMALY, "flow 1", 40)],
        demo=False,
        now=NOW,
    )
    store.add_many(
        [_candidate(AlertSeverity.CRITICAL, AlertCategory.BRUTE_FORCE, "10.0.0.1", 90)],
        demo=False,
        now=NOW + timedelta(hours=1),
    )
    store.add_many(
        [_candidate(AlertSeverity.MEDIUM, AlertCategory.PHISHING, "a@b.example", 70)],
        demo=False,
        now=NOW + timedelta(hours=2),
    )
    return store


def _sources(store: AlertStore, **criteria: object) -> list[str]:
    alerts, _ = store.query(AlertFilter(**criteria))  # type: ignore[arg-type]
    return [alert.source for alert in alerts]


def test_default_order_is_newest_first(populated: AlertStore) -> None:
    assert _sources(populated) == ["a@b.example", "10.0.0.1", "flow 1"]


def test_severity_order_lists_most_severe_first(populated: AlertStore) -> None:
    assert _sources(populated, newest_first=False) == ["10.0.0.1", "a@b.example", "flow 1"]


def test_filters_combine_with_and_and_repeat_values_with_or(populated: AlertStore) -> None:
    both = [AlertSeverity.LOW, AlertSeverity.CRITICAL]

    assert _sources(populated, severities=both) == ["10.0.0.1", "flow 1"]
    assert _sources(populated, severities=both, categories=[AlertCategory.BRUTE_FORCE]) == [
        "10.0.0.1"
    ]
    assert _sources(populated, min_confidence=70) == ["a@b.example", "10.0.0.1"]
    assert _sources(populated, source="flow 1") == ["flow 1"]
    assert _sources(populated, statuses=["resolved"]) == []


def test_created_range_is_inclusive(populated: AlertStore) -> None:
    window = {"created_from": NOW + timedelta(hours=1), "created_to": NOW + timedelta(hours=2)}

    assert _sources(populated, **window) == ["a@b.example", "10.0.0.1"]


def test_paging_reports_the_total_and_clamps_the_page_size(populated: AlertStore) -> None:
    page, total = populated.query(AlertFilter(limit=1, offset=1))
    everything, _ = populated.query(AlertFilter(limit=10_000))

    assert (total, [a.source for a in page]) == (3, ["10.0.0.1"])
    assert len(everything) == 3


def test_filter_values_are_bound_not_interpolated(populated: AlertStore) -> None:
    assert _sources(populated, source="x' OR '1'='1") == []
    assert populated.query(AlertFilter())[1] == 3


def test_the_database_rejects_an_out_of_range_confidence(store: AlertStore) -> None:
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        store.add_many([_candidate(confidence=101)], demo=False)
    assert store.query(AlertFilter())[1] == 0


def test_a_failed_batch_stores_nothing(store: AlertStore) -> None:
    import sqlite3

    with pytest.raises(sqlite3.IntegrityError):
        store.add_many([_candidate(), _candidate(confidence=-1)], demo=False)

    assert store.query(AlertFilter())[1] == 0
