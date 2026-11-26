"""Investigation workflow: status changes and append-only analyst notes."""

import sqlite3
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from app.detection.alerts import (
    AlertCandidate,
    AlertCategory,
    AlertSeverity,
    Evidence,
    EvidenceKind,
)
from app.storage.alerts import AlertFilter, AlertStore, StoredAlert
from tests.test_api_alerts import _post_log, client, settings  # noqa: F401  (fixtures)

NOW = datetime(2026, 11, 26, 12, 0, tzinfo=UTC)


def _candidate(source: str = "203.0.113.45") -> AlertCandidate:
    return AlertCandidate(
        severity=AlertSeverity.MEDIUM,
        confidence=80,
        category=AlertCategory.BRUTE_FORCE,
        source=source,
        asset="vpn",
        title="title",
        evidence=(Evidence(EvidenceKind.RULE_MATCH, "rule", "matched", 5.0, ("a",)),),
    )


@pytest.fixture
def store(tmp_path: Path) -> AlertStore:
    return AlertStore(tmp_path / "alerts.db")


def _one(store: AlertStore) -> StoredAlert:
    [saved] = store.add_many([_candidate()], demo=False, now=NOW)
    return saved


def _reload(store: AlertStore, alert: StoredAlert) -> StoredAlert:
    loaded = store.get(alert.id)
    assert loaded is not None
    return loaded


@pytest.mark.parametrize("status", ["acknowledged", "false_positive", "resolved", "open"])
def test_every_status_can_be_set(store: AlertStore, status: str) -> None:
    saved = _one(store)

    updated = store.update(saved.id, status=status)

    assert updated is not None
    assert updated.status == status
    assert _reload(store, saved).status == status


def test_any_status_can_follow_any_other_so_mistakes_can_be_undone(store: AlertStore) -> None:
    saved = _one(store)

    for status in ("resolved", "open", "false_positive", "acknowledged", "resolved"):
        updated = store.update(saved.id, status=status)
        assert updated is not None
        assert updated.status == status


def test_a_status_change_leaves_the_rest_of_the_alert_alone(store: AlertStore) -> None:
    saved = _one(store)

    updated = store.update(saved.id, status="resolved")

    assert updated is not None
    assert updated.created_at == saved.created_at
    assert updated.evidence == saved.evidence
    assert updated.notes == ()


def test_notes_append_in_order_with_their_own_timestamps(store: AlertStore) -> None:
    saved = _one(store)

    store.update(saved.id, note="  first look  ", now=NOW + timedelta(minutes=1))
    updated = store.update(saved.id, note="second", now=NOW + timedelta(minutes=5))

    assert updated is not None
    assert [(n.text, n.created_at) for n in updated.notes] == [
        ("first look", NOW + timedelta(minutes=1)),
        ("second", NOW + timedelta(minutes=5)),
    ]
    assert updated.status == "open"


def test_status_and_note_change_together(store: AlertStore) -> None:
    saved = _one(store)

    updated = store.update(saved.id, status="false_positive", note="Scanner in the test lab")

    assert updated is not None
    assert updated.status == "false_positive"
    assert [n.text for n in updated.notes] == ["Scanner in the test lab"]


def test_notes_stay_with_their_own_alert_in_gets_and_lists(store: AlertStore) -> None:
    first, second = store.add_many([_candidate(), _candidate("other")], demo=False, now=NOW)
    store.update(first.id, note="about first")

    listed, _ = store.query(AlertFilter())

    assert {a.id: [n.text for n in a.notes] for a in listed} == {
        first.id: ["about first"],
        second.id: [],
    }
    assert [n.text for n in _reload(store, first).notes] == ["about first"]


def test_bad_input_changes_nothing(store: AlertStore) -> None:
    saved = _one(store)

    for kwargs in ({"status": "investigating"}, {"note": "   "}, {"note": "x" * 2001}):
        with pytest.raises(ValueError):
            store.update(saved.id, **kwargs)
    with pytest.raises(ValueError):  # a valid status is not applied when the note is bad
        store.update(saved.id, status="resolved", note="")

    unchanged = _reload(store, saved)
    assert (unchanged.status, unchanged.notes) == ("open", ())


def test_updating_a_missing_alert_is_none(store: AlertStore) -> None:
    assert store.update(404, status="resolved") is None
    assert store.update(404, note="orphan") is None


def test_the_database_itself_refuses_to_edit_or_delete_notes(
    store: AlertStore, tmp_path: Path
) -> None:
    saved = _one(store)
    store.update(saved.id, note="keep me")
    connection = sqlite3.connect(tmp_path / "alerts.db")
    try:
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("UPDATE alert_notes SET text = 'changed'")
        with pytest.raises(sqlite3.DatabaseError, match="append-only"):
            connection.execute("DELETE FROM alert_notes")
    finally:
        connection.close()

    assert [n.text for n in _reload(store, saved).notes] == ["keep me"]


def test_an_item_3_database_without_notes_gains_the_table_when_reopened(tmp_path: Path) -> None:
    path = tmp_path / "old.db"
    AlertStore(path).add_many([_candidate()], demo=False)
    connection = sqlite3.connect(path)
    connection.executescript(
        "DROP TRIGGER alert_notes_no_update; DROP TRIGGER alert_notes_no_delete;"
        " DROP TABLE alert_notes;"
    )
    connection.close()

    updated = AlertStore(path).update(1, note="after upgrade")

    assert updated is not None
    assert [n.text for n in updated.notes] == ["after upgrade"]


def _first_alert_id(client: TestClient) -> int:
    return _post_log(client).json()["data"]["alerts"][0]["id"]


@pytest.mark.parametrize("status", ["acknowledged", "false_positive", "resolved", "open"])
def test_patch_sets_the_status_and_returns_the_alert(client: TestClient, status: str) -> None:
    alert_id = _first_alert_id(client)

    response = client.patch(f"/api/v1/alerts/{alert_id}", json={"status": status})

    data = response.json()["data"]
    assert response.status_code == 200
    assert (data["id"], data["status"], data["notes"]) == (alert_id, status, [])
    assert client.get(f"/api/v1/alerts/{alert_id}").json()["data"]["status"] == status


def test_patch_appends_notes_and_the_detail_shows_the_whole_history(client: TestClient) -> None:
    alert_id = _first_alert_id(client)

    client.patch(f"/api/v1/alerts/{alert_id}", json={"note": "Checked the VPN logs."})
    response = client.patch(
        f"/api/v1/alerts/{alert_id}", json={"status": "resolved", "note": "  Owner confirmed.  "}
    )

    notes = response.json()["data"]["notes"]
    assert [n["text"] for n in notes] == ["Checked the VPN logs.", "Owner confirmed."]
    assert notes[0]["created_at"] <= notes[1]["created_at"]
    assert all(set(n) == {"id", "created_at", "text"} for n in notes)  # no author field
    assert client.get(f"/api/v1/alerts/{alert_id}").json()["data"]["notes"] == notes
    listed = client.get("/api/v1/alerts?status=resolved").json()["data"]["alerts"]
    assert [a["notes"] for a in listed] == [notes]


def test_a_status_filter_follows_status_changes(client: TestClient) -> None:
    alert_id = _first_alert_id(client)
    client.patch(f"/api/v1/alerts/{alert_id}", json={"status": "false_positive"})

    flagged = client.get("/api/v1/alerts?status=false_positive").json()["data"]
    still_open = client.get("/api/v1/alerts?status=open").json()["data"]

    assert [a["id"] for a in flagged["alerts"]] == [alert_id]
    assert alert_id not in [a["id"] for a in still_open["alerts"]]


@pytest.mark.parametrize(
    "body",
    [
        {},
        {"status": "investigating"},
        {"status": None, "note": None},
        {"note": "   "},
        {"note": "x" * 2001},
        {"note": 5},
        {"status": "resolved", "author": "alice"},
    ],
)
def test_patch_rejects_invalid_bodies_and_changes_nothing(
    client: TestClient, body: dict[str, object]
) -> None:
    alert_id = _first_alert_id(client)

    response = client.patch(f"/api/v1/alerts/{alert_id}", json=body)

    assert response.status_code == 422
    assert response.json()["success"] is False
    after = client.get(f"/api/v1/alerts/{alert_id}").json()["data"]
    assert (after["status"], after["notes"]) == ("open", [])


def test_patch_of_a_missing_alert_is_404(client: TestClient) -> None:
    response = client.patch("/api/v1/alerts/999", json={"status": "resolved"})

    assert response.status_code == 404
    assert response.json()["error"]["code"] == "alert_not_found"
