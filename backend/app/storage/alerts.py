"""SQLite persistence for alerts.

Each call opens its own short-lived connection, so the store is safe to use from
the API's worker threads. Alerts are added in batches; afterwards only their status
can change, and notes can be appended but never edited or removed.
"""

import hashlib
import json
import sqlite3
from collections.abc import Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

from app.detection.alerts import (
    SEVERITY_ORDER,
    AlertCandidate,
    AlertCategory,
    AlertSeverity,
    Evidence,
    EvidenceKind,
)

STATUSES: tuple[str, ...] = ("open", "acknowledged", "false_positive", "resolved")
MAX_PAGE_SIZE = 200
DEFAULT_PAGE_SIZE = 50
MAX_NOTE_CHARS = 2000
_BUSY_TIMEOUT_SECONDS = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alerts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL,
    occurred_at TEXT,
    severity TEXT NOT NULL CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    confidence INTEGER NOT NULL CHECK (confidence BETWEEN 0 AND 100),
    category TEXT NOT NULL,
    source TEXT NOT NULL,
    asset TEXT,
    title TEXT NOT NULL,
    evidence TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open'
        CHECK (status IN ('open', 'acknowledged', 'false_positive', 'resolved')),
    demo INTEGER NOT NULL DEFAULT 0 CHECK (demo IN (0, 1)),
    fingerprint TEXT
);
CREATE INDEX IF NOT EXISTS alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS alerts_severity ON alerts (severity);
CREATE TABLE IF NOT EXISTS alert_notes (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id INTEGER NOT NULL REFERENCES alerts (id),
    created_at TEXT NOT NULL,
    text TEXT NOT NULL CHECK (length(text) BETWEEN 1 AND 2000)
);
CREATE INDEX IF NOT EXISTS alert_notes_alert ON alert_notes (alert_id);
CREATE TRIGGER IF NOT EXISTS alert_notes_no_update BEFORE UPDATE ON alert_notes
BEGIN SELECT RAISE(ABORT, 'notes are append-only'); END;
CREATE TRIGGER IF NOT EXISTS alert_notes_no_delete BEFORE DELETE ON alert_notes
BEGIN SELECT RAISE(ABORT, 'notes are append-only'); END;
"""

# Created after the column is guaranteed to exist (databases from before de-duplication lack it).
# Rows without a fingerprint (older duplicates that lost the backfill) are not constrained.
_FINGERPRINT_INDEX = (
    "CREATE UNIQUE INDEX IF NOT EXISTS alerts_fingerprint ON alerts (fingerprint)"
    " WHERE fingerprint IS NOT NULL"
)

_SEVERITY_RANK_SQL = (
    "CASE severity "
    + " ".join(f"WHEN '{name}' THEN {rank}" for rank, name in enumerate(SEVERITY_ORDER))
    + " END"
)
_COLUMNS = (
    "id, created_at, occurred_at, severity, confidence, category, source, asset, title, "
    "evidence, status, demo"
)


@dataclass(frozen=True)
class StoredNote:
    id: int
    created_at: datetime
    text: str


@dataclass(frozen=True)
class StoredAlert:
    id: int
    created_at: datetime
    occurred_at: datetime | None
    severity: AlertSeverity
    confidence: int
    category: AlertCategory
    source: str
    asset: str | None
    title: str
    evidence: tuple[Evidence, ...]
    status: str
    # True when the alert came from labelled demo input, never from a real upload.
    demo: bool
    # Analyst notes, oldest first; there is no author until accounts exist.
    notes: tuple[StoredNote, ...] = ()


@dataclass(frozen=True)
class AlertFilter:
    severities: Sequence[AlertSeverity] = ()
    categories: Sequence[AlertCategory] = ()
    statuses: Sequence[str] = ()
    source: str | None = None
    created_from: datetime | None = None
    created_to: datetime | None = None
    min_confidence: int | None = None
    demo: bool | None = None
    newest_first: bool = True  # False sorts by severity, then newest
    limit: int = DEFAULT_PAGE_SIZE
    offset: int = 0


def _iso(value: datetime) -> str:
    """UTC with a fixed layout, so text comparison in SQL matches time order."""
    return value.astimezone(UTC).isoformat(timespec="microseconds")


def _without_intel_matches(evidence: str) -> str:
    """Evidence JSON minus threat_intel_match items; unchanged text when there are none."""
    if EvidenceKind.THREAT_INTEL_MATCH.value not in evidence:
        return evidence
    items = json.loads(evidence)
    kept = [item for item in items if item.get("kind") != EvidenceKind.THREAT_INTEL_MATCH.value]
    return json.dumps(kept)


def _fingerprint(
    *,
    category: str,
    source: str,
    asset: str | None,
    title: str,
    occurred_at: str | None,
    severity: str,
    confidence: int,
    evidence: str,
    demo: bool,
) -> str:
    """Hash of everything that makes an alert what it is, so a repeat can be recognised.

    Detection time is left out on purpose. Demo and real copies stay separate, and a
    changed score, severity or evidence (for example after retraining) is a new alert.
    Threat-intelligence matches are left out too: they record when the cache was last
    refreshed, which would otherwise make a repeated upload look like a new finding.
    """
    evidence = _without_intel_matches(evidence)
    payload = json.dumps(
        [category, source, asset, title, occurred_at, severity, confidence, evidence, demo]
    )
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class IngestOutcome:
    """The stored alert for every candidate, and how many were already on file."""

    alerts: list["StoredAlert"]
    duplicates: int


def _evidence_json(evidence: Sequence[Evidence]) -> str:
    return json.dumps(
        [
            {
                "kind": item.kind.value,
                "name": item.name,
                "description": item.description,
                "value": item.value,
                "examples": list(item.examples),
            }
            for item in evidence
        ]
    )


def _evidence_from_json(text: str) -> tuple[Evidence, ...]:
    return tuple(
        Evidence(
            kind=EvidenceKind(item["kind"]),
            name=item["name"],
            description=item["description"],
            value=item["value"],
            examples=tuple(item["examples"]),
        )
        for item in json.loads(text)
    )


def _alert_from_row(row: sqlite3.Row, notes: Sequence[StoredNote] = ()) -> StoredAlert:
    occurred = row["occurred_at"]
    return StoredAlert(
        id=row["id"],
        created_at=datetime.fromisoformat(row["created_at"]),
        occurred_at=datetime.fromisoformat(occurred) if occurred else None,
        severity=AlertSeverity(row["severity"]),
        confidence=row["confidence"],
        category=AlertCategory(row["category"]),
        source=row["source"],
        asset=row["asset"],
        title=row["title"],
        evidence=_evidence_from_json(row["evidence"]),
        status=row["status"],
        demo=bool(row["demo"]),
        notes=tuple(notes),
    )


def _notes_by_alert(
    connection: sqlite3.Connection, alert_ids: Sequence[int]
) -> dict[int, list[StoredNote]]:
    """Notes for several alerts in one query, oldest first."""
    grouped: dict[int, list[StoredNote]] = {alert_id: [] for alert_id in alert_ids}
    if not alert_ids:
        return grouped
    rows = connection.execute(
        "SELECT id, alert_id, created_at, text FROM alert_notes"
        f" WHERE alert_id IN ({', '.join('?' * len(alert_ids))}) ORDER BY id",
        list(alert_ids),
    ).fetchall()
    for row in rows:
        grouped[row["alert_id"]].append(
            StoredNote(row["id"], datetime.fromisoformat(row["created_at"]), row["text"])
        )
    return grouped


def _where(criteria: AlertFilter) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    for column, values in (
        ("severity", [v.value for v in criteria.severities]),
        ("category", [v.value for v in criteria.categories]),
        ("status", list(criteria.statuses)),
    ):
        if values:
            clauses.append(f"{column} IN ({', '.join('?' * len(values))})")
            params.extend(values)
    simple = (
        ("source = ?", criteria.source),
        ("created_at >= ?", _iso(criteria.created_from) if criteria.created_from else None),
        ("created_at <= ?", _iso(criteria.created_to) if criteria.created_to else None),
        ("confidence >= ?", criteria.min_confidence),
        ("demo = ?", None if criteria.demo is None else int(criteria.demo)),
    )
    for clause, value in simple:
        if value is not None:
            clauses.append(clause)
            params.append(value)
    return (" WHERE " + " AND ".join(clauses)) if clauses else "", params


class AlertStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        if path.parent != Path():
            path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)
            self._add_fingerprints(connection)

    @staticmethod
    def _add_fingerprints(connection: sqlite3.Connection) -> None:
        """Upgrades a database made before de-duplication; a no-op on current ones.

        Existing alerts are fingerprinted oldest first, so the earliest copy of a
        repeated alert is the one later repeats match. Older duplicates are kept.
        """
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(alerts)")}
        if "fingerprint" not in columns:
            connection.execute("ALTER TABLE alerts ADD COLUMN fingerprint TEXT")
        connection.execute(_FINGERPRINT_INDEX)
        pending = connection.execute(
            "SELECT id, category, source, asset, title, occurred_at, severity, confidence,"
            " evidence, demo FROM alerts WHERE fingerprint IS NULL ORDER BY id"
        ).fetchall()
        for row in pending:
            fingerprint = _fingerprint(
                category=row["category"],
                source=row["source"],
                asset=row["asset"],
                title=row["title"],
                occurred_at=row["occurred_at"],
                severity=row["severity"],
                confidence=row["confidence"],
                evidence=row["evidence"],
                demo=bool(row["demo"]),
            )
            connection.execute(
                "UPDATE alerts SET fingerprint = ? WHERE id = ? AND NOT EXISTS"
                " (SELECT 1 FROM alerts WHERE fingerprint = ?)",
                (fingerprint, row["id"], fingerprint),
            )

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=_BUSY_TIMEOUT_SECONDS)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        try:
            with connection:  # commits on success, rolls back on error
                yield connection
        finally:
            connection.close()

    def add_many(
        self, candidates: Sequence[AlertCandidate], *, demo: bool, now: datetime | None = None
    ) -> list[StoredAlert]:
        """Stores candidates, skipping repeats; returns the stored alert for each."""
        return self.ingest(candidates, demo=demo, now=now).alerts

    def ingest(
        self, candidates: Sequence[AlertCandidate], *, demo: bool, now: datetime | None = None
    ) -> IngestOutcome:
        """Stores every new candidate in one transaction, stamped with the detection time.

        A candidate whose content matches an alert already stored (same fingerprint) is
        not stored again: the existing alert, with its status and notes, is returned
        and counted as a duplicate.
        """
        created = _iso(now or datetime.now(UTC))
        duplicates = 0
        ids: list[int] = []
        with self._connect() as connection:
            for candidate in candidates:
                occurred = _iso(candidate.occurred_at) if candidate.occurred_at else None
                evidence = _evidence_json(candidate.evidence)
                fingerprint = _fingerprint(
                    category=candidate.category.value,
                    source=candidate.source,
                    asset=candidate.asset,
                    title=candidate.title,
                    occurred_at=occurred,
                    severity=candidate.severity.value,
                    confidence=candidate.confidence,
                    evidence=evidence,
                    demo=demo,
                )
                existing = connection.execute(
                    "SELECT id FROM alerts WHERE fingerprint = ?", (fingerprint,)
                ).fetchone()
                if existing is not None:
                    duplicates += 1
                    ids.append(existing["id"])
                    continue
                cursor = connection.execute(
                    "INSERT INTO alerts (created_at, occurred_at, severity, confidence,"
                    " category, source, asset, title, evidence, demo, fingerprint)"
                    " VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        created,
                        occurred,
                        candidate.severity.value,
                        candidate.confidence,
                        candidate.category.value,
                        candidate.source,
                        candidate.asset,
                        candidate.title,
                        evidence,
                        int(demo),
                        fingerprint,
                    ),
                )
                if cursor.lastrowid is None:
                    raise RuntimeError("the database did not return an id for a new alert")
                ids.append(cursor.lastrowid)
            alerts = [
                alert
                for alert in (self._load(connection, alert_id) for alert_id in ids)
                if alert is not None
            ]
        return IngestOutcome(alerts=alerts, duplicates=duplicates)

    def get(self, alert_id: int) -> StoredAlert | None:
        with self._connect() as connection:
            return self._load(connection, alert_id)

    @staticmethod
    def _load(connection: sqlite3.Connection, alert_id: int) -> StoredAlert | None:
        row = connection.execute(
            f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)
        ).fetchone()
        if row is None:
            return None
        return _alert_from_row(row, _notes_by_alert(connection, [alert_id])[alert_id])

    def update(
        self,
        alert_id: int,
        *,
        status: str | None = None,
        note: str | None = None,
        now: datetime | None = None,
    ) -> StoredAlert | None:
        """Sets the status and/or appends a note in one transaction.

        Any status can follow any other, so a mistaken change can be undone. Returns
        None when the alert does not exist; raises ValueError for an unknown status
        or a note that is empty or too long.
        """
        if status is not None and status not in STATUSES:
            raise ValueError(f"status must be one of {', '.join(STATUSES)}")
        text = note.strip() if note is not None else None
        if text is not None and not 1 <= len(text) <= MAX_NOTE_CHARS:
            raise ValueError(f"a note must be 1 to {MAX_NOTE_CHARS} characters")
        stamp = _iso(now or datetime.now(UTC))
        with self._connect() as connection:
            if (
                connection.execute("SELECT 1 FROM alerts WHERE id = ?", (alert_id,)).fetchone()
                is None
            ):
                return None
            if status is not None:
                connection.execute("UPDATE alerts SET status = ? WHERE id = ?", (status, alert_id))
            if text is not None:
                connection.execute(
                    "INSERT INTO alert_notes (alert_id, created_at, text) VALUES (?, ?, ?)",
                    (alert_id, stamp, text),
                )
            return self._load(connection, alert_id)

    def query(self, criteria: AlertFilter) -> tuple[list[StoredAlert], int]:
        """One page of matching alerts and the total number matching."""
        where, params = _where(criteria)
        order = (
            "created_at DESC, id DESC"
            if criteria.newest_first
            else f"{_SEVERITY_RANK_SQL} DESC, created_at DESC, id DESC"
        )
        limit = max(1, min(criteria.limit, MAX_PAGE_SIZE))
        with self._connect() as connection:
            total = connection.execute(f"SELECT COUNT(*) FROM alerts{where}", params).fetchone()[0]
            rows = connection.execute(
                f"SELECT {_COLUMNS} FROM alerts{where} ORDER BY {order} LIMIT ? OFFSET ?",
                [*params, limit, max(0, criteria.offset)],
            ).fetchall()
            notes = _notes_by_alert(connection, [row["id"] for row in rows])
        return [_alert_from_row(row, notes[row["id"]]) for row in rows], total
