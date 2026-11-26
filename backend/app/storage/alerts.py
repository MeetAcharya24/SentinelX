"""SQLite persistence for alerts.

Each call opens its own short-lived connection, so the store is safe to use from
the API's worker threads. Alerts are only added here; changing status and adding
notes belong to the investigation workflow.
"""

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
    demo INTEGER NOT NULL DEFAULT 0 CHECK (demo IN (0, 1))
);
CREATE INDEX IF NOT EXISTS alerts_created_at ON alerts (created_at);
CREATE INDEX IF NOT EXISTS alerts_severity ON alerts (severity);
"""

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


def _alert_from_row(row: sqlite3.Row) -> StoredAlert:
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
    )


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

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=_BUSY_TIMEOUT_SECONDS)
        connection.row_factory = sqlite3.Row
        try:
            with connection:  # commits on success, rolls back on error
                yield connection
        finally:
            connection.close()

    def add_many(
        self, candidates: Sequence[AlertCandidate], *, demo: bool, now: datetime | None = None
    ) -> list[StoredAlert]:
        """Stores every candidate in one transaction, stamped with the detection time."""
        created = _iso(now or datetime.now(UTC))
        with self._connect() as connection:
            ids = [
                connection.execute(
                    "INSERT INTO alerts (created_at, occurred_at, severity, confidence, category,"
                    " source, asset, title, evidence, demo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (
                        created,
                        _iso(candidate.occurred_at) if candidate.occurred_at else None,
                        candidate.severity.value,
                        candidate.confidence,
                        candidate.category.value,
                        candidate.source,
                        candidate.asset,
                        candidate.title,
                        _evidence_json(candidate.evidence),
                        int(demo),
                    ),
                ).lastrowid
                for candidate in candidates
            ]
            rows = [
                connection.execute(
                    f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)
                ).fetchone()
                for alert_id in ids
            ]
        return [_alert_from_row(row) for row in rows]

    def get(self, alert_id: int) -> StoredAlert | None:
        with self._connect() as connection:
            row = connection.execute(
                f"SELECT {_COLUMNS} FROM alerts WHERE id = ?", (alert_id,)
            ).fetchone()
        return _alert_from_row(row) if row else None

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
        return [_alert_from_row(row) for row in rows], total
