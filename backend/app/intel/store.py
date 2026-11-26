"""SQLite cache of indicators of compromise (IOCs) pulled from the public feeds.

Lives in the same database file as the alerts. `threat_intel_iocs` holds one row per
(feed, type, value); `threat_intel_feeds` records when each feed was last attempted
and last refreshed, so the job can respect its schedule and alerts can say how old
the data they matched is. Each call opens its own short-lived connection.
"""

import sqlite3
from collections.abc import Iterable, Iterator, Sequence
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

_BUSY_TIMEOUT_SECONDS = 10
_QUERY_CHUNK = 500

_SCHEMA = """
CREATE TABLE IF NOT EXISTS threat_intel_iocs (
    source TEXT NOT NULL,
    ioc_type TEXT NOT NULL CHECK (ioc_type IN ('ip', 'domain', 'url')),
    value TEXT NOT NULL,
    first_seen TEXT,
    fetched_at TEXT NOT NULL,
    malware TEXT,
    confidence INTEGER CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
    PRIMARY KEY (source, ioc_type, value)
) WITHOUT ROWID;
CREATE INDEX IF NOT EXISTS threat_intel_iocs_lookup ON threat_intel_iocs (ioc_type, value);
CREATE TABLE IF NOT EXISTS threat_intel_feeds (
    source TEXT PRIMARY KEY,
    last_attempt_at TEXT NOT NULL,
    last_success_at TEXT,
    last_error TEXT,
    ioc_count INTEGER NOT NULL DEFAULT 0
);
"""


@dataclass(frozen=True)
class Ioc:
    ioc_type: str
    value: str
    first_seen: datetime | None = None
    malware: str | None = None
    confidence: int | None = None


@dataclass(frozen=True)
class CachedIoc:
    source: str
    ioc_type: str
    value: str
    first_seen: datetime | None
    fetched_at: datetime
    malware: str | None
    confidence: int | None
    # When the whole feed was last refreshed successfully.
    feed_refreshed_at: datetime | None


@dataclass(frozen=True)
class FeedState:
    source: str
    last_attempt_at: datetime
    last_success_at: datetime | None
    last_error: str | None
    ioc_count: int


def _iso(value: datetime) -> str:
    return value.astimezone(UTC).isoformat(timespec="seconds")


def _parse(value: str | None) -> datetime | None:
    return datetime.fromisoformat(value) if value else None


class IntelStore:
    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        """One transaction: commit on success, roll back on error, always close."""
        connection = sqlite3.connect(self._path, timeout=_BUSY_TIMEOUT_SECONDS)
        connection.row_factory = sqlite3.Row
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def feed_state(self, source: str) -> FeedState | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT * FROM threat_intel_feeds WHERE source = ?", (source,)
            ).fetchone()
        if row is None:
            return None
        return FeedState(
            source=row["source"],
            last_attempt_at=datetime.fromisoformat(row["last_attempt_at"]),
            last_success_at=_parse(row["last_success_at"]),
            last_error=row["last_error"],
            ioc_count=row["ioc_count"],
        )

    def record_failure(self, source: str, error: str, *, now: datetime) -> None:
        """Notes a failed attempt; cached indicators and the last success stay as they were."""
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO threat_intel_feeds (source, last_attempt_at, last_error)"
                " VALUES (?, ?, ?) ON CONFLICT(source) DO UPDATE SET"
                " last_attempt_at = excluded.last_attempt_at, last_error = excluded.last_error",
                (source, _iso(now), error),
            )

    def replace_feed(self, source: str, iocs: Iterable[Ioc], *, now: datetime) -> int:
        """Swaps the feed's cached indicators for this list (an empty list is valid)."""
        with self._connect() as connection:
            connection.execute("DELETE FROM threat_intel_iocs WHERE source = ?", (source,))
            count = self._insert(connection, source, iocs, now)
            self._mark_success(connection, source, now, count)
        return count

    def merge_feed(
        self, source: str, iocs: Iterable[Ioc], *, now: datetime, keep_since: datetime
    ) -> int:
        """Adds or updates indicators, then drops those first seen before `keep_since`.

        Returns how many indicators the feed has cached afterwards.
        """
        with self._connect() as connection:
            self._insert(connection, source, iocs, now)
            connection.execute(
                "DELETE FROM threat_intel_iocs WHERE source = ?"
                " AND first_seen IS NOT NULL AND first_seen < ?",
                (source, _iso(keep_since)),
            )
            total = connection.execute(
                "SELECT COUNT(*) FROM threat_intel_iocs WHERE source = ?", (source,)
            ).fetchone()[0]
            self._mark_success(connection, source, now, total)
        return int(total)

    @staticmethod
    def _insert(
        connection: sqlite3.Connection, source: str, iocs: Iterable[Ioc], now: datetime
    ) -> int:
        rows = [
            (
                source,
                ioc.ioc_type,
                ioc.value,
                _iso(ioc.first_seen) if ioc.first_seen else None,
                _iso(now),
                ioc.malware,
                ioc.confidence,
            )
            for ioc in iocs
        ]
        connection.executemany(
            "INSERT INTO threat_intel_iocs"
            " (source, ioc_type, value, first_seen, fetched_at, malware, confidence)"
            " VALUES (?, ?, ?, ?, ?, ?, ?) ON CONFLICT(source, ioc_type, value) DO UPDATE SET"
            " fetched_at = excluded.fetched_at, malware = excluded.malware,"
            " confidence = excluded.confidence,"
            " first_seen = COALESCE(threat_intel_iocs.first_seen, excluded.first_seen)",
            rows,
        )
        return len(rows)

    @staticmethod
    def _mark_success(
        connection: sqlite3.Connection, source: str, now: datetime, count: int
    ) -> None:
        connection.execute(
            "INSERT INTO threat_intel_feeds"
            " (source, last_attempt_at, last_success_at, last_error, ioc_count)"
            " VALUES (?, ?, ?, NULL, ?) ON CONFLICT(source) DO UPDATE SET"
            " last_attempt_at = excluded.last_attempt_at,"
            " last_success_at = excluded.last_success_at, last_error = NULL,"
            " ioc_count = excluded.ioc_count",
            (source, _iso(now), _iso(now), count),
        )

    def find(self, ioc_type: str, values: Sequence[str]) -> list[CachedIoc]:
        """Cached indicators of one type whose value is exactly one of `values`."""
        unique = list(dict.fromkeys(values))
        found: list[CachedIoc] = []
        with self._connect() as connection:
            for start in range(0, len(unique), _QUERY_CHUNK):
                chunk = unique[start : start + _QUERY_CHUNK]
                marks = ",".join("?" * len(chunk))
                rows = connection.execute(
                    "SELECT i.*, f.last_success_at AS feed_refreshed_at"  # noqa: S608
                    " FROM threat_intel_iocs i"
                    " LEFT JOIN threat_intel_feeds f ON f.source = i.source"
                    f" WHERE i.ioc_type = ? AND i.value IN ({marks})"
                    " ORDER BY i.source, i.value",
                    (ioc_type, *chunk),
                ).fetchall()
                found.extend(
                    CachedIoc(
                        source=row["source"],
                        ioc_type=row["ioc_type"],
                        value=row["value"],
                        first_seen=_parse(row["first_seen"]),
                        fetched_at=datetime.fromisoformat(row["fetched_at"]),
                        malware=row["malware"],
                        confidence=row["confidence"],
                        feed_refreshed_at=_parse(row["feed_refreshed_at"]),
                    )
                    for row in rows
                )
        return found
