"""Produces, validates and caches the analyst's report for an alert.

The service picks the hosted provider when a key is configured and the built-in one
otherwise. A hosted answer is used only if it passes the grounding checks; on any
failure (no budget left, rate limit, network, bad JSON, uncited claims) the built-in
explanation is shown instead, with the reason, so the analyst never sees a stub.
The result is cached per alert, keyed by the provider and the alert's evidence hash,
so viewing an alert again costs nothing and a changed alert or a new key regenerates.
The analyst is advisory: nothing here writes to an alert.
"""

import json
import logging
import sqlite3
import threading
import time
from collections import deque
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Literal, Protocol

from app.analyst.deterministic import DeterministicAnalyst
from app.analyst.groq import (
    GroqAnalyst,
    ProviderError,
    RateLimitedError,
    Transport,
    urllib_transport,
)
from app.analyst.grounding import (
    AlertView,
    AnalysisContent,
    GroundingError,
    build_view,
    validate_content,
)
from app.core.config import Settings
from app.storage.alerts import StoredAlert

logger = logging.getLogger("sentinelx.analyst")

ADVISORY = "Advisory only: this explanation never changes an alert's status or severity."
# A fallback shown because the hosted provider failed is retried after this long.
FALLBACK_RETRY = timedelta(minutes=10)
_BUSY_TIMEOUT_SECONDS = 10

_SCHEMA = """
CREATE TABLE IF NOT EXISTS alert_analyses (
    alert_id INTEGER PRIMARY KEY,
    provider TEXT NOT NULL,
    evidence_hash TEXT NOT NULL,
    report TEXT NOT NULL,
    created_at TEXT NOT NULL,
    retry_after TEXT
);
"""


class AnalystReport(AnalysisContent):
    mode: Literal["llm", "deterministic"]
    provider: str
    model: str | None
    generated_at: datetime
    evidence_hash: str
    # Why the built-in explanation is shown although a hosted provider is configured.
    fallback_reason: str | None = None
    advisory: str = ADVISORY
    cached: bool = False


class Provider(Protocol):
    id: str
    model: str | None

    def generate(self, view: AlertView) -> AnalysisContent: ...


class SlidingWindowLimiter:
    """At most `limit` events in any `window` seconds (in memory, per process)."""

    def __init__(self, limit: int, window: float, clock: Callable[[], float] = time.monotonic):
        self._limit = limit
        self._window = window
        self._clock = clock
        self._events: deque[float] = deque()

    def allow(self) -> bool:
        now = self._clock()
        while self._events and now - self._events[0] >= self._window:
            self._events.popleft()
        if len(self._events) >= self._limit:
            return False
        self._events.append(now)
        return True


class AnalysisCache:
    def __init__(self, path: Path) -> None:
        self._path = path
        path.parent.mkdir(parents=True, exist_ok=True)
        with self._connect() as connection:
            connection.executescript(_SCHEMA)

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self._path, timeout=_BUSY_TIMEOUT_SECONDS)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    def get(
        self, alert_id: int, provider: str, evidence_hash: str, now: datetime
    ) -> AnalystReport | None:
        with self._connect() as connection:
            row = connection.execute(
                "SELECT provider, evidence_hash, report, retry_after FROM alert_analyses"
                " WHERE alert_id = ?",
                (alert_id,),
            ).fetchone()
        if row is None or (row[0], row[1]) != (provider, evidence_hash):
            return None
        if row[3] is not None and now >= datetime.fromisoformat(row[3]):
            return None
        return AnalystReport.model_validate(json.loads(row[2])).model_copy(update={"cached": True})

    def put(
        self, alert_id: int, provider: str, report: AnalystReport, retry_after: datetime | None
    ) -> None:
        with self._connect() as connection:
            connection.execute(
                "INSERT INTO alert_analyses (alert_id, provider, evidence_hash, report,"
                " created_at, retry_after) VALUES (?, ?, ?, ?, ?, ?)"
                " ON CONFLICT(alert_id) DO UPDATE SET provider = excluded.provider,"
                " evidence_hash = excluded.evidence_hash, report = excluded.report,"
                " created_at = excluded.created_at, retry_after = excluded.retry_after",
                (
                    alert_id,
                    provider,
                    report.evidence_hash,
                    report.model_dump_json(),
                    report.generated_at.isoformat(),
                    retry_after.isoformat() if retry_after else None,
                ),
            )


class AnalystService:
    def __init__(
        self,
        settings: Settings,
        *,
        transport: Transport = urllib_transport,
        clock: Callable[[], float] = time.monotonic,
        now: Callable[[], datetime] = lambda: datetime.now(UTC),
    ) -> None:
        self._now = now
        self._cache = AnalysisCache(settings.sqlite_path)
        self._builtin = DeterministicAnalyst()
        self._hosted: GroqAnalyst | None = None
        if settings.llm_configured and settings.groq_api_key is not None:
            self._hosted = GroqAnalyst(
                settings.groq_api_key.get_secret_value(), settings.groq_model, transport
            )
        self._per_minute = SlidingWindowLimiter(settings.analyst_calls_per_minute, 60, clock)
        self._per_day = SlidingWindowLimiter(settings.analyst_calls_per_day, 86_400, clock)
        self._lock = threading.Lock()

    @property
    def requested_provider(self) -> str:
        return (self._hosted or self._builtin).id

    def report_for(self, alert: StoredAlert, *, refresh: bool = False) -> AnalystReport:
        """The cached report if still valid, else a freshly generated (and cached) one."""
        view = build_view(alert)
        evidence_hash = view.content_hash()
        if not refresh:
            cached = self._cache.get(alert.id, self.requested_provider, evidence_hash, self._now())
            if cached is not None:
                return cached
        with self._lock:
            if not refresh:  # another request may have filled the cache while we waited
                cached = self._cache.get(
                    alert.id, self.requested_provider, evidence_hash, self._now()
                )
                if cached is not None:
                    return cached
            report = self._generate(view, evidence_hash)
        retry = self._now() + FALLBACK_RETRY if report.fallback_reason else None
        self._cache.put(alert.id, self.requested_provider, report, retry)
        return report

    def _generate(self, view: AlertView, evidence_hash: str) -> AnalystReport:
        reason = None
        if self._hosted is not None:
            try:
                return self._from_hosted(self._hosted, view, evidence_hash)
            except RateLimitedError:
                reason = "The hosted analyst is rate limited right now."
            except ProviderError as error:
                logger.warning("Hosted analyst failed: %s", error)
                reason = "The hosted analyst could not be used."
            except GroundingError as error:
                logger.warning("Hosted analyst output rejected: %s", error)
                reason = (
                    "The hosted analyst's answer cited something not in the alert, "
                    "so it was discarded."
                )
        content = self._builtin.generate(view)
        validate_content(content, view)  # the built-in text obeys the same rules
        return self._report(content, self._builtin, "deterministic", evidence_hash, reason)

    def _from_hosted(
        self, provider: GroqAnalyst, view: AlertView, evidence_hash: str
    ) -> AnalystReport:
        if not (self._per_minute.allow() and self._per_day.allow()):
            raise RateLimitedError("the local call budget is spent")
        content = provider.generate(view)
        validate_content(content, view, hosted=True)
        return self._report(content, provider, "llm", evidence_hash, None)

    def _report(
        self,
        content: AnalysisContent,
        provider: Provider,
        mode: Literal["llm", "deterministic"],
        evidence_hash: str,
        fallback_reason: str | None,
    ) -> AnalystReport:
        shown = (
            fallback_reason + " Showing the built-in explanation instead."
            if fallback_reason
            else None
        )
        return AnalystReport(
            **content.model_dump(),
            mode=mode,
            provider=provider.id,
            model=provider.model,
            generated_at=self._now(),
            evidence_hash=evidence_hash,
            fallback_reason=shown,
        )
