"""Refresh job: pulls both feeds into the local cache.

Run it from a scheduler, for example every six hours:

    python -m app.intel.refresh

The schedule is enforced here, not only documented: a feed refreshed within the last
six hours is skipped, and a feed whose last attempt failed is not retried for an hour,
so a job started too often (or by mistake in a loop) does not hammer abuse.ch.
`--force` skips both checks for a deliberate manual run. A failure in one feed never
touches the other feed or the indicators already cached.
"""

import argparse
import logging
import sys
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from enum import StrEnum

from app.core.config import Settings, get_settings
from app.core.logging import configure_logging
from app.intel.feeds import (
    FEODO_SOURCE,
    THREATFOX_SOURCE,
    FeedError,
    Fetcher,
    fetch_feodo,
    fetch_threatfox,
    http_fetch,
)
from app.intel.store import IntelStore

logger = logging.getLogger("sentinelx.intel")

MIN_REFRESH_INTERVAL = timedelta(hours=6)
RETRY_AFTER_FAILURE = timedelta(hours=1)
# ThreatFox stops serving an indicator six months after it was first seen.
THREATFOX_RETENTION = timedelta(days=180)


class Outcome(StrEnum):
    REFRESHED = "refreshed"
    FRESH = "skipped: refreshed recently"
    BACKOFF = "skipped: last attempt failed recently"
    NO_KEY = "skipped: THREATFOX_API_KEY is not set"
    FAILED = "failed"


@dataclass(frozen=True)
class FeedResult:
    source: str
    outcome: Outcome
    ioc_count: int | None = None
    detail: str | None = None


def _skip_reason(store: IntelStore, source: str, now: datetime) -> Outcome | None:
    state = store.feed_state(source)
    if state is None:
        return None
    if state.last_success_at and now - state.last_success_at < MIN_REFRESH_INTERVAL:
        return Outcome.FRESH
    failed_last = state.last_error is not None
    if failed_last and now - state.last_attempt_at < RETRY_AFTER_FAILURE:
        return Outcome.BACKOFF
    return None


def _refresh_feed(
    store: IntelStore, source: str, pull: Callable[[], int], now: datetime
) -> FeedResult:
    try:
        count = pull()
    except FeedError as error:
        logger.warning("Refresh of %s failed: %s", source, error)
        store.record_failure(source, str(error), now=now)
        return FeedResult(source, Outcome.FAILED, detail=str(error))
    return FeedResult(source, Outcome.REFRESHED, ioc_count=count)


def refresh_all(
    store: IntelStore,
    *,
    threatfox_key: str | None,
    fetch: Fetcher = http_fetch,
    now: datetime | None = None,
    force: bool = False,
) -> list[FeedResult]:
    """Refreshes each feed that is due; returns what happened to each."""
    moment = now or datetime.now(UTC)
    results: list[FeedResult] = []

    skip = None if force else _skip_reason(store, FEODO_SOURCE, moment)
    if skip:
        results.append(FeedResult(FEODO_SOURCE, skip))
    else:
        results.append(
            _refresh_feed(
                store,
                FEODO_SOURCE,
                lambda: store.replace_feed(FEODO_SOURCE, fetch_feodo(fetch), now=moment),
                moment,
            )
        )

    if not threatfox_key:
        results.append(FeedResult(THREATFOX_SOURCE, Outcome.NO_KEY))
        return results
    skip = None if force else _skip_reason(store, THREATFOX_SOURCE, moment)
    if skip:
        results.append(FeedResult(THREATFOX_SOURCE, skip))
    else:
        results.append(
            _refresh_feed(
                store,
                THREATFOX_SOURCE,
                lambda: store.merge_feed(
                    THREATFOX_SOURCE,
                    fetch_threatfox(fetch, threatfox_key),
                    now=moment,
                    keep_since=moment - THREATFOX_RETENTION,
                ),
                moment,
            )
        )
    return results


def run(settings: Settings, *, force: bool = False, fetch: Fetcher = http_fetch) -> int:
    """Refreshes using the configured database and key; the exit code is 1 if a feed failed."""
    store = IntelStore(settings.sqlite_path)
    key = settings.threatfox_api_key.get_secret_value() if settings.threatfox_api_key else None
    results = refresh_all(store, threatfox_key=key, fetch=fetch, force=force)
    for result in results:
        count = f" ({result.ioc_count} cached)" if result.ioc_count is not None else ""
        detail = f": {result.detail}" if result.detail else ""
        print(f"{result.source}: {result.outcome.value}{count}{detail}")
    return 1 if any(result.outcome is Outcome.FAILED for result in results) else 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m app.intel.refresh",
        description="Refresh the local threat-intelligence cache from abuse.ch.",
    )
    parser.add_argument(
        "--force", action="store_true", help="ignore the refresh schedule (manual run only)"
    )
    arguments = parser.parse_args(argv)
    settings = get_settings()
    configure_logging(settings.log_level)
    return run(settings, force=arguments.force)


if __name__ == "__main__":
    sys.exit(main())
