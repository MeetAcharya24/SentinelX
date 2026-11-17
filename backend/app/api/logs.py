"""Security log upload: validation against the published log schema."""

from collections import Counter
from dataclasses import asdict
from datetime import datetime

from fastapi import APIRouter, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel

from app.core.errors import AppError
from app.core.responses import Envelope, ok
from app.ingestion.logs import STATUSES, LogFileError, LogFormat, ParsedLog, parse_log

router = APIRouter(prefix="/api/v1/logs", tags=["logs"])

MAX_LISTED_EVENT_TYPES = 20
_FORMAT_BY_MEDIA_TYPE = {"text/csv": LogFormat.CSV, "application/json": LogFormat.JSON}
_REQUEST_BODY = {
    "required": True,
    "content": {
        "text/csv": {"schema": {"type": "string"}},
        "application/json": {"schema": {"type": "array", "items": {"type": "object"}}},
    },
}


class EventTypeCount(BaseModel):
    event_type: str
    count: int


class LogSummary(BaseModel):
    format: LogFormat
    event_count: int
    first_timestamp: datetime
    last_timestamp: datetime
    # Most frequent first; at most MAX_LISTED_EVENT_TYPES entries.
    event_types: list[EventTypeCount]
    distinct_event_types: int
    status_counts: dict[str, int]
    distinct_source_ips: int
    distinct_users: int
    # Fields outside the schema; they are not read.
    ignored_fields: list[str]


def _log_format(request: Request) -> LogFormat:
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    log_format = _FORMAT_BY_MEDIA_TYPE.get(media_type)
    if log_format is None:
        raise AppError(
            "unsupported_log_type",
            "Send the log as text/csv or application/json.",
            status_code=415,
        )
    return log_format


def _summarise(parsed: ParsedLog) -> LogSummary:
    events = parsed.events
    type_counts = Counter(event.event_type for event in events)
    statuses = Counter(event.status for event in events)
    # Ties are listed alphabetically so the same file always gives the same summary.
    listed = sorted(type_counts.items(), key=lambda item: (-item[1], item[0]))
    return LogSummary(
        format=parsed.format,
        event_count=len(events),
        first_timestamp=min(event.timestamp for event in events),
        last_timestamp=max(event.timestamp for event in events),
        event_types=[
            EventTypeCount(event_type=name, count=count)
            for name, count in listed[:MAX_LISTED_EVENT_TYPES]
        ],
        distinct_event_types=len(type_counts),
        status_counts={status: statuses[status] for status in STATUSES},
        distinct_source_ips=len({event.source_ip for event in events}),
        distinct_users=len({event.user for event in events if event.user is not None}),
        ignored_fields=list(parsed.ignored_fields),
    )


@router.post("/validate", openapi_extra={"requestBody": _REQUEST_BODY})
async def validate_log(request: Request) -> Envelope[LogSummary]:
    """Checks a log you are authorised to inspect against the log schema.

    The body is the file itself. Nothing is stored: the response summarises
    what was read, or lists what must be fixed.
    """
    log_format = _log_format(request)
    content = await request.body()
    try:
        parsed = await run_in_threadpool(parse_log, content, log_format)
    except LogFileError as error:
        details = [asdict(problem) for problem in error.problems] or None
        raise AppError(
            "invalid_log_file", error.message, status_code=422, details=details
        ) from error
    return ok(_summarise(parsed))
