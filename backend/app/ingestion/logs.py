"""Parsing and validating uploaded security logs (CSV or JSON).

A file is accepted only as a whole: one invalid row rejects it, with the
problems listed. Problem messages never repeat submitted values.
"""

import csv
import io
import json
from collections.abc import Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from ipaddress import ip_address

REQUIRED_FIELDS: tuple[str, ...] = ("timestamp", "event_type", "source_ip", "status")
OPTIONAL_FIELDS: tuple[str, ...] = ("user", "asset_id")
LOG_FIELDS: tuple[str, ...] = REQUIRED_FIELDS + OPTIONAL_FIELDS
STATUSES: tuple[str, ...] = ("success", "fail")

MAX_EVENT_TYPE_LENGTH = 64
MAX_TEXT_LENGTH = 256
# Enough to show what is wrong without echoing a whole bad file back.
MAX_REPORTED_PROBLEMS = 20
MAX_REPORTED_IGNORED_FIELDS = 20
MAX_IGNORED_FIELD_LENGTH = 64


class LogFormat(StrEnum):
    CSV = "csv"
    JSON = "json"


@dataclass(frozen=True)
class LogEvent:
    timestamp: datetime  # always UTC
    event_type: str
    source_ip: str
    status: str
    user: str | None
    asset_id: str | None


@dataclass(frozen=True)
class RowProblem:
    row: int  # position of the event in the file, starting at 1
    field: str  # empty when the problem concerns the whole row
    message: str


@dataclass(frozen=True)
class ParsedLog:
    format: LogFormat
    events: tuple[LogEvent, ...]
    ignored_fields: tuple[str, ...]


class LogFileError(ValueError):
    """The file cannot be accepted; `problems` lists the first invalid values."""

    def __init__(
        self, message: str, problems: tuple[RowProblem, ...] = (), problem_count: int = 0
    ) -> None:
        super().__init__(message)
        self.message = message
        self.problems = problems
        self.problem_count = problem_count


class _FieldError(ValueError):
    pass


# A record is a mapping of field name to raw value, or the reason the row is unusable.
_Record = Mapping[str, object] | str


def _text(value: object, required: bool, max_length: int = MAX_TEXT_LENGTH) -> str | None:
    if value is None:
        text = ""
    elif isinstance(value, str):
        text = value.strip()
    else:
        raise _FieldError("must be text")
    if not text:
        if required:
            raise _FieldError("is required")
        return None
    if len(text) > max_length:
        raise _FieldError(f"must be at most {max_length} characters")
    return text


def _timestamp(value: object) -> datetime:
    text = _text(value, required=True)
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        raise _FieldError("is not an ISO 8601 timestamp") from None
    if parsed.tzinfo is None:
        raise _FieldError("needs a UTC offset or Z, for example 2026-01-31T08:00:00Z")
    try:
        return parsed.astimezone(UTC)
    except OverflowError:
        raise _FieldError("is not an ISO 8601 timestamp") from None


def _event_type(value: object) -> str:
    return _text(value, required=True, max_length=MAX_EVENT_TYPE_LENGTH).lower()


def _source_ip(value: object) -> str:
    text = _text(value, required=True)
    try:
        return str(ip_address(text))
    except ValueError:
        raise _FieldError("is not an IPv4 or IPv6 address") from None


def _status(value: object) -> str:
    status = _text(value, required=True).lower()
    if status not in STATUSES:
        raise _FieldError("must be success or fail")
    return status


def _optional_text(value: object) -> str | None:
    return _text(value, required=False)


_FIELD_PARSERS = {
    "timestamp": _timestamp,
    "event_type": _event_type,
    "source_ip": _source_ip,
    "status": _status,
    "user": _optional_text,
    "asset_id": _optional_text,
}


def _to_event(row: int, record: Mapping[str, object]) -> LogEvent | list[RowProblem]:
    values: dict[str, object] = {}
    problems: list[RowProblem] = []
    for field, parse in _FIELD_PARSERS.items():
        try:
            values[field] = parse(record.get(field))
        except _FieldError as error:
            problems.append(RowProblem(row=row, field=field, message=f"{field} {error}"))
    return problems or LogEvent(**values)


def _to_events(records: Iterable[_Record]) -> tuple[LogEvent, ...]:
    events: list[LogEvent] = []
    problems: list[RowProblem] = []
    problem_count = 0
    for row, record in enumerate(records, start=1):
        if isinstance(record, str):
            result: LogEvent | list[RowProblem] = [RowProblem(row=row, field="", message=record)]
        else:
            result = _to_event(row, record)
        if isinstance(result, LogEvent):
            events.append(result)
            continue
        problem_count += len(result)
        problems.extend(result[: MAX_REPORTED_PROBLEMS - len(problems)])
    if problem_count:
        noun = "problem" if problem_count == 1 else "problems"
        raise LogFileError(
            f"The file was rejected: {problem_count} {noun} found.",
            problems=tuple(problems),
            problem_count=problem_count,
        )
    if not events:
        raise LogFileError("The file has no events.")
    return tuple(events)


def _ignored(fields: Iterable[str]) -> tuple[str, ...]:
    """Names of fields outside the schema, bounded in number and length."""
    names = {field.strip()[:MAX_IGNORED_FIELD_LENGTH] for field in fields} - set(LOG_FIELDS)
    return tuple(sorted(name for name in names if name)[:MAX_REPORTED_IGNORED_FIELDS])


def _is_blank(values: list[str]) -> bool:
    return not values or (len(values) == 1 and not values[0].strip())


def _csv_records(rows: Iterator[list[str]], header: list[str]) -> Iterator[_Record]:
    for values in rows:
        if _is_blank(values):
            continue
        if len(values) != len(header):
            noun = "value" if len(values) == 1 else "values"
            yield f"row has {len(values)} {noun}, expected {len(header)}"
        else:
            yield dict(zip(header, values, strict=True))


def _parse_csv(text: str) -> ParsedLog:
    rows = csv.reader(io.StringIO(text, newline=""))
    try:
        header = [name.strip() for name in next(row for row in rows if not _is_blank(row))]
        # Only schema columns are named: other header text is not repeated back.
        duplicated = [name for name in LOG_FIELDS if header.count(name) > 1]
        if duplicated:
            raise LogFileError(f"Columns appear more than once: {', '.join(duplicated)}.")
        missing = [name for name in REQUIRED_FIELDS if name not in header]
        if missing:
            raise LogFileError(f"Missing required columns: {', '.join(missing)}.")
        events = _to_events(_csv_records(rows, header))
    except csv.Error:
        raise LogFileError("The file is not valid CSV.") from None
    return ParsedLog(format=LogFormat.CSV, events=events, ignored_fields=_ignored(header))


def _parse_json(text: str) -> ParsedLog:
    try:
        document = json.loads(text)
    except (ValueError, RecursionError):
        raise LogFileError("The file is not valid JSON.") from None
    if not isinstance(document, list):
        raise LogFileError("The JSON file must be an array of event objects.")
    records: list[_Record] = [
        item if isinstance(item, dict) else "event must be a JSON object" for item in document
    ]
    events = _to_events(records)
    keys = (key for record in records if not isinstance(record, str) for key in record)
    return ParsedLog(format=LogFormat.JSON, events=events, ignored_fields=_ignored(keys))


def parse_log(content: bytes, log_format: LogFormat) -> ParsedLog:
    """Returns the file's events, or raises `LogFileError` if any part is invalid."""
    try:
        text = content.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise LogFileError("The file is not UTF-8 text.") from None
    if not text.strip():
        raise LogFileError("The file is empty.")
    return _parse_csv(text) if log_format is LogFormat.CSV else _parse_json(text)
