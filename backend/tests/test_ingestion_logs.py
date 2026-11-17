import json
from datetime import UTC, datetime

import pytest

from app.core.config import REPO_ROOT
from app.ingestion.logs import (
    MAX_REPORTED_PROBLEMS,
    LogFileError,
    LogFormat,
    RowProblem,
    parse_log,
)

HEADER = "timestamp,event_type,source_ip,user,status,asset_id"
ROW = "2026-11-16T08:00:00Z,login_success,192.0.2.10,alice,success,web-01"
EVENT = {
    "timestamp": "2026-11-16T08:00:00Z",
    "event_type": "login_success",
    "source_ip": "192.0.2.10",
    "status": "success",
}


def _csv(*rows: str, header: str = HEADER) -> bytes:
    return "\n".join([header, *rows]).encode()


def _json(*events: object) -> bytes:
    return json.dumps(list(events)).encode()


def _problems(content: bytes, log_format: LogFormat) -> tuple[RowProblem, ...]:
    with pytest.raises(LogFileError) as raised:
        parse_log(content, log_format)
    return raised.value.problems


def test_csv_row_becomes_a_normalised_event() -> None:
    parsed = parse_log(_csv(ROW), LogFormat.CSV)

    assert parsed.format is LogFormat.CSV
    assert len(parsed.events) == 1
    event = parsed.events[0]
    assert event.timestamp == datetime(2026, 11, 16, 8, 0, tzinfo=UTC)
    assert event.event_type == "login_success"
    assert event.source_ip == "192.0.2.10"
    assert event.user == "alice"
    assert event.status == "success"
    assert event.asset_id == "web-01"


def test_json_array_becomes_normalised_events() -> None:
    parsed = parse_log(_json(EVENT, {**EVENT, "user": "bob"}), LogFormat.JSON)

    assert parsed.format is LogFormat.JSON
    assert [event.user for event in parsed.events] == [None, "bob"]


def test_timestamps_are_converted_to_utc() -> None:
    row = ROW.replace("08:00:00Z", "08:00:00+05:30")

    event = parse_log(_csv(row), LogFormat.CSV).events[0]

    assert event.timestamp == datetime(2026, 11, 16, 2, 30, tzinfo=UTC)


def test_values_are_trimmed_and_case_is_normalised() -> None:
    row = " 2026-11-16T08:00:00Z , Login_Failure , 2001:DB8::1 , alice , FAIL , "

    event = parse_log(_csv(row), LogFormat.CSV).events[0]

    assert event.event_type == "login_failure"
    assert event.source_ip == "2001:db8::1"
    assert event.status == "fail"
    assert event.user == "alice"
    assert event.asset_id is None


def test_optional_columns_may_be_absent() -> None:
    content = _csv(
        "2026-11-16T08:00:00Z,access,192.0.2.10,success",
        header="timestamp,event_type,source_ip,status",
    )

    event = parse_log(content, LogFormat.CSV).events[0]

    assert event.user is None
    assert event.asset_id is None


def test_unknown_fields_are_ignored_and_reported() -> None:
    csv_log = parse_log(_csv(ROW + ",x", header=HEADER + ",session"), LogFormat.CSV)
    json_log = parse_log(_json({**EVENT, "zone": "a"}, {**EVENT, "agent": "b"}), LogFormat.JSON)

    assert csv_log.ignored_fields == ("session",)
    assert json_log.ignored_fields == ("agent", "zone")


def test_byte_order_mark_and_blank_lines_are_tolerated() -> None:
    content = b"\xef\xbb\xbf" + _csv(ROW, "", ROW) + b"\n\n"

    assert len(parse_log(content, LogFormat.CSV).events) == 2


@pytest.mark.parametrize(
    ("content", "log_format", "message"),
    [
        (b"", LogFormat.CSV, "empty"),
        (b"   \n", LogFormat.JSON, "empty"),
        (b"\xff\xfe\x00", LogFormat.CSV, "UTF-8"),
        (HEADER.encode(), LogFormat.CSV, "no events"),
        (b"[]", LogFormat.JSON, "no events"),
        (b"{not json", LogFormat.JSON, "not valid JSON"),
        (b'{"events": []}', LogFormat.JSON, "array"),
        (b"[" * 100_000, LogFormat.JSON, "not valid JSON"),
        (_csv(ROW, header="timestamp,event_type,user"), LogFormat.CSV, "source_ip, status"),
        (_csv(ROW, header=HEADER + ",status"), LogFormat.CSV, "more than once: status"),
    ],
)
def test_unusable_file_is_rejected_as_a_whole(
    content: bytes, log_format: LogFormat, message: str
) -> None:
    with pytest.raises(LogFileError, match=message) as raised:
        parse_log(content, log_format)

    assert raised.value.problems == ()


@pytest.mark.parametrize(
    ("field", "value", "message"),
    [
        ("timestamp", "yesterday", "ISO 8601"),
        ("timestamp", "2026-11-16T08:00:00", "UTC offset"),
        ("timestamp", "0001-01-01T00:00:00+05:00", "ISO 8601"),
        ("timestamp", "", "required"),
        ("event_type", "", "required"),
        ("event_type", "x" * 65, "at most 64"),
        ("source_ip", "999.1.1.1", "IPv4 or IPv6"),
        ("source_ip", "example.com", "IPv4 or IPv6"),
        ("status", "maybe", "success or fail"),
        ("user", "x" * 257, "at most 256"),
        ("asset_id", "x" * 257, "at most 256"),
    ],
)
def test_invalid_value_is_reported_with_its_row_and_field(
    field: str, value: str, message: str
) -> None:
    good = {**EVENT, "user": "alice", "asset_id": "web-01"}

    problems = _problems(_json(good, {**good, field: value}), LogFormat.JSON)

    assert len(problems) == 1
    assert problems[0].row == 2
    assert problems[0].field == field
    assert message in problems[0].message


def test_json_rejects_missing_null_and_non_text_values() -> None:
    without_ip = {key: value for key, value in EVENT.items() if key != "source_ip"}

    problems = _problems(
        _json(without_ip, {**EVENT, "status": None}, {**EVENT, "user": 7}, "text"),
        LogFormat.JSON,
    )

    assert [(p.row, p.field) for p in problems] == [
        (1, "source_ip"),
        (2, "status"),
        (3, "user"),
        (4, ""),
    ]
    assert "required" in problems[0].message
    assert "required" in problems[1].message
    assert "text" in problems[2].message
    assert "object" in problems[3].message


def test_csv_row_with_the_wrong_number_of_values_is_reported() -> None:
    problems = _problems(_csv(ROW, ROW + ",extra", "a,b"), LogFormat.CSV)

    assert [(p.row, p.field) for p in problems] == [(2, ""), (3, "")]
    assert "7 values" in problems[0].message
    assert "expected 6" in problems[0].message


def test_one_bad_row_rejects_the_file_and_all_its_problems_are_listed() -> None:
    bad = "never,login_failure,nowhere,alice,unknown,web-01"

    with pytest.raises(LogFileError) as raised:
        parse_log(_csv(ROW, bad), LogFormat.CSV)

    assert [p.field for p in raised.value.problems] == ["timestamp", "source_ip", "status"]
    assert raised.value.problem_count == 3


def test_reported_problems_are_capped_but_all_are_counted() -> None:
    bad_rows = [ROW.replace("192.0.2.10", "nowhere")] * (MAX_REPORTED_PROBLEMS + 5)

    with pytest.raises(LogFileError) as raised:
        parse_log(_csv(*bad_rows), LogFormat.CSV)

    assert len(raised.value.problems) == MAX_REPORTED_PROBLEMS
    assert raised.value.problem_count == MAX_REPORTED_PROBLEMS + 5


def test_problem_messages_do_not_repeat_the_submitted_value() -> None:
    problems = _problems(_json({**EVENT, "source_ip": "<script>"}), LogFormat.JSON)

    assert "<script>" not in problems[0].message


def test_header_text_outside_the_schema_is_not_repeated_in_errors() -> None:
    header = "timestamp,event_type,source_ip,SECRET,SECRET"

    with pytest.raises(LogFileError) as raised:
        parse_log(_csv(ROW, header=header), LogFormat.CSV)

    assert raised.value.message == "Missing required columns: status."


def test_repeated_unknown_column_does_not_reject_the_file() -> None:
    content = _csv(ROW + ",a,b", header=HEADER + ",note,note")

    assert parse_log(content, LogFormat.CSV).ignored_fields == ("note",)


def test_ignored_field_names_are_shortened_and_blank_ones_dropped() -> None:
    csv_log = parse_log(_csv(ROW + ",,", header=f"{HEADER},{'n' * 500},"), LogFormat.CSV)
    json_log = parse_log(_json({**EVENT, "k" * 500: "x", "": "y"}), LogFormat.JSON)

    assert csv_log.ignored_fields == ("n" * 64,)
    assert json_log.ignored_fields == ("k" * 64,)


def test_whitespace_only_lines_are_skipped_like_blank_ones() -> None:
    content = b"  \n" + _csv(ROW, "   ", ROW.replace("192.0.2.10", "nowhere"))

    problems = _problems(content, LogFormat.CSV)

    assert [(p.row, p.field) for p in problems] == [(2, "source_ip")]


def test_oversized_csv_field_is_rejected_not_raised() -> None:
    row = ROW.replace("alice", "x" * 200_000)

    with pytest.raises(LogFileError):
        parse_log(_csv(row), LogFormat.CSV)


def test_published_demo_log_passes_validation() -> None:
    content = (REPO_ROOT / "samples" / "demo_security_log.csv").read_bytes()

    parsed = parse_log(content, LogFormat.CSV)

    assert len(parsed.events) >= 20
    assert parsed.ignored_fields == ()
