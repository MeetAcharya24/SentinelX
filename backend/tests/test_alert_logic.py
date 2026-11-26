"""Scoring-to-alert rules, log rules and the known-bad lists (no models, no database)."""

from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

import pytest

from app.detection.alerts import (
    ANOMALY_ONLY_CONFIDENCE,
    AlertCategory,
    AlertSeverity,
    EvidenceKind,
    flow_candidate,
    phishing_candidate,
    raise_severity,
)
from app.detection.log_rules import check_log_events
from app.detection.phishing_signals import Severity, Signal
from app.detection.watchlist import Watchlist, load_watchlist
from app.ingestion.logs import LogEvent

THRESHOLD = 0.0


def _flow(probability: float, score: float, unseen: list[str] | None = None):
    return flow_candidate(1, probability, score, THRESHOLD, unseen or [])


def test_a_flow_neither_model_flags_makes_no_alert() -> None:
    assert _flow(0.2, -0.1) is None


def test_both_models_flagging_is_high_and_carries_both_scores() -> None:
    alert = _flow(0.97, 0.12)

    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert alert.confidence == 97
    assert alert.category == AlertCategory.NETWORK_ANOMALY
    assert [e.name for e in alert.evidence] == [
        "random_forest_attack_probability",
        "isolation_forest_anomaly_score",
    ]
    assert all(e.kind == EvidenceKind.MODEL_SCORE for e in alert.evidence)
    assert alert.evidence[0].value == 0.97


@pytest.mark.parametrize(
    ("probability", "score", "severity"),
    [(0.95, -0.2, AlertSeverity.MEDIUM), (0.6, -0.2, AlertSeverity.LOW)],
)
def test_forest_alone_is_graded_by_how_strong_its_score_is(
    probability: float, score: float, severity: AlertSeverity
) -> None:
    alert = _flow(probability, score)

    assert alert is not None
    assert alert.severity == severity


def test_anomaly_alone_is_low_with_a_fixed_low_confidence() -> None:
    alert = _flow(0.1, 0.3)

    assert alert is not None
    assert alert.severity == AlertSeverity.LOW
    assert alert.confidence == ANOMALY_ONLY_CONFIDENCE


def test_unseen_categories_are_attached_as_a_caveat() -> None:
    alert = _flow(0.9, 0.1, ["proto"])

    assert alert is not None
    caveat = alert.evidence[-1]
    assert (caveat.kind, caveat.examples) == (EvidenceKind.CAVEAT, ("proto",))


def test_raise_severity_stops_at_critical() -> None:
    assert raise_severity(AlertSeverity.LOW) == AlertSeverity.MEDIUM
    assert raise_severity(AlertSeverity.HIGH, 5) == AlertSeverity.CRITICAL


SIGNALS = [
    Signal("urgency_language", Severity.SUSPICIOUS, "pressure", ("urgent",)),
    Signal("ip_address_link", Severity.SUSPICIOUS, "raw ip", ("203.0.113.9",)),
    Signal("url_shortener", Severity.INFO, "short", ("bit.ly",)),
]


def _phish(probability: float, signals: list[Signal], matches: list[str] | None = None):
    return phishing_candidate(
        "a@b.example", "Verify now", probability, signals, [("account", 1.2)], matches or []
    )


def test_a_benign_email_with_no_match_makes_no_alert() -> None:
    assert _phish(0.1, SIGNALS) is None


def test_phishing_alert_carries_score_signals_and_terms() -> None:
    alert = _phish(0.95, SIGNALS)

    assert alert is not None
    assert alert.severity == AlertSeverity.HIGH
    assert alert.category == AlertCategory.PHISHING
    kinds = [e.kind for e in alert.evidence]
    assert kinds[0] == EvidenceKind.MODEL_SCORE
    assert kinds.count(EvidenceKind.PHISHING_SIGNAL) == 3
    assert kinds[-1] == EvidenceKind.MODEL_TERM
    assert alert.title == "Suspected phishing email: Verify now"


@pytest.mark.parametrize(
    ("probability", "signals", "severity"),
    [
        (0.95, SIGNALS[:1], AlertSeverity.MEDIUM),
        (0.6, SIGNALS[:1], AlertSeverity.MEDIUM),
        (0.6, SIGNALS[2:], AlertSeverity.LOW),
    ],
)
def test_phishing_severity_follows_score_and_signal_agreement(
    probability: float, signals: list[Signal], severity: AlertSeverity
) -> None:
    alert = _phish(probability, signals)

    assert alert is not None
    assert alert.severity == severity


def test_a_bad_domain_match_raises_severity_and_alerts_on_its_own() -> None:
    raised = _phish(0.6, SIGNALS[2:], ["evil.test"])
    alone = _phish(0.1, [], ["evil.test"])

    assert raised is not None
    assert raised.severity == AlertSeverity.MEDIUM
    assert alone is not None
    assert alone.severity == AlertSeverity.MEDIUM  # low, raised once
    assert any(e.name == "known_bad_domain" for e in alone.evidence)


def _event(
    seconds: int,
    event_type: str = "login_failure",
    status: str = "fail",
    ip: str = "203.0.113.45",
    base: datetime = datetime(2026, 1, 12, 9, 0, tzinfo=UTC),
) -> LogEvent:
    return LogEvent(
        timestamp=base + timedelta(seconds=seconds),
        event_type=event_type,
        source_ip=ip,
        status=status,
        user="admin",
        asset_id="vpn",
    )


def _rules(events: list[LogEvent], watchlist: Watchlist | None = None):
    return check_log_events(events, watchlist or Watchlist())


def test_five_failures_in_the_window_is_a_medium_burst() -> None:
    alerts = _rules([_event(i * 10) for i in range(5)])

    assert [a.category for a in alerts] == [AlertCategory.BRUTE_FORCE]
    assert alerts[0].severity == AlertSeverity.MEDIUM
    assert alerts[0].evidence[0].value == 5


def test_ten_failures_is_high_and_four_is_nothing() -> None:
    assert _rules([_event(i * 10) for i in range(10)])[0].severity == AlertSeverity.HIGH
    assert _rules([_event(i * 10) for i in range(4)]) == []


def test_failures_spread_beyond_the_window_do_not_count() -> None:
    assert _rules([_event(i * 400) for i in range(8)]) == []


def test_success_right_after_a_burst_is_critical() -> None:
    events = [_event(i * 10) for i in range(6)]
    events.append(_event(120, "login_success", "success"))

    alert = _rules(events)[0]

    assert alert.severity == AlertSeverity.CRITICAL
    assert [e.name for e in alert.evidence] == ["failed_login_burst", "success_after_failures"]


def test_success_long_after_a_burst_does_not_escalate() -> None:
    events = [_event(i * 10) for i in range(6)]
    events.append(_event(3600, "login_success", "success"))

    assert _rules(events)[0].severity == AlertSeverity.MEDIUM


def test_known_bad_source_ip_alerts_once_per_address() -> None:
    watchlist = Watchlist(networks=(ip_network("203.0.113.0/24"),))
    events = [_event(0, "access", "success"), _event(5, "access", "success")]

    alerts = _rules(events, watchlist)

    assert [a.category for a in alerts] == [AlertCategory.KNOWN_BAD_SOURCE]
    assert alerts[0].evidence[0].examples == ("203.0.113.0/24",)
    assert alerts[0].evidence[0].value == 2


def test_signature_events_and_off_hours_changes_are_medium() -> None:
    night = datetime(2026, 1, 13, 2, 47, tzinfo=UTC)
    events = [
        _event(0, "config_change", "success", base=night),
        _event(0, "audit_cleared", "success", ip="192.0.2.1"),
        _event(0, "config_change", "success", ip="192.0.2.2"),  # 09:00 UTC, business hours
    ]

    alerts = _rules(events)

    assert [(a.source, a.title) for a in alerts] == [
        ("203.0.113.45", "Configuration change outside business hours"),
        ("192.0.2.1", "Audit log tampering event"),
    ]
    assert {a.severity for a in alerts} == {AlertSeverity.MEDIUM}


def test_watchlist_matches_addresses_ranges_and_subdomains(tmp_path: Path) -> None:
    (tmp_path / "bad_ips.txt").write_text(
        "# demo\n203.0.113.45\n198.51.100.0/24  # range\nnot-an-ip\n2001:db8::/32\n",
        encoding="utf-8",
    )
    (tmp_path / "bad_domains.txt").write_text("Evil.Test\nbad domain\n", encoding="utf-8")

    watchlist = load_watchlist(tmp_path)

    assert watchlist.match_ip("203.0.113.45") == "203.0.113.45/32"
    assert watchlist.match_ip("198.51.100.200") == "198.51.100.0/24"
    assert watchlist.match_ip("2001:db8::1") == "2001:db8::/32"
    assert watchlist.match_ip("192.0.2.1") is None
    assert watchlist.match_ip("garbage") is None
    assert watchlist.match_domain("login.evil.test") == "evil.test"
    assert watchlist.match_domain("notevil.test") is None


def test_missing_blocklist_files_mean_nothing_matches(tmp_path: Path) -> None:
    watchlist = load_watchlist(tmp_path / "absent")

    assert watchlist.match_ip("203.0.113.45") is None
    assert watchlist.match_domain("evil.test") is None
