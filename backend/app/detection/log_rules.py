"""Rule-based checks over validated security log events.

Rules: a known-bad source address, a burst of failed logins (escalated when the
same address then logs in successfully), and a few event signatures. The window,
counts and hours below are fixed starting points, not tuned to any environment.
"""

import re
from collections import defaultdict
from collections.abc import Iterable
from datetime import timedelta

from app.detection.alerts import (
    RULE_CONFIDENCE,
    AlertCandidate,
    AlertCategory,
    AlertSeverity,
    Evidence,
    EvidenceKind,
)
from app.detection.watchlist import Watchlist
from app.ingestion.logs import LogEvent

BURST_WINDOW = timedelta(minutes=5)
BURST_MIN_FAILURES = 5
BURST_HIGH_FAILURES = 10
SUCCESS_AFTER_BURST_WINDOW = timedelta(minutes=10)
# Business hours in UTC: the log schema stores UTC and has no time zone per site.
BUSINESS_HOURS_UTC = range(6, 20)
SENSITIVE_EVENT_TYPES = frozenset({"config_change"})
# Event types that are suspicious by name wherever they occur; extend as needed.
EVENT_SIGNATURES: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^(privilege_escalation|priv_esc)$"), "Privilege escalation event"),
    (re.compile(r"^(log|audit)_(cleared|deleted|disabled)$"), "Audit log tampering event"),
    (re.compile(r"^(mfa|2fa)_(disabled|removed)$"), "Multi-factor authentication turned off"),
)
MAX_EXAMPLES = 3


def _is_failed_login(event: LogEvent) -> bool:
    return event.status == "fail" and "login" in event.event_type


def _is_successful_login(event: LogEvent) -> bool:
    return event.status == "success" and "login" in event.event_type


def _known_bad_sources(events: list[LogEvent], watchlist: Watchlist) -> list[AlertCandidate]:
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)
    alerts = []
    for ip, ip_events in by_ip.items():
        entry = watchlist.match_ip(ip)
        if entry is None:
            continue
        alerts.append(
            AlertCandidate(
                severity=AlertSeverity.HIGH,
                confidence=RULE_CONFIDENCE,
                category=AlertCategory.KNOWN_BAD_SOURCE,
                source=ip,
                asset=ip_events[0].asset_id,
                title="Activity from a known-bad address",
                evidence=(
                    Evidence(
                        EvidenceKind.RULE_MATCH,
                        "known_bad_ip",
                        f"Source address is on the known-bad list (entry {entry}); "
                        f"{len(ip_events)} event(s) in this file.",
                        float(len(ip_events)),
                        (entry,),
                    ),
                ),
                occurred_at=min(event.timestamp for event in ip_events),
            )
        )
    return alerts


def _densest_window(failures: list[LogEvent]) -> list[LogEvent]:
    """The run of failures inside BURST_WINDOW with the most events (earliest on ties)."""
    best: list[LogEvent] = []
    start = 0
    for end in range(len(failures)):
        while failures[end].timestamp - failures[start].timestamp > BURST_WINDOW:
            start += 1
        if end - start + 1 > len(best):
            best = failures[start : end + 1]
    return best


def _failed_login_bursts(events: list[LogEvent]) -> list[AlertCandidate]:
    by_ip: dict[str, list[LogEvent]] = defaultdict(list)
    for event in events:
        by_ip[event.source_ip].append(event)
    alerts = []
    for ip, ip_events in by_ip.items():
        ordered = sorted(ip_events, key=lambda event: event.timestamp)
        burst = _densest_window([event for event in ordered if _is_failed_login(event)])
        if len(burst) < BURST_MIN_FAILURES:
            continue
        end = burst[-1].timestamp
        success = next(
            (
                event
                for event in ordered
                if _is_successful_login(event)
                and timedelta(0) <= event.timestamp - end <= SUCCESS_AFTER_BURST_WINDOW
            ),
            None,
        )
        severity = AlertSeverity.HIGH if len(burst) >= BURST_HIGH_FAILURES else AlertSeverity.MEDIUM
        evidence = [
            Evidence(
                EvidenceKind.RULE_MATCH,
                "failed_login_burst",
                f"{len(burst)} failed logins from one address within "
                f"{int(BURST_WINDOW.total_seconds() // 60)} minutes "
                f"(rule: {BURST_MIN_FAILURES} or more).",
                float(len(burst)),
                tuple(sorted({event.user for event in burst if event.user})[:MAX_EXAMPLES]),
            )
        ]
        title = "Burst of failed logins"
        if success is not None:
            severity = AlertSeverity.CRITICAL
            title = "Successful login right after a burst of failed logins"
            evidence.append(
                Evidence(
                    EvidenceKind.RULE_MATCH,
                    "success_after_failures",
                    "The same address logged in successfully within "
                    f"{int(SUCCESS_AFTER_BURST_WINDOW.total_seconds() // 60)} minutes "
                    "of the last failure.",
                    examples=(success.user or "unknown user",),
                )
            )
        alerts.append(
            AlertCandidate(
                severity=severity,
                confidence=RULE_CONFIDENCE,
                category=AlertCategory.BRUTE_FORCE,
                source=ip,
                asset=burst[0].asset_id,
                title=title,
                evidence=tuple(evidence),
                occurred_at=burst[0].timestamp,
            )
        )
    return alerts


def _signature_alerts(events: list[LogEvent]) -> list[AlertCandidate]:
    alerts = []
    for event in events:
        evidence: list[Evidence] = []
        title = ""
        for pattern, description in EVENT_SIGNATURES:
            if pattern.match(event.event_type):
                title = description
                evidence.append(
                    Evidence(
                        EvidenceKind.RULE_MATCH,
                        "event_signature",
                        f"{description}: event type matches a known suspicious name.",
                        examples=(event.event_type,),
                    )
                )
        if (
            event.event_type in SENSITIVE_EVENT_TYPES
            and event.status == "success"
            and event.timestamp.hour not in BUSINESS_HOURS_UTC
        ):
            title = title or "Configuration change outside business hours"
            evidence.append(
                Evidence(
                    EvidenceKind.RULE_MATCH,
                    "off_hours_change",
                    f"{event.event_type} at {event.timestamp:%H:%M} UTC, outside "
                    f"{BUSINESS_HOURS_UTC.start:02d}:00-{BUSINESS_HOURS_UTC.stop:02d}:00 UTC.",
                )
            )
        if evidence:
            alerts.append(
                AlertCandidate(
                    severity=AlertSeverity.MEDIUM,
                    confidence=RULE_CONFIDENCE - 20,
                    category=AlertCategory.SUSPICIOUS_ACTIVITY,
                    source=event.source_ip,
                    asset=event.asset_id,
                    title=title,
                    evidence=tuple(evidence),
                    occurred_at=event.timestamp,
                )
            )
    return alerts


def check_log_events(events: Iterable[LogEvent], watchlist: Watchlist) -> list[AlertCandidate]:
    """Runs every rule; the same activity can trigger more than one alert."""
    ordered = list(events)
    return [
        *_known_bad_sources(ordered, watchlist),
        *_failed_login_bursts(ordered),
        *_signature_alerts(ordered),
    ]
