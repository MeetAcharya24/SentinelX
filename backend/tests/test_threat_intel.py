"""Threat-intelligence cache, feed parsing, the refresh schedule and alert enrichment.

Both feeds are replaced by fake fetchers: nothing here touches the network.
"""

import json
from datetime import UTC, datetime, timedelta
from ipaddress import ip_network
from pathlib import Path

import pytest

from app.detection.alerts import AlertCandidate, AlertCategory, AlertSeverity, EvidenceKind
from app.detection.enrichment import email_evidence, enrich_log_candidates
from app.detection.pipeline import alerts_from_email, alerts_from_log
from app.detection.watchlist import Watchlist
from app.ingestion.email import parse_email
from app.ingestion.logs import LogFormat, parse_log
from app.intel import refresh
from app.intel.feeds import (
    FEODO_SOURCE,
    FEODO_URL,
    THREATFOX_SOURCE,
    THREATFOX_URL,
    FeedError,
    http_fetch,
    parse_feodo,
    parse_threatfox,
)
from app.intel.lookup import ThreatIntel, domain_candidates
from app.intel.store import IntelStore, Ioc
from app.ml.phishing_model import build_pipeline
from app.storage.alerts import AlertStore
from tests.test_phishing import LEGIT_TEXTS, PHISH_TEXTS

NOW = datetime(2026, 11, 26, 10, 0, tzinfo=UTC)

FEODO_JSON = json.dumps(
    [
        {
            "ip_address": "203.0.113.45",
            "port": 443,
            "status": "online",
            "first_seen": "2026-11-20 08:00:00",
            "malware": "QakBot",
        },
        {"ip_address": "not-an-address"},
        "junk",
    ]
).encode()

THREATFOX_JSON = json.dumps(
    {
        "query_status": "ok",
        "data": [
            {
                "ioc": "198.51.100.7:8443",
                "ioc_type": "ip:port",
                "malware_printable": "Cobalt Strike",
                "confidence_level": 75,
                "first_seen": "2026-11-25 12:00:00 UTC",
            },
            {
                "ioc": "Evil.Example.",
                "ioc_type": "domain",
                "malware_printable": "Dridex",
                "confidence_level": 50,
                "first_seen": "2026-11-24 12:00:00 UTC",
            },
            {
                "ioc": "http://evil.example/payload.exe",
                "ioc_type": "url",
                "malware_printable": "Dridex",
                "confidence_level": 90,
                "first_seen": "2026-11-24 12:00:00 UTC",
            },
            {"ioc": "d41d8cd98f00b204e9800998ecf8427e", "ioc_type": "md5_hash"},
            {"ioc": "bad:port", "ioc_type": "ip:port"},
        ],
    }
).encode()


class FakeFeeds:
    """Stands in for the network: serves canned bodies and records every request."""

    def __init__(self, feodo: bytes = FEODO_JSON, threatfox: bytes = THREATFOX_JSON) -> None:
        self.bodies = {FEODO_URL: feodo, THREATFOX_URL: threatfox}
        self.requests: list[tuple[str, dict[str, str], bytes | None]] = []

    def __call__(self, url: str, headers: dict[str, str], body: bytes | None) -> bytes:
        self.requests.append((url, headers, body))
        result = self.bodies[url]
        if isinstance(result, Exception):
            raise result
        return result


@pytest.fixture
def store(tmp_path: Path) -> IntelStore:
    return IntelStore(tmp_path / "intel.db")


# --- parsing ---------------------------------------------------------------


def test_feodo_list_keeps_valid_addresses_and_skips_bad_records() -> None:
    iocs = parse_feodo(FEODO_JSON)

    assert [(i.ioc_type, i.value, i.malware) for i in iocs] == [("ip", "203.0.113.45", "QakBot")]
    assert iocs[0].first_seen == datetime(2026, 11, 20, 8, 0, tzinfo=UTC)


def test_an_empty_feodo_list_is_valid() -> None:
    assert parse_feodo(b"[]") == []


@pytest.mark.parametrize("raw", [b"not json", b'{"a": 1}'])
def test_a_malformed_feodo_document_is_an_error(raw: bytes) -> None:
    with pytest.raises(FeedError):
        parse_feodo(raw)


def test_threatfox_keeps_ip_domain_and_url_indicators_only() -> None:
    iocs = parse_threatfox(THREATFOX_JSON)

    assert [(i.ioc_type, i.value, i.malware, i.confidence) for i in iocs] == [
        ("ip", "198.51.100.7", "Cobalt Strike", 75),
        ("domain", "evil.example", "Dridex", 50),
        ("url", "http://evil.example/payload.exe", "Dridex", 90),
    ]


def _port_record(port: int, confidence: int, first_seen: str, malware: str) -> dict[str, object]:
    return {
        "ioc": f"198.51.100.7:{port}",
        "ioc_type": "ip:port",
        "confidence_level": confidence,
        "first_seen": f"{first_seen} UTC",
        "malware_printable": malware,
    }


@pytest.mark.parametrize("reverse", [False, True], ids=["response order", "reversed order"])
def test_threatfox_keeps_highest_confidence_across_ports_and_newest_first_seen_on_a_tie(
    reverse: bool,
) -> None:
    records = [
        # Highest confidence overall is not the latest record and not the newest.
        _port_record(443, 90, "2026-11-20 08:00:00", "Highest"),
        # Ties with the next on confidence 75; older first_seen, so it loses.
        _port_record(8443, 75, "2026-11-21 08:00:00", "TiedOlder"),
        # Later in the response and newest of all, but lower confidence than 90.
        _port_record(80, 50, "2026-11-25 08:00:00", "LaterButWeaker"),
    ]
    raw = json.dumps({"query_status": "ok", "data": records[::-1] if reverse else records}).encode()

    (ioc,) = parse_threatfox(raw)

    assert (ioc.value, ioc.confidence, ioc.malware) == ("198.51.100.7", 90, "Highest")
    assert ioc.first_seen == datetime(2026, 11, 20, 8, 0, tzinfo=UTC)


@pytest.mark.parametrize("reverse", [False, True], ids=["response order", "reversed order"])
def test_threatfox_breaks_an_equal_confidence_tie_with_the_most_recent_first_seen(
    reverse: bool,
) -> None:
    records = [
        _port_record(443, 75, "2026-11-20 08:00:00", "Older"),
        _port_record(8443, 75, "2026-11-24 08:00:00", "Newest"),
        _port_record(80, 75, "2026-11-22 08:00:00", "Middle"),
        _port_record(22, 50, "2026-11-25 08:00:00", "LowerConfidence"),
    ]
    raw = json.dumps({"query_status": "ok", "data": records[::-1] if reverse else records}).encode()

    (ioc,) = parse_threatfox(raw)

    assert (ioc.confidence, ioc.malware) == (75, "Newest")
    assert ioc.first_seen == datetime(2026, 11, 24, 8, 0, tzinfo=UTC)


def test_threatfox_without_results_is_empty_and_other_statuses_are_errors() -> None:
    assert parse_threatfox(b'{"query_status": "no_result"}') == []
    with pytest.raises(FeedError, match="unauthorized"):
        parse_threatfox(b'{"query_status": "unauthorized"}')


def test_http_fetch_refuses_plain_http() -> None:
    with pytest.raises(FeedError, match="https"):
        http_fetch("http://example.test/feed", {}, None)


# --- cache -----------------------------------------------------------------


def test_replacing_a_feed_swaps_its_rows_and_records_the_refresh(store: IntelStore) -> None:
    store.replace_feed(FEODO_SOURCE, [Ioc("ip", "203.0.113.45")], now=NOW)
    later = NOW + timedelta(hours=6)

    count = store.replace_feed(FEODO_SOURCE, [], now=later)

    assert count == 0
    assert store.find("ip", ["203.0.113.45"]) == []
    state = store.feed_state(FEODO_SOURCE)
    assert state is not None and state.last_success_at == later and state.ioc_count == 0


def test_merging_updates_rows_and_drops_those_past_retention(store: IntelStore) -> None:
    old = datetime(2026, 1, 1, tzinfo=UTC)
    store.merge_feed(
        THREATFOX_SOURCE,
        [
            Ioc("domain", "old.example", first_seen=old),
            Ioc("domain", "new.example", first_seen=NOW),
        ],
        now=NOW,
        keep_since=NOW - timedelta(days=180),
    )

    assert store.find("domain", ["old.example"]) == []
    assert [i.value for i in store.find("domain", ["new.example", "old.example"])] == [
        "new.example"
    ]


def test_a_failed_attempt_keeps_cached_rows_and_the_last_success(store: IntelStore) -> None:
    store.replace_feed(FEODO_SOURCE, [Ioc("ip", "203.0.113.45")], now=NOW)

    store.record_failure(FEODO_SOURCE, "boom", now=NOW + timedelta(hours=7))

    state = store.feed_state(FEODO_SOURCE)
    assert state is not None
    assert (state.last_success_at, state.last_error) == (NOW, "boom")
    assert len(store.find("ip", ["203.0.113.45"])) == 1


# --- refresh job -----------------------------------------------------------


def test_refresh_pulls_both_feeds_into_the_cache(store: IntelStore) -> None:
    feeds = FakeFeeds()

    results = refresh.refresh_all(store, threatfox_key="k", fetch=feeds, now=NOW)

    assert [(r.source, r.outcome, r.ioc_count) for r in results] == [
        (FEODO_SOURCE, refresh.Outcome.REFRESHED, 1),
        (THREATFOX_SOURCE, refresh.Outcome.REFRESHED, 3),
    ]
    sent = {url: (headers, body) for url, headers, body in feeds.requests}
    assert sent[THREATFOX_URL][0]["Auth-Key"] == "k"
    assert json.loads(sent[THREATFOX_URL][1] or b"") == {"query": "get_iocs", "days": 7}
    assert [i.source for i in store.find("ip", ["203.0.113.45", "198.51.100.7"])] == [
        FEODO_SOURCE,
        THREATFOX_SOURCE,
    ]


def test_refresh_without_a_threatfox_key_still_refreshes_feodo(store: IntelStore) -> None:
    feeds = FakeFeeds()

    results = refresh.refresh_all(store, threatfox_key=None, fetch=feeds, now=NOW)

    assert [r.outcome for r in results] == [refresh.Outcome.REFRESHED, refresh.Outcome.NO_KEY]
    assert [url for url, _, _ in feeds.requests] == [FEODO_URL]


def test_a_feed_refreshed_within_six_hours_is_not_requested_again(store: IntelStore) -> None:
    refresh.refresh_all(store, threatfox_key="k", fetch=FakeFeeds(), now=NOW)
    feeds = FakeFeeds()

    soon = refresh.refresh_all(
        store, threatfox_key="k", fetch=feeds, now=NOW + timedelta(hours=5, minutes=59)
    )
    due = refresh.refresh_all(
        store, threatfox_key="k", fetch=feeds, now=NOW + timedelta(hours=6, minutes=1)
    )

    assert [r.outcome for r in soon] == [refresh.Outcome.FRESH, refresh.Outcome.FRESH]
    assert [r.outcome for r in due] == [refresh.Outcome.REFRESHED, refresh.Outcome.REFRESHED]
    assert len(feeds.requests) == 2


def test_force_ignores_the_schedule(store: IntelStore) -> None:
    refresh.refresh_all(store, threatfox_key="k", fetch=FakeFeeds(), now=NOW)
    feeds = FakeFeeds()

    refresh.refresh_all(store, threatfox_key="k", fetch=feeds, now=NOW, force=True)

    assert len(feeds.requests) == 2


def test_one_failing_feed_does_not_stop_or_wipe_the_other(store: IntelStore) -> None:
    refresh.refresh_all(store, threatfox_key="k", fetch=FakeFeeds(), now=NOW)
    broken = FakeFeeds(threatfox=FeedError("the feed answered HTTP 401"))  # type: ignore[arg-type]

    results = refresh.refresh_all(
        store, threatfox_key="k", fetch=broken, now=NOW + timedelta(hours=7)
    )

    assert [r.outcome for r in results] == [refresh.Outcome.REFRESHED, refresh.Outcome.FAILED]
    assert len(store.find("domain", ["evil.example"])) == 1


def test_a_failed_feed_is_not_retried_for_an_hour(store: IntelStore) -> None:
    broken = FakeFeeds(feodo=FeedError("down"))  # type: ignore[arg-type]
    refresh.refresh_all(store, threatfox_key=None, fetch=broken, now=NOW)

    soon = refresh.refresh_all(
        store, threatfox_key=None, fetch=broken, now=NOW + timedelta(minutes=30)
    )
    later = refresh.refresh_all(
        store, threatfox_key=None, fetch=FakeFeeds(), now=NOW + timedelta(minutes=61)
    )

    assert soon[0].outcome is refresh.Outcome.BACKOFF
    assert later[0].outcome is refresh.Outcome.REFRESHED
    assert len(broken.requests) == 1


def test_run_reports_each_feed_and_exits_non_zero_on_failure(
    make_settings, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    settings = make_settings(database_url=f"sqlite:///{tmp_path / 'a.db'}")
    ok_code = refresh.run(settings, fetch=FakeFeeds())
    failing = make_settings(database_url=f"sqlite:///{tmp_path / 'b.db'}")
    bad_code = refresh.run(failing, fetch=FakeFeeds(feodo=b"nope"))

    output = capsys.readouterr().out
    assert (ok_code, bad_code) == (0, 1)
    assert "feodo_tracker: refreshed (1 cached)" in output
    assert "threatfox: skipped: THREATFOX_API_KEY is not set" in output
    assert "feodo_tracker: failed: the feed response is not valid JSON" in output


# --- lookup and enrichment -------------------------------------------------


@pytest.fixture
def intel(store: IntelStore) -> ThreatIntel:
    refresh.refresh_all(store, threatfox_key="k", fetch=FakeFeeds(), now=NOW)
    return ThreatIntel(store)


def test_domain_candidates_include_parents_but_not_the_bare_suffix() -> None:
    assert domain_candidates("A.B.Evil.Example.") == [
        "a.b.evil.example",
        "b.evil.example",
        "evil.example",
    ]
    assert domain_candidates("localhost") == []


def test_lookup_matches_addresses_subdomains_and_urls(intel: ThreatIntel) -> None:
    assert list(intel.match_ips(["203.0.113.45", "192.0.2.1", "garbage"])) == ["203.0.113.45"]
    assert list(intel.match_hosts(["cdn.evil.example", "fine.example"])) == ["cdn.evil.example"]
    assert list(intel.match_urls(["http://evil.example/payload.exe"])) == [
        "http://evil.example/payload.exe"
    ]
    assert ThreatIntel(None).match_ips(["203.0.113.45"]) == {}


LOG_CSV = b"timestamp,event_type,source_ip,user,status,asset_id\n" + b"".join(
    f"2026-01-12T09:15:{second:02d}Z,login_attempt,203.0.113.45,admin,fail,web-01\n".encode()
    for second in range(6)
)


def _log_candidates(intel: ThreatIntel | None) -> list[AlertCandidate]:
    return alerts_from_log(parse_log(LOG_CSV, LogFormat.CSV), Watchlist(), intel)


def test_a_log_alert_from_a_listed_address_gains_threat_intel_evidence(intel: ThreatIntel) -> None:
    (alert,) = _log_candidates(intel)

    match = alert.evidence[-1]
    assert alert.category is AlertCategory.BRUTE_FORCE and alert.severity is AlertSeverity.MEDIUM
    assert match.kind is EvidenceKind.THREAT_INTEL_MATCH
    assert match.name == FEODO_SOURCE
    assert match.examples == ("203.0.113.45",)
    assert "Feodo Tracker (abuse.ch)" in match.description
    assert "QakBot" in match.description
    assert "Cache last refreshed 2026-11-26 10:00 UTC" in match.description


def test_enrichment_sits_beside_the_operator_blocklist_and_changes_no_scores(
    intel: ThreatIntel,
) -> None:
    watchlist = Watchlist(networks=(ip_network("203.0.113.45"),))
    plain = alerts_from_log(parse_log(LOG_CSV, LogFormat.CSV), watchlist)
    enriched = alerts_from_log(parse_log(LOG_CSV, LogFormat.CSV), watchlist, intel)

    assert [a.category for a in enriched] == [a.category for a in plain]
    assert [(a.severity, a.confidence) for a in enriched] == [
        (a.severity, a.confidence) for a in plain
    ]
    blocklist = [e for a in enriched for e in a.evidence if e.name == "known_bad_ip"]
    feed = [e for a in enriched for e in a.evidence if e.kind is EvidenceKind.THREAT_INTEL_MATCH]
    assert len(blocklist) == 1 and len(feed) == 2  # one match per alert on that address


def test_unlisted_addresses_and_an_empty_cache_add_nothing(store: IntelStore) -> None:
    (plain,) = _log_candidates(None)

    assert _log_candidates(ThreatIntel(store)) == [plain]
    assert enrich_log_candidates([plain], ThreatIntel(None)) == [plain]


EMAIL = (
    b"From: Support <help@evil.example>\r\nTo: you@example.test\r\nSubject: Verify now\r\n"
    b"Content-Type: text/html\r\n\r\n"
    b'<a href="http://evil.example/payload.exe">Download</a> '
    b'<a href="http://198.51.100.7/login">Sign in</a>'
)


def test_email_evidence_covers_sender_domain_link_url_and_link_address(intel: ThreatIntel) -> None:
    evidence = email_evidence(intel, parse_email(EMAIL))

    assert all(e.kind is EvidenceKind.THREAT_INTEL_MATCH for e in evidence)
    text = " | ".join(e.description for e in evidence)
    assert "Sender domain evil.example is listed in ThreatFox (abuse.ch)" in text
    assert "Link URL http://evil.example/payload.exe" in text
    assert "Link address 198.51.100.7" in text
    assert len(evidence) <= 5


def test_a_clean_email_has_no_feed_evidence(intel: ThreatIntel) -> None:
    clean = parse_email(b"From: a@fine.example\r\nSubject: Hi\r\n\r\nhello")

    assert email_evidence(intel, clean) == []


def test_alerts_from_email_appends_intel_evidence_to_an_existing_alert(
    intel: ThreatIntel,
) -> None:
    classifier = build_pipeline().fit(
        PHISH_TEXTS + LEGIT_TEXTS, [1] * len(PHISH_TEXTS) + [0] * len(LEGIT_TEXTS)
    )
    watchlist = Watchlist(domains=frozenset({"evil.example"}))

    (alert,) = alerts_from_email(parse_email(EMAIL), classifier, watchlist, intel)

    kinds = [e.kind for e in alert.evidence]
    assert EvidenceKind.THREAT_INTEL_MATCH in kinds
    assert any(e.name == "known_bad_domain" for e in alert.evidence)


# --- storage: repeated uploads still de-duplicate across refreshes ----------


def test_a_repeat_after_a_refresh_is_still_a_duplicate(tmp_path: Path, store: IntelStore) -> None:
    alerts = AlertStore(tmp_path / "alerts.db")
    refresh.refresh_all(store, threatfox_key="k", fetch=FakeFeeds(), now=NOW)
    first = alerts.ingest(_log_candidates(ThreatIntel(store)), demo=False)

    refresh.refresh_all(
        store, threatfox_key="k", fetch=FakeFeeds(), now=NOW + timedelta(days=1), force=True
    )
    again = alerts.ingest(_log_candidates(ThreatIntel(store)), demo=False)

    assert first.duplicates == 0 and again.duplicates == 1
    assert again.alerts[0].id == first.alerts[0].id
    assert any(e.kind is EvidenceKind.THREAT_INTEL_MATCH for e in first.alerts[0].evidence)
