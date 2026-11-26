"""Clients and parsers for the two abuse.ch feeds.

Feodo Tracker's recommended botnet C2 address list needs no key; ThreatFox needs a
free Auth-Key from auth.abuse.ch. Both are fetched with one request per refresh.
Parsing is separate from the network call and tolerant of single bad records: a
malformed item is skipped, a malformed document is an error.

Terms: https://abuse.ch/terms-of-use/ (fair use for ThreatFox, CC0 for Feodo Tracker).
"""

import ipaddress
import json
import urllib.error
import urllib.request
from collections.abc import Callable
from datetime import UTC, datetime
from urllib.parse import urlsplit

from app.intel.store import Ioc

FEODO_SOURCE = "feodo_tracker"
THREATFOX_SOURCE = "threatfox"
FEED_LABELS = {
    FEODO_SOURCE: "Feodo Tracker (abuse.ch)",
    THREATFOX_SOURCE: "ThreatFox (abuse.ch)",
}

FEODO_URL = "https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json"
THREATFOX_URL = "https://threatfox-api.abuse.ch/api/v1/"
# The API serves at most seven days of indicators per call.
THREATFOX_DAYS = 7

REQUEST_TIMEOUT_SECONDS = 30
# A live seven-day ThreatFox response was 15.9 MB on 2026-11-26 (it includes hash indicators).
MAX_RESPONSE_BYTES = 64 * 1024 * 1024
MAX_URL_CHARS = 2048
_USER_AGENT = "SentinelX-threat-intel-refresh"

# (url, headers, request body or None) -> response body. Replaced in tests.
Fetcher = Callable[[str, dict[str, str], bytes | None], bytes]


class FeedError(Exception):
    """A feed could not be fetched or its response was not usable."""


def http_fetch(url: str, headers: dict[str, str], body: bytes | None) -> bytes:
    """One HTTPS request (POST when there is a body), with a timeout and a size cap."""
    if urlsplit(url).scheme != "https":
        raise FeedError("feeds are only fetched over https")
    request = urllib.request.Request(  # noqa: S310 - scheme checked above
        url, data=body, headers={"User-Agent": _USER_AGENT, **headers}
    )
    try:
        with urllib.request.urlopen(request, timeout=REQUEST_TIMEOUT_SECONDS) as response:  # noqa: S310
            content = response.read(MAX_RESPONSE_BYTES + 1)
    except urllib.error.HTTPError as error:
        raise FeedError(f"the feed answered HTTP {error.code}") from error
    except (urllib.error.URLError, TimeoutError, OSError) as error:
        raise FeedError(f"the feed could not be reached: {error}") from error
    if len(content) > MAX_RESPONSE_BYTES:
        raise FeedError("the feed response is larger than the allowed size")
    return content


def _load_json(raw: bytes) -> object:
    try:
        return json.loads(raw)
    except ValueError as error:
        raise FeedError("the feed response is not valid JSON") from error


def _timestamp(value: object) -> datetime | None:
    """`2026-01-12 09:15:00` or `... UTC`, read as UTC; anything else is unknown."""
    if not isinstance(value, str):
        return None
    text = value.removesuffix(" UTC").strip()
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    return parsed.replace(tzinfo=UTC) if parsed.tzinfo is None else parsed.astimezone(UTC)


def _address(value: object) -> str | None:
    if not isinstance(value, str):
        return None
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def _label(value: object) -> str | None:
    return value.strip()[:80] or None if isinstance(value, str) else None


def fetch_feodo(fetch: Fetcher) -> list[Ioc]:
    return parse_feodo(fetch(FEODO_URL, {}, None))


def parse_feodo(raw: bytes) -> list[Ioc]:
    """Botnet C2 addresses from Feodo Tracker's recommended list (a JSON array, possibly empty)."""
    document = _load_json(raw)
    if not isinstance(document, list):
        raise FeedError("the Feodo Tracker list is not a JSON array")
    iocs: dict[str, Ioc] = {}
    for item in document:
        if not isinstance(item, dict):
            continue
        address = _address(item.get("ip_address"))
        if address is None:
            continue
        iocs[address] = Ioc(
            ioc_type="ip",
            value=address,
            first_seen=_timestamp(item.get("first_seen")),
            malware=_label(item.get("malware")),
        )
    return list(iocs.values())


def fetch_threatfox(fetch: Fetcher, auth_key: str) -> list[Ioc]:
    body = json.dumps({"query": "get_iocs", "days": THREATFOX_DAYS}).encode("utf-8")
    raw = fetch(THREATFOX_URL, {"Auth-Key": auth_key, "Content-Type": "application/json"}, body)
    return parse_threatfox(raw)


def _threatfox_value(ioc_type: object, value: object) -> tuple[str, str] | None:
    """(our type, normalised value) for an `ip:port`, `domain` or `url` indicator."""
    if not isinstance(ioc_type, str) or not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if ioc_type == "ip:port":
        address = _address(text.rpartition(":")[0] if ":" in text else text)
        return ("ip", address) if address else None
    if ioc_type == "domain":
        return ("domain", text.lower().rstrip("."))
    if ioc_type == "url" and len(text) <= MAX_URL_CHARS:
        return ("url", text)
    return None


def _strength(ioc: Ioc) -> tuple[int, datetime]:
    """Ranks records for one indicator: higher confidence wins, newer first_seen breaks a tie.

    A record with no confidence ranks below any with one; one with no first_seen ranks
    oldest. Equal on both, the record that appeared first in the response is kept, so
    the result does not depend on response order except for exact ties.
    """
    return (
        ioc.confidence if ioc.confidence is not None else -1,
        ioc.first_seen or datetime.min.replace(tzinfo=UTC),
    )


def parse_threatfox(raw: bytes) -> list[Ioc]:
    """IP, domain and URL indicators from a ThreatFox `get_iocs` response.

    One address listed on several ports (and any repeated domain or URL) becomes one
    indicator: the record with the highest `confidence_level`, ties going to the most
    recent `first_seen`; its malware family and first_seen are the ones stored.

    File hashes are ignored: SentinelX has no file inputs to match them against.
    A response with no data is an empty list; any other non-`ok` status is an error.
    """
    document = _load_json(raw)
    if not isinstance(document, dict):
        raise FeedError("the ThreatFox response is not a JSON object")
    status = document.get("query_status")
    if status == "no_result":
        return []
    if status != "ok":
        raise FeedError(f"ThreatFox answered query_status {status!r}")
    data = document.get("data")
    if not isinstance(data, list):
        raise FeedError("the ThreatFox response has no data list")
    iocs: dict[tuple[str, str], Ioc] = {}
    for item in data:
        if not isinstance(item, dict):
            continue
        parsed = _threatfox_value(item.get("ioc_type"), item.get("ioc"))
        if parsed is None:
            continue
        confidence = item.get("confidence_level")
        candidate = Ioc(
            ioc_type=parsed[0],
            value=parsed[1],
            first_seen=_timestamp(item.get("first_seen")),
            malware=_label(item.get("malware_printable")),
            confidence=confidence
            if isinstance(confidence, int) and 0 <= confidence <= 100
            else None,
        )
        current = iocs.get(parsed)
        if current is None or _strength(candidate) > _strength(current):
            iocs[parsed] = candidate
    return list(iocs.values())
