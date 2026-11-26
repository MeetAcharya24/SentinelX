"""Threat-intelligence enrichment: cached feed matches become `threat_intel_match` evidence.

This runs next to the operator-supplied known-bad lists, not instead of them, and it
only adds evidence to alerts that already exist. It never changes severity or
confidence: the feeds differ in quality and age, so the analyst weighs the match.
"""

from collections.abc import Sequence
from dataclasses import replace
from datetime import datetime

from app.detection.alerts import AlertCandidate, Evidence, EvidenceKind
from app.ingestion.email import ParsedEmail
from app.intel.feeds import FEED_LABELS
from app.intel.lookup import ThreatIntel, normalise_ip
from app.intel.store import CachedIoc

MAX_INTEL_EVIDENCE = 5
_KIND_WORDS = {"ip": "address", "domain": "domain", "url": "URL"}


def _utc(value: datetime | None) -> str:
    return value.strftime("%Y-%m-%d %H:%M UTC") if value else "unknown"


def match_evidence(subject: str, matched: str, ioc: CachedIoc) -> Evidence:
    """One evidence entry: what matched, which feed, and when the cache was last refreshed."""
    feed = FEED_LABELS.get(ioc.source, ioc.source)
    listed = (
        f"{matched} is listed"
        if matched == ioc.value
        else (f"{matched} falls under the listed {_KIND_WORDS[ioc.ioc_type]} {ioc.value}")
    )
    malware = f" Associated malware: {ioc.malware}." if ioc.malware else ""
    description = (
        f"{subject} {listed} in {feed}.{malware} First seen {_utc(ioc.first_seen)}. "
        f"Cache last refreshed {_utc(ioc.feed_refreshed_at)}."
    )
    return Evidence(
        EvidenceKind.THREAT_INTEL_MATCH,
        ioc.source,
        description,
        float(ioc.confidence) if ioc.confidence is not None else None,
        (ioc.value,),
    )


def source_address_evidence(
    intel: ThreatIntel, addresses: Sequence[str]
) -> dict[str, list[Evidence]]:
    """Evidence per source address that has a cached match."""
    return {
        address: [match_evidence("Source address", address, ioc) for ioc in iocs]
        for address, iocs in intel.match_ips(addresses).items()
    }


def enrich_log_candidates(
    candidates: Sequence[AlertCandidate], intel: ThreatIntel
) -> list[AlertCandidate]:
    """Adds feed matches to alerts whose source is an address found in the cache."""
    by_address = source_address_evidence(
        intel, [c.source for c in candidates if normalise_ip(c.source)]
    )
    return [
        replace(c, evidence=(*c.evidence, *by_address[c.source][:MAX_INTEL_EVIDENCE]))
        if c.source in by_address
        else c
        for c in candidates
    ]


def email_evidence(intel: ThreatIntel, email: ParsedEmail) -> list[Evidence]:
    """Feed matches for the sender's domain and every link's host and address."""
    sender_domain = email.from_address.rsplit("@", 1)[-1] if "@" in email.from_address else ""
    link_hosts = [link.host for link in email.links if link.host]
    hosts = list(dict.fromkeys(h for h in [sender_domain, *link_hosts] if h))
    addresses = [h for h in hosts if normalise_ip(h)]
    domains = [h for h in hosts if h not in addresses]
    evidence: list[Evidence] = []
    for host, iocs in intel.match_hosts(domains).items():
        label = "Sender domain" if host == sender_domain else "Link host"
        evidence.extend(match_evidence(label, host, ioc) for ioc in iocs)
    for address, iocs in intel.match_ips(addresses).items():
        evidence.extend(match_evidence("Link address", address, ioc) for ioc in iocs)
    urls = list(dict.fromkeys(link.url for link in email.links))
    for url, iocs in intel.match_urls(urls).items():
        evidence.extend(match_evidence("Link URL", url, ioc) for ioc in iocs)
    return evidence[:MAX_INTEL_EVIDENCE]


def with_evidence(candidate: AlertCandidate, extra: Sequence[Evidence]) -> AlertCandidate:
    return replace(candidate, evidence=(*candidate.evidence, *extra)) if extra else candidate
