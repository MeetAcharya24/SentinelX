"""Read-side access to the indicator cache: addresses, hosts and URLs to cached matches."""

import ipaddress
from collections.abc import Iterable

from app.intel.store import CachedIoc, IntelStore

MIN_DOMAIN_LABELS = 2


def normalise_ip(value: str) -> str | None:
    try:
        return str(ipaddress.ip_address(value.strip().strip("[]")))
    except ValueError:
        return None


def domain_candidates(host: str) -> list[str]:
    """The host and each parent domain with at least two labels (`a.evil.test`, `evil.test`)."""
    labels = host.strip().lower().rstrip(".").split(".")
    return [
        ".".join(labels[start:])
        for start in range(len(labels))
        if len(labels) - start >= MIN_DOMAIN_LABELS
    ]


class ThreatIntel:
    """Looks things up in the cache; a missing store (or an empty cache) matches nothing."""

    def __init__(self, store: IntelStore | None = None) -> None:
        self._store = store

    def match_ips(self, addresses: Iterable[str]) -> dict[str, list[CachedIoc]]:
        """Cached matches per input address (keys are the strings passed in)."""
        if self._store is None:
            return {}
        normalised = {address: normalise_ip(address) for address in addresses}
        found = self._store.find("ip", [value for value in normalised.values() if value])
        by_value: dict[str, list[CachedIoc]] = {}
        for ioc in found:
            by_value.setdefault(ioc.value, []).append(ioc)
        return {
            address: by_value[value]
            for address, value in normalised.items()
            if value and value in by_value
        }

    def match_hosts(self, hosts: Iterable[str]) -> dict[str, list[CachedIoc]]:
        """Cached domain matches per host; a host also matches a listed parent domain."""
        if self._store is None:
            return {}
        candidates = {host: domain_candidates(host) for host in hosts}
        found = self._store.find(
            "domain", [name for names in candidates.values() for name in names]
        )
        by_value: dict[str, list[CachedIoc]] = {}
        for ioc in found:
            by_value.setdefault(ioc.value, []).append(ioc)
        matches = {
            host: [ioc for name in names for ioc in by_value.get(name, [])]
            for host, names in candidates.items()
        }
        return {host: iocs for host, iocs in matches.items() if iocs}

    def match_urls(self, urls: Iterable[str]) -> dict[str, list[CachedIoc]]:
        """Cached URL matches per URL (exact match on the stripped text)."""
        if self._store is None:
            return {}
        stripped = {url: url.strip() for url in urls}
        found = self._store.find("url", list(stripped.values()))
        by_value: dict[str, list[CachedIoc]] = {}
        for ioc in found:
            by_value.setdefault(ioc.value, []).append(ioc)
        return {url: by_value[value] for url, value in stripped.items() if value in by_value}
