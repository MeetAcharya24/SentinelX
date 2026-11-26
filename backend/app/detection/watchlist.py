"""Operator-supplied lists of known-bad addresses and domains.

The lists are plain text files, one entry per line (`#` starts a comment), read
from the blocklist folder: `bad_ips.txt` (addresses or CIDR ranges) and
`bad_domains.txt`. SentinelX ships no real threat intelligence; with no files the
rules simply never match. Bad entries are skipped and counted, not fatal.
"""

import logging
from dataclasses import dataclass, field
from ipaddress import IPv4Network, IPv6Network, ip_address, ip_network
from pathlib import Path

logger = logging.getLogger("sentinelx.watchlist")

IP_FILENAME = "bad_ips.txt"
DOMAIN_FILENAME = "bad_domains.txt"

_Network = IPv4Network | IPv6Network


@dataclass(frozen=True)
class Watchlist:
    networks: tuple[_Network, ...] = ()
    domains: frozenset[str] = field(default_factory=frozenset)

    def match_ip(self, address: str) -> str | None:
        """The listed entry containing this address, or None."""
        try:
            parsed = ip_address(address.strip("[]"))
        except ValueError:
            return None
        for network in self.networks:
            if parsed.version == network.version and parsed in network:
                return str(network)
        return None

    def match_domain(self, host: str) -> str | None:
        """The listed domain this host is or sits under (`a.evil.test` matches `evil.test`)."""
        labels = host.lower().rstrip(".").split(".")
        for start in range(len(labels)):
            candidate = ".".join(labels[start:])
            if candidate in self.domains:
                return candidate
        return None


def _entries(path: Path) -> list[str]:
    if not path.is_file():
        return []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    stripped = (line.split("#", 1)[0].strip() for line in lines)
    return [line for line in stripped if line]


def _valid_domain(entry: str) -> bool:
    labels = entry.split(".")
    return len(labels) >= 2 and all(
        label and label.replace("-", "").isalnum() and not label.startswith("-") for label in labels
    )


def load_watchlist(directory: Path) -> Watchlist:
    networks: list[_Network] = []
    skipped = 0
    for entry in _entries(directory / IP_FILENAME):
        try:
            networks.append(ip_network(entry, strict=False))
        except ValueError:
            skipped += 1
    domains: set[str] = set()
    for entry in _entries(directory / DOMAIN_FILENAME):
        lowered = entry.lower().rstrip(".")
        if _valid_domain(lowered):
            domains.add(lowered)
        else:
            skipped += 1
    if skipped:
        logger.warning("Skipped %d invalid blocklist entries in %s", skipped, directory)
    return Watchlist(networks=tuple(networks), domains=frozenset(domains))
