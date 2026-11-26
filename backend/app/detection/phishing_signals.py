"""Transparent, rule-based phishing signals read from a parsed email.

Each signal names a specific observation and quotes only what was observed. The
rules do not decide the verdict; they are the evidence shown next to it.
"""

import re
from dataclasses import dataclass
from enum import StrEnum
from ipaddress import ip_address

from app.ingestion.email import Link, ParsedEmail

MAX_EXAMPLES = 3
_MAX_EXAMPLE_LENGTH = 80

_URGENCY = re.compile(
    r"\b(urgent(ly)?|immediately|within \d+ (hours?|days?)|act now|final notice|"
    r"suspended|will be (closed|locked|terminated)|limited time|expires?)\b",
    re.IGNORECASE,
)
_CREDENTIALS = re.compile(
    r"\b(verify your (account|identity)|confirm your (account|identity|password)|"
    r"update your (account|billing|payment)|password|pin number|social security|"
    r"log ?in to|sign ?in to|bank account|credit card)\b",
    re.IGNORECASE,
)
_RISKY_EXTENSIONS = (
    ".exe", ".scr", ".bat", ".cmd", ".com", ".pif", ".js", ".vbs", ".jar", ".msi", ".lnk",
    ".iso", ".html", ".htm", ".docm", ".xlsm",
)  # fmt: skip
_URL_SHORTENERS = frozenset({"bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd"})
_URL_IN_TEXT = re.compile(r"https?://|www\.", re.IGNORECASE)


class Severity(StrEnum):
    INFO = "info"
    SUSPICIOUS = "suspicious"


@dataclass(frozen=True)
class Signal:
    code: str
    severity: Severity
    description: str
    # Short quotes or values that triggered it, at most MAX_EXAMPLES.
    examples: tuple[str, ...] = ()


def _clip(value: str) -> str:
    return value if len(value) <= _MAX_EXAMPLE_LENGTH else value[: _MAX_EXAMPLE_LENGTH - 1] + "…"


def _domain(address: str) -> str:
    return address.rsplit("@", 1)[-1] if "@" in address else ""


def _is_ip_literal(host: str) -> bool:
    try:
        ip_address(host.strip("[]"))
    except ValueError:
        return False
    return True


def _registered_part(host: str) -> str:
    """Last two labels: a rough stand-in for the registrable domain, with no suffix list."""
    labels = host.split(".")
    return ".".join(labels[-2:])


def _reply_to_mismatch(email: ParsedEmail) -> list[Signal]:
    sender, reply = _domain(email.from_address), _domain(email.reply_to_address)
    if sender and reply and _registered_part(sender) != _registered_part(reply):
        return [
            Signal(
                "reply_to_mismatch",
                Severity.SUSPICIOUS,
                "Replies go to a different domain than the sender's.",
                (f"from {sender}", f"reply-to {reply}"),
            )
        ]
    return []


def _link_signals(links: tuple[Link, ...]) -> list[Signal]:
    signals: list[Signal] = []
    ip_hosts = [link.host for link in links if _is_ip_literal(link.host)]
    if ip_hosts:
        signals.append(
            Signal(
                "ip_address_link",
                Severity.SUSPICIOUS,
                "A link points to a raw IP address instead of a domain name.",
                tuple(_clip(host) for host in dict.fromkeys(ip_hosts))[:MAX_EXAMPLES],
            )
        )
    mismatched = [
        f"shows {_clip(link.text)} → goes to {_clip(link.host)}"
        for link in links
        if _URL_IN_TEXT.search(link.text)
        and link.host
        and _shown_host(link.text) not in ("", link.host)
        and _registered_part(_shown_host(link.text)) != _registered_part(link.host)
    ]
    if mismatched:
        signals.append(
            Signal(
                "link_text_mismatch",
                Severity.SUSPICIOUS,
                "The visible text of a link names a different site than the one it opens.",
                tuple(mismatched[:MAX_EXAMPLES]),
            )
        )
    shortened = [link.host for link in links if link.host in _URL_SHORTENERS]
    if shortened:
        signals.append(
            Signal(
                "url_shortener",
                Severity.INFO,
                "A link uses a URL shortener, which hides its destination.",
                tuple(dict.fromkeys(shortened))[:MAX_EXAMPLES],
            )
        )
    return signals


def _shown_host(text: str) -> str:
    match = re.search(r"(?:https?://)?((?:[\w-]+\.)+[a-z]{2,})", text, re.IGNORECASE)
    return match.group(1).lower() if match else ""


def _wording_signals(email: ParsedEmail) -> list[Signal]:
    text = email.model_text
    signals: list[Signal] = []
    for code, pattern, description in (
        ("urgency_language", _URGENCY, "The text pressures the reader to act quickly."),
        (
            "credential_request",
            _CREDENTIALS,
            "The text asks for, or points to, account or payment details.",
        ),
    ):
        found = list(dict.fromkeys(m.group(0).lower() for m in pattern.finditer(text)))
        if found:
            signals.append(
                Signal(code, Severity.SUSPICIOUS, description, tuple(found[:MAX_EXAMPLES]))
            )
    return signals


def _attachment_signals(email: ParsedEmail) -> list[Signal]:
    risky = [name for name in email.attachment_names if name.lower().endswith(_RISKY_EXTENSIONS)]
    if not risky:
        return []
    return [
        Signal(
            "risky_attachment",
            Severity.SUSPICIOUS,
            "An attachment has a file type that can run code or open a web page.",
            tuple(_clip(name) for name in risky[:MAX_EXAMPLES]),
        )
    ]


def extract_signals(email: ParsedEmail) -> list[Signal]:
    return [
        *_reply_to_mismatch(email),
        *_link_signals(email.links),
        *_wording_signals(email),
        *_attachment_signals(email),
    ]
