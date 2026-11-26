"""Parsing a pasted or uploaded email into the parts the phishing checks read.

Nothing is fetched or executed: links are only read as text, and attachments
are only listed by file name.
"""

import re
from dataclasses import dataclass
from email import message_from_bytes, policy
from email.message import EmailMessage
from html.parser import HTMLParser
from urllib.parse import urlsplit

MAX_LINKS = 200
_URL_PATTERN = re.compile(r"https?://[^\s<>\"')\]]+", re.IGNORECASE)
_SKIPPED_HTML_TAGS = frozenset({"script", "style", "head"})
_WHITESPACE = re.compile(r"\s+")


class EmailParseError(ValueError):
    """The input is empty or has nothing that can be read as an email."""


@dataclass(frozen=True)
class Link:
    url: str
    # Text the reader sees for the link; empty for plain-text URLs.
    text: str

    @property
    def host(self) -> str:
        try:
            return (urlsplit(self.url).hostname or "").lower()
        except ValueError:
            return ""


@dataclass(frozen=True)
class ParsedEmail:
    subject: str
    from_address: str
    reply_to_address: str
    body_text: str
    links: tuple[Link, ...]
    attachment_names: tuple[str, ...]

    @property
    def model_text(self) -> str:
        """What the text model reads: subject and visible body, no headers."""
        return f"{self.subject}\n{self.body_text}".strip()


class _HtmlText(HTMLParser):
    """Collects visible text and links from an HTML body."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.links: list[Link] = []
        self._skip_depth = 0
        self._href: str | None = None
        self._anchor_parts: list[str] = []

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        if tag in _SKIPPED_HTML_TAGS:
            self._skip_depth += 1
        elif tag == "a":
            self._href = dict(attrs).get("href")
            self._anchor_parts = []

    def handle_endtag(self, tag: str) -> None:
        if tag in _SKIPPED_HTML_TAGS and self._skip_depth:
            self._skip_depth -= 1
        elif tag == "a" and self._href is not None:
            text = _WHITESPACE.sub(" ", "".join(self._anchor_parts)).strip()
            self.links.append(Link(url=self._href.strip(), text=text))
            self._href = None

    def handle_data(self, data: str) -> None:
        if self._skip_depth:
            return
        self.parts.append(data)
        if self._href is not None:
            self._anchor_parts.append(data)


def _bare_address(header_value: object) -> str:
    match = re.search(r"[\w.+-]+@[\w.-]+", str(header_value or ""))
    return match.group(0).lower() if match else ""


def _body_parts(message: EmailMessage) -> tuple[str, str]:
    plain = message.get_body(preferencelist=("plain",))
    html = message.get_body(preferencelist=("html",))
    return _content(plain), _content(html)


def _content(part: EmailMessage | None) -> str:
    if part is None:
        return ""
    try:
        return str(part.get_content())
    except (LookupError, ValueError):
        # Unknown or broken charset: fall back to a lossy decode instead of failing.
        payload = part.get_payload(decode=True)
        return payload.decode("utf-8", errors="replace") if isinstance(payload, bytes) else ""


def _attachment_names(message: EmailMessage) -> tuple[str, ...]:
    names = [part.get_filename() for part in message.iter_attachments()]
    return tuple(name for name in names if name)


def parse_email(raw: bytes) -> ParsedEmail:
    """Reads a raw RFC 822 message, or a bare body with no headers."""
    if not raw.strip():
        raise EmailParseError("The email is empty.")
    message = message_from_bytes(raw, policy=policy.default)
    assert isinstance(message, EmailMessage)  # noqa: S101 - policy.default always yields this
    plain, html = _body_parts(message)
    if not message.keys() and not plain:
        # No headers at all: treat the whole input as the message text.
        plain = raw.decode("utf-8", errors="replace")

    html_reader = _HtmlText()
    if html:
        html_reader.feed(html)
    body_text = _WHITESPACE.sub(" ", plain or " ".join(html_reader.parts)).strip()
    if not body_text and not message.get("subject"):
        raise EmailParseError("The email has no readable text.")

    links = list(html_reader.links)
    known = {link.url for link in links}
    for url in _URL_PATTERN.findall(plain):
        if url not in known:
            links.append(Link(url=url, text=""))
    return ParsedEmail(
        subject=str(message.get("subject", "") or "").strip(),
        from_address=_bare_address(message.get("from")),
        reply_to_address=_bare_address(message.get("reply-to")),
        body_text=body_text,
        links=tuple(links[:MAX_LINKS]),
        attachment_names=_attachment_names(message),
    )
