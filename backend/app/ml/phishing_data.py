"""Loading the phishing training corpus from the local `data/phishing/` folder.

Phishing messages come from the mbox files of the Nazario phishing corpus;
legitimate ("ham") messages from the extracted SpamAssassin public corpus
folders. Both are downloaded by the operator (see the README) and never
committed. Only subject and visible body text are kept for modelling.
"""

import hashlib
import mailbox
from collections.abc import Iterator, Sequence
from contextlib import closing
from dataclasses import dataclass
from pathlib import Path

from app.ingestion.email import EmailParseError, parse_email

PHISHING_FOLDER = "phishing"
PHISHING_FILES: tuple[str, ...] = ("phishing0.mbox", "phishing1.mbox", "phishing2.mbox")
HAM_FOLDERS: tuple[str, ...] = ("easy_ham", "easy_ham_2", "hard_ham")
HAM_PARENT = "ham"
MIN_TEXT_CHARS = 20


class PhishingCorpusError(RuntimeError):
    """The corpus is missing or too incomplete to train on."""


@dataclass(frozen=True)
class PhishingCorpus:
    texts: tuple[str, ...]
    labels: tuple[int, ...]  # 1 = phishing, 0 = legitimate
    duplicates_removed: int
    unreadable: int


def _phishing_messages(path: Path) -> Iterator[bytes]:
    with closing(mailbox.mbox(path, create=False)) as corpus:
        for message in corpus:
            yield message.as_bytes()


def _ham_messages(folder: Path) -> Iterator[bytes]:
    for path in sorted(folder.iterdir()):
        if path.is_file():
            yield path.read_bytes()


def _usable_text(raw: bytes) -> str | None:
    try:
        text = parse_email(raw).model_text
    except EmailParseError:
        return None
    return text if len(text) >= MIN_TEXT_CHARS else None


def _collect(sources: Sequence[Iterator[bytes]], label: int) -> tuple[list[tuple[str, int]], int]:
    rows: list[tuple[str, int]] = []
    unreadable = 0
    for source in sources:
        for raw in source:
            text = _usable_text(raw)
            if text is None:
                unreadable += 1
            else:
                rows.append((text, label))
    return rows, unreadable


def _sources(data_dir: Path) -> tuple[list[Iterator[bytes]], list[Iterator[bytes]]]:
    root = data_dir / PHISHING_FOLDER
    phishing_paths = [root / name for name in PHISHING_FILES]
    ham_paths = [root / HAM_PARENT / name for name in HAM_FOLDERS]
    missing = [
        str(p.relative_to(data_dir)) for p in (*phishing_paths, *ham_paths) if not p.exists()
    ]
    if missing:
        raise PhishingCorpusError(
            "Missing corpus files: "
            + ", ".join(missing)
            + ". See 'Phishing corpus' in the README for the download step."
        )
    return [_phishing_messages(p) for p in phishing_paths], [_ham_messages(p) for p in ham_paths]


def load_corpus(data_dir: Path) -> PhishingCorpus:
    """Reads both classes, drops messages with the same text, and reports what was skipped.

    Phishing campaigns resend one template many times, so duplicates are removed
    before any train/test split to keep copies of one message out of both sides.
    """
    phishing_sources, ham_sources = _sources(data_dir)
    phishing_rows, phishing_bad = _collect(phishing_sources, 1)
    ham_rows, ham_bad = _collect(ham_sources, 0)

    seen: set[str] = set()
    kept: list[tuple[str, int]] = []
    for text, label in phishing_rows + ham_rows:
        digest = hashlib.sha256(text.casefold().encode("utf-8")).hexdigest()
        if digest not in seen:
            seen.add(digest)
            kept.append((text, label))
    return PhishingCorpus(
        texts=tuple(text for text, _ in kept),
        labels=tuple(label for _, label in kept),
        duplicates_removed=len(phishing_rows) + len(ham_rows) - len(kept),
        unreadable=phishing_bad + ham_bad,
    )
