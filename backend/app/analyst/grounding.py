"""What the analyst may talk about, and the checks that keep it to that.

An alert is reduced to a `AlertView`: a few alert fields plus its stored evidence, each
evidence item under a stable key. Every statement the analyst produces must cite keys
from that view (`alert:<field>` or `evidence:<key>`). `validate_content` enforces this
for every provider, hosted or built-in, and rejects what it cannot trace.

The checks are deliberately mechanical and partial. They prove that citations exist
and that no address or hostname appears that is not in the alert, and they refuse
first-person claims of actions taken. They cannot prove a sentence is a faithful
reading of the evidence it cites; that is why the cited keys are shown to the analyst.
Evidence text can contain attacker-controlled content (an email subject, a URL), so
it is always passed to a model as data and never trusted as instructions.
"""

import hashlib
import json
import re
import unicodedata
from dataclasses import dataclass
from typing import Annotated

from pydantic import BaseModel, Field, StringConstraints

from app.detection.alerts import Evidence
from app.storage.alerts import StoredAlert

ALERT_FIELDS = ("title", "severity", "confidence", "category", "source", "asset", "occurred_at")
MAX_FINDINGS = 8
MAX_CHECKS = 5
MAX_TEXT_CHARS = 700
_PROMPT_DESCRIPTION_CHARS = 600
_PROMPT_EXAMPLE_CHARS = 200
_PROMPT_EXAMPLES = 5

Text = Annotated[
    str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_TEXT_CHARS)
]
Cites = Annotated[list[str], Field(min_length=1, max_length=12)]


class Finding(BaseModel):
    statement: Text
    cites: Cites


class Check(BaseModel):
    text: Text
    cites: Cites


class AnalysisContent(BaseModel):
    """The narrative itself, as a provider produces it."""

    summary: Finding
    findings: Annotated[list[Finding], Field(max_length=MAX_FINDINGS)]
    limits: Annotated[list[Text], Field(max_length=MAX_FINDINGS)]
    suggested_checks: Annotated[list[Check], Field(max_length=MAX_CHECKS)]


class GroundingError(ValueError):
    """A provider's output cites something that is not in the alert, or breaks a rule."""


@dataclass(frozen=True)
class EvidenceRef:
    key: str
    evidence: Evidence


@dataclass(frozen=True)
class AlertView:
    fields: dict[str, str | int]
    evidence: tuple[EvidenceRef, ...]

    @property
    def valid_cites(self) -> frozenset[str]:
        return frozenset(
            [f"alert:{name}" for name in self.fields]
            + [f"evidence:{ref.key}" for ref in self.evidence]
        )

    @property
    def corpus(self) -> str:
        """Every string the analyst is allowed to repeat, lower-cased for matching."""
        parts: list[str] = [str(value) for value in self.fields.values()]
        for ref in self.evidence:
            parts += [ref.key, ref.evidence.description, *ref.evidence.examples]
        return "\n".join(parts).lower()

    def content_hash(self) -> str:
        """Identity of what the analyst saw; changes when the alert's evidence does."""
        return hashlib.sha256(json.dumps(self.for_prompt(), sort_keys=True).encode()).hexdigest()

    def for_prompt(self) -> dict[str, object]:
        """Compact, size-bounded form given to a model."""
        return {
            "alert": self.fields,
            "evidence": [
                {
                    "key": ref.key,
                    "kind": ref.evidence.kind.value,
                    "description": ref.evidence.description[:_PROMPT_DESCRIPTION_CHARS],
                    "value": ref.evidence.value,
                    "examples": [e[:_PROMPT_EXAMPLE_CHARS] for e in ref.evidence.examples][
                        :_PROMPT_EXAMPLES
                    ],
                }
                for ref in self.evidence
            ],
        }


def build_view(alert: StoredAlert) -> AlertView:
    """Alert fields and evidence under stable keys; analyst notes and status are left out."""
    fields: dict[str, str | int] = {
        "title": alert.title,
        "severity": alert.severity.value,
        "confidence": alert.confidence,
        "category": alert.category.value,
        "source": alert.source,
    }
    if alert.asset:
        fields["asset"] = alert.asset
    if alert.occurred_at:
        fields["occurred_at"] = alert.occurred_at.isoformat()
    seen: dict[str, int] = {}
    refs: list[EvidenceRef] = []
    for item in alert.evidence:
        seen[item.name] = seen.get(item.name, 0) + 1
        key = item.name if seen[item.name] == 1 else f"{item.name}#{seen[item.name]}"
        refs.append(EvidenceRef(key, item))
    return AlertView(fields=fields, evidence=tuple(refs))


_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_HOSTNAME = re.compile(r"\b[a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9-]+)*\.[a-z]{2,}\b", re.I)
_ACTION_CLAIM = re.compile(
    r"\b(?:i|we)(?:'ve| have)?\s+(?:already\s+)?"
    r"(?:blocked|isolated|quarantined|disabled|reset|changed|updated|escalated|contacted|"
    r"notified|scanned|removed|deleted|closed|resolved|marked)\b",
    re.I,
)


# Hedged inference ("suggesting", "likely", "may be") reads as analysis but is not in the
# evidence. Refused in model-written summary and findings; the built-in text only restates
# stored descriptions, so it is exempt.
_INFERENCE = re.compile(
    r"\b(?:indicat(?:es|ing|ed)|suggest(?:s|ing|ed)|impl(?:y|ies|ying)|likely|unlikely|"
    r"probabl[ey]|possibl[ey]|potential(?:ly)?|presumably|appears? to|seems? to|"
    r"may be|might be|could be|intended|attempt(?:s|ing)? to)\b",
    re.I,
)
_DASHES = re.compile("[\u2010-\u2015\u2212]")


def _plain(text: str) -> str:
    """NFKC and ASCII hyphens, so look-alike characters cannot hide an address or hostname."""
    return _DASHES.sub("-", unicodedata.normalize("NFKC", text))


def _texts(content: AnalysisContent) -> list[str]:
    return [
        content.summary.statement,
        *(finding.statement for finding in content.findings),
        *content.limits,
        *(check.text for check in content.suggested_checks),
    ]


def validate_content(content: AnalysisContent, view: AlertView, *, hosted: bool = False) -> None:
    """Raises GroundingError unless every statement is cited, traceable and passive.

    `hosted` adds the refusal of hedged inference in the summary and findings."""
    valid = view.valid_cites
    cited = [
        ("summary", content.summary.cites),
        *((f"finding {i}", f.cites) for i, f in enumerate(content.findings, start=1)),
        *((f"check {i}", c.cites) for i, c in enumerate(content.suggested_checks, start=1)),
    ]
    for label, cites in cited:
        unknown = [cite for cite in cites if cite not in valid]
        if unknown:
            raise GroundingError(f"{label} cites something not in the alert: {unknown}")
    if hosted:
        narrative = [content.summary.statement, *(f.statement for f in content.findings)]
        for text in narrative:
            match = _INFERENCE.search(_plain(text))
            if match:
                raise GroundingError(
                    f"the narrative infers beyond the evidence ({match.group(0)!r})"
                )
    corpus = view.corpus
    for text in map(_plain, _texts(content)):
        if _ACTION_CLAIM.search(text):
            raise GroundingError("the text claims an action was taken")
        for token in [*_IPV4.findall(text), *_HOSTNAME.findall(text)]:
            if token.lower() not in corpus:
                raise GroundingError(f"the text mentions {token!r}, which is not in the alert")
