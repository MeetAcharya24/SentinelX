"""Built-in analyst: a templated explanation written from the alert's own evidence.

No model and no network. It is the fallback whenever no hosted provider is configured
or the hosted one fails, and it must satisfy the same citation rules: every sentence
is built from stored fields and cites the keys it used.
"""

from app.analyst.grounding import (
    MAX_FINDINGS,
    AlertView,
    AnalysisContent,
    Check,
    EvidenceRef,
    Finding,
)
from app.detection.alerts import EvidenceKind

PROVIDER_ID = "built-in-v1"

# Order the evidence kinds are explained in: concrete matches before statistics.
_KIND_ORDER = (
    EvidenceKind.RULE_MATCH,
    EvidenceKind.THREAT_INTEL_MATCH,
    EvidenceKind.MODEL_SCORE,
    EvidenceKind.PHISHING_SIGNAL,
)
_KIND_NAMES = {
    EvidenceKind.RULE_MATCH: "rule match",
    EvidenceKind.THREAT_INTEL_MATCH: "threat-intelligence match",
    EvidenceKind.MODEL_SCORE: "model score",
    EvidenceKind.PHISHING_SIGNAL: "email signal",
}

# General defensive guidance per category; every check names the alert field it rests on.
_CHECKS = {
    "brute_force": "Review the targeted accounts' activity after the failed logins and "
    "confirm none of them was accessed from the same source.",
    "known_bad_source": "Look for other activity from this address in your own logs; "
    "whether to block it is an operator decision.",
    "network_anomaly": "Compare this flow with what is normal for the hosts involved "
    "before treating it as hostile; the models are statistical.",
    "suspicious_activity": "Confirm with whoever owns the change that the activity was authorised.",
    "phishing": "Do not open the links or attachments; check the sender and link domains "
    "with your mail administrators and report the message through your usual process.",
}


def _statement(ref: EvidenceRef) -> str:
    item = ref.evidence
    text = item.description.strip()
    extra = [example for example in item.examples if example.lower() not in text.lower()]
    return f"{text} ({', '.join(extra[:3])})" if extra else text


def _summary(view: AlertView) -> Finding:
    fields = view.fields
    asset = f", affecting {fields['asset']}" if "asset" in fields else ""
    when = f", occurring at {fields['occurred_at']}" if "occurred_at" in fields else ""
    return Finding(
        statement=(
            f"{fields['title']}. This is a {fields['severity']}-severity "
            f"{str(fields['category']).replace('_', ' ')} alert at {fields['confidence']}% "
            f"confidence from source {fields['source']}{asset}{when}."
        ),
        cites=[f"alert:{name}" for name in fields],
    )


def _findings(view: AlertView) -> tuple[list[Finding], list[EvidenceRef]]:
    """One finding per concrete evidence item, model terms grouped; returns what was left out."""
    findings: list[Finding] = []
    covered: list[EvidenceRef] = []
    for kind in _KIND_ORDER:
        for ref in (r for r in view.evidence if r.evidence.kind is kind):
            findings.append(Finding(statement=_statement(ref), cites=[f"evidence:{ref.key}"]))
            covered.append(ref)
    terms = [r for r in view.evidence if r.evidence.kind is EvidenceKind.MODEL_TERM]
    if terms:
        names = ", ".join(ref.evidence.name for ref in terms)
        findings.append(
            Finding(
                statement="Terms in the message that pushed the classifier towards phishing: "
                f"{names}.",
                cites=[f"evidence:{ref.key}" for ref in terms],
            )
        )
        covered.extend(terms)
    kinds = {ref.evidence.kind for ref in covered if ref.evidence.kind in _KIND_NAMES}
    if len(kinds) > 1:
        names = " and ".join(_KIND_NAMES[kind] for kind in _KIND_ORDER if kind in kinds)
        keys = [f"evidence:{ref.key}" for ref in covered if ref.evidence.kind in kinds]
        findings.append(
            Finding(
                statement=f"More than one kind of evidence supports this alert: {names}.",
                cites=keys[:12],
            )
        )
    return findings[:MAX_FINDINGS], covered[MAX_FINDINGS:]


def _limits(view: AlertView, left_out: list[EvidenceRef]) -> list[str]:
    substantive = [r for r in view.evidence if r.evidence.kind is not EvidenceKind.CAVEAT]
    limits: list[str] = []
    if not substantive:
        limits.append(
            "This alert has no stored evidence, so only its title, severity, confidence, "
            "category and source can be explained."
        )
    elif len(substantive) == 1:
        limits.append(
            "Only one evidence item supports this alert, so this explanation cannot say more "
            "than that item does."
        )
    limits.extend(
        ref.evidence.description
        for ref in view.evidence
        if ref.evidence.kind is EvidenceKind.CAVEAT
    )
    if left_out:
        limits.append(
            f"{len(left_out)} further evidence item(s) are not summarised here: "
            + ", ".join(ref.key for ref in left_out)
            + "."
        )
    limits.append(
        "This explanation covers only the stored alert and its evidence; it has not seen "
        "other logs or traffic."
    )
    return limits[:MAX_FINDINGS]


def _checks(view: AlertView) -> list[Check]:
    checks: list[Check] = []
    category = str(view.fields["category"])
    if category in _CHECKS:
        checks.append(Check(text=_CHECKS[category], cites=["alert:category", "alert:source"]))
    intel = [r for r in view.evidence if r.evidence.kind is EvidenceKind.THREAT_INTEL_MATCH]
    if intel:
        checks.append(
            Check(
                text="Treat the feed match as a lead, not proof: feeds can list shared or "
                "recycled addresses, so confirm it in your own telemetry.",
                cites=[f"evidence:{ref.key}" for ref in intel[:3]],
            )
        )
    return checks


class DeterministicAnalyst:
    id = PROVIDER_ID
    model: str | None = None

    def generate(self, view: AlertView) -> AnalysisContent:
        findings, left_out = _findings(view)
        if not findings:
            findings = [
                Finding(
                    statement="No detector evidence was stored with this alert.",
                    cites=["alert:title"],
                )
            ]
        return AnalysisContent(
            summary=_summary(view),
            findings=findings,
            limits=_limits(view, left_out),
            suggested_checks=_checks(view),
        )
