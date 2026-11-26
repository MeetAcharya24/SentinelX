"""Alert candidates and the rules that turn scores and matches into one.

Everything here is pure: numbers and matches in, a candidate with its severity and
evidence out. Reading models, files and the database happens elsewhere.

Severity is deliberately simple and written out below so an analyst can predict
it: it follows how many independent detectors agree and how strong the model
scores are. It is decision support, not a measured risk rating.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum

from app.detection.phishing_signals import Severity as SignalSeverity
from app.detection.phishing_signals import Signal


class AlertSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


SEVERITY_ORDER: tuple[AlertSeverity, ...] = tuple(AlertSeverity)


class AlertCategory(StrEnum):
    NETWORK_ANOMALY = "network_anomaly"
    BRUTE_FORCE = "brute_force"
    KNOWN_BAD_SOURCE = "known_bad_source"
    SUSPICIOUS_ACTIVITY = "suspicious_activity"
    PHISHING = "phishing"


class EvidenceKind(StrEnum):
    MODEL_SCORE = "model_score"
    RULE_MATCH = "rule_match"
    PHISHING_SIGNAL = "phishing_signal"
    MODEL_TERM = "model_term"
    CAVEAT = "caveat"


@dataclass(frozen=True)
class Evidence:
    kind: EvidenceKind
    name: str
    description: str
    # Score, weight or count behind the observation, when it has one.
    value: float | None = None
    examples: tuple[str, ...] = ()


@dataclass(frozen=True)
class AlertCandidate:
    severity: AlertSeverity
    confidence: int  # 0-100
    category: AlertCategory
    source: str
    asset: str | None
    title: str
    evidence: tuple[Evidence, ...]
    # When the underlying activity happened, if the input says; detection time is stored separately.
    occurred_at: datetime | None = None


# Thresholds for the network and phishing rules.
FLOW_STRONG_PROBABILITY = 0.9
PHISHING_STRONG_PROBABILITY = 0.9
MODEL_THRESHOLD = 0.5
# Anomaly-only flags carry no probability, so they get a fixed, low confidence.
ANOMALY_ONLY_CONFIDENCE = 40
RULE_CONFIDENCE = 80
MAX_TITLE_CHARS = 120


def raise_severity(severity: AlertSeverity, levels: int = 1) -> AlertSeverity:
    index = min(SEVERITY_ORDER.index(severity) + levels, len(SEVERITY_ORDER) - 1)
    return SEVERITY_ORDER[index]


def _percent(probability: float) -> int:
    return max(0, min(100, round(probability * 100)))


def flow_candidate(
    index: int,
    attack_probability: float,
    anomaly_score: float,
    anomaly_threshold: float,
    unseen_categories: list[str],
) -> AlertCandidate | None:
    """One flow's two model scores become an alert, or nothing.

    Both detectors flag: high. Random Forest alone at 0.9 or more: medium (it flags
    about one normal flow in four, so a weaker score alone is only low). Isolation
    Forest alone: low, because it misses most attacks and flags about one normal
    flow in ten.
    """
    forest_flags = attack_probability >= MODEL_THRESHOLD
    anomaly_flags = anomaly_score > anomaly_threshold
    if not (forest_flags or anomaly_flags):
        return None
    if forest_flags and anomaly_flags:
        severity = AlertSeverity.HIGH
    elif attack_probability >= FLOW_STRONG_PROBABILITY:
        severity = AlertSeverity.MEDIUM
    else:
        severity = AlertSeverity.LOW
    evidence = [
        Evidence(
            EvidenceKind.MODEL_SCORE,
            "random_forest_attack_probability",
            f"Random Forest attack probability {attack_probability:.2f} "
            f"({'at or above' if forest_flags else 'below'} the {MODEL_THRESHOLD} threshold).",
            attack_probability,
        ),
        Evidence(
            EvidenceKind.MODEL_SCORE,
            "isolation_forest_anomaly_score",
            f"Isolation Forest anomaly score {anomaly_score:.3f} "
            f"({'above' if anomaly_flags else 'not above'} {anomaly_threshold}: "
            f"{'unlike' if anomaly_flags else 'similar to'} normal training flows).",
            anomaly_score,
        ),
    ]
    if unseen_categories:
        evidence.append(
            Evidence(
                EvidenceKind.CAVEAT,
                "unseen_categories",
                "Some categorical fields had values the model never saw in training.",
                examples=tuple(unseen_categories),
            )
        )
    confidence = _percent(attack_probability) if forest_flags else ANOMALY_ONLY_CONFIDENCE
    return AlertCandidate(
        severity=severity,
        confidence=confidence,
        category=AlertCategory.NETWORK_ANOMALY,
        source=f"flow {index}",
        asset=None,
        title="Flow flagged by "
        + ("both network models" if forest_flags and anomaly_flags else "one network model"),
        evidence=tuple(evidence),
    )


def phishing_candidate(
    sender: str,
    subject: str,
    phishing_probability: float,
    signals: list[Signal],
    top_terms: list[tuple[str, float]],
    watchlist_matches: list[str],
) -> AlertCandidate | None:
    """A classified email becomes an alert when the model flags it or a link matches a bad list.

    Base severity from the model score and how many suspicious signals agree; a match
    on the known-bad domain list raises it by one level.
    """
    flagged = phishing_probability >= MODEL_THRESHOLD
    if not flagged and not watchlist_matches:
        return None
    suspicious = sum(1 for signal in signals if signal.severity == SignalSeverity.SUSPICIOUS)
    if not flagged:
        severity = AlertSeverity.LOW
    elif phishing_probability >= PHISHING_STRONG_PROBABILITY and suspicious >= 2:
        severity = AlertSeverity.HIGH
    elif phishing_probability >= PHISHING_STRONG_PROBABILITY or suspicious >= 1:
        severity = AlertSeverity.MEDIUM
    else:
        severity = AlertSeverity.LOW
    if watchlist_matches:
        severity = raise_severity(severity)
    evidence: list[Evidence] = [
        Evidence(
            EvidenceKind.MODEL_SCORE,
            "phishing_probability",
            f"Phishing classifier probability {phishing_probability:.2f} "
            f"({'at or above' if flagged else 'below'} the {MODEL_THRESHOLD} threshold).",
            phishing_probability,
        )
    ]
    if watchlist_matches:
        evidence.append(
            Evidence(
                EvidenceKind.RULE_MATCH,
                "known_bad_domain",
                "The sender or a link uses a domain on the known-bad list.",
                examples=tuple(watchlist_matches),
            )
        )
    evidence.extend(
        Evidence(
            EvidenceKind.PHISHING_SIGNAL,
            signal.code,
            signal.description,
            examples=signal.examples,
        )
        for signal in signals
    )
    evidence.extend(
        Evidence(
            EvidenceKind.MODEL_TERM,
            term,
            "Term in the message that pushed the classifier towards phishing.",
            weight,
        )
        for term, weight in top_terms
    )
    clipped = subject if len(subject) <= MAX_TITLE_CHARS else subject[: MAX_TITLE_CHARS - 1] + "…"
    return AlertCandidate(
        severity=severity,
        confidence=_percent(phishing_probability) if flagged else RULE_CONFIDENCE,
        category=AlertCategory.PHISHING,
        source=sender or "unknown sender",
        asset=None,
        title=f"Suspected phishing email: {clipped}" if clipped else "Suspected phishing email",
        evidence=tuple(evidence),
    )
