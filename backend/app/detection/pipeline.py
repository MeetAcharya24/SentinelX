"""Alert generation: runs the models and rules over one input and returns candidates.

Network flows go through the Random Forest and the Isolation Forest, security
logs through the rule checks, and emails through the phishing classifier, its
signals and the known-bad domain list.
"""

import pandas as pd
from sklearn.pipeline import Pipeline

from app.detection.alerts import AlertCandidate, flow_candidate, phishing_candidate
from app.detection.log_rules import check_log_events
from app.detection.phishing_signals import extract_signals
from app.detection.watchlist import Watchlist
from app.ingestion.email import ParsedEmail
from app.ingestion.logs import ParsedLog
from app.ml.anomaly import FLAG_THRESHOLD, anomaly_scores
from app.ml.inference import attack_probabilities, unseen_categories
from app.ml.phishing_model import phishing_probability, top_contributions


def alerts_from_flows(
    features: pd.DataFrame, forest: Pipeline, anomaly_model: Pipeline
) -> list[AlertCandidate]:
    """Scores each flow with both models; flows are numbered from 1 in input order."""
    probabilities = attack_probabilities(forest, features)
    scores = anomaly_scores(anomaly_model, features)
    unseen = unseen_categories(forest, features)
    candidates = (
        flow_candidate(index, float(probability), float(score), FLAG_THRESHOLD, names)
        for index, (probability, score, names) in enumerate(
            zip(probabilities, scores, unseen, strict=True), start=1
        )
    )
    return [candidate for candidate in candidates if candidate is not None]


def alerts_from_log(parsed: ParsedLog, watchlist: Watchlist) -> list[AlertCandidate]:
    return check_log_events(parsed.events, watchlist)


def _bad_domain_matches(email: ParsedEmail, watchlist: Watchlist) -> list[str]:
    hosts = [email.from_address.rsplit("@", 1)[-1], *(link.host for link in email.links)]
    matches = (watchlist.match_domain(host) for host in hosts if host)
    return list(dict.fromkeys(match for match in matches if match))


def alerts_from_email(
    email: ParsedEmail, classifier: Pipeline, watchlist: Watchlist
) -> list[AlertCandidate]:
    text = email.model_text
    toward_phishing, _ = top_contributions(classifier, text)
    candidate = phishing_candidate(
        sender=email.from_address,
        subject=email.subject,
        phishing_probability=phishing_probability(classifier, text),
        signals=extract_signals(email),
        top_terms=[(contribution.term, contribution.weight) for contribution in toward_phishing],
        watchlist_matches=_bad_domain_matches(email, watchlist),
    )
    return [candidate] if candidate is not None else []
