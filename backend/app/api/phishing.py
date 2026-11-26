"""Phishing email classification with the evidence behind each verdict."""

import logging
import threading
from enum import StrEnum
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ValidationError

from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.core.responses import Envelope, ok
from app.detection.phishing_signals import Severity, extract_signals
from app.ingestion.email import EmailParseError, ParsedEmail, parse_email
from app.ml.persistence import ModelUnavailableError
from app.ml.phishing_model import (
    DECISION_THRESHOLD,
    LoadedPhishingModel,
    load_phishing_model,
    phishing_probability,
    top_contributions,
)

logger = logging.getLogger("sentinelx.model")

router = APIRouter(prefix="/api/v1/phishing", tags=["phishing"])

_MODEL_STATE_KEY = "phishing_model"
_ACCEPTED_TYPES = ("text/plain", "message/rfc822")
_load_lock = threading.Lock()
_REQUEST_BODY = {
    "required": True,
    "content": {media_type: {"schema": {"type": "string"}} for media_type in _ACCEPTED_TYPES},
}


class PhishingLabel(StrEnum):
    PHISHING = "phishing"
    LEGITIMATE = "legitimate"


class SignalOut(BaseModel):
    code: str
    severity: Severity
    description: str
    examples: list[str]


class TermOut(BaseModel):
    term: str
    weight: float


class ModelTerms(BaseModel):
    """Words and phrases in this message that moved the model's score, strongest first."""

    toward_phishing: list[TermOut]
    toward_legitimate: list[TermOut]


class PhishingMetrics(BaseModel):
    """Measured on messages held out from training, from the two public corpora."""

    precision: float
    recall: float
    f1: float
    accuracy: float
    false_positive_rate: float
    test_rows: int
    test_attack_share: float


class PhishingModelInfo(BaseModel):
    name: str
    trained_at: str
    training_rows: int
    test_metrics: PhishingMetrics


class PhishingResult(BaseModel):
    label: PhishingLabel
    # Probability of the predicted label (0.5 to 1.0): the model's score, not certainty.
    confidence: float
    phishing_probability: float
    threshold: float
    # Rule-based observations shown beside the verdict; they do not set the label.
    signals: list[SignalOut]
    model_terms: ModelTerms
    links_found: list[str]
    attachments_found: list[str]
    model: PhishingModelInfo


def _read_model(settings: Settings) -> tuple[LoadedPhishingModel, PhishingModelInfo]:
    try:
        loaded = load_phishing_model(settings.phishing_model_dir)
        info = PhishingModelInfo(
            name=loaded.metadata.model_name,
            trained_at=loaded.metadata.trained_at,
            training_rows=loaded.metadata.training_rows,
            test_metrics=PhishingMetrics.model_validate(loaded.metadata.test_metrics),
        )
    except ModelUnavailableError as error:
        logger.warning("Phishing model unavailable: %s", error)
        raise AppError("model_unavailable", error.public_message, status_code=503) from error
    except ValidationError as error:
        logger.warning("Phishing model metadata has unexpected metrics: %s", error)
        raise AppError(
            "model_unavailable",
            "The stored phishing model cannot be used. "
            "Retrain it with `python -m app.ml.phishing_train`.",
            status_code=503,
        ) from error
    return loaded, info


def served_model(
    request: Request, settings: Settings
) -> tuple[LoadedPhishingModel, PhishingModelInfo]:
    """Loads the saved model on first use and keeps it for later requests."""
    state = request.app.state
    served = getattr(state, _MODEL_STATE_KEY, None)
    if served is None:
        with _load_lock:
            served = getattr(state, _MODEL_STATE_KEY, None)
            if served is None:
                served = _read_model(settings)
                setattr(state, _MODEL_STATE_KEY, served)
    return served


def _check_content_type(request: Request) -> None:
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type not in _ACCEPTED_TYPES:
        raise AppError(
            "unsupported_email_type",
            "Send the email as text/plain or message/rfc822.",
            status_code=415,
        )


def classify_parsed(
    parsed: ParsedEmail, loaded: LoadedPhishingModel, info: PhishingModelInfo
) -> PhishingResult:
    text = parsed.model_text
    probability = phishing_probability(loaded.pipeline, text)
    is_phishing = probability >= DECISION_THRESHOLD
    toward_phishing, toward_legitimate = top_contributions(loaded.pipeline, text)
    return PhishingResult(
        label=PhishingLabel.PHISHING if is_phishing else PhishingLabel.LEGITIMATE,
        confidence=probability if is_phishing else 1.0 - probability,
        phishing_probability=probability,
        threshold=DECISION_THRESHOLD,
        signals=[
            SignalOut(
                code=signal.code,
                severity=signal.severity,
                description=signal.description,
                examples=list(signal.examples),
            )
            for signal in extract_signals(parsed)
        ],
        model_terms=ModelTerms(
            toward_phishing=[TermOut(term=t.term, weight=t.weight) for t in toward_phishing],
            toward_legitimate=[TermOut(term=t.term, weight=t.weight) for t in toward_legitimate],
        ),
        links_found=[link.url for link in parsed.links[:20]],
        attachments_found=list(parsed.attachment_names),
        model=info,
    )


@router.post("/classify", openapi_extra={"requestBody": _REQUEST_BODY})
async def classify_email(
    request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> Envelope[PhishingResult]:
    """Classifies one email you are authorised to inspect.

    The body is the email itself, with or without headers. Links are listed as
    text and never opened; attachments are listed by name and never read.
    """
    _check_content_type(request)
    loaded, info = served_model(request, settings)
    try:
        parsed = await run_in_threadpool(parse_email, await request.body())
    except EmailParseError as error:
        raise AppError("invalid_email", str(error), status_code=422) from error
    return ok(await run_in_threadpool(classify_parsed, parsed, loaded, info))
