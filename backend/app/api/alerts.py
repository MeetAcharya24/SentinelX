"""Alert generation from network flows, security logs and emails, and the alert list."""

import threading
from dataclasses import asdict
from datetime import UTC, datetime
from typing import Annotated, Literal

import pandas as pd
from fastapi import APIRouter, Depends, Query, Request
from fastapi.concurrency import run_in_threadpool
from pydantic import BaseModel, ConfigDict, StringConstraints, model_validator

from app.api.logs import log_format_of
from app.api.network import ScoreRequest
from app.api.network import served_model as served_network_model
from app.api.phishing import served_model as served_phishing_model
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.core.responses import Envelope, ok
from app.detection.alerts import AlertCandidate, AlertCategory, AlertSeverity, Evidence
from app.detection.pipeline import alerts_from_email, alerts_from_flows, alerts_from_log
from app.detection.watchlist import load_watchlist
from app.ingestion.email import EmailParseError, parse_email
from app.ingestion.logs import LogFileError, parse_log
from app.intel.lookup import ThreatIntel
from app.intel.store import IntelStore
from app.ml.anomaly import ANOMALY_DIRNAME
from app.ml.persistence import LoadedModel, ModelUnavailableError, load_model
from app.ml.schema import FEATURE_COLUMNS
from app.storage.alerts import (
    DEFAULT_PAGE_SIZE,
    MAX_NOTE_CHARS,
    MAX_PAGE_SIZE,
    AlertFilter,
    AlertStore,
    StoredAlert,
)

router = APIRouter(prefix="/api/v1", tags=["alerts"])

_STORE_STATE_KEY = "alert_store"
_ANOMALY_STATE_KEY = "anomaly_model"
_state_lock = threading.Lock()
_EMAIL_TYPES = ("text/plain", "message/rfc822")

AlertStatus = Literal["open", "acknowledged", "false_positive", "resolved"]
DemoFlag = Annotated[
    bool,
    Query(description="Mark the alerts as coming from labelled demo input, not a real upload."),
]


class EvidenceOut(BaseModel):
    kind: str
    name: str
    description: str
    value: float | None
    examples: list[str]


class NoteOut(BaseModel):
    id: int
    created_at: datetime
    text: str


class AlertOut(BaseModel):
    id: int
    created_at: datetime
    occurred_at: datetime | None
    severity: AlertSeverity
    confidence: int
    category: AlertCategory
    source: str
    asset: str | None
    title: str
    evidence: list[EvidenceOut]
    status: str
    demo: bool
    # Analyst notes, oldest first. There is no author field until accounts exist.
    notes: list[NoteOut]


class AnalysisResult(BaseModel):
    analyzed: int
    # One entry per flagged item; repeats of an alert already stored come back as stored.
    alerts: list[AlertOut]
    # How many of those were already on file, so nothing new was stored for them.
    duplicates: int = 0


class AlertUpdate(BaseModel):
    """Change an alert's status, append a note, or both. Notes are never edited or removed."""

    model_config = ConfigDict(extra="forbid")

    status: AlertStatus | None = None
    note: (
        Annotated[
            str, StringConstraints(strip_whitespace=True, min_length=1, max_length=MAX_NOTE_CHARS)
        ]
        | None
    ) = None

    @model_validator(mode="after")
    def _needs_a_change(self) -> "AlertUpdate":
        if self.status is None and self.note is None:
            raise ValueError("send a status, a note, or both")
        return self


class AlertPage(BaseModel):
    total: int
    limit: int
    offset: int
    alerts: list[AlertOut]


def _evidence_out(item: Evidence) -> EvidenceOut:
    return EvidenceOut(
        kind=item.kind.value,
        name=item.name,
        description=item.description,
        value=item.value,
        examples=list(item.examples),
    )


def _alert_out(alert: StoredAlert) -> AlertOut:
    fields = asdict(alert)
    fields["evidence"] = [_evidence_out(item) for item in alert.evidence]
    return AlertOut(**fields)


def alert_store(request: Request, settings: Settings) -> AlertStore:
    state = request.app.state
    store = getattr(state, _STORE_STATE_KEY, None)
    if store is None:
        with _state_lock:
            store = getattr(state, _STORE_STATE_KEY, None)
            if store is None:
                store = AlertStore(settings.sqlite_path)
                setattr(state, _STORE_STATE_KEY, store)
    return store


def _anomaly_model(request: Request, settings: Settings) -> LoadedModel:
    state = request.app.state
    loaded = getattr(state, _ANOMALY_STATE_KEY, None)
    if loaded is None:
        with _state_lock:
            loaded = getattr(state, _ANOMALY_STATE_KEY, None)
            if loaded is None:
                try:
                    loaded = load_model(settings.model_dir / ANOMALY_DIRNAME)
                except ModelUnavailableError as error:
                    raise AppError(
                        "model_unavailable",
                        "The anomaly detector is not available. "
                        "Retrain with `python -m app.ml.train`.",
                        status_code=503,
                    ) from error
                loaded.pipeline.set_params(model__n_jobs=1)
                setattr(state, _ANOMALY_STATE_KEY, loaded)
    return loaded


def _intel(settings: Settings) -> ThreatIntel:
    """Threat-intelligence lookups backed by the cache in the alert database."""
    return ThreatIntel(IntelStore(settings.sqlite_path))


def _store_alerts(
    request: Request,
    settings: Settings,
    candidates: list[AlertCandidate],
    demo: bool,
    analyzed: int,
) -> AnalysisResult:
    outcome = alert_store(request, settings).ingest(candidates, demo=demo)
    return AnalysisResult(
        analyzed=analyzed,
        alerts=[_alert_out(alert) for alert in outcome.alerts],
        duplicates=outcome.duplicates,
    )


@router.post("/analyze/network")
def analyze_network(
    body: ScoreRequest,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    demo: DemoFlag = False,
) -> Envelope[AnalysisResult]:
    """Scores flows with both network models and stores an alert for each flagged flow."""
    forest = served_network_model(request, settings).loaded.pipeline
    anomaly = _anomaly_model(request, settings).pipeline
    features = pd.DataFrame([flow.model_dump() for flow in body.flows])[list(FEATURE_COLUMNS)]
    candidates = alerts_from_flows(features, forest, anomaly)
    return ok(_store_alerts(request, settings, candidates, demo, len(body.flows)))


@router.post(
    "/analyze/logs",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {
                "text/csv": {"schema": {"type": "string"}},
                "application/json": {"schema": {"type": "array", "items": {"type": "object"}}},
            },
        }
    },
)
async def analyze_log(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    demo: DemoFlag = False,
) -> Envelope[AnalysisResult]:
    """Validates a log file, applies the rule checks and stores the alerts."""
    log_format = log_format_of(request)
    content = await request.body()
    try:
        parsed = await run_in_threadpool(parse_log, content, log_format)
    except LogFileError as error:
        details = [asdict(problem) for problem in error.problems] or None
        raise AppError(
            "invalid_log_file", error.message, status_code=422, details=details
        ) from error
    watchlist = load_watchlist(settings.blocklist_path)
    candidates = await run_in_threadpool(alerts_from_log, parsed, watchlist, _intel(settings))
    result = await run_in_threadpool(
        _store_alerts, request, settings, candidates, demo, len(parsed.events)
    )
    return ok(result)


@router.post(
    "/analyze/phishing",
    openapi_extra={
        "requestBody": {
            "required": True,
            "content": {media_type: {"schema": {"type": "string"}} for media_type in _EMAIL_TYPES},
        }
    },
)
async def analyze_email(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    demo: DemoFlag = False,
) -> Envelope[AnalysisResult]:
    """Classifies one email and stores an alert when it looks like phishing."""
    media_type = request.headers.get("content-type", "").split(";")[0].strip().lower()
    if media_type not in _EMAIL_TYPES:
        raise AppError(
            "unsupported_email_type",
            "Send the email as text/plain or message/rfc822.",
            status_code=415,
        )
    classifier, _ = served_phishing_model(request, settings)
    try:
        parsed = await run_in_threadpool(parse_email, await request.body())
    except EmailParseError as error:
        raise AppError("invalid_email", str(error), status_code=422) from error
    watchlist = load_watchlist(settings.blocklist_path)
    candidates = await run_in_threadpool(
        alerts_from_email, parsed, classifier.pipeline, watchlist, _intel(settings)
    )
    result = await run_in_threadpool(_store_alerts, request, settings, candidates, demo, 1)
    return ok(result)


@router.get("/alerts")
def list_alerts(
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
    severity: Annotated[list[AlertSeverity] | None, Query()] = None,
    category: Annotated[list[AlertCategory] | None, Query()] = None,
    status: Annotated[list[AlertStatus] | None, Query()] = None,
    source: Annotated[str | None, Query(max_length=256)] = None,
    created_from: datetime | None = None,
    created_to: datetime | None = None,
    min_confidence: Annotated[int | None, Query(ge=0, le=100)] = None,
    demo: bool | None = None,
    sort: Literal["newest", "severity"] = "newest",
    limit: Annotated[int, Query(ge=1, le=MAX_PAGE_SIZE)] = DEFAULT_PAGE_SIZE,
    offset: Annotated[int, Query(ge=0)] = 0,
) -> Envelope[AlertPage]:
    """Lists stored alerts. Repeat `severity`, `category` or `status` to match any of several.

    Timestamps without a UTC offset are read as UTC. `sort=severity` lists the most
    severe first, newest first within a severity.
    """
    criteria = AlertFilter(
        severities=severity or (),
        categories=category or (),
        statuses=status or (),
        source=source,
        created_from=_as_utc(created_from),
        created_to=_as_utc(created_to),
        min_confidence=min_confidence,
        demo=demo,
        newest_first=sort == "newest",
        limit=limit,
        offset=offset,
    )
    alerts, total = alert_store(request, settings).query(criteria)
    return ok(
        AlertPage(total=total, limit=limit, offset=offset, alerts=[_alert_out(a) for a in alerts])
    )


@router.get("/alerts/{alert_id}")
def get_alert(
    alert_id: int, request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> Envelope[AlertOut]:
    alert = alert_store(request, settings).get(alert_id)
    if alert is None:
        raise AppError("alert_not_found", "No alert with that id.", status_code=404)
    return ok(_alert_out(alert))


@router.patch("/alerts/{alert_id}")
def update_alert(
    alert_id: int,
    body: AlertUpdate,
    request: Request,
    settings: Annotated[Settings, Depends(get_settings)],
) -> Envelope[AlertOut]:
    """Sets an alert's status and/or appends a timestamped note, in one step.

    Any status may follow any other, so a mistaken change can be reversed. Notes are
    append-only and carry no author yet. The response is the full updated alert,
    including every note so far.
    """
    alert = alert_store(request, settings).update(alert_id, status=body.status, note=body.note)
    if alert is None:
        raise AppError("alert_not_found", "No alert with that id.", status_code=404)
    return ok(_alert_out(alert))


def _as_utc(value: datetime | None) -> datetime | None:
    return value.replace(tzinfo=UTC) if value is not None and value.tzinfo is None else value
