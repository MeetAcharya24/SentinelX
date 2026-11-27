"""The AI analyst's explanation of one stored alert (advisory, read-only for the alert)."""

import threading
from typing import Annotated

from fastapi import APIRouter, Depends, Request
from fastapi.concurrency import run_in_threadpool

from app.analyst.service import AnalystReport, AnalystService
from app.api.alerts import alert_store
from app.core.config import Settings, get_settings
from app.core.errors import AppError
from app.core.responses import Envelope, ok
from app.core.writeguard import require_write_token
from app.storage.alerts import StoredAlert

router = APIRouter(prefix="/api/v1", tags=["analyst"])

_STATE_KEY = "analyst_service"
_state_lock = threading.Lock()


def analyst_service(request: Request, settings: Settings) -> AnalystService:
    state = request.app.state
    service = getattr(state, _STATE_KEY, None)
    if service is None:
        with _state_lock:
            service = getattr(state, _STATE_KEY, None)
            if service is None:
                service = AnalystService(settings)
                setattr(state, _STATE_KEY, service)
    return service


def _alert(request: Request, settings: Settings, alert_id: int) -> StoredAlert:
    alert = alert_store(request, settings).get(alert_id)
    if alert is None:
        raise AppError("alert_not_found", "No alert with that id.", status_code=404)
    return alert


@router.get("/alerts/{alert_id}/analysis")
async def get_analysis(
    alert_id: int, request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> Envelope[AnalystReport]:
    """The analyst's explanation, generated on first view and cached until the alert's
    evidence or the configured provider changes. Every statement cites the alert fields
    and evidence keys it used."""
    alert = _alert(request, settings, alert_id)
    service = analyst_service(request, settings)
    return ok(await run_in_threadpool(service.report_for, alert))


@router.post("/alerts/{alert_id}/analysis/refresh", dependencies=[Depends(require_write_token)])
async def refresh_analysis(
    alert_id: int, request: Request, settings: Annotated[Settings, Depends(get_settings)]
) -> Envelope[AnalystReport]:
    """Regenerates the explanation, ignoring the cache (spends hosted-provider budget)."""
    alert = _alert(request, settings, alert_id)
    service = analyst_service(request, settings)
    return ok(await run_in_threadpool(lambda: service.report_for(alert, refresh=True)))
