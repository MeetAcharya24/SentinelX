"""Service health and capability status."""

from typing import Annotated, Literal

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app import __version__
from app.core.config import Settings, get_settings
from app.core.responses import Envelope, ok

router = APIRouter(tags=["health"])


class AnalystStatus(BaseModel):
    mode: Literal["llm", "deterministic"]
    provider: str | None


class HealthStatus(BaseModel):
    status: Literal["ok"]
    version: str
    environment: str
    analyst: AnalystStatus
    threatfox_configured: bool


@router.get("/health")
def health(settings: Annotated[Settings, Depends(get_settings)]) -> Envelope[HealthStatus]:
    analyst = (
        AnalystStatus(mode="llm", provider=settings.llm_provider)
        if settings.llm_configured
        else AnalystStatus(mode="deterministic", provider=None)
    )
    return ok(
        HealthStatus(
            status="ok",
            version=__version__,
            environment=settings.app_env,
            analyst=analyst,
            threatfox_configured=settings.threatfox_configured,
        )
    )
