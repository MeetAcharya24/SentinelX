"""FastAPI application factory."""

import logging
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import alerts, analyst, health, logs, network, phishing
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.limits import BodySizeLimitMiddleware
from app.core.logging import REQUEST_ID_HEADER, RequestLoggingMiddleware, configure_logging
from app.core.ratelimit import RateLimitMiddleware
from app.intel.refresh import run as run_intel_refresh

logger = logging.getLogger("sentinelx.startup")


def _refresh_intel_quietly(settings: Settings) -> None:
    """Background refresh: a failure is logged, never raised into the server."""
    try:
        run_intel_refresh(settings)
    except Exception:
        logger.exception("Startup threat-intelligence refresh failed")


def _start_intel_refresh(settings: Settings) -> None:
    threading.Thread(
        target=_refresh_intel_quietly, args=(settings,), name="intel-refresh", daemon=True
    ).start()


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    @asynccontextmanager
    async def lifespan(_: FastAPI) -> AsyncIterator[None]:
        if settings.startup_intel_refresh:
            _start_intel_refresh(settings)
        yield

    app = FastAPI(
        lifespan=lifespan,
        title="SentinelX API",
        version=__version__,
        description="Defensive security analytics for authorised logs and network datasets.",
    )
    app.dependency_overrides[get_settings] = lambda: settings

    # Added first, so it sits closest to the routes and refuses before any parsing.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
    if settings.rate_limit_per_minute > 0:
        # Outside the size limit, so a refused client is turned away before its body is read,
        # but inside logging and CORS so the 429 carries a request id and CORS headers.
        app.add_middleware(
            RateLimitMiddleware,
            per_minute=settings.rate_limit_per_minute,
            burst=settings.rate_limit_burst,
            trust_proxy_headers=settings.trust_proxy_headers,
        )
    app.add_middleware(RequestLoggingMiddleware)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=settings.cors_origin_list,
        allow_methods=["*"],
        allow_headers=["*"],
        expose_headers=[REQUEST_ID_HEADER],
    )
    register_error_handlers(app)
    app.include_router(health.router)
    app.include_router(alerts.router)
    app.include_router(analyst.router)
    app.include_router(logs.router)
    app.include_router(network.router)
    app.include_router(phishing.router)
    return app


app = create_app()
