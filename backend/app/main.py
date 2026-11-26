"""FastAPI application factory."""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app import __version__
from app.api import alerts, health, logs, network, phishing
from app.core.config import Settings, get_settings
from app.core.errors import register_error_handlers
from app.core.limits import BodySizeLimitMiddleware
from app.core.logging import REQUEST_ID_HEADER, RequestLoggingMiddleware, configure_logging


def create_app(settings: Settings | None = None) -> FastAPI:
    settings = settings or get_settings()
    configure_logging(settings.log_level)

    app = FastAPI(
        title="SentinelX API",
        version=__version__,
        description="Defensive security analytics for authorised logs and network datasets.",
    )
    app.dependency_overrides[get_settings] = lambda: settings

    # Added first, so it sits closest to the routes and refuses before any parsing.
    app.add_middleware(BodySizeLimitMiddleware, max_bytes=settings.max_request_bytes)
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
    app.include_router(logs.router)
    app.include_router(network.router)
    app.include_router(phishing.router)
    return app


app = create_app()
