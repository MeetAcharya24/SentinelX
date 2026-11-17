"""Structured error handling: every failure leaves as the same JSON envelope."""

import logging
from collections.abc import Mapping

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from app.core.responses import fail

logger = logging.getLogger("sentinelx.errors")

INTERNAL_ERROR_MESSAGE = "An unexpected error occurred."


class AppError(Exception):
    """Expected, client-reportable failure raised by application code."""

    def __init__(
        self,
        code: str,
        message: str,
        status_code: int = 400,
        details: list[dict] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.status_code = status_code
        self.details = details


def _error_response(
    status_code: int,
    code: str,
    message: str,
    details: list[dict] | None = None,
    headers: Mapping[str, str] | None = None,
) -> JSONResponse:
    return JSONResponse(
        status_code=status_code,
        content=fail(code, message, details).model_dump(),
        headers=headers,
    )


async def _handle_app_error(_: Request, exc: AppError) -> JSONResponse:
    return _error_response(exc.status_code, exc.code, exc.message, exc.details)


async def _handle_http_error(_: Request, exc: StarletteHTTPException) -> JSONResponse:
    return _error_response(
        exc.status_code, f"http_{exc.status_code}", str(exc.detail), headers=exc.headers
    )


async def _handle_validation_error(_: Request, exc: RequestValidationError) -> JSONResponse:
    details = [
        {"field": ".".join(str(part) for part in error["loc"]), "message": error["msg"]}
        for error in exc.errors()
    ]
    return _error_response(422, "validation_error", "Request validation failed.", details)


def unexpected_error_response(request: Request, exc: Exception) -> JSONResponse:
    """Logs a crash in full and returns the generic envelope the client sees.

    Called from the request middleware rather than registered as a handler:
    Starlette runs `Exception` handlers outside all middleware, which would
    strip the CORS and request-ID headers from the response.
    """
    logger.exception("Unhandled error on %s %s", request.method, request.url.path, exc_info=exc)
    return _error_response(500, "internal_error", INTERNAL_ERROR_MESSAGE)


def register_error_handlers(app: FastAPI) -> None:
    app.add_exception_handler(AppError, _handle_app_error)
    app.add_exception_handler(StarletteHTTPException, _handle_http_error)
    app.add_exception_handler(RequestValidationError, _handle_validation_error)
