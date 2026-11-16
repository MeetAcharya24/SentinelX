"""Request size limit, enforced before any body is parsed."""

from starlette.datastructures import Headers
from starlette.exceptions import HTTPException
from starlette.status import HTTP_413_CONTENT_TOO_LARGE
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from app.core.responses import fail

_MESSAGE = "The request body is too large."
_REFUSAL_BODY = fail(f"http_{HTTP_413_CONTENT_TOO_LARGE}", _MESSAGE).model_dump_json().encode()


class BodySizeLimitMiddleware:
    """Answers 413 when a body exceeds `max_bytes`, declared or streamed.

    A declared length is refused without reading anything. A streamed body is
    cut off as soon as it passes the limit; the error handler then renders the
    413 like any other HTTP error.
    """

    def __init__(self, app: ASGIApp, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        declared = Headers(scope=scope).get("content-length", "")
        if declared.isdigit() and int(declared) > self.max_bytes:
            await self._refuse(send)
            return

        received = 0

        async def limited_receive() -> Message:
            nonlocal received
            message = await receive()
            if message["type"] == "http.request":
                received += len(message.get("body", b""))
                if received > self.max_bytes:
                    raise HTTPException(HTTP_413_CONTENT_TOO_LARGE, _MESSAGE)
            return message

        await self.app(scope, limited_receive, send)

    @staticmethod
    async def _refuse(send: Send) -> None:
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_REFUSAL_BODY)).encode()),
        ]
        await send({"type": "http.response.start", "status": 413, "headers": headers})
        await send({"type": "http.response.body", "body": _REFUSAL_BODY})
