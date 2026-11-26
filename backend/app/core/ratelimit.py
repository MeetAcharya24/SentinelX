"""Per-client request rate limiting: an in-memory token bucket for a single instance.

Each client gets a bucket holding up to `burst` tokens that refills at
`per_minute / 60` tokens a second. A request spends its cost in tokens; with too few
left it is refused with 429 and a `Retry-After` header saying when enough will
have refilled. Reads cost 1 and POSTs (which run models or call a provider) cost
`POST_COST`, so the CPU-heavy endpoints are throttled harder than plain reads.

State lives in this process only, which is right for one instance; running more than
one would give each its own buckets (a shared store would be needed then). The
number of tracked clients is capped so a flood of distinct addresses cannot grow it
without bound. `/health` is never limited, so uptime checks cannot lock themselves out.
"""

import math
import time
from collections import OrderedDict
from collections.abc import Callable
from dataclasses import dataclass

from starlette.datastructures import Headers
from starlette.types import ASGIApp, Receive, Scope, Send

from app.core.responses import fail

POST_COST = 5
MAX_TRACKED_CLIENTS = 10_000
EXEMPT_PATHS = frozenset({"/health"})
_MESSAGE = "Too many requests. Please slow down and try again shortly."
_BODY = fail("http_429", _MESSAGE).model_dump_json().encode()


@dataclass
class _Bucket:
    tokens: float
    updated: float


class RateLimitMiddleware:
    def __init__(
        self,
        app: ASGIApp,
        *,
        per_minute: int,
        burst: int,
        trust_proxy_headers: bool = False,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        self.app = app
        self.burst = float(burst)
        self.rate = per_minute / 60.0
        self.trust_proxy_headers = trust_proxy_headers
        self.clock = clock
        self._buckets: OrderedDict[str, _Bucket] = OrderedDict()

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope["path"] in EXEMPT_PATHS or scope["method"] == "OPTIONS":
            await self.app(scope, receive, send)
            return
        cost = POST_COST if scope["method"] == "POST" else 1
        wait = self._spend(self._client_key(scope), min(cost, self.burst))
        if wait is None:
            await self.app(scope, receive, send)
            return
        headers = [
            (b"content-type", b"application/json"),
            (b"content-length", str(len(_BODY)).encode()),
            (b"retry-after", str(wait).encode()),
        ]
        await send({"type": "http.response.start", "status": 429, "headers": headers})
        await send({"type": "http.response.body", "body": _BODY})

    def _client_key(self, scope: Scope) -> str:
        if self.trust_proxy_headers:
            forwarded = Headers(scope=scope).get("x-forwarded-for", "")
            # The rightmost entry is the one the trusted proxy added; earlier ones are
            # client-supplied and can be forged.
            last = forwarded.rsplit(",", 1)[-1].strip()
            if last:
                return last
        client = scope.get("client")
        return client[0] if client else "unknown"

    def _spend(self, key: str, cost: float) -> int | None:
        """Takes `cost` tokens; returns None if allowed, else whole seconds to wait."""
        now = self.clock()
        bucket = self._buckets.get(key)
        if bucket is None:
            bucket = _Bucket(tokens=self.burst, updated=now)
            self._buckets[key] = bucket
            self._trim()
        else:
            self._buckets.move_to_end(key)
        bucket.tokens = min(self.burst, bucket.tokens + (now - bucket.updated) * self.rate)
        bucket.updated = now
        if bucket.tokens >= cost:
            bucket.tokens -= cost
            return None
        return max(1, math.ceil((cost - bucket.tokens) / self.rate))

    def _trim(self) -> None:
        """Keeps the table bounded: drop the least recently seen clients first."""
        while len(self._buckets) > MAX_TRACKED_CLIENTS:
            self._buckets.popitem(last=False)
