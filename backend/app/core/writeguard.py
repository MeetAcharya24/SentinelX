"""Optional shared-secret check for the mutating and expensive endpoints.

With `DEMO_WRITE_TOKEN` unset (local development, tests, CI) nothing is checked. With it set,
a gated route needs an `X-Demo-Write-Token` header carrying the same value. It is a coarse
gate for a public demo, not authentication: there are no users, one secret is shared by every
caller, and it sits beside the rate limiter rather than replacing it.
"""

import hmac
from typing import Annotated

from fastapi import Depends, Header

from app.core.config import Settings, get_settings
from app.core.errors import AppError

WRITE_TOKEN_HEADER = "X-Demo-Write-Token"  # noqa: S105 - a header name, not a secret

REFUSAL = f"This instance is write-protected. Send the {WRITE_TOKEN_HEADER} header to make changes."


def _matches(supplied: str, expected: str) -> bool:
    # Compare bytes in constant time; `compare_digest` rejects non-ASCII str outright.
    return hmac.compare_digest(supplied.encode("utf-8"), expected.encode("utf-8"))


def require_write_token(
    settings: Annotated[Settings, Depends(get_settings)],
    supplied: Annotated[
        str | None,
        Header(
            alias=WRITE_TOKEN_HEADER,
            description="Required only when the server sets DEMO_WRITE_TOKEN.",
        ),
    ] = None,
) -> None:
    """Route dependency: refuses with 403 unless the configured token is presented."""
    if settings.demo_write_token is None:
        return
    if supplied is None or not _matches(supplied, settings.demo_write_token.get_secret_value()):
        raise AppError("write_protected", REFUSAL, status_code=403)
