"""Response envelope shared by every endpoint."""

from typing import Generic, TypeVar

from pydantic import BaseModel

T = TypeVar("T")


class ErrorDetail(BaseModel):
    code: str
    message: str
    details: list[dict] | None = None


class Envelope(BaseModel, Generic[T]):
    success: bool
    data: T | None = None
    error: ErrorDetail | None = None


def ok(data: T) -> Envelope[T]:
    return Envelope(success=True, data=data)


def fail(code: str, message: str, details: list[dict] | None = None) -> Envelope[None]:
    return Envelope(success=False, error=ErrorDetail(code=code, message=message, details=details))
