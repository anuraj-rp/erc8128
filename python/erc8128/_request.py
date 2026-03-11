from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Any, Mapping

import httpx

from pydantic import BaseModel, ConfigDict, Field, field_validator

from .types import Erc8128Error, Hex


class Headers(dict[str, str]):
    def __init__(self, values: Mapping[str, str] | None = None):
        super().__init__()
        if values:
            for key, value in values.items():
                self[key] = value

    def __getitem__(self, key: str) -> str:
        return super().__getitem__(key.lower())

    def __setitem__(self, key: str, value: str) -> None:
        super().__setitem__(key.lower(), str(value))

    def get(self, key: str, default: str | None = None) -> str | None:
        return super().get(key.lower(), default)

    def set(self, key: str, value: str) -> None:
        self[key] = value

    def copy(self) -> "Headers":
        return Headers(self)


class HttpRequest(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    url: str
    method: str = "GET"
    headers: Headers = Field(default_factory=Headers)
    body: bytes | str | bytearray | None = None

    def __init__(self, url: str, **data: Any):
        super().__init__(url=url, **data)

    @field_validator("method", mode="before")
    @classmethod
    def normalize_method(cls, value: str | None) -> str:
        return (value or "GET").upper()

    @field_validator("headers", mode="before")
    @classmethod
    def normalize_headers(cls, value: Headers | Mapping[str, str] | None) -> Headers:
        if isinstance(value, Headers):
            return value
        return Headers(value)

    def clone(self, *, headers: Mapping[str, str] | None = None) -> "HttpRequest":
        return self.model_copy(
            update={"headers": Headers(headers or self.headers)},
            deep=True,
        )


class HttpResponse(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True)

    status: int
    headers: Headers
    body: bytes
    url: str

    def __init__(self, **data: Any):
        super().__init__(**data)

    @field_validator("headers", mode="before")
    @classmethod
    def normalize_headers(cls, value: Headers | Mapping[str, str]) -> Headers:
        if isinstance(value, Headers):
            return value
        return Headers(value)

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


@dataclass(frozen=True)
class SanitizedUrl:
    scheme: str
    hostname: str | None
    port: int | None
    path: str
    query: str


def to_request(input_value: str | HttpRequest, init: Mapping[str, Any] | None = None) -> HttpRequest:
    if isinstance(input_value, HttpRequest):
        if not init:
            return input_value
        return HttpRequest(
            url=init.get("url", input_value.url),
            method=init.get("method", input_value.method),
            headers=init.get("headers", input_value.headers),
            body=init.get("body", input_value.body),
        )
    init = init or {}
    return HttpRequest(
        url=input_value,
        method=init.get("method", "GET"),
        headers=init.get("headers", {}),
        body=init.get("body"),
    )


def sanitize_url(url: str):
    try:
        parsed = httpx.URL(url)
    except Exception as exc:
        raise Erc8128Error("UNSUPPORTED_REQUEST", f"Request.url must be absolute (got: {url}).") from exc
    if not parsed.scheme or not parsed.host:
        raise Erc8128Error("UNSUPPORTED_REQUEST", f"Request.url must be absolute (got: {url}).")
    return SanitizedUrl(
        scheme=parsed.scheme,
        hostname=parsed.host,
        port=parsed.port,
        path=parsed.path,
        query=parsed.query.decode("ascii"),
    )


def unix_now() -> int:
    import time

    return int(time.time())


def random_bytes(length: int) -> bytes:
    return secrets.token_bytes(length)


def read_body_bytes(request: HttpRequest) -> bytes:
    body = request.body
    if body is None:
        return b""
    if isinstance(body, bytes):
        return body
    if isinstance(body, bytearray):
        return bytes(body)
    if isinstance(body, str):
        return body.encode("utf-8")
    raise Erc8128Error("BODY_READ_FAILED", "Unsupported request body type.")


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def base64_encode(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def base64_decode(value: str) -> bytes | None:
    try:
        padding = "=" * (-len(value) % 4)
        return base64.b64decode(value + padding, validate=True)
    except Exception:
        return None


def base64_url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def hex_to_bytes(value: Hex) -> bytes:
    if not value.startswith("0x") or len(value) % 2 != 0:
        raise Erc8128Error("UNSUPPORTED_REQUEST", "Invalid hex length.")
    try:
        return bytes.fromhex(value[2:])
    except ValueError as exc:
        raise Erc8128Error("UNSUPPORTED_REQUEST", "Invalid hex characters.") from exc


def bytes_to_hex(value: bytes) -> Hex:
    return f"0x{value.hex()}"


def default_fetch(request: HttpRequest) -> HttpResponse:
    response = httpx.request(
        request.method,
        request.url,
        headers=dict(request.headers),
        content=read_body_bytes(request) if request.body is not None else None,
        follow_redirects=False,
    )
    return HttpResponse(
        status=response.status_code,
        headers=Headers(dict(response.headers)),
        body=response.content,
        url=str(response.url),
    )
