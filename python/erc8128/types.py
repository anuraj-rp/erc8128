from __future__ import annotations

from dataclasses import dataclass, fields
from typing import Any, Callable, Literal, TypeVar

Hex = str
Address = str
BindingMode = Literal["request-bound", "class-bound"]
ReplayMode = Literal["non-replayable", "replayable"]
ContentDigestMode = Literal["auto", "recompute", "require", "off"]


class Erc8128Error(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass(frozen=True)
class SignatureParams:
    created: int
    expires: int
    keyid: str
    nonce: str | None = None
    tag: str | None = None


@dataclass(frozen=True)
class SignOptions:
    label: str | None = None
    binding: BindingMode | None = None
    replay: ReplayMode | None = None
    created: int | None = None
    expires: int | None = None
    ttl_seconds: int | None = None
    nonce: str | Callable[[], str] | None = None
    content_digest: ContentDigestMode | None = None
    components: list[str] | None = None


@dataclass(frozen=True)
class ClientOptions(SignOptions):
    fetch: Callable[[Any], Any] | None = None


@dataclass(frozen=True)
class VerifyPolicy:
    label: str | None = None
    strict_label: bool | None = None
    additional_request_bound_components: list[str] | None = None
    class_bound_policies: list[str] | list[list[str]] | None = None
    replayable: bool | None = None
    replayable_not_before: Callable[[str], int | None] | None = None
    replayable_invalidated: Callable[[dict[str, Any]], bool] | None = None
    max_signature_verifications: int | None = None
    now: Callable[[], int] | None = None
    clock_skew_sec: int | None = None
    max_validity_sec: int | None = None
    max_nonce_window_sec: int | None = None
    nonce_key: Callable[[str, str], str] | None = None


@dataclass(frozen=True)
class VerifySuccess:
    address: Address
    chain_id: int
    label: str
    components: list[str]
    params: SignatureParams
    replayable: bool
    binding: BindingMode
    ok: Literal[True] = True


@dataclass(frozen=True)
class VerifyFailure:
    reason: str
    detail: str | None = None
    ok: Literal[False] = False


VerifyResult = VerifySuccess | VerifyFailure

T = TypeVar("T")


def merge_dataclass(base: T | None, override: T | None, cls: type[T]) -> T:
    source = base or cls()
    if override is None:
        return source
    values = {}
    for field in fields(cls):
        candidate = getattr(override, field.name)
        values[field.name] = candidate if candidate is not None else getattr(source, field.name)
    return cls(**values)
