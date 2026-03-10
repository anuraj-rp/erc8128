from __future__ import annotations

from typing import Any, Callable, Literal, TypeVar
from pydantic import BaseModel, ConfigDict

Hex = str
Address = str
BindingMode = Literal["request-bound", "class-bound"]
ReplayMode = Literal["non-replayable", "replayable"]
ContentDigestMode = Literal["auto", "recompute", "require", "off"]


class Erc8128Error(Exception):
    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


class Erc8128Model(BaseModel):
    model_config = ConfigDict(arbitrary_types_allowed=True, frozen=True)


class SignatureParams(Erc8128Model):
    created: int
    expires: int
    keyid: str
    nonce: str | None = None
    tag: str | None = None


class SignOptions(Erc8128Model):
    label: str | None = None
    binding: BindingMode | None = None
    replay: ReplayMode | None = None
    created: int | None = None
    expires: int | None = None
    ttl_seconds: int | None = None
    nonce: str | Callable[[], str] | None = None
    content_digest: ContentDigestMode | None = None
    components: list[str] | None = None


class ClientOptions(SignOptions):
    fetch: Callable[[Any], Any] | None = None


class VerifyPolicy(Erc8128Model):
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


class VerifySuccess(Erc8128Model):
    address: Address
    chain_id: int
    label: str
    components: list[str]
    params: SignatureParams
    replayable: bool
    binding: BindingMode
    ok: Literal[True] = True


class VerifyFailure(Erc8128Model):
    reason: str
    detail: str | None = None
    ok: Literal[False] = False


VerifyResult = VerifySuccess | VerifyFailure

T = TypeVar("T")


def merge_model(base: T | None, override: T | None, cls: type[T]) -> T:
    source = base or cls()
    if override is None:
        return source
    values = {
        field_name: getattr(override, field_name)
        for field_name in cls.model_fields
        if getattr(override, field_name) is not None
    }
    return source.model_copy(update=values)
