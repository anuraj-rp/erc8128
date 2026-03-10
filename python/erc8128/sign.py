from __future__ import annotations

from typing import Any, Mapping

from ._request import HttpRequest, default_fetch, to_request, unix_now, base64_encode, hex_to_bytes
from ._shared import (
    append_dictionary_member,
    assert_signature_params_for_serialization,
    create_signature_base_minimal,
    format_key_id,
    resolve_components,
    resolve_nonce,
    serialize_signature_header,
    serialize_signature_input_header,
    serialize_signature_params_inner_list,
    set_content_digest_header,
)
from .types import ClientOptions, Erc8128Error, SignOptions, SignatureParams, merge_dataclass


def sign_request(
    input_value: str | HttpRequest,
    signer: Any,
    init: Mapping[str, Any] | None = None,
    options: SignOptions | None = None,
) -> HttpRequest:
    resolved_options = merge_dataclass(SignOptions(), options, SignOptions)
    request = to_request(input_value, init)
    label = resolved_options.label or "eth"
    binding = resolved_options.binding or "request-bound"
    replay = resolved_options.replay or "non-replayable"
    digest_mode = resolved_options.content_digest or "auto"
    created = resolved_options.created if resolved_options.created is not None else unix_now()
    ttl_seconds = resolved_options.ttl_seconds if resolved_options.ttl_seconds is not None else 60
    expires = resolved_options.expires if resolved_options.expires is not None else created + ttl_seconds
    nonce = resolve_nonce(resolved_options.nonce) if replay == "non-replayable" else None
    chain_id = getattr(signer, "chain_id", getattr(signer, "chainId", None))
    address = getattr(signer, "address", None)
    if chain_id is None or address is None:
        raise Erc8128Error("INVALID_OPTIONS", "Signer must define chain_id/chainId and address.")
    keyid = format_key_id(chain_id, address)
    url = request.url
    has_query = "?" in url and not url.endswith("?")
    has_body = request.body is not None
    components = resolve_components(binding, has_query, has_body, resolved_options.components)
    signed_request = request
    if "content-digest" in components:
        signed_request = set_content_digest_header(signed_request, digest_mode)
    elif binding == "request-bound" and has_body:
        components = [*components, "content-digest"]
        signed_request = set_content_digest_header(signed_request, digest_mode)
    params = SignatureParams(created=created, expires=expires, keyid=keyid, nonce=nonce)
    assert_signature_params_for_serialization(params)
    signature_params_value = serialize_signature_params_inner_list(components, params)
    signature_input_header = serialize_signature_input_header(label, signature_params_value)
    signature_base = create_signature_base_minimal(signed_request, components, signature_params_value)
    sign_message = getattr(signer, "sign_message", getattr(signer, "signMessage", None))
    if not callable(sign_message):
        raise Erc8128Error("INVALID_OPTIONS", "Signer must define sign_message/signMessage.")
    signature_hex = sign_message(signature_base)
    signature_bytes = hex_to_bytes(signature_hex)
    if not signature_bytes:
        raise Erc8128Error("UNSUPPORTED_REQUEST", "Signer returned empty signature.")
    signature_header = serialize_signature_header(label, base64_encode(signature_bytes))
    headers = signed_request.headers.copy()
    headers.set("signature-input", append_dictionary_member(headers.get("signature-input"), signature_input_header))
    headers.set("signature", append_dictionary_member(headers.get("signature"), signature_header))
    return signed_request.clone(headers=headers)


def signed_fetch(
    input_value: str | HttpRequest,
    signer: Any,
    init: Mapping[str, Any] | None = None,
    options: ClientOptions | None = None,
):
    resolved_options = merge_dataclass(ClientOptions(), options, ClientOptions)
    request = sign_request(input_value, signer, init=init, options=SignOptions(
        label=resolved_options.label,
        binding=resolved_options.binding,
        replay=resolved_options.replay,
        created=resolved_options.created,
        expires=resolved_options.expires,
        ttl_seconds=resolved_options.ttl_seconds,
        nonce=resolved_options.nonce,
        content_digest=resolved_options.content_digest,
        components=resolved_options.components,
    ))
    fetch = resolved_options.fetch or default_fetch
    return fetch(request)
