from __future__ import annotations

from typing import Any, Mapping

from ._request import HttpRequest
from .sign import sign_request, signed_fetch
from .types import ClientOptions, SignOptions, VerifyPolicy, merge_model
from .verify import verify_request


class SignerClient:
    def __init__(self, signer: Any, defaults: ClientOptions | None = None):
        self.signer = signer
        self.defaults = defaults or ClientOptions()

    def sign_request(self, input_value: str | HttpRequest, init: Mapping[str, Any] | None = None, options: SignOptions | None = None) -> HttpRequest:
        merged = merge_model(
            SignOptions(
                label=self.defaults.label,
                binding=self.defaults.binding,
                replay=self.defaults.replay,
                created=self.defaults.created,
                expires=self.defaults.expires,
                ttl_seconds=self.defaults.ttl_seconds,
                nonce=self.defaults.nonce,
                content_digest=self.defaults.content_digest,
                components=self.defaults.components,
            ),
            options,
            SignOptions,
        )
        return sign_request(input_value, self.signer, init=init, options=merged)

    def signed_fetch(self, input_value: str | HttpRequest, init: Mapping[str, Any] | None = None, options: ClientOptions | None = None):
        merged = merge_model(self.defaults, options, ClientOptions)
        return signed_fetch(input_value, self.signer, init=init, options=merged)

    def fetch(self, input_value: str | HttpRequest, init: Mapping[str, Any] | None = None, options: ClientOptions | None = None):
        return self.signed_fetch(input_value, init=init, options=options)


class VerifierClient:
    def __init__(self, verify_message, nonce_store, defaults: VerifyPolicy | None = None):
        self.verify_message = verify_message
        self.nonce_store = nonce_store
        self.defaults = defaults or VerifyPolicy()

    def verify_request(self, request: HttpRequest, policy: VerifyPolicy | None = None, set_headers=None):
        merged = merge_model(self.defaults, policy, VerifyPolicy)
        return verify_request(
            request=request,
            verify_message=self.verify_message,
            nonce_store=self.nonce_store,
            policy=merged,
            set_headers=set_headers,
        )


def create_signer_client(signer: Any, defaults: ClientOptions | None = None) -> SignerClient:
    return SignerClient(signer, defaults)


def create_verifier_client(verify_message, nonce_store, defaults: VerifyPolicy | None = None) -> VerifierClient:
    return VerifierClient(verify_message, nonce_store, defaults)
