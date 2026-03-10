from __future__ import annotations

from typing import Any, Callable

from ._request import HttpRequest, bytes_to_hex, unix_now
from ._shared import (
    SelectedSignature,
    build_attempts,
    create_signature_base_minimal,
    ensure_authority,
    normalize_class_bound_policies,
    normalize_components_list,
    parse_key_id,
    required_request_bound_components,
    run_nonce_checks,
    run_time_checks,
    select_signature_from_headers,
    signature_bytes_to_hex,
    verify_content_digest,
)
from .types import VerifyFailure, VerifyPolicy, VerifySuccess, merge_model


def verify_request(
    request: HttpRequest,
    verify_message: Callable[[dict[str, Any]], bool],
    nonce_store: Any,
    policy: VerifyPolicy | None = None,
    set_headers: Callable[[str, str], None] | None = None,
):
    resolved_policy = merge_model(VerifyPolicy(), policy, VerifyPolicy)
    label = resolved_policy.label
    strict_label = resolved_policy.strict_label or False
    now = resolved_policy.now() if resolved_policy.now else unix_now()
    skew = resolved_policy.clock_skew_sec or 0
    allow_replayable = resolved_policy.replayable or False
    has_query = "?" in request.url and not request.url.endswith("?")
    has_body = request.body is not None
    request_bound_extras = normalize_components_list(resolved_policy.additional_request_bound_components)
    request_bound_required = required_request_bound_components(has_query, has_body, request_bound_extras)
    class_bound_policies = [ensure_authority(policy_item) for policy_item in normalize_class_bound_policies(resolved_policy.class_bound_policies)]
    if set_headers:
        set_headers("Accept-Signature", build_accept_signature_header(request_bound_required, class_bound_policies, not allow_replayable))
    signature_input_header = request.headers.get("signature-input")
    signature_header = request.headers.get("signature")
    if not signature_input_header or not signature_header:
        return VerifyFailure(reason="missing_headers")
    selected = select_signature_from_headers(signature_input_header, signature_header, label, strict_label)
    if isinstance(selected, VerifyFailure):
        return selected
    valid_candidates = [candidate for candidate in selected if parse_key_id(candidate.params.keyid)]
    if not valid_candidates:
        return VerifyFailure(reason="bad_keyid")
    attempts, saw_class_bound = build_attempts(
        valid_candidates,
        has_query,
        has_body,
        request_bound_extras,
        request_bound_required,
        class_bound_policies,
    )
    if not attempts:
        return VerifyFailure(reason="class_bound_not_allowed" if saw_class_bound and class_bound_policies else "not_request_bound")
    max_signature_verifications = (
        3 if resolved_policy.max_signature_verifications is None else resolved_policy.max_signature_verifications
    )
    last_failure = VerifyFailure(reason="bad_signature")
    for attempt in attempts[:max_signature_verifications]:
        candidate: SelectedSignature = attempt.candidate
        params = candidate.params
        replayable = not params.nonce
        time_failure = run_time_checks(now, skew, resolved_policy.max_validity_sec, params.created, params.expires)
        if time_failure:
            last_failure = time_failure
            continue
        nonce_failure, nonce_plan = run_nonce_checks(
            allow_replayable,
            params,
            now,
            nonce_store,
            resolved_policy.nonce_key,
            resolved_policy.max_nonce_window_sec,
        )
        if nonce_failure:
            last_failure = nonce_failure
            continue
        if replayable:
            has_invalidation = callable(resolved_policy.replayable_not_before) or callable(resolved_policy.replayable_invalidated)
            if not has_invalidation:
                last_failure = VerifyFailure(reason="replayable_invalidation_required")
                continue
            if callable(resolved_policy.replayable_not_before):
                cutoff = resolved_policy.replayable_not_before(params.keyid)
                if cutoff is not None and params.created < cutoff:
                    last_failure = VerifyFailure(reason="replayable_not_before")
                    continue
        if "content-digest" in candidate.components:
            if not request.headers.get("content-digest"):
                last_failure = VerifyFailure(reason="digest_required")
                continue
            if not verify_content_digest(request):
                last_failure = VerifyFailure(reason="digest_mismatch")
                continue
        signature_base = create_signature_base_minimal(request, candidate.components, candidate.signature_params_value)
        signature_hex = signature_bytes_to_hex(candidate.sig_b64)
        if not signature_hex:
            last_failure = VerifyFailure(reason="bad_signature_bytes")
            continue
        if replayable and callable(resolved_policy.replayable_invalidated):
            invalidated = resolved_policy.replayable_invalidated(
                {
                    "keyid": params.keyid,
                    "created": params.created,
                    "expires": params.expires,
                    "label": candidate.label,
                    "signature": signature_hex,
                    "signatureBase": signature_base,
                    "signatureParamsValue": candidate.signature_params_value,
                }
            )
            if invalidated:
                last_failure = VerifyFailure(reason="replayable_invalidated")
                continue
        try:
            ok = verify_message(
                {
                    "address": attempt.key["address"],
                    "message": {"raw": bytes_to_hex(signature_base)},
                    "signature": signature_hex,
                }
            )
        except Exception:
            last_failure = VerifyFailure(reason="bad_signature_check")
            continue
        if ok:
            if nonce_plan.replay_key is not None:
                consumed = nonce_store.consume(nonce_plan.replay_key, nonce_plan.replay_ttl_seconds)
                if not consumed:
                    last_failure = VerifyFailure(reason="replay")
                    continue
            return VerifySuccess(
                address=attempt.key["address"],
                chain_id=attempt.key["chain_id"],
                label=candidate.label,
                components=candidate.components,
                params=params,
                replayable=replayable,
                binding=attempt.kind,
            )
        last_failure = VerifyFailure(reason="bad_signature")
    return last_failure


def build_accept_signature_header(request_bound_required: list[str], class_bound_policies: list[list[str]], require_nonce: bool) -> str:
    policies = ['(' + ' '.join(f'"{component}"' for component in request_bound_required) + ')']
    policies.extend('(' + ' '.join(f'"{component}"' for component in policy) + ')' for policy in class_bound_policies)
    value = ", ".join(policies)
    return f"{value};nonce={'?1' if require_nonce else '?0'}"
