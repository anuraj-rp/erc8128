from __future__ import annotations

import hmac
import re
from dataclasses import dataclass
from typing import Any, Mapping

from ._request import (
    Headers,
    HttpRequest,
    base64_decode,
    base64_encode,
    base64_url_encode,
    bytes_to_hex,
    hex_to_bytes,
    random_bytes,
    read_body_bytes,
    sanitize_url,
    sha256,
)
from .types import Erc8128Error, SignatureParams, VerifyFailure


KEYID_RE = re.compile(r"^erc8128:(\d+):(0x[a-fA-F0-9]{40})$")


def format_key_id(chain_id: int, address: str) -> str:
    if not isinstance(chain_id, int) or isinstance(chain_id, bool) or chain_id < 0:
        raise Erc8128Error("INVALID_OPTIONS", "chainId must be positive integer.")
    return f"erc8128:{chain_id}:{address.lower()}"


def parse_key_id(keyid: str) -> dict[str, Any] | None:
    match = KEYID_RE.match(keyid)
    if not match:
        return None
    return {"chain_id": int(match.group(1)), "address": match.group(2).lower()}


def resolve_nonce(nonce: str | Any | None) -> str:
    if isinstance(nonce, str):
        return nonce
    if callable(nonce):
        return nonce()
    return base64_url_encode(random_bytes(16))


def quote_sf_string(value: str) -> str:
    for char in value:
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise Erc8128Error("BAD_HEADER_VALUE", "sf-string cannot contain control characters.")
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def assert_label(label: str) -> None:
    if not re.match(r"^[a-z][a-z0-9_.-]*$", label):
        raise Erc8128Error("PARSE_ERROR", f"Invalid signature label: {label}")


def assert_signature_params_for_serialization(params: SignatureParams) -> None:
    if int(params.created) != params.created or int(params.expires) != params.expires:
        raise Erc8128Error("INVALID_OPTIONS", "created/expires must be integers.")
    if params.expires <= params.created:
        raise Erc8128Error("INVALID_OPTIONS", "expires must be > created.")
    if not params.keyid:
        raise Erc8128Error("INVALID_OPTIONS", "keyid is required.")


def serialize_signature_params_inner_list(components: list[str], params: SignatureParams) -> str:
    out = f"({' '.join(quote_sf_string(component) for component in components)})"
    out += f";created={params.created};expires={params.expires}"
    if params.nonce is not None:
        out += f";nonce={quote_sf_string(params.nonce)}"
    if params.tag is not None:
        out += f";tag={quote_sf_string(params.tag)}"
    out += f";keyid={quote_sf_string(params.keyid)}"
    return out


def serialize_signature_input_header(label: str, signature_params_value: str) -> str:
    assert_label(label)
    return f"{label}={signature_params_value}"


def serialize_signature_header(label: str, signature_b64: str) -> str:
    assert_label(label)
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", signature_b64):
        raise Erc8128Error("BAD_HEADER_VALUE", "Signature must be base64.")
    return f"{label}=:{signature_b64}:"


def append_dictionary_member(existing: str | None, member: str) -> str:
    return member if not existing else f"{existing}, {member}"


def normalize_components(components: list[str]) -> list[str]:
    return [component.strip() for component in components if component.strip()]


def default_components(binding: str, has_query: bool, has_body: bool) -> list[str]:
    if binding == "class-bound":
        return ["@authority"]
    components = ["@authority", "@method", "@path"]
    if has_query:
        components.append("@query")
    if has_body:
        components.append("content-digest")
    return components


def resolve_components(binding: str, has_query: bool, has_body: bool, provided_components: list[str] | None) -> list[str]:
    if binding == "request-bound":
        base = default_components(binding, has_query, has_body)
        if not provided_components:
            return base
        extra = [component for component in normalize_components(provided_components) if component not in base]
        return base + extra
    if not provided_components:
        raise Erc8128Error("INVALID_OPTIONS", "components are required for class-bound signatures.")
    components = normalize_components(provided_components)
    if "@authority" not in components:
        components.insert(0, "@authority")
    return components


def set_content_digest_header(request: HttpRequest, mode: str) -> HttpRequest:
    headers = request.headers.copy()
    existing = headers.get("content-digest")
    if mode == "off":
        raise Erc8128Error("DIGEST_REQUIRED", "content-digest is required by covered components, but contentDigest='off'.")
    if mode == "require" and not existing:
        raise Erc8128Error("DIGEST_REQUIRED", "content-digest is required but missing.")
    if existing and mode == "auto":
        return request
    digest = base64_encode(sha256(read_body_bytes(request)))
    headers.set("content-digest", f"sha-256=:{digest}:")
    return request.clone(headers=headers)


def parse_content_digest(value: str) -> dict[str, str] | None:
    match = re.match(r"^([A-Za-z0-9_-]+)=:([A-Za-z0-9+/]+={0,2}):$", value.strip())
    if not match:
        return None
    return {"alg": match.group(1).lower(), "b64": match.group(2)}


def verify_content_digest(request: HttpRequest) -> bool:
    value = request.headers.get("content-digest")
    if not value:
        return False
    parsed = parse_content_digest(value)
    if not parsed or parsed["alg"] != "sha-256":
        return False
    return hmac.compare_digest(parsed["b64"], base64_encode(sha256(read_body_bytes(request))))


def create_signature_base_minimal(request: HttpRequest, components: list[str], signature_params_value: str) -> bytes:
    url = sanitize_url(request.url)
    lines: list[str] = []
    for component in components:
        value = component_value_minimal(request, url, component)
        if any(ord(char) < 0x20 or ord(char) > 0x7E for char in value) or "\r" in value or "\n" in value:
            raise Erc8128Error("BAD_DERIVED_VALUE", f"Component {component} produced invalid characters.")
        lines.append(f"{quote_sf_string(component)}: {value}")
    lines.append(f"{quote_sf_string('@signature-params')}: {signature_params_value}")
    return "\n".join(lines).encode("utf-8")


def component_value_minimal(request: HttpRequest, url, component: str) -> str:
    if component == "@method":
        return request.method.upper()
    if component == "@authority":
        authority = url.hostname.lower() if url.hostname else ""
        if url.port:
            is_default = (url.scheme == "http" and url.port == 80) or (url.scheme == "https" and url.port == 443)
            if not is_default:
                authority = f"{authority}:{url.port}"
        return authority
    if component == "@path":
        return url.path or "/"
    if component == "@query":
        return f"?{url.query}" if url.query else ""
    header_value = request.headers.get(component)
    if header_value is None:
        raise Erc8128Error("BAD_HEADER_VALUE", f'Required header "{component}" is missing.')
    return re.sub(r"[ \t]+", " ", header_value.strip())


@dataclass(frozen=True)
class ParsedSignatureInputMember:
    label: str
    components: list[str]
    params: SignatureParams
    signature_params_value: str


def parse_signature_input_dictionary(header_value: str) -> list[ParsedSignatureInputMember]:
    out: list[ParsedSignatureInputMember] = []
    for raw in split_top_level_commas(header_value):
        member = raw.strip()
        if not member:
            continue
        label, sep, value = member.partition("=")
        if not sep:
            raise Erc8128Error("PARSE_ERROR", "Invalid Signature-Input member (missing '=').")
        label = label.strip()
        assert_label(label)
        items, params = parse_inner_list_with_params(value.strip())
        out.append(
            ParsedSignatureInputMember(
                label=label,
                components=items,
                params=params,
                signature_params_value=value.strip(),
            )
        )
    return out


def parse_signature_dictionary(header_value: str) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in split_top_level_commas(header_value):
        member = raw.strip()
        if not member:
            continue
        label, sep, value = member.partition("=")
        if not sep:
            raise Erc8128Error("PARSE_ERROR", "Invalid Signature member (missing '=').")
        label = label.strip()
        assert_label(label)
        out[label] = parse_binary_item(value.strip())
    return out


def parse_binary_item(value: str) -> str:
    if not value.startswith(":") or not value.endswith(":") or len(value) < 3:
        raise Erc8128Error("PARSE_ERROR", "Invalid sf-binary.")
    inner = value[1:-1]
    if not re.match(r"^[A-Za-z0-9+/]+={0,2}$", inner):
        raise Erc8128Error("PARSE_ERROR", "Invalid base64 in sf-binary.")
    return inner


def parse_inner_list_with_params(value: str) -> tuple[list[str], SignatureParams]:
    s = value.strip()
    if not s.startswith("("):
        raise Erc8128Error("PARSE_ERROR", "Inner list must start with '('.")
    index = 1
    items: list[str] = []
    while index < len(s):
        while index < len(s) and s[index] in " \t":
            index += 1
        if index < len(s) and s[index] == ")":
            index += 1
            break
        item, index = parse_sf_string(s, index)
        items.append(item)
        while index < len(s) and s[index] in " \t":
            index += 1
    if not items:
        raise Erc8128Error("PARSE_ERROR", "Inner list has no items.")
    params: dict[str, Any] = {}
    while index < len(s):
        while index < len(s) and s[index] in " \t":
            index += 1
        if index >= len(s) or s[index] != ";":
            break
        index += 1
        while index < len(s) and s[index] in " \t":
            index += 1
        key_match = re.match(r"[A-Za-z0-9_\-*.]+", s[index:])
        if not key_match:
            raise Erc8128Error("PARSE_ERROR", "Expected token.")
        key = key_match.group(0)
        index += len(key)
        while index < len(s) and s[index] in " \t":
            index += 1
        if index >= len(s) or s[index] != "=":
            raise Erc8128Error("PARSE_ERROR", f"Param {key} missing '='.")
        index += 1
        while index < len(s) and s[index] in " \t":
            index += 1
        if index < len(s) and s[index] == '"':
            params[key], index = parse_sf_string(s, index)
            continue
        number_match = re.match(r"-?\d+", s[index:])
        if not number_match:
            raise Erc8128Error("PARSE_ERROR", "Expected param value.")
        params[key] = int(number_match.group(0))
        index += len(number_match.group(0))
    created = params.get("created")
    expires = params.get("expires")
    keyid = params.get("keyid")
    if not isinstance(created, int) or not isinstance(expires, int) or not isinstance(keyid, str):
        raise Erc8128Error("PARSE_ERROR", "Missing or invalid created/expires/keyid in Signature-Input.")
    return items, SignatureParams(
        created=created,
        expires=expires,
        keyid=keyid,
        nonce=params.get("nonce") if isinstance(params.get("nonce"), str) else None,
        tag=params.get("tag") if isinstance(params.get("tag"), str) else None,
    )


def parse_sf_string(s: str, index: int) -> tuple[str, int]:
    if s[index] != '"':
        raise Erc8128Error("PARSE_ERROR", "Expected sf-string.")
    index += 1
    out = []
    while index < len(s):
        char = s[index]
        if char == '"':
            return "".join(out), index + 1
        if char == "\\":
            index += 1
            if index >= len(s):
                raise Erc8128Error("PARSE_ERROR", "Bad escape in sf-string.")
            out.append(s[index])
            index += 1
            continue
        if ord(char) < 0x20 or ord(char) == 0x7F:
            raise Erc8128Error("PARSE_ERROR", "Control char in sf-string.")
        out.append(char)
        index += 1
    raise Erc8128Error("PARSE_ERROR", "Expected sf-string.")


def split_top_level_commas(value: str) -> list[str]:
    out: list[str] = []
    current: list[str] = []
    in_quotes = False
    escaped = False
    for char in value:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and in_quotes:
            current.append(char)
            escaped = True
            continue
        if char == '"':
            current.append(char)
            in_quotes = not in_quotes
            continue
        if char == "," and not in_quotes:
            out.append("".join(current))
            current = []
            continue
        current.append(char)
    if current:
        out.append("".join(current))
    return out


@dataclass(frozen=True)
class SelectedSignature:
    label: str
    components: list[str]
    params: SignatureParams
    signature_params_value: str
    sig_b64: str


def select_signature_from_headers(signature_input_header: str, signature_header: str, label: str | None, strict_label: bool) -> list[SelectedSignature] | VerifyFailure:
    try:
        parsed_inputs = parse_signature_input_dictionary(signature_input_header)
        parsed_signatures = parse_signature_dictionary(signature_header)
        candidates = [
            SelectedSignature(
                label=member.label,
                components=member.components,
                params=member.params,
                signature_params_value=member.signature_params_value,
                sig_b64=parsed_signatures[member.label],
            )
            for member in parsed_inputs
            if member.label in parsed_signatures
        ]
    except Erc8128Error as error:
        return VerifyFailure(reason="bad_signature_input", detail=str(error))
    if not candidates:
        return VerifyFailure(reason="label_not_found")
    if label is not None and strict_label:
        matching = [candidate for candidate in candidates if candidate.label == label]
        if not matching:
            return VerifyFailure(reason="label_not_found")
        return matching
    return candidates


def normalize_components_list(components: list[str] | None) -> list[str]:
    if not components:
        return []
    out: list[str] = []
    for component in components:
        normalized = component.strip()
        if normalized and normalized not in out:
            out.append(normalized)
    return out


def normalize_class_bound_policies(policies: list[str] | list[list[str]] | None) -> list[list[str]]:
    if not policies:
        return []
    if policies and isinstance(policies[0], str):
        return [normalize_components_list(policies)]  # type: ignore[arg-type]
    return [normalize_components_list(policy) for policy in policies]  # type: ignore[list-item]


def ensure_authority(policy: list[str]) -> list[str]:
    return policy if "@authority" in policy else ["@authority", *policy]


def required_request_bound_components(has_query: bool, has_body: bool, extra_components: list[str] | None) -> list[str]:
    needed = ["@authority", "@method", "@path"]
    if has_query:
        needed.append("@query")
    if has_body:
        needed.append("content-digest")
    for component in extra_components or []:
        if component not in needed:
            needed.append(component)
    return needed


def includes_all_components(required: list[str], components: list[str]) -> bool:
    available = set(components)
    return all(component in available for component in required)


@dataclass(frozen=True)
class Attempt:
    candidate: SelectedSignature
    key: dict[str, Any]
    kind: str
    policy_length: int


def build_attempts(candidates: list[SelectedSignature], has_query: bool, has_body: bool, request_bound_extras: list[str], request_bound_required: list[str], class_bound_policies: list[list[str]]) -> tuple[list[Attempt], bool]:
    attempts: list[Attempt] = []
    saw_class_bound = False
    for candidate in candidates:
        key = parse_key_id(candidate.params.keyid)
        if not key:
            continue
        if includes_all_components(required_request_bound_components(has_query, has_body, request_bound_extras), candidate.components):
            attempts.append(Attempt(candidate=candidate, key=key, kind="request-bound", policy_length=len(request_bound_required)))
            continue
        saw_class_bound = True
        matches = [policy for policy in class_bound_policies if includes_all_components(policy, candidate.components)]
        if not matches:
            continue
        attempts.append(Attempt(candidate=candidate, key=key, kind="class-bound", policy_length=min(len(policy) for policy in matches)))
    return attempts, saw_class_bound


def run_time_checks(now: int, skew: int, max_validity_sec: int | None, created: int, expires: int):
    if int(created) != created or int(expires) != expires or expires <= created:
        return VerifyFailure(reason="bad_time")
    if now + skew < created:
        return VerifyFailure(reason="not_yet_valid")
    if now - skew > expires:
        return VerifyFailure(reason="expired")
    max_validity = 300 if max_validity_sec is None else max_validity_sec
    if expires - created > max_validity:
        return VerifyFailure(reason="validity_too_long")
    return None


@dataclass(frozen=True)
class NoncePlan:
    replay_key: str | None
    replay_ttl_seconds: int


def run_nonce_checks(allow_replayable: bool, params: SignatureParams, now: int, nonce_store: Any, nonce_key: Any, max_nonce_window_sec: int | None):
    has_nonce = bool(params.nonce)
    if not has_nonce and not allow_replayable:
        return VerifyFailure(reason="replayable_not_allowed"), NoncePlan(None, 0)
    if has_nonce:
        if nonce_store is None or not hasattr(nonce_store, "consume"):
            return VerifyFailure(reason="nonce_required", detail="nonceStore missing"), NoncePlan(None, 0)
        if max_nonce_window_sec is not None and params.expires - params.created > max_nonce_window_sec:
            return VerifyFailure(reason="nonce_window_too_long"), NoncePlan(None, 0)
        key_fn = nonce_key or (lambda keyid, nonce: f"{keyid}:{nonce}")
        return None, NoncePlan(key_fn(params.keyid, params.nonce), max(0, params.expires - now))
    return None, NoncePlan(None, 0)


def signature_bytes_to_hex(signature_b64: str) -> str | None:
    decoded = base64_decode(signature_b64)
    if decoded is None or len(decoded) == 0:
        return None
    return bytes_to_hex(decoded)
