import base64
import hashlib
import hmac
import unittest

from erc8128 import HttpRequest, SignOptions, VerifyPolicy, sign_request, verify_request
from erc8128._shared import format_key_id
from erc8128.verify import build_accept_signature_header


SECRET = b"erc8128-test-secret"
ADDRESS = "0x1111111111111111111111111111111111111111"


class HmacSigner:
    chain_id = 1
    address = ADDRESS

    def sign_message(self, message: bytes) -> str:
        digest = hmac.new(SECRET, message, hashlib.sha256).digest()
        return f"0x{digest.hex()}"


class NonceStore:
    def __init__(self):
        self.seen = set()

    def consume(self, key: str, ttl_seconds: int) -> bool:
        if key in self.seen:
            return False
        self.seen.add(key)
        return True


def verify_message(args):
    expected = hmac.new(SECRET, bytes.fromhex(args["message"]["raw"][2:]), hashlib.sha256).hexdigest()
    return args["address"].lower() == ADDRESS and args["signature"] == f"0x{expected}"


class SignVerifyTests(unittest.TestCase):
    def test_round_trip_request_bound_post(self):
        signer = HmacSigner()
        created = 1_700_000_000
        request = HttpRequest(
            "https://example.com/api/v1/hello?x=1",
            method="POST",
            headers={"content-type": "text/plain"},
            body="hello",
        )
        signed = sign_request(
            request,
            signer,
            options=SignOptions(created=created, expires=created + 60, nonce="nonce-1"),
        )
        digest = base64.b64encode(hashlib.sha256(b"hello").digest()).decode("ascii")
        self.assertEqual(signed.headers.get("content-digest"), f"sha-256=:{digest}:")
        self.assertIn('nonce="nonce-1"', signed.headers["signature-input"])
        result = verify_request(
            signed,
            verify_message=verify_message,
            nonce_store=NonceStore(),
            policy=VerifyPolicy(now=lambda: created),
        )
        self.assertTrue(result.ok)
        self.assertEqual(result.address, ADDRESS)
        self.assertEqual(result.chain_id, 1)
        self.assertFalse(result.replayable)
        self.assertEqual(result.binding, "request-bound")

    def test_verify_rejects_replay(self):
        signer = HmacSigner()
        created = 1_700_000_000
        signed = sign_request(
            "https://example.com/replay",
            signer,
            init={"method": "GET"},
            options=SignOptions(created=created, expires=created + 60, nonce="nonce-2"),
        )
        store = NonceStore()
        first = verify_request(signed, verify_message=verify_message, nonce_store=store, policy=VerifyPolicy(now=lambda: created))
        second = verify_request(signed, verify_message=verify_message, nonce_store=store, policy=VerifyPolicy(now=lambda: created))
        self.assertTrue(first.ok)
        self.assertFalse(second.ok)
        self.assertEqual(second.reason, "replay")

    def test_verify_defaults_max_signature_verifications_for_non_positive_values(self):
        signer = HmacSigner()
        created = 1_700_000_000
        signed = sign_request(
            "https://example.com/limit",
            signer,
            init={"method": "GET"},
            options=SignOptions(created=created, expires=created + 60, nonce="nonce-3"),
        )
        calls = 0

        def counting_verify_message(args):
            nonlocal calls
            calls += 1
            return verify_message(args)

        for limit in (0, -1):
            with self.subTest(limit=limit):
                calls = 0
                result = verify_request(
                    signed,
                    verify_message=counting_verify_message,
                    nonce_store=NonceStore(),
                    policy=VerifyPolicy(now=lambda: created, max_signature_verifications=limit),
                )
                self.assertTrue(result.ok)
                self.assertEqual(calls, 1)

    def test_verify_sets_accept_signature_header_in_ts_format(self):
        header = build_accept_signature_header(
            ["@authority", "@method", "@path"],
            [["@authority"], ["@authority", "@method", "@path"]],
            True,
        )
        self.assertEqual(
            header,
            'sig1=("@authority" "@method" "@path");keyid;created;expires;nonce, '
            'sig2=("@authority");keyid;created;expires;nonce',
        )

    def test_verify_ignores_accept_signature_header_failures(self):
        signer = HmacSigner()
        created = 1_700_000_000
        signed = sign_request(
            "https://example.com/header-failure",
            signer,
            init={"method": "GET"},
            options=SignOptions(created=created, expires=created + 60, nonce="nonce-4"),
        )

        def raising_set_headers(name, value):
            raise RuntimeError("header sink failed")

        result = verify_request(
            signed,
            verify_message=verify_message,
            nonce_store=NonceStore(),
            policy=VerifyPolicy(now=lambda: created),
            set_headers=raising_set_headers,
        )
        self.assertTrue(result.ok)

    def test_verify_ignores_accept_signature_serialization_failures(self):
        signer = HmacSigner()
        created = 1_700_000_000
        signed = sign_request(
            "https://example.com/header-serialization-failure",
            signer,
            init={"method": "GET"},
            options=SignOptions(created=created, expires=created + 60, nonce="nonce-5"),
        )

        result = verify_request(
            signed,
            verify_message=verify_message,
            nonce_store=NonceStore(),
            policy=VerifyPolicy(
                now=lambda: created,
                class_bound_policies=[["@authority", "bad\ncomponent"]],
            ),
            set_headers=lambda name, value: None,
        )
        self.assertTrue(result.ok)

    def test_format_key_id_rejects_bool_and_float(self):
        for chain_id in (True, 1.0):
            with self.subTest(chain_id=chain_id):
                with self.assertRaisesRegex(Exception, "chainId must be positive integer"):
                    format_key_id(chain_id, ADDRESS)


if __name__ == "__main__":
    unittest.main()
