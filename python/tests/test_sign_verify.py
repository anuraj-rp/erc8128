import base64
import hashlib
import hmac
import unittest

from erc8128 import HttpRequest, SignOptions, VerifyPolicy, sign_request, verify_request


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


if __name__ == "__main__":
    unittest.main()
