import hashlib
import hmac
import unittest
from unittest.mock import patch

import httpx

from erc8128 import ClientOptions, HttpResponse, SignOptions, VerifyPolicy, create_signer_client, create_verifier_client
from erc8128._request import HttpRequest, default_fetch


SECRET = b"erc8128-test-secret"
ADDRESS = "0x1111111111111111111111111111111111111111"


class HmacSigner:
    chain_id = 1
    address = ADDRESS

    def sign_message(self, message: bytes) -> str:
        digest = hmac.new(SECRET, message, hashlib.sha256).digest()
        return f"0x{digest.hex()}"


class NonceStore:
    def consume(self, key: str, ttl_seconds: int) -> bool:
        return True


def verify_message(args):
    expected = hmac.new(SECRET, bytes.fromhex(args["message"]["raw"][2:]), hashlib.sha256).hexdigest()
    return args["address"].lower() == ADDRESS and args["signature"] == f"0x{expected}"


class ClientTests(unittest.TestCase):
    def test_http_response_and_options_are_pydantic_models(self):
        response = HttpResponse(status=200, headers={"X-Test": "1"}, body=b"ok", url="https://example.com")
        self.assertEqual(response.headers["x-test"], "1")
        self.assertEqual(ClientOptions(nonce="nonce-1").model_dump()["nonce"], "nonce-1")

    def test_sign_request_merges_defaults_with_call_options(self):
        client = create_signer_client(
            HmacSigner(),
            ClientOptions(created=1_700_000_000, expires=1_700_000_060, nonce="nonce-default"),
        )
        signed = client.sign_request("https://example.com", options=SignOptions(nonce="nonce-override"))
        self.assertIn('nonce="nonce-override"', signed.headers["signature-input"])
        self.assertIn("created=1700000000", signed.headers["signature-input"])
        self.assertIn("expires=1700000060", signed.headers["signature-input"])

    def test_fetch_uses_configured_fetch(self):
        recorded = {}

        def fetch(request):
            recorded["request"] = request
            return HttpResponse(status=200, headers=request.headers.copy(), body=b"ok", url=request.url)

        client = create_signer_client(
            HmacSigner(),
            ClientOptions(
                fetch=fetch,
                created=1_700_000_000,
                expires=1_700_000_060,
                nonce="nonce-default",
            ),
        )
        client.fetch("https://example.com", init={"method": "GET"}, options=ClientOptions(nonce="nonce-call"))
        self.assertIn('nonce="nonce-call"', recorded["request"].headers["signature-input"])

    @patch("erc8128._request.httpx.request")
    def test_default_fetch_uses_httpx(self, mock_request):
        mock_request.return_value = httpx.Response(
            201,
            headers={"X-Test": "1"},
            content=b"ok",
            request=httpx.Request("POST", "https://example.com/orders"),
        )

        response = default_fetch(
            HttpRequest(
                "https://example.com/orders",
                method="POST",
                headers={"content-type": "text/plain"},
                body="hello",
            )
        )

        mock_request.assert_called_once_with(
            "POST",
            "https://example.com/orders",
            headers={"content-type": "text/plain"},
            content=b"hello",
            follow_redirects=True,
        )
        self.assertEqual(response.status, 201)
        self.assertEqual(response.headers["x-test"], "1")
        self.assertEqual(response.body, b"ok")
        self.assertEqual(response.url, "https://example.com/orders")

    def test_verifier_client_uses_defaults(self):
        signer_client = create_signer_client(HmacSigner())
        signed = signer_client.sign_request(
            "https://example.com/orders",
            init={"method": "POST", "body": '{"amount":"1"}', "headers": {"content-type": "application/json"}},
            options=SignOptions(created=1_700_000_000, expires=1_700_000_060, nonce="nonce-client"),
        )
        verifier = create_verifier_client(
            verify_message=verify_message,
            nonce_store=NonceStore(),
            defaults=VerifyPolicy(now=lambda: 1_700_000_000),
        )
        result = verifier.verify_request(signed)
        self.assertTrue(result.ok)


if __name__ == "__main__":
    unittest.main()
