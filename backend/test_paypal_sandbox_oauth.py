"""
FraudTrace AI — PayPal Sandbox OAuth Connectivity Test Script
=============================================================
Verifies both:
1. Offline unit/security checks (mocked HTTP transport: Basic Auth formatting,
   `grant_type=client_credentials`, Sandbox-only URL enforcement, missing config,
   safe HTTP 401/network error handling, and zero secret/token leakage).
2. Live PayPal Sandbox OAuth connectivity test against `POST /v1/oauth2/token`
   using credentials loaded cleanly from `backend/.env`.

Usage (from D:\\FraudTrace-AI):
    backend\\.venv\\Scripts\\python.exe backend\\test_paypal_sandbox_oauth.py
    backend\\.venv\\Scripts\\python.exe backend\\test_paypal_sandbox_oauth.py --offline-only
"""

from __future__ import annotations

import argparse
import base64
from dataclasses import asdict
import json
import sys
from pathlib import Path

import httpx

# Ensure `backend/` is importable regardless of caller working directory
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.services.paypal_client import verify_paypal_sandbox_oauth  # noqa: E402


def run_offline_unit_checks() -> None:
    """Verifies OAuth request structure, error handling, and non-disclosure guarantees cleanly."""
    dummy_id = "sandbox_dummy_client_id"
    dummy_secret = "sandbox_dummy_secret_value_never_leaked"
    dummy_token = "A21AA_DUMMY_ACCESS_TOKEN_MUST_NOT_APPEAR"
    dummy_env = {
        "PAYPAL_CLIENT_ID": dummy_id,
        "PAYPAL_CLIENT_SECRET": dummy_secret,
        "PAYPAL_BASE_URL": "https://api-m.sandbox.paypal.com",
    }

    # 1. Valid OAuth response verifies Basic auth header, form body, and strips token from output
    captured: dict[str, str] = {}

    def _ok_handler(request: httpx.Request) -> httpx.Response:
        captured["method"] = request.method
        captured["url"] = str(request.url)
        captured["auth"] = request.headers.get("authorization", "")
        captured["content_type"] = request.headers.get("content-type", "")
        captured["body"] = request.content.decode("utf-8")
        return httpx.Response(
            status_code=200,
            json={
                "scope": "https://uri.paypal.com/services/payments/realtimepayment",
                "access_token": dummy_token,
                "token_type": "Bearer",
                "app_id": "APP-SANDBOX-TEST",
                "expires_in": 32400,
            },
        )

    ok_res = verify_paypal_sandbox_oauth(
        env_path=None,
        environ=dummy_env,
        transport=httpx.MockTransport(_ok_handler),
    )
    expected_b64 = base64.b64encode(f"{dummy_id}:{dummy_secret}".encode("utf-8")).decode("ascii")
    assert captured["method"] == "POST"
    assert captured["url"] == "https://api-m.sandbox.paypal.com/v1/oauth2/token"
    assert captured["auth"] == f"Basic {expected_b64}"
    assert "application/x-www-form-urlencoded" in captured["content_type"]
    assert captured["body"] == "grant_type=client_credentials"
    assert ok_res.authenticated is True
    assert ok_res.status_code == 200
    assert ok_res.token_received is True
    assert ok_res.token_type == "Bearer"
    assert ok_res.expires_in == 32400
    assert ok_res.scope_count == 1
    serialized_ok = json.dumps(asdict(ok_res))
    assert dummy_token not in serialized_ok
    assert dummy_secret not in serialized_ok
    assert dummy_id not in serialized_ok

    # 2. HTTP 401 handles bad credentials safely without leaking secrets or raw JSON error description
    def _auth_fail_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(
            status_code=401,
            json={
                "error": "invalid_client",
                "error_description": f"sensitive-echo {dummy_secret}",
            },
        )

    fail_res = verify_paypal_sandbox_oauth(
        env_path=None,
        environ=dummy_env,
        transport=httpx.MockTransport(_auth_fail_handler),
    )
    assert fail_res.authenticated is False
    assert fail_res.status_code == 401
    assert fail_res.token_received is False
    assert fail_res.error_code == "invalid_client"
    assert dummy_secret not in fail_res.message

    # 3. Missing required variables caught safely
    missing_res = verify_paypal_sandbox_oauth(env_path=None, environ={"PAYPAL_BASE_URL": "https://api-m.sandbox.paypal.com"})
    assert missing_res.authenticated is False
    assert missing_res.error_code == "configuration_error"
    assert "PAYPAL_CLIENT_ID" in missing_res.message
    assert "PAYPAL_CLIENT_SECRET" in missing_res.message

    # 4. Reject live production PayPal endpoint cleanly
    live_res = verify_paypal_sandbox_oauth(
        env_path=None,
        environ={
            "PAYPAL_CLIENT_ID": dummy_id,
            "PAYPAL_CLIENT_SECRET": dummy_secret,
            "PAYPAL_BASE_URL": "https://api-m.paypal.com",
        },
    )
    assert live_res.authenticated is False
    assert live_res.error_code == "configuration_error"
    assert "non-sandbox" in live_res.message

    # 5. HTTP 200 missing access_token rejected cleanly
    def _missing_token_handler(_: httpx.Request) -> httpx.Response:
        return httpx.Response(status_code=200, json={"token_type": "Bearer"})

    missing_tok_res = verify_paypal_sandbox_oauth(
        env_path=None,
        environ=dummy_env,
        transport=httpx.MockTransport(_missing_token_handler),
    )
    assert missing_tok_res.authenticated is False
    assert missing_tok_res.error_code == "missing_access_token"


def run_live_connectivity_check() -> int:
    """Runs the live PayPal Sandbox OAuth check against backend/.env without disclosing secrets."""
    result = verify_paypal_sandbox_oauth()
    print("PayPal Sandbox OAuth Connectivity Check")
    print(f"  Base URL       : {result.base_url}")
    print(f"  HTTP Status    : {result.status_code}")
    print(f"  Authenticated  : {result.authenticated}")
    print(f"  Token Received : {result.token_received}")
    if result.token_type:
        print(f"  Token Type     : {result.token_type}")
    if result.expires_in is not None:
        print(f"  Expires In     : {result.expires_in}s")
    if result.scope_count:
        print(f"  Granted Scopes : {result.scope_count}")
    if result.error_code:
        print(f"  Error Code     : {result.error_code}")
    print(f"  Message        : {result.message}")
    return 0 if result.authenticated else 1


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FraudTrace AI PayPal Sandbox OAuth connectivity test"
    )
    parser.add_argument(
        "--offline-only",
        action="store_true",
        help="Run only offline unit/security checks with mocked HTTP transport",
    )
    args = parser.parse_args()

    run_offline_unit_checks()
    print("[PASS] Offline PayPal OAuth unit and security checks passed.")

    if args.offline_only:
        return 0

    return run_live_connectivity_check()


if __name__ == "__main__":
    raise SystemExit(main())
