"""
FraudTrace AI — Test Suite: PayPal Sandbox Orders v2 Integration
================================================================
Offline verification suite using isolated temporary SQLite databases and
mocked `httpx.MockTransport` HTTP responses covering:
1. OAuth in-memory token reuse, early expiry refresh, and HTTP 401 retry.
2. Order creation validation, idempotent replay, conflict detection, and safe URL checks.
3. Failed OAuth auth, PayPal HTTP errors, and timeouts with secret non-disclosure.
4. Eligible APPROVED-order enforcement, declined capture handling, and amount parity guard.
5. Confirmed capture -> FraudTrace deterministic risk evaluation without auto-blocking.
6. Repeated capture idempotency and duplicate internal transaction prevention.
7. Invalid payment amounts and unsupported currency rejection.
8. Non-disclosure of Client ID, Client Secret, and Bearer tokens across responses & DB.

ISOLATION:
Uses `httpx.MockTransport` and isolated temporary SQLite files (`tempfile`),
never touching PayPal live/sandbox network or `backend/data/fraudtrace.db`.
"""

from __future__ import annotations

from decimal import Decimal
import json
from pathlib import Path
import sys
import tempfile

import httpx
from fastapi import HTTPException, Response
from pydantic import ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

# Ensure `backend/` directory is importable
sys.path.insert(0, str(Path(__file__).resolve().parent))

from app.database import Base  # noqa: E402
from app.models import Evidence, Investigation, PayPalOrder, Transaction  # noqa: E402
from app.routes import paypal as paypal_routes  # noqa: E402
from app.schemas import PayPalOrderCreateRequest  # noqa: E402
from app.services.paypal_client import (  # noqa: E402
    DEFAULT_PAYPAL_CANCEL_URL,
    DEFAULT_PAYPAL_RETURN_URL,
    PayPalConfigurationError,
    PayPalSandboxClient,
    load_paypal_sandbox_config,
    validate_paypal_redirect_url,
)
from app.services.risk_engine import analyze_transaction_risk  # noqa: E402
import test_paypal_sandbox_live as live_smoke  # noqa: E402


def _create_isolated_session():
    temp_handle = tempfile.NamedTemporaryFile(suffix="_test_paypal_ft.db", delete=False)
    temp_path = Path(temp_handle.name).resolve()
    temp_handle.close()

    engine = create_engine(
        f"sqlite:///{temp_path.as_posix()}",
        connect_args={"check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def set_pragma(dbapi_connection, _connection_record):  # noqa: ANN001
        cursor = dbapi_connection.cursor()
        cursor.execute("PRAGMA foreign_keys=ON")
        cursor.close()

    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base.metadata.create_all(bind=engine)
    return engine, SessionLocal, temp_path


def _teardown_isolated_db(engine, temp_path: Path) -> None:
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if temp_path.exists():
        temp_path.unlink()


class _FakeClock:
    def __init__(self, initial: float = 1000.0) -> None:
        self.now = initial

    def __call__(self) -> float:
        return self.now


class _PayPalMockHarness:
    """Controllable in-memory PayPal Sandbox HTTP mock for OAuth + Orders v2."""

    def __init__(self) -> None:
        self.dummy_client_id = "SANDBOX_MOCK_CLIENT_ID_XYZ"
        self.dummy_client_secret = "SANDBOX_MOCK_CLIENT_SECRET_DO_NOT_LEAK"
        self.tokens_issued: list[str] = []
        self.token_calls = 0
        self.create_calls = 0
        self.get_calls = 0
        self.capture_calls = 0
        self.last_create_headers: dict[str, str] = {}
        self.last_create_body: dict = {}
        self.last_capture_headers: dict[str, str] = {}

        self.token_ttl = 120
        self.fail_oauth_401 = False
        self.force_401_once_on_orders = False
        self.orders_error_status: int | None = None
        self.simulate_timeout = False
        self.return_phishing_approval_link = False
        self.simulate_payer_action_required = False
        self.tamper_capture_amount: str | None = None

        self.orders_store: dict[str, dict] = {}
        self._seq = 100
        self._cap_seq = 500

    def env_dict(self) -> dict[str, str]:
        return {
            "PAYPAL_CLIENT_ID": self.dummy_client_id,
            "PAYPAL_CLIENT_SECRET": self.dummy_client_secret,
            "PAYPAL_BASE_URL": "https://api-m.sandbox.paypal.com",
        }

    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self._handle_request)

    def _handle_request(self, request: httpx.Request) -> httpx.Response:
        if self.simulate_timeout:
            raise httpx.ReadTimeout("Simulated PayPal timeout", request=request)

        path = request.url.path
        method = request.method.upper()

        if method == "POST" and path == "/v1/oauth2/token":
            self.token_calls += 1
            if self.fail_oauth_401:
                return httpx.Response(
                    status_code=401,
                    json={
                        "error": "invalid_client",
                        "error_description": f"Rejected {self.dummy_client_secret}",
                    },
                )
            token_val = f"MOCK_ACCESS_TOKEN_{self.token_calls}_{self.dummy_client_secret[:4]}"
            self.tokens_issued.append(token_val)
            return httpx.Response(
                status_code=200,
                json={
                    "scope": "https://uri.paypal.com/services/payments/realtimepayment",
                    "access_token": token_val,
                    "token_type": "Bearer",
                    "expires_in": self.token_ttl,
                },
            )

        # Verify Bearer token exists cleanly on Orders v2 calls
        auth_header = request.headers.get("authorization", "")
        if not auth_header.startswith("Bearer MOCK_ACCESS_TOKEN_"):
            return httpx.Response(status_code=401, json={"error": "invalid_token"})

        if self.force_401_once_on_orders:
            self.force_401_once_on_orders = False
            return httpx.Response(status_code=401, json={"name": "AUTHENTICATION_FAILURE"})

        if self.orders_error_status is not None:
            return httpx.Response(
                status_code=self.orders_error_status,
                json={
                    "name": "UNPROCESSABLE_ENTITY" if self.orders_error_status == 422 else "INTERNAL_SERVER_ERROR",
                    "message": f"Upstream raw detail containing {self.dummy_client_secret}",
                },
            )

        if method == "POST" and path == "/v2/checkout/orders":
            self.create_calls += 1
            self.last_create_headers = dict(request.headers)
            body = json.loads(request.content.decode("utf-8"))
            self.last_create_body = body

            self._seq += 1
            order_id = f"5O190127TN3647{self._seq}"
            pu = body["purchase_units"][0]
            amt_obj = pu["amount"]

            approval_href = (
                "https://evil-phishing.example.com/checkout?token=" + order_id
                if self.return_phishing_approval_link
                else f"https://www.sandbox.paypal.com/checkoutnow?token={order_id}"
            )
            link_rel = "payer-action" if self.simulate_payer_action_required else "approve"
            initial_status = "PAYER_ACTION_REQUIRED" if self.simulate_payer_action_required else "CREATED"

            record = {
                "id": order_id,
                "intent": body.get("intent", "CAPTURE"),
                "status": initial_status,
                "purchase_units": [
                    {
                        "reference_id": pu["reference_id"],
                        "amount": {
                            "currency_code": amt_obj["currency_code"],
                            "value": amt_obj["value"],
                        },
                    }
                ],
                "links": [
                    {"href": approval_href, "rel": link_rel, "method": "GET"},
                ],
            }
            self.orders_store[order_id] = record
            return httpx.Response(status_code=201, json=record)

        if method == "GET" and path.startswith("/v2/checkout/orders/"):
            self.get_calls += 1
            order_id = path.rsplit("/", 1)[-1]
            record = self.orders_store.get(order_id)
            if record is None:
                return httpx.Response(status_code=404, json={"name": "RESOURCE_NOT_FOUND"})
            return httpx.Response(status_code=200, json=record)

        if method == "POST" and path.startswith("/v2/checkout/orders/") and path.endswith("/capture"):
            self.capture_calls += 1
            self.last_capture_headers = dict(request.headers)
            parts = path.split("/")
            order_id = parts[-2]
            record = self.orders_store.get(order_id)
            if record is None:
                return httpx.Response(status_code=404, json={"name": "RESOURCE_NOT_FOUND"})

            pu = record["purchase_units"][0]
            self._cap_seq += 1
            cap_id = f"2GG279541U47{self._cap_seq}"
            cap_value = self.tamper_capture_amount or pu["amount"]["value"]
            cap_status = record.pop("_next_capture_status", "COMPLETED")
            order_status = "COMPLETED" if cap_status == "COMPLETED" else "PAYER_ACTION_REQUIRED"
            record["status"] = order_status
            record["payer"] = {"payer_id": "SANDBOX_PAYER_998"}
            pu["payments"] = {
                "captures": [
                    {
                        "id": cap_id,
                        "status": cap_status,
                        "amount": {
                            "currency_code": pu["amount"]["currency_code"],
                            "value": cap_value,
                        },
                    }
                ]
            }
            return httpx.Response(status_code=201, json=record)

        return httpx.Response(status_code=404, json={"error": "unknown_route"})


def _assert_no_secrets_disclosed(harness: _PayPalMockHarness, *objects: object) -> None:
    dumped = json.dumps(objects, default=str)
    assert harness.dummy_client_secret not in dumped
    assert harness.dummy_client_id not in dumped
    for tok in harness.tokens_issued:
        assert tok not in dumped


def test_1_token_caching_expiry_and_401_refresh() -> None:
    harness = _PayPalMockHarness()
    clock = _FakeClock(initial=1000.0)
    client = PayPalSandboxClient(
        env_path=None,
        environ=harness.env_dict(),
        transport=harness.transport(),
        expiry_skew_seconds=60.0,
        monotonic_fn=clock,
    )

    # First order acquires initial OAuth token cleanly (expires_in=120 -> buffered deadline = 1060.0)
    ord1 = client.create_order(amount=Decimal("45.00"), currency="USD", internal_reference="REF-TOK-1")
    assert ord1.status == "CREATED"
    assert harness.token_calls == 1
    assert client.get_cache_debug_state()["has_token"] is True

    # t=1050.0 (< 1060.0) reuses cached in-memory token without extra /v1/oauth2/token call
    clock.now = 1050.0
    ord2 = client.create_order(amount=Decimal("55.00"), currency="USD", internal_reference="REF-TOK-2")
    assert ord2.status == "CREATED"
    assert harness.token_calls == 1

    # t=1061.0 (>= 1060.0 buffered deadline) triggers automatic token refresh
    clock.now = 1061.0
    client.create_order(amount=Decimal("65.00"), currency="USD", internal_reference="REF-TOK-3")
    assert harness.token_calls == 2

    # Upstream 401 on Orders v2 clears cache and refreshes ONCE cleanly
    harness.force_401_once_on_orders = True
    ord4 = client.create_order(amount=Decimal("75.00"), currency="USD", internal_reference="REF-TOK-4")
    assert ord4.status == "CREATED"
    assert harness.token_calls == 3

    # Secrets / token must never appear in cache debug state or __repr__
    _assert_no_secrets_disclosed(harness, client.get_cache_debug_state(), repr(client))


def test_2_invalid_amounts_and_currencies_rejected() -> None:
    bad_payloads = [
        {"amount": "0.00", "currency": "USD"},
        {"amount": "-12.50", "currency": "USD"},
        {"amount": "12.345", "currency": "USD"},
        {"amount": "100000.01", "currency": "USD"},
        {"amount": "25.00", "currency": "XYZ"},
        {"amount": "25.00", "currency": "12"},
        {"amount": "25.00", "currency": "USD", "internal_reference": "bad space!"},
    ]
    for bad in bad_payloads:
        try:
            PayPalOrderCreateRequest(**bad)
            raise AssertionError(f"Expected ValidationError for invalid payload: {bad}")
        except ValidationError:
            pass

    valid = PayPalOrderCreateRequest(amount=Decimal("125.5"), currency=" eur ")
    assert valid.amount == Decimal("125.50")
    assert valid.currency == "EUR"


def test_3_create_order_idempotency_and_error_handling() -> None:
    engine, SessionLocal, temp_path = _create_isolated_session()
    harness = _PayPalMockHarness()
    clock = _FakeClock()
    client = PayPalSandboxClient(
        env_path=None,
        environ=harness.env_dict(),
        transport=harness.transport(),
        monotonic_fn=clock,
    )

    try:
        with SessionLocal() as db:
            # 1. Successful create order
            resp1 = Response()
            created = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("149.99"),
                    currency="USD",
                    internal_reference="ORD_IDEM_001",
                    sender_id="BUYER_ALFA",
                ),
                response=resp1,
                db=db,
                paypal_client=client,
            )
            assert created.intent == "CAPTURE"
            assert created.status == "CREATED"
            assert created.amount == Decimal("149.99")
            assert created.currency == "USD"
            assert created.idempotent_replay is False
            assert created.approval_url is not None
            assert created.approval_url.startswith("https://www.sandbox.paypal.com/")
            assert harness.last_create_headers.get("paypal-request-id") == "ORD_IDEM_001"
            assert harness.last_create_body["intent"] == "CAPTURE"

            # 2. Identical retry with same internal_reference returns cached DB order without extra PayPal call
            prior_create_calls = harness.create_calls
            resp2 = Response()
            replayed = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("149.99"),
                    currency="USD",
                    internal_reference="ORD_IDEM_001",
                    sender_id="BUYER_ALFA",
                ),
                response=resp2,
                db=db,
                paypal_client=client,
            )
            assert resp2.status_code == 200
            assert replayed.idempotent_replay is True
            assert replayed.paypal_order_id == created.paypal_order_id
            assert harness.create_calls == prior_create_calls

            # 3. Same internal_reference with different amount -> 409 Conflict
            try:
                paypal_routes.create_paypal_order(
                    payload=PayPalOrderCreateRequest(
                        amount=Decimal("99.99"),
                        currency="USD",
                        internal_reference="ORD_IDEM_001",
                    ),
                    response=Response(),
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected 409 for mismatched idempotent order amount")
            except HTTPException as exc:
                assert exc.status_code == 409

            # 4. Suspicious non-sandbox HATEOAS approval link filtered safely
            harness.return_phishing_approval_link = True
            phish_check = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(amount=Decimal("20.00"), currency="USD"),
                response=Response(),
                db=db,
                paypal_client=client,
            )
            assert phish_check.approval_url is None
            harness.return_phishing_approval_link = False

            # 5. Auth failure -> safe 502 without leaking secret/error_description
            client.clear_cached_token()
            harness.fail_oauth_401 = True
            try:
                paypal_routes.create_paypal_order(
                    payload=PayPalOrderCreateRequest(amount=Decimal("10.00"), currency="USD"),
                    response=Response(),
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected HTTPException on failed OAuth")
            except HTTPException as exc:
                assert exc.status_code == 502
                _assert_no_secrets_disclosed(harness, exc.detail)
            harness.fail_oauth_401 = False

            # 6. PayPal 422/500 API errors and Timeout handled cleanly without leaking raw upstream text
            for err_code, expected_http in ((422, 422), (500, 502)):
                harness.orders_error_status = err_code
                try:
                    paypal_routes.create_paypal_order(
                        payload=PayPalOrderCreateRequest(amount=Decimal("10.00"), currency="USD"),
                        response=Response(),
                        db=db,
                        paypal_client=client,
                    )
                    raise AssertionError(f"Expected {expected_http} on PayPal HTTP {err_code}")
                except HTTPException as exc:
                    assert exc.status_code == expected_http
                    _assert_no_secrets_disclosed(harness, exc.detail)
            harness.orders_error_status = None

            harness.simulate_timeout = True
            try:
                paypal_routes.create_paypal_order(
                    payload=PayPalOrderCreateRequest(amount=Decimal("10.00"), currency="USD"),
                    response=Response(),
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected 504 on timeout")
            except HTTPException as exc:
                assert exc.status_code == 504
            harness.simulate_timeout = False

            _assert_no_secrets_disclosed(harness, created.model_dump(), replayed.model_dump())
    finally:
        _teardown_isolated_db(engine, temp_path)


def test_4_capture_guards_fraudtrace_scoring_and_duplicate_prevention() -> None:
    engine, SessionLocal, temp_path = _create_isolated_session()
    harness = _PayPalMockHarness()
    clock = _FakeClock()
    client = PayPalSandboxClient(
        env_path=None,
        environ=harness.env_dict(),
        transport=harness.transport(),
        monotonic_fn=clock,
    )

    try:
        with SessionLocal() as db:
            # Unknown order ID -> 404
            try:
                paypal_routes.capture_paypal_order(
                    order_id="MISSING_ORDER_999",
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected 404 for unknown order")
            except HTTPException as exc:
                assert exc.status_code == 404

            # Create Order A and attempt capture BEFORE approval (status=CREATED) -> 409 and capture NOT called
            created_a = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("500.00"),
                    currency="USD",
                    internal_reference="PP_CHECK_HIGH_RISK",
                    sender_id="PAYPAL_BURST_BUYER",
                    receiver_id="MERCHANT_VAULT_1",
                ),
                response=Response(),
                db=db,
                paypal_client=client,
            )
            try:
                paypal_routes.capture_paypal_order(
                    order_id=created_a.paypal_order_id,
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected 409 when capturing unapproved CREATED order")
            except HTTPException as exc:
                assert exc.status_code == 409
            assert harness.capture_calls == 0
            assert db.execute(select(Transaction)).scalars().all() == []

            # Approve Order A, but simulate DECLINED capture -> 422 and NO Transaction created
            harness.orders_store[created_a.paypal_order_id]["status"] = "APPROVED"
            harness.orders_store[created_a.paypal_order_id]["_next_capture_status"] = "DECLINED"
            try:
                paypal_routes.capture_paypal_order(
                    order_id=created_a.paypal_order_id,
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected 422 on DECLINED PayPal capture")
            except HTTPException as exc:
                assert exc.status_code == 422
            assert db.execute(select(Transaction)).scalars().all() == []
            row_after_decline = db.execute(
                select(PayPalOrder).where(PayPalOrder.paypal_order_id == created_a.paypal_order_id)
            ).scalar_one()
            assert row_after_decline.status == "DECLINED"
            assert row_after_decline.transaction_id is None

            # Verify amount mismatch tampering protection on Order B
            created_b = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("80.00"),
                    currency="USD",
                    internal_reference="PP_TAMPER_CHECK",
                ),
                response=Response(),
                db=db,
                paypal_client=client,
            )
            harness.orders_store[created_b.paypal_order_id]["status"] = "APPROVED"
            harness.tamper_capture_amount = "999.00"
            try:
                paypal_routes.capture_paypal_order(
                    order_id=created_b.paypal_order_id,
                    db=db,
                    paypal_client=client,
                )
                raise AssertionError("Expected 422 on tampered captured amount")
            except HTTPException as exc:
                assert exc.status_code == 422
            harness.tamper_capture_amount = None
            assert db.execute(select(Transaction)).scalars().all() == []

            # Now test confirmed capture + UNTOUCHED deterministic risk engine scoring:
            # Seed 3 prior $10.00 transfers in same minute so Order A ($500.00 = 50x avg, 3+ velocity, repeated recipient)
            # triggers TRANSACTION_VELOCITY (+25), AMOUNT_ANOMALY (+30), REPEATED_RECIPIENT_ACTIVITY (+25) => 80.0 CRITICAL!
            # Capture MUST still complete normally and record Transaction/Investigation without blocking/reversing payment.
            from datetime import datetime, timedelta, timezone

            now_utc = datetime.now(timezone.utc)
            for idx in range(1, 4):
                ts_prior = now_utc - timedelta(minutes=4 - idx)
                db.add(
                    Transaction(
                        reference=f"SEED-PRIOR-{idx}",
                        sender_id="PAYPAL_BURST_BUYER",
                        receiver_id="MERCHANT_VAULT_1",
                        amount=Decimal("10.00"),
                        currency="USD",
                        timestamp=ts_prior,
                        risk_score=10.0 if idx == 1 else 0.0,
                        risk_level="LOW",
                        investigation_status="CLEARED",
                    )
                )
            db.commit()

            # Reset Order A cleanly to APPROVED & capture
            harness.orders_store[created_a.paypal_order_id]["status"] = "APPROVED"
            expected_deterministic = analyze_transaction_risk(
                sender_id="PAYPAL_BURST_BUYER",
                receiver_id="MERCHANT_VAULT_1",
                amount=Decimal("500.00"),
                currency="USD",
                current_time=now_utc,
                db=db,
            )
            capture_res = paypal_routes.capture_paypal_order(
                order_id=created_a.paypal_order_id,
                db=db,
                paypal_client=client,
            )
            assert capture_res.already_captured is False
            assert capture_res.paypal_order.status == "COMPLETED"
            assert capture_res.paypal_order.paypal_capture_id is not None
            assert capture_res.paypal_order.captured_amount == Decimal("500.00")
            assert capture_res.paypal_order.transaction_id == capture_res.transaction_analysis.transaction.id

            # Exact preservation of deterministic risk score without blocking capture
            assert capture_res.transaction_analysis.risk_score == expected_deterministic.risk_score == 80.0
            assert capture_res.transaction_analysis.risk_level == "CRITICAL"
            assert capture_res.transaction_analysis.investigation_status == "FLAGGED"
            assert capture_res.transaction_analysis.transaction.reference.startswith("PP-CAP-")
            assert created_a.paypal_order_id in capture_res.transaction_analysis.explanation
            assert capture_res.paypal_order.paypal_capture_id in capture_res.transaction_analysis.explanation
            assert "PP_CHECK_HIGH_RISK" in capture_res.transaction_analysis.explanation

            # Repeat capture request -> MUST return existing result idempotently with 0 new PayPal calls & 0 duplicate txns
            prev_get_calls = harness.get_calls
            prev_cap_calls = harness.capture_calls
            txn_count_before = len(db.execute(select(Transaction)).scalars().all())
            inv_count_before = len(db.execute(select(Investigation)).scalars().all())
            ev_count_before = len(db.execute(select(Evidence)).scalars().all())

            repeat_res = paypal_routes.capture_paypal_order(
                order_id=created_a.paypal_order_id,
                db=db,
                paypal_client=client,
            )
            assert repeat_res.already_captured is True
            assert repeat_res.transaction_analysis.transaction.id == capture_res.transaction_analysis.transaction.id
            assert harness.get_calls == prev_get_calls
            assert harness.capture_calls == prev_cap_calls
            assert len(db.execute(select(Transaction)).scalars().all()) == txn_count_before
            assert len(db.execute(select(Investigation)).scalars().all()) == inv_count_before
            assert len(db.execute(select(Evidence)).scalars().all()) == ev_count_before

            # Already-COMPLETED on PayPal before local DB link -> GET recovers cleanly with 0 POST /capture calls
            created_c = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("240.00"),
                    currency="USD",
                    internal_reference="FT-ORD-RECOVERY-1",
                    sender_id="ACC_SAND_1",
                    receiver_id="ACC_SAND_9",
                ),
                response=Response(),
                db=db,
                paypal_client=client,
            )
            harness.orders_store[created_c.paypal_order_id]["status"] = "COMPLETED"
            harness.orders_store[created_c.paypal_order_id]["payer"] = {"payer_id": "SANDBOX_PAYER_REC"}
            harness.orders_store[created_c.paypal_order_id]["purchase_units"][0]["payments"] = {
                "captures": [
                    {
                        "id": "2GG279541U47RECOV1",
                        "status": "COMPLETED",
                        "amount": {"currency_code": "USD", "value": "240.00"},
                    }
                ]
            }
            cap_calls_before_recovery = harness.capture_calls
            recovered_res = paypal_routes.capture_paypal_order(
                order_id=created_c.paypal_order_id,
                db=db,
                paypal_client=client,
            )
            assert harness.capture_calls == cap_calls_before_recovery
            assert recovered_res.already_captured is False
            assert recovered_res.paypal_order.status == "COMPLETED"
            assert recovered_res.paypal_order.paypal_capture_id == "2GG279541U47RECOV1"
            assert recovered_res.transaction_analysis.transaction.reference == "PP-CAP-2GG279541U47RECOV1"

            # Check DB + response JSON never disclose secrets or tokens
            all_orders_dump = [repr(o) for o in db.execute(select(PayPalOrder)).scalars().all()]
            _assert_no_secrets_disclosed(harness, capture_res.model_dump(), repeat_res.model_dump(), recovered_res.model_dump(), all_orders_dump)
    finally:
        _teardown_isolated_db(engine, temp_path)


def test_5_experience_context_and_redirect_url_validation() -> None:
    engine, SessionLocal, temp_path = _create_isolated_session()
    harness = _PayPalMockHarness()
    clock = _FakeClock()

    try:
        # 1. Default experience_context uses payment_source.paypal.experience_context (never application_context)
        harness.simulate_payer_action_required = True
        default_client = PayPalSandboxClient(
            env_path=None,
            environ=harness.env_dict(),
            transport=harness.transport(),
            monotonic_fn=clock,
        )
        with SessionLocal() as db:
            created = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("12.00"),
                    currency="USD",
                    internal_reference="ORD_EXP_CTX_1",
                ),
                response=Response(),
                db=db,
                paypal_client=default_client,
            )
            assert created.status == "PAYER_ACTION_REQUIRED"
            assert created.approval_url is not None
            assert created.approval_url.startswith("https://www.sandbox.paypal.com/checkoutnow?token=")

        sent_body = harness.last_create_body
        assert "application_context" not in sent_body
        exp_ctx = sent_body["payment_source"]["paypal"]["experience_context"]
        assert exp_ctx == {
            "shipping_preference": "NO_SHIPPING",
            "user_action": "PAY_NOW",
            "return_url": DEFAULT_PAYPAL_RETURN_URL,
            "cancel_url": DEFAULT_PAYPAL_CANCEL_URL,
        }

        # 2. Configurable HTTPS redirect URLs from env propagate cleanly into experience_context
        custom_env = dict(harness.env_dict())
        custom_env["PAYPAL_RETURN_URL"] = "https://fraudtrace.example.com/paypal/return"
        custom_env["PAYPAL_CANCEL_URL"] = "https://fraudtrace.example.com/paypal/cancel"
        custom_client = PayPalSandboxClient(
            env_path=None,
            environ=custom_env,
            transport=harness.transport(),
            monotonic_fn=clock,
        )
        custom_client.create_order(
            amount=Decimal("15.00"),
            currency="USD",
            internal_reference="ORD_EXP_CTX_2",
        )
        custom_exp_ctx = harness.last_create_body["payment_source"]["paypal"]["experience_context"]
        assert custom_exp_ctx["return_url"] == "https://fraudtrace.example.com/paypal/return"
        assert custom_exp_ctx["cancel_url"] == "https://fraudtrace.example.com/paypal/cancel"

        # 3. Redirect URL validation: localhost HTTP allowed; non-localhost HTTP & unsafe URLs rejected
        assert validate_paypal_redirect_url("http://localhost:5173/?paypal=return") == DEFAULT_PAYPAL_RETURN_URL
        assert validate_paypal_redirect_url("http://127.0.0.1:5173/return") == "http://127.0.0.1:5173/return"
        assert (
            validate_paypal_redirect_url("https://fraudtrace.example.com/callback")
            == "https://fraudtrace.example.com/callback"
        )

        unsafe_urls = [
            "",
            "   ",
            "http://example.com/?paypal=return",
            "http://localhost.evil.com/?paypal=return",
            "javascript:alert(1)",
            "data:text/html,hi",
            "/relative/callback",
            "//evil.example.com/callback",
            "https://user:pass@localhost:5173/return",
            "https://169.254.169.254/latest/meta-data",
            "https://192.168.1.10/return",
            "https://internal-host/return",
            "http://localhost:5173/ bad",
        ]
        for bad_url in unsafe_urls:
            try:
                validate_paypal_redirect_url(bad_url)
                raise AssertionError(f"Expected ValueError for unsafe redirect URL: {bad_url!r}")
            except ValueError:
                pass

            bad_cfg_env = dict(harness.env_dict())
            bad_cfg_env["PAYPAL_RETURN_URL"] = bad_url if bad_url.strip() else "http://not-localhost.com/ret"
            try:
                load_paypal_sandbox_config(env_path=None, environ=bad_cfg_env)
                raise AssertionError(f"Expected PayPalConfigurationError for env URL: {bad_cfg_env['PAYPAL_RETURN_URL']!r}")
            except PayPalConfigurationError:
                pass

        # 4. API request schema allows localhost HTTP dev URLs and blocks arbitrary external open redirects
        ok_req = PayPalOrderCreateRequest(
            amount=Decimal("25.00"),
            currency="USD",
            return_url="http://localhost:5173/approved",
            cancel_url="http://localhost:5173/cancelled",
        )
        assert ok_req.return_url == "http://localhost:5173/approved"

        for blocked_api_url in (
            "https://untrusted-phishing.example.com/steal",
            "http://evil.example.com/cb",
            "javascript:alert(1)",
        ):
            try:
                PayPalOrderCreateRequest(
                    amount=Decimal("25.00"),
                    currency="USD",
                    return_url=blocked_api_url,
                )
                raise AssertionError(f"Expected ValidationError for request redirect URL: {blocked_api_url!r}")
            except ValidationError:
                pass
    finally:
        _teardown_isolated_db(engine, temp_path)


def test_6_live_smoke_stale_order_handling() -> None:
    engine, SessionLocal, temp_path = _create_isolated_session()
    harness = _PayPalMockHarness()
    clock = _FakeClock()
    client = PayPalSandboxClient(
        env_path=None,
        environ=harness.env_dict(),
        transport=harness.transport(),
        monotonic_fn=clock,
    )

    try:
        with SessionLocal() as db:
            # 1. Seed a stale local uncaptured smoke order whose PayPal order now returns 404
            expired_row = PayPalOrder(
                internal_reference="PP-LIVE-EXPIRED01",
                paypal_order_id="5O190127TN3647999",
                intent="CAPTURE",
                status="CREATED",
                requested_amount=Decimal("1.00"),
                currency="USD",
                sender_id="SANDBOX_SMOKE_BUYER_01",
                receiver_id="FRAUDTRACE_SANDBOX_MERCHANT",
            )
            db.add(expired_row)
            db.commit()

            calls_before = harness.get_calls
            plan_after_404 = live_smoke.resolve_smoke_order_plan(
                db=db,
                paypal_client=client,
                requested_internal_reference=None,
                requested_amount="1.00",
                requested_currency="USD",
                new_order=False,
                reference_factory=lambda: "PP-LIVE-FRESH001",
            )
            assert harness.get_calls == calls_before + 1
            assert plan_after_404.action == "create_fresh"
            assert plan_after_404.stale_marked_order_id == "5O190127TN3647999"
            assert plan_after_404.internal_reference == "PP-LIVE-FRESH001"

            db.refresh(expired_row)
            assert expired_row.status == "STALE_EXPIRED"

            # Explicit stale reference must NOT be silently replayed
            explicit_plan = live_smoke.resolve_smoke_order_plan(
                db=db,
                paypal_client=client,
                requested_internal_reference="PP-LIVE-EXPIRED01",
                requested_amount="1.00",
                requested_currency="USD",
                new_order=False,
            )
            assert explicit_plan.action == "explicit_ref_stale"

            # 2. Active live uncaptured order on PayPal MUST replay without creating a duplicate order
            harness.simulate_payer_action_required = True
            created_live = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal("1.00"),
                    currency="USD",
                    internal_reference="PP-LIVE-ACTIVE01",
                    sender_id="SANDBOX_SMOKE_BUYER_01",
                    receiver_id="FRAUDTRACE_SANDBOX_MERCHANT",
                ),
                response=Response(),
                db=db,
                paypal_client=client,
            )
            create_calls_before = harness.create_calls
            replay_plan = live_smoke.resolve_smoke_order_plan(
                db=db,
                paypal_client=client,
                requested_internal_reference=None,
                requested_amount="1.00",
                requested_currency="USD",
                new_order=False,
            )
            assert replay_plan.action == "replay_active"
            assert replay_plan.internal_reference == "PP-LIVE-ACTIVE01"
            assert replay_plan.existing_order_id == created_live.paypal_order_id

            replay_resp = Response()
            replayed_order = paypal_routes.create_paypal_order(
                payload=PayPalOrderCreateRequest(
                    amount=Decimal(replay_plan.amount),
                    currency=replay_plan.currency,
                    internal_reference=replay_plan.internal_reference,
                    sender_id="SANDBOX_SMOKE_BUYER_01",
                    receiver_id="FRAUDTRACE_SANDBOX_MERCHANT",
                ),
                response=replay_resp,
                db=db,
                paypal_client=client,
            )
            assert replay_resp.status_code == 200
            assert replayed_order.idempotent_replay is True
            assert harness.create_calls == create_calls_before
    finally:
        _teardown_isolated_db(engine, temp_path)


def run_all_tests() -> None:
    tests = [
        test_1_token_caching_expiry_and_401_refresh,
        test_2_invalid_amounts_and_currencies_rejected,
        test_3_create_order_idempotency_and_error_handling,
        test_4_capture_guards_fraudtrace_scoring_and_duplicate_prevention,
        test_5_experience_context_and_redirect_url_validation,
        test_6_live_smoke_stale_order_handling,
    ]
    print("Running FraudTrace AI PayPal Sandbox Orders v2 Test Suite...")
    for fn in tests:
        fn()
        print(f"  [PASS] {fn.__name__}")
    print(f"All {len(tests)} PayPal Orders v2 test groups passed.")


if __name__ == "__main__":
    run_all_tests()
