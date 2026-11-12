"""
FraudTrace AI — Live PayPal Sandbox End-to-End Smoke Test
===========================================================
Verifies genuine PayPal Sandbox Orders v2 connectivity, order creation,
manual buyer approval handoff, capture verification, FraudTrace deterministic
risk evaluation, duplicate-capture idempotency, and demo DB preservation.

Strictly Sandbox-only:
- Loads credentials from `backend/.env` via `PayPalSandboxClient`.
- Enforces HTTPS + `*.sandbox.paypal.com` hosts (never Live production endpoints).
- Uses an isolated scratch SQLite database cloned from `backend/data/fraudtrace.db`.
- Never automates or bypasses PayPal buyer approval.
- Never logs, prints, or persists `PAYPAL_CLIENT_ID`, `PAYPAL_CLIENT_SECRET`,
  or OAuth access tokens.

Usage (from D:\\FraudTrace-AI):
    # Step 1: Authenticate & create (or idempotently replay) a USD 1.00 Sandbox order
    backend\\.venv\\Scripts\\python.exe -u backend\\test_paypal_sandbox_live.py create

    # Optional: Inspect current local & PayPal status without modifying data
    backend\\.venv\\Scripts\\python.exe -u backend\\test_paypal_sandbox_live.py status

    # Step 2 (after manual buyer approval in browser): Capture & verify idempotency
    backend\\.venv\\Scripts\\python.exe -u backend\\test_paypal_sandbox_live.py capture
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
from decimal import Decimal
import hashlib
import io
import json
import logging
import os
from pathlib import Path
import shutil
import sqlite3
import sys
import tempfile
from typing import Any, Callable, Optional
import uuid

BACKEND_DIR = Path(__file__).resolve().parent
DEMO_DB_PATH = BACKEND_DIR / "data" / "fraudtrace.db"
DEFAULT_SCRATCH_DB_PATH = Path(tempfile.gettempdir()) / "fraudtrace_paypal_live_smoke.db"
SMOKE_ORDER_REF_PREFIX = "PP-LIVE-"
STALE_ORDER_STATUSES = frozenset({"STALE_EXPIRED", "EXPIRED", "VOIDED", "STALE_VOIDED"})
LIVE_REPLAYABLE_STATUSES = frozenset({"CREATED", "PAYER_ACTION_REQUIRED", "APPROVED"})


@dataclass(frozen=True)
class SmokeOrderPlan:
    """Resolution outcome before issuing POST /api/v1/paypal/orders in the live smoke script."""

    action: str
    internal_reference: Optional[str]
    amount: str
    currency: str
    existing_order_id: Optional[str] = None
    existing_txn_id: Optional[int] = None
    stale_marked_order_id: Optional[str] = None
    message: str = ""


def _generate_smoke_internal_reference() -> str:
    return f"{SMOKE_ORDER_REF_PREFIX}{uuid.uuid4().hex[:12].upper()}"


def resolve_smoke_order_plan(
    db: Any,
    paypal_client: Any,
    *,
    requested_internal_reference: Optional[str],
    requested_amount: str,
    requested_currency: str,
    new_order: bool,
    reference_factory: Callable[[], str] = _generate_smoke_internal_reference,
) -> SmokeOrderPlan:
    """
    Checks cached local PayPalOrder state against live PayPal before replaying:
    - Never silently replays an expired/404 order.
    - Marks 404/expired/voided cached smoke orders stale cleanly (`STALE_EXPIRED`)
      and picks a new unique internal_reference when creating a replacement.
    - Replays verified live uncaptured orders idempotently to avoid duplicates.
    """
    from sqlalchemy import desc, select
    from app.models import PayPalOrder
    from app.services.paypal_client import PayPalAPIError

    candidate: Optional[PayPalOrder] = None
    if requested_internal_reference:
        candidate = db.execute(
            select(PayPalOrder).where(PayPalOrder.internal_reference == requested_internal_reference)
        ).scalar_one_or_none()
    elif not new_order:
        candidate = db.execute(
            select(PayPalOrder)
            .where(
                PayPalOrder.internal_reference.startswith(SMOKE_ORDER_REF_PREFIX),
                PayPalOrder.status.notin_(STALE_ORDER_STATUSES),
            )
            .order_by(desc(PayPalOrder.id))
            .limit(1)
        ).scalar_one_or_none()

    if candidate is None:
        fresh_ref = requested_internal_reference or reference_factory()
        return SmokeOrderPlan(
            action="create_fresh",
            internal_reference=fresh_ref,
            amount=requested_amount,
            currency=requested_currency,
            message=f"Creating new PayPal Sandbox order with internal_reference='{fresh_ref}'.",
        )

    if candidate.transaction_id is not None:
        return SmokeOrderPlan(
            action="already_completed_local",
            internal_reference=candidate.internal_reference,
            amount=f"{candidate.requested_amount:.2f}",
            currency=candidate.currency,
            existing_order_id=candidate.paypal_order_id,
            existing_txn_id=candidate.transaction_id,
            message=(
                f"Existing smoke order {candidate.paypal_order_id} ({candidate.internal_reference}) "
                f"is already COMPLETED (transaction_id={candidate.transaction_id})."
            ),
        )

    if candidate.status in STALE_ORDER_STATUSES:
        return SmokeOrderPlan(
            action="explicit_ref_stale",
            internal_reference=candidate.internal_reference,
            amount=f"{candidate.requested_amount:.2f}",
            currency=candidate.currency,
            existing_order_id=candidate.paypal_order_id,
            message=(
                f"Cached order {candidate.paypal_order_id} ({candidate.internal_reference}) is marked "
                f"{candidate.status} and will not be replayed."
            ),
        )

    # Verify cached uncaptured order directly against PayPal before replaying
    try:
        live_snapshot = paypal_client.get_order(candidate.paypal_order_id)
    except PayPalAPIError as exc:
        if exc.status_code == 404 or exc.error_code == "RESOURCE_NOT_FOUND":
            candidate.status = "STALE_EXPIRED"
            db.commit()
            db.refresh(candidate)
            if requested_internal_reference:
                return SmokeOrderPlan(
                    action="explicit_ref_stale",
                    internal_reference=candidate.internal_reference,
                    amount=requested_amount,
                    currency=requested_currency,
                    stale_marked_order_id=candidate.paypal_order_id,
                    message=(
                        f"PayPal returned 404 RESOURCE_NOT_FOUND for cached order {candidate.paypal_order_id} "
                        f"({candidate.internal_reference}); marked STALE_EXPIRED and refused silent replay."
                    ),
                )
            fresh_ref = reference_factory()
            return SmokeOrderPlan(
                action="create_fresh",
                internal_reference=fresh_ref,
                amount=requested_amount,
                currency=requested_currency,
                stale_marked_order_id=candidate.paypal_order_id,
                message=(
                    f"PayPal returned 404 RESOURCE_NOT_FOUND for cached order {candidate.paypal_order_id} "
                    f"({candidate.internal_reference}); marked STALE_EXPIRED and switched to '{fresh_ref}'."
                ),
            )
        raise

    if live_snapshot.status in {"VOIDED", "EXPIRED"}:
        candidate.status = f"STALE_{live_snapshot.status}"[:32]
        db.commit()
        db.refresh(candidate)
        if requested_internal_reference:
            return SmokeOrderPlan(
                action="explicit_ref_stale",
                internal_reference=candidate.internal_reference,
                amount=requested_amount,
                currency=requested_currency,
                stale_marked_order_id=candidate.paypal_order_id,
                message=(
                    f"PayPal reported terminal status {live_snapshot.status} for {candidate.paypal_order_id}; "
                    f"marked {candidate.status} and refused silent replay."
                ),
            )
        fresh_ref = reference_factory()
        return SmokeOrderPlan(
            action="create_fresh",
            internal_reference=fresh_ref,
            amount=requested_amount,
            currency=requested_currency,
            stale_marked_order_id=candidate.paypal_order_id,
            message=(
                f"PayPal reported terminal status {live_snapshot.status} for {candidate.paypal_order_id}; "
                f"marked {candidate.status} and switched to '{fresh_ref}'."
            ),
        )

    if live_snapshot.status == "COMPLETED":
        candidate.status = "COMPLETED"
        db.commit()
        db.refresh(candidate)
        return SmokeOrderPlan(
            action="completed_on_paypal",
            internal_reference=candidate.internal_reference,
            amount=f"{candidate.requested_amount:.2f}",
            currency=candidate.currency,
            existing_order_id=candidate.paypal_order_id,
            message=(
                f"Cached order {candidate.paypal_order_id} ({candidate.internal_reference}) is already "
                "COMPLETED on PayPal. Run `capture` to finalize local persistence without creating a duplicate."
            ),
        )

    if live_snapshot.status in LIVE_REPLAYABLE_STATUSES:
        if candidate.status != live_snapshot.status:
            candidate.status = live_snapshot.status
            db.commit()
            db.refresh(candidate)
        return SmokeOrderPlan(
            action="replay_active",
            internal_reference=candidate.internal_reference,
            amount=f"{candidate.requested_amount:.2f}",
            currency=candidate.currency,
            existing_order_id=candidate.paypal_order_id,
            message=(
                f"Verified cached order {candidate.paypal_order_id} ({candidate.internal_reference}) is live "
                f"on PayPal (status={live_snapshot.status}); replaying without creating a duplicate order."
            ),
        )

    raise RuntimeError(
        f"Unexpected live PayPal order status '{live_snapshot.status}' for {candidate.paypal_order_id}."
    )


def _sha256_file(path: Path) -> str:
    hasher = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(65536), b""):
            hasher.update(chunk)
    return hasher.hexdigest()


def _read_demo_db_snapshot(db_path: Path) -> dict[str, Any]:
    if not db_path.is_file():
        raise FileNotFoundError(f"Demo SQLite database not found at: {db_path}")
    sha256 = _sha256_file(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        tables = sorted(
            row[0]
            for row in conn.execute("SELECT name, type FROM sqlite_master").fetchall()
            if row[1] == "table"
        )
        counts = {
            t: int(conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0])
            for t in ("transactions", "investigations", "evidences")
            if t in tables
        }
    finally:
        conn.close()
    return {"sha256": sha256, "tables": tables, "counts": counts}


def _prepare_scratch_database(scratch_db_path: Path, *, reset_scratch: bool = False) -> None:
    """Clones the demo database cleanly before configuring `DATABASE_URL`."""
    scratch_db_path.parent.mkdir(parents=True, exist_ok=True)
    if reset_scratch and scratch_db_path.exists():
        scratch_db_path.unlink()
    if not scratch_db_path.exists():
        shutil.copyfile(DEMO_DB_PATH, scratch_db_path)


class _LogCaptureHandler(logging.Handler):
    """Captures formatted log records in memory to audit against secret/token leaks."""

    def __init__(self) -> None:
        super().__init__(level=logging.DEBUG)
        self.lines: list[str] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.lines.append(self.format(record))


def _collect_sensitive_values_for_audit(
    config_client_id: str,
    config_client_secret: str,
    paypal_client: Any,
) -> list[str]:
    """Builds in-memory list of sensitive strings to verify non-disclosure cleanly."""
    secrets: list[str] = []
    if config_client_id:
        secrets.append(config_client_id)
    if config_client_secret:
        secrets.append(config_client_secret)
    cached_entry = getattr(paypal_client, "_cached_entry", None)
    token = getattr(cached_entry, "access_token", None)
    if isinstance(token, str) and token:
        secrets.append(token)
    return secrets


def _assert_no_secrets_leaked(
    *,
    sensitive_values: list[str],
    log_lines: list[str],
    output_text: str,
    payloads: list[Any],
    db_path: Path,
) -> None:
    """Fails immediately if any credential or OAuth token appears in logs, output, API payloads, or SQLite."""
    serialized_payloads = json.dumps(payloads, default=str)
    joined_logs = "\n".join(log_lines)

    conn = sqlite3.connect(str(db_path))
    try:
        db_dump_parts: list[str] = []
        table_rows = conn.execute("SELECT name, type FROM sqlite_master").fetchall()
        for table_name, obj_type in table_rows:
            if obj_type != "table" or table_name.startswith("sqlite_"):
                continue
            rows = conn.execute(f'SELECT * FROM "{table_name}"').fetchall()
            db_dump_parts.append(f"{table_name}:{rows!r}")
        db_text = "\n".join(db_dump_parts)
    finally:
        conn.close()

    for secret in sensitive_values:
        if len(secret) < 8:
            continue
        assert secret not in output_text, "SECURITY FAILURE: sensitive value appeared in console output"
        assert secret not in joined_logs, "SECURITY FAILURE: sensitive value appeared in Python logs"
        assert secret not in serialized_payloads, "SECURITY FAILURE: sensitive value appeared in API payload"
        assert secret not in db_text, "SECURITY FAILURE: sensitive value persisted in SQLite scratch database"


def _emit_line(buf: io.StringIO, text: str = "") -> None:
    print(text)
    buf.write(text + "\n")


def _print_approval_instructions(
    buf: io.StringIO,
    *,
    paypal_order_id: str,
    internal_reference: str,
    amount: str,
    currency: str,
    approval_url: Optional[str],
    scratch_db_path: Path,
) -> None:
    _emit_line(buf, "")
    _emit_line(buf, "=== Phase 3: Manual Sandbox Buyer Approval Instructions ===")
    _emit_line(buf, f"PayPal Order ID     : {paypal_order_id}")
    _emit_line(buf, f"Internal Reference  : {internal_reference}")
    _emit_line(buf, f"Order Amount        : {amount} {currency}")
    _emit_line(buf, f"Approval URL        : {approval_url or '(none returned)'}")
    _emit_line(buf, "Steps:")
    _emit_line(buf, "  1. Open the Approval URL above in your browser.")
    _emit_line(buf, "  2. Sign in with your PayPal Sandbox Personal buyer account (from PayPal Developer Dashboard).")
    _emit_line(buf, "  3. Review the USD order details and click Complete Purchase / Approve.")
    _emit_line(buf, "  4. Once approved on PayPal Sandbox, run Phase 4 capture:")
    _emit_line(
        buf,
        f'     backend\\.venv\\Scripts\\python.exe -u backend\\test_paypal_sandbox_live.py capture '
        f'--order-id {paypal_order_id} --db-path "{scratch_db_path}"',
    )


def _db_table_counts(conn_session: Any, models_tuple: tuple[Any, ...]) -> dict[str, int]:
    from sqlalchemy import func, select

    return {
        model.__tablename__: int(conn_session.execute(select(func.count()).select_from(model)).scalar_one())
        for model in models_tuple
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="FraudTrace AI Live PayPal Sandbox End-to-End Smoke Test (isolated scratch DB)."
    )
    parser.add_argument(
        "action",
        nargs="?",
        default="create",
        choices=("create", "status", "capture"),
        help="Smoke step to execute (default: create).",
    )
    parser.add_argument(
        "--amount",
        default="1.00",
        help="Order amount to create on PayPal Sandbox (default: 1.00).",
    )
    parser.add_argument(
        "--currency",
        default="USD",
        help="3-letter ISO currency code (default: USD).",
    )
    parser.add_argument(
        "--internal-reference",
        default=None,
        help="Explicit unique internal_reference for idempotent create/replay.",
    )
    parser.add_argument(
        "--order-id",
        default=None,
        help="Target PayPal Order ID for `status` or `capture` (defaults to latest smoke order in scratch DB).",
    )
    parser.add_argument(
        "--sender-id",
        default="SANDBOX_SMOKE_BUYER_01",
        help="Internal sender account identifier recorded upon capture evaluation.",
    )
    parser.add_argument(
        "--receiver-id",
        default="FRAUDTRACE_SANDBOX_MERCHANT",
        help="Internal receiver/merchant identifier recorded upon capture evaluation.",
    )
    parser.add_argument(
        "--db-path",
        default=str(DEFAULT_SCRATCH_DB_PATH),
        help=f"Isolated scratch SQLite file path (default: {DEFAULT_SCRATCH_DB_PATH}).",
    )
    parser.add_argument(
        "--new-order",
        action="store_true",
        help="Force generating a new unique internal_reference instead of reusing the active smoke order.",
    )
    parser.add_argument(
        "--reset-scratch-db",
        action="store_true",
        help="Re-clone the scratch database cleanly from backend/data/fraudtrace.db before running.",
    )
    args = parser.parse_args()

    scratch_db_path = Path(args.db_path).resolve()
    if scratch_db_path == DEMO_DB_PATH.resolve():
        print("REFUSING RUN: --db-path must NOT target backend/data/fraudtrace.db directly.", file=sys.stderr)
        return 2

    baseline_demo = _read_demo_db_snapshot(DEMO_DB_PATH)
    _prepare_scratch_database(scratch_db_path, reset_scratch=args.reset_scratch_db)

    # Bind DATABASE_URL strictly to the scratch DB BEFORE importing FraudTrace DB modules
    os.environ["DATABASE_URL"] = f"sqlite:///{scratch_db_path.as_posix()}"
    sys.path.insert(0, str(BACKEND_DIR))

    from fastapi.testclient import TestClient  # noqa: E402
    from sqlalchemy import desc, select  # noqa: E402

    from app.database import SessionLocal, init_db  # noqa: E402
    from app.main import app  # noqa: E402
    from app.models import Evidence, Investigation, PayPalOrder, Transaction  # noqa: E402
    from app.services.paypal_client import (  # noqa: E402
        PayPalAPIError,
        PayPalConfigurationError,
        get_paypal_client,
        load_paypal_sandbox_config,
    )

    init_db()

    log_handler = _LogCaptureHandler()
    log_handler.setFormatter(logging.Formatter("%(name)s %(levelname)s %(message)s"))
    root_logger = logging.getLogger()
    root_logger.addHandler(log_handler)

    output_buf = io.StringIO()
    captured_payloads: list[Any] = []
    paypal_client = get_paypal_client()

    try:
        _emit_line(output_buf, "FraudTrace AI — Live PayPal Sandbox Smoke Test")
        _emit_line(output_buf, f"Action              : {args.action}")
        _emit_line(output_buf, f"Scratch DB          : {scratch_db_path}")
        _emit_line(output_buf, f"Demo DB SHA256      : {baseline_demo['sha256']} (read-only baseline)")

        try:
            cfg = load_paypal_sandbox_config()
        except PayPalConfigurationError as exc:
            _emit_line(output_buf, f"[ERROR] Configuration check failed: {exc}")
            return 1

        if "sandbox.paypal.com" not in cfg.base_url.lower():
            _emit_line(output_buf, f"[ERROR] Refusing non-sandbox base URL: {cfg.base_url}")
            return 1

        _emit_line(output_buf, f"PayPal Base URL     : {cfg.base_url}")
        _emit_line(output_buf, f"Return Redirect URL : {cfg.return_url}")
        _emit_line(output_buf, f"Cancel Redirect URL : {cfg.cancel_url}")

        oauth_res = paypal_client.check_oauth_connectivity()
        captured_payloads.append(oauth_res.__dict__)
        if not oauth_res.authenticated:
            _emit_line(
                output_buf,
                f"[ERROR] Live PayPal Sandbox OAuth failed: "
                f"status={oauth_res.status_code}, error_code={oauth_res.error_code}, detail={oauth_res.message}",
            )
            return 1

        _emit_line(
            output_buf,
            f"OAuth Verified      : HTTP {oauth_res.status_code} "
            f"(token_type={oauth_res.token_type}, expires_in={oauth_res.expires_in}s, scopes={oauth_res.scope_count})",
        )

        # Verify PayPal client & route calls cleanly through the live FastAPI ASGI app
        if args.action == "create":
            req_amount = str(Decimal(args.amount).quantize(Decimal("0.01")))
            req_currency = args.currency.strip().upper()

            with SessionLocal() as db:
                try:
                    plan = resolve_smoke_order_plan(
                        db=db,
                        paypal_client=paypal_client,
                        requested_internal_reference=args.internal_reference,
                        requested_amount=req_amount,
                        requested_currency=req_currency,
                        new_order=args.new_order,
                    )
                except PayPalAPIError as exc:
                    _emit_line(
                        output_buf,
                        f"[ERROR] Failed checking cached order against PayPal: HTTP {exc.status_code} "
                        f"(code={exc.error_code}): {exc.message}",
                    )
                    return 1

            if plan.message:
                _emit_line(output_buf, plan.message)

            if plan.action == "already_completed_local":
                _emit_line(output_buf, "No duplicate order created. Pass `--new-order` to start a new smoke order.")
                _assert_no_secrets_leaked(
                    sensitive_values=_collect_sensitive_values_for_audit(
                        cfg.client_id, cfg.client_secret, paypal_client
                    ),
                    log_lines=log_handler.lines,
                    output_text=output_buf.getvalue(),
                    payloads=captured_payloads,
                    db_path=scratch_db_path,
                )
                return 0

            if plan.action == "completed_on_paypal":
                _emit_line(output_buf, "Run `capture` for this order_id to sync it cleanly, or `--new-order`.")
                return 0

            if plan.action == "explicit_ref_stale":
                _emit_line(
                    output_buf,
                    "[ERROR] Provide a new unique `--internal-reference` or omit it to generate a fresh smoke reference.",
                )
                return 1

            chosen_ref = plan.internal_reference
            req_amount = plan.amount
            req_currency = plan.currency

            with TestClient(app) as client:
                res = client.post(
                    "/api/v1/paypal/orders",
                    json={
                        "amount": req_amount,
                        "currency": req_currency,
                        "internal_reference": chosen_ref,
                        "sender_id": args.sender_id,
                        "receiver_id": args.receiver_id,
                    },
                )
                body = res.json()
                captured_payloads.append(body)

                if res.status_code not in (200, 201):
                    _emit_line(
                        output_buf,
                        f"[ERROR] Order creation failed: HTTP {res.status_code} -> {body}",
                    )
                    return 1

                # Verify rerun idempotency immediately against backend route (must return 200 & replay=True)
                replay_res = client.post(
                    "/api/v1/paypal/orders",
                    json={
                        "amount": req_amount,
                        "currency": req_currency,
                        "internal_reference": chosen_ref,
                        "sender_id": args.sender_id,
                        "receiver_id": args.receiver_id,
                    },
                )
                replay_body = replay_res.json()
                captured_payloads.append(replay_body)
                assert replay_res.status_code == 200, f"Expected 200 replay, got {replay_res.status_code}: {replay_body}"
                assert replay_body["idempotent_replay"] is True
                assert replay_body["paypal_order_id"] == body["paypal_order_id"]

            _emit_line(output_buf, f"Order Endpoint HTTP : {res.status_code} (idempotent_replay={body['idempotent_replay']})")
            _emit_line(output_buf, f"Create Replay Check : HTTP {replay_res.status_code} (idempotent_replay=True)")
            _emit_line(output_buf, f"PayPal Order Status : {body['status']}")
            _print_approval_instructions(
                output_buf,
                paypal_order_id=body["paypal_order_id"],
                internal_reference=body["internal_reference"],
                amount=str(body["amount"]),
                currency=body["currency"],
                approval_url=body.get("approval_url"),
                scratch_db_path=scratch_db_path,
            )

        elif args.action in ("status", "capture"):
            with SessionLocal() as db:
                if args.order_id:
                    order_rec = db.execute(
                        select(PayPalOrder).where(PayPalOrder.paypal_order_id == args.order_id.strip())
                    ).scalar_one_or_none()
                else:
                    order_rec = db.execute(
                        select(PayPalOrder)
                        .where(
                            PayPalOrder.internal_reference.startswith(SMOKE_ORDER_REF_PREFIX),
                            PayPalOrder.status.notin_(STALE_ORDER_STATUSES),
                        )
                        .order_by(desc(PayPalOrder.id))
                        .limit(1)
                    ).scalar_one_or_none()

                if order_rec is None:
                    _emit_line(
                        output_buf,
                        "[ERROR] No matching PayPal Sandbox smoke order found in scratch DB. Run `create` first.",
                    )
                    return 1

                target_order_id = order_rec.paypal_order_id
                target_internal_ref = order_rec.internal_reference
                expected_amount = order_rec.requested_amount
                expected_currency = order_rec.currency
                local_status_before = order_rec.status
                local_txn_before = order_rec.transaction_id
                counts_before = _db_table_counts(db, (PayPalOrder, Transaction, Investigation, Evidence))

            try:
                live_snapshot = paypal_client.get_order(target_order_id)
            except PayPalAPIError as exc:
                _emit_line(
                    output_buf,
                    f"[ERROR] Live GET order failed: HTTP {exc.status_code} (code={exc.error_code}): {exc.message}",
                )
                return 1

            captured_payloads.append(live_snapshot.__dict__)
            _emit_line(output_buf, f"PayPal Order ID     : {target_order_id}")
            _emit_line(output_buf, f"Internal Reference  : {target_internal_ref}")
            _emit_line(output_buf, f"Local Status Before : {local_status_before} (txn_id={local_txn_before})")
            _emit_line(output_buf, f"Live PayPal Status  : {live_snapshot.status} (payer_id={live_snapshot.payer_id})")

            if args.action == "status":
                _assert_no_secrets_leaked(
                    sensitive_values=_collect_sensitive_values_for_audit(
                        cfg.client_id, cfg.client_secret, paypal_client
                    ),
                    log_lines=log_handler.lines,
                    output_text=output_buf.getvalue(),
                    payloads=captured_payloads,
                    db_path=scratch_db_path,
                )
                return 0

            with TestClient(app) as client:
                cap_res = client.post(f"/api/v1/paypal/orders/{target_order_id}/capture")
                cap_body = cap_res.json()
                captured_payloads.append(cap_body)

                if cap_res.status_code != 200:
                    _emit_line(
                        output_buf,
                        f"[ERROR] Capture endpoint returned HTTP {cap_res.status_code}: {cap_body}",
                    )
                    return 1

                assert cap_body["paypal_order"]["status"] == "COMPLETED"
                assert cap_body["paypal_order"]["paypal_capture_id"]
                assert Decimal(str(cap_body["paypal_order"]["captured_amount"])) == expected_amount
                assert cap_body["paypal_order"]["currency"] == expected_currency

                first_txn = cap_body["transaction_analysis"]["transaction"]
                first_txn_id = first_txn["id"]

                # Repeated capture request must be idempotent and create zero duplicate transactions
                repeat_res = client.post(f"/api/v1/paypal/orders/{target_order_id}/capture")
                repeat_body = repeat_res.json()
                captured_payloads.append(repeat_body)
                assert repeat_res.status_code == 200, f"Repeat capture returned HTTP {repeat_res.status_code}: {repeat_body}"
                assert repeat_body["already_captured"] is True
                assert repeat_body["transaction_analysis"]["transaction"]["id"] == first_txn_id

            with SessionLocal() as db:
                counts_after = _db_table_counts(db, (PayPalOrder, Transaction, Investigation, Evidence))
                persisted_order = db.execute(
                    select(PayPalOrder).where(PayPalOrder.paypal_order_id == target_order_id)
                ).scalar_one()
                persisted_txn = db.execute(
                    select(Transaction).where(Transaction.id == first_txn_id)
                ).scalar_one()

            expected_txn_delta = 0 if local_txn_before is not None else 1
            actual_txn_delta = counts_after["transactions"] - counts_before["transactions"]
            assert actual_txn_delta == expected_txn_delta, (
                f"Expected +{expected_txn_delta} Transaction rows, saw +{actual_txn_delta}"
            )
            assert persisted_order.paypal_capture_id == cap_body["paypal_order"]["paypal_capture_id"]
            assert persisted_order.transaction_id == persisted_txn.id

            analysis = cap_body["transaction_analysis"]
            _emit_line(output_buf, "=== Phase 4: Capture, Risk Analysis & Idempotency Results ===")
            _emit_line(output_buf, f"Capture Endpoint    : HTTP {cap_res.status_code} (already_captured={cap_body['already_captured']})")
            _emit_line(output_buf, f"PayPal Status       : {persisted_order.status}")
            _emit_line(output_buf, f"PayPal Capture ID   : {persisted_order.paypal_capture_id}")
            _emit_line(output_buf, f"Captured Amount     : {persisted_order.captured_amount} {persisted_order.currency}")
            _emit_line(output_buf, f"FraudTrace Txn ID   : {persisted_txn.id} (ref={persisted_txn.reference})")
            _emit_line(
                output_buf,
                f"Risk Assessment     : score={analysis['risk_score']}, level={analysis['risk_level']}, "
                f"status={analysis['investigation_status']}, evidence_count={len(analysis['evidence'])}",
            )
            _emit_line(
                output_buf,
                f"Repeat Capture Test : HTTP {repeat_res.status_code} "
                f"(already_captured={repeat_body['already_captured']}, txn_id={repeat_body['transaction_analysis']['transaction']['id']})",
            )
            _emit_line(
                output_buf,
                f"Scratch DB Deltas   : txns +{counts_after['transactions'] - counts_before['transactions']}, "
                f"investigations +{counts_after['investigations'] - counts_before['investigations']}, "
                f"evidences +{counts_after['evidences'] - counts_before['evidences']}",
            )

        _assert_no_secrets_leaked(
            sensitive_values=_collect_sensitive_values_for_audit(
                cfg.client_id, cfg.client_secret, paypal_client
            ),
            log_lines=log_handler.lines,
            output_text=output_buf.getvalue(),
            payloads=captured_payloads,
            db_path=scratch_db_path,
        )

        after_demo = _read_demo_db_snapshot(DEMO_DB_PATH)
        assert after_demo == baseline_demo, (
            f"Demo database modified unexpectedly! before={baseline_demo}, after={after_demo}"
        )
        _emit_line(
            output_buf,
            f"Security & Demo DB  : PASS (0 credential/token leaks; backend/data/fraudtrace.db SHA256 & counts unchanged)",
        )
        return 0
    finally:
        root_logger.removeHandler(log_handler)


if __name__ == "__main__":
    raise SystemExit(main())
