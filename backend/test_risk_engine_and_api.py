"""
FraudTrace AI — Test Suite: Risk Engine & Transaction Analysis API
==================================================================
Tests:
1. Low-risk baseline transaction (no rules triggered -> score 0, LOW, CLEARED).
2. New recipient detection (NEW_RECIPIENT -> 10 pts, LOW).
3. Transaction velocity detection (TRANSACTION_VELOCITY -> 25 pts, MEDIUM).
4. Repeated recipient detection (REPEATED_RECIPIENT_ACTIVITY -> 25 pts, MEDIUM).
5. Amount anomaly detection (AMOUNT_ANOMALY -> 30 pts, HIGH).
6. Multiple rules triggering & score capping at 100 (CRITICAL).
7. Currency mismatch exclusion for amount anomaly (only same currency evaluated).
8. Insufficient historical data (< 3 transactions does not trigger anomaly).
9. Duplicate transaction reference rejection (HTTP 409 Conflict).
10. Database persistence of Transaction, Investigation, and Evidence records.
11. Retrieval APIs (GET /api/v1/transactions and GET /api/v1/transactions/{id}).
12. Input validation error handling (negative amount, blank reference, invalid currency).

ISOLATION:
Uses an isolated temporary SQLite database file (tempfile), ensuring the primary
development database (`backend/data/fraudtrace.db`) is completely untouched.
"""

import os
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path

# Ensure `backend` directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from fastapi import HTTPException
from pydantic import ValidationError
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Evidence, Investigation, Transaction
from app.routes.transactions import (
    analyze_transaction,
    get_transaction_detail,
    list_transactions,
)
from app.schemas import TransactionAnalyzeRequest
from app.services.risk_engine import (
    analyze_transaction_risk,
    evaluate_amount_anomaly,
    evaluate_new_recipient,
    evaluate_repeated_recipient_activity,
    evaluate_transaction_velocity,
)

# ---------------------------------------------------------------------------
# Isolated Test Database Setup (Temporary SQLite file)
# ---------------------------------------------------------------------------
_temp_db_handle = tempfile.NamedTemporaryFile(suffix="_test_ft.db", delete=False)
_temp_db_path = Path(_temp_db_handle.name).resolve()
_temp_db_handle.close()

test_engine = create_engine(
    f"sqlite:///{_temp_db_path.as_posix()}",
    connect_args={"check_same_thread": False},
)


@event.listens_for(test_engine, "connect")
def set_sqlite_pragma(dbapi_connection, connection_record):  # noqa: ANN001
    cursor = dbapi_connection.cursor()
    cursor.execute("PRAGMA foreign_keys=ON")
    cursor.close()


TestingSessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=test_engine)


def setup_test_db():
    Base.metadata.create_all(bind=test_engine)


def cleanup_test_db():
    Base.metadata.drop_all(bind=test_engine)
    test_engine.dispose()
    try:
        if _temp_db_path.exists():
            _temp_db_path.unlink()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# Test Functions
# ---------------------------------------------------------------------------

def test_1_new_recipient_detection():
    """Test Rule 3: NEW_RECIPIENT triggers 10 pts when sender has never transacted with receiver."""
    print("Test 1: Testing Rule 3 (NEW_RECIPIENT)...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        eval_res = evaluate_new_recipient("SENDER_ALPHA", "RECEIVER_BETA", now, db)
        assert eval_res.triggered is True
        assert eval_res.points_contributed == 10
        assert eval_res.severity == "LOW"
        assert "New recipient detected" in eval_res.description

        # Insert a transaction between them and re-evaluate
        prior_txn = Transaction(
            reference="TXN-NEWREC-PREV",
            sender_id="SENDER_ALPHA",
            receiver_id="RECEIVER_BETA",
            amount=Decimal("100.00"),
            currency="USD",
            timestamp=now - timedelta(days=1),
        )
        db.add(prior_txn)
        db.commit()

        eval_res_2 = evaluate_new_recipient("SENDER_ALPHA", "RECEIVER_BETA", now, db)
        assert eval_res_2.triggered is False
        assert eval_res_2.points_contributed == 0
        print("✓ Rule 3 passed.", flush=True)
    finally:
        db.close()


def test_2_transaction_velocity():
    """Test Rule 1: TRANSACTION_VELOCITY triggers 25 pts when 3+ txns occur within 10 min."""
    print("Test 2: Testing Rule 1 (TRANSACTION_VELOCITY)...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_VELOCITY"

        # Initially 0 transactions
        eval_0 = evaluate_transaction_velocity(sender, now, db)
        assert eval_0.triggered is False

        # Add 3 transactions within the last 5 minutes
        for i in range(3):
            t = Transaction(
                reference=f"TXN-VEL-{i}",
                sender_id=sender,
                receiver_id=f"REC-{i}",
                amount=Decimal("50.00"),
                currency="USD",
                timestamp=now - timedelta(minutes=i + 1),
            )
            db.add(t)
        db.commit()

        eval_res = evaluate_transaction_velocity(sender, now, db)
        assert eval_res.triggered is True
        assert eval_res.points_contributed == 25
        assert eval_res.severity == "MEDIUM"
        assert "High transaction velocity detected" in eval_res.description
        print("✓ Rule 1 passed.", flush=True)
    finally:
        db.close()


def test_3_repeated_recipient_activity():
    """Test Rule 4: REPEATED_RECIPIENT_ACTIVITY triggers 25 pts for 3+ txns to same recipient in 10 min."""
    print("Test 3: Testing Rule 4 (REPEATED_RECIPIENT_ACTIVITY)...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_REPAIR"
        receiver = "REC_TARGET"

        # Initially 0 transactions
        eval_0 = evaluate_repeated_recipient_activity(sender, receiver, now, db)
        assert eval_0.triggered is False

        # Add 3 transactions to this exact receiver within the last 8 minutes
        for i in range(3):
            t = Transaction(
                reference=f"TXN-REPAIR-{i}",
                sender_id=sender,
                receiver_id=receiver,
                amount=Decimal("25.00"),
                currency="USD",
                timestamp=now - timedelta(minutes=i + 1),
            )
            db.add(t)
        db.commit()

        eval_res = evaluate_repeated_recipient_activity(sender, receiver, now, db)
        assert eval_res.triggered is True
        assert eval_res.points_contributed == 25
        assert eval_res.severity == "MEDIUM"
        assert "Repeated recipient activity" in eval_res.description
        print("✓ Rule 4 passed.", flush=True)
    finally:
        db.close()


def test_4_amount_anomaly():
    """Test Rule 2: AMOUNT_ANOMALY triggers 30 pts when amount >= 5x historical average."""
    print("Test 4: Testing Rule 2 (AMOUNT_ANOMALY)...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_ANOMALY"

        # Add 3 historical transactions (average = 100.00 USD)
        for i in range(3):
            db.add(
                Transaction(
                    reference=f"TXN-ANOM-HIST-{i}",
                    sender_id=sender,
                    receiver_id="REC-X",
                    amount=Decimal("100.00"),
                    currency="USD",
                    timestamp=now - timedelta(days=i + 1),
                )
            )
        db.commit()

        # Normal amount: 300 USD (< 5x avg of 100 USD) -> Should NOT trigger
        eval_norm = evaluate_amount_anomaly(sender, Decimal("300.00"), "USD", now, db)
        assert eval_norm.triggered is False

        # Anomalous amount: 600 USD (6x avg of 100 USD) -> Triggers 30 pts
        eval_anomaly = evaluate_amount_anomaly(sender, Decimal("600.00"), "USD", now, db)
        assert eval_anomaly.triggered is True
        assert eval_anomaly.points_contributed == 30
        assert eval_anomaly.severity == "HIGH"
        assert "Amount anomaly detected" in eval_anomaly.description
        print("✓ Rule 2 passed.", flush=True)
    finally:
        db.close()


def test_5_multiple_rules_and_score_capping():
    """Test score aggregation and capping at 100 when multiple rules trigger."""
    print("Test 5: Testing Multiple Rules & Capping...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_MAX_RISK"
        receiver = "REC_FRESH"

        # Baseline transactions for amount anomaly
        for i in range(3):
            db.add(
                Transaction(
                    reference=f"TXN-MAXHIST-{i}",
                    sender_id=sender,
                    receiver_id="OTHER_REC",
                    amount=Decimal("10.00"),
                    currency="USD",
                    timestamp=now - timedelta(days=i + 1),
                )
            )
        # Recent transactions triggering velocity & repeated recipient
        for i in range(3):
            db.add(
                Transaction(
                    reference=f"TXN-MAXRECENT-{i}",
                    sender_id=sender,
                    receiver_id=receiver,
                    amount=Decimal("10.00"),
                    currency="USD",
                    timestamp=now - timedelta(minutes=i + 1),
                )
            )
        db.commit()

        # Velocity (25) + Repeated recipient (25) + Amount anomaly (30) = 80 -> CRITICAL
        res = analyze_transaction_risk(
            sender_id=sender,
            receiver_id=receiver,
            amount=Decimal("5000.00"),
            currency="USD",
            current_time=now,
            db=db,
        )
        assert res.risk_score == 80.0
        assert res.risk_level == "CRITICAL"
        assert res.investigation_status == "FLAGGED"
        assert len(res.evidence_items) == 3
        print("✓ Multiple rules & capping verified.", flush=True)
    finally:
        db.close()


def test_6_currency_mismatch_exclusion():
    """Test Rule 2 does not compare transactions across different currencies."""
    print("Test 6: Testing Currency Mismatch Exclusion...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_CURR_MISMATCH"

        # Sender has 5 historical transactions in USD
        for i in range(5):
            db.add(
                Transaction(
                    reference=f"TXN-CURR-USD-{i}",
                    sender_id=sender,
                    receiver_id="REC-USD",
                    amount=Decimal("10.00"),
                    currency="USD",
                    timestamp=now - timedelta(days=i + 1),
                )
            )
        db.commit()

        # Evaluating a EUR transaction -> sender has 0 EUR transactions
        # Should NOT trigger amount anomaly despite large amount
        eval_eur = evaluate_amount_anomaly(sender, Decimal("10000.00"), "EUR", now, db)
        assert eval_eur.triggered is False
        assert "0 previous record(s) found" in eval_eur.description
        print("✓ Currency mismatch exclusion verified.", flush=True)
    finally:
        db.close()


def test_7_insufficient_historical_data():
    """Test Rule 2 requires at least 3 previous transactions to trigger."""
    print("Test 7: Testing Insufficient Historical Data Rule...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_INSUFF_HIST"

        # Only 2 previous transactions
        for i in range(2):
            db.add(
                Transaction(
                    reference=f"TXN-INSUFF-{i}",
                    sender_id=sender,
                    receiver_id="REC-Y",
                    amount=Decimal("20.00"),
                    currency="USD",
                    timestamp=now - timedelta(days=i + 1),
                )
            )
        db.commit()

        eval_res = evaluate_amount_anomaly(sender, Decimal("10000.00"), "USD", now, db)
        assert eval_res.triggered is False
        assert "minimum required: 3" in eval_res.description
        print("✓ Insufficient historical data handling verified.", flush=True)
    finally:
        db.close()


def test_8_low_risk_transaction_no_rules():
    """Test clean transaction where no rules trigger -> score 0, LOW, CLEARED."""
    print("Test 8: Testing Low-Risk Baseline Transaction...", flush=True)
    db = TestingSessionLocal()
    try:
        now = datetime.now(timezone.utc)
        sender = "SENDER_CLEAN"
        receiver = "REC_CLEAN"

        # Provide historical transactions with the same recipient over long span
        for i in range(5):
            db.add(
                Transaction(
                    reference=f"TXN-CLEAN-{i}",
                    sender_id=sender,
                    receiver_id=receiver,
                    amount=Decimal("100.00"),
                    currency="USD",
                    timestamp=now - timedelta(days=i + 1),
                )
            )
        db.commit()

        # Normal amount (120 USD), existing recipient, no velocity
        res = analyze_transaction_risk(
            sender_id=sender,
            receiver_id=receiver,
            amount=Decimal("120.00"),
            currency="USD",
            current_time=now,
            db=db,
        )
        assert res.risk_score == 0.0
        assert res.risk_level == "LOW"
        assert res.investigation_status == "CLEARED"
        assert len(res.evidence_items) == 0
        assert "No configured risk indicators were detected" in res.summary
        print("✓ Low-risk baseline verified.", flush=True)
    finally:
        db.close()


def test_9_api_analyze_and_persistence():
    """Test POST /api/v1/transactions/analyze logic & complete database persistence."""
    print("Test 9: Testing POST /api/v1/transactions/analyze & persistence...", flush=True)
    db = TestingSessionLocal()
    try:
        req = TransactionAnalyzeRequest(
            reference="TXN-API-ANALYZE-001",
            sender_id="API_USER_1",
            receiver_id="API_USER_2",
            amount=Decimal("250.00"),
            currency="USD",
        )

        response = analyze_transaction(payload=req, db=db)
        assert response.transaction.reference == "TXN-API-ANALYZE-001"
        assert response.transaction.amount == Decimal("250.00")
        assert response.risk_score == 10.0
        assert response.risk_level == "LOW"
        assert len(response.evidence) == 1
        assert response.evidence[0].evidence_type == "NEW_RECIPIENT"
        assert response.investigation is not None

        # Verify persistence in database
        saved = db.execute(
            select(Transaction).where(Transaction.reference == "TXN-API-ANALYZE-001")
        ).scalar_one_or_none()
        assert saved is not None
        assert len(saved.investigations) == 1
        assert len(saved.investigations[0].evidences) == 1
        print("✓ POST /analyze & persistence verified.", flush=True)
    finally:
        db.close()


def test_10_api_duplicate_reference_rejection():
    """Test duplicate reference rejection returns HTTP 409 Conflict."""
    print("Test 10: Testing Duplicate Reference Rejection (HTTP 409)...", flush=True)
    db = TestingSessionLocal()
    try:
        req = TransactionAnalyzeRequest(
            reference="TXN-API-DUPLICATE-REF",
            sender_id="USER_A",
            receiver_id="USER_B",
            amount=Decimal("50.00"),
            currency="USD",
        )

        # First submission succeeds
        res1 = analyze_transaction(payload=req, db=db)
        assert res1.transaction.reference == "TXN-API-DUPLICATE-REF"

        # Second submission with identical reference raises 409
        caught_409 = False
        try:
            analyze_transaction(payload=req, db=db)
        except HTTPException as exc:
            assert exc.status_code == 409
            assert "already exists" in exc.detail
            caught_409 = True

        assert caught_409, "Expected HTTPException 409 on duplicate reference!"
        print("✓ Duplicate reference returns 409 Conflict.", flush=True)
    finally:
        db.close()


def test_11_api_retrieval_endpoints():
    """Test GET /api/v1/transactions and GET /api/v1/transactions/{id}."""
    print("Test 11: Testing Retrieval APIs...", flush=True)
    db = TestingSessionLocal()
    try:
        # List transactions
        list_res = list_transactions(limit=10, offset=0, db=db)
        assert list_res.total >= 1
        assert len(list_res.items) >= 1

        first_id = list_res.items[0].id

        # Detail of existing transaction
        detail_res = get_transaction_detail(transaction_id=first_id, db=db)
        assert detail_res.id == first_id
        assert hasattr(detail_res, "investigations")

        # Detail of non-existent transaction raises 404
        caught_404 = False
        try:
            get_transaction_detail(transaction_id=999999, db=db)
        except HTTPException as exc:
            assert exc.status_code == 404
            caught_404 = True

        assert caught_404, "Expected HTTPException 404 on missing transaction!"
        print("✓ Retrieval APIs verified.", flush=True)
    finally:
        db.close()


def test_12_api_input_validation():
    """Test input validation for invalid amounts, blank fields, and bad currency."""
    print("Test 12: Testing Input Validation Models...", flush=True)
    # Negative amount rejected
    neg_caught = False
    try:
        TransactionAnalyzeRequest(
            reference="TXN-BAD-1",
            sender_id="USER_1",
            receiver_id="USER_2",
            amount=Decimal("-50.00"),
            currency="USD",
        )
    except ValidationError:
        neg_caught = True
    assert neg_caught, "Expected ValidationError for negative amount"

    # Blank sender_id rejected
    blank_caught = False
    try:
        TransactionAnalyzeRequest(
            reference="TXN-BAD-2",
            sender_id="   ",
            receiver_id="USER_2",
            amount=Decimal("50.00"),
            currency="USD",
        )
    except ValidationError:
        blank_caught = True
    assert blank_caught, "Expected ValidationError for blank sender_id"

    # Bad currency rejected
    curr_caught = False
    try:
        TransactionAnalyzeRequest(
            reference="TXN-BAD-3",
            sender_id="USER_1",
            receiver_id="USER_2",
            amount=Decimal("50.00"),
            currency="US1",
        )
    except ValidationError:
        curr_caught = True
    assert curr_caught, "Expected ValidationError for invalid currency code"
    print("✓ Input validation verified.", flush=True)


def run_all_tests():
    print("==================================================================", flush=True)
    print("FraudTrace AI: Running Automated Test Suite (Isolated SQLite DB)", flush=True)
    print("==================================================================", flush=True)
    setup_test_db()
    try:
        test_1_new_recipient_detection()
        test_2_transaction_velocity()
        test_3_repeated_recipient_activity()
        test_4_amount_anomaly()
        test_5_multiple_rules_and_score_capping()
        test_6_currency_mismatch_exclusion()
        test_7_insufficient_historical_data()
        test_8_low_risk_transaction_no_rules()
        test_9_api_analyze_and_persistence()
        test_10_api_duplicate_reference_rejection()
        test_11_api_retrieval_endpoints()
        test_12_api_input_validation()

        print("\n==================================================================", flush=True)
        print("ALL 12 AUTOMATED TEST SUITES PASSED (100% PASS RATE)", flush=True)
        print("==================================================================", flush=True)
    finally:
        cleanup_test_db()


if __name__ == "__main__":
    run_all_tests()
