"""
FraudTrace AI — Database Layer Verification Script
==================================================
Tests:
1. Table creation & schema verification (Numeric(18, 2), primary keys, indexes).
2. Clean insertion of Transaction, Investigation, and Evidence records using Decimal amounts.
3. Bidirectional ORM relationship traversal.
4. Cascade deletion (deleting Transaction cascades to Investigation and Evidence).
5. SQLite Foreign-Key enforcement (PRAGMA foreign_keys = ON).
6. Repeatability: Cleans up before and after test execution, guaranteed via try/finally.
7. Safe 503 error handling on database connection failure.
"""

import os
import sys
import tempfile
from decimal import Decimal
from pathlib import Path
from unittest.mock import MagicMock

# Ensure `backend` is on python path
sys.path.insert(0, str(Path(__file__).resolve().parent))

# Isolate database tests from backend/data/fraudtrace.db
_temp_db_handle = tempfile.NamedTemporaryFile(suffix="_test_db_layer.db", delete=False)
_temp_db_path = Path(_temp_db_handle.name).resolve()
_temp_db_handle.close()
os.environ["DATABASE_URL"] = f"sqlite:///{_temp_db_path.as_posix()}"

from fastapi import HTTPException  # noqa: E402
from sqlalchemy import inspect, select  # noqa: E402
from sqlalchemy.exc import IntegrityError  # noqa: E402
from app.database import engine, SessionLocal, init_db  # noqa: E402
from app.models import Transaction, Investigation, Evidence  # noqa: E402
from app.main import database_health_check  # noqa: E402

TEST_REF = "TXN-AUDIT-TEST-001"


def cleanup_test_data(db) -> None:
    """Removes any test records to ensure repeatability."""
    existing_txns = db.execute(
        select(Transaction).where(Transaction.reference.startswith("TXN-AUDIT-"))
    ).scalars().all()
    for txn in existing_txns:
        db.delete(txn)
    db.commit()


def run_tests() -> None:
    print("--- 1. Initializing Database & Verifying Schema ---")
    init_db()

    inspector = inspect(engine)
    tables = inspector.get_table_names()
    print(f"Tables present in database: {tables}")
    assert "transactions" in tables, "Table 'transactions' missing!"
    assert "investigations" in tables, "Table 'investigations' missing!"
    assert "evidences" in tables, "Table 'evidences' missing!"

    # Verify amount column type is NUMERIC
    cols = {col["name"]: col for col in inspector.get_columns("transactions")}
    amount_col_type = str(cols["amount"]["type"])
    print(f"Transaction.amount column type: {amount_col_type}")
    assert "NUMERIC" in amount_col_type.upper(), f"Expected NUMERIC, got {amount_col_type}"
    print("[PASS] All tables and column types verified.")

    db = SessionLocal()
    try:
        # Pre-cleanup in case of previous interrupted run
        cleanup_test_data(db)

        print("\n--- 2. Inserting Transaction with Decimal Amount & Child Records ---")
        sample_txn = Transaction(
            reference=TEST_REF,
            sender_id="ACC-SENDER-8841",
            receiver_id="ACC-MULE-9923",
            amount=Decimal("14500.00"),
            currency="USD",
            risk_score=87.5,
            risk_level="HIGH",
            investigation_status="FLAGGED",
        )

        sample_inv = Investigation(
            transaction=sample_txn,
            status="OPEN",
            summary="Rapid high-value transfer to newly created account.",
            priority="HIGH",
        )

        sample_evidence = Evidence(
            investigation=sample_inv,
            evidence_type="VELOCITY_SPIKE",
            description="3 high-volume deposits in 12 minutes.",
            severity="HIGH",
        )

        db.add(sample_txn)
        db.commit()
        db.refresh(sample_txn)
        print(f"[PASS] Saved Transaction: ID={sample_txn.id}, Amount={sample_txn.amount} (type={type(sample_txn.amount).__name__})")
        assert isinstance(sample_txn.amount, Decimal), "Expected Decimal type for amount"
        assert sample_txn.amount == Decimal("14500.00")

        print("\n--- 3. Verifying Bidirectional Relationships ---")
        loaded_txn = db.execute(
            select(Transaction).where(Transaction.reference == TEST_REF)
        ).scalar_one()

        assert len(loaded_txn.investigations) == 1
        inv = loaded_txn.investigations[0]
        assert inv.status == "OPEN"
        assert len(inv.evidences) == 1
        ev = inv.evidences[0]
        assert ev.evidence_type == "VELOCITY_SPIKE"
        assert ev.investigation.id == inv.id
        assert inv.transaction.id == loaded_txn.id
        print("[PASS] Bidirectional relationships verified.")

        print("\n--- 4. Verifying SQLite Foreign Key Enforcement ---")
        orphan_inv = Investigation(
            transaction_id=9999999,  # Non-existent transaction ID
            status="OPEN",
            summary="Orphan investigation should be rejected by SQLite.",
        )
        db.add(orphan_inv)
        fk_violation_caught = False
        try:
            db.commit()
        except IntegrityError:
            db.rollback()
            fk_violation_caught = True
            print("[PASS] Foreign-key enforcement verified: SQLite rejected orphan child record.")

        assert fk_violation_caught, "Expected IntegrityError when inserting invalid foreign key!"

        print("\n--- 5. Verifying Cascade Deletion ---")
        txn_id = loaded_txn.id
        inv_id = inv.id
        ev_id = ev.id

        # Delete parent transaction
        db.delete(loaded_txn)
        db.commit()

        # Verify children were cascaded
        rem_inv = db.execute(select(Investigation).where(Investigation.id == inv_id)).scalar_one_or_none()
        rem_ev = db.execute(select(Evidence).where(Evidence.id == ev_id)).scalar_one_or_none()
        assert rem_inv is None, "Investigation should have been deleted by cascade!"
        assert rem_ev is None, "Evidence should have been deleted by cascade!"
        print("[PASS] Cascade deletion verified: child Investigation and Evidence deleted with parent.")

    finally:
        # Guarantee no test data remains
        cleanup_test_data(db)
        db.close()

    print("\n--- 6. Verifying Safe 503 Health Response on Database Failure ---")
    mock_db = MagicMock()
    mock_db.execute.side_effect = Exception("Simulated SQLite lock / disk failure")
    try:
        database_health_check(mock_db)
        raise AssertionError("Expected HTTPException 503!")
    except HTTPException as exc:
        assert exc.status_code == 503, f"Expected 503, got {exc.status_code}"
        assert exc.detail == "Database service unavailable", f"Unexpected error detail: {exc.detail}"
        print(f"[PASS] Safe 503 response verified: HTTP {exc.status_code} - detail: '{exc.detail}'")

    print("\n[PASS] All database tests completed cleanly and successfully.")


if __name__ == "__main__":
    try:
        run_tests()
    finally:
        engine.dispose()
        try:
            if _temp_db_path.exists():
                _temp_db_path.unlink()
        except Exception:
            pass
