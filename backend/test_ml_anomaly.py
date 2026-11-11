"""
FraudTrace AI — Test Suite: Experimental ML Anomaly Detection Service
====================================================================
Tests the unsupervised IsolationForest anomaly detection service and
guards against data leakage, reproducibility drift, invalid features,
and deterministic score contamination.

ISOLATION:
Uses in-memory synthetic transaction records and an isolated temporary SQLite
database file (`tempfile`), leaving `backend/data/fraudtrace.db` untouched.
"""

import math
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

# Ensure `backend` directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker

from app.database import Base
from app.models import Transaction
from app.routes import transactions as tx_routes
from app.schemas import TransactionAnalyzeRequest
from app.services import ml_anomaly_detector as ml_mod
from app.services.ml_anomaly_detector import (
    MIN_TRAINING_SAMPLES,
    _CausalFeatureTracker,
    _parse_transaction_record,
    evaluate_transaction_anomaly,
    evaluate_transaction_anomaly_from_records,
)


def _make_record(
    idx: int,
    sender_id: str,
    receiver_id: str,
    amount: float | Decimal | str,
    ts: datetime,
) -> SimpleNamespace:
    return SimpleNamespace(
        id=idx,
        reference=f"ML-TEST-{idx:03d}",
        sender_id=sender_id,
        receiver_id=receiver_id,
        amount=amount,
        currency="USD",
        timestamp=ts,
    )


def _build_baseline_history(base_time: datetime, count: int = 12) -> list[SimpleNamespace]:
    """Generates a deterministic set of steady low-variance recurring transactions."""
    rows: list[SimpleNamespace] = []
    pairs = [
        ("ACC_ALFA", "MERCHANT_ONE", "52.00"),
        ("ACC_BRAVO", "MERCHANT_TWO", "64.00"),
        ("ACC_CHARLIE", "MERCHANT_THREE", "48.00"),
    ]
    for i in range(count):
        sender, receiver, amt = pairs[i % len(pairs)]
        rows.append(
            _make_record(
                idx=i + 1,
                sender_id=sender,
                receiver_id=receiver,
                amount=Decimal(amt) + Decimal(i % 5),
                ts=base_time + timedelta(hours=i * 4),
            )
        )
    return rows


def test_1_insufficient_historical_data_returns_unavailable() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    history = _build_baseline_history(now - timedelta(days=5), count=MIN_TRAINING_SAMPLES - 1)
    target = _make_record(99, "ACC_ALFA", "MERCHANT_ONE", Decimal("55.00"), now)

    result = evaluate_transaction_anomaly_from_records(history, target)

    assert result.available is False
    assert result.status == "UNAVAILABLE"
    assert result.is_anomaly is None
    assert result.decision_score is None
    assert result.training_sample_count == MIN_TRAINING_SAMPLES - 1
    assert "at least 10" in result.explanation


def test_2_normal_vs_outlier_and_lower_decision_score_semantics() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    # Build 15 steady baseline rows so recurring behavior is strongly established
    history = _build_baseline_history(now - timedelta(days=10), count=15)

    normal_target = _make_record(100, "ACC_ALFA", "MERCHANT_ONE", Decimal("54.00"), now)
    outlier_target = _make_record(101, "ACC_NEW_ENTITY", "UNSEEN_VAULT", Decimal("9500.00"), now)

    normal_res = evaluate_transaction_anomaly_from_records(history, normal_target)
    outlier_res = evaluate_transaction_anomaly_from_records(history, outlier_target)

    assert normal_res.available is True
    assert normal_res.status == "NORMAL"
    assert normal_res.is_anomaly is False
    assert normal_res.decision_score is not None
    assert normal_res.training_sample_count == 15

    assert outlier_res.available is True
    assert outlier_res.status == "ANOMALY"
    assert outlier_res.is_anomaly is True
    assert outlier_res.decision_score is not None

    # Requirement 2: Lower decision_function score = more unusual
    assert outlier_res.decision_score < normal_res.decision_score
    assert outlier_res.decision_score < 0.0

    # Descriptive deviations present and accurately non-causal / non-SHAP
    assert len(outlier_res.feature_deviations) >= 1
    assert "NOT SHAP" in outlier_res.methodology_note
    assert "NOT a fraud probability" in outlier_res.score_interpretation


def test_3_reproducibility_with_fixed_random_state() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    history = _build_baseline_history(now - timedelta(days=10), count=14)
    target = _make_record(102, "ACC_X", "VAULT_Y", Decimal("4200.00"), now)

    res_a = evaluate_transaction_anomaly_from_records(history, target)
    res_b = evaluate_transaction_anomaly_from_records(list(reversed(history)), target)

    assert res_a.available is True and res_b.available is True
    assert res_a.random_state == 42
    assert res_a.decision_score == res_b.decision_score
    assert res_a.status == res_b.status
    assert [d.feature_name for d in res_a.feature_deviations] == [
        d.feature_name for d in res_b.feature_deviations
    ]


def test_4_no_data_leakage_excludes_target_and_future_rows() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    history = _build_baseline_history(now - timedelta(days=10), count=14)
    target = _make_record(50, "ACC_ALFA", "MERCHANT_ONE", Decimal("54.00"), now)

    # Evaluate cleanly with only historical data
    baseline_res = evaluate_transaction_anomaly_from_records(history, target)

    # Inject duplicate target + extreme future anomalies after `now`
    future_rows = [
        _make_record(200 + i, "ACC_FUTURE", "EXFIL_DEST", Decimal("99999.00"), now + timedelta(minutes=i + 1))
        for i in range(25)
    ]
    polluted_records = history + [target] + future_rows
    polluted_res = evaluate_transaction_anomaly_from_records(polluted_records, target)

    assert polluted_res.training_sample_count == baseline_res.training_sample_count == 14
    assert polluted_res.decision_score == baseline_res.decision_score
    assert polluted_res.status == baseline_res.status

    # Evaluating an early transaction in the timeline must NOT use later rows even if present
    early_target = history[3]  # only 3 transactions came before index 3
    early_res = evaluate_transaction_anomaly_from_records(history + future_rows, early_target)
    assert early_res.available is False
    assert early_res.status == "UNAVAILABLE"
    assert early_res.training_sample_count == 3


def test_5_causal_feature_tracker_builds_strictly_from_preceding_rows() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    tracker = _CausalFeatureTracker()

    r1 = _parse_transaction_record(_make_record(1, "S1", "R1", Decimal("100.00"), now - timedelta(minutes=5)))
    r2 = _parse_transaction_record(_make_record(2, "S1", "R1", Decimal("200.00"), now - timedelta(minutes=2)))
    r3 = _parse_transaction_record(_make_record(3, "S1", "R2", Decimal("300.00"), now))
    assert r1 is not None and r2 is not None and r3 is not None

    f1 = tracker.extract_features(r1)
    assert f1[2] == 0.0  # sender_tx_count before r1
    assert f1[4] == 0.0  # sender_velocity_10m before r1
    assert f1[5] == 1.0  # is_new_recipient
    tracker.update(r1)

    f2 = tracker.extract_features(r2)
    assert f2[2] == 1.0  # sender_tx_count before r2
    assert f2[4] == 1.0  # r1 occurred 3 min earlier
    assert f2[5] == 0.0  # S1->R1 seen once before
    assert f2[6] == 100.0  # sender_historical_avg before r2
    assert f2[7] == 2.0  # 200 / 100
    tracker.update(r2)

    f3 = tracker.extract_features(r3)
    assert f3[2] == 2.0  # r1 and r2
    assert f3[4] == 2.0  # both within 10 mins
    assert f3[5] == 1.0  # S1->R2 is new
    assert f3[6] == 150.0  # mean(100, 200)
    assert f3[7] == 2.0  # 300 / 150


def test_6_invalid_features_and_model_failures_degrade_safely() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    history = _build_baseline_history(now - timedelta(days=5), count=12)

    # Invalid target amount (NaN / negative)
    bad_nan_target = _make_record(90, "ACC_A", "ACC_B", float("nan"), now)
    res_nan = evaluate_transaction_anomaly_from_records(history, bad_nan_target)
    assert res_nan.available is False
    assert res_nan.status == "UNAVAILABLE"

    bad_neg_target = _make_record(91, "ACC_A", "ACC_B", -10.0, now)
    res_neg = evaluate_transaction_anomaly_from_records(history, bad_neg_target)
    assert res_neg.available is False
    assert res_neg.status == "UNAVAILABLE"

    # Mixed invalid historical rows should be safely ignored; valid count checked properly
    corrupted_history = history[:9] + [
        _make_record(80, "BAD", "BAD2", float("inf"), now - timedelta(minutes=20)),
        _make_record(81, "", "BAD2", Decimal("25.00"), now - timedelta(minutes=15)),
    ]
    normal_target = _make_record(92, "ACC_ALFA", "MERCHANT_ONE", Decimal("50.00"), now)
    res_corrupt = evaluate_transaction_anomaly_from_records(corrupted_history, normal_target)
    assert res_corrupt.available is False
    assert res_corrupt.training_sample_count == 9

    # Simulated scikit-learn runtime failure must never crash callers
    with patch.object(ml_mod, "IsolationForest", side_effect=RuntimeError("boom")):
        res_err = evaluate_transaction_anomaly_from_records(history, normal_target)
    assert res_err.available is False
    assert res_err.status == "UNAVAILABLE"
    assert "deterministic rules remain active" in res_err.explanation


def test_7_database_backed_evaluation_preserves_records() -> None:
    temp_handle = tempfile.NamedTemporaryFile(suffix="_test_ml_ft.db", delete=False)
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

    try:
        with SessionLocal() as db:
            now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
            for item in _build_baseline_history(now - timedelta(days=5), count=12):
                db.add(
                    Transaction(
                        reference=item.reference,
                        sender_id=item.sender_id,
                        receiver_id=item.receiver_id,
                        amount=Decimal(item.amount),
                        currency="USD",
                        timestamp=item.timestamp,
                        risk_score=0.0,
                        risk_level="LOW",
                        investigation_status="CLEARED",
                    )
                )
            outlier_tx = Transaction(
                reference="ML-TEST-DB-OUTLIER",
                sender_id="ACC_BRAND_NEW",
                receiver_id="VAULT_Z",
                amount=Decimal("8800.00"),
                currency="USD",
                timestamp=now,
                risk_score=10.0,
                risk_level="LOW",
                investigation_status="CLEARED",
            )
            db.add(outlier_tx)
            db.commit()
            db.refresh(outlier_tx)

            assessment = evaluate_transaction_anomaly(db, outlier_tx)
            assert assessment.available is True
            assert assessment.status == "ANOMALY"
            assert assessment.is_anomaly is True
            assert assessment.training_sample_count == 12
            assert math.isfinite(assessment.decision_score or float("nan"))

            # Verify DB records remain unaltered
            count_in_db = len(db.execute(select(Transaction)).scalars().all())
            assert count_in_db == 13
            assert float(outlier_tx.risk_score) == 10.0
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        if temp_path.exists():
            temp_path.unlink()


def test_8_zero_variance_training_set_returns_unavailable() -> None:
    now = datetime(2026, 11, 10, 12, 0, tzinfo=timezone.utc)
    # Distinct sender/receiver pairs with identical amounts produce zero variance in all 8 features
    constant_history = [
        _make_record(i + 1, f"UNIQUE_S_{i}", f"UNIQUE_R_{i}", Decimal("75.00"), now - timedelta(hours=20 - i))
        for i in range(12)
    ]
    target = _make_record(50, "UNIQUE_S_TARGET", "UNIQUE_R_TARGET", Decimal("2500.00"), now)

    res = evaluate_transaction_anomaly_from_records(constant_history, target)
    assert res.available is False
    assert res.status == "UNAVAILABLE"
    assert "zero variance" in res.explanation


def test_9_api_integration_preserves_deterministic_scores_and_resilience() -> None:
    temp_handle = tempfile.NamedTemporaryFile(suffix="_test_ml_api_ft.db", delete=False)
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

    try:
        with SessionLocal() as db:
            now = datetime(2026, 11, 10, 14, 0, tzinfo=timezone.utc)

            # Ingest 12 baseline rows via API route; first 10 must degrade cleanly as UNAVAILABLE
            first_resp = None
            for idx, rec in enumerate(_build_baseline_history(now - timedelta(days=5), count=12)):
                req = TransactionAnalyzeRequest(
                    reference=f"ML-API-{idx + 1:03d}",
                    sender_id=rec.sender_id,
                    receiver_id=rec.receiver_id,
                    amount=rec.amount,
                    currency="USD",
                    timestamp=rec.timestamp,
                )
                resp = tx_routes.analyze_transaction(req, db=db)
                if idx == 0:
                    first_resp = resp
                if idx < MIN_TRAINING_SAMPLES:
                    assert resp.ml_anomaly is not None
                    assert resp.ml_anomaly.available is False
                    assert resp.ml_anomaly.status == "UNAVAILABLE"

            assert first_resp is not None
            assert first_resp.risk_score == 10.0  # deterministic NEW_RECIPIENT unchanged

            # 13th transaction: large amount to new recipient -> ML anomaly flagged, deterministic rule unchanged
            spike_req = TransactionAnalyzeRequest(
                reference="ML-API-SPIKE",
                sender_id="ACC_BRAND_NEW",
                receiver_id="VAULT_EXIT",
                amount=Decimal("9800.00"),
                currency="USD",
                timestamp=now,
            )
            spike_resp = tx_routes.analyze_transaction(spike_req, db=db)
            assert spike_resp.risk_score == 10.0  # only NEW_RECIPIENT triggered; ML never inflated risk_score!
            assert spike_resp.risk_level == "LOW"
            assert spike_resp.ml_anomaly is not None
            assert spike_resp.ml_anomaly.available is True
            assert spike_resp.ml_anomaly.status == "ANOMALY"
            assert spike_resp.ml_anomaly.is_anomaly is True
            assert spike_resp.ml_anomaly.training_sample_count == 12
            assert spike_resp.ml_anomaly.decision_score is not None
            assert spike_resp.ml_anomaly.decision_score < 0.0

            # Detail endpoint returns identical leakage-free ML output
            detail_resp = tx_routes.get_transaction_detail(spike_resp.transaction.id, db=db)
            assert detail_resp.risk_score == 10.0
            assert detail_resp.ml_anomaly is not None
            assert detail_resp.ml_anomaly.decision_score == spike_resp.ml_anomaly.decision_score
            assert detail_resp.ml_anomaly.status == "ANOMALY"

            # Simulated ML wrapper failure in route must NOT break transaction retrieval or analysis
            with patch.object(tx_routes, "evaluate_transaction_anomaly", side_effect=RuntimeError("unexpected")):
                resilient_detail = tx_routes.get_transaction_detail(spike_resp.transaction.id, db=db)
                resilient_post_req = TransactionAnalyzeRequest(
                    reference="ML-API-FAILSAFE",
                    sender_id="ACC_BRAND_NEW_FAILSAFE",
                    receiver_id="VAULT_EXIT",
                    amount=Decimal("55.00"),
                    currency="USD",
                    timestamp=now + timedelta(minutes=1),
                )
                resilient_post = tx_routes.analyze_transaction(resilient_post_req, db=db)

            assert resilient_detail.risk_score == 10.0
            assert resilient_detail.ml_anomaly is not None
            assert resilient_detail.ml_anomaly.available is False
            assert resilient_detail.ml_anomaly.status == "UNAVAILABLE"

            assert resilient_post.risk_score == 10.0
            assert resilient_post.ml_anomaly is not None
            assert resilient_post.ml_anomaly.available is False
            assert resilient_post.ml_anomaly.status == "UNAVAILABLE"
    finally:
        Base.metadata.drop_all(bind=engine)
        engine.dispose()
        if temp_path.exists():
            temp_path.unlink()


def run_all_tests() -> None:
    tests = [
        test_1_insufficient_historical_data_returns_unavailable,
        test_2_normal_vs_outlier_and_lower_decision_score_semantics,
        test_3_reproducibility_with_fixed_random_state,
        test_4_no_data_leakage_excludes_target_and_future_rows,
        test_5_causal_feature_tracker_builds_strictly_from_preceding_rows,
        test_6_invalid_features_and_model_failures_degrade_safely,
        test_7_database_backed_evaluation_preserves_records,
        test_8_zero_variance_training_set_returns_unavailable,
        test_9_api_integration_preserves_deterministic_scores_and_resilience,
    ]
    print("Running FraudTrace AI Experimental ML Anomaly Tests...")
    for fn in tests:
        fn()
        print(f"  [PASS] {fn.__name__}")
    print(f"All {len(tests)} ML anomaly tests passed.")


if __name__ == "__main__":
    run_all_tests()
