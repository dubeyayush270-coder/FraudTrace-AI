"""
FraudTrace AI — Experimental ML Anomaly Detection Service
=========================================================
Provides an unsupervised behavioral outlier signal using scikit-learn's
IsolationForest alongside (and strictly separate from) the deterministic
rule-based risk engine.

Guardrails & Scientific Integrity:
- Output is an experimental behavioral anomaly signal, NEVER a fraud probability,
  percentage, or determination of criminal guilt.
- Deterministic risk_score / risk_level / investigation_status are never altered
  or blended with IsolationForest scores.
- Lower IsolationForest decision_function values indicate more unusual behavior
  (negative values cross the model's outlier threshold).
- Only numerical derived behavioral features are used (no entity identifiers or
  investigation/rule outcome labels).
- Zero data leakage: the evaluated transaction and any post-transaction records
  are excluded from training, and each historical training row's features are
  built strictly from transactions that preceded it.
"""

from __future__ import annotations

import logging
import math
from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any, Iterable, Optional, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Transaction
from app.services.risk_engine import ensure_utc

try:
    import numpy as np
    from sklearn.ensemble import IsolationForest
    from sklearn.preprocessing import StandardScaler

    _SKLEARN_AVAILABLE = True
    _SKLEARN_IMPORT_ERROR: Optional[str] = None
except Exception as exc:  # pragma: no cover - defensive fallback if ML deps missing
    np = None  # type: ignore[assignment]
    IsolationForest = None  # type: ignore[assignment,misc]
    StandardScaler = None  # type: ignore[assignment,misc]
    _SKLEARN_AVAILABLE = False
    _SKLEARN_IMPORT_ERROR = str(exc)

logger = logging.getLogger(__name__)

MIN_TRAINING_SAMPLES = 10
DEFAULT_RANDOM_STATE = 42
DEFAULT_CONTAMINATION = 0.1
DEFAULT_N_ESTIMATORS = 100
VELOCITY_WINDOW_MINUTES = 10

FEATURE_SPEC: list[tuple[str, str]] = [
    ("amount", "Transaction Amount"),
    ("log_amount", "Log-Transformed Amount"),
    ("sender_tx_count", "Prior Sender Transaction Count"),
    ("receiver_tx_count", "Prior Receiver Transaction Count"),
    ("sender_velocity_10m", "Prior Sender 10-Min Velocity"),
    ("is_new_recipient", "First-Time Sender-Receiver Pair"),
    ("sender_historical_avg", "Prior Sender/Baseline Mean Amount"),
    ("amount_to_avg_ratio", "Amount-to-Baseline Ratio"),
]

SCORE_INTERPRETATION_TEXT = (
    "Lower IsolationForest decision_function values indicate more unusual transaction behavior; "
    "values below 0.0 cross the unsupervised outlier boundary. "
    "This is an outlier score, NOT a fraud probability."
)

METHODOLOGY_NOTE_TEXT = (
    "Descriptive z-score feature deviations compare this transaction against the causal prior "
    "historical baseline. They indicate statistical distance in input features and are NOT "
    "SHAP attributions or causal explanations."
)

LIMITATIONS_TEXT = (
    "Experimental unsupervised outlier check trained solely on prior local database history "
    "(non-FX-adjusted amounts). Small sample counts reflect demo exploration only and do not "
    "establish production accuracy or fraud guilt."
)


@dataclass
class FeatureDeviation:
    """Descriptive statistical difference for one numerical feature vs. training history."""

    feature_name: str
    display_label: str
    target_value: float
    training_mean: float
    training_std: float
    z_score_deviation: Optional[float]
    summary: str


@dataclass
class MLAnomalyAssessment:
    """Structured experimental ML anomaly result attached alongside deterministic risk output."""

    available: bool
    status: str  # "NORMAL", "ANOMALY", or "UNAVAILABLE"
    experimental: bool = True
    model_name: str = "IsolationForest (Experimental)"
    random_state: int = DEFAULT_RANDOM_STATE
    is_anomaly: Optional[bool] = None
    decision_score: Optional[float] = None
    score_interpretation: str = SCORE_INTERPRETATION_TEXT
    training_sample_count: int = 0
    minimum_samples_required: int = MIN_TRAINING_SAMPLES
    features_used: list[str] = field(default_factory=list)
    feature_deviations: list[FeatureDeviation] = field(default_factory=list)
    explanation: str = ""
    methodology_note: str = METHODOLOGY_NOTE_TEXT
    limitations: str = LIMITATIONS_TEXT


@dataclass(frozen=True)
class _ParsedTxRecord:
    """Validated canonical transaction view for causal feature construction."""

    timestamp_utc: datetime
    sort_id: int
    raw_id: Optional[int]
    reference: str
    sender_id: str
    receiver_id: str
    amount: float


def _unavailable_assessment(
    reason: str,
    *,
    training_sample_count: int = 0,
    minimum_samples_required: int = MIN_TRAINING_SAMPLES,
    random_state: int = DEFAULT_RANDOM_STATE,
) -> MLAnomalyAssessment:
    return MLAnomalyAssessment(
        available=False,
        status="UNAVAILABLE",
        experimental=True,
        model_name="IsolationForest (Experimental)",
        random_state=random_state,
        is_anomaly=None,
        decision_score=None,
        score_interpretation=SCORE_INTERPRETATION_TEXT,
        training_sample_count=training_sample_count,
        minimum_samples_required=minimum_samples_required,
        features_used=[key for key, _ in FEATURE_SPEC],
        feature_deviations=[],
        explanation=reason,
        methodology_note=METHODOLOGY_NOTE_TEXT,
        limitations=LIMITATIONS_TEXT,
    )


def _parse_transaction_record(record: Any) -> Optional[_ParsedTxRecord]:
    """Extracts and validates numerical & causal ordering fields from a transaction-like object."""
    if record is None:
        return None

    try:
        raw_amount = getattr(record, "amount", None)
        if raw_amount is None or isinstance(raw_amount, bool):
            return None
        amount = float(raw_amount)
        if not math.isfinite(amount) or amount < 0.0:
            return None

        raw_ts = getattr(record, "timestamp", None)
        if not isinstance(raw_ts, datetime):
            return None
        ts_utc = ensure_utc(raw_ts)

        sender_id = str(getattr(record, "sender_id", "") or "").strip()
        receiver_id = str(getattr(record, "receiver_id", "") or "").strip()
        if not sender_id or not receiver_id:
            return None

        raw_id = getattr(record, "id", None)
        sort_id = int(raw_id) if raw_id is not None else 0
        reference = str(getattr(record, "reference", "") or "").strip()
    except (TypeError, ValueError):
        return None

    return _ParsedTxRecord(
        timestamp_utc=ts_utc,
        sort_id=sort_id,
        raw_id=int(raw_id) if raw_id is not None else None,
        reference=reference,
        sender_id=sender_id,
        receiver_id=receiver_id,
        amount=amount,
    )


def _is_strictly_prior_record(candidate: _ParsedTxRecord, target: _ParsedTxRecord) -> bool:
    """
    Returns True only if candidate is strictly distinct from target and occurred
    no later than target in causal order (never includes future rows or target itself).
    """
    if target.raw_id is not None and candidate.raw_id is not None:
        if candidate.raw_id == target.raw_id:
            return False

    if target.reference and candidate.reference == target.reference:
        return False

    if candidate.timestamp_utc > target.timestamp_utc:
        return False

    if candidate.timestamp_utc == target.timestamp_utc:
        # When target is persisted with an id, only rows inserted earlier share its timestamp safely.
        if target.raw_id is not None and candidate.raw_id is not None:
            return candidate.raw_id < target.raw_id

    return True


class _CausalFeatureTracker:
    """Maintains incremental historical state across causally ordered transactions."""

    def __init__(self, velocity_window_minutes: int = VELOCITY_WINDOW_MINUTES) -> None:
        self.velocity_window = timedelta(minutes=velocity_window_minutes)
        self.sender_counts: dict[str, int] = defaultdict(int)
        self.sender_amount_sums: dict[str, float] = defaultdict(float)
        self.receiver_counts: dict[str, int] = defaultdict(int)
        self.pair_seen: set[tuple[str, str]] = set()
        self.sender_timestamps: dict[str, deque[datetime]] = defaultdict(deque)
        self.global_prior_sum: float = 0.0
        self.global_prior_count: int = 0

    def extract_features(self, rec: _ParsedTxRecord) -> list[float]:
        """Computes numerical features for `rec` using ONLY state prior to `rec`."""
        sender_prior_count = self.sender_counts[rec.sender_id]
        receiver_prior_count = self.receiver_counts[rec.receiver_id]

        window_cutoff = rec.timestamp_utc - self.velocity_window
        ts_queue = self.sender_timestamps[rec.sender_id]
        while ts_queue and ts_queue[0] < window_cutoff:
            ts_queue.popleft()
        sender_velocity_10m = float(len(ts_queue))

        is_new_recipient = 0.0 if (rec.sender_id, rec.receiver_id) in self.pair_seen else 1.0

        if sender_prior_count > 0:
            baseline_avg = self.sender_amount_sums[rec.sender_id] / float(sender_prior_count)
        elif self.global_prior_count > 0:
            baseline_avg = self.global_prior_sum / float(self.global_prior_count)
        else:
            baseline_avg = rec.amount

        amount_to_avg_ratio = rec.amount / max(baseline_avg, 1.0)

        return [
            float(rec.amount),
            float(math.log1p(max(rec.amount, 0.0))),
            float(sender_prior_count),
            float(receiver_prior_count),
            sender_velocity_10m,
            is_new_recipient,
            float(baseline_avg),
            float(amount_to_avg_ratio),
        ]

    def update(self, rec: _ParsedTxRecord) -> None:
        """Advances historical state after `rec`'s own features have been extracted."""
        self.sender_counts[rec.sender_id] += 1
        self.sender_amount_sums[rec.sender_id] += rec.amount
        self.receiver_counts[rec.receiver_id] += 1
        self.pair_seen.add((rec.sender_id, rec.receiver_id))
        self.sender_timestamps[rec.sender_id].append(rec.timestamp_utc)
        self.global_prior_sum += rec.amount
        self.global_prior_count += 1


def _compute_feature_deviations(
    train_matrix: Any,
    target_vector: Any,
    max_items: int = 3,
) -> list[FeatureDeviation]:
    """
    Computes descriptive z-score deviations against the historical training matrix.
    Strictly reports distributional differences, not SHAP or causal attribution.
    """
    col_means = np.mean(train_matrix, axis=0)
    col_stds = np.std(train_matrix, axis=0)

    scored: list[tuple[float, FeatureDeviation]] = []
    for idx, (feature_key, display_label) in enumerate(FEATURE_SPEC):
        t_val = float(target_vector[idx])
        m_val = float(col_means[idx])
        s_val = float(col_stds[idx])

        if s_val > 1e-9:
            z_val = float((t_val - m_val) / s_val)
            abs_rank = abs(z_val)
            if abs_rank < 0.5:
                continue
            direction = "above" if z_val >= 0 else "below"
            summary = (
                f"{display_label} ({t_val:.2f}) is {abs_rank:.2f} std deviations {direction} "
                f"the prior historical mean ({m_val:.2f})."
            )
            scored.append(
                (
                    abs_rank,
                    FeatureDeviation(
                        feature_name=feature_key,
                        display_label=display_label,
                        target_value=round(t_val, 4),
                        training_mean=round(m_val, 4),
                        training_std=round(s_val, 4),
                        z_score_deviation=round(z_val, 4),
                        summary=summary,
                    ),
                )
            )
        else:
            diff = abs(t_val - m_val)
            if diff <= 1e-9:
                continue
            summary = (
                f"{display_label} ({t_val:.2f}) departs from the constant prior historical "
                f"baseline ({m_val:.2f})."
            )
            scored.append(
                (
                    1e6 + diff,
                    FeatureDeviation(
                        feature_name=feature_key,
                        display_label=display_label,
                        target_value=round(t_val, 4),
                        training_mean=round(m_val, 4),
                        training_std=0.0,
                        z_score_deviation=None,
                        summary=summary,
                    ),
                )
            )

    scored.sort(key=lambda item: item[0], reverse=True)
    return [item[1] for item in scored[:max_items]]


def evaluate_transaction_anomaly_from_records(
    records: Iterable[Any],
    target_transaction: Any,
    *,
    min_training_samples: int = MIN_TRAINING_SAMPLES,
    random_state: int = DEFAULT_RANDOM_STATE,
    contamination: float = DEFAULT_CONTAMINATION,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
) -> MLAnomalyAssessment:
    """
    Runs reproducible experimental IsolationForest anomaly evaluation on `target_transaction`
    using only causally prior historical records from `records`.
    """
    if not _SKLEARN_AVAILABLE:
        return _unavailable_assessment(
            f"ML dependencies unavailable ({_SKLEARN_IMPORT_ERROR or 'scikit-learn missing'}).",
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )

    parsed_target = _parse_transaction_record(target_transaction)
    if parsed_target is None:
        return _unavailable_assessment(
            "Target transaction contains invalid or incomplete numerical fields for ML evaluation.",
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )

    prior_records: list[_ParsedTxRecord] = []
    for raw_rec in records:
        if raw_rec is target_transaction:
            continue
        parsed_rec = _parse_transaction_record(raw_rec)
        if parsed_rec is None:
            continue
        if _is_strictly_prior_record(parsed_rec, parsed_target):
            prior_records.append(parsed_rec)

    prior_records.sort(key=lambda r: (r.timestamp_utc, r.sort_id, r.reference))

    if len(prior_records) < min_training_samples:
        return _unavailable_assessment(
            (
                f"Experimental ML anomaly detection requires at least {min_training_samples} "
                f"usable prior historical transactions (found {len(prior_records)}). "
                "Deterministic risk evaluation remains active."
            ),
            training_sample_count=len(prior_records),
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )

    tracker = _CausalFeatureTracker()
    train_vectors: list[list[float]] = []
    for hist_rec in prior_records:
        vec = tracker.extract_features(hist_rec)
        if all(math.isfinite(val) for val in vec):
            train_vectors.append(vec)
            tracker.update(hist_rec)

    if len(train_vectors) < min_training_samples:
        return _unavailable_assessment(
            (
                f"Insufficient finite training feature vectors ({len(train_vectors)} of "
                f"{min_training_samples} required)."
            ),
            training_sample_count=len(train_vectors),
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )

    target_vector_list = tracker.extract_features(parsed_target)
    if not all(math.isfinite(val) for val in target_vector_list):
        return _unavailable_assessment(
            "Target transaction produced non-finite derived ML features.",
            training_sample_count=len(train_vectors),
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )

    try:
        x_train = np.asarray(train_vectors, dtype=np.float64)
        x_target = np.asarray([target_vector_list], dtype=np.float64)

        col_stds = np.std(x_train, axis=0)
        if bool(np.all(col_stds <= 1e-12)):
            return _unavailable_assessment(
                "Prior historical features show zero variance; IsolationForest scoring skipped.",
                training_sample_count=len(train_vectors),
                minimum_samples_required=min_training_samples,
                random_state=random_state,
            )

        scaler = StandardScaler()
        x_train_scaled = scaler.fit_transform(x_train)
        x_target_scaled = scaler.transform(x_target)

        model = IsolationForest(
            n_estimators=n_estimators,
            contamination=contamination,
            random_state=random_state,
        )
        model.fit(x_train_scaled)

        raw_score = float(model.decision_function(x_target_scaled)[0])
        raw_pred = int(model.predict(x_target_scaled)[0])
        if not math.isfinite(raw_score):
            return _unavailable_assessment(
                "IsolationForest returned a non-finite decision_function score.",
                training_sample_count=len(train_vectors),
                minimum_samples_required=min_training_samples,
                random_state=random_state,
            )

        is_anomaly = (raw_pred == -1) or (raw_score < 0.0)
        status = "ANOMALY" if is_anomaly else "NORMAL"
        deviations = _compute_feature_deviations(x_train, x_target[0])

        rounded_score = round(raw_score, 4)
        if is_anomaly:
            lead = (
                f"Experimental IsolationForest flagged this transaction as a behavioral outlier "
                f"(decision_score={rounded_score:.4f}; lower values indicate greater unusualness) "
                f"relative to {len(train_vectors)} prior historical transactions."
            )
        else:
            lead = (
                f"Experimental IsolationForest placed this transaction within the normal baseline "
                f"(decision_score={rounded_score:.4f}; lower values indicate greater unusualness) "
                f"across {len(train_vectors)} prior historical transactions."
            )

        if deviations:
            top_notes = " ".join(dev.summary for dev in deviations)
            explanation = f"{lead} Notable feature deviations: {top_notes}"
        else:
            explanation = f"{lead} No derived numerical feature deviated more than 0.5 std deviations."

        return MLAnomalyAssessment(
            available=True,
            status=status,
            experimental=True,
            model_name="IsolationForest (Experimental)",
            random_state=random_state,
            is_anomaly=is_anomaly,
            decision_score=rounded_score,
            score_interpretation=SCORE_INTERPRETATION_TEXT,
            training_sample_count=len(train_vectors),
            minimum_samples_required=min_training_samples,
            features_used=[key for key, _ in FEATURE_SPEC],
            feature_deviations=deviations,
            explanation=explanation,
            methodology_note=METHODOLOGY_NOTE_TEXT,
            limitations=LIMITATIONS_TEXT,
        )
    except Exception as exc:
        logger.warning("Experimental ML anomaly evaluation failed safely: %s", exc)
        return _unavailable_assessment(
            "Experimental ML anomaly model could not complete cleanly; deterministic rules remain active.",
            training_sample_count=len(train_vectors),
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )


def evaluate_transaction_anomaly(
    db: Session,
    target_transaction: Any,
    *,
    min_training_samples: int = MIN_TRAINING_SAMPLES,
    random_state: int = DEFAULT_RANDOM_STATE,
    contamination: float = DEFAULT_CONTAMINATION,
    n_estimators: int = DEFAULT_N_ESTIMATORS,
) -> MLAnomalyAssessment:
    """
    Loads persisted transactions from SQLAlchemy and delegates causal, leakage-free
    experimental IsolationForest evaluation. Never raises into API callers.
    """
    try:
        rows: Sequence[Transaction] = (
            db.execute(
                select(Transaction).order_by(Transaction.timestamp.asc(), Transaction.id.asc())
            )
            .scalars()
            .all()
        )
        return evaluate_transaction_anomaly_from_records(
            records=rows,
            target_transaction=target_transaction,
            min_training_samples=min_training_samples,
            random_state=random_state,
            contamination=contamination,
            n_estimators=n_estimators,
        )
    except Exception as exc:
        logger.warning("ML anomaly database query failed safely: %s", exc)
        return _unavailable_assessment(
            "Experimental ML anomaly data retrieval failed cleanly; deterministic rules remain active.",
            minimum_samples_required=min_training_samples,
            random_state=random_state,
        )
