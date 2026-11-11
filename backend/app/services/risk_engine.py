"""
FraudTrace AI — Explainable Rule-Based Fraud Risk Engine
=========================================================
Evaluates transactions against deterministic heuristic rules:
1. TRANSACTION_VELOCITY        (25 pts) — 3+ transactions from sender within 10 min.
2. AMOUNT_ANOMALY             (30 pts) — Amount >= 5x sender's average (min 3 prior txns, same currency).
3. NEW_RECIPIENT              (10 pts) — First transaction between sender and receiver.
4. REPEATED_RECIPIENT_ACTIVITY (25 pts) — 3+ transactions from sender to receiver within 10 min.

Risk Score & Levels:
- Initial score: 0
- Cap: 100
- 0–24: LOW | 25–49: MEDIUM | 50–74: HIGH | 75–100: CRITICAL
Note: These are heuristic risk scores based on rule indicators, NOT fraud probabilities.
"""

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Transaction


@dataclass
class RuleEvaluation:
    """Represents the outcome of a single heuristic rule evaluation."""
    rule_name: str
    triggered: bool
    evidence_type: str
    description: str
    severity: str
    points_contributed: int


@dataclass
class RiskAnalysisResult:
    """Aggregated risk assessment with explainable evidence."""
    risk_score: float
    risk_level: str
    investigation_status: str
    summary: str
    evidence_items: list[RuleEvaluation]


def ensure_utc(dt: datetime) -> datetime:
    """Ensure datetime has UTC timezone."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc)


def evaluate_transaction_velocity(
    sender_id: str,
    current_time: datetime,
    db: Session,
    window_minutes: int = 10,
    threshold: int = 3,
) -> RuleEvaluation:
    """
    Rule 1: TRANSACTION_VELOCITY
    Detects 3 or more transactions from the same sender within a rolling 10-minute window.
    Assigns 25 risk points.
    """
    ts = ensure_utc(current_time)
    window_start = ts - timedelta(minutes=window_minutes)

    recent_txns = db.execute(
        select(Transaction).where(
            Transaction.sender_id == sender_id,
            Transaction.timestamp >= window_start,
            Transaction.timestamp <= ts,
        )
    ).scalars().all()

    count = len(recent_txns)
    triggered = count >= threshold

    if triggered:
        description = (
            f"High transaction velocity detected: Sender '{sender_id}' initiated {count} "
            f"transactions within a {window_minutes}-minute window (threshold: {threshold})."
        )
        return RuleEvaluation(
            rule_name="TRANSACTION_VELOCITY",
            triggered=True,
            evidence_type="TRANSACTION_VELOCITY",
            description=description,
            severity="MEDIUM",
            points_contributed=25,
        )

    return RuleEvaluation(
        rule_name="TRANSACTION_VELOCITY",
        triggered=False,
        evidence_type="TRANSACTION_VELOCITY",
        description="Normal sender transaction frequency.",
        severity="LOW",
        points_contributed=0,
    )


def evaluate_amount_anomaly(
    sender_id: str,
    amount: Decimal,
    currency: str,
    current_time: datetime,
    db: Session,
    multiplier: Decimal = Decimal("5.0"),
    min_history_count: int = 3,
) -> RuleEvaluation:
    """
    Rule 2: AMOUNT_ANOMALY
    Compares the submitted transaction amount against sender's historical average in the same currency.
    Triggers when amount >= 5x historical average. Requires at least 3 previous transactions.
    Assigns 30 risk points.
    """
    ts = ensure_utc(current_time)

    # Query historical transactions from this sender in the matching currency
    history = db.execute(
        select(Transaction).where(
            Transaction.sender_id == sender_id,
            Transaction.currency == currency,
            Transaction.timestamp <= ts,
        )
    ).scalars().all()

    if len(history) < min_history_count:
        return RuleEvaluation(
            rule_name="AMOUNT_ANOMALY",
            triggered=False,
            evidence_type="AMOUNT_ANOMALY",
            description=(
                f"Insufficient historical data to evaluate amount anomaly for sender '{sender_id}' "
                f"in currency '{currency}' ({len(history)} previous record(s) found, minimum required: {min_history_count})."
            ),
            severity="LOW",
            points_contributed=0,
        )

    total_historical = sum(t.amount for t in history)
    avg_amount = total_historical / Decimal(len(history))
    ratio = amount / avg_amount if avg_amount > 0 else Decimal("0")

    triggered = amount >= (multiplier * avg_amount)

    if triggered:
        description = (
            f"Amount anomaly detected: Submitted amount of {amount:.2f} {currency} is {ratio:.1f}x "
            f"higher than sender's historical average of {avg_amount:.2f} {currency} "
            f"(computed across {len(history)} previous transactions). Trigger threshold is {multiplier}x."
        )
        return RuleEvaluation(
            rule_name="AMOUNT_ANOMALY",
            triggered=True,
            evidence_type="AMOUNT_ANOMALY",
            description=description,
            severity="HIGH",
            points_contributed=30,
        )

    return RuleEvaluation(
        rule_name="AMOUNT_ANOMALY",
        triggered=False,
        evidence_type="AMOUNT_ANOMALY",
        description=f"Transaction amount {amount:.2f} {currency} is within expected historical distribution (avg: {avg_amount:.2f} {currency}).",
        severity="LOW",
        points_contributed=0,
    )


def evaluate_new_recipient(
    sender_id: str,
    receiver_id: str,
    current_time: datetime,
    db: Session,
) -> RuleEvaluation:
    """
    Rule 3: NEW_RECIPIENT
    Detects when the sender has never previously transacted with the receiver.
    Assigns 10 risk points.
    Note: Not treated alone as evidence of fraud.
    """
    ts = ensure_utc(current_time)

    prior_txn = db.execute(
        select(Transaction).where(
            Transaction.sender_id == sender_id,
            Transaction.receiver_id == receiver_id,
            Transaction.timestamp <= ts,
        ).limit(1)
    ).scalar_one_or_none()

    is_new = prior_txn is None

    if is_new:
        description = (
            f"New recipient detected: Sender '{sender_id}' has no prior recorded transactions "
            f"with receiver '{receiver_id}'. (Informational indicator; not standalone evidence of fraud)."
        )
        return RuleEvaluation(
            rule_name="NEW_RECIPIENT",
            triggered=True,
            evidence_type="NEW_RECIPIENT",
            description=description,
            severity="LOW",
            points_contributed=10,
        )

    return RuleEvaluation(
        rule_name="NEW_RECIPIENT",
        triggered=False,
        evidence_type="NEW_RECIPIENT",
        description=f"Sender has prior verified transaction history with receiver '{receiver_id}'.",
        severity="LOW",
        points_contributed=0,
    )


def evaluate_repeated_recipient_activity(
    sender_id: str,
    receiver_id: str,
    current_time: datetime,
    db: Session,
    window_minutes: int = 10,
    threshold: int = 3,
) -> RuleEvaluation:
    """
    Rule 4: REPEATED_RECIPIENT_ACTIVITY
    Detects 3 or more transactions from the same sender to the same receiver within a 10-minute window.
    Assigns 25 risk points.
    """
    ts = ensure_utc(current_time)
    window_start = ts - timedelta(minutes=window_minutes)

    recent_pair_txns = db.execute(
        select(Transaction).where(
            Transaction.sender_id == sender_id,
            Transaction.receiver_id == receiver_id,
            Transaction.timestamp >= window_start,
            Transaction.timestamp <= ts,
        )
    ).scalars().all()

    count = len(recent_pair_txns)
    triggered = count >= threshold

    if triggered:
        description = (
            f"Repeated recipient activity: Sender '{sender_id}' sent {count} transactions to "
            f"receiver '{receiver_id}' within {window_minutes} minutes (threshold: {threshold})."
        )
        return RuleEvaluation(
            rule_name="REPEATED_RECIPIENT_ACTIVITY",
            triggered=True,
            evidence_type="REPEATED_RECIPIENT_ACTIVITY",
            description=description,
            severity="MEDIUM",
            points_contributed=25,
        )

    return RuleEvaluation(
        rule_name="REPEATED_RECIPIENT_ACTIVITY",
        triggered=False,
        evidence_type="REPEATED_RECIPIENT_ACTIVITY",
        description="Normal transaction cadence between sender and receiver.",
        severity="LOW",
        points_contributed=0,
    )


def determine_risk_level(score: float) -> str:
    """
    Maps numeric heuristic score to risk level.
    0–24: LOW
    25–49: MEDIUM
    50–74: HIGH
    75–100: CRITICAL
    """
    if score >= 75:
        return "CRITICAL"
    if score >= 50:
        return "HIGH"
    if score >= 25:
        return "MEDIUM"
    return "LOW"


def determine_investigation_status(risk_level: str) -> str:
    """Maps risk level to operational investigation status."""
    if risk_level in ("CRITICAL", "HIGH"):
        return "FLAGGED"
    if risk_level == "MEDIUM":
        return "UNDER_REVIEW"
    return "CLEARED"


def analyze_transaction_risk(
    sender_id: str,
    receiver_id: str,
    amount: Decimal,
    currency: str,
    current_time: datetime,
    db: Session,
) -> RiskAnalysisResult:
    """
    Executes the modular rule-based risk evaluation suite against a transaction.
    Sums points from all triggered rules, caps final score at 100, and builds
    explainable evidentiary findings.
    """
    ts = ensure_utc(current_time)

    # Evaluate each rule independently
    evaluations: list[RuleEvaluation] = [
        evaluate_transaction_velocity(sender_id, ts, db),
        evaluate_amount_anomaly(sender_id, amount, currency, ts, db),
        evaluate_new_recipient(sender_id, receiver_id, ts, db),
        evaluate_repeated_recipient_activity(sender_id, receiver_id, ts, db),
    ]

    triggered_items = [e for e in evaluations if e.triggered]
    raw_points = sum(e.points_contributed for e in triggered_items)
    final_score = float(min(raw_points, 100))

    risk_level = determine_risk_level(final_score)
    inv_status = determine_investigation_status(risk_level)

    if triggered_items:
        rule_names = ", ".join(e.rule_name for e in triggered_items)
        summary = (
            f"Risk analysis evaluated {len(triggered_items)} triggered indicator(s) [{rule_names}], "
            f"yielding a heuristic score of {final_score:.0f}/100 ({risk_level} risk)."
        )
    else:
        summary = (
            "No configured risk indicators were detected. Transaction parameters align with normal baseline activity."
        )

    return RiskAnalysisResult(
        risk_score=final_score,
        risk_level=risk_level,
        investigation_status=inv_status,
        summary=summary,
        evidence_items=triggered_items,
    )
