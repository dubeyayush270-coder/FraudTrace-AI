"""
FraudTrace AI — Transaction API Routes
=======================================
Endpoints:
- POST /api/v1/transactions/analyze     — Ingests and analyzes a transaction with explainable risk rules.
- GET  /api/v1/transactions             — Retrieves paginated recent transactions.
- GET  /api/v1/transactions/{id}        — Retrieves full transaction details with investigations & evidence.
"""

from datetime import datetime, timezone
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models import Evidence, Investigation, Transaction
from app.schemas import (
    EvidenceResponse,
    InvestigationResponse,
    TransactionAnalyzeRequest,
    TransactionAnalyzeResponse,
    TransactionDetailResponse,
    TransactionListResponse,
    TransactionResponse,
)
from app.services.risk_engine import analyze_transaction_risk, ensure_utc

logger = logging.getLogger("fraudtrace.transactions")

router = APIRouter(prefix="/api/v1/transactions", tags=["transactions"])


@router.post(
    "/analyze",
    response_model=TransactionAnalyzeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Ingest and evaluate a transaction for fraud risk",
)
def analyze_transaction(
    payload: TransactionAnalyzeRequest,
    db: Session = Depends(get_db),
) -> TransactionAnalyzeResponse:
    """
    Submits a transaction to FraudTrace AI's explainable heuristic risk engine:
    1. Validates transaction reference uniqueness (returns 409 if duplicate).
    2. Runs deterministic fraud indicator rules (Velocity, Amount Anomaly, New Recipient, Repeated Recipient).
    3. Persists Transaction, Investigation, and Evidence records atomically.
    4. Returns complete explainable evidence breakdown.
    """
    # 1. Check for duplicate reference
    existing_txn = db.execute(
        select(Transaction).where(Transaction.reference == payload.reference)
    ).scalar_one_or_none()

    if existing_txn is not None:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"Transaction reference '{payload.reference}' already exists.",
        )

    # 2. Resolve timestamp (default to current UTC if omitted)
    txn_time = ensure_utc(payload.timestamp) if payload.timestamp else datetime.now(timezone.utc)

    # 3. Execute explainable risk evaluation
    analysis = analyze_transaction_risk(
        sender_id=payload.sender_id,
        receiver_id=payload.receiver_id,
        amount=payload.amount,
        currency=payload.currency,
        current_time=txn_time,
        db=db,
    )

    try:
        # 4. Create and persist Transaction record
        transaction = Transaction(
            reference=payload.reference,
            sender_id=payload.sender_id,
            receiver_id=payload.receiver_id,
            amount=payload.amount,
            currency=payload.currency,
            timestamp=txn_time,
            risk_score=analysis.risk_score,
            risk_level=analysis.risk_level,
            investigation_status=analysis.investigation_status,
        )
        db.add(transaction)
        db.flush()  # Obtain transaction.id for foreign key reference

        # 5. Create Investigation record
        priority_map = {
            "CRITICAL": "CRITICAL",
            "HIGH": "HIGH",
            "MEDIUM": "MEDIUM",
            "LOW": "NORMAL",
        }
        investigation = Investigation(
            transaction_id=transaction.id,
            status="OPEN" if analysis.risk_score >= 25 else "CLOSED",
            summary=analysis.summary,
            priority=priority_map.get(analysis.risk_level, "NORMAL"),
        )
        db.add(investigation)
        db.flush()  # Obtain investigation.id for child evidence records

        # 6. Create Evidence records
        saved_evidences: list[Evidence] = []
        for ev_item in analysis.evidence_items:
            evidence = Evidence(
                investigation_id=investigation.id,
                evidence_type=ev_item.evidence_type,
                description=ev_item.description,
                severity=ev_item.severity,
            )
            db.add(evidence)
            saved_evidences.append(evidence)

        # 7. Atomically commit all records
        db.commit()
        db.refresh(transaction)
        db.refresh(investigation)

    except IntegrityError as exc:
        db.rollback()
        # Handle race-condition reference collisions
        if "UNIQUE constraint failed" in str(exc) or "reference" in str(exc).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Transaction reference '{payload.reference}' already exists.",
            ) from exc
        logger.error(f"Integrity error during transaction analysis: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist transaction due to data integrity constraint.",
        ) from exc
    except Exception as exc:
        db.rollback()
        logger.error(f"Unexpected error analyzing transaction: {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while analyzing the transaction.",
        ) from exc

    # 8. Build structured Pydantic response
    evidence_responses = [
        EvidenceResponse(
            id=ev.id,
            evidence_type=ev.evidence_type,
            description=ev.description,
            severity=ev.severity,
            created_at=ev.created_at,
        )
        for ev in saved_evidences
    ]

    investigation_response = InvestigationResponse(
        id=investigation.id,
        status=investigation.status,
        summary=investigation.summary,
        priority=investigation.priority,
        created_at=investigation.created_at,
        evidences=evidence_responses,
    )

    return TransactionAnalyzeResponse(
        transaction=TransactionResponse.model_validate(transaction),
        risk_score=analysis.risk_score,
        risk_level=analysis.risk_level,
        investigation_status=analysis.investigation_status,
        investigation=investigation_response,
        evidence=evidence_responses,
        explanation=analysis.summary,
    )


@router.get(
    "",
    response_model=TransactionListResponse,
    summary="List recent transactions with pagination",
)
def list_transactions(
    limit: int = Query(default=20, ge=1, le=100, description="Max records to return"),
    offset: int = Query(default=0, ge=0, description="Records to skip"),
    db: Session = Depends(get_db),
) -> TransactionListResponse:
    """
    Returns recent transactions ordered by timestamp (descending).
    Includes fraud risk score, risk level, and investigation status.
    """
    total_count = db.scalar(select(func.count(Transaction.id))) or 0

    query = (
        select(Transaction)
        .order_by(Transaction.timestamp.desc(), Transaction.id.desc())
        .offset(offset)
        .limit(limit)
    )
    txns = db.execute(query).scalars().all()

    return TransactionListResponse(
        items=[TransactionResponse.model_validate(t) for t in txns],
        total=total_count,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{transaction_id}",
    response_model=TransactionDetailResponse,
    summary="Get transaction details with investigations and evidence",
)
def get_transaction_detail(
    transaction_id: int,
    db: Session = Depends(get_db),
) -> TransactionDetailResponse:
    """
    Retrieves full transaction details, including all linked investigations
    and evidentiary signals.
    """
    query = (
        select(Transaction)
        .options(
            selectinload(Transaction.investigations).selectinload(Investigation.evidences)
        )
        .where(Transaction.id == transaction_id)
    )
    txn = db.execute(query).scalar_one_or_none()

    if txn is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Transaction with ID {transaction_id} not found.",
        )

    return TransactionDetailResponse.model_validate(txn)
