"""
FraudTrace AI — PayPal Sandbox Orders v2 API Routes
===================================================
Endpoints:
- POST /api/v1/paypal/orders                    — Validates amount/currency & creates PayPal Sandbox order.
- POST /api/v1/paypal/orders/{order_id}/capture — Captures approved PayPal order & runs FraudTrace risk evaluation.

Security & Integrity Controls:
- Uses PayPal Sandbox APIs only via PayPalSandboxClient (in-memory OAuth cache).
- Never exposes Client Secrets, OAuth access tokens, or raw PayPal payloads.
- Enforces server-validated amounts/currencies before create and during capture.
- Requires APPROVED status before capture and rejects unapproved/failed payments cleanly.
- Prevents duplicate internal transactions using order/capture uniqueness constraints.
- Evaluates captured payments through the untouched deterministic risk engine without
  automatically blocking or reversing completed captures based on risk scores.
"""

from __future__ import annotations

from datetime import datetime, timezone
import logging
import re
from typing import Optional
import uuid

from fastapi import APIRouter, Depends, HTTPException, Response, status
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models import Evidence, Investigation, PayPalOrder, Transaction
from app.routes.transactions import _build_ml_anomaly_response
from app.schemas import (
    EvidenceResponse,
    InvestigationResponse,
    PayPalCaptureResponse,
    PayPalOrderCreateRequest,
    PayPalOrderCreateResponse,
    PayPalOrderSummaryResponse,
    TransactionAnalyzeResponse,
    TransactionResponse,
)
from app.services.paypal_client import (
    PayPalAPIError,
    PayPalConfigurationError,
    PayPalOrderSnapshot,
    PayPalSandboxClient,
    get_paypal_client,
)
from app.services.risk_engine import analyze_transaction_risk

logger = logging.getLogger("fraudtrace.paypal")

router = APIRouter(prefix="/api/v1/paypal", tags=["paypal"])

ORDER_ID_PATTERN = re.compile(r"^[A-Za-z0-9_-]{5,64}$")


def _validate_order_id_path(raw_order_id: str) -> str:
    clean = raw_order_id.strip()
    if not ORDER_ID_PATTERN.match(clean):
        raise HTTPException(
            status_code=422,
            detail="Invalid PayPal order ID format.",
        )
    return clean


def _map_priority(risk_level: str) -> str:
    return {
        "CRITICAL": "CRITICAL",
        "HIGH": "HIGH",
        "MEDIUM": "MEDIUM",
        "LOW": "NORMAL",
    }.get(risk_level, "NORMAL")


def _build_transaction_analyze_response(
    db: Session,
    txn: Transaction,
) -> TransactionAnalyzeResponse:
    """Constructs TransactionAnalyzeResponse cleanly from a persisted Transaction record."""
    loaded_txn = db.execute(
        select(Transaction)
        .options(selectinload(Transaction.investigations).selectinload(Investigation.evidences))
        .where(Transaction.id == txn.id)
    ).scalar_one()

    primary_inv: Optional[Investigation] = loaded_txn.investigations[0] if loaded_txn.investigations else None
    evidences = primary_inv.evidences if primary_inv is not None else []

    evidence_responses = [
        EvidenceResponse(
            id=ev.id,
            evidence_type=ev.evidence_type,
            description=ev.description,
            severity=ev.severity,
            created_at=ev.created_at,
        )
        for ev in evidences
    ]

    investigation_response = (
        InvestigationResponse(
            id=primary_inv.id,
            status=primary_inv.status,
            summary=primary_inv.summary,
            priority=primary_inv.priority,
            created_at=primary_inv.created_at,
            evidences=evidence_responses,
        )
        if primary_inv is not None
        else None
    )

    explanation = (
        primary_inv.summary
        if primary_inv is not None and primary_inv.summary
        else f"Risk assessment recorded for PayPal capture transaction '{loaded_txn.reference}'."
    )

    return TransactionAnalyzeResponse(
        transaction=TransactionResponse.model_validate(loaded_txn),
        risk_score=float(loaded_txn.risk_score or 0.0),
        risk_level=loaded_txn.risk_level or "LOW",
        investigation_status=loaded_txn.investigation_status,
        investigation=investigation_response,
        evidence=evidence_responses,
        explanation=explanation,
        ml_anomaly=_build_ml_anomaly_response(db=db, txn=loaded_txn),
    )


def _persist_captured_transaction(
    db: Session,
    order_record: PayPalOrder,
    snapshot: PayPalOrderSnapshot,
) -> PayPalCaptureResponse:
    """
    Validates confirmed capture figures against stored backend order metadata, runs
    FraudTrace's untouched deterministic risk engine, and persists Transaction,
    Investigation, Evidence[], and PayPalOrder link atomically without duplication.
    """
    capture_rec = snapshot.capture
    if capture_rec is None:
        raise HTTPException(
            status_code=422,
            detail="PayPal Sandbox order response did not contain capture details.",
        )

    captured_amount = capture_rec.amount if capture_rec.amount is not None else snapshot.amount
    captured_currency = capture_rec.currency if capture_rec.currency is not None else snapshot.currency

    if captured_amount is None or captured_currency is None:
        order_record.status = "CAPTURE_UNVERIFIED"
        order_record.paypal_capture_id = capture_rec.capture_id
        db.commit()
        raise HTTPException(
            status_code=422,
            detail="PayPal Sandbox capture response omitted validated amount or currency.",
        )

    if captured_amount != order_record.requested_amount or captured_currency != order_record.currency:
        order_record.status = "AMOUNT_MISMATCH"
        order_record.paypal_capture_id = capture_rec.capture_id
        db.commit()
        raise HTTPException(
            status_code=422,
            detail=(
                "PayPal captured amount or currency does not match the recorded backend order. "
                "Transaction was not recorded as clean."
            ),
        )

    # Secondary idempotency guard against capture_id or reference collisions
    txn_reference = f"PP-CAP-{capture_rec.capture_id}"[:64]
    existing_txn = db.execute(
        select(Transaction).where(Transaction.reference == txn_reference)
    ).scalar_one_or_none()
    if existing_txn is not None:
        if order_record.transaction_id is None:
            order_record.transaction_id = existing_txn.id
            order_record.status = "COMPLETED"
            order_record.paypal_capture_id = capture_rec.capture_id
            order_record.captured_amount = captured_amount
            order_record.payer_id = order_record.payer_id or snapshot.payer_id
            order_record.captured_at = order_record.captured_at or datetime.now(timezone.utc)
            db.commit()
            db.refresh(order_record)
        return PayPalCaptureResponse(
            paypal_order=PayPalOrderSummaryResponse.model_validate(order_record),
            already_captured=True,
            transaction_analysis=_build_transaction_analyze_response(db=db, txn=existing_txn),
            message="PayPal order capture was already recorded in FraudTrace AI; returning existing assessment.",
        )

    capture_time = datetime.now(timezone.utc)
    sender_account = (
        order_record.sender_id
        or (f"PAYPAL_{snapshot.payer_id}" if snapshot.payer_id else "PAYPAL_SANDBOX_PAYER")
    )[:128]
    receiver_account = order_record.receiver_id[:128]

    # Evaluate through FraudTrace's untouched deterministic rule engine
    analysis = analyze_transaction_risk(
        sender_id=sender_account,
        receiver_id=receiver_account,
        amount=captured_amount,
        currency=captured_currency,
        current_time=capture_time,
        db=db,
    )

    try:
        transaction = Transaction(
            reference=txn_reference,
            sender_id=sender_account,
            receiver_id=receiver_account,
            amount=captured_amount,
            currency=captured_currency,
            timestamp=capture_time,
            risk_score=analysis.risk_score,
            risk_level=analysis.risk_level,
            investigation_status=analysis.investigation_status,
        )
        db.add(transaction)
        db.flush()

        paypal_metadata_tag = (
            f"[PayPal Order: {order_record.paypal_order_id} | "
            f"Capture: {capture_rec.capture_id} | "
            f"Internal Ref: {order_record.internal_reference}]"
        )
        investigation = Investigation(
            transaction_id=transaction.id,
            status="OPEN" if analysis.risk_score >= 25 else "CLOSED",
            summary=f"{analysis.summary} {paypal_metadata_tag}",
            priority=_map_priority(analysis.risk_level),
        )
        db.add(investigation)
        db.flush()

        for ev_item in analysis.evidence_items:
            db.add(
                Evidence(
                    investigation_id=investigation.id,
                    evidence_type=ev_item.evidence_type,
                    description=ev_item.description,
                    severity=ev_item.severity,
                )
            )

        order_record.status = "COMPLETED"
        order_record.paypal_capture_id = capture_rec.capture_id
        order_record.captured_amount = captured_amount
        order_record.payer_id = snapshot.payer_id
        order_record.transaction_id = transaction.id
        order_record.captured_at = capture_time

        db.commit()
        db.refresh(order_record)
        db.refresh(transaction)

    except IntegrityError as exc:
        db.rollback()
        logger.warning("Capture persistence integrity collision handled safely", exc_info=True)
        existing_retry_txn = db.execute(
            select(Transaction).where(Transaction.reference == txn_reference)
        ).scalar_one_or_none()
        reloaded_order = db.execute(
            select(PayPalOrder).where(PayPalOrder.id == order_record.id)
        ).scalar_one()
        if existing_retry_txn is not None and reloaded_order.transaction_id == existing_retry_txn.id:
            return PayPalCaptureResponse(
                paypal_order=PayPalOrderSummaryResponse.model_validate(reloaded_order),
                already_captured=True,
                transaction_analysis=_build_transaction_analyze_response(db=db, txn=existing_retry_txn),
                message="PayPal order capture was already processed; returning persisted result.",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="PayPal capture record conflicted with an existing persisted transaction.",
        ) from exc
    except Exception as exc:
        db.rollback()
        logger.error("Unexpected failure recording PayPal capture transaction", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist captured PayPal transaction cleanly.",
        ) from exc

    return PayPalCaptureResponse(
        paypal_order=PayPalOrderSummaryResponse.model_validate(order_record),
        already_captured=False,
        transaction_analysis=_build_transaction_analyze_response(db=db, txn=transaction),
        message="PayPal Sandbox order captured and evaluated by FraudTrace AI.",
    )


@router.post(
    "/orders",
    response_model=PayPalOrderCreateResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Create a PayPal Sandbox checkout order (intent=CAPTURE)",
)
def create_paypal_order(
    payload: PayPalOrderCreateRequest,
    response: Response,
    db: Session = Depends(get_db),
    paypal_client: PayPalSandboxClient = Depends(get_paypal_client),
) -> PayPalOrderCreateResponse:
    """
    Validates requested payment amount and supported currency on the backend,
    creates a PayPal Orders v2 order (`intent=CAPTURE`) using an idempotency reference,
    persists order metadata cleanly, and returns only safe approval information.
    """
    internal_ref = payload.internal_reference or f"PP-ORD-{uuid.uuid4().hex[:16].upper()}"

    existing_order = db.execute(
        select(PayPalOrder).where(PayPalOrder.internal_reference == internal_ref)
    ).scalar_one_or_none()

    if existing_order is not None:
        sender_mismatch = (
            payload.sender_id is not None
            and existing_order.sender_id is not None
            and payload.sender_id != existing_order.sender_id
        )
        if (
            existing_order.requested_amount != payload.amount
            or existing_order.currency != payload.currency
            or existing_order.receiver_id != payload.receiver_id
            or sender_mismatch
        ):
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Internal reference '{internal_ref}' is already assigned to different payment parameters.",
            )

        response.status_code = status.HTTP_200_OK
        return PayPalOrderCreateResponse(
            internal_reference=existing_order.internal_reference,
            paypal_order_id=existing_order.paypal_order_id,
            status=existing_order.status,
            intent=existing_order.intent,
            amount=existing_order.requested_amount,
            currency=existing_order.currency,
            approval_url=existing_order.approval_url,
            idempotent_replay=True,
            created_at=existing_order.created_at,
            message="Existing PayPal Sandbox order returned for idempotent internal_reference.",
        )

    try:
        created = paypal_client.create_order(
            amount=payload.amount,
            currency=payload.currency,
            internal_reference=internal_ref,
            return_url=payload.return_url,
            cancel_url=payload.cancel_url,
        )
    except PayPalConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except PayPalAPIError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        ) from exc

    try:
        order_record = PayPalOrder(
            internal_reference=internal_ref,
            paypal_order_id=created.paypal_order_id,
            intent=created.intent,
            status=created.status,
            requested_amount=created.amount,
            currency=created.currency,
            sender_id=payload.sender_id,
            receiver_id=payload.receiver_id,
            approval_url=created.approval_url,
        )
        db.add(order_record)
        db.commit()
        db.refresh(order_record)
    except IntegrityError as exc:
        db.rollback()
        existing_race = db.execute(
            select(PayPalOrder).where(PayPalOrder.internal_reference == internal_ref)
        ).scalar_one_or_none()
        if existing_race is not None and existing_race.requested_amount == payload.amount:
            response.status_code = status.HTTP_200_OK
            return PayPalOrderCreateResponse(
                internal_reference=existing_race.internal_reference,
                paypal_order_id=existing_race.paypal_order_id,
                status=existing_race.status,
                intent=existing_race.intent,
                amount=existing_race.requested_amount,
                currency=existing_race.currency,
                approval_url=existing_race.approval_url,
                idempotent_replay=True,
                created_at=existing_race.created_at,
                message="Existing PayPal Sandbox order returned for concurrent idempotent replay.",
            )
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="PayPal order identifier or internal reference already exists.",
        ) from exc
    except Exception as exc:
        db.rollback()
        logger.error("Unexpected error saving created PayPal order", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to save PayPal Sandbox order metadata.",
        ) from exc

    return PayPalOrderCreateResponse(
        internal_reference=order_record.internal_reference,
        paypal_order_id=order_record.paypal_order_id,
        status=order_record.status,
        intent=order_record.intent,
        amount=order_record.requested_amount,
        currency=order_record.currency,
        approval_url=order_record.approval_url,
        idempotent_replay=False,
        created_at=order_record.created_at,
        message="PayPal Sandbox order created successfully.",
    )


@router.post(
    "/orders/{order_id}/capture",
    response_model=PayPalCaptureResponse,
    status_code=status.HTTP_200_OK,
    summary="Capture an approved PayPal Sandbox order and analyze payment risk",
)
def capture_paypal_order(
    order_id: str,
    db: Session = Depends(get_db),
    paypal_client: PayPalSandboxClient = Depends(get_paypal_client),
) -> PayPalCaptureResponse:
    """
    Captures an approved PayPal Sandbox order cleanly:
    1. Rejects unknown orders (`404`) and invalid order ID formats (`422`).
    2. Returns idempotently without re-capturing or duplicating transactions when already completed.
    3. Queries PayPal order status first and rejects unapproved/ineligible orders (`409`).
    4. Captures approved order, validates status == COMPLETED plus amount/currency parity.
    5. Feeds confirmed capture into FraudTrace's deterministic risk engine without blocking settlement.
    """
    clean_order_id = _validate_order_id_path(order_id)

    order_record = db.execute(
        select(PayPalOrder).where(PayPalOrder.paypal_order_id == clean_order_id)
    ).scalar_one_or_none()

    if order_record is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"PayPal Sandbox order '{clean_order_id}' was not found.",
        )

    # Already captured and evaluated -> pure idempotent return with zero duplicate API or DB work
    if order_record.transaction_id is not None:
        existing_txn = db.execute(
            select(Transaction).where(Transaction.id == order_record.transaction_id)
        ).scalar_one_or_none()
        if existing_txn is not None:
            return PayPalCaptureResponse(
                paypal_order=PayPalOrderSummaryResponse.model_validate(order_record),
                already_captured=True,
                transaction_analysis=_build_transaction_analyze_response(db=db, txn=existing_txn),
                message="PayPal Sandbox order was already captured; returning persisted evaluation.",
            )

    # Check authoritative PayPal order status before executing capture
    try:
        current_snapshot = paypal_client.get_order(clean_order_id)
    except PayPalConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except PayPalAPIError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        ) from exc

    if current_snapshot.intent != "CAPTURE":
        raise HTTPException(
            status_code=422,
            detail=f"PayPal order intent '{current_snapshot.intent}' is not CAPTURE.",
        )

    if current_snapshot.amount is not None and current_snapshot.amount != order_record.requested_amount:
        raise HTTPException(
            status_code=422,
            detail="PayPal order amount does not match the backend order record.",
        )
    if current_snapshot.currency is not None and current_snapshot.currency != order_record.currency:
        raise HTTPException(
            status_code=422,
            detail="PayPal order currency does not match the backend order record.",
        )

    # If PayPal already completed capture earlier before local commit finished, finalize idempotently
    if current_snapshot.status == "COMPLETED":
        if current_snapshot.capture is not None and current_snapshot.capture.status == "COMPLETED":
            return _persist_captured_transaction(db=db, order_record=order_record, snapshot=current_snapshot)
        raise HTTPException(
            status_code=422,
            detail="PayPal order is COMPLETED without a verified COMPLETED capture record.",
        )

    if current_snapshot.status != "APPROVED":
        order_record.status = current_snapshot.status
        db.commit()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=(
                f"PayPal order '{clean_order_id}' is not eligible for capture "
                f"(current status: '{current_snapshot.status}'). Approval is required first."
            ),
        )

    # Execute capture against PayPal Orders v2 using deterministic idempotency key
    try:
        capture_snapshot = paypal_client.capture_order(
            clean_order_id,
            idempotency_key=f"CAP-{order_record.internal_reference}",
        )
    except PayPalConfigurationError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        ) from exc
    except PayPalAPIError as exc:
        raise HTTPException(
            status_code=exc.status_code,
            detail=exc.message,
        ) from exc

    cap_rec = capture_snapshot.capture
    if capture_snapshot.status != "COMPLETED" or cap_rec is None or cap_rec.status != "COMPLETED":
        reported_status = cap_rec.status if cap_rec is not None else capture_snapshot.status
        order_record.status = reported_status[:32]
        if cap_rec is not None:
            order_record.paypal_capture_id = cap_rec.capture_id
        db.commit()
        raise HTTPException(
            status_code=422,
            detail=(
                f"PayPal Sandbox capture did not complete cleanly (status: '{reported_status}'). "
                "No payment transaction was recorded."
            ),
        )

    return _persist_captured_transaction(db=db, order_record=order_record, snapshot=capture_snapshot)
