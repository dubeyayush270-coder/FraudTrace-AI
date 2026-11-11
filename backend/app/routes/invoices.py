"""
FraudTrace AI — Invoice Investigation API Routes
===============================================
Endpoints:
- POST /api/v1/invoices/analyze       — Validates, extracts, analyzes, and persists invoice metadata.
- GET  /api/v1/invoices               — Retrieves paginated invoice investigation history.
- GET  /api/v1/invoices/{invoice_id}  — Retrieves full invoice fields, findings, and metadata.
"""

from __future__ import annotations

import json
import logging
from typing import Annotated, Any, Optional

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from sqlalchemy import func, select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, selectinload

from app.database import get_db
from app.models import Invoice, InvoiceFinding
from app.schemas import (
    ExtractedFieldResponse,
    InvoiceAnalyzeResponse,
    InvoiceDetailResponse,
    InvoiceFindingResponse,
    InvoiceListResponse,
    InvoiceSummaryResponse,
)
from app.services.invoice_analyzer import analyze_invoice
from app.services.invoice_extractor import (
    INVOICE_FIELD_NAMES,
    InvoiceValidationError,
    extract_invoice_document,
    read_bounded_upload_sync,
)

logger = logging.getLogger("fraudtrace.invoices")

router = APIRouter(prefix="/api/v1/invoices", tags=["invoices"])


def _parse_corrections_form(raw_json: Optional[str]) -> dict[str, Any]:
    """Parses optional JSON user-corrections cleanly without allowing unknown field keys."""
    if raw_json is None or not raw_json.strip():
        return {}
    try:
        parsed = json.loads(raw_json)
    except (json.JSONDecodeError, TypeError) as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid JSON format for user corrections.",
        ) from exc

    if not isinstance(parsed, dict):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User corrections must be a JSON object keyed by invoice field names.",
        )

    allowed_set = set(INVOICE_FIELD_NAMES)
    unknown_keys = [k for k in parsed.keys() if k not in allowed_set]
    if unknown_keys:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Unsupported invoice correction field(s): {', '.join(sorted(unknown_keys))}",
        )

    return parsed


def _serialize_field_metadata(
    extraction_note: str,
    fields: list[ExtractedFieldResponse],
) -> str:
    payload = {
        "extraction_note": extraction_note,
        "fields": [item.model_dump() for item in fields],
    }
    return json.dumps(payload)


def _deserialize_field_metadata(raw_json: Optional[str]) -> tuple[Optional[str], list[ExtractedFieldResponse]]:
    if not raw_json:
        return None, []
    try:
        parsed = json.loads(raw_json)
        note = parsed.get("extraction_note") if isinstance(parsed, dict) else None
        raw_fields = parsed.get("fields", []) if isinstance(parsed, dict) else []
        fields = [ExtractedFieldResponse(**entry) for entry in raw_fields if isinstance(entry, dict)]
        return note, fields
    except Exception:
        return None, []


def _parse_supporting_values(raw_json: Optional[str]) -> dict[str, Any]:
    if not raw_json:
        return {}
    try:
        parsed = json.loads(raw_json)
        return parsed if isinstance(parsed, dict) else {}
    except Exception:
        return {}


def _to_summary_response(inv: Invoice) -> InvoiceSummaryResponse:
    return InvoiceSummaryResponse(
        id=inv.id,
        submission_reference=inv.submission_reference,
        original_filename=inv.original_filename,
        file_type=inv.file_type,
        file_size_bytes=inv.file_size_bytes,
        page_count=inv.page_count,
        ocr_available=inv.ocr_available,
        vendor_name=inv.vendor_name,
        normalized_vendor_name=inv.normalized_vendor_name,
        invoice_number=inv.invoice_number,
        normalized_invoice_number=inv.normalized_invoice_number,
        invoice_date=inv.invoice_date,
        due_date=inv.due_date,
        currency=inv.currency,
        subtotal=inv.subtotal,
        tax=inv.tax,
        total_amount=inv.total_amount,
        po_number=inv.po_number,
        extraction_status=inv.extraction_status,
        investigation_status=inv.investigation_status,
        summary=inv.summary,
        findings_count=len(inv.findings),
        created_at=inv.created_at,
        updated_at=inv.updated_at,
    )


def _to_finding_responses(findings: list[InvoiceFinding]) -> list[InvoiceFindingResponse]:
    return [
        InvoiceFindingResponse(
            id=item.id,
            finding_code=item.finding_code,
            severity=item.severity,
            explanation=item.explanation,
            supporting_values=_parse_supporting_values(item.supporting_values),
            created_at=item.created_at,
        )
        for item in findings
    ]


@router.post(
    "/analyze",
    response_model=InvoiceAnalyzeResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload and evaluate an invoice document (PDF, PNG, JPG/JPEG)",
)
def analyze_invoice_upload(
    file: Annotated[UploadFile, File(...)],
    submission_reference: Annotated[Optional[str], Form()] = None,
    reject_duplicates: Annotated[bool, Form()] = False,
    corrections_json: Annotated[Optional[str], Form()] = None,
    db: Session = Depends(get_db),
) -> InvoiceAnalyzeResponse:
    """
    Securely reads up to 10 MB of an uploaded PDF/PNG/JPEG invoice, validates file signatures
    and structural bounds, extracts structured fields without fabricating missing values, runs
    deterministic invoice consistency checks, and persists metadata + findings without retaining
    raw document bytes.
    """
    clean_ref = submission_reference.strip() if submission_reference else None
    if clean_ref == "":
        clean_ref = None
    if clean_ref is not None:
        if len(clean_ref) > 128:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Submission reference exceeds maximum length of 128 characters.",
            )
        existing_submission = db.execute(
            select(Invoice).where(Invoice.submission_reference == clean_ref)
        ).scalar_one_or_none()
        if existing_submission is not None:
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Submission reference '{clean_ref}' has already been analyzed.",
            )

    parsed_corrections = _parse_corrections_form(corrections_json)

    try:
        file_bytes = read_bounded_upload_sync(file)
        extraction = extract_invoice_document(
            data=file_bytes,
            raw_filename=file.filename,
            corrections=parsed_corrections,
        )
    except InvoiceValidationError as exc:
        raise HTTPException(status_code=exc.status_code, detail=exc.detail) from exc
    except HTTPException:
        raise
    except Exception:
        logger.warning("Unexpected invoice extraction failure", exc_info=True)
        raise HTTPException(
            status_code=422,
            detail="Unable to process uploaded invoice document safely.",
        )

    analysis = analyze_invoice(extraction=extraction, db=db)

    if reject_duplicates and any(f.finding_code == "DUPLICATE_INVOICE" for f in analysis.findings):
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Duplicate invoice detected for the same normalized vendor and invoice number.",
        )

    field_responses = [
        ExtractedFieldResponse(
            field_name=info.field_name,
            extracted_value=info.extracted_value,
            corrected_value=info.corrected_value,
            effective_value=info.effective_value,
            extraction_status=info.extraction_status,
            confidence=info.confidence,
        )
        for info in extraction.fields.values()
    ]

    try:
        invoice_record = Invoice(
            submission_reference=clean_ref,
            original_filename=extraction.original_filename,
            file_type=extraction.file_type,
            file_size_bytes=extraction.file_size_bytes,
            page_count=extraction.page_count,
            ocr_available=extraction.ocr_available,
            vendor_name=extraction.vendor_name,
            normalized_vendor_name=analysis.normalized_vendor_name,
            invoice_number=extraction.invoice_number,
            normalized_invoice_number=analysis.normalized_invoice_number,
            invoice_date=extraction.invoice_date,
            due_date=extraction.due_date,
            currency=extraction.currency,
            subtotal=extraction.subtotal,
            tax=extraction.tax,
            total_amount=extraction.total_amount,
            po_number=extraction.po_number,
            extraction_status=extraction.extraction_status,
            investigation_status=analysis.investigation_status,
            summary=analysis.summary,
            field_metadata_json=_serialize_field_metadata(extraction.extraction_note, field_responses),
        )
        db.add(invoice_record)
        db.flush()

        for finding in analysis.findings:
            db.add(
                InvoiceFinding(
                    invoice_id=invoice_record.id,
                    finding_code=finding.finding_code,
                    severity=finding.severity,
                    explanation=finding.explanation,
                    supporting_values=json.dumps(finding.supporting_values),
                )
            )

        db.commit()
        db.refresh(invoice_record)
        persisted = db.execute(
            select(Invoice)
            .options(selectinload(Invoice.findings))
            .where(Invoice.id == invoice_record.id)
        ).scalar_one()

    except IntegrityError as exc:
        db.rollback()
        if "submission_reference" in str(exc).lower() or "unique constraint" in str(exc).lower():
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail="Duplicate submission reference conflict.",
            ) from exc
        logger.error("Integrity error persisting invoice investigation", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Failed to persist invoice investigation due to a data integrity constraint.",
        ) from exc
    except Exception as exc:
        db.rollback()
        logger.error("Unexpected error persisting invoice investigation", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected error occurred while saving the invoice investigation.",
        ) from exc

    return InvoiceAnalyzeResponse(
        invoice=_to_summary_response(persisted),
        fields=field_responses,
        findings=_to_finding_responses(persisted.findings),
        extraction_note=extraction.extraction_note,
    )


@router.get(
    "",
    response_model=InvoiceListResponse,
    summary="List invoice investigation history with pagination",
)
def list_invoices(
    limit: Annotated[int, Query(ge=1, le=100, description="Max records to return")] = 20,
    offset: Annotated[int, Query(ge=0, description="Records to skip")] = 0,
    db: Session = Depends(get_db),
) -> InvoiceListResponse:
    """Returns persisted invoice investigation summaries newest-first."""
    total_count = db.scalar(select(func.count(Invoice.id))) or 0

    rows = (
        db.execute(
            select(Invoice)
            .options(selectinload(Invoice.findings))
            .order_by(Invoice.created_at.desc(), Invoice.id.desc())
            .offset(offset)
            .limit(limit)
        )
        .scalars()
        .all()
    )

    return InvoiceListResponse(
        items=[_to_summary_response(inv) for inv in rows],
        total=total_count,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{invoice_id}",
    response_model=InvoiceDetailResponse,
    summary="Get full invoice investigation details and findings",
)
def get_invoice_detail(
    invoice_id: int,
    db: Session = Depends(get_db),
) -> InvoiceDetailResponse:
    """Retrieves full metadata, extracted/corrected field breakdown, and findings for an invoice."""
    inv = db.execute(
        select(Invoice)
        .options(selectinload(Invoice.findings))
        .where(Invoice.id == invoice_id)
    ).scalar_one_or_none()

    if inv is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Invoice with ID {invoice_id} not found.",
        )

    note, fields = _deserialize_field_metadata(inv.field_metadata_json)
    summary_data = _to_summary_response(inv).model_dump()
    return InvoiceDetailResponse(
        **summary_data,
        extraction_note=note,
        fields=fields,
        findings=_to_finding_responses(inv.findings),
    )
