"""
FraudTrace AI — Deterministic Invoice Investigation Engine
==========================================================
Evaluates extracted (and optionally user-corrected) invoice metadata against
transparent, deterministic rules:

1. Duplicate invoice detection (normalized vendor_name + normalized invoice_number)
2. Missing critical fields (vendor_name, invoice_number, invoice_date, total_amount)
3. Arithmetic consistency (Decimal subtotal + tax ≈ total_amount within 0.02)
4. Date validation (invalid dates, due_date < invoice_date, future invoice_date warning)
5. Extraction quality (OCR_UNAVAILABLE, UNREADABLE, low/incomplete text)

Integrity & Responsible Use:
- Never invents fraud probabilities or ML confidence scores.
- Never declares confirmed fraud solely from rule warnings.
- Keeps clean extraction failures clearly separate from clean passes.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from decimal import Decimal
from typing import Any, Optional

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.models import Invoice
from app.services.invoice_extractor import InvoiceExtractionResult

ARITHMETIC_TOLERANCE = Decimal("0.02")


@dataclass
class InvoiceFindingItem:
    """Structured deterministic finding produced during invoice review."""

    finding_code: str
    severity: str  # LOW | MEDIUM | HIGH
    explanation: str
    supporting_values: dict[str, Any] = field(default_factory=dict)


@dataclass
class InvoiceAnalysisOutcome:
    """Complete deterministic assessment outcome ready for persistence & API serialization."""

    normalized_vendor_name: Optional[str]
    normalized_invoice_number: Optional[str]
    investigation_status: str  # NO_FINDINGS | NEEDS_REVIEW | INCOMPLETE_EXTRACTION
    summary: str
    findings: list[InvoiceFindingItem] = field(default_factory=list)


def normalize_vendor_name(vendor_name: Optional[str]) -> Optional[str]:
    """Normalizes vendor/supplier names consistently for duplicate matching."""
    if not vendor_name:
        return None
    cleaned = re.sub(r"[^a-z0-9]+", " ", vendor_name.strip().lower()).strip()
    return cleaned or None


def normalize_invoice_number(invoice_number: Optional[str]) -> Optional[str]:
    """Normalizes invoice numbers consistently across spacing and punctuation variants."""
    if not invoice_number:
        return None
    cleaned = re.sub(r"[^A-Z0-9]+", "", invoice_number.strip().upper())
    return cleaned or None


def _parse_iso_calendar_date(raw_date: Optional[str]) -> tuple[Optional[date], bool]:
    """
    Parses canonical ISO YYYY-MM-DD (or strict YYYY/MM/DD) date string.
    Returns (parsed_date, is_present_and_invalid).
    """
    if not raw_date:
        return None, False
    clean = raw_date.strip()
    if not clean:
        return None, False

    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y", "%d-%m-%Y", "%m-%d-%Y"):
        try:
            return datetime.strptime(clean, fmt).date(), False
        except ValueError:
            continue
    return None, True


def analyze_invoice(
    extraction: InvoiceExtractionResult,
    db: Session,
    *,
    exclude_invoice_id: Optional[int] = None,
    reference_today: Optional[date] = None,
) -> InvoiceAnalysisOutcome:
    """
    Runs deterministic invoice rules without inventing missing numbers or altering
    transaction/ML state.
    """
    today_utc = reference_today or datetime.now(timezone.utc).date()
    norm_vendor = normalize_vendor_name(extraction.vendor_name)
    norm_inv_num = normalize_invoice_number(extraction.invoice_number)

    findings: list[InvoiceFindingItem] = []

    # Rule 5 first for visibility: Extraction quality / OCR availability
    if extraction.extraction_status == "OCR_UNAVAILABLE":
        findings.append(
            InvoiceFindingItem(
                finding_code="EXTRACTION_QUALITY",
                severity="MEDIUM",
                explanation=(
                    f"{extraction.extraction_note} Document review cannot rely on automated "
                    "text extraction from scanned images or image-only PDFs until OCR is available."
                ),
                supporting_values={
                    "extraction_status": extraction.extraction_status,
                    "ocr_available": extraction.ocr_available,
                    "file_type": extraction.file_type,
                    "extracted_text_length": extraction.extracted_text_length,
                },
            )
        )
    elif extraction.extraction_status == "UNREADABLE":
        findings.append(
            InvoiceFindingItem(
                finding_code="EXTRACTION_QUALITY",
                severity="HIGH",
                explanation=(
                    f"{extraction.extraction_note} Automated text extraction yielded insufficient "
                    "readable content for reliable verification."
                ),
                supporting_values={
                    "extraction_status": extraction.extraction_status,
                    "extracted_text_length": extraction.extracted_text_length,
                    "file_type": extraction.file_type,
                },
            )
        )
    elif extraction.extraction_status == "PARTIAL_EXTRACTION":
        findings.append(
            InvoiceFindingItem(
                finding_code="EXTRACTION_QUALITY",
                severity="LOW",
                explanation=(
                    "Only partial invoice fields were matched automatically from document text. "
                    "Verify extracted fields against the source invoice."
                ),
                supporting_values={
                    "extraction_status": extraction.extraction_status,
                    "extracted_text_length": extraction.extracted_text_length,
                    "file_type": extraction.file_type,
                },
            )
        )

    # Rule 1: Duplicate invoice detection (normalized vendor AND normalized invoice number)
    if norm_vendor and norm_inv_num:
        dup_query = select(Invoice).where(
            Invoice.normalized_vendor_name == norm_vendor,
            Invoice.normalized_invoice_number == norm_inv_num,
        )
        if exclude_invoice_id is not None:
            dup_query = dup_query.where(Invoice.id != exclude_invoice_id)

        matching_invoices = db.execute(dup_query.order_by(Invoice.id.asc())).scalars().all()
        if matching_invoices:
            matching_ids = [inv.id for inv in matching_invoices]
            matching_files = [inv.original_filename for inv in matching_invoices]
            findings.append(
                InvoiceFindingItem(
                    finding_code="DUPLICATE_INVOICE",
                    severity="HIGH",
                    explanation=(
                        f"Invoice number '{extraction.invoice_number}' for vendor '{extraction.vendor_name}' "
                        f"matches {len(matching_invoices)} prior persisted invoice record(s). "
                        "This warrants duplicate-billing verification and does not independently confirm fraud."
                    ),
                    supporting_values={
                        "vendor_name": extraction.vendor_name,
                        "normalized_vendor_name": norm_vendor,
                        "invoice_number": extraction.invoice_number,
                        "normalized_invoice_number": norm_inv_num,
                        "matching_invoice_ids": matching_ids,
                        "matching_filenames": matching_files,
                    },
                )
            )

    # Rule 2: Missing critical fields
    missing_fields: list[str] = []
    if not extraction.vendor_name:
        missing_fields.append("vendor_name")
    if not extraction.invoice_number:
        missing_fields.append("invoice_number")
    if not extraction.invoice_date:
        missing_fields.append("invoice_date")
    if extraction.total_amount is None:
        missing_fields.append("total_amount")

    if missing_fields:
        findings.append(
            InvoiceFindingItem(
                finding_code="MISSING_CRITICAL_FIELDS",
                severity="MEDIUM" if len(missing_fields) < 4 else "HIGH",
                explanation=(
                    "Critical invoice metadata could not be verified because the following field(s) "
                    f"are missing: {', '.join(missing_fields)}."
                ),
                supporting_values={
                    "missing_fields": missing_fields,
                    "extraction_status": extraction.extraction_status,
                },
            )
        )

    # Rule 3: Arithmetic consistency (Decimal subtotal + tax ≈ total_amount within 0.02)
    if (
        extraction.subtotal is not None
        and extraction.tax is not None
        and extraction.total_amount is not None
    ):
        computed_total = (extraction.subtotal + extraction.tax).quantize(Decimal("0.01"))
        recorded_total = extraction.total_amount.quantize(Decimal("0.01"))
        difference = abs(computed_total - recorded_total)
        if difference > ARITHMETIC_TOLERANCE:
            findings.append(
                InvoiceFindingItem(
                    finding_code="ARITHMETIC_MISMATCH",
                    severity="HIGH",
                    explanation=(
                        f"Extracted/submitted subtotal ({extraction.subtotal:.2f}) plus tax "
                        f"({extraction.tax:.2f}) equals {computed_total:.2f}, which differs from "
                        f"total amount ({recorded_total:.2f}) by {difference:.2f} (tolerance {ARITHMETIC_TOLERANCE:.2f})."
                    ),
                    supporting_values={
                        "subtotal": str(extraction.subtotal),
                        "tax": str(extraction.tax),
                        "computed_total": str(computed_total),
                        "total_amount": str(recorded_total),
                        "difference": str(difference),
                        "tolerance": str(ARITHMETIC_TOLERANCE),
                    },
                )
            )

    # Rule 4: Date validation (invalid format, due_date < invoice_date, future invoice_date warning)
    parsed_inv_date, inv_date_invalid = _parse_iso_calendar_date(extraction.invoice_date)
    parsed_due_date, due_date_invalid = _parse_iso_calendar_date(extraction.due_date)

    if inv_date_invalid:
        findings.append(
            InvoiceFindingItem(
                finding_code="INVALID_DATE",
                severity="HIGH",
                explanation=(
                    f"Invoice date value '{extraction.invoice_date}' is not a valid calendar date."
                ),
                supporting_values={"field": "invoice_date", "raw_value": extraction.invoice_date},
            )
        )

    if due_date_invalid:
        findings.append(
            InvoiceFindingItem(
                finding_code="INVALID_DATE",
                severity="MEDIUM",
                explanation=(
                    f"Due date value '{extraction.due_date}' is not a valid calendar date."
                ),
                supporting_values={"field": "due_date", "raw_value": extraction.due_date},
            )
        )

    if parsed_inv_date is not None and parsed_due_date is not None:
        if parsed_due_date < parsed_inv_date:
            findings.append(
                InvoiceFindingItem(
                    finding_code="DUE_BEFORE_INVOICE_DATE",
                    severity="HIGH",
                    explanation=(
                        f"Payment due date ({parsed_due_date.isoformat()}) precedes the invoice date "
                        f"({parsed_inv_date.isoformat()})."
                    ),
                    supporting_values={
                        "invoice_date": parsed_inv_date.isoformat(),
                        "due_date": parsed_due_date.isoformat(),
                    },
                )
            )

    if parsed_inv_date is not None and parsed_inv_date > today_utc:
        findings.append(
            InvoiceFindingItem(
                finding_code="FUTURE_INVOICE_DATE",
                severity="MEDIUM",
                explanation=(
                    f"Invoice date ({parsed_inv_date.isoformat()}) is in the future relative to UTC date "
                    f"{today_utc.isoformat()}. Verify whether pre-billing applies; this warning alone does "
                    "not confirm fraud."
                ),
                supporting_values={
                    "invoice_date": parsed_inv_date.isoformat(),
                    "reference_date": today_utc.isoformat(),
                },
            )
        )

    # Determine honest overall status (never mark incomplete/failed extraction clean)
    extraction_unsuccessful = extraction.extraction_status in {
        "OCR_UNAVAILABLE",
        "UNREADABLE",
        "EXTRACTION_FAILED",
    }

    if extraction_unsuccessful:
        investigation_status = "INCOMPLETE_EXTRACTION"
        summary = (
            f"Extraction incomplete ({extraction.extraction_status}) for '{extraction.original_filename}'. "
            f"Generated {len(findings)} review finding(s); automated completeness could not be verified."
        )
    elif findings:
        investigation_status = "NEEDS_REVIEW"
        codes = ", ".join(item.finding_code for item in findings)
        summary = (
            f"Deterministic checks flagged {len(findings)} finding(s) requiring human review ({codes}). "
            "Rule findings assist verification and do not independently establish fraud."
        )
    else:
        investigation_status = "NO_FINDINGS"
        summary = (
            f"All deterministic checks completed on extracted/verified fields for '{extraction.original_filename}' "
            "with no rule findings detected."
        )

    return InvoiceAnalysisOutcome(
        normalized_vendor_name=norm_vendor,
        normalized_invoice_number=norm_inv_num,
        investigation_status=investigation_status,
        summary=summary,
        findings=findings,
    )
