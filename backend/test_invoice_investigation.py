"""
FraudTrace AI — Test Suite: Invoice Investigation Module
========================================================
Covers document upload security, file signature & Pillow/PyMuPDF validation,
field extraction, OCR-unavailable fallback, separated user corrections,
deterministic invoice investigation rules, persistence, API status codes,
and non-regression against existing transaction & ML systems.

ISOLATION:
Uses in-memory PDF/image byte fixtures and an isolated temporary SQLite database
file (`tempfile`), leaving `backend/data/fraudtrace.db` completely untouched.
"""

from __future__ import annotations

import io
import json
import sys
import tempfile
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path
from unittest.mock import patch

# Ensure `backend` directory is on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent))

import pymupdf
from fastapi import HTTPException
from PIL import Image
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import sessionmaker
from starlette.datastructures import UploadFile

from app.database import Base
from app.models import Invoice, InvoiceFinding, Transaction
from app.routes import invoices as invoice_routes
from app.routes import transactions as tx_routes
from app.schemas import TransactionAnalyzeRequest
from app.services import invoice_extractor as ext_mod
from app.services.invoice_analyzer import analyze_invoice
from app.services.invoice_extractor import (
    MAX_FILE_SIZE_BYTES,
    InvoiceValidationError,
    extract_invoice_document,
    read_bounded_upload_sync,
    sanitize_filename,
)


def _make_pdf_bytes(lines_per_page: list[list[str]], encrypt_password: str | None = None) -> bytes:
    """Builds an in-memory PDF using PyMuPDF without touching the filesystem."""
    doc = pymupdf.open()
    try:
        if not lines_per_page:
            # Blank page edge case
            doc.new_page()
        for page_lines in lines_per_page:
            page = doc.new_page()
            y = 72
            for line in page_lines:
                page.insert_text((72, y), line, fontsize=11)
                y += 18
        if encrypt_password:
            return doc.tobytes(
                encryption=pymupdf.PDF_ENCRYPT_AES_256,
                owner_pw=encrypt_password,
                user_pw=encrypt_password,
            )
        return doc.tobytes()
    finally:
        doc.close()


def _make_zero_page_pdf_stub() -> bytes:
    """Constructs a minimal syntactically valid PDF with 0 Pages (/Count 0 /Kids [])."""
    return (
        b"%PDF-1.4\n"
        b"1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
        b"2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n"
        b"xref\n0 3\n0000000000 65535 f \n"
        b"0000000009 00000 n \n"
        b"0000000058 00000 n \n"
        b"trailer\n<< /Size 3 /Root 1 0 R >>\n"
        b"startxref\n115\n%%EOF\n"
    )


def _make_image_bytes(fmt: str = "PNG", size: tuple[int, int] = (240, 120)) -> bytes:
    buf = io.BytesIO()
    img = Image.new("RGB", size, color=(240, 244, 250))
    img.save(buf, format=fmt)
    return buf.getvalue()


def _make_scanned_pdf_bytes() -> bytes:
    """Builds a 1-page PDF embedding a raster image with zero selectable text."""
    png_bytes = _make_image_bytes("PNG", size=(300, 160))
    doc = pymupdf.open()
    try:
        page = doc.new_page()
        rect = pymupdf.Rect(50, 50, 350, 210)
        page.insert_image(rect, stream=png_bytes)
        return doc.tobytes()
    finally:
        doc.close()


def _create_isolated_session():
    temp_handle = tempfile.NamedTemporaryFile(suffix="_test_inv_ft.db", delete=False)
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
    return engine, SessionLocal, temp_path


def _teardown_isolated_db(engine, temp_path: Path) -> None:
    Base.metadata.drop_all(bind=engine)
    engine.dispose()
    if temp_path.exists():
        temp_path.unlink()


# ---------------------------------------------------------------------------
# Document Validation & Extraction Tests
# ---------------------------------------------------------------------------

def test_1_valid_pdf_extraction_and_filename_sanitization() -> None:
    pdf_bytes = _make_pdf_bytes([
        [
            "Vendor: Acme Industrial Supplies Inc.",
            "Invoice Number: INV-2026-0042",
            "Invoice Date: 2026-10-15",
            "Due Date: 2026-11-15",
            "Currency: USD",
            "PO Number: PO-77891",
            "Subtotal: $1,000.00",
            "Tax: $82.50",
            "Total Amount: $1,082.50",
        ]
    ])
    result = extract_invoice_document(
        data=pdf_bytes,
        raw_filename=r"C:\evil\..\..\secret\acme_invoice#1.pdf",
    )

    assert result.original_filename == "acme_invoice_1.pdf"
    assert result.file_type == "PDF"
    assert result.page_count == 1
    assert result.extraction_status == "EXTRACTED"
    assert result.vendor_name == "Acme Industrial Supplies Inc."
    assert result.invoice_number == "INV-2026-0042"
    assert result.invoice_date == "2026-10-15"
    assert result.due_date == "2026-11-15"
    assert result.currency == "USD"
    assert result.po_number == "PO-77891"
    assert result.subtotal == Decimal("1000.00")
    assert result.tax == Decimal("82.50")
    assert result.total_amount == Decimal("1082.50")
    assert result.fields["vendor_name"].extraction_status == "EXTRACTED"
    assert result.fields["vendor_name"].extracted_value == "Acme Industrial Supplies Inc."


def test_2_security_upload_validation_and_limits() -> None:
    # Filename traversal sanitization
    assert sanitize_filename("../../etc/passwd\x00.pdf") == "passwd.pdf"

    # Empty upload -> 400
    empty_upload = UploadFile(file=io.BytesIO(b""), filename="empty.pdf")
    try:
        read_bounded_upload_sync(empty_upload)
        raise AssertionError("Expected 400 for empty upload")
    except InvoiceValidationError as exc:
        assert exc.status_code == 400

    # Oversized upload -> stops at > max_bytes with 413
    oversized_upload = UploadFile(file=io.BytesIO(b"A" * (MAX_FILE_SIZE_BYTES + 128)), filename="big.pdf")
    try:
        read_bounded_upload_sync(oversized_upload)
        raise AssertionError("Expected 413 for oversized upload")
    except InvoiceValidationError as exc:
        assert exc.status_code == 413

    # Invalid file signature disguised as .pdf -> 415
    try:
        extract_invoice_document(data=b"MZ-not-a-pdf-secret-bytes", raw_filename="fake.pdf")
        raise AssertionError("Expected 415 for spoofed PDF signature")
    except InvoiceValidationError as exc:
        assert exc.status_code == 415
        assert "MZ-not-a-pdf" not in exc.detail

    # Unsupported extension/type -> 415
    try:
        extract_invoice_document(data=b"plain text note", raw_filename="notes.txt")
        raise AssertionError("Expected 415 for .txt upload")
    except InvoiceValidationError as exc:
        assert exc.status_code == 415

    # Malformed PDF -> 422
    try:
        extract_invoice_document(data=b"%PDF-1.7\ncompletely_corrupted_stream", raw_filename="broken.pdf")
        raise AssertionError("Expected 422 for malformed PDF")
    except InvoiceValidationError as exc:
        assert exc.status_code == 422

    # Encrypted PDF -> 422
    encrypted_pdf = _make_pdf_bytes([["Vendor: Secret Co", "Total: $10.00"]], encrypt_password="pw123")
    try:
        extract_invoice_document(data=encrypted_pdf, raw_filename="encrypted.pdf")
        raise AssertionError("Expected 422 for encrypted PDF")
    except InvoiceValidationError as exc:
        assert exc.status_code == 422
        assert "Encrypted" in exc.detail

    # > 5 pages PDF -> 422
    six_page_pdf = _make_pdf_bytes([[f"Page {i} text line"] for i in range(1, 7)])
    try:
        extract_invoice_document(data=six_page_pdf, raw_filename="six_pages.pdf")
        raise AssertionError("Expected 422 for 6-page PDF")
    except InvoiceValidationError as exc:
        assert exc.status_code == 422
        assert "6 pages" in exc.detail

    # Zero-page PDF -> 422
    try:
        extract_invoice_document(data=_make_zero_page_pdf_stub(), raw_filename="zero.pdf")
        raise AssertionError("Expected 422 for zero-page PDF")
    except InvoiceValidationError as exc:
        assert exc.status_code == 422

    # Valid PNG / JPEG signatures pass structural validation and report OCR availability honestly
    with patch.object(ext_mod, "detect_tesseract_availability", return_value=(False, None)):
        png_res = extract_invoice_document(data=_make_image_bytes("PNG"), raw_filename="scan.png")
        jpg_res = extract_invoice_document(data=_make_image_bytes("JPEG"), raw_filename="scan.jpg")
        scanned_pdf_res = extract_invoice_document(data=_make_scanned_pdf_bytes(), raw_filename="scanned.pdf")

    for res in (png_res, jpg_res, scanned_pdf_res):
        assert res.ocr_available is False
        assert res.extraction_status == "OCR_UNAVAILABLE"
        assert res.vendor_name is None
        assert res.total_amount is None
        assert res.fields["vendor_name"].extraction_status == "OCR_UNAVAILABLE"

    # Image dimension/pixel limit rejection -> 422
    with patch.object(ext_mod, "MAX_IMAGE_DIMENSION", 100):
        try:
            extract_invoice_document(data=_make_image_bytes("PNG", size=(200, 50)), raw_filename="wide.png")
            raise AssertionError("Expected 422 for oversized image dimensions")
        except InvoiceValidationError as exc:
            assert exc.status_code == 422

    # Truncated/corrupt PNG signature -> 422
    try:
        extract_invoice_document(data=b"\x89PNG\r\n\x1a\nCORRUPT_DATA", raw_filename="bad.png")
        raise AssertionError("Expected 422 for truncated PNG")
    except InvoiceValidationError as exc:
        assert exc.status_code == 422


def test_3_missing_fields_and_separated_user_corrections() -> None:
    pdf_bytes = _make_pdf_bytes([
        [
            "Vendor: Northwind Traders",
            "Notes: Partial memo without invoice number, date, or amounts.",
        ]
    ])
    # Without corrections -> missing fields remain None (never fabricated)
    res_raw = extract_invoice_document(data=pdf_bytes, raw_filename="partial.pdf")
    assert res_raw.extraction_status == "PARTIAL_EXTRACTION"
    assert res_raw.vendor_name == "Northwind Traders"
    assert res_raw.invoice_number is None
    assert res_raw.total_amount is None
    assert res_raw.fields["invoice_number"].extraction_status == "MISSING"

    # With user corrections -> original extracted value preserved cleanly alongside corrected value
    res_corr = extract_invoice_document(
        data=pdf_bytes,
        raw_filename="partial.pdf",
        corrections={"invoice_number": "NW-901", "total_amount": "250.00"},
    )
    assert res_corr.fields["invoice_number"].extracted_value is None
    assert res_corr.fields["invoice_number"].corrected_value == "NW-901"
    assert res_corr.fields["invoice_number"].effective_value == "NW-901"
    assert res_corr.fields["invoice_number"].extraction_status == "USER_CORRECTED"
    assert res_corr.total_amount == Decimal("250.00")


# ---------------------------------------------------------------------------
# Deterministic Invoice Analysis Rules Tests
# ---------------------------------------------------------------------------

def test_4_invoice_analysis_rules_and_edge_cases() -> None:
    engine, SessionLocal, temp_path = _create_isolated_session()
    ref_today = date(2026, 11, 11)

    try:
        with SessionLocal() as db:
            # A. Clean invoice with rounding tolerance (100.00 + 8.00 = 108.00 vs 108.02 -> 0.02 passes)
            clean_pdf = _make_pdf_bytes([
                [
                    "Vendor: Acme Supplies Ltd.",
                    "Invoice Number: INV-1001",
                    "Invoice Date: 2026-10-10",
                    "Due Date: 2026-11-10",
                    "Currency: USD",
                    "Subtotal: $100.00",
                    "Tax: $8.00",
                    "Total Amount: $108.02",
                ]
            ])
            clean_ext = extract_invoice_document(data=clean_pdf, raw_filename="acme_clean.pdf")
            clean_out = analyze_invoice(clean_ext, db, reference_today=ref_today)
            assert clean_out.investigation_status == "NO_FINDINGS"
            assert clean_out.findings == []

            db.add(
                Invoice(
                    original_filename=clean_ext.original_filename,
                    file_type=clean_ext.file_type,
                    file_size_bytes=clean_ext.file_size_bytes,
                    page_count=clean_ext.page_count,
                    ocr_available=clean_ext.ocr_available,
                    vendor_name=clean_ext.vendor_name,
                    normalized_vendor_name=clean_out.normalized_vendor_name,
                    invoice_number=clean_ext.invoice_number,
                    normalized_invoice_number=clean_out.normalized_invoice_number,
                    invoice_date=clean_ext.invoice_date,
                    due_date=clean_ext.due_date,
                    currency=clean_ext.currency,
                    subtotal=clean_ext.subtotal,
                    tax=clean_ext.tax,
                    total_amount=clean_ext.total_amount,
                    extraction_status=clean_ext.extraction_status,
                    investigation_status=clean_out.investigation_status,
                    summary=clean_out.summary,
                )
            )
            db.commit()

            # B. Duplicate normalized vendor + invoice number ("acme supplies ltd" + "inv 1001")
            dup_pdf = _make_pdf_bytes([
                [
                    "Vendor:  ACME  Supplies   Ltd ",
                    "Invoice Number: inv 1001",
                    "Invoice Date: 2026-10-11",
                    "Due Date: 2026-11-10",
                    "Currency: USD",
                    "Subtotal: $100.00",
                    "Tax: $8.00",
                    "Total Amount: $108.00",
                ]
            ])
            dup_ext = extract_invoice_document(data=dup_pdf, raw_filename="acme_dup.pdf")
            dup_out = analyze_invoice(dup_ext, db, reference_today=ref_today)
            assert dup_out.investigation_status == "NEEDS_REVIEW"
            assert any(f.finding_code == "DUPLICATE_INVOICE" and f.severity == "HIGH" for f in dup_out.findings)

            # C. Same invoice number INV-1001 from a DIFFERENT vendor must NOT flag DUPLICATE_INVOICE
            other_vendor_pdf = _make_pdf_bytes([
                [
                    "Vendor: Globex Logistics Group",
                    "Invoice Number: INV-1001",
                    "Invoice Date: 2026-10-12",
                    "Due Date: 2026-11-10",
                    "Currency: EUR",
                    "Subtotal: EUR 200.00",
                    "Tax: EUR 20.00",
                    "Total Amount: EUR 220.00",
                ]
            ])
            other_ext = extract_invoice_document(data=other_vendor_pdf, raw_filename="globex.pdf")
            other_out = analyze_invoice(other_ext, db, reference_today=ref_today)
            assert not any(f.finding_code == "DUPLICATE_INVOICE" for f in other_out.findings)
            assert other_out.investigation_status == "NO_FINDINGS"

            # D. Arithmetic mismatch (> 0.02), due date before invoice date, future warning, invalid date
            mismatch_pdf = _make_pdf_bytes([
                [
                    "Vendor: Delta Cloud Inc",
                    "Invoice Number: D-500",
                    "Invoice Date: 2026-11-25",
                    "Due Date: 2026-11-01",
                    "Subtotal: $100.00",
                    "Tax: $8.00",
                    "Total Amount: $108.50",
                ]
            ])
            mis_ext = extract_invoice_document(data=mismatch_pdf, raw_filename="mismatch.pdf")
            mis_out = analyze_invoice(mis_ext, db, reference_today=ref_today)
            codes = {f.finding_code for f in mis_out.findings}
            assert "ARITHMETIC_MISMATCH" in codes
            assert "DUE_BEFORE_INVOICE_DATE" in codes
            assert "FUTURE_INVOICE_DATE" in codes
            future_item = next(f for f in mis_out.findings if f.finding_code == "FUTURE_INVOICE_DATE")
            assert future_item.severity == "MEDIUM"
            assert "does not confirm fraud" in future_item.explanation

            # Invalid date string check
            bad_date_pdf = _make_pdf_bytes([
                [
                    "Vendor: Horizon Corp",
                    "Invoice Number: H-12",
                    "Invoice Date: 2026-13-45",
                    "Total Amount: $90.00",
                ]
            ])
            bad_date_ext = extract_invoice_document(data=bad_date_pdf, raw_filename="baddate.pdf")
            bad_date_out = analyze_invoice(bad_date_ext, db, reference_today=ref_today)
            assert any(f.finding_code == "INVALID_DATE" for f in bad_date_out.findings)

            # Missing critical fields check (without treating missing subtotal/tax as arithmetic mismatch)
            missing_pdf = _make_pdf_bytes([
                [
                    "Vendor: Stark Consulting",
                    "Memo: Retainer inquiry without invoice number, date, or total.",
                ]
            ])
            miss_ext = extract_invoice_document(data=missing_pdf, raw_filename="missing.pdf")
            miss_out = analyze_invoice(miss_ext, db, reference_today=ref_today)
            miss_codes = {f.finding_code for f in miss_out.findings}
            assert "MISSING_CRITICAL_FIELDS" in miss_codes
            assert "ARITHMETIC_MISMATCH" not in miss_codes

            # Poor extraction / OCR unavailable never returns NO_FINDINGS
            with patch.object(ext_mod, "detect_tesseract_availability", return_value=(False, None)):
                img_ext = extract_invoice_document(data=_make_image_bytes("PNG"), raw_filename="receipt.png")
            img_out = analyze_invoice(img_ext, db, reference_today=ref_today)
            assert img_out.investigation_status == "INCOMPLETE_EXTRACTION"
            assert any(f.finding_code == "EXTRACTION_QUALITY" for f in img_out.findings)
    finally:
        _teardown_isolated_db(engine, temp_path)


# ---------------------------------------------------------------------------
# Persistence, API Routes & Non-Regression Tests
# ---------------------------------------------------------------------------

def test_5_api_persistence_history_detail_errors_and_non_regression() -> None:
    engine, SessionLocal, temp_path = _create_isolated_session()

    try:
        with SessionLocal() as db:
            # 1. Seed a baseline transaction and ensure transaction scoring + ML still work identically
            txn_resp = tx_routes.analyze_transaction(
                TransactionAnalyzeRequest(
                    reference="INV-TEST-TX-001",
                    sender_id="SENDER_A",
                    receiver_id="RECEIVER_B",
                    amount=Decimal("250.00"),
                    currency="USD",
                ),
                db=db,
            )
            assert txn_resp.risk_score == 10.0  # NEW_RECIPIENT
            assert txn_resp.ml_anomaly is not None
            assert txn_resp.ml_anomaly.status == "UNAVAILABLE"

            # 2. Valid text PDF upload -> persisted + findings + detail + history
            pdf_one = _make_pdf_bytes([
                [
                    "Vendor: Summit Electronics",
                    "Invoice Number: SM-2026-01",
                    "Invoice Date: 2026-10-01",
                    "Due Date: 2026-10-31",
                    "Currency: USD",
                    "PO Number: PO-100",
                    "Subtotal: $500.00",
                    "Tax: $50.00",
                    "Total Amount: $550.00",
                ]
            ])
            uf1 = UploadFile(file=io.BytesIO(pdf_one), filename="summit_01.pdf")
            res1 = invoice_routes.analyze_invoice_upload(
                file=uf1,
                submission_reference="SUB-REF-001",
                db=db,
            )
            assert res1.invoice.id > 0
            assert res1.invoice.investigation_status == "NO_FINDINGS"
            assert res1.invoice.total_amount == Decimal("550.00")
            assert res1.findings == []

            # Duplicate submission_reference -> 409 Conflict
            uf_dup_ref = UploadFile(file=io.BytesIO(pdf_one), filename="summit_retry.pdf")
            try:
                invoice_routes.analyze_invoice_upload(
                    file=uf_dup_ref,
                    submission_reference="SUB-REF-001",
                    db=db,
                )
                raise AssertionError("Expected 409 for duplicate submission_reference")
            except HTTPException as exc:
                assert exc.status_code == 409

            # Duplicate vendor+invoice upload with reject_duplicates=True -> 409 Conflict
            uf_strict_dup = UploadFile(file=io.BytesIO(pdf_one), filename="summit_dup.pdf")
            try:
                invoice_routes.analyze_invoice_upload(
                    file=uf_strict_dup,
                    reject_duplicates=True,
                    db=db,
                )
                raise AssertionError("Expected 409 when reject_duplicates=True")
            except HTTPException as exc:
                assert exc.status_code == 409

            # Re-upload without reject_duplicates -> persisted & flagged DUPLICATE_INVOICE
            uf2 = UploadFile(file=io.BytesIO(pdf_one), filename="summit_rebill.pdf")
            res2 = invoice_routes.analyze_invoice_upload(file=uf2, db=db)
            assert res2.invoice.investigation_status == "NEEDS_REVIEW"
            assert any(f.finding_code == "DUPLICATE_INVOICE" for f in res2.findings)

            # History retrieval
            history = invoice_routes.list_invoices(limit=20, offset=0, db=db)
            assert history.total == 2
            assert len(history.items) == 2

            # Detail retrieval
            detail = invoice_routes.get_invoice_detail(res2.invoice.id, db=db)
            assert detail.id == res2.invoice.id
            assert len(detail.findings) == 1
            assert any(f.field_name == "vendor_name" and f.effective_value == "Summit Electronics" for f in detail.fields)

            # 404 detail check
            try:
                invoice_routes.get_invoice_detail(999999, db=db)
                raise AssertionError("Expected 404 for nonexistent invoice id")
            except HTTPException as exc:
                assert exc.status_code == 404

            # Bad corrections_json -> 400
            uf_bad_corr = UploadFile(file=io.BytesIO(pdf_one), filename="bad_corr.pdf")
            try:
                invoice_routes.analyze_invoice_upload(
                    file=uf_bad_corr,
                    corrections_json="{not-valid-json",
                    db=db,
                )
                raise AssertionError("Expected 400 for malformed corrections_json")
            except HTTPException as exc:
                assert exc.status_code == 400

            # Graceful unexpected extractor crash -> safe 422 with zero leak
            uf_crash = UploadFile(file=io.BytesIO(pdf_one), filename="crash.pdf")
            with patch.object(invoice_routes, "extract_invoice_document", side_effect=RuntimeError("/secret/internal/path secret_text")):
                try:
                    invoice_routes.analyze_invoice_upload(file=uf_crash, db=db)
                    raise AssertionError("Expected safe 422 on extractor exception")
                except HTTPException as exc:
                    assert exc.status_code == 422
                    assert "/secret/internal/path" not in str(exc.detail)
                    assert "secret_text" not in str(exc.detail)

            # Cascade deletion removes InvoiceFinding children automatically
            inv_to_del = db.execute(select(Invoice).where(Invoice.id == res2.invoice.id)).scalar_one()
            db.delete(inv_to_del)
            db.commit()
            remaining_findings = db.execute(
                select(InvoiceFinding).where(InvoiceFinding.invoice_id == res2.invoice.id)
            ).scalars().all()
            assert remaining_findings == []

            # Transaction records remained completely untouched by invoice workflows
            tx_check = db.execute(select(Transaction).where(Transaction.id == txn_resp.transaction.id)).scalar_one()
            assert tx_check.risk_score == 10.0
    finally:
        _teardown_isolated_db(engine, temp_path)


def run_all_tests() -> None:
    tests = [
        test_1_valid_pdf_extraction_and_filename_sanitization,
        test_2_security_upload_validation_and_limits,
        test_3_missing_fields_and_separated_user_corrections,
        test_4_invoice_analysis_rules_and_edge_cases,
        test_5_api_persistence_history_detail_errors_and_non_regression,
    ]
    print("Running FraudTrace AI Invoice Investigation Test Suite...")
    for fn in tests:
        fn()
        print(f"  [PASS] {fn.__name__}")
    print(f"All {len(tests)} invoice investigation test groups passed.")


if __name__ == "__main__":
    run_all_tests()
