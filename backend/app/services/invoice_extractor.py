"""
FraudTrace AI — Secure Invoice Upload Validation & Extraction Service
======================================================================
Handles security-hardened document ingestion and structured field extraction
for PDF, PNG, and JPEG invoice uploads without executing uploaded content or
permanently storing original document bytes.

Security & Integrity Controls:
- Bounded streaming read capped strictly at 10 MB (returns HTTP 413 cleanly).
- Magic-byte file signature verification (never trusts extensions or MIME alone).
- PDF validation via PyMuPDF: rejects malformed, encrypted, 0-page, or > 5-page PDFs.
- Image validation via Pillow: Image.verify(), load(), and pixel bounds against
  decompression-bomb attacks.
- Dynamic Tesseract OCR binary detection: never claims OCR works when the
  executable is absent; honestly reports OCR_UNAVAILABLE for scanned/image files.
- Never fabricates missing fields; separates extracted values from optional user
  corrections cleanly.
"""

from __future__ import annotations

import io
import os
import re
import shutil
import subprocess
import warnings
from dataclasses import dataclass, field
from datetime import datetime
from decimal import Decimal, InvalidOperation
from pathlib import PurePosixPath
from typing import Any, Optional

from fastapi import UploadFile

try:
    import pymupdf

    _PYMUPDF_AVAILABLE = True
except Exception:  # pragma: no cover - defensive fallback
    pymupdf = None  # type: ignore[assignment]
    _PYMUPDF_AVAILABLE = False

try:
    from PIL import Image, UnidentifiedImageError

    _PIL_AVAILABLE = True
except Exception:  # pragma: no cover - defensive fallback
    Image = None  # type: ignore[assignment]
    UnidentifiedImageError = Exception  # type: ignore[assignment,misc]
    _PIL_AVAILABLE = False

try:
    import pytesseract

    _PYTESSERACT_AVAILABLE = True
except Exception:  # pragma: no cover - defensive fallback
    pytesseract = None  # type: ignore[assignment]
    _PYTESSERACT_AVAILABLE = False

MAX_FILE_SIZE_BYTES = 10 * 1024 * 1024  # 10 MB
MAX_PDF_PAGES = 5
MAX_IMAGE_DIMENSION = 10_000
MAX_IMAGE_PIXELS = 25_000_000
MIN_READABLE_TEXT_CHARS = 25

ALLOWED_EXTENSIONS = {".pdf", ".png", ".jpg", ".jpeg"}
INVOICE_FIELD_NAMES = (
    "vendor_name",
    "invoice_number",
    "invoice_date",
    "due_date",
    "currency",
    "subtotal",
    "tax",
    "total_amount",
    "po_number",
)

CRITICAL_FIELDS = ("vendor_name", "invoice_number", "invoice_date", "total_amount")

CURRENCY_SYMBOLS = {
    "$": "USD",
    "€": "EUR",
    "£": "GBP",
    "₹": "INR",
}

KNOWN_CURRENCY_CODES = (
    "USD",
    "EUR",
    "GBP",
    "INR",
    "CAD",
    "AUD",
    "JPY",
    "CHF",
    "SGD",
)


class InvoiceValidationError(Exception):
    """Typed security/validation error mapped safely to HTTP responses without exposing raw content."""

    def __init__(self, status_code: int, detail: str) -> None:
        super().__init__(detail)
        self.status_code = status_code
        self.detail = detail


@dataclass
class ExtractedFieldInfo:
    """Tracks raw extracted value vs. optional user correction cleanly."""

    field_name: str
    extracted_value: Optional[str] = None
    corrected_value: Optional[str] = None
    effective_value: Optional[str] = None
    extraction_status: str = "MISSING"  # EXTRACTED | MISSING | OCR_UNAVAILABLE | USER_CORRECTED
    confidence: str = "NONE"  # HIGH | MEDIUM | NONE | USER_PROVIDED


@dataclass
class InvoiceExtractionResult:
    """Complete sanitized document validation & structured extraction outcome."""

    original_filename: str
    file_type: str  # PDF | PNG | JPEG
    file_size_bytes: int
    page_count: Optional[int]
    ocr_available: bool
    extraction_status: str  # EXTRACTED | PARTIAL_EXTRACTION | OCR_UNAVAILABLE | UNREADABLE
    extraction_note: str
    extracted_text_length: int
    fields: dict[str, ExtractedFieldInfo] = field(default_factory=dict)

    # Convenience accessors for effective values (never exposing raw document text)
    vendor_name: Optional[str] = None
    invoice_number: Optional[str] = None
    invoice_date: Optional[str] = None
    due_date: Optional[str] = None
    currency: Optional[str] = None
    subtotal: Optional[Decimal] = None
    tax: Optional[Decimal] = None
    total_amount: Optional[Decimal] = None
    po_number: Optional[str] = None


def sanitize_filename(raw_filename: Optional[str]) -> str:
    """
    Produces a safe display filename stripped of directory traversal segments,
    control characters, and unsafe filesystem characters. Never used as a path.
    """
    if not raw_filename:
        return "uploaded_invoice"

    # Strip Windows and POSIX directory components
    normalized = raw_filename.replace("\\", "/")
    base = PurePosixPath(normalized).name
    # Strip control characters and unsafe symbols
    cleaned = re.sub(r"[\x00-\x1f\x7f]", "", base)
    cleaned = re.sub(r"[^A-Za-z0-9._ -]", "_", cleaned).strip()
    cleaned = cleaned.lstrip(".")
    cleaned = re.sub(r"\s+", " ", cleaned)
    if not cleaned:
        return "uploaded_invoice"
    return cleaned[:120]


def _append_bounded_chunk(chunks: bytearray, chunk: bytes, max_bytes: int) -> None:
    if len(chunks) + len(chunk) > max_bytes:
        raise InvoiceValidationError(
            status_code=413,
            detail=f"Uploaded file exceeds the maximum allowed size of {max_bytes // (1024 * 1024)} MB.",
        )
    chunks.extend(chunk)


def _finalize_bounded_bytes(chunks: bytearray) -> bytes:
    if len(chunks) == 0:
        raise InvoiceValidationError(
            status_code=400,
            detail="Uploaded file is empty.",
        )
    return bytes(chunks)


def read_bounded_upload_sync(
    upload_file: UploadFile,
    max_bytes: int = MAX_FILE_SIZE_BYTES,
) -> bytes:
    """
    Synchronously streams an uploaded file in 64 KB chunks and aborts immediately
    once `max_bytes` is exceeded so oversized payloads cannot exhaust memory.
    """
    chunks = bytearray()
    chunk_size = 65_536
    file_obj = upload_file.file

    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        _append_bounded_chunk(chunks, chunk, max_bytes)

    return _finalize_bounded_bytes(chunks)


async def read_bounded_upload(
    upload_file: UploadFile,
    max_bytes: int = MAX_FILE_SIZE_BYTES,
) -> bytes:
    """
    Asynchronously streams an uploaded file in chunks and aborts immediately once
    `max_bytes` is exceeded so oversized payloads cannot exhaust memory.
    """
    chunks = bytearray()
    chunk_size = 65_536

    while True:
        chunk = await upload_file.read(chunk_size)
        if not chunk:
            break
        _append_bounded_chunk(chunks, chunk, max_bytes)

    return _finalize_bounded_bytes(chunks)


def detect_file_type_by_signature(
    data: bytes,
    sanitized_filename: str,
) -> str:
    """
    Detects file type via magic-byte signatures rather than extension or Content-Type.
    Also rejects conflicting disallowed extensions cleanly.
    """
    if not data:
        raise InvoiceValidationError(status_code=400, detail="Uploaded file is empty.")

    ext = os.path.splitext(sanitized_filename.lower())[1]
    if ext and ext not in ALLOWED_EXTENSIONS:
        raise InvoiceValidationError(
            status_code=415,
            detail="Unsupported file type. Only PDF, PNG, and JPG/JPEG invoices are accepted.",
        )

    stripped_pdf = data.lstrip(b"\xef\xbb\xbf \t\r\n")
    if stripped_pdf.startswith(b"%PDF-"):
        if ext and ext != ".pdf":
            raise InvoiceValidationError(
                status_code=415,
                detail="File extension does not match PDF document signature.",
            )
        return "PDF"

    if data.startswith(b"\x89PNG\r\n\x1a\n"):
        if ext and ext != ".png":
            raise InvoiceValidationError(
                status_code=415,
                detail="File extension does not match PNG image signature.",
            )
        return "PNG"

    if data.startswith(b"\xff\xd8\xff"):
        if ext and ext not in {".jpg", ".jpeg"}:
            raise InvoiceValidationError(
                status_code=415,
                detail="File extension does not match JPEG image signature.",
            )
        return "JPEG"

    # If extension looks like a supported type but magic signature fails, report invalid signature/content
    if ext in ALLOWED_EXTENSIONS:
        raise InvoiceValidationError(
            status_code=415,
            detail="Invalid file signature for the uploaded document type.",
        )

    raise InvoiceValidationError(
        status_code=415,
        detail="Unsupported file format. Only valid PDF, PNG, and JPG/JPEG signatures are accepted.",
    )


def detect_tesseract_availability() -> tuple[bool, Optional[str]]:
    """
    Dynamically checks whether the external Tesseract OCR executable is installed
    and runnable. Never claims OCR is available if the binary check fails.
    """
    candidates: list[str] = []
    which_hit = shutil.which("tesseract")
    if which_hit:
        candidates.append(which_hit)

    if os.name == "nt":
        for path in (
            r"C:\Program Files\Tesseract-OCR\tesseract.exe",
            r"C:\Program Files (x86)\Tesseract-OCR\tesseract.exe",
        ):
            if os.path.isfile(path) and path not in candidates:
                candidates.append(path)

    for exe_path in candidates:
        try:
            proc = subprocess.run(
                [exe_path, "--version"],
                capture_output=True,
                text=True,
                timeout=3,
                check=False,
            )
            if proc.returncode == 0:
                return True, exe_path
        except Exception:
            continue

    return False, None


def _validate_image_bytes(data: bytes, expected_type: str) -> tuple[int, int]:
    """Validates PNG/JPEG structure and enforces strict pixel/dimension limits via Pillow."""
    if not _PIL_AVAILABLE or Image is None:
        raise InvoiceValidationError(
            status_code=500,
            detail="Image processing library is unavailable on the server.",
        )

    previous_max_pixels = Image.MAX_IMAGE_PIXELS
    Image.MAX_IMAGE_PIXELS = MAX_IMAGE_PIXELS
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", Image.DecompressionBombWarning)
            with Image.open(io.BytesIO(data)) as verified_img:
                detected_fmt = (verified_img.format or "").upper()
                verified_img.verify()

            with Image.open(io.BytesIO(data)) as loaded_img:
                loaded_img.load()
                width, height = loaded_img.size
    except InvoiceValidationError:
        raise
    except Image.DecompressionBombWarning:
        raise InvoiceValidationError(
            status_code=422,
            detail="Image dimensions or pixel density exceed allowed security limits.",
        )
    except Image.DecompressionBombError:
        raise InvoiceValidationError(
            status_code=422,
            detail="Image dimensions exceed maximum allowed pixel limit.",
        )
    except (UnidentifiedImageError, OSError, ValueError, SyntaxError):
        raise InvoiceValidationError(
            status_code=422,
            detail="Malformed or truncated image file.",
        )
    finally:
        Image.MAX_IMAGE_PIXELS = previous_max_pixels

    if expected_type == "PNG" and detected_fmt != "PNG":
        raise InvoiceValidationError(status_code=415, detail="Image content does not match PNG format.")
    if expected_type == "JPEG" and detected_fmt != "JPEG":
        raise InvoiceValidationError(status_code=415, detail="Image content does not match JPEG format.")

    if (
        width <= 0
        or height <= 0
        or width > MAX_IMAGE_DIMENSION
        or height > MAX_IMAGE_DIMENSION
        or (width * height) > MAX_IMAGE_PIXELS
    ):
        raise InvoiceValidationError(
            status_code=422,
            detail=f"Image dimensions ({width}x{height}) exceed security limits.",
        )

    return width, height


def _extract_text_from_pdf(
    data: bytes,
    ocr_available: bool,
    tesseract_exe: Optional[str],
) -> tuple[str, int, str, str]:
    """
    Validates PDF via PyMuPDF (non-encrypted, 1..5 pages) and extracts embedded text.
    Falls back to pytesseract only if executable is verified; otherwise flags OCR_UNAVAILABLE
    for scanned PDFs.
    """
    if not _PYMUPDF_AVAILABLE or pymupdf is None:
        raise InvoiceValidationError(
            status_code=500,
            detail="PDF processing library is unavailable on the server.",
        )

    doc = None
    try:
        doc = pymupdf.open(stream=data, filetype="pdf")
    except Exception:
        raise InvoiceValidationError(
            status_code=422,
            detail="Malformed or unreadable PDF document.",
        )

    try:
        if getattr(doc, "is_encrypted", False) or getattr(doc, "needs_pass", False):
            raise InvoiceValidationError(
                status_code=422,
                detail="Encrypted or password-protected PDF documents are not supported.",
            )

        page_count = int(doc.page_count)
        if page_count <= 0:
            raise InvoiceValidationError(
                status_code=422,
                detail="PDF document contains zero pages.",
            )
        if page_count > MAX_PDF_PAGES:
            raise InvoiceValidationError(
                status_code=422,
                detail=f"PDF contains {page_count} pages, exceeding the maximum allowed limit of {MAX_PDF_PAGES} pages.",
            )

        page_texts: list[str] = []
        for idx in range(page_count):
            page = doc.load_page(idx)
            page_texts.append(page.get_text("text") or "")

        combined_text = "\n".join(page_texts).strip()
        alnum_count = sum(1 for ch in combined_text if ch.isalnum())

        if alnum_count >= MIN_READABLE_TEXT_CHARS:
            return (
                combined_text,
                page_count,
                "EXTRACTED",
                f"Extracted embedded text from {page_count}-page PDF using PyMuPDF.",
            )

        # Insufficient embedded text -> likely scanned/image-only PDF
        if ocr_available and _PYTESSERACT_AVAILABLE and pytesseract is not None and _PIL_AVAILABLE and Image is not None:
            if tesseract_exe:
                pytesseract.pytesseract.tesseract_cmd = tesseract_exe
            ocr_pages: list[str] = []
            try:
                for idx in range(page_count):
                    page = doc.load_page(idx)
                    pix = page.get_pixmap(dpi=150)
                    img = Image.frombytes("RGB", (pix.width, pix.height), pix.samples)
                    ocr_pages.append(pytesseract.image_to_string(img) or "")
                ocr_text = "\n".join(ocr_pages).strip()
                if sum(1 for ch in ocr_text if ch.isalnum()) >= MIN_READABLE_TEXT_CHARS:
                    return (
                        ocr_text,
                        page_count,
                        "EXTRACTED",
                        f"Extracted text via Tesseract OCR across {page_count}-page PDF.",
                    )
                return (
                    ocr_text,
                    page_count,
                    "UNREADABLE",
                    "PDF contained minimal readable text even after OCR attempt.",
                )
            except Exception:
                return (
                    combined_text,
                    page_count,
                    "OCR_UNAVAILABLE",
                    "Scanned/low-text PDF detected and OCR execution could not extract readable text.",
                )

        # Look carefully: scanned PDF vs truly empty/unreadable short text PDF
        has_images = False
        for idx in range(page_count):
            if doc.load_page(idx).get_images(full=False):
                has_images = True
                break

        if has_images or alnum_count == 0:
            return (
                combined_text,
                page_count,
                "OCR_UNAVAILABLE",
                "PDF contains little or no embedded text (likely scanned), and Tesseract OCR is not available on this host.",
            )

        return (
            combined_text,
            page_count,
            "UNREADABLE",
            "PDF contained insufficient readable text for automated field extraction.",
        )
    finally:
        if doc is not None:
            doc.close()


def _extract_text_from_image(
    data: bytes,
    file_type: str,
    ocr_available: bool,
    tesseract_exe: Optional[str],
) -> tuple[str, str, str]:
    """Validates image security limits and runs pytesseract only when Tesseract binary exists."""
    width, height = _validate_image_bytes(data, expected_type=file_type)

    if ocr_available and _PYTESSERACT_AVAILABLE and pytesseract is not None and _PIL_AVAILABLE and Image is not None:
        if tesseract_exe:
            pytesseract.pytesseract.tesseract_cmd = tesseract_exe
        try:
            with Image.open(io.BytesIO(data)) as img:
                rgb = img.convert("RGB")
                text = (pytesseract.image_to_string(rgb) or "").strip()
            if sum(1 for ch in text if ch.isalnum()) >= MIN_READABLE_TEXT_CHARS:
                return (
                    text,
                    "EXTRACTED",
                    f"Extracted text from {width}x{height} {file_type} image using Tesseract OCR.",
                )
            return (
                text,
                "UNREADABLE",
                f"Validated {width}x{height} {file_type} image, but OCR yielded insufficient readable text.",
            )
        except Exception:
            return (
                "",
                "OCR_UNAVAILABLE",
                f"Validated {width}x{height} {file_type} image, but Tesseract OCR could not execute.",
            )

    return (
        "",
        "OCR_UNAVAILABLE",
        f"Validated {width}x{height} {file_type} image, but Tesseract OCR is not installed/available on this host.",
    )


def _normalize_extracted_date(raw_value: str) -> str:
    """Normalizes common valid invoice date formats to ISO YYYY-MM-DD, preserving invalid labels for audit."""
    clean = re.sub(r"\s+", " ", raw_value.strip(" .,:;"))
    for fmt in (
        "%Y-%m-%d",
        "%Y/%m/%d",
        "%d/%m/%Y",
        "%m/%d/%Y",
        "%d-%m-%Y",
        "%m-%d-%Y",
        "%b %d, %Y",
        "%B %d, %Y",
        "%d %b %Y",
        "%d %B %Y",
    ):
        try:
            parsed = datetime.strptime(clean, fmt).date()
            return parsed.isoformat()
        except ValueError:
            continue
    return clean[:64]


def _parse_money_token(raw_token: str) -> Optional[Decimal]:
    """Parses currency amount token strictly as quantized Decimal; never invents values."""
    clean = raw_token.strip().replace(",", "")
    clean = re.sub(r"^[^\d-]+", "", clean)
    if not clean:
        return None
    try:
        dec = Decimal(clean)
        if not dec.is_finite():
            return None
        return dec.quantize(Decimal("0.01"))
    except (InvalidOperation, ValueError):
        return None


def _extract_labeled_money(lines: list[str], patterns: list[str]) -> Optional[tuple[Decimal, str]]:
    """Extracts the first labeled monetary amount matching one of `patterns`."""
    for line in lines:
        for pat in patterns:
            match = re.search(pat, line, flags=re.IGNORECASE)
            if match:
                raw_num = match.group("amount")
                val = _parse_money_token(raw_num)
                if val is not None:
                    curr = match.groupdict().get("currency")
                    return val, (curr.upper() if curr else "")
    return None


def _parse_fields_from_text(text: str) -> dict[str, tuple[Optional[str], str, str]]:
    """
    Extracts structured invoice fields deterministically from plain text without fabricating missing data.
    Returns mapping field_name -> (value_or_none, status, confidence).
    """
    lines = [line.strip() for line in text.splitlines() if line.strip()]
    results: dict[str, tuple[Optional[str], str, str]] = {
        name: (None, "MISSING", "NONE") for name in INVOICE_FIELD_NAMES
    }
    if not lines:
        return results

    # 1. Vendor / Supplier name
    for line in lines:
        m = re.match(
            r"^(?:Vendor|Supplier|Seller|From|Billed\s+By|Issued\s+By)\s*[:\-]\s*(.+)$",
            line,
            flags=re.IGNORECASE,
        )
        if m:
            candidate = m.group(1).strip()
            if candidate and not re.match(r"^(?:n/?a|none|-+)$", candidate, flags=re.IGNORECASE):
                results["vendor_name"] = (candidate[:255], "EXTRACTED", "HIGH")
                break

    if results["vendor_name"][0] is None:
        # Careful header heuristic: only accept the first clean non-label line before INVOICE header
        for line in lines[:3]:
            if re.search(
                r"\b(invoice|bill\s+to|ship\s+to|date|due|total|subtotal|tax|po\s*#|page)\b",
                line,
                flags=re.IGNORECASE,
            ):
                continue
            if len(line) >= 3 and re.search(r"[A-Za-z]{2,}", line) and not re.match(r"^[\d\W]+$", line):
                results["vendor_name"] = (line[:255], "EXTRACTED", "MEDIUM")
                break

    # 2. Invoice number (allows optional spaced numeric groups like "INV 1001" without swallowing next label)
    for line in lines:
        m = re.search(
            r"\b(?:Invoice\s*(?:No\.?|Number|#)|Inv\s*(?:No\.?|#))\s*[:#\-]?\s*([A-Za-z0-9][A-Za-z0-9\-_/]*(?:\s+\d[A-Za-z0-9\-_/]*){0,2})(?!\S)",
            line,
            flags=re.IGNORECASE,
        )
        if m:
            token = m.group(1).strip()[:45]
            if len(token) >= 2 and token.lower() not in {"date", "amount", "total"}:
                results["invoice_number"] = (token[:128], "EXTRACTED", "HIGH")
                break

    # 3. PO / Reference number
    for line in lines:
        m = re.search(
            r"\b(?:Purchase\s*Order(?:\s*(?:No\.?|Number|#))?|P\.?O\.?\s*(?:No\.?|Number|#))\s*[:#\-]?\s*([A-Za-z0-9][A-Za-z0-9\-_/]{1,40})\b",
            line,
            flags=re.IGNORECASE,
        )
        if m:
            token = m.group(1).strip()
            if token.lower() not in {"date", "amount"}:
                results["po_number"] = (token[:128], "EXTRACTED", "HIGH")
                break

    # 4. Invoice Date & Due Date
    for line in lines:
        m_inv = re.search(
            r"\b(?:Invoice\s*Date|Date\s*of\s*Issue|Issued\s*Date)\s*[:\-]\s*([^\r\n;|]+)",
            line,
            flags=re.IGNORECASE,
        )
        if m_inv and results["invoice_date"][0] is None:
            raw_date = m_inv.group(1).strip()
            # Stop before inline secondary label like "Due Date:" on same line
            raw_date = re.split(r"\s{2,}|\bDue\s*Date\b", raw_date, maxsplit=1, flags=re.IGNORECASE)[0].strip()
            if raw_date:
                results["invoice_date"] = (_normalize_extracted_date(raw_date), "EXTRACTED", "HIGH")

        m_due = re.search(
            r"\b(?:Due\s*Date|Payment\s*Due|Pay\s*By)\s*[:\-]\s*([^\r\n;|]+)",
            line,
            flags=re.IGNORECASE,
        )
        if m_due and results["due_date"][0] is None:
            raw_due = m_due.group(1).strip()
            raw_due = re.split(r"\s{2,}", raw_due, maxsplit=1)[0].strip()
            if raw_due:
                results["due_date"] = (_normalize_extracted_date(raw_due), "EXTRACTED", "HIGH")

    # 5. Monetary amounts (Subtotal, Tax, Total Amount) & Currency
    curr_match = re.search(r"\bCurrency\s*[:\-]\s*([A-Z]{3})\b", text, flags=re.IGNORECASE)
    detected_currencies: list[str] = []
    if curr_match:
        code = curr_match.group(1).upper()
        if code in KNOWN_CURRENCY_CODES:
            results["currency"] = (code, "EXTRACTED", "HIGH")

    sub_match = _extract_labeled_money(
        lines,
        [
            rf"\bSub[\s\-]?Total\b\s*[:\-]?\s*(?:(?P<currency>{'|'.join(KNOWN_CURRENCY_CODES)})\s*)?[$€£₹]?\s*(?P<amount>-?[\d,]+(?:\.\d{{1,2}})?)",
        ],
    )
    if sub_match is not None:
        results["subtotal"] = (f"{sub_match[0]:.2f}", "EXTRACTED", "HIGH")
        if sub_match[1]:
            detected_currencies.append(sub_match[1])

    tax_match = _extract_labeled_money(
        lines,
        [
            rf"\b(?:Sales\s+Tax|Tax|VAT|GST)(?:\s*\([^)]*\))?\b\s*[:\-]?\s*(?:(?P<currency>{'|'.join(KNOWN_CURRENCY_CODES)})\s*)?[$€£₹]?\s*(?P<amount>-?[\d,]+(?:\.\d{{1,2}})?)",
        ],
    )
    if tax_match is not None:
        results["tax"] = (f"{tax_match[0]:.2f}", "EXTRACTED", "HIGH")
        if tax_match[1]:
            detected_currencies.append(tax_match[1])

    total_match = _extract_labeled_money(
        lines,
        [
            rf"\b(?:Grand\s+Total|Total\s+Amount|Amount\s+Due|Balance\s+Due)\b\s*[:\-]?\s*(?:(?P<currency>{'|'.join(KNOWN_CURRENCY_CODES)})\s*)?[$€£₹]?\s*(?P<amount>-?[\d,]+(?:\.\d{{1,2}})?)",
            rf"(?<!Sub)(?<!Sub\s)(?<!Sub-)\bTotal\b\s*[:\-]?\s*(?:(?P<currency>{'|'.join(KNOWN_CURRENCY_CODES)})\s*)?[$€£₹]?\s*(?P<amount>-?[\d,]+(?:\.\d{{1,2}})?)",
        ],
    )
    if total_match is not None:
        results["total_amount"] = (f"{total_match[0]:.2f}", "EXTRACTED", "HIGH")
        if total_match[1]:
            detected_currencies.append(total_match[1])

    if results["currency"][0] is None:
        if detected_currencies:
            results["currency"] = (detected_currencies[0], "EXTRACTED", "HIGH")
        else:
            iso_hits = re.findall(rf"\b({'|'.join(KNOWN_CURRENCY_CODES)})\b", text.upper())
            if iso_hits:
                results["currency"] = (iso_hits[0], "EXTRACTED", "MEDIUM")
            else:
                for symbol, iso_code in CURRENCY_SYMBOLS.items():
                    if symbol in text:
                        results["currency"] = (iso_code, "EXTRACTED", "MEDIUM")
                        break

    return results


def _normalize_correction_value(field_name: str, raw_val: Any) -> Optional[str]:
    if raw_val is None:
        return None
    text = str(raw_val).strip()
    if not text:
        return None

    if field_name in {"subtotal", "tax", "total_amount"}:
        dec = _parse_money_token(text)
        if dec is None:
            raise InvoiceValidationError(
                status_code=400,
                detail=f"User correction for '{field_name}' must be a valid finite decimal number.",
            )
        return f"{dec:.2f}"

    if field_name == "currency":
        clean_curr = text.upper()
        if len(clean_curr) != 3 or not clean_curr.isalpha():
            raise InvoiceValidationError(
                status_code=400,
                detail="User correction for 'currency' must be a 3-letter ISO currency code.",
            )
        return clean_curr

    if field_name in {"invoice_date", "due_date"}:
        return _normalize_extracted_date(text)

    if field_name in {"vendor_name", "invoice_number", "po_number"}:
        return text[:255] if field_name == "vendor_name" else text[:128]

    return text[:255]


def extract_invoice_document(
    *,
    data: bytes,
    raw_filename: Optional[str],
    corrections: Optional[dict[str, Any]] = None,
) -> InvoiceExtractionResult:
    """
    Validates file signature and structural security constraints, extracts readable
    document text cleanly, parses invoice fields without inventing missing values,
    and merges optional user corrections separately from extracted outputs.
    """
    safe_filename = sanitize_filename(raw_filename)
    file_type = detect_file_type_by_signature(data, safe_filename)
    file_size = len(data)
    ocr_available, tesseract_exe = detect_tesseract_availability()

    page_count: Optional[int] = None
    if file_type == "PDF":
        raw_text, page_count, doc_status, note = _extract_text_from_pdf(
            data=data,
            ocr_available=ocr_available,
            tesseract_exe=tesseract_exe,
        )
    else:
        raw_text, doc_status, note = _extract_text_from_image(
            data=data,
            file_type=file_type,
            ocr_available=ocr_available,
            tesseract_exe=tesseract_exe,
        )

    parsed_map = _parse_fields_from_text(raw_text) if doc_status in {"EXTRACTED", "UNREADABLE"} else {
        name: (None, "OCR_UNAVAILABLE" if doc_status == "OCR_UNAVAILABLE" else "MISSING", "NONE")
        for name in INVOICE_FIELD_NAMES
    }

    # Refine document-level extraction_status if text was read from PDF/OCR
    extracted_critical_count = sum(1 for key in CRITICAL_FIELDS if parsed_map[key][0] is not None)
    overall_status = doc_status
    if doc_status == "EXTRACTED" and extracted_critical_count < len(CRITICAL_FIELDS):
        overall_status = "PARTIAL_EXTRACTION"
        if extracted_critical_count == 0:
            note = (
                f"{note} Automated parser could not match critical invoice fields; "
                "manual review or user correction is needed."
            )

    clean_corrections = corrections or {}
    field_infos: dict[str, ExtractedFieldInfo] = {}
    for field_name in INVOICE_FIELD_NAMES:
        ext_val, ext_status, ext_conf = parsed_map[field_name]
        corr_raw = clean_corrections.get(field_name)
        corr_val = _normalize_correction_value(field_name, corr_raw)

        if corr_val is not None:
            field_infos[field_name] = ExtractedFieldInfo(
                field_name=field_name,
                extracted_value=ext_val,
                corrected_value=corr_val,
                effective_value=corr_val,
                extraction_status="USER_CORRECTED",
                confidence="USER_PROVIDED",
            )
        else:
            field_infos[field_name] = ExtractedFieldInfo(
                field_name=field_name,
                extracted_value=ext_val,
                corrected_value=None,
                effective_value=ext_val,
                extraction_status=ext_status,
                confidence=ext_conf,
            )

    def _effective_dec(name: str) -> Optional[Decimal]:
        val = field_infos[name].effective_value
        return Decimal(val) if val is not None else None

    return InvoiceExtractionResult(
        original_filename=safe_filename,
        file_type=file_type,
        file_size_bytes=file_size,
        page_count=page_count,
        ocr_available=ocr_available,
        extraction_status=overall_status,
        extraction_note=note,
        extracted_text_length=len(raw_text.strip()),
        fields=field_infos,
        vendor_name=field_infos["vendor_name"].effective_value,
        invoice_number=field_infos["invoice_number"].effective_value,
        invoice_date=field_infos["invoice_date"].effective_value,
        due_date=field_infos["due_date"].effective_value,
        currency=field_infos["currency"].effective_value,
        subtotal=_effective_dec("subtotal"),
        tax=_effective_dec("tax"),
        total_amount=_effective_dec("total_amount"),
        po_number=field_infos["po_number"].effective_value,
    )
