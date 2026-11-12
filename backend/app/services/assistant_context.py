"""
FraudTrace AI — Investigation Context Retrieval & Sanitization Service
=======================================================================
Builds minimal, privacy-sanitized investigation context bundles strictly from
existing read-only SQLAlchemy records and domain services (`fraud_graph`,
`ml_anomaly_detector`, `invoices`).

Privacy & Security Guarantees:
- Never modifies database state (read-only ORM queries only).
- Never allows the LLM or user input to execute SQL, inspect files, or bypass
  scoped lookups.
- Never forwards raw uploaded invoice files, raw extracted document text,
  OAuth/API secrets, email addresses, phone numbers, physical addresses, or
  person names to an external LLM.
- Pseudonymizes account identifiers (`ACCT_01`, ...) and vendor names
  (`VENDOR_01`, ...) before constructing the external payload.
- Maintains a strict canonical `allowed_citations` registry so any fabricated
  citation ID returned by a model can be rejected cleanly.
"""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field
import re
from typing import Any, Optional

from sqlalchemy import func, select
from sqlalchemy.orm import Session, selectinload

from app.models import Evidence, Investigation, Invoice, InvoiceFinding, Transaction
from app.routes.invoices import _deserialize_field_metadata, _parse_supporting_values
from app.services.fraud_graph import (
    NetworkPattern,
    build_transaction_graph,
    detect_all_patterns,
    get_account_connections,
)
from app.services.ml_anomaly_detector import evaluate_transaction_anomaly

MAX_CROSS_TRANSACTIONS = 12
MAX_CROSS_INVOICES = 8
MAX_NETWORK_PATTERNS = 12
MAX_EXCERPT_LENGTH = 260

EMAIL_PATTERN = re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")
PHONE_PATTERN = re.compile(
    r"(?:(?<!\d)(?:\+?\d{1,3}[\s.-]?)?(?:\(\d{2,4}\)|\d{3})[\s.-]\d{3,4}[\s.-]\d{4}\b)"
)
STREET_ADDRESS_PATTERN = re.compile(
    r"\b\d{1,5}\s+(?:[A-Za-z0-9.'-]+\s+){1,4}"
    r"(?:Street|St|Avenue|Ave|Road|Rd|Boulevard|Blvd|Lane|Ln|Drive|Dr|Court|Ct|Way|Place|Pl)\b\.?",
    re.IGNORECASE,
)
LABELED_NAME_PATTERN = re.compile(
    r"\b(?:Name|Customer|Client|Contact|Attn|Recipient Name|Sender Name|Owner)\s*:\s*([A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,3})",
    re.IGNORECASE,
)
HONORIFIC_NAME_PATTERN = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof)\.?\s+[A-Z][a-z]+(?:\s+[A-Z][a-z]+){0,2}\b"
)
CREDENTIAL_PATTERN = re.compile(
    r"(?i)\b(?:bearer|basic)\s+[A-Za-z0-9._~+/-]+=*"
    r"|AIza[0-9A-Za-z_-]{16,}"
    r"|\b(?:api[_-]?key|secret|password|access[_-]?token|client[_-]?secret)\s*[:=]\s*\S+"
)

EXPLICIT_TXN_ID_PATTERN = re.compile(r"(?:\btransaction\s*#?|\btxn\s*#?|#)(\d+)\b", re.IGNORECASE)
EXPLICIT_INV_ID_PATTERN = re.compile(r"\binvestigation\s*#?(\d+)\b", re.IGNORECASE)
EXPLICIT_INVOICE_ID_PATTERN = re.compile(r"\binvoice\s*#?(\d+)\b", re.IGNORECASE)


class ContextNotFoundError(Exception):
    """Raised when a caller requests a nonexistent FraudTrace investigation entity."""

    def __init__(self, detail: str) -> None:
        super().__init__(detail)
        self.detail = detail


@dataclass(frozen=True)
class CitationMeta:
    """Authoritative record backing an allowed citation_id."""

    citation_id: str
    record_type: str
    record_id: str
    label: str
    excerpt: str


@dataclass
class AssistantContextBundle:
    """Sanitized payload ready for external AI prompts + strict server citation registry."""

    scopes_used: list[str]
    sanitized_context: dict[str, Any]
    allowed_citations: dict[str, CitationMeta] = field(default_factory=dict)
    standard_limitations: list[str] = field(default_factory=list)
    default_suggested_questions: list[str] = field(default_factory=list)
    pseudonym_map: dict[str, str] = field(default_factory=dict)


class _AliasSanitizer:
    """
    Maps real/arbitrary account identifiers and vendor names into stable
    per-request pseudonyms and scrubs PII/secrets from all descriptive text.
    """

    def __init__(self) -> None:
        self._account_to_alias: dict[str, str] = {}
        self._alias_to_account: dict[str, str] = {}
        self._vendor_to_alias: dict[str, str] = {}
        self._txn_ref_to_alias: dict[str, str] = {}

    def alias_account(self, raw_account: Optional[str]) -> Optional[str]:
        if raw_account is None:
            return None
        clean = raw_account.strip()
        if not clean:
            return None
        existing = self._account_to_alias.get(clean)
        if existing is not None:
            return existing
        alias = f"ACCT_{len(self._account_to_alias) + 1:02d}"
        self._account_to_alias[clean] = alias
        self._alias_to_account[alias] = clean
        return alias

    def alias_vendor(self, raw_vendor: Optional[str]) -> Optional[str]:
        if raw_vendor is None:
            return None
        clean = raw_vendor.strip()
        if not clean:
            return None
        norm = clean.lower()
        existing = self._vendor_to_alias.get(norm)
        if existing is not None:
            return existing
        alias = f"VENDOR_{len(self._vendor_to_alias) + 1:02d}"
        self._vendor_to_alias[norm] = alias
        return alias

    def alias_transaction_ref(self, raw_ref: Optional[str], txn_id: Optional[int] = None) -> Optional[str]:
        if raw_ref is None:
            return None
        clean = raw_ref.strip()
        if not clean:
            return None
        if clean in self._txn_ref_to_alias:
            return self._txn_ref_to_alias[clean]
        alias = f"TXN_REF_{txn_id}" if txn_id is not None else f"TXN_REF_{len(self._txn_ref_to_alias) + 1:02d}"
        self._txn_ref_to_alias[clean] = alias
        return alias

    def sanitize_text(self, raw_text: Optional[str], *, max_len: int = 500) -> str:
        if not raw_text:
            return ""
        text = str(raw_text)

        # Replace longer identifiers first to avoid partial substring corruption.
        for raw_acct, alias in sorted(
            self._account_to_alias.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            text = text.replace(raw_acct, alias)

        for raw_ref, alias in sorted(
            self._txn_ref_to_alias.items(), key=lambda kv: len(kv[0]), reverse=True
        ):
            text = text.replace(raw_ref, alias)

        text = CREDENTIAL_PATTERN.sub("[REDACTED_SECRET]", text)
        text = EMAIL_PATTERN.sub("[REDACTED_EMAIL]", text)
        text = PHONE_PATTERN.sub("[REDACTED_PHONE]", text)
        text = STREET_ADDRESS_PATTERN.sub("[REDACTED_ADDRESS]", text)
        text = LABELED_NAME_PATTERN.sub("[REDACTED_NAME]", text)
        text = HONORIFIC_NAME_PATTERN.sub("[REDACTED_NAME]", text)
        text = re.sub(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]", " ", text)
        text = re.sub(r"\s+", " ", text).strip()
        if len(text) > max_len:
            return f"{text[: max_len - 3].rstrip()}..."
        return text

    @property
    def reverse_account_map(self) -> dict[str, str]:
        return dict(self._alias_to_account)


def _format_decimal(value: Any) -> Optional[str]:
    if value is None:
        return None
    return str(value)


def _format_iso(dt: Any) -> Optional[str]:
    if dt is None:
        return None
    if hasattr(dt, "isoformat"):
        return dt.isoformat()
    return str(dt)


def _register_citation(
    registry: dict[str, CitationMeta],
    *,
    citation_id: str,
    record_type: str,
    record_id: str,
    label: str,
    excerpt: str,
) -> None:
    if citation_id in registry:
        return
    clean_excerpt = excerpt.strip()
    if len(clean_excerpt) > MAX_EXCERPT_LENGTH:
        clean_excerpt = f"{clean_excerpt[: MAX_EXCERPT_LENGTH - 3].rstrip()}..."
    registry[citation_id] = CitationMeta(
        citation_id=citation_id,
        record_type=record_type,
        record_id=record_id,
        label=label,
        excerpt=clean_excerpt,
    )


def _question_requests_network(question: str) -> bool:
    lowered = question.lower()
    return any(
        kw in lowered
        for kw in ("network", "graph", "connect", "hop", "hub", "receiver", "sender", "pattern", "cluster", "relay")
    )


def _question_requests_cross(question: str) -> bool:
    lowered = question.lower()
    return any(
        kw in lowered
        for kw in ("common", "compare", "between", "across", "multiple", "all ", "overall", "summary", "other transaction")
    )


def _question_requests_invoice(question: str) -> bool:
    lowered = question.lower()
    return any(kw in lowered for kw in ("invoice", "vendor", "ocr", "pdf", "receipt", "billing", "arithmetic"))


def _build_transaction_entry(
    txn: Transaction,
    *,
    db: Session,
    sanitizer: _AliasSanitizer,
    registry: dict[str, CitationMeta],
    include_ml: bool = True,
) -> dict[str, Any]:
    sender_alias = sanitizer.alias_account(txn.sender_id) or "ACCT_UNKNOWN"
    receiver_alias = sanitizer.alias_account(txn.receiver_id) or "ACCT_UNKNOWN"
    sanitizer.alias_transaction_ref(txn.reference, txn.id)

    txn_cid = f"TXN:{txn.id}"
    _register_citation(
        registry,
        citation_id=txn_cid,
        record_type="transaction",
        record_id=str(txn.id),
        label=f"Transaction #{txn.id} ({txn.risk_level or 'UNSCORED'})",
        excerpt=(
            f"Amount {txn.amount} {txn.currency} from {sender_alias} to {receiver_alias}; "
            f"risk_score={txn.risk_score}, risk_level={txn.risk_level}, status={txn.investigation_status}."
        ),
    )

    investigations_out: list[dict[str, Any]] = []
    for inv in txn.investigations:
        inv_cid = f"INV:{inv.id}"
        sanitized_summary = sanitizer.sanitize_text(inv.summary, max_len=450)
        _register_citation(
            registry,
            citation_id=inv_cid,
            record_type="investigation",
            record_id=str(inv.id),
            label=f"Investigation #{inv.id} ({inv.status})",
            excerpt=sanitized_summary or f"Investigation status={inv.status}, priority={inv.priority}.",
        )

        evidences_out: list[dict[str, Any]] = []
        for ev in inv.evidences:
            ev_cid = f"EV:{ev.id}"
            sanitized_desc = sanitizer.sanitize_text(ev.description, max_len=360)
            _register_citation(
                registry,
                citation_id=ev_cid,
                record_type="evidence",
                record_id=str(ev.id),
                label=f"{ev.evidence_type} ({ev.severity})",
                excerpt=sanitized_desc,
            )
            evidences_out.append(
                {
                    "citation_id": ev_cid,
                    "evidence_type": ev.evidence_type,
                    "severity": ev.severity,
                    "description": sanitized_desc,
                }
            )

        investigations_out.append(
            {
                "citation_id": inv_cid,
                "status": inv.status,
                "priority": inv.priority,
                "summary": sanitized_summary,
                "evidences": evidences_out,
            }
        )

    ml_payload: Optional[dict[str, Any]] = None
    if include_ml:
        assessment = evaluate_transaction_anomaly(db=db, target_transaction=txn)
        ml_cid = f"ML:{txn.id}"
        _register_citation(
            registry,
            citation_id=ml_cid,
            record_type="ml_anomaly",
            record_id=str(txn.id),
            label=f"Experimental IsolationForest (#{txn.id}: {assessment.status})",
            excerpt=(
                f"status={assessment.status}, decision_score={assessment.decision_score}, "
                f"training_samples={assessment.training_sample_count}/{assessment.minimum_samples_required}. "
                "Experimental behavioral outlier signal only; NOT a fraud probability."
            ),
        )
        ml_payload = {
            "citation_id": ml_cid,
            "available": assessment.available,
            "status": assessment.status,
            "experimental": True,
            "model_name": assessment.model_name,
            "is_anomaly": assessment.is_anomaly,
            "decision_score": assessment.decision_score,
            "training_sample_count": assessment.training_sample_count,
            "minimum_samples_required": assessment.minimum_samples_required,
            "top_feature_deviations": [
                {
                    "feature_name": dev.feature_name,
                    "display_label": dev.display_label,
                    "z_score_deviation": dev.z_score_deviation,
                    "summary": sanitizer.sanitize_text(dev.summary, max_len=200),
                }
                for dev in assessment.feature_deviations[:4]
            ],
            "explanation": sanitizer.sanitize_text(assessment.explanation, max_len=360),
            "limitations": assessment.limitations,
        }

    return {
        "citation_id": txn_cid,
        "transaction_id": txn.id,
        "sender_account_ref": sender_alias,
        "receiver_account_ref": receiver_alias,
        "amount": _format_decimal(txn.amount),
        "currency": txn.currency,
        "timestamp": _format_iso(txn.timestamp),
        "deterministic_risk_score": txn.risk_score,
        "deterministic_risk_level": txn.risk_level,
        "investigation_status": txn.investigation_status,
        "investigations": investigations_out,
        "experimental_ml_anomaly": ml_payload,
    }


def _build_pattern_entry(
    idx: int,
    pattern: NetworkPattern,
    *,
    ref_to_txn_id: dict[str, int],
    sanitizer: _AliasSanitizer,
    registry: dict[str, CitationMeta],
) -> dict[str, Any]:
    involved_aliases = [sanitizer.alias_account(acct) or "ACCT_UNKNOWN" for acct in pattern.involved_accounts]
    linked_txn_citations: list[str] = []
    for ref in pattern.transaction_references:
        matched_id = ref_to_txn_id.get(ref)
        sanitizer.alias_transaction_ref(ref, matched_id)
        if matched_id is not None:
            txn_cid = f"TXN:{matched_id}"
            linked_txn_citations.append(txn_cid)
            _register_citation(
                registry,
                citation_id=txn_cid,
                record_type="transaction",
                record_id=str(matched_id),
                label=f"Transaction #{matched_id} (linked to {pattern.pattern_type})",
                excerpt=f"Transaction #{matched_id} referenced by network lead {pattern.pattern_type}.",
            )

    pat_cid = f"PAT:{idx}:{pattern.pattern_type}"
    sanitized_explanation = sanitizer.sanitize_text(pattern.explanation, max_len=380)
    _register_citation(
        registry,
        citation_id=pat_cid,
        record_type="network_pattern",
        record_id=f"{idx}:{pattern.pattern_type}",
        label=f"{pattern.pattern_type} ({pattern.severity})",
        excerpt=sanitized_explanation,
    )

    return {
        "citation_id": pat_cid,
        "pattern_type": pattern.pattern_type,
        "severity": pattern.severity,
        "involved_account_refs": involved_aliases,
        "linked_transaction_citations": linked_txn_citations,
        "supporting_counts": pattern.supporting_counts,
        "explanation": sanitized_explanation,
    }


def _build_invoice_entry(
    invoice: Invoice,
    *,
    sanitizer: _AliasSanitizer,
    registry: dict[str, CitationMeta],
) -> dict[str, Any]:
    vendor_alias = sanitizer.alias_vendor(invoice.vendor_name)
    inv_cid = f"INVOICE:{invoice.id}"
    sanitized_summary = sanitizer.sanitize_text(invoice.summary, max_len=400)
    if invoice.vendor_name and vendor_alias:
        sanitized_summary = sanitized_summary.replace(invoice.vendor_name, vendor_alias)

    _register_citation(
        registry,
        citation_id=inv_cid,
        record_type="invoice",
        record_id=str(invoice.id),
        label=f"Invoice #{invoice.id} ({invoice.investigation_status})",
        excerpt=(
            f"Type={invoice.file_type}, extraction_status={invoice.extraction_status}, "
            f"ocr_available={invoice.ocr_available}, status={invoice.investigation_status}. "
            f"{sanitized_summary}"
        ),
    )

    note, fields = _deserialize_field_metadata(invoice.field_metadata_json)
    sanitized_fields: list[dict[str, Any]] = []
    for fld in fields:
        field_cid = f"INVOICE_FIELD:{invoice.id}:{fld.field_name}"
        if fld.field_name == "vendor_name":
            ext_val = sanitizer.alias_vendor(fld.extracted_value) if fld.extracted_value else None
            corr_val = sanitizer.alias_vendor(fld.corrected_value) if fld.corrected_value else None
            eff_val = sanitizer.alias_vendor(fld.effective_value) if fld.effective_value else None
        else:
            ext_val = sanitizer.sanitize_text(fld.extracted_value, max_len=120) if fld.extracted_value else None
            corr_val = sanitizer.sanitize_text(fld.corrected_value, max_len=120) if fld.corrected_value else None
            eff_val = sanitizer.sanitize_text(fld.effective_value, max_len=120) if fld.effective_value else None

        _register_citation(
            registry,
            citation_id=field_cid,
            record_type="invoice_field",
            record_id=f"{invoice.id}:{fld.field_name}",
            label=f"Invoice #{invoice.id} field: {fld.field_name}",
            excerpt=(
                f"effective={eff_val}, extracted={ext_val}, corrected={corr_val}, "
                f"status={fld.extraction_status}, confidence={fld.confidence}"
            ),
        )
        sanitized_fields.append(
            {
                "citation_id": field_cid,
                "field_name": fld.field_name,
                "extracted_value": ext_val,
                "corrected_value": corr_val,
                "effective_value": eff_val,
                "extraction_status": fld.extraction_status,
                "confidence": fld.confidence,
            }
        )

    sanitized_findings: list[dict[str, Any]] = []
    for finding in invoice.findings:
        finding_cid = f"INVOICE_FINDING:{finding.id}"
        expl = sanitizer.sanitize_text(finding.explanation, max_len=360)
        if invoice.vendor_name and vendor_alias:
            expl = expl.replace(invoice.vendor_name, vendor_alias)

        raw_supporting = _parse_supporting_values(finding.supporting_values)
        safe_supporting: dict[str, Any] = {}
        for key, val in raw_supporting.items():
            if "vendor" in key.lower():
                safe_supporting[key] = vendor_alias or "[REDACTED_VENDOR]"
            elif isinstance(val, str):
                cleaned_val = sanitizer.sanitize_text(val, max_len=120)
                if invoice.vendor_name and vendor_alias:
                    cleaned_val = cleaned_val.replace(invoice.vendor_name, vendor_alias)
                safe_supporting[key] = cleaned_val
            else:
                safe_supporting[key] = val

        _register_citation(
            registry,
            citation_id=finding_cid,
            record_type="invoice_finding",
            record_id=str(finding.id),
            label=f"Invoice Finding {finding.finding_code} ({finding.severity})",
            excerpt=expl,
        )
        sanitized_findings.append(
            {
                "citation_id": finding_cid,
                "finding_code": finding.finding_code,
                "severity": finding.severity,
                "explanation": expl,
                "supporting_values": safe_supporting,
            }
        )

    return {
        "citation_id": inv_cid,
        "invoice_id": invoice.id,
        "file_type": invoice.file_type,
        "page_count": invoice.page_count,
        "ocr_available": invoice.ocr_available,
        "extraction_status": invoice.extraction_status,
        "investigation_status": invoice.investigation_status,
        "vendor_ref": vendor_alias,
        "invoice_date": invoice.invoice_date,
        "due_date": invoice.due_date,
        "currency": invoice.currency,
        "subtotal": _format_decimal(invoice.subtotal),
        "tax": _format_decimal(invoice.tax),
        "total_amount": _format_decimal(invoice.total_amount),
        "extraction_note": sanitizer.sanitize_text(note, max_len=300) if note else None,
        "summary": sanitized_summary,
        "fields": sanitized_fields,
        "findings": sanitized_findings,
    }


def retrieve_investigation_context(
    db: Session,
    *,
    question: str,
    transaction_id: Optional[int] = None,
    investigation_id: Optional[int] = None,
    invoice_id: Optional[int] = None,
    account_id: Optional[str] = None,
) -> AssistantContextBundle:
    """
    Retrieves scoped, read-only FraudTrace AI context and transforms it into a
    minimal, pseudonymized JSON dictionary plus an authoritative citation map.
    """
    sanitizer = _AliasSanitizer()
    registry: dict[str, CitationMeta] = {}
    scopes_used: list[str] = []
    standard_limitations: list[str] = []
    suggested_questions: list[str] = []

    target_txn_ids: list[int] = []
    target_account_ids: list[str] = []
    target_invoice_ids: list[int] = []

    # 1. Resolve explicit selectors first (with 404 verification)
    if investigation_id is not None:
        inv = db.execute(
            select(Investigation)
            .options(selectinload(Investigation.evidences))
            .where(Investigation.id == investigation_id)
        ).scalar_one_or_none()
        if inv is None:
            raise ContextNotFoundError(f"Investigation with ID {investigation_id} was not found.")
        if inv.transaction_id not in target_txn_ids:
            target_txn_ids.append(inv.transaction_id)

    if transaction_id is not None:
        if transaction_id not in target_txn_ids:
            target_txn_ids.append(transaction_id)

    if invoice_id is not None:
        target_invoice_ids.append(invoice_id)

    clean_account_id = account_id.strip() if account_id else None
    if clean_account_id:
        target_account_ids.append(clean_account_id)

    # 2. If no explicit IDs were selected, inspect question for explicit #ID hints
    if (
        transaction_id is None
        and investigation_id is None
        and invoice_id is None
        and not clean_account_id
    ):
        for match in EXPLICIT_INV_ID_PATTERN.findall(question):
            hint_inv_id = int(match)
            hinted_inv = db.execute(
                select(Investigation).where(Investigation.id == hint_inv_id)
            ).scalar_one_or_none()
            if hinted_inv is not None and hinted_inv.transaction_id not in target_txn_ids:
                target_txn_ids.append(hinted_inv.transaction_id)

        for match in EXPLICIT_INVOICE_ID_PATTERN.findall(question):
            hint_invoice_id = int(match)
            exists = db.scalar(select(Invoice.id).where(Invoice.id == hint_invoice_id))
            if exists is not None and hint_invoice_id not in target_invoice_ids:
                target_invoice_ids.append(hint_invoice_id)

        for match in EXPLICIT_TXN_ID_PATTERN.findall(question):
            hint_txn_id = int(match)
            exists = db.scalar(select(Transaction.id).where(Transaction.id == hint_txn_id))
            if exists is not None and hint_txn_id not in target_txn_ids:
                target_txn_ids.append(hint_txn_id)

    context_payload: dict[str, Any] = {}

    # 3. Preload reference -> id lookup only if needed for network pattern cross-referencing
    ref_to_txn_id: dict[str, int] = {}
    need_graph = bool(target_account_ids or target_txn_ids or _question_requests_network(question))
    graph = None
    all_patterns: list[NetworkPattern] = []
    if need_graph:
        all_ref_rows = db.execute(select(Transaction.id, Transaction.reference)).all()
        ref_to_txn_id = {row.reference: row.id for row in all_ref_rows}
        graph = build_transaction_graph(db)
        all_patterns = detect_all_patterns(graph)

    # A. Transaction & Investigation Context
    if target_txn_ids:
        txns = (
            db.execute(
                select(Transaction)
                .options(
                    selectinload(Transaction.investigations).selectinload(Investigation.evidences)
                )
                .where(Transaction.id.in_(target_txn_ids))
            )
            .scalars()
            .all()
        )
        found_ids = {t.id for t in txns}
        for missing_id in target_txn_ids:
            if missing_id not in found_ids:
                raise ContextNotFoundError(f"Transaction with ID {missing_id} was not found.")

        scopes_used.append("transaction")
        txn_entries = [
            _build_transaction_entry(
                txn,
                db=db,
                sanitizer=sanitizer,
                registry=registry,
                include_ml=True,
            )
            for txn in txns
        ]
        context_payload["transactions"] = txn_entries

        # Automatically include local network context for accounts involved in these transactions
        for txn in txns:
            if txn.sender_id not in target_account_ids:
                target_account_ids.append(txn.sender_id)
            if txn.receiver_id not in target_account_ids:
                target_account_ids.append(txn.receiver_id)

        standard_limitations.append(
            "Heuristic risk scores reflect deterministic rule weights (0-100), not calibrated fraud probabilities."
        )
        if any(entry.get("experimental_ml_anomaly") for entry in txn_entries):
            standard_limitations.append(
                "IsolationForest scores are experimental unsupervised outlier signals (lower/negative = more unusual), not causal attributions or guilt determinations."
            )
            standard_limitations.append(
                "The experimental Isolation Forest model uses some behavioral features that overlap with deterministic fraud-risk rules. Agreement between their findings does not constitute independent multi-model confirmation. Both outputs are indicators for investigation, not proof of fraud."
            )
        suggested_questions.extend(
            [
                "Which deterministic indicators contributed to this risk score?",
                "Are either of the involved accounts part of suspicious network patterns?",
                "What concrete verification steps should an investigator take next?",
            ]
        )

    # B. Network & Account Context
    if graph is not None and (target_account_ids or _question_requests_network(question)):
        scopes_used.append("network")
        account_profiles: list[dict[str, Any]] = []
        relevant_pattern_indices: list[int] = []

        if clean_account_id and clean_account_id not in graph:
            raise ContextNotFoundError(
                f"Account '{clean_account_id}' was not found in the transaction network."
            )

        for acct in target_account_ids:
            if acct not in graph:
                continue
            acct_alias = sanitizer.alias_account(acct) or "ACCT_UNKNOWN"
            in_edges = list(graph.in_edges(acct, data=True))
            out_edges = list(graph.out_edges(acct, data=True))
            connections = get_account_connections(graph, acct, max_hops=2)

            connected_entries: list[dict[str, Any]] = []
            for conn in connections[:25]:
                conn_alias = sanitizer.alias_account(conn.account_id) or "ACCT_UNKNOWN"
                connected_entries.append(
                    {
                        "account_ref": conn_alias,
                        "hop_distance": conn.hop_distance,
                        "relationship": conn.relationship,
                    }
                )

            acct_cid = f"ACCT:{acct_alias}"
            _register_citation(
                registry,
                citation_id=acct_cid,
                record_type="account",
                record_id=acct_alias,
                label=f"Account {acct_alias} ({len(in_edges)} in / {len(out_edges)} out)",
                excerpt=(
                    f"Incoming txns: {len(in_edges)}, outgoing txns: {len(out_edges)}, "
                    f"1-2 hop neighbors: {len(connections)}."
                ),
            )

            related_txn_citations: list[str] = []
            for src, dst, edge_data in (in_edges + out_edges)[:15]:
                tid = edge_data.get("transaction_id")
                if tid is None:
                    continue
                src_alias = sanitizer.alias_account(src) or "ACCT_UNKNOWN"
                dst_alias = sanitizer.alias_account(dst) or "ACCT_UNKNOWN"
                txn_cid = f"TXN:{tid}"
                if txn_cid not in related_txn_citations:
                    related_txn_citations.append(txn_cid)
                _register_citation(
                    registry,
                    citation_id=txn_cid,
                    record_type="transaction",
                    record_id=str(tid),
                    label=f"Transaction #{tid} ({src_alias} -> {dst_alias})",
                    excerpt=(
                        f"Amount {edge_data.get('amount')} {edge_data.get('currency')} "
                        f"from {src_alias} to {dst_alias}."
                    ),
                )

            matching_pats: list[str] = []
            for idx, pat in enumerate(all_patterns, start=1):
                if acct in pat.involved_accounts:
                    matching_pats.append(f"PAT:{idx}:{pat.pattern_type}")
                    if idx not in relevant_pattern_indices:
                        relevant_pattern_indices.append(idx)

            account_profiles.append(
                {
                    "citation_id": acct_cid,
                    "account_ref": acct_alias,
                    "incoming_transaction_count": len(in_edges),
                    "outgoing_transaction_count": len(out_edges),
                    "connected_accounts_1_to_2_hops": connected_entries,
                    "connected_transaction_citations": related_txn_citations,
                    "linked_pattern_citations": matching_pats,
                }
            )

        # If general network question without a specific account, include top patterns
        if not relevant_pattern_indices and _question_requests_network(question):
            relevant_pattern_indices = list(
                range(1, min(len(all_patterns), MAX_NETWORK_PATTERNS) + 1)
            )

        pattern_entries = [
            _build_pattern_entry(
                idx,
                all_patterns[idx - 1],
                ref_to_txn_id=ref_to_txn_id,
                sanitizer=sanitizer,
                registry=registry,
            )
            for idx in relevant_pattern_indices[:MAX_NETWORK_PATTERNS]
            if 1 <= idx <= len(all_patterns)
        ]

        context_payload["network"] = {
            "total_accounts_in_graph": graph.number_of_nodes(),
            "total_transactions_in_graph": graph.number_of_edges(),
            "total_detected_patterns": len(all_patterns),
            "account_profiles": account_profiles,
            "detected_patterns": pattern_entries,
        }
        standard_limitations.append(
            "Network graph patterns identify structural transaction leads only and do not establish coordinated fraud or criminal intent."
        )
        if not suggested_questions:
            suggested_questions.extend(
                [
                    "Which accounts are connected within 1-2 hops of this account?",
                    "Explain the suspicious structural network patterns detected here.",
                    "What corroborating records should be verified before escalation?",
                ]
            )

    # C. Invoice Context
    if target_invoice_ids:
        invoices = (
            db.execute(
                select(Invoice)
                .options(selectinload(Invoice.findings))
                .where(Invoice.id.in_(target_invoice_ids))
            )
            .scalars()
            .all()
        )
        found_inv_ids = {inv.id for inv in invoices}
        for missing_id in target_invoice_ids:
            if missing_id not in found_inv_ids:
                raise ContextNotFoundError(f"Invoice with ID {missing_id} was not found.")

        scopes_used.append("invoice")
        invoice_entries = [
            _build_invoice_entry(inv, sanitizer=sanitizer, registry=registry) for inv in invoices
        ]
        context_payload["invoices"] = invoice_entries
        if any(not inv.ocr_available or inv.extraction_status == "OCR_UNAVAILABLE" for inv in invoices):
            standard_limitations.append(
                "Tesseract OCR was unavailable for one or more scanned/image invoices; missing fields reflect extraction limits rather than verified absences."
            )
        standard_limitations.append(
            "Invoice findings come from deterministic arithmetic, date, completeness, and duplicate checks; raw uploaded files are never transmitted."
        )
        if not suggested_questions:
            suggested_questions.extend(
                [
                    "Explain the deterministic findings raised for this invoice.",
                    "Were any invoice fields manually corrected versus extracted?",
                    "Does limited OCR availability restrict automated review on this document?",
                ]
            )

    # D. Cross-Investigation Context (triggered for comparative queries or general dashboard questions)
    need_cross = (
        not target_txn_ids and not target_invoice_ids and not clean_account_id
    ) or _question_requests_cross(question)

    if need_cross:
        scopes_used.append("cross_investigation")
        total_txns = db.scalar(select(func.count(Transaction.id))) or 0
        total_invoices = db.scalar(select(func.count(Invoice.id))) or 0

        recent_txns = (
            db.execute(
                select(Transaction)
                .options(
                    selectinload(Transaction.investigations).selectinload(Investigation.evidences)
                )
                .order_by(Transaction.risk_score.desc(), Transaction.timestamp.desc(), Transaction.id.desc())
                .limit(MAX_CROSS_TRANSACTIONS)
            )
            .scalars()
            .all()
        )

        # Register transactions and collect shared indicator/account counts
        indicator_counter: Counter[str] = Counter()
        cross_txn_summaries: list[dict[str, Any]] = []
        account_txn_counts: Counter[str] = Counter()

        for txn in recent_txns:
            sender_alias = sanitizer.alias_account(txn.sender_id) or "ACCT_UNKNOWN"
            receiver_alias = sanitizer.alias_account(txn.receiver_id) or "ACCT_UNKNOWN"
            sanitizer.alias_transaction_ref(txn.reference, txn.id)

            txn_cid = f"TXN:{txn.id}"
            _register_citation(
                registry,
                citation_id=txn_cid,
                record_type="transaction",
                record_id=str(txn.id),
                label=f"Transaction #{txn.id} ({txn.risk_level or 'UNSCORED'})",
                excerpt=(
                    f"Amount {txn.amount} {txn.currency} ({sender_alias} -> {receiver_alias}); "
                    f"score={txn.risk_score}, status={txn.investigation_status}."
                ),
            )
            account_txn_counts[sender_alias] += 1
            account_txn_counts[receiver_alias] += 1

            ev_types: list[str] = []
            for inv in txn.investigations:
                for ev in inv.evidences:
                    ev_types.append(ev.evidence_type)
                    indicator_counter[ev.evidence_type] += 1

            cross_txn_summaries.append(
                {
                    "citation_id": txn_cid,
                    "transaction_id": txn.id,
                    "sender_account_ref": sender_alias,
                    "receiver_account_ref": receiver_alias,
                    "amount": _format_decimal(txn.amount),
                    "currency": txn.currency,
                    "risk_score": txn.risk_score,
                    "risk_level": txn.risk_level,
                    "investigation_status": txn.investigation_status,
                    "evidence_types": sorted(set(ev_types)),
                }
            )

        invoice_summaries: list[dict[str, Any]] = []
        if not target_invoice_ids and (_question_requests_invoice(question) or not target_txn_ids):
            recent_invoices = (
                db.execute(
                    select(Invoice)
                    .options(selectinload(Invoice.findings))
                    .order_by(Invoice.created_at.desc(), Invoice.id.desc())
                    .limit(MAX_CROSS_INVOICES)
                )
                .scalars()
                .all()
            )
            for inv in recent_invoices:
                vendor_alias = sanitizer.alias_vendor(inv.vendor_name)
                inv_cid = f"INVOICE:{inv.id}"
                _register_citation(
                    registry,
                    citation_id=inv_cid,
                    record_type="invoice",
                    record_id=str(inv.id),
                    label=f"Invoice #{inv.id} ({inv.investigation_status})",
                    excerpt=(
                        f"type={inv.file_type}, extraction={inv.extraction_status}, "
                        f"ocr={inv.ocr_available}, findings={[f.finding_code for f in inv.findings]}."
                    ),
                )
                invoice_summaries.append(
                    {
                        "citation_id": inv_cid,
                        "invoice_id": inv.id,
                        "vendor_ref": vendor_alias,
                        "extraction_status": inv.extraction_status,
                        "investigation_status": inv.investigation_status,
                        "ocr_available": inv.ocr_available,
                        "finding_codes": [f.finding_code for f in inv.findings],
                    }
                )

        cross_cid = "CROSS:OVERVIEW"
        _register_citation(
            registry,
            citation_id=cross_cid,
            record_type="cross_investigation",
            record_id="overview",
            label="Cross-Investigation Summary",
            excerpt=(
                f"Total transactions={total_txns}, total invoices={total_invoices}, "
                f"shared evidence counts={dict(indicator_counter)}."
            ),
        )

        context_payload["cross_investigation"] = {
            "citation_id": cross_cid,
            "total_transactions_in_db": total_txns,
            "total_invoices_in_db": total_invoices,
            "sampled_high_risk_or_recent_transactions": cross_txn_summaries,
            "shared_evidence_type_counts_in_sample": dict(indicator_counter),
            "repeated_account_refs_in_sample": {
                acct: cnt for acct, cnt in account_txn_counts.items() if cnt > 1
            },
            "recent_invoices": invoice_summaries,
        }
        if not standard_limitations:
            standard_limitations.append(
                "Cross-investigation context inspects a bounded sample of recent/high-risk records rather than executing unrestricted database scans."
            )
        if not suggested_questions:
            suggested_questions.extend(
                [
                    "What common risk indicators appear across the highest-risk transactions?",
                    "Which accounts appear repeatedly across multiple flagged investigations?",
                    "Summarize open investigation priorities and recommended next checks.",
                ]
            )

    # Deduplicate limitations and suggestions preserving order
    unique_limitations = list(dict.fromkeys(standard_limitations))
    unique_suggestions = list(dict.fromkeys(suggested_questions))[:4]

    return AssistantContextBundle(
        scopes_used=list(dict.fromkeys(scopes_used)),
        sanitized_context=context_payload,
        allowed_citations=registry,
        standard_limitations=unique_limitations,
        default_suggested_questions=unique_suggestions,
        pseudonym_map=sanitizer.reverse_account_map,
    )
