"""
FraudTrace AI — Database Models
================================
SQLAlchemy 2.x declarative models representing:
1. Transaction   — Payment / financial transaction records with fraud risk indicators.
2. Investigation — In-depth fraud investigations tied to suspicious transactions.
3. Evidence      — Specific rule violations, graph anomaly findings, or signals.
"""

from datetime import datetime, timezone
from decimal import Decimal
from typing import Optional

from sqlalchemy import Boolean, DateTime, Float, ForeignKey, Integer, Numeric, String, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.database import Base


def utc_now() -> datetime:
    """Helper to return current timezone-aware UTC datetime."""
    return datetime.now(timezone.utc)


class Transaction(Base):
    """
    Transaction Model
    -----------------
    Represents a payment or transfer event evaluated by FraudTrace AI.
    Amount is stored as Numeric(18, 2) for exact financial precision without
    floating-point rounding errors.
    """
    __tablename__ = "transactions"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    reference: Mapped[str] = mapped_column(String(64), unique=True, index=True, nullable=False)
    sender_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    receiver_id: Mapped[str] = mapped_column(String(128), index=True, nullable=False)
    amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    currency: Mapped[str] = mapped_column(String(10), default="USD", nullable=False)
    timestamp: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Fraud scoring attributes
    risk_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    risk_level: Mapped[Optional[str]] = mapped_column(String(32), nullable=True)  # LOW, MEDIUM, HIGH, CRITICAL
    investigation_status: Mapped[str] = mapped_column(
        String(32), default="UNINVESTIGATED", nullable=False
    )  # UNINVESTIGATED, UNDER_REVIEW, FLAGGED, CLEARED

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    # Relationships: One Transaction can have one or more Investigations
    investigations: Mapped[list["Investigation"]] = relationship(
        back_populates="transaction", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Transaction(id={self.id}, ref='{self.reference}', amount={self.amount:.2f} {self.currency}, "
            f"risk_level='{self.risk_level}', status='{self.investigation_status}')>"
        )


class Investigation(Base):
    """
    Investigation Model
    -------------------
    Represents an active or historical fraud inquiry on a transaction.
    """
    __tablename__ = "investigations"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    transaction_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("transactions.id", ondelete="CASCADE"), index=True, nullable=False
    )
    status: Mapped[str] = mapped_column(
        String(32), default="OPEN", nullable=False
    )  # OPEN, IN_PROGRESS, CLOSED, ESCALATED
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    priority: Mapped[str] = mapped_column(String(32), default="NORMAL", nullable=False)

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    # Relationships
    transaction: Mapped["Transaction"] = relationship(back_populates="investigations")
    evidences: Mapped[list["Evidence"]] = relationship(
        back_populates="investigation", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return f"<Investigation(id={self.id}, txn_id={self.transaction_id}, status='{self.status}')>"


class Evidence(Base):
    """
    Evidence Model
    --------------
    Stores distinct pieces of evidence or signals detected for an investigation.
    """
    __tablename__ = "evidences"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    investigation_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("investigations.id", ondelete="CASCADE"), index=True, nullable=False
    )
    evidence_type: Mapped[str] = mapped_column(
        String(64), nullable=False
    )  # e.g. "AMOUNT_ANOMALY", "GRAPH_CLUSTER", "RAPID_VELOCITY", "DOCUMENT_MISMATCH"
    description: Mapped[str] = mapped_column(Text, nullable=False)
    severity: Mapped[str] = mapped_column(
        String(32), default="MEDIUM", nullable=False
    )  # LOW, MEDIUM, HIGH, CRITICAL

    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=utc_now, nullable=False)

    # Relationships
    investigation: Mapped["Investigation"] = relationship(back_populates="evidences")

    def __repr__(self) -> str:
        return (
            f"<Evidence(id={self.id}, inv_id={self.investigation_id}, "
            f"type='{self.evidence_type}', severity='{self.severity}')>"
        )


class Invoice(Base):
    """
    Invoice Model
    -------------
    Stores sanitized invoice metadata, extraction outcomes, separated user
    corrections metadata, and investigative review status. Original uploaded
    document bytes are never stored.
    """
    __tablename__ = "invoices"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    submission_reference: Mapped[Optional[str]] = mapped_column(
        String(128), unique=True, index=True, nullable=True
    )
    original_filename: Mapped[str] = mapped_column(String(255), nullable=False)
    file_type: Mapped[str] = mapped_column(String(16), nullable=False)
    file_size_bytes: Mapped[int] = mapped_column(Integer, nullable=False)
    page_count: Mapped[Optional[int]] = mapped_column(Integer, nullable=True)
    ocr_available: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    vendor_name: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)
    normalized_vendor_name: Mapped[Optional[str]] = mapped_column(
        String(255), index=True, nullable=True
    )
    invoice_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    normalized_invoice_number: Mapped[Optional[str]] = mapped_column(
        String(128), index=True, nullable=True
    )
    invoice_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    due_date: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    currency: Mapped[Optional[str]] = mapped_column(String(10), nullable=True)

    subtotal: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 2), nullable=True)
    tax: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 2), nullable=True)
    total_amount: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 2), nullable=True)
    po_number: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)

    extraction_status: Mapped[str] = mapped_column(String(64), nullable=False)
    investigation_status: Mapped[str] = mapped_column(String(64), nullable=False)
    summary: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    field_metadata_json: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )

    findings: Mapped[list["InvoiceFinding"]] = relationship(
        back_populates="invoice", cascade="all, delete-orphan"
    )

    def __repr__(self) -> str:
        return (
            f"<Invoice(id={self.id}, filename='{self.original_filename}', "
            f"vendor='{self.vendor_name}', invoice_number='{self.invoice_number}', "
            f"status='{self.investigation_status}')>"
        )


class InvoiceFinding(Base):
    """
    InvoiceFinding Model
    --------------------
    Stores deterministic invoice investigation findings tied to an Invoice record.
    """
    __tablename__ = "invoice_findings"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    invoice_id: Mapped[int] = mapped_column(
        Integer, ForeignKey("invoices.id", ondelete="CASCADE"), index=True, nullable=False
    )
    finding_code: Mapped[str] = mapped_column(String(64), nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="MEDIUM", nullable=False)
    explanation: Mapped[str] = mapped_column(Text, nullable=False)
    supporting_values: Mapped[Optional[str]] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )

    invoice: Mapped["Invoice"] = relationship(back_populates="findings")

    def __repr__(self) -> str:
        return (
            f"<InvoiceFinding(id={self.id}, invoice_id={self.invoice_id}, "
            f"code='{self.finding_code}', severity='{self.severity}')>"
        )


class PayPalOrder(Base):
    """
    PayPalOrder Model
    -----------------
    Stores PayPal Sandbox Orders v2 lifecycle identifiers, validated requested/captured
    amounts, and at-most-one link to an evaluated FraudTrace Transaction.
    Never stores OAuth access tokens, client secrets, or sensitive card/payer credentials.
    """
    __tablename__ = "paypal_orders"

    id: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    internal_reference: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    paypal_order_id: Mapped[str] = mapped_column(
        String(64), unique=True, index=True, nullable=False
    )
    paypal_capture_id: Mapped[Optional[str]] = mapped_column(
        String(64), unique=True, index=True, nullable=True
    )
    intent: Mapped[str] = mapped_column(String(16), default="CAPTURE", nullable=False)
    status: Mapped[str] = mapped_column(String(32), default="CREATED", nullable=False)

    requested_amount: Mapped[Decimal] = mapped_column(Numeric(18, 2), nullable=False)
    captured_amount: Mapped[Optional[Decimal]] = mapped_column(Numeric(18, 2), nullable=True)
    currency: Mapped[str] = mapped_column(String(10), default="USD", nullable=False)

    sender_id: Mapped[Optional[str]] = mapped_column(String(128), nullable=True)
    receiver_id: Mapped[str] = mapped_column(
        String(128), default="FRAUDTRACE_SANDBOX_MERCHANT", nullable=False
    )
    payer_id: Mapped[Optional[str]] = mapped_column(String(64), nullable=True)
    approval_url: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    transaction_id: Mapped[Optional[int]] = mapped_column(
        Integer,
        ForeignKey("transactions.id", ondelete="SET NULL"),
        unique=True,
        index=True,
        nullable=True,
    )

    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=utc_now, onupdate=utc_now, nullable=False
    )
    captured_at: Mapped[Optional[datetime]] = mapped_column(
        DateTime(timezone=True), nullable=True
    )

    transaction: Mapped[Optional["Transaction"]] = relationship()

    def __repr__(self) -> str:
        return (
            f"<PayPalOrder(id={self.id}, internal_ref='{self.internal_reference}', "
            f"order_id='{self.paypal_order_id}', status='{self.status}', txn_id={self.transaction_id})>"
        )
