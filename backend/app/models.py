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

from sqlalchemy import DateTime, Float, ForeignKey, Integer, Numeric, String, Text
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
