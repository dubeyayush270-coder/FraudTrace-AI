"""
FraudTrace AI — API Request and Response Schemas
=================================================
Pydantic schemas for data validation, serialization, and OpenAPI documentation.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator


class TransactionAnalyzeRequest(BaseModel):
    """Payload for submitting and evaluating a transaction."""
    reference: str = Field(..., min_length=1, max_length=64, description="Unique transaction reference ID")
    sender_id: str = Field(..., min_length=1, max_length=128, description="Sender account or entity identifier")
    receiver_id: str = Field(..., min_length=1, max_length=128, description="Recipient account or entity identifier")
    amount: Decimal = Field(..., gt=Decimal("0.00"), description="Transaction amount (must be positive)")
    currency: str = Field(default="USD", min_length=3, max_length=3, description="3-letter ISO currency code")
    timestamp: Optional[datetime] = Field(default=None, description="Transaction timestamp (UTC). Defaults to current time if omitted.")

    @field_validator("currency")
    @classmethod
    def validate_currency(cls, v: str) -> str:
        clean = v.strip().upper()
        if len(clean) != 3 or not clean.isalpha():
            raise ValueError("Currency must be a 3-letter alphabetic ISO code (e.g. USD, EUR, GBP)")
        return clean

    @field_validator("reference", "sender_id", "receiver_id")
    @classmethod
    def validate_non_empty_strings(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Identifier field cannot be blank or only whitespace")
        return clean


class EvidenceResponse(BaseModel):
    """Schema representing an individual evidence finding."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    evidence_type: str
    description: str
    severity: str
    created_at: datetime


class InvestigationResponse(BaseModel):
    """Schema representing an investigation record with child evidence."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    status: str
    summary: Optional[str] = None
    priority: str
    created_at: datetime
    evidences: list[EvidenceResponse] = []


class TransactionResponse(BaseModel):
    """Schema representing a transaction record."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    reference: str
    sender_id: str
    receiver_id: str
    amount: Decimal
    currency: str
    timestamp: datetime
    risk_score: Optional[float] = None
    risk_level: Optional[str] = None
    investigation_status: str
    created_at: datetime


class FeatureDeviationResponse(BaseModel):
    """Descriptive statistical feature deviation relative to prior causal history."""
    feature_name: str
    display_label: str
    target_value: float
    training_mean: float
    training_std: float
    z_score_deviation: Optional[float] = None
    summary: str


class MLAnomalyResponse(BaseModel):
    """Experimental IsolationForest outlier metadata (never a fraud probability)."""
    available: bool
    status: str
    experimental: bool = True
    model_name: str
    random_state: int
    is_anomaly: Optional[bool] = None
    decision_score: Optional[float] = None
    score_interpretation: str
    training_sample_count: int
    minimum_samples_required: int
    features_used: list[str] = []
    feature_deviations: list[FeatureDeviationResponse] = []
    explanation: str
    methodology_note: str
    limitations: str


class TransactionAnalyzeResponse(BaseModel):
    """Complete analysis outcome returned to client upon evaluating a transaction."""
    transaction: TransactionResponse
    risk_score: float
    risk_level: str
    investigation_status: str
    investigation: Optional[InvestigationResponse] = None
    evidence: list[EvidenceResponse] = []
    explanation: str
    ml_anomaly: Optional[MLAnomalyResponse] = None


class TransactionDetailResponse(TransactionResponse):
    """Detailed transaction response including full investigation history and evidence."""
    investigations: list[InvestigationResponse] = []
    ml_anomaly: Optional[MLAnomalyResponse] = None


class TransactionListResponse(BaseModel):
    """Paginated list of transactions."""
    items: list[TransactionResponse]
    total: int
    limit: int
    offset: int



# ---------------------------------------------------------------------------
# Fraud Network Intelligence Schemas
# ---------------------------------------------------------------------------

class NetworkPatternResponse(BaseModel):
    """Schema describing a structural fraud network pattern / investigation lead."""
    pattern_type: str
    involved_accounts: list[str]
    transaction_references: list[str]
    explanation: str
    severity: str
    supporting_counts: dict[str, int]
    timestamps: list[datetime]


class ConnectedAccountResponse(BaseModel):
    """Schema describing an account connected to a target within 1–2 graph hops."""
    account_id: str
    hop_distance: int
    relationship: str


class NetworkOverviewResponse(BaseModel):
    """High-level overview of the transaction network and detected leads."""
    total_accounts: int
    total_transactions: int
    connected_components: int
    suspicious_patterns_detected: int
    suspicious_account_identifiers: list[str]
    patterns_summary: dict[str, int]


class AccountNetworkResponse(BaseModel):
    """Detailed network graph intelligence profile for a single account."""
    account_id: str
    incoming_transaction_count: int
    outgoing_transaction_count: int
    connected_accounts: list[ConnectedAccountResponse]
    relevant_patterns: list[NetworkPatternResponse]
    related_transaction_references: list[str]


class NetworkPatternListResponse(BaseModel):
    """Paginated list of detected suspicious network patterns."""
    items: list[NetworkPatternResponse]
    total: int
    limit: int
    offset: int


# ---------------------------------------------------------------------------
# Invoice Investigation Schemas
# ---------------------------------------------------------------------------

class ExtractedFieldResponse(BaseModel):
    """Preserves original extracted value separately from user-supplied correction."""
    field_name: str
    extracted_value: Optional[str] = None
    corrected_value: Optional[str] = None
    effective_value: Optional[str] = None
    extraction_status: str
    confidence: str


class InvoiceFindingResponse(BaseModel):
    """Deterministic finding emitted by the invoice investigation engine."""
    model_config = ConfigDict(from_attributes=True)

    id: Optional[int] = None
    finding_code: str
    severity: str
    explanation: str
    supporting_values: dict[str, Any] = {}
    created_at: Optional[datetime] = None


class InvoiceSummaryResponse(BaseModel):
    """Summary metadata and assessment status for a persisted invoice."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    submission_reference: Optional[str] = None
    original_filename: str
    file_type: str
    file_size_bytes: int
    page_count: Optional[int] = None
    ocr_available: bool
    vendor_name: Optional[str] = None
    normalized_vendor_name: Optional[str] = None
    invoice_number: Optional[str] = None
    normalized_invoice_number: Optional[str] = None
    invoice_date: Optional[str] = None
    due_date: Optional[str] = None
    currency: Optional[str] = None
    subtotal: Optional[Decimal] = None
    tax: Optional[Decimal] = None
    total_amount: Optional[Decimal] = None
    po_number: Optional[str] = None
    extraction_status: str
    investigation_status: str
    summary: Optional[str] = None
    findings_count: int = 0
    created_at: datetime
    updated_at: datetime


class InvoiceDetailResponse(InvoiceSummaryResponse):
    """Full invoice investigation detail including per-field statuses and findings."""
    extraction_note: Optional[str] = None
    fields: list[ExtractedFieldResponse] = []
    findings: list[InvoiceFindingResponse] = []


class InvoiceAnalyzeResponse(BaseModel):
    """Response payload returned after uploading and analyzing an invoice."""
    invoice: InvoiceSummaryResponse
    fields: list[ExtractedFieldResponse] = []
    findings: list[InvoiceFindingResponse] = []
    extraction_note: str


class InvoiceListResponse(BaseModel):
    """Paginated invoice investigation history."""
    items: list[InvoiceSummaryResponse]
    total: int
    limit: int
    offset: int
