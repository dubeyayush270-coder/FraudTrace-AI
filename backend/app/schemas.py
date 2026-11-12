"""
FraudTrace AI — API Request and Response Schemas
=================================================
Pydantic schemas for data validation, serialization, and OpenAPI documentation.
"""

from datetime import datetime
from decimal import Decimal
from typing import Any, Optional

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.services.paypal_client import (
    get_allowed_paypal_redirect_hosts,
    validate_paypal_redirect_url,
)


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


# ---------------------------------------------------------------------------
# PayPal Sandbox Orders v2 Integration Schemas
# ---------------------------------------------------------------------------

SUPPORTED_PAYPAL_CURRENCIES = frozenset({"USD", "EUR", "GBP", "CAD", "AUD", "CHF", "SGD"})
MAX_PAYPAL_ORDER_AMOUNT = Decimal("100000.00")


class PayPalOrderCreateRequest(BaseModel):
    """Validated payload for creating a PayPal Sandbox checkout order (intent=CAPTURE)."""
    model_config = ConfigDict(str_strip_whitespace=True)

    amount: Decimal = Field(
        ...,
        ge=Decimal("0.01"),
        le=MAX_PAYPAL_ORDER_AMOUNT,
        description="Positive payment amount (0.01 to 100000.00, max 2 decimal places)",
    )
    currency: str = Field(
        default="USD",
        min_length=3,
        max_length=3,
        description="Supported 3-letter ISO currency code",
    )
    internal_reference: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=64,
        description="Optional idempotency / internal trace reference",
    )
    sender_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Optional internal sender account identifier for FraudTrace evaluation",
    )
    receiver_id: str = Field(
        default="FRAUDTRACE_SANDBOX_MERCHANT",
        min_length=1,
        max_length=128,
        description="Recipient merchant/account identifier for FraudTrace evaluation",
    )
    return_url: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="Optional validated buyer approval return URL (defaults to configured local dev URL)",
    )
    cancel_url: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=2048,
        description="Optional validated buyer checkout cancel URL (defaults to configured local dev URL)",
    )

    @field_validator("amount")
    @classmethod
    def validate_amount_scale(cls, v: Decimal) -> Decimal:
        if not v.is_finite():
            raise ValueError("Amount must be a finite decimal number.")
        exponent = v.as_tuple().exponent
        if isinstance(exponent, int) and exponent < -2:
            raise ValueError("Amount cannot have more than 2 decimal places.")
        return v.quantize(Decimal("0.01"))

    @field_validator("currency")
    @classmethod
    def validate_supported_currency(cls, v: str) -> str:
        clean = v.strip().upper()
        if len(clean) != 3 or not clean.isalpha() or clean not in SUPPORTED_PAYPAL_CURRENCIES:
            supported = ", ".join(sorted(SUPPORTED_PAYPAL_CURRENCIES))
            raise ValueError(f"Unsupported currency '{clean}'. Supported currencies: {supported}.")
        return clean

    @field_validator("internal_reference")
    @classmethod
    def validate_internal_reference(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            raise ValueError("internal_reference cannot be blank.")
        if not all(ch.isalnum() or ch in "_-" for ch in clean):
            raise ValueError("internal_reference may only contain letters, digits, hyphens, and underscores.")
        return clean

    @field_validator("sender_id")
    @classmethod
    def validate_sender_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            raise ValueError("sender_id cannot be blank.")
        return clean

    @field_validator("receiver_id")
    @classmethod
    def validate_receiver_id(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("receiver_id cannot be blank.")
        return clean

    @field_validator("return_url", "cancel_url")
    @classmethod
    def validate_redirect_urls(cls, v: Optional[str], info: Any) -> Optional[str]:
        if v is None:
            return None
        allowed_hosts = get_allowed_paypal_redirect_hosts()
        return validate_paypal_redirect_url(
            v,
            field_name=str(getattr(info, "field_name", "redirect_url")),
            allowed_hosts=allowed_hosts,
        )


class PayPalOrderSummaryResponse(BaseModel):
    """Non-sensitive persisted PayPal Sandbox order metadata."""
    model_config = ConfigDict(from_attributes=True)

    id: int
    internal_reference: str
    paypal_order_id: str
    paypal_capture_id: Optional[str] = None
    intent: str
    status: str
    requested_amount: Decimal
    captured_amount: Optional[Decimal] = None
    currency: str
    sender_id: Optional[str] = None
    receiver_id: str
    payer_id: Optional[str] = None
    approval_url: Optional[str] = None
    transaction_id: Optional[int] = None
    created_at: datetime
    updated_at: datetime
    captured_at: Optional[datetime] = None


class PayPalOrderCreateResponse(BaseModel):
    """Response returned upon creating or idempotently replaying a PayPal Sandbox order."""

    internal_reference: str
    paypal_order_id: str
    status: str
    intent: str
    amount: Decimal
    currency: str
    approval_url: Optional[str] = None
    idempotent_replay: bool = False
    created_at: datetime
    message: str


class PayPalCaptureResponse(BaseModel):
    """Response returned after capturing an approved PayPal Sandbox order and evaluating FraudTrace risk."""

    paypal_order: PayPalOrderSummaryResponse
    already_captured: bool = False
    transaction_analysis: TransactionAnalyzeResponse
    message: str


# ---------------------------------------------------------------------------
# AI Investigation Assistant Schemas
# ---------------------------------------------------------------------------

MAX_ASSISTANT_MESSAGE_CHARS = 2000


class AssistantChatRequest(BaseModel):
    """Stateless investigation question scoped to FraudTrace AI records."""

    model_config = ConfigDict(extra="forbid", str_strip_whitespace=True)

    message: str = Field(
        ...,
        min_length=1,
        max_length=MAX_ASSISTANT_MESSAGE_CHARS,
        description="Investigator question about existing FraudTrace AI records",
    )
    transaction_id: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional Transaction ID context selector",
    )
    investigation_id: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional Investigation ID context selector",
    )
    invoice_id: Optional[int] = Field(
        default=None,
        ge=1,
        description="Optional Invoice ID context selector",
    )
    account_id: Optional[str] = Field(
        default=None,
        min_length=1,
        max_length=128,
        description="Optional Account ID context selector",
    )

    @field_validator("message")
    @classmethod
    def validate_message_content(cls, v: str) -> str:
        clean = v.strip()
        if not clean:
            raise ValueError("Assistant question cannot be empty or whitespace only.")
        if any(ord(ch) < 32 and ch not in ("\n", "\t", "\r") for ch in clean):
            raise ValueError("Assistant question contains unsupported control characters.")
        return clean

    @field_validator("account_id")
    @classmethod
    def validate_account_id(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return None
        clean = v.strip()
        if not clean:
            raise ValueError("account_id cannot be blank.")
        if any(ord(ch) < 32 for ch in clean):
            raise ValueError("account_id contains invalid control characters.")
        return clean


class AssistantCitationResponse(BaseModel):
    """Verified evidence citation referencing a retrieved FraudTrace record."""

    citation_id: str
    record_type: str
    record_id: str
    label: str
    claim: str
    excerpt: str


class AssistantChatResponse(BaseModel):
    """Structured, evidence-grounded response returned by POST /api/v1/assistant/chat."""

    answer: str
    citations: list[AssistantCitationResponse] = []
    suggested_questions: list[str] = []
    limitations: list[str] = []
    provider: str
    model: str
    request_id: str


class AssistantStatusResponse(BaseModel):
    """Non-sensitive AI assistant configuration readiness summary."""

    enabled: bool
    ready: bool
    provider: str
    model: str
    data_classification: str
    privacy_policy_ok: bool
    status_code: str
    message: str
