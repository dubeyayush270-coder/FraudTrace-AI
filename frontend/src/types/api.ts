/**
 * FraudTrace AI — Backend API TypeScript Interfaces
 * Exact contracts matching FastAPI Pydantic schemas in backend/app/schemas.py
 */

export interface HealthResponse {
  status: string
}

export interface DatabaseHealthResponse {
  status: string
  database: string
}

export interface TransactionAnalyzeRequest {
  reference: string
  sender_id: string
  receiver_id: string
  amount: string | number
  currency: string
  timestamp?: string
}

export interface EvidenceResponse {
  id: number | null
  evidence_type: string
  description: string
  severity: string
  created_at: string
}

export interface InvestigationResponse {
  id: number | null
  status: string
  summary: string | null
  priority: string
  created_at: string
  evidences: EvidenceResponse[]
}

export interface TransactionResponse {
  id: number
  reference: string
  sender_id: string
  receiver_id: string
  amount: string | number
  currency: string
  timestamp: string
  risk_score: number | null
  risk_level: string | null
  investigation_status: string
  created_at: string
}

export interface FeatureDeviation {
  feature_name: string
  display_label: string
  target_value: number
  training_mean: number
  training_std: number
  z_score_deviation: number | null
  summary: string
}

export interface MLAnomalyResponse {
  available: boolean
  status: string
  experimental: boolean
  model_name: string
  random_state: number
  is_anomaly: boolean | null
  decision_score: number | null
  score_interpretation: string
  training_sample_count: number
  minimum_samples_required: number
  features_used: string[]
  feature_deviations: FeatureDeviation[]
  explanation: string
  methodology_note: string
  limitations: string
}

export interface TransactionAnalyzeResponse {
  transaction: TransactionResponse
  risk_score: number
  risk_level: string
  investigation_status: string
  investigation: InvestigationResponse | null
  evidence: EvidenceResponse[]
  explanation: string
  ml_anomaly?: MLAnomalyResponse | null
}

export interface TransactionDetailResponse extends TransactionResponse {
  investigations: InvestigationResponse[]
  ml_anomaly?: MLAnomalyResponse | null
}

export interface TransactionListResponse {
  items: TransactionResponse[]
  total: number
  limit: number
  offset: number
}

export interface NetworkPatternResponse {
  pattern_type: string
  involved_accounts: string[]
  transaction_references: string[]
  explanation: string
  severity: string
  supporting_counts: Record<string, number>
  timestamps: string[]
}

export interface ConnectedAccountResponse {
  account_id: string
  hop_distance: number
  relationship: string
}

export interface NetworkOverviewResponse {
  total_accounts: number
  total_transactions: number
  connected_components: number
  suspicious_patterns_detected: number
  suspicious_account_identifiers: string[]
  patterns_summary: Record<string, number>
}

export interface AccountNetworkResponse {
  account_id: string
  incoming_transaction_count: number
  outgoing_transaction_count: number
  connected_accounts: ConnectedAccountResponse[]
  relevant_patterns: NetworkPatternResponse[]
  related_transaction_references: string[]
}

export interface NetworkPatternListResponse {
  items: NetworkPatternResponse[]
  total: number
  limit: number
  offset: number
}

export interface ExtractedFieldMetadata {
  field_name: string
  extracted_value: string | null
  corrected_value: string | null
  effective_value: string | null
  extraction_status: string
  confidence: string
}

export interface InvoiceFindingResponse {
  id?: number | null
  finding_code: string
  severity: string
  explanation: string
  supporting_values: Record<string, unknown>
  created_at?: string | null
}

export interface InvoiceSummaryResponse {
  id: number
  submission_reference: string | null
  original_filename: string
  file_type: string
  file_size_bytes: number
  page_count: number | null
  ocr_available: boolean
  vendor_name: string | null
  normalized_vendor_name: string | null
  invoice_number: string | null
  normalized_invoice_number: string | null
  invoice_date: string | null
  due_date: string | null
  currency: string | null
  subtotal: string | null
  tax: string | null
  total_amount: string | null
  po_number: string | null
  extraction_status: string
  investigation_status: string
  summary: string | null
  findings_count: number
  created_at: string
  updated_at: string
}

export interface InvoiceDetailResponse extends InvoiceSummaryResponse {
  extraction_note?: string | null
  fields: ExtractedFieldMetadata[]
  findings: InvoiceFindingResponse[]
}

export interface InvoiceAnalyzeResponse {
  invoice: InvoiceSummaryResponse
  fields: ExtractedFieldMetadata[]
  findings: InvoiceFindingResponse[]
  extraction_note: string
}

export interface InvoiceListResponse {
  items: InvoiceSummaryResponse[]
  total: number
  limit: number
  offset: number
}
