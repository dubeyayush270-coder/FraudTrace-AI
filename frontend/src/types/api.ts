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

export interface TransactionAnalyzeResponse {
  transaction: TransactionResponse
  risk_score: number
  risk_level: string
  investigation_status: string
  investigation: InvestigationResponse | null
  evidence: EvidenceResponse[]
  explanation: string
}

export interface TransactionDetailResponse extends TransactionResponse {
  investigations: InvestigationResponse[]
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
