/**
 * FraudTrace AI — Centralized Backend API Client
 * Reads VITE_API_URL with local FastAPI fallback (http://127.0.0.1:8000).
 */

import type {
  AccountNetworkResponse,
  AssistantChatRequest,
  AssistantChatResponse,
  AssistantStatusResponse,
  DatabaseHealthResponse,
  HealthResponse,
  InvoiceAnalyzeResponse,
  InvoiceDetailResponse,
  InvoiceListResponse,
  NetworkOverviewResponse,
  NetworkPatternListResponse,
  TransactionAnalyzeRequest,
  TransactionAnalyzeResponse,
  TransactionDetailResponse,
  TransactionListResponse,
} from '../types/api'

export const API_BASE_URL: string =
  import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

export class ApiClientError extends Error {
  status: number
  isNetworkError: boolean

  constructor(message: string, status = 0, isNetworkError = false) {
    super(message)
    this.name = 'ApiClientError'
    this.status = status
    this.isNetworkError = isNetworkError
  }
}

interface ValidationDetailItem {
  loc?: Array<string | number>
  msg?: string
}

function extractErrorMessage(payload: unknown, fallback: string): string {
  if (!payload || typeof payload !== 'object') {
    return fallback
  }

  const record = payload as { detail?: unknown }
  if (typeof record.detail === 'string' && record.detail.trim().length > 0) {
    return record.detail
  }

  if (Array.isArray(record.detail) && record.detail.length > 0) {
    const messages = record.detail
      .map((item) => {
        if (!item || typeof item !== 'object') return null
        const entry = item as ValidationDetailItem
        const field = Array.isArray(entry.loc)
          ? String(entry.loc[entry.loc.length - 1] ?? 'field')
          : 'input'
        const msg = entry.msg ?? 'invalid value'
        return `${field}: ${msg}`
      })
      .filter((msg): msg is string => msg !== null)
    if (messages.length > 0) {
      return messages.join(' | ')
    }
  }

  return fallback
}

async function requestJson<T>(
  path: string,
  options?: RequestInit,
): Promise<T> {
  let response: Response
  try {
    response = await fetch(`${API_BASE_URL}${path}`, {
      headers: {
        Accept: 'application/json',
        ...(options?.body && !(options.body instanceof FormData)
          ? { 'Content-Type': 'application/json' }
          : {}),
        ...options?.headers,
      },
      ...options,
    })
  } catch {
    throw new ApiClientError(
      `Unable to reach FraudTrace AI backend at ${API_BASE_URL}. Ensure FastAPI is running.`,
      0,
      true,
    )
  }

  let parsedBody: unknown = null
  try {
    parsedBody = await response.json()
  } catch {
    // Response may not contain valid JSON
  }

  if (!response.ok) {
    const message = extractErrorMessage(
      parsedBody,
      `Request failed with HTTP ${response.status}`,
    )
    throw new ApiClientError(message, response.status, false)
  }

  if (parsedBody === null) {
    throw new ApiClientError('Received empty or invalid JSON from backend.', response.status, false)
  }

  return parsedBody as T
}

export async function checkHealth(): Promise<HealthResponse> {
  return requestJson<HealthResponse>('/health')
}

export async function checkDatabaseHealth(): Promise<DatabaseHealthResponse> {
  return requestJson<DatabaseHealthResponse>('/health/database')
}

export async function analyzeTransaction(
  payload: TransactionAnalyzeRequest,
): Promise<TransactionAnalyzeResponse> {
  return requestJson<TransactionAnalyzeResponse>('/api/v1/transactions/analyze', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}

export async function fetchTransactions(
  limit = 100,
  offset = 0,
): Promise<TransactionListResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  })
  return requestJson<TransactionListResponse>(`/api/v1/transactions?${params.toString()}`)
}

export async function fetchTransactionDetail(
  transactionId: number,
): Promise<TransactionDetailResponse> {
  return requestJson<TransactionDetailResponse>(`/api/v1/transactions/${transactionId}`)
}

export async function fetchNetworkOverview(): Promise<NetworkOverviewResponse> {
  return requestJson<NetworkOverviewResponse>('/api/v1/network/overview')
}

export async function fetchNetworkPatterns(
  limit = 50,
  offset = 0,
  patternType?: string,
): Promise<NetworkPatternListResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  })
  if (patternType && patternType !== 'ALL') {
    params.set('pattern_type', patternType)
  }
  return requestJson<NetworkPatternListResponse>(
    `/api/v1/network/patterns?${params.toString()}`,
  )
}

export async function fetchAccountNetwork(
  accountId: string,
): Promise<AccountNetworkResponse> {
  const encoded = encodeURIComponent(accountId.trim())
  return requestJson<AccountNetworkResponse>(`/api/v1/network/accounts/${encoded}`)
}

export async function analyzeInvoice(
  file: File,
  options?: {
    submissionReference?: string
    rejectDuplicates?: boolean
    corrections?: Record<string, string>
  },
): Promise<InvoiceAnalyzeResponse> {
  const formData = new FormData()
  formData.append('file', file)

  if (options?.submissionReference?.trim()) {
    formData.append('submission_reference', options.submissionReference.trim())
  }
  if (options?.rejectDuplicates !== undefined) {
    formData.append('reject_duplicates', String(options.rejectDuplicates))
  }
  if (options?.corrections && Object.keys(options.corrections).length > 0) {
    formData.append('corrections_json', JSON.stringify(options.corrections))
  }

  return requestJson<InvoiceAnalyzeResponse>('/api/v1/invoices/analyze', {
    method: 'POST',
    body: formData,
  })
}

export async function fetchInvoices(
  limit = 20,
  offset = 0,
): Promise<InvoiceListResponse> {
  const params = new URLSearchParams({
    limit: String(limit),
    offset: String(offset),
  })
  return requestJson<InvoiceListResponse>(`/api/v1/invoices?${params.toString()}`)
}

export async function fetchInvoiceDetail(
  invoiceId: number,
): Promise<InvoiceDetailResponse> {
  return requestJson<InvoiceDetailResponse>(`/api/v1/invoices/${invoiceId}`)
}

export async function fetchAssistantStatus(): Promise<AssistantStatusResponse> {
  return requestJson<AssistantStatusResponse>('/api/v1/assistant/status')
}

export async function askInvestigationAssistant(
  payload: AssistantChatRequest,
): Promise<AssistantChatResponse> {
  return requestJson<AssistantChatResponse>('/api/v1/assistant/chat', {
    method: 'POST',
    body: JSON.stringify(payload),
  })
}
