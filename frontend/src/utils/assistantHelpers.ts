/**
 * FraudTrace AI — Pure Investigation Assistant Helper Utilities
 * Separated from React component modules for Fast Refresh compatibility and
 * clean Node-based unit testing.
 */

import type { AssistantChatRequest, AssistantStatusResponse } from '../types/api'

export type WorkspaceTab = 'all' | 'transactions' | 'network' | 'invoices' | 'assistant'

export const MAX_ASSISTANT_QUESTION_LENGTH = 2000

export function resolveTabForTransactionInspection(currentTab: WorkspaceTab): WorkspaceTab {
  if (currentTab === 'all' || currentTab === 'transactions') {
    return currentTab
  }
  if (currentTab === 'network') {
    return 'all'
  }
  return 'transactions'
}

export function resolveTabForAccountInspection(currentTab: WorkspaceTab): WorkspaceTab {
  if (currentTab === 'all' || currentTab === 'network') {
    return currentTab
  }
  if (currentTab === 'transactions') {
    return 'all'
  }
  return 'network'
}

export function resolveTabForInvoiceInspection(_currentTab: WorkspaceTab): WorkspaceTab {
  return 'invoices'
}

export interface InvoiceLoadCallbacks<TDetail> {
  fetcher: (invoiceId: number) => Promise<TDetail>
  onStartLoading: (invoiceId: number) => void
  onSuccess: (invoiceId: number, detail: TDetail) => void
  onError: (invoiceId: number, message: string) => void
  onFinishLoading: (invoiceId: number) => void
  isMounted?: () => boolean
}

export interface StartedInvoiceRequest {
  seq: number
  promise: Promise<boolean>
  cancel: () => void
}

/**
 * Coordinates invoice detail requests across React StrictMode double-mounts,
 * citation jumps, manual history clicks, and rapid selection switches so that:
 * 1) StrictMode cleanup resets in-flight tracking cleanly,
 * 2) loadedInvoiceId is updated only after a request succeeds, and
 * 3) stale/out-of-order responses never overwrite newer selections.
 */
export function createInvoiceSelectionController<TDetail>(
  callbacks: InvoiceLoadCallbacks<TDetail>,
) {
  let latestSeq = 0
  let loadedInvoiceId: number | null = null
  let inFlight: { seq: number; invoiceId: number } | null = null

  const canCommit = (seq: number, isCancelled?: () => boolean) => {
    if (callbacks.isMounted && !callbacks.isMounted()) {
      return false
    }
    if (isCancelled?.()) {
      return false
    }
    return seq === latestSeq
  }

  return {
    getLoadedInvoiceId: () => loadedInvoiceId,
    getInFlightInvoiceId: () => inFlight?.invoiceId ?? null,
    isAlreadyLoaded: (invoiceId: number) =>
      loadedInvoiceId === invoiceId && inFlight === null,
    isLoadedOrInFlight: (invoiceId: number) =>
      loadedInvoiceId === invoiceId || inFlight?.invoiceId === invoiceId,
    markLoaded(invoiceId: number) {
      latestSeq += 1
      inFlight = null
      loadedInvoiceId = invoiceId
      if (!callbacks.isMounted || callbacks.isMounted()) {
        callbacks.onFinishLoading(invoiceId)
      }
    },
    invalidateAll() {
      latestSeq += 1
      inFlight = null
    },
    startLoad(
      invoiceId: number,
      options?: {
        isCancelled?: () => boolean
      },
    ): StartedInvoiceRequest {
      latestSeq += 1
      const seq = latestSeq
      let locallyCancelled = false
      inFlight = { seq, invoiceId }

      if (canCommit(seq, () => locallyCancelled || Boolean(options?.isCancelled?.()))) {
        callbacks.onStartLoading(invoiceId)
      }

      const promise = callbacks
        .fetcher(invoiceId)
        .then((detail) => {
          if (inFlight?.seq === seq) {
            inFlight = null
          }
          if (!canCommit(seq, () => locallyCancelled || Boolean(options?.isCancelled?.()))) {
            return false
          }
          loadedInvoiceId = invoiceId
          callbacks.onSuccess(invoiceId, detail)
          callbacks.onFinishLoading(invoiceId)
          return true
        })
        .catch((err: unknown) => {
          if (inFlight?.seq === seq) {
            inFlight = null
          }
          if (!canCommit(seq, () => locallyCancelled || Boolean(options?.isCancelled?.()))) {
            return false
          }
          const message =
            err instanceof Error ? err.message : 'Unable to load invoice details.'
          callbacks.onError(invoiceId, message)
          callbacks.onFinishLoading(invoiceId)
          return false
        })

      return {
        seq,
        promise,
        cancel: () => {
          locallyCancelled = true
          if (inFlight?.seq === seq) {
            inFlight = null
          }
          if (latestSeq === seq) {
            latestSeq += 1
          }
        },
      }
    },
  }
}

export interface AssistantContextSelection {
  transactionId: number | null
  investigationId: number | null
  invoiceId: number | null
  accountId: string | null
}

export function createEmptyAssistantContext(): AssistantContextSelection {
  return {
    transactionId: null,
    investigationId: null,
    invoiceId: null,
    accountId: null,
  }
}

export function buildAssistantChatPayload(
  question: string,
  context: AssistantContextSelection,
): AssistantChatRequest {
  const clean = question.trim()
  return {
    message: clean,
    ...(context.transactionId !== null ? { transaction_id: context.transactionId } : {}),
    ...(context.investigationId !== null ? { investigation_id: context.investigationId } : {}),
    ...(context.invoiceId !== null ? { invoice_id: context.invoiceId } : {}),
    ...(context.accountId?.trim() ? { account_id: context.accountId.trim() } : {}),
  }
}

export function buildSuggestedQuestions(context: AssistantContextSelection): string[] {
  if (context.invoiceId !== null) {
    return [
      `Explain the deterministic findings for invoice #${context.invoiceId}.`,
      `Are there extracted versus corrected field discrepancies on invoice #${context.invoiceId}?`,
      `What OCR or extraction limitations apply to invoice #${context.invoiceId}?`,
      `What should an investigator verify next for invoice #${context.invoiceId}?`,
    ]
  }
  if (context.transactionId !== null || context.investigationId !== null) {
    const label =
      context.transactionId !== null
        ? `transaction #${context.transactionId}`
        : `investigation #${context.investigationId}`
    return [
      `Why was ${label} flagged and which indicators contributed to its risk score?`,
      `Which accounts are connected to ${label} and are there suspicious network patterns?`,
      `Explain the experimental ML output and its limitations for ${label}.`,
      `Generate an evidence-grounded investigation report for ${label}.`,
    ]
  }
  if (context.accountId) {
    return [
      `Which accounts are connected within 1-2 hops of ${context.accountId}?`,
      `Explain any suspicious network patterns involving ${context.accountId}.`,
      `What should an investigator verify next for ${context.accountId}?`,
    ]
  }
  return [
    'Are there common risk indicators across the highest-risk transactions?',
    'Explain the suspicious network patterns detected in the transaction graph.',
    'Summarize open investigation priorities and recommended next verification checks.',
    'Explain how deterministic risk scores differ from the experimental ML anomaly signal.',
  ]
}

export function getProviderBadgeMeta(status: AssistantStatusResponse | null): {
  label: string
  classes: string
} {
  if (!status) {
    return {
      label: 'Checking AI Status…',
      classes: 'border-slate-700 bg-slate-800/70 text-slate-300',
    }
  }
  if (status.ready) {
    return {
      label: `Ready · ${status.provider} (${status.model})`,
      classes: 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300',
    }
  }
  if (!status.enabled) {
    return {
      label: 'Assistant Disabled (AI_ENABLED=false)',
      classes: 'border-amber-500/40 bg-amber-500/15 text-amber-300',
    }
  }
  if (!status.privacy_policy_ok) {
    return {
      label: 'Blocked by Data Privacy Policy',
      classes: 'border-rose-500/40 bg-rose-500/15 text-rose-300',
    }
  }
  return {
    label: `Unavailable (${status.status_code})`,
    classes: 'border-orange-500/40 bg-orange-500/15 text-orange-300',
  }
}
