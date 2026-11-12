/**
 * InvestigationAssistantPanel Component
 * Evidence-grounded, stateless AI Investigation Assistant UI integrated into the
 * FraudTrace AI dark-navy investigation console.
 */

import { useCallback, useEffect, useMemo, useState } from 'react'
import type { FormEvent } from 'react'
import {
  ApiClientError,
  askInvestigationAssistant,
  fetchAssistantStatus,
  fetchInvoices,
} from '../services/api'
import type {
  AssistantChatRequest,
  AssistantChatResponse,
  AssistantCitation,
  AssistantStatusResponse,
  InvoiceSummaryResponse,
  NetworkOverviewResponse,
  TransactionDetailResponse,
  TransactionResponse,
} from '../types/api'
import {
  type AssistantContextSelection,
  MAX_ASSISTANT_QUESTION_LENGTH,
  buildAssistantChatPayload,
  buildSuggestedQuestions,
  createEmptyAssistantContext,
  getProviderBadgeMeta,
} from '../utils/assistantHelpers'
import { SafeMarkdown } from '../utils/safeMarkdown'

export interface AssistantMessageTurn {
  id: string
  question: string
  context: AssistantContextSelection
  response: AssistantChatResponse
  createdAt: string
}

export interface InvestigationAssistantPanelProps {
  transactions: TransactionResponse[]
  selectedTransactionDetail: TransactionDetailResponse | null
  networkOverview: NetworkOverviewResponse | null
  selectedAccountId: string | null
  contextValue?: AssistantContextSelection | null
  questionDraft?: string
  onQuestionDraftChange?: (nextDraft: string) => void
  onContextChange: (next: AssistantContextSelection) => void
  onSelectTransaction?: (transactionId: number) => void
  onInspectAccount?: (accountId: string) => void
  onSelectInvoice?: (invoiceId: number) => void
  // Optional overrides for deterministic testing or status injection
  initialStatus?: AssistantStatusResponse | null
  initialTurns?: AssistantMessageTurn[]
  initialLoading?: boolean
  initialError?: string | null
}

function getRecordTypeBadgeClasses(recordType: string): string {
  switch (recordType) {
    case 'transaction':
      return 'border-sky-500/40 bg-sky-500/15 text-sky-300'
    case 'evidence':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
    case 'network_pattern':
    case 'account':
      return 'border-violet-500/40 bg-violet-500/15 text-violet-300'
    case 'invoice':
    case 'invoice_finding':
    case 'invoice_field':
      return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
    default:
      return 'border-slate-600/50 bg-slate-800 text-slate-300'
  }
}

export function AssistantCitationList({
  citations,
  onSelectTransaction,
  onInspectAccount,
  onSelectInvoice,
}: {
  citations: AssistantCitation[]
  onSelectTransaction?: (transactionId: number) => void
  onInspectAccount?: (accountId: string) => void
  onSelectInvoice?: (invoiceId: number) => void
}) {
  if (citations.length === 0) {
    return (
      <div className="rounded-lg border border-dashed border-slate-700/80 bg-slate-900/50 px-3 py-2 text-[11px] text-slate-400">
        No record citations were attached to this response.
      </div>
    )
  }

  return (
    <div className="space-y-2" aria-label="Evidence citations">
      <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
        Verified Evidence Citations ({citations.length})
      </p>
      <div className="grid grid-cols-1 gap-2 md:grid-cols-2">
        {citations.map((cit, idx) => {
          const numericId = Number(cit.record_id)
          const trimmedRecordId = cit.record_id.trim()
          const canJumpTxn =
            cit.record_type === 'transaction' &&
            Number.isInteger(numericId) &&
            numericId > 0 &&
            Boolean(onSelectTransaction)
          const canJumpAccount =
            cit.record_type === 'account' &&
            trimmedRecordId.length > 0 &&
            Boolean(onInspectAccount)
          const canJumpInvoice =
            cit.record_type === 'invoice' &&
            Number.isInteger(numericId) &&
            numericId > 0 &&
            Boolean(onSelectInvoice)
          const canJump = canJumpTxn || canJumpAccount || canJumpInvoice

          return (
            <div
              key={`${cit.citation_id}-${idx}`}
              className="rounded-lg border border-slate-800 bg-[#0A101E] p-2.5 text-xs"
            >
              <div className="flex flex-wrap items-center justify-between gap-1.5">
                <span
                  className={`inline-flex items-center rounded border px-1.5 py-0.5 font-mono text-[10px] font-semibold ${getRecordTypeBadgeClasses(
                    cit.record_type,
                  )}`}
                >
                  {cit.citation_id}
                </span>
                {canJump && (
                  <button
                    type="button"
                    aria-label={`Inspect Record ${cit.citation_id}`}
                    onClick={() => {
                      if (canJumpTxn && onSelectTransaction) {
                        onSelectTransaction(numericId)
                      } else if (canJumpAccount && onInspectAccount) {
                        onInspectAccount(trimmedRecordId)
                      } else if (canJumpInvoice && onSelectInvoice) {
                        onSelectInvoice(numericId)
                      }
                    }}
                    className="text-[10px] font-medium text-sky-400 hover:text-sky-300 hover:underline"
                  >
                    Inspect Record →
                  </button>
                )}
              </div>
              <p className="mt-1.5 font-medium text-slate-200">{cit.label}</p>
              <p className="mt-0.5 text-[11px] text-slate-300">
                <span className="text-slate-400">Claim: </span>
                {cit.claim}
              </p>
              <p className="mt-1 text-[11px] text-slate-400 break-words">{cit.excerpt}</p>
            </div>
          )
        })}
      </div>
    </div>
  )
}

export default function InvestigationAssistantPanel({
  transactions,
  selectedTransactionDetail,
  networkOverview,
  selectedAccountId,
  contextValue = null,
  questionDraft,
  onQuestionDraftChange,
  onContextChange,
  onSelectTransaction,
  onInspectAccount,
  onSelectInvoice,
  initialStatus = null,
  initialTurns = [],
  initialLoading = false,
  initialError = null,
}: InvestigationAssistantPanelProps) {
  const [statusInfo, setStatusInfo] = useState<AssistantStatusResponse | null>(initialStatus)
  const [statusError, setStatusError] = useState<string | null>(null)
  const [invoices, setInvoices] = useState<InvoiceSummaryResponse[]>([])

  const [localContext, setLocalContext] = useState<AssistantContextSelection>(() => ({
    transactionId: selectedTransactionDetail?.id ?? null,
    investigationId: selectedTransactionDetail?.investigations[0]?.id ?? null,
    invoiceId: null,
    accountId: selectedAccountId ?? null,
  }))
  const context = contextValue ?? localContext

  const [localQuestionInput, setLocalQuestionInput] = useState('')
  const questionInput = questionDraft !== undefined ? questionDraft : localQuestionInput

  const setQuestionInput = useCallback(
    (next: string) => {
      if (onQuestionDraftChange) {
        onQuestionDraftChange(next)
      } else {
        setLocalQuestionInput(next)
      }
    },
    [onQuestionDraftChange],
  )

  const [turns, setTurns] = useState<AssistantMessageTurn[]>(initialTurns)
  const [isLoading, setIsLoading] = useState(initialLoading)
  const [submitError, setSubmitError] = useState<string | null>(initialError)
  const [lastFailedRequest, setLastFailedRequest] = useState<AssistantChatRequest | null>(null)

  const loadMetadata = useCallback(async () => {
    const [astStatus, invList] = await Promise.allSettled([
      fetchAssistantStatus(),
      fetchInvoices(25, 0),
    ])
    if (astStatus.status === 'fulfilled') {
      setStatusInfo(astStatus.value)
      setStatusError(null)
    } else {
      setStatusError(
        astStatus.reason instanceof Error
          ? astStatus.reason.message
          : 'Unable to check AI assistant status.',
      )
    }
    if (invList.status === 'fulfilled') {
      setInvoices(invList.value.items)
    }
  }, [])

  useEffect(() => {
    if (initialStatus !== null) return
    let cancelled = false
    void Promise.resolve().then(() => {
      if (!cancelled) {
        return loadMetadata()
      }
      return undefined
    })
    return () => {
      cancelled = true
    }
  }, [initialStatus, loadMetadata])

  const accountOptions = useMemo(() => {
    const set = new Set<string>()
    if (context.accountId) set.add(context.accountId)
    if (selectedAccountId) set.add(selectedAccountId)
    for (const acct of networkOverview?.suspicious_account_identifiers ?? []) {
      set.add(acct)
    }
    for (const txn of transactions.slice(0, 20)) {
      set.add(txn.sender_id)
      set.add(txn.receiver_id)
    }
    return Array.from(set)
  }, [context.accountId, networkOverview, selectedAccountId, transactions])

  const investigationOptions = useMemo(() => {
    const list = selectedTransactionDetail?.investigations ?? []
    return list.filter((inv): inv is typeof inv & { id: number } => inv.id !== null)
  }, [selectedTransactionDetail])

  const suggestedQuestions = useMemo(() => buildSuggestedQuestions(context), [context])
  const badgeMeta = getProviderBadgeMeta(statusInfo)

  function updateContext(patch: Partial<AssistantContextSelection>) {
    const next: AssistantContextSelection = { ...context, ...patch }
    setLocalContext(next)
    onContextChange(next)
  }

  function clearContext() {
    const cleared = createEmptyAssistantContext()
    setLocalContext(cleared)
    onContextChange(cleared)
  }

  async function submitQuestion(rawQuestion: string) {
    const clean = rawQuestion.trim()
    if (!clean || isLoading) return
    if (clean.length > MAX_ASSISTANT_QUESTION_LENGTH) {
      setSubmitError(`Question exceeds ${MAX_ASSISTANT_QUESTION_LENGTH} character limit.`)
      return
    }

    const requestPayload = buildAssistantChatPayload(clean, context)

    setIsLoading(true)
    setSubmitError(null)
    setLastFailedRequest(requestPayload)

    try {
      const response = await askInvestigationAssistant(requestPayload)
      const turn: AssistantMessageTurn = {
        id: response.request_id || `turn_${Date.now()}`,
        question: clean,
        context: { ...context },
        response,
        createdAt: new Date().toISOString(),
      }
      setTurns((prev) => [...prev, turn])
      setQuestionInput('')
      setLastFailedRequest(null)
    } catch (err) {
      const message =
        err instanceof ApiClientError || err instanceof Error
          ? err.message
          : 'Failed to generate grounded assistant explanation.'
      setSubmitError(message)
    } finally {
      setIsLoading(false)
    }
  }

  function handleFormSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    void submitQuestion(questionInput)
  }

  async function handleRetry() {
    if (!lastFailedRequest || isLoading) return
    setIsLoading(true)
    setSubmitError(null)
    try {
      const response = await askInvestigationAssistant(lastFailedRequest)
      const turn: AssistantMessageTurn = {
        id: response.request_id || `turn_${Date.now()}`,
        question: lastFailedRequest.message,
        context: {
          transactionId: lastFailedRequest.transaction_id ?? null,
          investigationId: lastFailedRequest.investigation_id ?? null,
          invoiceId: lastFailedRequest.invoice_id ?? null,
          accountId: lastFailedRequest.account_id ?? null,
        },
        response,
        createdAt: new Date().toISOString(),
      }
      setTurns((prev) => [...prev, turn])
      setQuestionInput('')
      setLastFailedRequest(null)
    } catch (err) {
      setSubmitError(
        err instanceof Error ? err.message : 'Retry failed while contacting the AI assistant.',
      )
    } finally {
      setIsLoading(false)
    }
  }

  const hasActiveContext =
    context.transactionId !== null ||
    context.investigationId !== null ||
    context.invoiceId !== null ||
    Boolean(context.accountId)

  function handleClearConversation() {
    if (isLoading) return
    setTurns([])
    setSubmitError(null)
    setLastFailedRequest(null)
  }

  return (
    <section
      aria-label="AI Investigation Assistant"
      className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-4 shadow-sm sm:p-5"
    >
      {/* Header Bar */}
      <div className="flex flex-col gap-3 border-b border-slate-800 pb-4 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h2 className="text-base font-semibold text-white">
              AI Investigation Assistant
            </h2>
            <span
              className={`inline-flex items-center rounded-full border px-2.5 py-0.5 text-[11px] font-medium ${badgeMeta.classes}`}
            >
              {badgeMeta.label}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-400">
            Stateless, evidence-grounded investigation explanations powered by sanitized FraudTrace AI records.
          </p>
        </div>

        <div className="flex flex-wrap items-center gap-2 self-start sm:self-auto">
          {(turns.length > 0 || submitError !== null) && (
            <button
              type="button"
              disabled={isLoading}
              onClick={handleClearConversation}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-amber-500/60 hover:text-amber-200 disabled:cursor-not-allowed disabled:opacity-50"
            >
              Clear Conversation
            </button>
          )}
          <button
            type="button"
            onClick={() => void loadMetadata()}
            className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-sky-500/60 hover:text-sky-300"
          >
            Refresh AI Status
          </button>
        </div>
      </div>

      {/* Actionable Provider Unavailable / Disabled Banner */}
      {(statusError || (statusInfo && !statusInfo.ready)) && (
        <div
          role="status"
          className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3 text-xs text-amber-200"
        >
          <p className="font-semibold">
            External AI Provider Not Ready
          </p>
          <p className="mt-1 leading-relaxed text-amber-100/90">
            {statusError ?? statusInfo?.message}
          </p>
          <p className="mt-1.5 text-[11px] text-amber-200/80">
            FraudTrace AI never fabricates or simulates LLM answers when external AI is disabled or unavailable.
            Deterministic risk scoring, fraud graph intelligence, and invoice rules continue operating normally.
          </p>
        </div>
      )}

      {/* Main Responsive Layout: Left Context & Suggestions / Right Conversation Workspace */}
      <div className="mt-4 grid grid-cols-1 gap-5 xl:grid-cols-12">
        {/* Left Sidebar: Scoped Context Selector + Suggested Questions */}
        <aside className="space-y-4 xl:col-span-4">
          <div className="rounded-lg border border-slate-800 bg-[#121B2E] p-3.5">
            <div className="flex items-center justify-between gap-2">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Investigation Context
              </h3>
              {hasActiveContext && (
                <button
                  type="button"
                  onClick={clearContext}
                  className="text-[11px] font-medium text-sky-400 hover:text-sky-300 hover:underline"
                >
                  Clear All
                </button>
              )}
            </div>
            <p className="mt-1 text-[11px] text-slate-400">
              Scope retrieval to specific records, or clear all selectors for cross-investigation questions.
            </p>

            <div className="mt-3 grid grid-cols-1 gap-2.5 sm:grid-cols-2 xl:grid-cols-1">
              {/* Transaction Selector */}
              <label className="block text-[11px] text-slate-300">
                <span className="font-medium text-slate-400">Transaction</span>
                <select
                  aria-label="Select transaction context"
                  value={context.transactionId ?? ''}
                  onChange={(e) => {
                    const val = e.target.value ? Number(e.target.value) : null
                    updateContext({ transactionId: val })
                  }}
                  className="mt-1 w-full rounded-lg border border-slate-700/80 bg-[#0D1424] px-2.5 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                >
                  <option value="">All / None selected</option>
                  {transactions.slice(0, 50).map((txn) => (
                    <option key={txn.id} value={txn.id}>
                      #{txn.id} · {txn.reference} ({txn.risk_level ?? 'UNSCORED'})
                    </option>
                  ))}
                </select>
              </label>

              {/* Investigation ID Selector / Input */}
              <label className="block text-[11px] text-slate-300">
                <span className="font-medium text-slate-400">Investigation ID (Optional)</span>
                {investigationOptions.length > 0 ? (
                  <select
                    aria-label="Select investigation context"
                    value={context.investigationId ?? ''}
                    onChange={(e) => {
                      const val = e.target.value ? Number(e.target.value) : null
                      updateContext({ investigationId: val })
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-700/80 bg-[#0D1424] px-2.5 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                  >
                    <option value="">Auto from transaction / None</option>
                    {investigationOptions.map((inv) => (
                      <option key={inv.id} value={inv.id}>
                        Investigation #{inv.id} ({inv.status})
                      </option>
                    ))}
                  </select>
                ) : (
                  <input
                    type="number"
                    min={1}
                    aria-label="Investigation ID context"
                    placeholder="e.g. 16"
                    value={context.investigationId ?? ''}
                    onChange={(e) => {
                      const raw = e.target.value.trim()
                      updateContext({
                        investigationId: raw ? Math.max(1, Number(raw)) : null,
                      })
                    }}
                    className="mt-1 w-full rounded-lg border border-slate-700/80 bg-[#0D1424] px-2.5 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                  />
                )}
              </label>

              {/* Invoice Selector */}
              <label className="block text-[11px] text-slate-300">
                <span className="font-medium text-slate-400">Invoice</span>
                <select
                  aria-label="Select invoice context"
                  value={context.invoiceId ?? ''}
                  onChange={(e) => {
                    const val = e.target.value ? Number(e.target.value) : null
                    updateContext({ invoiceId: val })
                  }}
                  className="mt-1 w-full rounded-lg border border-slate-700/80 bg-[#0D1424] px-2.5 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                >
                  <option value="">None selected</option>
                  {invoices.map((inv) => (
                    <option key={inv.id} value={inv.id}>
                      Invoice #{inv.id} · {inv.vendor_name ?? inv.original_filename} ({inv.investigation_status})
                    </option>
                  ))}
                </select>
              </label>

              {/* Account Selector */}
              <label className="block text-[11px] text-slate-300">
                <span className="font-medium text-slate-400">Account ID</span>
                <select
                  aria-label="Select account context"
                  value={context.accountId ?? ''}
                  onChange={(e) => {
                    const val = e.target.value.trim()
                    updateContext({ accountId: val || null })
                  }}
                  className="mt-1 w-full rounded-lg border border-slate-700/80 bg-[#0D1424] px-2.5 py-2 text-xs text-white focus:border-sky-500 focus:outline-none"
                >
                  <option value="">None selected</option>
                  {accountOptions.map((acct) => (
                    <option key={acct} value={acct}>
                      {acct}
                    </option>
                  ))}
                </select>
              </label>
            </div>

            {context.accountId && onInspectAccount && (
              <button
                type="button"
                onClick={() => onInspectAccount(context.accountId as string)}
                className="mt-3 w-full rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1.5 text-[11px] font-medium text-slate-200 transition hover:border-sky-500/60 hover:text-sky-300"
              >
                Inspect <span className="font-mono">{context.accountId}</span> in Network Graph
              </button>
            )}
          </div>

          {/* Suggested Questions */}
          <div className="rounded-lg border border-slate-800 bg-[#121B2E] p-3.5">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
              Suggested Questions
            </h3>
            <div className="mt-2.5 flex flex-col gap-2">
              {suggestedQuestions.map((prompt) => (
                <button
                  key={prompt}
                  type="button"
                  disabled={isLoading}
                  onClick={() => void submitQuestion(prompt)}
                  className="rounded-lg border border-slate-700/80 bg-[#0D1424] px-3 py-2 text-left text-xs text-slate-200 transition hover:border-sky-500/60 hover:text-sky-200 disabled:opacity-50"
                >
                  {prompt}
                </button>
              ))}
            </div>
          </div>

          {/* Privacy & Grounding Guardrails */}
          <div className="rounded-lg border border-slate-800 bg-[#0A101E] p-3.5 text-[11px] text-slate-400">
            <p className="font-semibold text-slate-300">Privacy & Grounding Controls</p>
            <ul className="mt-1.5 list-disc space-y-1 pl-4 leading-relaxed">
              <li>Personal details, tokens, and raw invoice files are stripped before LLM calls.</li>
              <li>Accounts and vendors are pseudonymized; deterministic rules remain authoritative.</li>
              <li>Scores never represent fraud probabilities or criminal guilt.</li>
            </ul>
          </div>
        </aside>

        {/* Right Workspace: Conversation Thread & Message Composer */}
        <div className="flex flex-col justify-between gap-4 xl:col-span-8">
          {/* Conversation History / Empty State / Loading */}
          <div className="min-h-[340px] space-y-4 rounded-lg border border-slate-800 bg-[#121B2E]/60 p-4">
            {turns.length === 0 && !isLoading && !submitError && (
              <div className="flex h-full min-h-[280px] flex-col items-center justify-center text-center">
                <div className="rounded-full border border-sky-500/30 bg-sky-500/10 px-3 py-1 text-[11px] font-medium text-sky-300">
                  Evidence-Grounded Investigation Copilot
                </div>
                <h3 className="mt-3 text-sm font-semibold text-white">
                  Ask about transactions, fraud networks, or invoices
                </h3>
                <p className="mt-1.5 max-w-md text-xs leading-relaxed text-slate-400">
                  Select a transaction, investigation, invoice, or account on the left—or click any
                  suggested question—to generate a cited explanation grounded strictly in retrieved
                  FraudTrace AI records.
                </p>
              </div>
            )}

            {turns.map((turn) => (
              <article
                key={turn.id}
                className="space-y-3 rounded-lg border border-slate-800 bg-[#0D1424] p-4"
              >
                {/* Investigator question */}
                <div className="flex flex-wrap items-start justify-between gap-2 border-b border-slate-800/80 pb-2.5">
                  <div>
                    <span className="text-[10px] font-semibold uppercase tracking-wider text-sky-400">
                      Investigator Question
                    </span>
                    <p className="mt-0.5 text-sm font-medium text-white break-words">
                      {turn.question}
                    </p>
                  </div>
                  <span className="rounded border border-slate-700 bg-slate-900 px-2 py-0.5 font-mono text-[10px] text-slate-400">
                    {turn.response.provider}/{turn.response.model} · {turn.response.request_id}
                  </span>
                </div>

                {/* Safe Markdown Answer */}
                <div className="rounded-lg border border-slate-800/70 bg-[#10192D] p-3.5">
                  <SafeMarkdown content={turn.response.answer} />
                </div>

                {/* Verified Citations */}
                <AssistantCitationList
                  citations={turn.response.citations}
                  onSelectTransaction={onSelectTransaction}
                  onInspectAccount={onInspectAccount}
                  onSelectInvoice={onSelectInvoice}
                />

                {/* Limitations & Uncertainty Notice */}
                {turn.response.limitations.length > 0 && (
                  <div
                    role="note"
                    aria-label="Limitations and uncertainty"
                    className="rounded-lg border border-amber-500/30 bg-amber-500/5 px-3 py-2.5 text-[11px] text-amber-200/90"
                  >
                    <p className="font-semibold text-amber-300">
                      Limitations & Uncertainty Disclosures
                    </p>
                    <ul className="mt-1 list-disc space-y-1 pl-4 leading-relaxed">
                      {turn.response.limitations.map((lim, i) => (
                        <li key={`${turn.id}-lim-${i}`}>{lim}</li>
                      ))}
                    </ul>
                  </div>
                )}

                {/* Follow-up suggestions */}
                {turn.response.suggested_questions.length > 0 && (
                  <div className="flex flex-wrap items-center gap-1.5 pt-1">
                    <span className="text-[11px] text-slate-400">Follow-up:</span>
                    {turn.response.suggested_questions.map((followUp) => (
                      <button
                        key={followUp}
                        type="button"
                        disabled={isLoading}
                        onClick={() => void submitQuestion(followUp)}
                        className="rounded-full border border-slate-700 bg-slate-900 px-2.5 py-1 text-[11px] text-slate-300 transition hover:border-sky-500/60 hover:text-sky-200 disabled:opacity-50"
                      >
                        {followUp}
                      </button>
                    ))}
                  </div>
                )}
              </article>
            ))}

            {/* Loading State */}
            {isLoading && (
              <div
                role="status"
                aria-label="Generating assistant explanation"
                className="space-y-2.5 rounded-lg border border-sky-500/30 bg-[#0D1424] p-4"
              >
                <div className="flex items-center gap-2 text-xs font-medium text-sky-300">
                  <span className="inline-block h-2 w-2 animate-ping rounded-full bg-sky-400" />
                  Retrieving sanitized evidence and generating grounded explanation…
                </div>
                <div className="h-3 w-3/4 animate-pulse rounded bg-slate-800" />
                <div className="h-3 w-1/2 animate-pulse rounded bg-slate-800" />
              </div>
            )}

            {/* Error & Retry State */}
            {submitError && (
              <div
                role="alert"
                className="flex flex-col gap-2.5 rounded-lg border border-red-500/40 bg-red-500/10 p-3.5 text-xs text-red-200 sm:flex-row sm:items-center sm:justify-between"
              >
                <div className="space-y-0.5">
                  <p className="font-semibold text-red-100">Assistant Request Failed</p>
                  <p className="break-words">{submitError}</p>
                </div>
                {lastFailedRequest && (
                  <button
                    type="button"
                    disabled={isLoading}
                    onClick={() => void handleRetry()}
                    className="self-start rounded-md border border-red-400/50 bg-red-500/20 px-3 py-1.5 font-medium text-red-100 transition hover:bg-red-500/30 disabled:opacity-50 sm:self-auto"
                  >
                    Retry Request
                  </button>
                )}
              </div>
            )}
          </div>

          {/* Question Form Composer */}
          <form
            onSubmit={handleFormSubmit}
            className="rounded-lg border border-slate-800 bg-[#121B2E] p-3.5"
          >
            <div className="flex flex-col gap-2.5 sm:flex-row sm:items-end">
              <div className="min-w-0 flex-1">
                <div className="flex items-center justify-between gap-2">
                  <label
                    htmlFor="assistant-question-input"
                    className="text-xs font-medium text-slate-300"
                  >
                    Ask Investigation Question
                  </label>
                  <span className="text-[11px] text-slate-400">
                    {questionInput.length}/{MAX_ASSISTANT_QUESTION_LENGTH}
                  </span>
                </div>
                <textarea
                  id="assistant-question-input"
                  rows={2}
                  maxLength={MAX_ASSISTANT_QUESTION_LENGTH}
                  value={questionInput}
                  onChange={(e) => setQuestionInput(e.target.value)}
                  placeholder="e.g. Why was transaction #16 flagged, or what patterns link these accounts?"
                  className="mt-1.5 w-full resize-y rounded-lg border border-slate-700/80 bg-[#0D1424] px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                disabled={isLoading || questionInput.trim().length === 0}
                className="w-full rounded-lg bg-sky-600 px-4 py-2.5 text-xs font-semibold text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-50 sm:w-auto"
              >
                {isLoading ? 'Analyzing…' : 'Ask Assistant'}
              </button>
            </div>
          </form>
        </div>
      </div>
    </section>
  )
}
