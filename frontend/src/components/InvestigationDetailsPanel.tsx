/**
 * InvestigationDetailsPanel Component
 * Displays full investigation details from GET /api/v1/transactions/{id},
 * including risk breakdown, evidence items, and matching fraud network leads.
 */

import { useMemo } from 'react'
import type {
  NetworkPatternResponse,
  TransactionDetailResponse,
} from '../types/api'
import {
  formatAmount,
  formatEvidenceLabel,
  formatPatternLabel,
  formatTimestamp,
  getRiskBadgeClasses,
  getRiskBarColor,
  getStatusBadgeClasses,
} from '../utils/formatters'

interface InvestigationDetailsPanelProps {
  detail: TransactionDetailResponse | null
  patterns: NetworkPatternResponse[]
  isLoading: boolean
  error: string | null
  onInspectAccount: (accountId: string) => void
}

export default function InvestigationDetailsPanel({
  detail,
  patterns,
  isLoading,
  error,
  onInspectAccount,
}: InvestigationDetailsPanelProps) {
  const relevantPatterns = useMemo(() => {
    if (!detail) return []
    return patterns.filter(
      (pattern) =>
        pattern.transaction_references.includes(detail.reference) ||
        pattern.involved_accounts.includes(detail.sender_id) ||
        pattern.involved_accounts.includes(detail.receiver_id),
    )
  }, [detail, patterns])

  const primaryInvestigation = detail?.investigations[0] ?? null
  const evidenceItems = useMemo(
    () => detail?.investigations.flatMap((inv) => inv.evidences) ?? [],
    [detail],
  )

  return (
    <section
      aria-label="Investigation details"
      className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-5 shadow-sm"
    >
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-slate-800 pb-3">
        <div>
          <h2 className="text-base font-semibold text-white">
            Investigation Details
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Explainable risk evidence, investigation case status, and linked network signals
          </p>
        </div>

        {detail && (
          <div className="flex flex-wrap items-center gap-2">
            <button
              type="button"
              onClick={() => onInspectAccount(detail.sender_id)}
              className="rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-200 transition hover:border-sky-500/60 hover:text-sky-300"
            >
              Inspect Sender: <span className="font-mono">{detail.sender_id}</span>
            </button>
            <button
              type="button"
              onClick={() => onInspectAccount(detail.receiver_id)}
              className="rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-200 transition hover:border-sky-500/60 hover:text-sky-300"
            >
              Inspect Receiver: <span className="font-mono">{detail.receiver_id}</span>
            </button>
          </div>
        )}
      </div>

      {error && (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-xs text-red-200"
        >
          {error}
        </div>
      )}

      {!error && isLoading && (
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-3">
          <div className="h-32 animate-pulse rounded-lg bg-slate-800/60" />
          <div className="h-32 animate-pulse rounded-lg bg-slate-800/60" />
          <div className="h-32 animate-pulse rounded-lg bg-slate-800/60" />
        </div>
      )}

      {!error && !isLoading && !detail && (
        <div className="mt-4 rounded-lg border border-dashed border-slate-700/80 bg-[#121B2E]/40 px-4 py-8 text-center text-xs text-slate-400">
          Select a transaction from the table above or analyze a new transaction to inspect its evidence breakdown.
        </div>
      )}

      {!error && !isLoading && detail && (
        <div className="mt-4 space-y-5">
          {/* Top summary grid */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-3">
            {/* Transaction metadata */}
            <div className="rounded-lg border border-slate-800 bg-[#121B2E] p-4">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Transaction Record #{detail.id}
              </p>
              <p className="mt-1.5 font-mono text-sm font-semibold text-sky-300">
                {detail.reference}
              </p>
              <dl className="mt-3 space-y-1.5 text-xs">
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-400">Sender</dt>
                  <dd className="font-mono text-slate-200">{detail.sender_id}</dd>
                </div>
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-400">Receiver</dt>
                  <dd className="font-mono text-slate-200">{detail.receiver_id}</dd>
                </div>
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-400">Amount</dt>
                  <dd className="font-semibold text-white">
                    {formatAmount(detail.amount, detail.currency)}
                  </dd>
                </div>
                <div className="flex justify-between gap-2">
                  <dt className="text-slate-400">Timestamp</dt>
                  <dd className="tabular-nums text-slate-300">
                    {formatTimestamp(detail.timestamp)}
                  </dd>
                </div>
              </dl>
            </div>

            {/* Risk score & status */}
            <div className="rounded-lg border border-slate-800 bg-[#121B2E] p-4">
              <div className="flex items-center justify-between gap-2">
                <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                  Risk Assessment
                </p>
                <span
                  className={`rounded border px-2 py-0.5 text-[11px] font-semibold ${getRiskBadgeClasses(
                    detail.risk_level,
                  )}`}
                >
                  {detail.risk_level ?? 'UNKNOWN'}
                </span>
              </div>

              <div className="mt-3 flex items-baseline justify-between">
                <span className="text-2xl font-bold tabular-nums text-white">
                  {detail.risk_score ?? 0}
                  <span className="text-sm font-normal text-slate-400"> / 100</span>
                </span>
                <span
                  className={`rounded border px-2 py-0.5 text-[11px] font-medium ${getStatusBadgeClasses(
                    detail.investigation_status,
                  )}`}
                >
                  {detail.investigation_status}
                </span>
              </div>

              <div className="mt-2 h-2 w-full overflow-hidden rounded-full bg-slate-800">
                <div
                  className={`h-full ${getRiskBarColor(detail.risk_score)}`}
                  style={{
                    width: `${Math.min(100, Math.max(4, detail.risk_score ?? 0))}%`,
                  }}
                />
              </div>

              <div className="mt-3 flex flex-wrap items-center justify-between gap-2 text-xs text-slate-400">
                <span>
                  Case Status:{' '}
                  <strong className="text-slate-200">
                    {primaryInvestigation?.status ?? 'N/A'}
                  </strong>
                </span>
                <span>
                  Priority:{' '}
                  <strong className="text-slate-200">
                    {primaryInvestigation?.priority ?? 'NORMAL'}
                  </strong>
                </span>
              </div>
            </div>

            {/* Explanation summary */}
            <div className="rounded-lg border border-slate-800 bg-[#121B2E] p-4">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Explainable Risk Summary
              </p>
              <p className="mt-2 text-xs leading-relaxed text-slate-200">
                {primaryInvestigation?.summary ??
                  'No investigation summary recorded for this transaction.'}
              </p>
              <p className="mt-3 border-t border-slate-800 pt-2 text-[11px] text-slate-500">
                Rule scores assist human review and do not independently establish guilt or confirmed fraud.
              </p>
            </div>
          </div>

          {/* Evidence & Network Context side by side */}
          <div className="grid grid-cols-1 gap-4 lg:grid-cols-2">
            {/* Evidence list */}
            <div className="rounded-lg border border-slate-800 bg-[#121B2E]/70 p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Transaction Evidence Signals ({evidenceItems.length})
              </h3>
              {evidenceItems.length === 0 ? (
                <p className="mt-3 text-xs text-slate-400">
                  No rule-based risk indicators triggered for this transaction.
                </p>
              ) : (
                <div className="mt-3 space-y-2.5">
                  {evidenceItems.map((ev, idx) => (
                    <div
                      key={ev.id ?? `${ev.evidence_type}-${idx}`}
                      className="rounded-lg border border-slate-800 bg-[#0D1424] p-3 text-xs"
                    >
                      <div className="flex items-center justify-between gap-2">
                        <span className="font-semibold text-slate-100">
                          {formatEvidenceLabel(ev.evidence_type)}
                        </span>
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${getRiskBadgeClasses(
                            ev.severity,
                          )}`}
                        >
                          {ev.severity}
                        </span>
                      </div>
                      <p className="mt-1.5 leading-relaxed text-slate-300">
                        {ev.description}
                      </p>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Matching network patterns */}
            <div className="rounded-lg border border-slate-800 bg-[#121B2E]/70 p-4">
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-300">
                Related Network Leads ({relevantPatterns.length})
              </h3>
              {relevantPatterns.length === 0 ? (
                <p className="mt-3 text-xs text-slate-400">
                  No multi-account structural patterns linked to this transaction or its endpoints yet.
                </p>
              ) : (
                <div className="mt-3 space-y-2.5">
                  {relevantPatterns.map((pat, idx) => (
                    <div
                      key={`${pat.pattern_type}-${pat.involved_accounts[0] ?? idx}`}
                      className="rounded-lg border border-slate-800 bg-[#0D1424] p-3 text-xs"
                    >
                      <div className="flex flex-wrap items-center justify-between gap-2">
                        <span className="font-semibold text-amber-300">
                          {formatPatternLabel(pat.pattern_type)}
                        </span>
                        <span
                          className={`rounded border px-1.5 py-0.5 text-[10px] font-semibold ${getRiskBadgeClasses(
                            pat.severity,
                          )}`}
                        >
                          {pat.severity}
                        </span>
                      </div>
                      <p className="mt-1.5 leading-relaxed text-slate-300">
                        {pat.explanation}
                      </p>
                      <div className="mt-2 flex flex-wrap items-center gap-1.5">
                        <span className="text-[11px] text-slate-500">Accounts:</span>
                        {pat.involved_accounts.map((acct) => (
                          <button
                            key={acct}
                            type="button"
                            onClick={() => onInspectAccount(acct)}
                            className="rounded border border-slate-700 bg-slate-800/80 px-1.5 py-0.5 font-mono text-[10px] text-slate-200 hover:border-sky-500/60 hover:text-sky-300"
                          >
                            {acct}
                          </button>
                        ))}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
