/**
 * NetworkIntelligencePanel & AccountInspector Components
 * - Account Network Inspector powered by GET /api/v1/network/accounts/{account_id}
 * - Detected Suspicious Network Patterns powered by GET /api/v1/network/patterns
 */

import { useState } from 'react'
import type { FormEvent } from 'react'
import type {
  AccountNetworkResponse,
  NetworkOverviewResponse,
  NetworkPatternResponse,
} from '../types/api'
import {
  formatPatternLabel,
  formatTimestamp,
  getRiskBadgeClasses,
} from '../utils/formatters'

interface AccountNetworkInspectorProps {
  selectedAccountId: string | null
  accountNetwork: AccountNetworkResponse | null
  networkOverview: NetworkOverviewResponse | null
  isLoading: boolean
  error: string | null
  onInspectAccount: (accountId: string) => void
  onSelectTransactionRef: (reference: string) => void
}

export function AccountNetworkInspector({
  selectedAccountId,
  accountNetwork,
  networkOverview,
  isLoading,
  error,
  onInspectAccount,
  onSelectTransactionRef,
}: AccountNetworkInspectorProps) {
  const [searchInput, setSearchInput] = useState('')
  const suspiciousSet = new Set(
    networkOverview?.suspicious_account_identifiers ?? [],
  )

  function handleSearchSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    const clean = searchInput.trim()
    if (!clean) return
    onInspectAccount(clean)
  }

  return (
    <section
      aria-label="Account network inspector"
      className="flex flex-col rounded-xl border border-slate-800/90 bg-[#0D1424] p-5 shadow-sm"
    >
      <div>
        <h2 className="text-base font-semibold text-white">
          Account Network Inspector
        </h2>
        <p className="mt-0.5 text-xs text-slate-400">
          Inspect 1–2 hop connections and lead patterns via{' '}
          <code className="text-slate-300">/network/accounts/&#123;id&#125;</code>
        </p>
      </div>

      <form onSubmit={handleSearchSubmit} className="mt-3 flex gap-2">
        <input
          type="text"
          value={searchInput}
          onChange={(e) => setSearchInput(e.target.value)}
          placeholder="Enter account ID (e.g. ACCT_HUB_99)"
          aria-label="Inspect account identifier"
          className="min-w-0 flex-1 rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-2 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none"
        />
        <button
          type="submit"
          className="rounded-lg bg-slate-800 px-3.5 py-2 text-xs font-medium text-sky-300 ring-1 ring-slate-700 transition hover:bg-slate-700"
        >
          Inspect
        </button>
      </form>

      {/* Quick chips for accounts present in pattern leads */}
      {networkOverview && networkOverview.suspicious_account_identifiers.length > 0 && (
        <div className="mt-3">
          <p className="text-[11px] font-medium text-slate-400">
            Flagged Pattern Participants:
          </p>
          <div className="mt-1.5 flex flex-wrap gap-1.5">
            {networkOverview.suspicious_account_identifiers.slice(0, 8).map((acct) => {
              const isSelected = acct === selectedAccountId
              return (
                <button
                  key={acct}
                  type="button"
                  onClick={() => onInspectAccount(acct)}
                  className={`rounded border px-2 py-0.5 font-mono text-[11px] transition ${
                    isSelected
                      ? 'border-sky-400 bg-sky-500/20 text-sky-200'
                      : 'border-amber-500/35 bg-amber-500/10 text-amber-200 hover:bg-amber-500/20'
                  }`}
                >
                  {acct}
                </button>
              )
            })}
          </div>
        </div>
      )}

      {error && (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-amber-500/40 bg-amber-500/10 px-3.5 py-3 text-xs text-amber-200"
        >
          {error}
        </div>
      )}

      {!error && isLoading && (
        <div className="mt-4 space-y-3">
          <div className="h-16 animate-pulse rounded-lg bg-slate-800/60" />
          <div className="h-28 animate-pulse rounded-lg bg-slate-800/60" />
        </div>
      )}

      {!error && !isLoading && !accountNetwork && (
        <div className="mt-4 flex flex-1 items-center justify-center rounded-lg border border-dashed border-slate-700/80 bg-[#121B2E]/40 px-4 py-10 text-center text-xs text-slate-400">
          Select an account node from the graph, click a transaction participant, or enter an account ID above.
        </div>
      )}

      {!error && !isLoading && accountNetwork && (
        <div className="mt-4 space-y-4">
          {/* Account header summary */}
          <div className="rounded-lg border border-slate-800 bg-[#121B2E] p-3.5">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <span className="font-mono text-sm font-semibold text-sky-300">
                {accountNetwork.account_id}
              </span>
              {suspiciousSet.has(accountNetwork.account_id) ? (
                <span className="rounded border border-amber-500/40 bg-amber-500/15 px-2 py-0.5 text-[10px] font-semibold text-amber-300">
                  IN PATTERN LEADS
                </span>
              ) : (
                <span className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 text-[10px] text-slate-300">
                  STANDARD ENTITY
                </span>
              )}
            </div>

            <div className="mt-3 grid grid-cols-3 gap-2 text-center">
              <div className="rounded-md bg-[#0D1424] px-2 py-2">
                <p className="text-[10px] uppercase text-slate-500">Incoming</p>
                <p className="mt-0.5 text-sm font-semibold tabular-nums text-white">
                  {accountNetwork.incoming_transaction_count}
                </p>
              </div>
              <div className="rounded-md bg-[#0D1424] px-2 py-2">
                <p className="text-[10px] uppercase text-slate-500">Outgoing</p>
                <p className="mt-0.5 text-sm font-semibold tabular-nums text-white">
                  {accountNetwork.outgoing_transaction_count}
                </p>
              </div>
              <div className="rounded-md bg-[#0D1424] px-2 py-2">
                <p className="text-[10px] uppercase text-slate-500">Connections</p>
                <p className="mt-0.5 text-sm font-semibold tabular-nums text-sky-300">
                  {accountNetwork.connected_accounts.length}
                </p>
              </div>
            </div>
          </div>

          {/* 1-2 Hop Connections */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Connected Accounts (1–2 Hops)
            </h3>
            {accountNetwork.connected_accounts.length === 0 ? (
              <p className="mt-2 text-xs text-slate-500">
                No neighbor accounts within 2 hops.
              </p>
            ) : (
              <div className="mt-2 max-h-40 space-y-1.5 overflow-y-auto pr-1">
                {accountNetwork.connected_accounts.map((conn) => (
                  <button
                    key={conn.account_id}
                    type="button"
                    onClick={() => onInspectAccount(conn.account_id)}
                    className="flex w-full items-center justify-between rounded-md border border-slate-800 bg-[#121B2E] px-3 py-1.5 text-left text-xs transition hover:border-sky-500/50"
                  >
                    <span className="font-mono text-slate-200">{conn.account_id}</span>
                    <span className="flex items-center gap-1.5">
                      <span className="rounded bg-slate-800 px-1.5 py-0.5 text-[10px] text-slate-300">
                        {conn.hop_distance}-hop
                      </span>
                      <span className="rounded bg-sky-500/10 px-1.5 py-0.5 text-[10px] text-sky-300">
                        {conn.relationship}
                      </span>
                    </span>
                  </button>
                ))}
              </div>
            )}
          </div>

          {/* Related Transaction References */}
          <div>
            <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
              Related Transaction References ({accountNetwork.related_transaction_references.length})
            </h3>
            <div className="mt-2 flex flex-wrap gap-1.5">
              {accountNetwork.related_transaction_references.map((ref) => (
                <button
                  key={ref}
                  type="button"
                  onClick={() => onSelectTransactionRef(ref)}
                  className="rounded border border-slate-700 bg-[#121B2E] px-2 py-0.5 font-mono text-[11px] text-sky-300 hover:border-sky-500"
                >
                  {ref}
                </button>
              ))}
            </div>
          </div>

          {/* Relevant Patterns Summary for this Account */}
          {accountNetwork.relevant_patterns.length > 0 && (
            <div>
              <h3 className="text-xs font-semibold uppercase tracking-wider text-slate-400">
                Patterns Involving Account ({accountNetwork.relevant_patterns.length})
              </h3>
              <div className="mt-2 space-y-2">
                {accountNetwork.relevant_patterns.map((pat, idx) => (
                  <div
                    key={`${pat.pattern_type}-${idx}`}
                    className="rounded-lg border border-slate-800 bg-[#121B2E] p-2.5 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
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
                    <p className="mt-1 text-slate-300">{pat.explanation}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </section>
  )
}

interface NetworkPatternsExplorerProps {
  patterns: NetworkPatternResponse[]
  totalPatterns: number
  patternFilter: string
  networkOverview: NetworkOverviewResponse | null
  isLoading: boolean
  error: string | null
  onFilterChange: (patternType: string) => void
  onInspectAccount: (accountId: string) => void
  onSelectTransactionRef: (reference: string) => void
}

const PATTERN_TYPES = [
  'ALL',
  'HIGH_VOLUME_RECEIVER',
  'RAPID_FUND_MOVEMENT',
  'SHARED_RECEIVER',
] as const

export function NetworkPatternsExplorer({
  patterns,
  totalPatterns,
  patternFilter,
  networkOverview,
  isLoading,
  error,
  onFilterChange,
  onInspectAccount,
  onSelectTransactionRef,
}: NetworkPatternsExplorerProps) {
  const summary = networkOverview?.patterns_summary ?? {}

  return (
    <section
      aria-label="Suspicious network patterns"
      className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-5 shadow-sm"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">
            Fraud Network Pattern Intelligence
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Structural graph indicators highlighting multi-account relationships for review ({totalPatterns} matching lead(s))
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          {PATTERN_TYPES.map((type) => {
            const active = patternFilter === type
            const count =
              type === 'ALL'
                ? networkOverview?.suspicious_patterns_detected ?? totalPatterns
                : summary[type] ?? 0
            return (
              <button
                key={type}
                type="button"
                onClick={() => onFilterChange(type)}
                className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition ${
                  active
                    ? 'border-sky-500/60 bg-sky-500/15 text-sky-300'
                    : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:border-slate-600 hover:text-slate-200'
                }`}
              >
                {type === 'ALL' ? 'All Patterns' : formatPatternLabel(type)} ({count})
              </button>
            )
          })}
        </div>
      </div>

      {error && (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-4 py-3 text-xs text-red-200"
        >
          {error}
        </div>
      )}

      {!error && isLoading && patterns.length === 0 && (
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {[1, 2, 3].map((item) => (
            <div key={item} className="h-44 animate-pulse rounded-lg bg-slate-800/60" />
          ))}
        </div>
      )}

      {!error && !isLoading && patterns.length === 0 && (
        <div className="mt-4 rounded-lg border border-dashed border-slate-700/80 bg-[#121B2E]/40 px-4 py-8 text-center">
          <p className="text-sm font-medium text-slate-300">
            No suspicious network patterns detected
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Graph patterns appear when transactions form multi-sender clusters or rapid onward movement sequences.
          </p>
        </div>
      )}

      {!error && patterns.length > 0 && (
        <div className="mt-4 grid grid-cols-1 gap-4 md:grid-cols-2 lg:grid-cols-3">
          {patterns.map((pattern, idx) => (
            <article
              key={`${pattern.pattern_type}-${pattern.involved_accounts[0] ?? idx}-${idx}`}
              className="flex flex-col justify-between rounded-lg border border-slate-800 bg-[#121B2E] p-4"
            >
              <div>
                <div className="flex flex-wrap items-center justify-between gap-2">
                  <span className="text-xs font-semibold text-amber-300">
                    {formatPatternLabel(pattern.pattern_type)}
                  </span>
                  <span
                    className={`rounded border px-2 py-0.5 text-[10px] font-semibold ${getRiskBadgeClasses(
                      pattern.severity,
                    )}`}
                  >
                    {pattern.severity}
                  </span>
                </div>

                <p className="mt-2 text-xs leading-relaxed text-slate-300">
                  {pattern.explanation}
                </p>

                {/* Supporting counts */}
                <div className="mt-3 flex flex-wrap gap-1.5">
                  {Object.entries(pattern.supporting_counts).map(([metric, val]) => (
                    <span
                      key={metric}
                      className="rounded bg-[#0D1424] px-2 py-0.5 text-[10px] text-slate-300"
                    >
                      {metric.replaceAll('_', ' ')}:{' '}
                      <strong className="text-white">{val}</strong>
                    </span>
                  ))}
                </div>

                {/* Involved accounts */}
                <div className="mt-3">
                  <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                    Involved Accounts
                  </p>
                  <div className="mt-1 flex flex-wrap gap-1">
                    {pattern.involved_accounts.map((acct) => (
                      <button
                        key={acct}
                        type="button"
                        onClick={() => onInspectAccount(acct)}
                        className="rounded border border-slate-700 bg-slate-800/80 px-1.5 py-0.5 font-mono text-[11px] text-slate-200 hover:border-sky-500/60 hover:text-sky-300"
                      >
                        {acct}
                      </button>
                    ))}
                  </div>
                </div>
              </div>

              <div className="mt-3 border-t border-slate-800 pt-2.5">
                <p className="text-[10px] font-semibold uppercase tracking-wider text-slate-500">
                  Supporting References ({pattern.transaction_references.length})
                </p>
                <div className="mt-1 flex flex-wrap gap-1">
                  {pattern.transaction_references.map((ref) => (
                    <button
                      key={ref}
                      type="button"
                      onClick={() => onSelectTransactionRef(ref)}
                      className="rounded border border-slate-700/80 bg-[#0D1424] px-1.5 py-0.5 font-mono text-[10px] text-sky-300 hover:border-sky-500"
                    >
                      {ref}
                    </button>
                  ))}
                </div>
                {pattern.timestamps.length > 0 && (
                  <p className="mt-2 text-[10px] text-slate-500">
                    Latest event: {formatTimestamp(pattern.timestamps[pattern.timestamps.length - 1])}
                  </p>
                )}
              </div>
            </article>
          ))}
        </div>
      )}
    </section>
  )
}
