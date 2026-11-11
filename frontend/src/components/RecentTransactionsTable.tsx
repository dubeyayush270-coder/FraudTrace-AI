/**
 * RecentTransactionsTable Component
 * Lists recent transactions fetched from GET /api/v1/transactions with search
 * and risk-level filtering, plus click-to-inspect transaction & account actions.
 */

import { useMemo, useState } from 'react'
import type { TransactionResponse } from '../types/api'
import {
  formatAmount,
  formatTimestamp,
  getRiskBadgeClasses,
  getStatusBadgeClasses,
} from '../utils/formatters'

interface RecentTransactionsTableProps {
  transactions: TransactionResponse[]
  totalCount: number
  selectedTransactionId: number | null
  isLoading: boolean
  error: string | null
  onSelectTransaction: (transactionId: number) => void
  onInspectAccount: (accountId: string) => void
}

const RISK_FILTERS = ['ALL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'] as const

export default function RecentTransactionsTable({
  transactions,
  totalCount,
  selectedTransactionId,
  isLoading,
  error,
  onSelectTransaction,
  onInspectAccount,
}: RecentTransactionsTableProps) {
  const [searchTerm, setSearchTerm] = useState('')
  const [riskFilter, setRiskFilter] = useState<string>('ALL')

  const filteredTransactions = useMemo(() => {
    const query = searchTerm.trim().toLowerCase()
    return transactions.filter((txn) => {
      const matchesRisk =
        riskFilter === 'ALL' || (txn.risk_level ?? '').toUpperCase() === riskFilter
      if (!matchesRisk) return false
      if (!query) return true
      return (
        txn.reference.toLowerCase().includes(query) ||
        txn.sender_id.toLowerCase().includes(query) ||
        txn.receiver_id.toLowerCase().includes(query)
      )
    })
  }, [transactions, searchTerm, riskFilter])

  return (
    <section className="flex flex-col rounded-xl border border-slate-800/90 bg-[#0D1424] p-5 shadow-sm">
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">
            Recent Transactions
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Showing {filteredTransactions.length} of {totalCount} persisted record(s) · Click a row to inspect
          </p>
        </div>

        <input
          type="search"
          value={searchTerm}
          onChange={(e) => setSearchTerm(e.target.value)}
          placeholder="Filter reference or account…"
          aria-label="Filter recent transactions"
          className="w-full rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-1.5 text-xs text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none sm:w-56"
        />
      </div>

      {/* Risk level filter pills */}
      <div className="mt-3 flex flex-wrap gap-1.5">
        {RISK_FILTERS.map((level) => {
          const active = riskFilter === level
          return (
            <button
              key={level}
              type="button"
              onClick={() => setRiskFilter(level)}
              className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition ${
                active
                  ? 'border-sky-500/60 bg-sky-500/15 text-sky-300'
                  : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:border-slate-600 hover:text-slate-200'
              }`}
            >
              {level}
            </button>
          )
        })}
      </div>

      {error && (
        <div
          role="alert"
          className="mt-4 rounded-lg border border-red-500/40 bg-red-500/10 px-3.5 py-3 text-xs text-red-200"
        >
          {error}
        </div>
      )}

      {!error && isLoading && transactions.length === 0 && (
        <div className="mt-4 space-y-2">
          {[1, 2, 3, 4].map((row) => (
            <div
              key={row}
              className="h-11 animate-pulse rounded-lg bg-slate-800/60"
            />
          ))}
        </div>
      )}

      {!error && !isLoading && transactions.length === 0 && (
        <div className="mt-4 rounded-lg border border-dashed border-slate-700/80 bg-[#121B2E]/50 px-4 py-10 text-center">
          <p className="text-sm font-medium text-slate-300">
            No transactions analyzed yet
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Submit a transaction using the form or run{' '}
            <code className="rounded bg-slate-800 px-1.5 py-0.5 text-slate-300">
              backend/seed_demo_data.py
            </code>{' '}
            to populate demo leads.
          </p>
        </div>
      )}

      {!error && transactions.length > 0 && filteredTransactions.length === 0 && (
        <div className="mt-4 rounded-lg border border-slate-800 bg-[#121B2E]/40 px-4 py-8 text-center text-xs text-slate-400">
          No transactions match your current filter criteria.
        </div>
      )}

      {filteredTransactions.length > 0 && (
        <div className="mt-4 overflow-x-auto">
          <table className="w-full min-w-[660px] border-collapse text-left text-xs">
            <thead>
              <tr className="border-b border-slate-800 text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                <th className="py-2.5 pr-3">Reference</th>
                <th className="py-2.5 pr-3">Sender → Receiver</th>
                <th className="py-2.5 pr-3 text-right">Amount</th>
                <th className="py-2.5 pr-3 text-right">Score</th>
                <th className="py-2.5 pr-3">Risk</th>
                <th className="py-2.5 pr-3">Status</th>
                <th className="py-2.5 text-right">Timestamp</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-slate-800/70">
              {filteredTransactions.map((txn) => {
                const isSelected = txn.id === selectedTransactionId
                return (
                  <tr
                    key={txn.id}
                    onClick={() => onSelectTransaction(txn.id)}
                    className={`cursor-pointer transition ${
                      isSelected
                        ? 'bg-sky-500/12'
                        : 'hover:bg-slate-800/45'
                    }`}
                  >
                    <td className="py-2.5 pr-3 font-mono font-medium text-sky-300">
                      {txn.reference}
                    </td>
                    <td className="py-2.5 pr-3">
                      <div className="flex flex-wrap items-center gap-1">
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation()
                            onInspectAccount(txn.sender_id)
                          }}
                          title={`Inspect network for ${txn.sender_id}`}
                          className="rounded bg-slate-800/90 px-1.5 py-0.5 font-mono text-[11px] text-slate-200 hover:bg-sky-500/20 hover:text-sky-300"
                        >
                          {txn.sender_id}
                        </button>
                        <span className="text-slate-500" aria-hidden="true">
                          →
                        </span>
                        <button
                          type="button"
                          onClick={(e) => {
                            e.stopPropagation()
                            onInspectAccount(txn.receiver_id)
                          }}
                          title={`Inspect network for ${txn.receiver_id}`}
                          className="rounded bg-slate-800/90 px-1.5 py-0.5 font-mono text-[11px] text-slate-200 hover:bg-sky-500/20 hover:text-sky-300"
                        >
                          {txn.receiver_id}
                        </button>
                      </div>
                    </td>
                    <td className="py-2.5 pr-3 text-right font-medium tabular-nums text-white">
                      {formatAmount(txn.amount, txn.currency)}
                    </td>
                    <td className="py-2.5 pr-3 text-right font-semibold tabular-nums text-slate-200">
                      {txn.risk_score ?? 0}
                    </td>
                    <td className="py-2.5 pr-3">
                      <span
                        className={`inline-block rounded border px-2 py-0.5 text-[10px] font-semibold ${getRiskBadgeClasses(
                          txn.risk_level,
                        )}`}
                      >
                        {txn.risk_level ?? 'N/A'}
                      </span>
                    </td>
                    <td className="py-2.5 pr-3">
                      <span
                        className={`inline-block rounded border px-2 py-0.5 text-[10px] font-medium ${getStatusBadgeClasses(
                          txn.investigation_status,
                        )}`}
                      >
                        {txn.investigation_status}
                      </span>
                    </td>
                    <td className="py-2.5 text-right tabular-nums text-slate-400">
                      {formatTimestamp(txn.timestamp)}
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  )
}
