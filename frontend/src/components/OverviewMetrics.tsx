/**
 * OverviewMetrics Component
 * Displays live summary metrics computed strictly from backend API responses.
 */

import type { NetworkOverviewResponse } from '../types/api'

interface OverviewMetricsProps {
  totalTransactions: number
  highRiskTransactions: number
  loadedTransactionCount: number
  networkOverview: NetworkOverviewResponse | null
  dbConnected: boolean | null
  isLoading: boolean
}

export default function OverviewMetrics({
  totalTransactions,
  highRiskTransactions,
  loadedTransactionCount,
  networkOverview,
  dbConnected,
  isLoading,
}: OverviewMetricsProps) {
  const suspiciousAccountsCount =
    networkOverview?.suspicious_account_identifiers.length ?? 0

  const highRiskSubtitle =
    totalTransactions > loadedTransactionCount
      ? `HIGH / CRITICAL in latest ${loadedTransactionCount}`
      : 'HIGH or CRITICAL risk level'

  return (
    <section aria-label="Dashboard overview metrics">
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 lg:grid-cols-5">
        {/* Total Transactions */}
        <div className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Total Transactions
          </p>
          <p className="mt-2 text-2xl font-semibold tabular-nums text-white">
            {isLoading && networkOverview === null ? '—' : totalTransactions}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            Persisted in ledger
          </p>
        </div>

        {/* High-Risk Transactions */}
        <div className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            High-Risk Transactions
          </p>
          <p className="mt-2 text-2xl font-semibold tabular-nums text-orange-300">
            {isLoading && networkOverview === null ? '—' : highRiskTransactions}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {highRiskSubtitle}
          </p>
        </div>

        {/* Network Accounts */}
        <div className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Network Accounts
          </p>
          <p className="mt-2 text-2xl font-semibold tabular-nums text-sky-300">
            {networkOverview ? networkOverview.total_accounts : isLoading ? '—' : 0}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {networkOverview
              ? `${networkOverview.connected_components} connected component(s)`
              : 'Distinct graph entities'}
          </p>
        </div>

        {/* Suspicious Network Patterns */}
        <div className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Suspicious Patterns
          </p>
          <p className="mt-2 text-2xl font-semibold tabular-nums text-amber-300">
            {networkOverview
              ? networkOverview.suspicious_patterns_detected
              : isLoading
                ? '—'
                : 0}
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {suspiciousAccountsCount} account(s) in lead findings
          </p>
        </div>

        {/* Database Status */}
        <div className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-4 shadow-sm">
          <p className="text-xs font-medium uppercase tracking-wider text-slate-400">
            Database Engine
          </p>
          <div className="mt-2 flex items-center gap-2">
            <span
              aria-hidden="true"
              className={`inline-block h-2.5 w-2.5 rounded-full ${
                dbConnected === null
                  ? 'bg-yellow-400 animate-pulse'
                  : dbConnected
                    ? 'bg-emerald-400'
                    : 'bg-red-400'
              }`}
            />
            <span
              className={`text-base font-semibold ${
                dbConnected === null
                  ? 'text-yellow-300'
                  : dbConnected
                    ? 'text-emerald-300'
                    : 'text-red-300'
              }`}
            >
              {dbConnected === null
                ? 'Checking…'
                : dbConnected
                  ? 'SQLite Connected'
                  : 'Unavailable'}
            </span>
          </div>
          <p className="mt-1 text-xs text-slate-500">
            Via GET /health/database
          </p>
        </div>
      </div>
    </section>
  )
}
