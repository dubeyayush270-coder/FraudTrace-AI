/**
 * App Component — FraudTrace AI Investigation Dashboard
 * Coordinates backend health monitoring, transaction risk submission & review,
 * investigation evidence breakdown, and fraud network intelligence.
 */

import { useCallback, useEffect, useMemo, useRef, useState } from 'react'
import HealthStatus from './components/HealthStatus'
import InvestigationDetailsPanel from './components/InvestigationDetailsPanel'
import NetworkGraphPanel from './components/NetworkGraphPanel'
import {
  AccountNetworkInspector,
  NetworkPatternsExplorer,
} from './components/NetworkIntelligencePanel'
import OverviewMetrics from './components/OverviewMetrics'
import RecentTransactionsTable from './components/RecentTransactionsTable'
import TransactionAnalyzeForm from './components/TransactionAnalyzeForm'
import {
  ApiClientError,
  checkDatabaseHealth,
  fetchAccountNetwork,
  fetchNetworkOverview,
  fetchNetworkPatterns,
  fetchTransactionDetail,
  fetchTransactions,
} from './services/api'
import type {
  AccountNetworkResponse,
  NetworkOverviewResponse,
  NetworkPatternResponse,
  TransactionAnalyzeResponse,
  TransactionDetailResponse,
  TransactionResponse,
} from './types/api'

type WorkspaceTab = 'all' | 'transactions' | 'network'

export default function App() {
  const [activeTab, setActiveTab] = useState<WorkspaceTab>('all')
  const [refreshTrigger, setRefreshTrigger] = useState(0)

  // Dashboard core state
  const [dbConnected, setDbConnected] = useState<boolean | null>(null)
  const [transactions, setTransactions] = useState<TransactionResponse[]>([])
  const [totalTransactions, setTotalTransactions] = useState(0)
  const [networkOverview, setNetworkOverview] =
    useState<NetworkOverviewResponse | null>(null)
  const [patterns, setPatterns] = useState<NetworkPatternResponse[]>([])
  const [totalPatterns, setTotalPatterns] = useState(0)
  const [patternFilter, setPatternFilter] = useState<string>('ALL')

  const [isDashboardLoading, setIsDashboardLoading] = useState(true)
  const [dashboardError, setDashboardError] = useState<string | null>(null)
  const [transactionsError, setTransactionsError] = useState<string | null>(null)
  const [patternsError, setPatternsError] = useState<string | null>(null)

  // Selected transaction investigation state
  const [selectedTransactionId, setSelectedTransactionId] = useState<number | null>(
    null,
  )
  const [transactionDetail, setTransactionDetail] =
    useState<TransactionDetailResponse | null>(null)
  const [isDetailLoading, setIsDetailLoading] = useState(false)
  const [detailError, setDetailError] = useState<string | null>(null)

  // Selected account network state
  const [selectedAccountId, setSelectedAccountId] = useState<string | null>(null)
  const [accountNetwork, setAccountNetwork] =
    useState<AccountNetworkResponse | null>(null)
  const [isAccountLoading, setIsAccountLoading] = useState(false)
  const [accountError, setAccountError] = useState<string | null>(null)

  const selectedTxRef = useRef<number | null>(null)
  const selectedAcctRef = useRef<string | null>(null)
  const detailsSectionRef = useRef<HTMLDivElement | null>(null)
  const networkSectionRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    selectedTxRef.current = selectedTransactionId
    selectedAcctRef.current = selectedAccountId
  }, [selectedTransactionId, selectedAccountId])

  const loadTransactionDetailById = useCallback(async (transactionId: number) => {
    selectedTxRef.current = transactionId
    setSelectedTransactionId(transactionId)
    setIsDetailLoading(true)
    setDetailError(null)
    try {
      const detail = await fetchTransactionDetail(transactionId)
      setTransactionDetail(detail)
    } catch (err) {
      setTransactionDetail(null)
      setDetailError(
        err instanceof Error ? err.message : 'Unable to load transaction investigation.',
      )
    } finally {
      setIsDetailLoading(false)
    }
  }, [])

  const loadAccountById = useCallback(async (accountId: string) => {
    const clean = accountId.trim()
    if (!clean) return
    selectedAcctRef.current = clean
    setSelectedAccountId(clean)
    setIsAccountLoading(true)
    setAccountError(null)
    try {
      const profile = await fetchAccountNetwork(clean)
      setAccountNetwork(profile)
    } catch (err) {
      setAccountNetwork(null)
      if (err instanceof ApiClientError && err.status === 404) {
        setAccountError(err.message)
      } else {
        setAccountError(
          err instanceof Error ? err.message : 'Unable to load account network data.',
        )
      }
    } finally {
      setIsAccountLoading(false)
    }
  }, [])

  const syncDashboardData = useCallback(
    async (activePatternFilter: string, isCancelled?: () => boolean) => {
      const [dbRes, txRes, ovRes, patRes] = await Promise.allSettled([
        checkDatabaseHealth(),
        fetchTransactions(100, 0),
        fetchNetworkOverview(),
        fetchNetworkPatterns(50, 0, activePatternFilter),
      ])

      if (isCancelled?.()) return

      if (dbRes.status === 'fulfilled' && dbRes.value.status === 'ok') {
        setDbConnected(true)
      } else {
        setDbConnected(false)
      }

      const errors: string[] = []

      if (txRes.status === 'fulfilled') {
        setTransactions(txRes.value.items)
        setTotalTransactions(txRes.value.total)
        setTransactionsError(null)

        if (selectedTxRef.current === null && txRes.value.items.length > 0) {
          void loadTransactionDetailById(txRes.value.items[0].id)
        }
      } else {
        const msg =
          txRes.reason instanceof Error
            ? txRes.reason.message
            : 'Failed to load transactions.'
        setTransactionsError(msg)
        errors.push(msg)
      }

      if (ovRes.status === 'fulfilled') {
        setNetworkOverview(ovRes.value)
        if (
          selectedAcctRef.current === null &&
          ovRes.value.suspicious_account_identifiers.length > 0
        ) {
          void loadAccountById(ovRes.value.suspicious_account_identifiers[0])
        }
      } else {
        errors.push(
          ovRes.reason instanceof Error
            ? ovRes.reason.message
            : 'Failed to load network overview.',
        )
      }

      if (patRes.status === 'fulfilled') {
        setPatterns(patRes.value.items)
        setTotalPatterns(patRes.value.total)
        setPatternsError(null)
      } else {
        const msg =
          patRes.reason instanceof Error
            ? patRes.reason.message
            : 'Failed to load network patterns.'
        setPatternsError(msg)
        errors.push(msg)
      }

      setDashboardError(errors.length > 0 ? errors[0] : null)
      setIsDashboardLoading(false)
    },
    [loadAccountById, loadTransactionDetailById],
  )

  useEffect(() => {
    let cancelled = false
    void Promise.resolve().then(() => {
      if (!cancelled) {
        return syncDashboardData('ALL', () => cancelled)
      }
      return undefined
    })
    return () => {
      cancelled = true
    }
  }, [syncDashboardData])

  const handleManualRefresh = useCallback(async () => {
    setIsDashboardLoading(true)
    setDashboardError(null)
    setRefreshTrigger((prev) => prev + 1)
    await syncDashboardData(patternFilter)
    if (selectedTxRef.current !== null) {
      await loadTransactionDetailById(selectedTxRef.current)
    }
    if (selectedAcctRef.current !== null) {
      await loadAccountById(selectedAcctRef.current)
    }
  }, [
    loadAccountById,
    loadTransactionDetailById,
    patternFilter,
    syncDashboardData,
  ])

  const handleTransactionAnalyzed = useCallback(
    async (result: TransactionAnalyzeResponse) => {
      setIsDashboardLoading(true)
      setRefreshTrigger((prev) => prev + 1)
      await loadTransactionDetailById(result.transaction.id)
      await syncDashboardData(patternFilter)
      if (selectedAcctRef.current !== null) {
        await loadAccountById(selectedAcctRef.current)
      }
    },
    [loadAccountById, loadTransactionDetailById, patternFilter, syncDashboardData],
  )

  const handleSelectTransaction = useCallback(
    (transactionId: number) => {
      if (activeTab === 'network') {
        setActiveTab('all')
      }
      void loadTransactionDetailById(transactionId)
      window.setTimeout(() => {
        detailsSectionRef.current?.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
        })
      }, 60)
    },
    [activeTab, loadTransactionDetailById],
  )

  const handleSelectTransactionRef = useCallback(
    (reference: string) => {
      const match = transactions.find((txn) => txn.reference === reference)
      if (!match) return
      handleSelectTransaction(match.id)
    },
    [handleSelectTransaction, transactions],
  )

  const handleInspectAccount = useCallback(
    (accountId: string) => {
      if (activeTab === 'transactions') {
        setActiveTab('all')
      }
      void loadAccountById(accountId)
      window.setTimeout(() => {
        networkSectionRef.current?.scrollIntoView({
          behavior: 'smooth',
          block: 'nearest',
        })
      }, 60)
    },
    [activeTab, loadAccountById],
  )

  const handlePatternFilterChange = useCallback(
    async (nextFilter: string) => {
      setPatternFilter(nextFilter)
      setIsDashboardLoading(true)
      try {
        const res = await fetchNetworkPatterns(50, 0, nextFilter)
        setPatterns(res.items)
        setTotalPatterns(res.total)
        setPatternsError(null)
      } catch (err) {
        setPatternsError(
          err instanceof Error ? err.message : 'Failed to load filtered patterns.',
        )
      } finally {
        setIsDashboardLoading(false)
      }
    },
    [],
  )

  const highRiskTransactions = useMemo(
    () =>
      transactions.filter((txn) => {
        const lvl = (txn.risk_level ?? '').toUpperCase()
        return lvl === 'HIGH' || lvl === 'CRITICAL'
      }).length,
    [transactions],
  )

  const showTransactionsSection = activeTab === 'all' || activeTab === 'transactions'
  const showNetworkSection = activeTab === 'all' || activeTab === 'network'

  return (
    <div className="min-h-screen bg-[#070B14] text-slate-100">
      {/* Top Navigation & System Bar */}
      <header className="sticky top-0 z-20 border-b border-slate-800/90 bg-[#070B14]/95 backdrop-blur">
        <div className="mx-auto flex max-w-7xl flex-col gap-3 px-4 py-3.5 sm:px-6 lg:flex-row lg:items-center lg:justify-between lg:px-8">
          <div className="flex items-center gap-3">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg border border-sky-500/40 bg-sky-500/15 font-mono text-sm font-bold text-sky-300">
              FT
            </div>
            <div>
              <div className="flex items-center gap-2">
                <h1 className="text-lg font-bold tracking-tight text-white">
                  FraudTrace <span className="text-sky-400">AI</span>
                </h1>
                <span className="hidden rounded border border-slate-700 bg-slate-800/80 px-2 py-0.5 text-[10px] font-medium uppercase tracking-wider text-slate-300 sm:inline-block">
                  Investigation Console
                </span>
              </div>
              <p className="text-xs text-slate-400">
                One suspicious payment can reveal an entire fraud network.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-2.5">
            {/* Workspace view switcher */}
            <div
              role="tablist"
              aria-label="Dashboard view selector"
              className="inline-flex rounded-lg border border-slate-800 bg-[#0D1424] p-0.5 text-xs"
            >
              {(
                [
                  { id: 'all', label: 'Full Workspace' },
                  { id: 'transactions', label: 'Transactions & Risk' },
                  { id: 'network', label: 'Network & Graph' },
                ] as const
              ).map((tab) => (
                <button
                  key={tab.id}
                  type="button"
                  role="tab"
                  aria-selected={activeTab === tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`rounded-md px-2.5 py-1 font-medium transition ${
                    activeTab === tab.id
                      ? 'bg-sky-600 text-white'
                      : 'text-slate-400 hover:text-slate-200'
                  }`}
                >
                  {tab.label}
                </button>
              ))}
            </div>

            <HealthStatus refreshTrigger={refreshTrigger} />

            <button
              type="button"
              onClick={() => void handleManualRefresh()}
              disabled={isDashboardLoading}
              className="rounded-lg border border-slate-700 bg-slate-900 px-3 py-1.5 text-xs font-medium text-slate-200 transition hover:border-sky-500/60 hover:text-sky-300 disabled:opacity-50"
            >
              {isDashboardLoading ? 'Syncing…' : 'Refresh'}
            </button>
          </div>
        </div>
      </header>

      <main className="mx-auto max-w-7xl space-y-6 px-4 py-6 sm:px-6 lg:px-8">
        {/* Global backend error banner if API cannot be reached */}
        {dashboardError && (
          <div
            role="alert"
            className="flex flex-col gap-2 rounded-xl border border-red-500/40 bg-red-500/10 px-4 py-3 text-xs text-red-200 sm:flex-row sm:items-center sm:justify-between"
          >
            <div>
              <span className="font-semibold">API Sync Issue: </span>
              {dashboardError}
            </div>
            <button
              type="button"
              onClick={() => void handleManualRefresh()}
              className="self-start rounded-md border border-red-400/40 bg-red-500/20 px-3 py-1 font-medium text-red-100 hover:bg-red-500/30 sm:self-auto"
            >
              Retry Connection
            </button>
          </div>
        )}

        {/* Overview KPI Bar */}
        <OverviewMetrics
          totalTransactions={totalTransactions}
          highRiskTransactions={highRiskTransactions}
          loadedTransactionCount={transactions.length}
          networkOverview={networkOverview}
          dbConnected={dbConnected}
          isLoading={isDashboardLoading}
        />

        {/* Band 1: Transaction Analysis Form + Recent Transactions + Investigation Detail */}
        {showTransactionsSection && (
          <>
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <div className="xl:col-span-5">
                <TransactionAnalyzeForm
                  onAnalyzed={handleTransactionAnalyzed}
                  onSelectTransaction={handleSelectTransaction}
                  onInspectAccount={handleInspectAccount}
                />
              </div>

              <div className="xl:col-span-7">
                <RecentTransactionsTable
                  transactions={transactions}
                  totalCount={totalTransactions}
                  selectedTransactionId={selectedTransactionId}
                  isLoading={isDashboardLoading}
                  error={transactionsError}
                  onSelectTransaction={handleSelectTransaction}
                  onInspectAccount={handleInspectAccount}
                />
              </div>
            </div>

            <div ref={detailsSectionRef}>
              <InvestigationDetailsPanel
                detail={transactionDetail}
                patterns={patterns}
                isLoading={isDetailLoading}
                error={detailError}
                onInspectAccount={handleInspectAccount}
              />
            </div>
          </>
        )}

        {/* Band 2: Fraud Network Graph + Account Inspector + Suspicious Pattern Explorer */}
        {showNetworkSection && (
          <div ref={networkSectionRef} className="space-y-6">
            <div className="grid grid-cols-1 gap-6 xl:grid-cols-12">
              <div className="xl:col-span-7">
                <NetworkGraphPanel
                  transactions={transactions}
                  networkOverview={networkOverview}
                  selectedAccountId={selectedAccountId}
                  accountNetwork={accountNetwork}
                  isLoading={isDashboardLoading}
                  onSelectAccount={handleInspectAccount}
                  onSelectTransactionRef={handleSelectTransactionRef}
                />
              </div>

              <div className="xl:col-span-5">
                <AccountNetworkInspector
                  selectedAccountId={selectedAccountId}
                  accountNetwork={accountNetwork}
                  networkOverview={networkOverview}
                  isLoading={isAccountLoading}
                  error={accountError}
                  onInspectAccount={handleInspectAccount}
                  onSelectTransactionRef={handleSelectTransactionRef}
                />
              </div>
            </div>

            <NetworkPatternsExplorer
              patterns={patterns}
              totalPatterns={totalPatterns}
              patternFilter={patternFilter}
              networkOverview={networkOverview}
              isLoading={isDashboardLoading}
              error={patternsError}
              onFilterChange={(next) => void handlePatternFilterChange(next)}
              onInspectAccount={handleInspectAccount}
              onSelectTransactionRef={handleSelectTransactionRef}
            />
          </div>
        )}
      </main>
    </div>
  )
}
