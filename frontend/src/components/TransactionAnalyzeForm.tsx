/**
 * TransactionAnalyzeForm Component
 * Submits new transactions to POST /api/v1/transactions/analyze, handles
 * client/server validation errors and duplicate references (HTTP 409),
 * and renders immediate risk scoring + evidence feedback.
 */

import { useState } from 'react'
import type { FormEvent } from 'react'
import { ApiClientError, analyzeTransaction } from '../services/api'
import type { TransactionAnalyzeResponse } from '../types/api'
import {
  formatEvidenceLabel,
  formatAmount,
  getRiskBadgeClasses,
  getRiskBarColor,
  getStatusBadgeClasses,
} from '../utils/formatters'
import { MLAnomalyCard } from './MLAnomalyCard'

interface TransactionAnalyzeFormProps {
  onAnalyzed: (result: TransactionAnalyzeResponse) => Promise<void> | void
  onSelectTransaction: (transactionId: number) => void
  onInspectAccount: (accountId: string) => void
}

function generateDefaultRef(): string {
  const stamp = new Date()
    .toISOString()
    .replace(/[-:T.Z]/g, '')
    .slice(4, 14)
  const rand = Math.floor(100 + Math.random() * 900)
  return `FT-${stamp}-${rand}`
}

export default function TransactionAnalyzeForm({
  onAnalyzed,
  onSelectTransaction,
  onInspectAccount,
}: TransactionAnalyzeFormProps) {
  const [reference, setReference] = useState('')
  const [senderId, setSenderId] = useState('')
  const [receiverId, setReceiverId] = useState('')
  const [amount, setAmount] = useState('')
  const [currency, setCurrency] = useState('USD')

  const [isSubmitting, setIsSubmitting] = useState(false)
  const [errorMessage, setErrorMessage] = useState<string | null>(null)
  const [isDuplicateError, setIsDuplicateError] = useState(false)
  const [latestResult, setLatestResult] = useState<TransactionAnalyzeResponse | null>(null)

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault()
    setErrorMessage(null)
    setIsDuplicateError(false)

    const cleanRef = reference.trim()
    const cleanSender = senderId.trim()
    const cleanReceiver = receiverId.trim()
    const cleanCurrency = currency.trim().toUpperCase()
    const parsedAmount = Number(amount)

    if (!cleanRef || !cleanSender || !cleanReceiver) {
      setErrorMessage('Reference, sender identifier, and receiver identifier are required.')
      return
    }
    if (!Number.isFinite(parsedAmount) || parsedAmount <= 0) {
      setErrorMessage('Amount must be a positive number greater than 0.')
      return
    }
    if (!/^[A-Z]{3}$/.test(cleanCurrency)) {
      setErrorMessage('Currency must be a 3-letter ISO code (e.g. USD, EUR, GBP).')
      return
    }

    setIsSubmitting(true)
    try {
      const result = await analyzeTransaction({
        reference: cleanRef,
        sender_id: cleanSender,
        receiver_id: cleanReceiver,
        amount: amount.trim(),
        currency: cleanCurrency,
      })

      setLatestResult(result)
      setReference('')
      setAmount('')
      await onAnalyzed(result)
    } catch (err) {
      if (err instanceof ApiClientError) {
        setErrorMessage(err.message)
        setIsDuplicateError(err.status === 409)
      } else if (err instanceof Error) {
        setErrorMessage(err.message)
      } else {
        setErrorMessage('Unexpected error submitting transaction for analysis.')
      }
    } finally {
      setIsSubmitting(false)
    }
  }

  return (
    <section className="rounded-xl border border-slate-800/90 bg-[#0D1424] p-5 shadow-sm">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <div>
          <h2 className="text-base font-semibold text-white">
            Analyze Transaction
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Evaluate a payment through the deterministic risk engine
          </p>
        </div>
        <button
          type="button"
          onClick={() => setReference(generateDefaultRef())}
          className="rounded-md border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs font-medium text-slate-300 transition hover:border-sky-500/50 hover:text-sky-300"
        >
          Auto Ref
        </button>
      </div>

      <form onSubmit={handleSubmit} className="mt-4 space-y-3.5" noValidate>
        <div>
          <label
            htmlFor="tx-reference"
            className="mb-1 block text-xs font-medium text-slate-300"
          >
            Transaction Reference
          </label>
          <input
            id="tx-reference"
            type="text"
            value={reference}
            onChange={(e) => setReference(e.target.value)}
            placeholder="e.g. FT-2026-0042"
            maxLength={64}
            required
            className="w-full rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
          />
        </div>

        <div className="grid grid-cols-1 gap-3 sm:grid-cols-2">
          <div>
            <label
              htmlFor="tx-sender"
              className="mb-1 block text-xs font-medium text-slate-300"
            >
              Sender Identifier
            </label>
            <input
              id="tx-sender"
              type="text"
              value={senderId}
              onChange={(e) => setSenderId(e.target.value)}
              placeholder="e.g. ACCT_ALPHA"
              maxLength={128}
              required
              className="w-full rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          <div>
            <label
              htmlFor="tx-receiver"
              className="mb-1 block text-xs font-medium text-slate-300"
            >
              Receiver Identifier
            </label>
            <input
              id="tx-receiver"
              type="text"
              value={receiverId}
              onChange={(e) => setReceiverId(e.target.value)}
              placeholder="e.g. ACCT_HUB_99"
              maxLength={128}
              required
              className="w-full rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>
        </div>

        <div className="grid grid-cols-3 gap-3">
          <div className="col-span-2">
            <label
              htmlFor="tx-amount"
              className="mb-1 block text-xs font-medium text-slate-300"
            >
              Amount
            </label>
            <input
              id="tx-amount"
              type="number"
              step="0.01"
              min="0.01"
              value={amount}
              onChange={(e) => setAmount(e.target.value)}
              placeholder="e.g. 1250.00"
              required
              className="w-full rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-2 text-sm text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>

          <div>
            <label
              htmlFor="tx-currency"
              className="mb-1 block text-xs font-medium text-slate-300"
            >
              Currency
            </label>
            <input
              id="tx-currency"
              type="text"
              value={currency}
              onChange={(e) => setCurrency(e.target.value.toUpperCase())}
              placeholder="USD"
              maxLength={3}
              required
              className="w-full rounded-lg border border-slate-700/80 bg-[#121B2E] px-3 py-2 text-sm uppercase text-white placeholder-slate-500 focus:border-sky-500 focus:outline-none focus:ring-1 focus:ring-sky-500"
            />
          </div>
        </div>

        {errorMessage && (
          <div
            role="alert"
            className={`rounded-lg border px-3 py-2.5 text-xs ${
              isDuplicateError
                ? 'border-amber-500/40 bg-amber-500/10 text-amber-200'
                : 'border-red-500/40 bg-red-500/10 text-red-200'
            }`}
          >
            <span className="font-semibold">
              {isDuplicateError ? 'Duplicate Reference (409): ' : 'Submission Error: '}
            </span>
            {errorMessage}
          </div>
        )}

        <button
          type="submit"
          disabled={isSubmitting}
          className="flex w-full items-center justify-center gap-2 rounded-lg bg-sky-600 px-4 py-2.5 text-sm font-medium text-white transition hover:bg-sky-500 disabled:cursor-not-allowed disabled:opacity-60"
        >
          {isSubmitting ? 'Analyzing Transaction…' : 'Submit & Analyze Risk'}
        </button>
      </form>

      {/* Immediate submission feedback card */}
      {latestResult && (
        <div className="mt-5 rounded-lg border border-slate-700/70 bg-[#121B2E] p-4">
          <div className="flex flex-wrap items-center justify-between gap-2">
            <div>
              <p className="text-[11px] font-medium uppercase tracking-wider text-slate-400">
                Latest Analysis Result
              </p>
              <p className="mt-0.5 font-mono text-xs text-sky-300">
                {latestResult.transaction.reference} ·{' '}
                {formatAmount(
                  latestResult.transaction.amount,
                  latestResult.transaction.currency,
                )}
              </p>
            </div>
            <div className="flex items-center gap-2">
              <span
                className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${getRiskBadgeClasses(
                  latestResult.risk_level,
                )}`}
              >
                {latestResult.risk_level}
              </span>
              <span
                className={`rounded-md border px-2 py-0.5 text-xs font-medium ${getStatusBadgeClasses(
                  latestResult.investigation_status,
                )}`}
              >
                {latestResult.investigation_status}
              </span>
            </div>
          </div>

          <div className="mt-3">
            <div className="flex items-center justify-between text-xs">
              <span className="text-slate-400">Heuristic Risk Score</span>
              <span className="font-semibold tabular-nums text-white">
                {latestResult.risk_score} / 100
              </span>
            </div>
            <div className="mt-1.5 h-2 w-full overflow-hidden rounded-full bg-slate-800">
              <div
                className={`h-full transition-all ${getRiskBarColor(latestResult.risk_score)}`}
                style={{ width: `${Math.min(100, Math.max(4, latestResult.risk_score))}%` }}
              />
            </div>
          </div>

          <p className="mt-3 text-xs leading-relaxed text-slate-300">
            {latestResult.explanation}
          </p>

          {latestResult.evidence.length > 0 && (
            <div className="mt-3 space-y-2 border-t border-slate-700/60 pt-3">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Triggered Indicators ({latestResult.evidence.length})
              </p>
              {latestResult.evidence.map((ev, index) => (
                <div
                  key={ev.id ?? `${ev.evidence_type}-${index}`}
                  className="rounded-md border border-slate-800 bg-[#0D1424] px-3 py-2 text-xs"
                >
                  <div className="flex items-center justify-between gap-2">
                    <span className="font-medium text-slate-200">
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
                  <p className="mt-1 text-slate-400">{ev.description}</p>
                </div>
              ))}
            </div>
          )}

          <div className="mt-3">
            <MLAnomalyCard mlAnomaly={latestResult.ml_anomaly} compact />
          </div>

          <div className="mt-3 flex flex-wrap gap-2 border-t border-slate-700/60 pt-3">
            <button
              type="button"
              onClick={() => onSelectTransaction(latestResult.transaction.id)}
              className="rounded border border-sky-500/35 bg-sky-500/10 px-2.5 py-1 text-xs font-medium text-sky-300 transition hover:bg-sky-500/20"
            >
              Open Full Investigation
            </button>
            <button
              type="button"
              onClick={() => onInspectAccount(latestResult.transaction.sender_id)}
              className="rounded border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-300 transition hover:border-slate-500 hover:text-white"
            >
              Inspect {latestResult.transaction.sender_id}
            </button>
            <button
              type="button"
              onClick={() => onInspectAccount(latestResult.transaction.receiver_id)}
              className="rounded border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-xs text-slate-300 transition hover:border-slate-500 hover:text-white"
            >
              Inspect {latestResult.transaction.receiver_id}
            </button>
          </div>
        </div>
      )}
    </section>
  )
}
