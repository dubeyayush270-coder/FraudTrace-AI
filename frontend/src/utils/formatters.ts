/**
 * FraudTrace AI — Formatting & Risk Styling Utilities
 */

export function formatAmount(amount: string | number, currency: string): string {
  const numeric = typeof amount === 'number' ? amount : Number(amount)
  if (!Number.isFinite(numeric)) {
    return `${amount} ${currency}`
  }

  try {
    return new Intl.NumberFormat('en-US', {
      style: 'currency',
      currency: currency.toUpperCase(),
      minimumFractionDigits: 2,
      maximumFractionDigits: 2,
    }).format(numeric)
  } catch {
    return `${numeric.toFixed(2)} ${currency.toUpperCase()}`
  }
}

export function formatTimestamp(isoString: string): string {
  const date = new Date(isoString)
  if (Number.isNaN(date.getTime())) {
    return isoString
  }
  return new Intl.DateTimeFormat('en-US', {
    month: 'short',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false,
  }).format(date)
}

export function getRiskBadgeClasses(level: string | null | undefined): string {
  const normalized = (level ?? 'LOW').toUpperCase()
  switch (normalized) {
    case 'CRITICAL':
      return 'border-red-500/40 bg-red-500/15 text-red-300'
    case 'HIGH':
      return 'border-orange-500/40 bg-orange-500/15 text-orange-300'
    case 'MEDIUM':
      return 'border-amber-500/40 bg-amber-500/15 text-amber-300'
    case 'LOW':
      return 'border-emerald-500/40 bg-emerald-500/15 text-emerald-300'
    default:
      return 'border-slate-600/50 bg-slate-700/30 text-slate-300'
  }
}

export function getStatusBadgeClasses(status: string | null | undefined): string {
  const normalized = (status ?? 'PENDING').toUpperCase()
  switch (normalized) {
    case 'FLAGGED':
    case 'OPEN':
      return 'border-rose-500/35 bg-rose-500/10 text-rose-300'
    case 'UNDER_REVIEW':
    case 'IN_REVIEW':
      return 'border-amber-500/35 bg-amber-500/10 text-amber-300'
    case 'CLEARED':
    case 'CLOSED':
      return 'border-emerald-500/35 bg-emerald-500/10 text-emerald-300'
    default:
      return 'border-slate-600/40 bg-slate-700/25 text-slate-300'
  }
}

export function getRiskBarColor(score: number | null | undefined): string {
  const val = score ?? 0
  if (val >= 75) return 'bg-red-500'
  if (val >= 50) return 'bg-orange-500'
  if (val >= 25) return 'bg-amber-400'
  return 'bg-emerald-400'
}

export function formatPatternLabel(patternType: string): string {
  switch (patternType.toUpperCase()) {
    case 'HIGH_VOLUME_RECEIVER':
      return 'High-Volume Receiver'
    case 'RAPID_FUND_MOVEMENT':
      return 'Rapid Fund Movement'
    case 'SHARED_RECEIVER':
      return 'Shared Receiver'
    default:
      return patternType.replaceAll('_', ' ')
  }
}

export function formatEvidenceLabel(evidenceType: string): string {
  switch (evidenceType.toUpperCase()) {
    case 'TRANSACTION_VELOCITY':
      return 'Transaction Velocity'
    case 'AMOUNT_ANOMALY':
      return 'Amount Anomaly'
    case 'NEW_RECIPIENT':
      return 'New Recipient'
    case 'REPEATED_RECIPIENT_ACTIVITY':
      return 'Repeated Recipient Activity'
    default:
      return evidenceType.replaceAll('_', ' ')
  }
}
