/**
 * MLAnomalyCard Component
 * Renders the experimental unsupervised IsolationForest anomaly detection signal
 * strictly separated from deterministic rule scores and probabilities.
 */

import type { MLAnomalyResponse } from '../types/api'

interface MLAnomalyCardProps {
  mlAnomaly?: MLAnomalyResponse | null
  compact?: boolean
}

function getMlStatusBadge(status: string | undefined, available: boolean): {
  label: string
  classes: string
} {
  if (!available || !status || status === 'UNAVAILABLE') {
    return {
      label: 'Unavailable',
      classes: 'border-slate-600/50 bg-slate-800/70 text-slate-300',
    }
  }
  if (status === 'ANOMALY') {
    return {
      label: 'Behavioral Outlier',
      classes: 'border-fuchsia-500/40 bg-fuchsia-500/15 text-fuchsia-300',
    }
  }
  if (status === 'NORMAL') {
    return {
      label: 'No Outlier Flagged',
      classes: 'border-sky-500/35 bg-sky-500/10 text-sky-200',
    }
  }
  return {
    label: 'Unavailable',
    classes: 'border-slate-600/50 bg-slate-800/70 text-slate-300',
  }
}

export function MLAnomalyCard({ mlAnomaly, compact = false }: MLAnomalyCardProps) {
  const available = Boolean(mlAnomaly?.available)
  const badge = getMlStatusBadge(mlAnomaly?.status, available)
  const decisionScore =
    mlAnomaly?.decision_score !== null && mlAnomaly?.decision_score !== undefined
      ? mlAnomaly.decision_score.toFixed(4)
      : 'N/A'

  return (
    <div className="rounded-lg border border-indigo-500/30 bg-[#0D1526] p-4">
      <div className="flex flex-wrap items-start justify-between gap-2">
        <div>
          <div className="flex flex-wrap items-center gap-2">
            <h3 className="text-xs font-semibold uppercase tracking-wider text-indigo-200">
              ML Anomaly Intelligence
            </h3>
            <span className="rounded border border-indigo-400/40 bg-indigo-500/15 px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wide text-indigo-300">
              Experimental
            </span>
          </div>
          <p className="mt-1 text-[11px] text-slate-400">
            Independent unsupervised IsolationForest outlier check — does not modify deterministic risk score.
          </p>
        </div>

        <span
          className={`rounded-md border px-2 py-0.5 text-xs font-semibold ${badge.classes}`}
        >
          {badge.label}
        </span>
      </div>

      {!mlAnomaly || !available ? (
        <div className="mt-3 rounded-md border border-slate-800 bg-[#090E1A] px-3 py-2.5 text-xs text-slate-300">
          <p>
            {mlAnomaly?.explanation ??
              'Experimental ML anomaly signal is currently unavailable for this transaction. Deterministic rules remain active.'}
          </p>
          {mlAnomaly && (
            <p className="mt-1.5 text-[11px] text-slate-500">
              Causal prior baseline rows found: {mlAnomaly.training_sample_count} /{' '}
              {mlAnomaly.minimum_samples_required} required (seed={mlAnomaly.random_state}).
            </p>
          )}
        </div>
      ) : (
        <div className="mt-3 space-y-3">
          <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
            <div className="rounded-md border border-slate-800 bg-[#090E1A] px-3 py-2">
              <p className="text-[11px] text-slate-400">
                IsolationForest Decision Score
              </p>
              <p className="mt-0.5 font-mono text-base font-semibold tabular-nums text-white">
                {decisionScore}
              </p>
              <p className="mt-0.5 text-[10px] text-slate-500">
                Lower = more unusual (&lt; 0.0000 flags outlier). Not a fraud probability.
              </p>
            </div>

            <div className="rounded-md border border-slate-800 bg-[#090E1A] px-3 py-2">
              <p className="text-[11px] text-slate-400">Causal Training Baseline</p>
              <p className="mt-0.5 text-sm font-semibold tabular-nums text-slate-100">
                {mlAnomaly.training_sample_count} prior transactions
              </p>
              <p className="mt-0.5 text-[10px] text-slate-500">
                {mlAnomaly.model_name} · random_state={mlAnomaly.random_state}
              </p>
            </div>
          </div>

          <p className="text-xs leading-relaxed text-slate-300">
            {mlAnomaly.explanation}
          </p>

          {mlAnomaly.status === 'NORMAL' && (
            <p className="rounded-md border border-slate-800 bg-[#090E1A] px-3 py-1.5 text-[11px] text-slate-400">
              Baseline fit only: not a guarantee that the transaction is safe or free of fraud.
            </p>
          )}

          {mlAnomaly.feature_deviations.length > 0 && (
            <div className="space-y-1.5 border-t border-slate-800/80 pt-2.5">
              <p className="text-[11px] font-semibold uppercase tracking-wider text-slate-400">
                Descriptive Feature Deviations (Statistical Distance, Not SHAP / Not Causal)
              </p>
              <div className={compact ? 'space-y-1.5' : 'grid grid-cols-1 gap-2 lg:grid-cols-3'}>
                {mlAnomaly.feature_deviations.map((dev) => (
                  <div
                    key={dev.feature_name}
                    className="rounded-md border border-slate-800 bg-[#090E1A] px-3 py-2 text-xs"
                  >
                    <div className="flex items-center justify-between gap-2">
                      <span className="font-medium text-slate-200">
                        {dev.display_label}
                      </span>
                      <span className="rounded border border-slate-700 bg-slate-800/80 px-1.5 py-0.5 font-mono text-[10px] tabular-nums text-indigo-300">
                        {dev.z_score_deviation !== null
                          ? `z=${dev.z_score_deviation >= 0 ? '+' : ''}${dev.z_score_deviation.toFixed(2)}`
                          : 'Baseline shift'}
                      </span>
                    </div>
                    <p className="mt-1 text-[11px] leading-relaxed text-slate-400">
                      {dev.summary}
                    </p>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!compact && (
            <div className="border-t border-slate-800/80 pt-2 text-[11px] leading-relaxed text-slate-500">
              <p>{mlAnomaly.methodology_note}</p>
              <p className="mt-1">{mlAnomaly.limitations}</p>
            </div>
          )}
          {compact && (
            <p className="border-t border-slate-800/80 pt-2 text-[11px] text-slate-500">
              {mlAnomaly.limitations}
            </p>
          )}
        </div>
      )}
    </div>
  )
}
