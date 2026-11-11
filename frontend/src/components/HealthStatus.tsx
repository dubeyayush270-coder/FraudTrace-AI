/**
 * HealthStatus Component
 * ======================
 * Calls the backend /health endpoint on mount (and when refreshTrigger increments)
 * and displays one of three states:
 *   - "checking"      -> yellow pulsing dot
 *   - "connected"     -> green dot (HTTP 200 OK with { "status": "ok" })
 *   - "disconnected"  -> red dot
 */

import { useEffect, useState } from 'react'
import { API_BASE_URL } from '../services/api'

type Status = 'checking' | 'connected' | 'disconnected'

interface HealthStatusProps {
  refreshTrigger?: number
}

export default function HealthStatus({ refreshTrigger = 0 }: HealthStatusProps) {
  const [status, setStatus] = useState<Status>('checking')

  useEffect(() => {
    let active = true

    fetch(`${API_BASE_URL}/health`)
      .then(async (response) => {
        if (!active) return
        if (!response.ok) {
          setStatus('disconnected')
          return
        }

        const data = await response.json()
        if (!active) return

        if (data && typeof data === 'object' && data.status === 'ok') {
          setStatus('connected')
        } else {
          setStatus('disconnected')
        }
      })
      .catch(() => {
        if (active) {
          setStatus('disconnected')
        }
      })

    return () => {
      active = false
    }
  }, [refreshTrigger])

  const config: Record<Status, { dot: string; label: string; text: string }> = {
    checking: {
      dot: 'bg-yellow-400 animate-pulse',
      label: 'Checking…',
      text: 'text-yellow-300',
    },
    connected: {
      dot: 'bg-emerald-400',
      label: 'Backend Connected',
      text: 'text-emerald-300',
    },
    disconnected: {
      dot: 'bg-red-400',
      label: 'Backend Disconnected',
      text: 'text-red-300',
    },
  }

  const { dot, label, text } = config[status]

  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-slate-700/80 bg-slate-900/90 px-3.5 py-1.5">
      <span aria-hidden="true" className={`inline-block h-2 w-2 rounded-full ${dot}`} />
      <span className={`text-xs font-medium ${text}`}>{label}</span>
    </div>
  )
}
