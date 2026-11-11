/**
 * HealthStatus Component
 * ======================
 * Calls the backend /health endpoint when the page loads and
 * displays one of three states:
 *
 *   - "checking"      → yellow pulsing dot, shown while the fetch is in progress
 *   - "connected"     → green dot, shown when the backend responds with 200 OK
 *                       and the body contains { "status": "ok" }
 *   - "disconnected"  → red dot, shown when the fetch fails, the server returns
 *                       an error, or the payload is not { "status": "ok" }
 *
 * How it works:
 *   1. The component renders for the first time (mounts).
 *   2. useEffect runs — this is React's way of running code after rendering.
 *   3. fetch() sends a GET request to the backend health endpoint.
 *   4. We verify the HTTP response code is successful (200 OK).
 *   5. We parse the JSON body and verify data.status === 'ok'.
 *   6. Depending on the result, we call setStatus() to update the state.
 *   7. React automatically re-renders the component with the new status.
 *
 * The backend URL comes from the VITE_API_URL environment variable,
 * falling back to http://127.0.0.1:8000 if not set.
 */

import { useEffect, useState } from 'react'

// The three possible connection states.
// Using a TypeScript union type means the compiler will warn us
// if we ever use a value that is not one of these three strings.
type Status = 'checking' | 'connected' | 'disconnected'

export default function HealthStatus() {
  // useState gives us a reactive variable.
  // When we call setStatus(...), React re-renders this component.
  const [status, setStatus] = useState<Status>('checking')

  // useEffect runs AFTER the first render.
  // The empty array [] at the end means "run this only once, on mount".
  useEffect(() => {
    // Read the backend URL from Vite's environment variable system,
    // with a safe fallback to the local FastAPI default address.
    const apiUrl = import.meta.env.VITE_API_URL ?? 'http://127.0.0.1:8000'

    fetch(`${apiUrl}/health`)
      .then(async (response) => {
        // Step 1: verify HTTP status code (200–299)
        if (!response.ok) {
          setStatus('disconnected')
          return
        }

        // Step 2: safely parse JSON response
        const data = await response.json()

        // Step 3: verify explicit payload { "status": "ok" }
        if (data && typeof data === 'object' && data.status === 'ok') {
          setStatus('connected')
        } else {
          setStatus('disconnected')
        }
      })
      .catch(() => {
        // .catch() runs if the network request fails (e.g. backend down)
        // or if response.json() encounters invalid JSON syntax
        setStatus('disconnected')
      })
  }, []) // ← empty dependency array = run once on mount

  // Visual configuration for each state.
  // We define all three variants here so the logic below stays clean.
  const config: Record<Status, { dot: string; label: string; text: string }> = {
    checking: {
      dot: 'bg-yellow-400 animate-pulse',
      label: 'Checking…',
      text: 'text-yellow-400',
    },
    connected: {
      dot: 'bg-green-400',
      label: 'Backend Connected',
      text: 'text-green-400',
    },
    disconnected: {
      dot: 'bg-red-400',
      label: 'Backend Disconnected',
      text: 'text-red-400',
    },
  }

  const { dot, label, text } = config[status]

  return (
    <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/5 px-4 py-2">
      {/* Coloured dot indicator (aria-hidden because the text label conveys the status) */}
      <span aria-hidden="true" className={`inline-block h-2.5 w-2.5 rounded-full ${dot}`} />
      {/* Status label */}
      <span className={`text-sm font-medium ${text}`}>{label}</span>
    </div>
  )
}
