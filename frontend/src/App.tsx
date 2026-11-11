/**
 * App Component — FraudTrace AI Landing Page
 * ===========================================
 * This is the root component of the React application.
 * It renders the main landing page, which includes:
 *
 *   - Project name and tagline
 *   - Backend connection status (via HealthStatus component)
 *
 * In future milestones, navigation and dashboard content
 * will be added here.
 */

import HealthStatus from './components/HealthStatus'

export default function App() {
  return (
    // min-h-screen: makes the page at least as tall as the browser window
    // bg-gray-950:  very dark background (almost black)
    // flex + items/justify-center: perfectly centres content horizontally and vertically
    <main className="flex min-h-screen flex-col items-center justify-center bg-gray-950 px-4">
      <div className="max-w-2xl space-y-8 text-center">

        {/* Badge */}
        <div className="inline-block rounded-full border border-blue-500/30 bg-blue-500/10 px-4 py-1.5">
          <span className="text-xs font-semibold uppercase tracking-widest text-blue-400">
            Fraud Intelligence Platform
          </span>
        </div>

        {/* Project name */}
        {/* text-5xl: very large text; font-bold: heavy weight; tracking-tight: tighter letter spacing */}
        <h1 className="text-5xl font-bold tracking-tight text-white sm:text-6xl">
          FraudTrace{' '}
          {/* text-blue-400: the "AI" part is highlighted in blue */}
          <span className="text-blue-400">AI</span>
        </h1>

        {/* Tagline */}
        <p className="text-lg leading-relaxed text-gray-400 sm:text-xl">
          One suspicious payment can reveal an entire fraud network.
        </p>

        {/* Backend connection status */}
        {/* This component fetches /health and shows Checking / Connected / Disconnected */}
        <div className="pt-2">
          <HealthStatus />
        </div>

      </div>
    </main>
  )
}
