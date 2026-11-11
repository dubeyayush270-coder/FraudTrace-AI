/**
 * NetworkGraphPanel Component
 * Renders an interactive directed SVG transaction network graph showing:
 * - Account nodes (clickable to inspect via GET /api/v1/network/accounts/{id})
 * - Directed sender -> receiver edges with arrowheads and curved offsets
 * - Visual distinction for suspicious pattern participants and selected account
 * - Interactive edge reference & amount readout (never invents connections)
 */

import { useMemo, useState } from 'react'
import type {
  AccountNetworkResponse,
  NetworkOverviewResponse,
  TransactionResponse,
} from '../types/api'
import { formatAmount, formatTimestamp } from '../utils/formatters'

interface NetworkGraphPanelProps {
  transactions: TransactionResponse[]
  networkOverview: NetworkOverviewResponse | null
  selectedAccountId: string | null
  accountNetwork: AccountNetworkResponse | null
  isLoading: boolean
  onSelectAccount: (accountId: string) => void
  onSelectTransactionRef: (reference: string) => void
}

type GraphScope = 'all' | 'suspicious' | 'focused'

interface EdgeSummary {
  key: string
  source: string
  target: string
  txns: TransactionResponse[]
  totalAmountLabel: string
  isSuspiciousLink: boolean
}

interface PositionedNode {
  id: string
  x: number
  y: number
  isSuspicious: boolean
  inCount: number
  outCount: number
}

const SVG_WIDTH = 760
const SVG_HEIGHT = 400
const NODE_RADIUS = 20
const MAX_DISPLAY_NODES = 24

function shortenAccountLabel(id: string): string {
  if (id.length <= 13) return id
  return `${id.slice(0, 11)}…`
}

function computeDeterministicLayout(
  nodeIds: string[],
  edges: EdgeSummary[],
): Map<string, { x: number; y: number }> {
  const positions = new Map<string, { x: number; y: number }>()
  const count = nodeIds.length
  if (count === 0) return positions

  if (count === 1) {
    positions.set(nodeIds[0], { x: SVG_WIDTH / 2, y: SVG_HEIGHT / 2 })
    return positions
  }

  // Initial deterministic circle placement
  const cx = SVG_WIDTH / 2
  const cy = SVG_HEIGHT / 2
  const radiusX = Math.min(250, 95 + count * 12)
  const radiusY = Math.min(140, 65 + count * 8)

  nodeIds.forEach((id, idx) => {
    const angle = (2 * Math.PI * idx) / count - Math.PI / 2
    positions.set(id, {
      x: cx + radiusX * Math.cos(angle),
      y: cy + radiusY * Math.sin(angle),
    })
  })

  // Force-directed relaxation (deterministic, synchronous)
  const kRepel = 3800
  const kSpring = 0.045
  const idealEdgeLen = 145
  const centerPull = 0.018

  for (let step = 0; step < 85; step += 1) {
    const disp = new Map<string, { dx: number; dy: number }>()
    for (const id of nodeIds) {
      disp.set(id, { dx: 0, dy: 0 })
    }

    // Pairwise repulsion
    for (let i = 0; i < count; i += 1) {
      for (let j = i + 1; j < count; j += 1) {
        const a = nodeIds[i]
        const b = nodeIds[j]
        const pa = positions.get(a)!
        const pb = positions.get(b)!
        let dx = pb.x - pa.x
        let dy = pb.y - pa.y
        let dist = Math.hypot(dx, dy)
        if (dist < 1) {
          dx = 1
          dy = 0.5
          dist = Math.hypot(dx, dy)
        }
        const force = kRepel / (dist * dist)
        const fx = (dx / dist) * force
        const fy = (dy / dist) * force
        disp.get(a)!.dx -= fx
        disp.get(a)!.dy -= fy
        disp.get(b)!.dx += fx
        disp.get(b)!.dy += fy
      }
    }

    // Spring attraction along edges
    for (const edge of edges) {
      if (edge.source === edge.target) continue
      const ps = positions.get(edge.source)
      const pt = positions.get(edge.target)
      if (!ps || !pt) continue
      const dx = pt.x - ps.x
      const dy = pt.y - ps.y
      const dist = Math.max(1, Math.hypot(dx, dy))
      const force = kSpring * (dist - idealEdgeLen)
      const fx = (dx / dist) * force
      const fy = (dy / dist) * force
      disp.get(edge.source)!.dx += fx
      disp.get(edge.source)!.dy += fy
      disp.get(edge.target)!.dx -= fx
      disp.get(edge.target)!.dy -= fy
    }

    // Apply displacements + center gravity + bounding box
    const maxStep = Math.max(2, 18 * (1 - step / 85))
    for (const id of nodeIds) {
      const p = positions.get(id)!
      const d = disp.get(id)!
      d.dx += (cx - p.x) * centerPull
      d.dy += (cy - p.y) * centerPull

      const mag = Math.hypot(d.dx, d.dy)
      if (mag > 0) {
        const stepDist = Math.min(mag, maxStep)
        p.x += (d.dx / mag) * stepDist
        p.y += (d.dy / mag) * stepDist
      }

      p.x = Math.max(65, Math.min(SVG_WIDTH - 65, p.x))
      p.y = Math.max(52, Math.min(SVG_HEIGHT - 55, p.y))
    }
  }

  return positions
}

export default function NetworkGraphPanel({
  transactions,
  networkOverview,
  selectedAccountId,
  accountNetwork,
  isLoading,
  onSelectAccount,
  onSelectTransactionRef,
}: NetworkGraphPanelProps) {
  const [scope, setScope] = useState<GraphScope>('all')
  const [hoveredEdgeKey, setHoveredEdgeKey] = useState<string | null>(null)

  const suspiciousSet = useMemo(
    () => new Set(networkOverview?.suspicious_account_identifiers ?? []),
    [networkOverview],
  )

  const { nodes, edges, isTruncated } = useMemo(() => {
    if (transactions.length === 0) {
      return { nodes: [] as PositionedNode[], edges: [] as EdgeSummary[], isTruncated: false }
    }

    const focusedAccounts = new Set<string>()
    if (scope === 'focused' && selectedAccountId) {
      focusedAccounts.add(selectedAccountId)
      if (accountNetwork && accountNetwork.account_id === selectedAccountId) {
        for (const conn of accountNetwork.connected_accounts) {
          focusedAccounts.add(conn.account_id)
        }
      }
    }

    // Filter transactions according to graph scope
    const filteredTxns = transactions.filter((txn) => {
      if (scope === 'suspicious') {
        return suspiciousSet.has(txn.sender_id) || suspiciousSet.has(txn.receiver_id)
      }
      if (scope === 'focused' && selectedAccountId) {
        return (
          focusedAccounts.has(txn.sender_id) && focusedAccounts.has(txn.receiver_id)
        )
      }
      return true
    })

    // Collect distinct accounts prioritizing suspicious + selected + recent activity
    const allAccountIds = new Set<string>()
    const inCounts = new Map<string, number>()
    const outCounts = new Map<string, number>()

    for (const txn of filteredTxns) {
      allAccountIds.add(txn.sender_id)
      allAccountIds.add(txn.receiver_id)
      outCounts.set(txn.sender_id, (outCounts.get(txn.sender_id) ?? 0) + 1)
      inCounts.set(txn.receiver_id, (inCounts.get(txn.receiver_id) ?? 0) + 1)
    }

    let orderedIds = Array.from(allAccountIds).sort((a, b) => {
      const aSelected = a === selectedAccountId ? 1 : 0
      const bSelected = b === selectedAccountId ? 1 : 0
      if (aSelected !== bSelected) return bSelected - aSelected
      const aSusp = suspiciousSet.has(a) ? 1 : 0
      const bSusp = suspiciousSet.has(b) ? 1 : 0
      if (aSusp !== bSusp) return bSusp - aSusp
      const aDeg = (inCounts.get(a) ?? 0) + (outCounts.get(a) ?? 0)
      const bDeg = (inCounts.get(b) ?? 0) + (outCounts.get(b) ?? 0)
      if (aDeg !== bDeg) return bDeg - aDeg
      return a.localeCompare(b)
    })

    const truncated = orderedIds.length > MAX_DISPLAY_NODES
    if (truncated) {
      orderedIds = orderedIds.slice(0, MAX_DISPLAY_NODES)
    }
    const visibleSet = new Set(orderedIds)

    // Group transactions by directed pair (sender -> receiver)
    const groupedEdges = new Map<string, TransactionResponse[]>()
    for (const txn of filteredTxns) {
      if (!visibleSet.has(txn.sender_id) || !visibleSet.has(txn.receiver_id)) {
        continue
      }
      const key = `${txn.sender_id}__TO__${txn.receiver_id}`
      const bucket = groupedEdges.get(key)
      if (bucket) {
        bucket.push(txn)
      } else {
        groupedEdges.set(key, [txn])
      }
    }

    const edgeList: EdgeSummary[] = Array.from(groupedEdges.entries()).map(
      ([key, txns]) => {
        const source = txns[0].sender_id
        const target = txns[0].receiver_id
        const currencies = new Set(txns.map((t) => t.currency))
        let totalAmountLabel = `${txns.length} txn(s)`
        if (currencies.size === 1) {
          const sum = txns.reduce((acc, item) => acc + Number(item.amount || 0), 0)
          totalAmountLabel = formatAmount(sum, txns[0].currency)
        }
        return {
          key,
          source,
          target,
          txns,
          totalAmountLabel,
          isSuspiciousLink: suspiciousSet.has(source) && suspiciousSet.has(target),
        }
      },
    )

    const coords = computeDeterministicLayout(orderedIds, edgeList)
    const positionedNodes: PositionedNode[] = orderedIds.map((id) => {
      const pos = coords.get(id) ?? { x: SVG_WIDTH / 2, y: SVG_HEIGHT / 2 }
      return {
        id,
        x: pos.x,
        y: pos.y,
        isSuspicious: suspiciousSet.has(id),
        inCount: inCounts.get(id) ?? 0,
        outCount: outCounts.get(id) ?? 0,
      }
    })

    return {
      nodes: positionedNodes,
      edges: edgeList,
      isTruncated: truncated,
    }
  }, [transactions, suspiciousSet, scope, selectedAccountId, accountNetwork])

  const nodeMap = useMemo(() => {
    const map = new Map<string, PositionedNode>()
    for (const node of nodes) {
      map.set(node.id, node)
    }
    return map
  }, [nodes])

  const edgeLookup = useMemo(() => new Set(edges.map((e) => e.key)), [edges])

  const activeEdge = useMemo(
    () => edges.find((e) => e.key === hoveredEdgeKey) ?? edges[0] ?? null,
    [edges, hoveredEdgeKey],
  )

  return (
    <section
      aria-label="Fraud network visualization"
      className="flex flex-col rounded-xl border border-slate-800/90 bg-[#0D1424] p-5 shadow-sm"
    >
      <div className="flex flex-col gap-3 sm:flex-row sm:items-center sm:justify-between">
        <div>
          <h2 className="text-base font-semibold text-white">
            Transaction Network Graph
          </h2>
          <p className="mt-0.5 text-xs text-slate-400">
            Directed money-flow map · Click any account node to inspect 1–2 hop connections
          </p>
        </div>

        <div className="flex flex-wrap gap-1.5">
          <button
            type="button"
            onClick={() => setScope('all')}
            className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition ${
              scope === 'all'
                ? 'border-sky-500/60 bg-sky-500/15 text-sky-300'
                : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            All Nodes
          </button>
          <button
            type="button"
            onClick={() => setScope('suspicious')}
            className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition ${
              scope === 'suspicious'
                ? 'border-amber-500/60 bg-amber-500/15 text-amber-300'
                : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            Pattern Leads
          </button>
          <button
            type="button"
            disabled={!selectedAccountId}
            onClick={() => setScope('focused')}
            className={`rounded-md border px-2.5 py-1 text-[11px] font-medium transition disabled:cursor-not-allowed disabled:opacity-40 ${
              scope === 'focused'
                ? 'border-sky-500/60 bg-sky-500/15 text-sky-300'
                : 'border-slate-700/70 bg-slate-900/60 text-slate-400 hover:text-slate-200'
            }`}
          >
            Selected Focus
          </button>
        </div>
      </div>

      {/* Legend */}
      <div className="mt-3 flex flex-wrap items-center gap-4 text-[11px] text-slate-400">
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full border-2 border-amber-400 bg-amber-500/30" />
          Pattern Participant
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full border-2 border-slate-400 bg-slate-700" />
          Standard Account
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="h-2.5 w-2.5 rounded-full border-2 border-sky-400 bg-sky-500/30" />
          Selected Account
        </span>
        <span className="inline-flex items-center gap-1.5">
          <span aria-hidden="true" className="text-sky-400">──▶</span>
          Sender to Receiver
        </span>
      </div>

      {isTruncated && (
        <div className="mt-2 rounded-md border border-amber-500/30 bg-amber-500/10 px-3 py-1.5 text-[11px] text-amber-200">
          Showing top {MAX_DISPLAY_NODES} accounts by alert priority and connectivity. Select any account and choose &ldquo;Selected Focus&rdquo; to isolate its neighborhood.
        </div>
      )}

      {isLoading && transactions.length === 0 ? (
        <div className="mt-4 h-[360px] animate-pulse rounded-xl bg-slate-800/50" />
      ) : nodes.length === 0 ? (
        <div className="mt-4 flex h-[320px] flex-col items-center justify-center rounded-xl border border-dashed border-slate-700/80 bg-[#121B2E]/40 px-4 text-center">
          <p className="text-sm font-medium text-slate-300">
            No graph connections available for this view
          </p>
          <p className="mt-1 text-xs text-slate-500">
            {transactions.length === 0
              ? 'Analyze transactions or seed demo data to visualize account relationships.'
              : 'Switch back to "All Nodes" or select an account with connected transactions.'}
          </p>
        </div>
      ) : (
        <div className="mt-3 overflow-hidden rounded-xl border border-slate-800 bg-[#080D18]">
          <svg
            viewBox={`0 0 ${SVG_WIDTH} ${SVG_HEIGHT}`}
            className="h-[360px] w-full select-none"
            role="img"
            aria-label="Directed transaction network graph"
          >
            <defs>
              <marker
                id="ft-arrow-normal"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#64748b" />
              </marker>
              <marker
                id="ft-arrow-suspicious"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6"
                markerHeight="6"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#f59e0b" />
              </marker>
              <marker
                id="ft-arrow-active"
                viewBox="0 0 10 10"
                refX="8"
                refY="5"
                markerWidth="6.5"
                markerHeight="6.5"
                orient="auto-start-reverse"
              >
                <path d="M 0 1 L 10 5 L 0 9 z" fill="#38bdf8" />
              </marker>
            </defs>

            {/* Directed edges */}
            {edges.map((edge) => {
              const src = nodeMap.get(edge.source)
              const dst = nodeMap.get(edge.target)
              if (!src || !dst) return null

              const isHighlighted =
                hoveredEdgeKey === edge.key ||
                edge.source === selectedAccountId ||
                edge.target === selectedAccountId

              // Self-loop edge handling
              if (edge.source === edge.target) {
                const pathD = `M ${src.x - 10} ${src.y - NODE_RADIUS} C ${src.x - 28} ${src.y - 54}, ${src.x + 28} ${src.y - 54}, ${src.x + 10} ${src.y - NODE_RADIUS - 2}`
                return (
                  <path
                    key={edge.key}
                    d={pathD}
                    fill="none"
                    stroke={isHighlighted ? '#38bdf8' : '#64748b'}
                    strokeWidth={isHighlighted ? 2.2 : 1.5}
                    markerEnd={isHighlighted ? 'url(#ft-arrow-active)' : 'url(#ft-arrow-normal)'}
                    className="cursor-pointer transition-opacity"
                    onMouseEnter={() => setHoveredEdgeKey(edge.key)}
                  />
                )
              }

              const dx = dst.x - src.x
              const dy = dst.y - src.y
              const dist = Math.max(1, Math.hypot(dx, dy))
              const ux = dx / dist
              const uy = dy / dist

              // Offset curve when bidirectional edges exist
              const reverseKey = `${edge.target}__TO__${edge.source}`
              const hasReverse = edgeLookup.has(reverseKey)
              const curveOffset = hasReverse ? 22 : 10

              const midX = (src.x + dst.x) / 2 - uy * curveOffset
              const midY = (src.y + dst.y) / 2 + ux * curveOffset

              const startX = src.x + ux * (NODE_RADIUS + 2)
              const startY = src.y + uy * (NODE_RADIUS + 2)
              const endX = dst.x - ux * (NODE_RADIUS + 5)
              const endY = dst.y - uy * (NODE_RADIUS + 5)

              const pathD = `M ${startX.toFixed(1)} ${startY.toFixed(1)} Q ${midX.toFixed(1)} ${midY.toFixed(1)} ${endX.toFixed(1)} ${endY.toFixed(1)}`

              const strokeColor = isHighlighted
                ? '#38bdf8'
                : edge.isSuspiciousLink
                  ? '#f59e0b'
                  : '#475569'

              const marker = isHighlighted
                ? 'url(#ft-arrow-active)'
                : edge.isSuspiciousLink
                  ? 'url(#ft-arrow-suspicious)'
                  : 'url(#ft-arrow-normal)'

              const primaryRef = edge.txns[0].reference
              const edgeLabel =
                edge.txns.length > 1
                  ? `${primaryRef} (+${edge.txns.length - 1})`
                  : primaryRef

              return (
                <g
                  key={edge.key}
                  className="cursor-pointer"
                  onMouseEnter={() => setHoveredEdgeKey(edge.key)}
                  onClick={() => onSelectTransactionRef(primaryRef)}
                >
                  <path
                    d={pathD}
                    fill="none"
                    stroke="transparent"
                    strokeWidth={14}
                  />
                  <path
                    d={pathD}
                    fill="none"
                    stroke={strokeColor}
                    strokeWidth={isHighlighted ? 2.4 : edge.isSuspiciousLink ? 1.8 : 1.4}
                    strokeOpacity={isHighlighted ? 0.95 : 0.72}
                    markerEnd={marker}
                  />
                  <text
                    x={midX}
                    y={midY - 4}
                    textAnchor="middle"
                    fill={isHighlighted ? '#bae6fd' : '#94a3b8'}
                    fontSize="9"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                    className="pointer-events-none"
                  >
                    {edgeLabel}
                  </text>
                </g>
              )
            })}

            {/* Account nodes */}
            {nodes.map((node) => {
              const isSelected = node.id === selectedAccountId
              const fill = isSelected
                ? '#0c4a6e'
                : node.isSuspicious
                  ? '#451a03'
                  : '#1e293b'
              const stroke = isSelected
                ? '#38bdf8'
                : node.isSuspicious
                  ? '#f59e0b'
                  : '#64748b'

              return (
                <g
                  key={node.id}
                  transform={`translate(${node.x.toFixed(1)}, ${node.y.toFixed(1)})`}
                  className="cursor-pointer"
                  onClick={() => onSelectAccount(node.id)}
                  role="button"
                  tabIndex={0}
                  aria-label={`Inspect account ${node.id}`}
                  onKeyDown={(e) => {
                    if (e.key === 'Enter' || e.key === ' ') {
                      e.preventDefault()
                      onSelectAccount(node.id)
                    }
                  }}
                >
                  {node.isSuspicious && (
                    <circle
                      r={NODE_RADIUS + 5}
                      fill="none"
                      stroke="#f59e0b"
                      strokeOpacity={0.35}
                      strokeWidth={1.5}
                      strokeDasharray="3 3"
                    />
                  )}
                  <circle
                    r={NODE_RADIUS}
                    fill={fill}
                    stroke={stroke}
                    strokeWidth={isSelected ? 2.8 : 2}
                  />
                  <text
                    textAnchor="middle"
                    dy="0.35em"
                    fill="#f8fafc"
                    fontSize="9"
                    fontWeight="600"
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                  >
                    {node.inCount}/{node.outCount}
                  </text>
                  <rect
                    x={-52}
                    y={NODE_RADIUS + 4}
                    width={104}
                    height={16}
                    rx={4}
                    fill="#0b1120"
                    fillOpacity={0.88}
                  />
                  <text
                    y={NODE_RADIUS + 15}
                    textAnchor="middle"
                    fill={isSelected ? '#7dd3fc' : node.isSuspicious ? '#fcd34d' : '#cbd5e1'}
                    fontSize="10"
                    fontWeight={isSelected ? '700' : '500'}
                    fontFamily="ui-monospace, SFMono-Regular, Menlo, monospace"
                  >
                    {shortenAccountLabel(node.id)}
                  </text>
                </g>
              )
            })}
          </svg>

          {/* Edge transaction details strip */}
          <div className="flex flex-wrap items-center justify-between gap-2 border-t border-slate-800 bg-[#0D1424] px-3.5 py-2.5 text-xs">
            {activeEdge ? (
              <>
                <div className="flex flex-wrap items-center gap-2 text-slate-300">
                  <span className="font-mono text-sky-300">{activeEdge.source}</span>
                  <span className="text-slate-500">→</span>
                  <span className="font-mono text-sky-300">{activeEdge.target}</span>
                  <span className="text-slate-500">·</span>
                  <span className="font-semibold text-white">
                    {activeEdge.totalAmountLabel}
                  </span>
                  <span className="text-slate-500">
                    ({formatTimestamp(activeEdge.txns[0].timestamp)})
                  </span>
                </div>
                <div className="flex flex-wrap items-center gap-1.5">
                  {activeEdge.txns.slice(0, 3).map((tx) => (
                    <button
                      key={tx.id}
                      type="button"
                      onClick={() => onSelectTransactionRef(tx.reference)}
                      className="rounded border border-slate-700 bg-slate-800 px-2 py-0.5 font-mono text-[11px] text-sky-300 hover:border-sky-500"
                    >
                      {tx.reference}
                    </button>
                  ))}
                  {activeEdge.txns.length > 3 && (
                    <span className="text-[11px] text-slate-500">
                      +{activeEdge.txns.length - 3} more
                    </span>
                  )}
                </div>
              </>
            ) : (
              <span className="text-slate-400">
                Node counts show incoming / outgoing transaction edges. Click a node to inspect.
              </span>
            )}
          </div>
        </div>
      )}
    </section>
  )
}
