import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Share2 } from 'lucide-react'
import { osintApi, type OsintGraphNode } from '@/api/osint'

const STATUS_FILL: Record<string, string> = {
  done:    '#10b981',
  running: '#3b82f6',
  pending: '#6b7280',
  failed:  '#ef4444',
  stopped: '#eab308',
}

// OsintGraphView renders the investigation graph (auto-pivot) as a depth-column
// node-link diagram. Each node is a scanned entity; clicking it opens that scan.
// Renders nothing until the graph has more than one node (i.e. a pivot occurred).
export default function OsintGraphView({ scanId, live }: { scanId: string; live: boolean }) {
  const navigate = useNavigate()
  const { data } = useQuery({
    queryKey: ['osint-graph', scanId],
    queryFn: () => osintApi.graph(scanId),
    refetchInterval: live ? 4000 : false,
  })

  if (!data || data.nodes.length <= 1) return null

  const maxDepth = Math.max(...data.nodes.map((n) => n.depth))
  const byDepth: Record<number, OsintGraphNode[]> = {}
  data.nodes.forEach((n) => {
    if (!byDepth[n.depth]) byDepth[n.depth] = []
    byDepth[n.depth].push(n)
  })

  const colW = 210
  const rowH = 54
  const padX = 16
  const padY = 28
  const labelW = 150
  const maxRows = Math.max(...Object.values(byDepth).map((a) => a.length))
  const width = padX * 2 + maxDepth * colW + labelW
  const height = padY * 2 + Math.max(maxRows - 1, 0) * rowH + 20

  const pos: Record<string, { x: number; y: number }> = {}
  Object.entries(byDepth).forEach(([d, arr]) => {
    const depthN = Number(d)
    arr.forEach((n, i) => {
      pos[n.id] = {
        x: padX + depthN * colW,
        y: padY + i * rowH + ((maxRows - arr.length) * rowH) / 2,
      }
    })
  })

  return (
    <div className="card p-4 space-y-2 overflow-x-auto">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
        <Share2 className="h-4 w-4 text-emerald-400" /> Investigation Graph · {data.nodes.length} entities
      </h3>
      <svg width={Math.max(width, 400)} height={Math.max(height, 120)} className="min-w-full">
        {data.edges.map((e, i) => {
          const a = pos[e.from]
          const b = pos[e.to]
          if (!a || !b) return null
          const mx = (a.x + b.x) / 2
          return (
            <path
              key={i}
              d={`M ${a.x} ${a.y} C ${mx} ${a.y}, ${mx} ${b.y}, ${b.x} ${b.y}`}
              stroke="#374151"
              fill="none"
              strokeWidth={1}
            />
          )
        })}
        {data.nodes.map((n) => {
          const p = pos[n.id]
          const fill = STATUS_FILL[n.status] ?? '#6b7280'
          const label = n.target.length > 20 ? n.target.slice(0, 19) + '…' : n.target
          return (
            <g key={n.id} className="cursor-pointer" onClick={() => navigate(`/osint/${n.id}`)}>
              <circle
                cx={p.x} cy={p.y} r={n.root ? 9 : 6}
                fill={fill}
                stroke={n.root ? '#f3f4f6' : 'none'}
                strokeWidth={n.root ? 1.5 : 0}
              >
                {n.status === 'running' && (
                  <animate attributeName="r" values={n.root ? '9;12;9' : '6;9;6'} dur="1.4s" repeatCount="indefinite" />
                )}
              </circle>
              <text x={p.x + 13} y={p.y + 3} fontSize="11" fill="#d1d5db" fontFamily="monospace">{label}</text>
              <text x={p.x + 13} y={p.y + 15} fontSize="8" fill="#6b7280">{n.type} · {n.findings} findings</text>
            </g>
          )
        })}
      </svg>
      <p className="text-[11px] text-gray-600">Click a node to open that entity's investigation.</p>
    </div>
  )
}
