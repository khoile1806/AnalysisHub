import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Link2 } from 'lucide-react'
import { osintApi } from '@/api/osint'

// OsintCorrelations surfaces indicators that link 2+ investigated entities — the
// de-anonymisation signal (e.g. a registrant email tying two domains together).
// Self-hides when there are no cross-links.
export default function OsintCorrelations({ scanId, live }: { scanId: string; live: boolean }) {
  const navigate = useNavigate()
  const { data } = useQuery({
    queryKey: ['osint-correlations', scanId],
    queryFn: () => osintApi.correlations(scanId),
    refetchInterval: live ? 5000 : false,
  })

  if (!data || data.length === 0) return null

  return (
    <div className="card p-4 space-y-2">
      <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
        <Link2 className="h-4 w-4 text-emerald-400" /> Shared indicators · {data.length}
      </h3>
      <p className="text-[11px] text-gray-500">
        Indicators that link two or more investigated entities — de-anonymisation signals.
      </p>
      <div className="space-y-2">
        {data.slice(0, 30).map((c, i) => (
          <div key={i} className="rounded-lg border border-gray-800 bg-gray-900/40 p-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="font-mono text-sm text-emerald-300 break-all">{c.value}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-400 shrink-0">
                {c.count} entities
              </span>
            </div>
            <div className="flex flex-wrap gap-1.5 mt-1.5">
              {c.entities.map((e) => (
                <button
                  key={e.id}
                  onClick={() => navigate(`/osint/${e.id}`)}
                  className="text-[11px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 hover:bg-gray-700 transition-colors"
                  title="Open this entity's investigation"
                >
                  {e.type}:{e.target.length > 24 ? e.target.slice(0, 23) + '…' : e.target}
                </button>
              ))}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}
