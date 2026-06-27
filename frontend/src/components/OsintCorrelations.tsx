import { useQuery } from '@tanstack/react-query'
import { useNavigate } from 'react-router-dom'
import { Link2, Image as ImageIcon } from 'lucide-react'
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
          <div key={i} className={`rounded-lg border bg-gray-900/40 p-2.5 ${c.kind === 'avatar' ? 'border-emerald-800/50' : 'border-gray-800'}`}>
            <div className="flex items-center justify-between gap-2">
              <span className="flex items-center gap-1.5 font-mono text-sm text-emerald-300 break-all">
                {c.kind === 'avatar' && <ImageIcon className="h-3.5 w-3.5 shrink-0" />}
                {c.value}
              </span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-900/40 text-emerald-400 shrink-0">
                {c.count} entities
              </span>
            </div>
            {c.kind === 'avatar' ? (
              <div className="flex flex-wrap gap-2 mt-2">
                {c.entities.map((e) => (
                  <button
                    key={e.id}
                    onClick={() => navigate(`/osint/${e.id}`)}
                    className="flex items-center gap-2 rounded border border-slate-700 bg-gray-800/60 px-2 py-1 hover:border-emerald-700 transition-colors"
                    title="Open this entity's investigation"
                  >
                    {e.avatar_url
                      ? <img src={e.avatar_url} alt="" className="h-8 w-8 rounded object-cover bg-gray-900" referrerPolicy="no-referrer" loading="lazy" />
                      : <ImageIcon className="h-8 w-8 p-1.5 text-gray-600" />}
                    <span className="text-[11px] font-mono text-gray-300">{e.type}:{e.target.length > 20 ? e.target.slice(0, 19) + '…' : e.target}</span>
                  </button>
                ))}
              </div>
            ) : (
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
            )}
          </div>
        ))}
      </div>
    </div>
  )
}
