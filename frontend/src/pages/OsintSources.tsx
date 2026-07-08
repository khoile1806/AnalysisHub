import { useQuery } from '@tanstack/react-query'
import { Key, CheckCircle2, XCircle } from 'lucide-react'
import { osintApi } from '@/api/osint'

// OsintSourcesPanel shows which optional OSINT intelligence sources have an API key
// configured — so an analyst can tell "the source returned nothing" from "the
// source was never configured and its collector was silently skipped".
export function OsintSourcesPanel() {
  const { data } = useQuery({ queryKey: ['osint-sources'], queryFn: osintApi.sources })

  return (
    <div className="space-y-4">
      <div className="card p-4">
        <div className="flex items-center gap-2">
          <Key className="h-4 w-4 text-emerald-400" />
          <span className="font-medium text-gray-200">OSINT Sources &amp; API Keys</span>
          {data && (
            <span className="text-xs text-gray-500">— {data.configured_count}/{data.total} configured</span>
          )}
        </div>
        <p className="text-xs text-gray-500 mt-1">
          Collectors for unconfigured sources are silently skipped during a scan. Set the environment variable (in <span className="font-mono text-gray-400">.env</span>) and restart the backend to enable them.
        </p>
      </div>

      {data && (
        <div className="card overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="bg-gray-900/60 text-gray-500 text-[11px] uppercase tracking-wider">
              <tr>
                <th className="text-left px-3 py-2">Source</th>
                <th className="text-left px-3 py-2">Category</th>
                <th className="text-center px-3 py-2">Status</th>
                <th className="text-left px-3 py-2">Env var</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/60">
              {data.sources.map((s) => (
                <tr key={s.name} className="hover:bg-gray-800/30">
                  <td className="px-3 py-2">
                    <div className="text-gray-200">{s.name}</div>
                    <div className="text-[11px] text-gray-600">{s.note}</div>
                  </td>
                  <td className="px-3 py-2 text-[11px] text-gray-500 uppercase tracking-wide">{s.category}</td>
                  <td className="px-3 py-2 text-center">
                    {s.configured
                      ? <span className="inline-flex items-center gap-1 text-emerald-400 text-xs"><CheckCircle2 className="h-3.5 w-3.5" /> configured</span>
                      : <span className="inline-flex items-center gap-1 text-gray-500 text-xs"><XCircle className="h-3.5 w-3.5" /> not set</span>}
                  </td>
                  <td className="px-3 py-2 font-mono text-[11px] text-gray-500">{s.env_var}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
