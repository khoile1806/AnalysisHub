import { useQuery } from '@tanstack/react-query'
import { X, ExternalLink, ShieldCheck, ShieldAlert, ShieldQuestion, Loader2 } from 'lucide-react'
import { intelApi } from '@/api/intel'
import { getErrorMessage } from '@/lib/utils'

// IntelLookupModal runs a live threat-intel lookup (VirusTotal + any configured
// sources) for one indicator and shows the verdict. Reusable from any scan view
// — pass the suspicious value (hash / IP / domain / URL) and an onClose handler.
export default function IntelLookupModal({
  indicator,
  type,
  onClose,
}: {
  indicator: string
  type?: string
  onClose: () => void
}) {
  const { data, isLoading, error } = useQuery({
    queryKey: ['intel-lookup', indicator, type],
    queryFn: () => intelApi.lookup(indicator, type),
    retry: false,
  })

  const score = data?.max_score ?? 0
  const verdict = data?.threat ? (score >= 70 ? 'malicious' : 'suspicious') : 'clean'
  const verdictStyle = {
    malicious: { icon: ShieldAlert, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', label: 'MALICIOUS' },
    suspicious: { icon: ShieldAlert, color: 'text-amber-400', bg: 'bg-amber-500/10 border-amber-500/30', label: 'SUSPICIOUS' },
    clean: { icon: ShieldCheck, color: 'text-emerald-400', bg: 'bg-emerald-500/10 border-emerald-500/30', label: 'NO THREAT' },
  }[verdict]
  const VIcon = verdictStyle.icon

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-lg bg-[#1C1C1E] border border-gray-800 rounded-xl shadow-2xl" onClick={e => e.stopPropagation()}>
        {/* Header */}
        <div className="flex items-start justify-between p-4 border-b border-gray-800">
          <div className="min-w-0">
            <h3 className="text-sm font-semibold text-gray-100 flex items-center gap-2">
              <ShieldQuestion className="h-4 w-4 text-purple-400" /> Threat Intel Lookup
            </h3>
            <p className="text-xs text-gray-400 mt-1 font-mono break-all">
              <span className="uppercase text-gray-600">{data?.type || type || '?'}</span> · {indicator}
            </p>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-200 shrink-0"><X className="h-4 w-4" /></button>
        </div>

        {/* Body */}
        <div className="p-4 space-y-4 max-h-[60vh] overflow-auto">
          {isLoading && (
            <div className="flex items-center gap-2 text-sm text-gray-400 py-6 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" /> Querying VirusTotal…
            </div>
          )}

          {error && <p className="text-sm text-red-400">{getErrorMessage(error)}</p>}

          {data && !isLoading && (
            <>
              {!data.configured ? (
                <div className="rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
                  {data.message || 'No threat-intel API keys configured.'}
                </div>
              ) : (
                <>
                  {/* Verdict banner */}
                  <div className={`flex items-center gap-3 rounded-lg border p-3 ${verdictStyle.bg}`}>
                    <VIcon className={`h-6 w-6 ${verdictStyle.color}`} />
                    <div>
                      <p className={`text-sm font-bold ${verdictStyle.color}`}>{verdictStyle.label}</p>
                      <p className="text-xs text-gray-400">Max maliciousness score: {score}/100</p>
                    </div>
                  </div>

                  {/* Per-source findings */}
                  {(data.findings?.length ?? 0) === 0 ? (
                    <p className="text-xs text-gray-500">No source returned data for this indicator.</p>
                  ) : (
                    <div className="space-y-2">
                      {data.findings!.map((f, i) => (
                        <div key={i} className="rounded-lg border border-gray-800 bg-gray-900/40 p-3">
                          <div className="flex items-center justify-between gap-2">
                            <span className="text-xs font-semibold text-gray-200">{f.Source}</span>
                            <span className={`text-[10px] px-1.5 py-0.5 rounded ${f.Malicious ? 'bg-red-500/20 text-red-400' : 'bg-gray-700 text-gray-300'}`}>
                              score {f.Score}
                            </span>
                          </div>
                          <p className="text-xs text-gray-400 mt-1">{f.Summary}</p>
                          {(f.Labels?.length ?? 0) > 0 && (
                            <div className="flex flex-wrap gap-1 mt-1.5">
                              {f.Labels!.map(l => <span key={l} className="text-[10px] px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300">{l}</span>)}
                            </div>
                          )}
                          {f.Extra && Object.keys(f.Extra).length > 0 && (
                            <div className="flex flex-wrap gap-x-4 gap-y-0.5 mt-1.5 text-[10px] text-gray-500">
                              {Object.entries(f.Extra).map(([k, v]) => <span key={k}>{k}: <span className="text-gray-400">{v}</span></span>)}
                            </div>
                          )}
                        </div>
                      ))}
                    </div>
                  )}
                </>
              )}
            </>
          )}
        </div>

        {/* Footer — always offer the VT GUI link */}
        {data?.vt_url && (
          <div className="p-4 border-t border-gray-800 flex justify-end">
            <a
              href={data.vt_url}
              target="_blank"
              rel="noopener noreferrer"
              className="inline-flex items-center gap-2 px-3 py-1.5 text-xs font-medium text-emerald-400 hover:bg-emerald-500/10 rounded-lg transition-colors"
            >
              Open on VirusTotal <ExternalLink className="h-3.5 w-3.5" />
            </a>
          </div>
        )}
      </div>
    </div>
  )
}
