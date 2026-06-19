import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { Sparkles, ShieldAlert, AlertTriangle, Info, CheckCircle2 } from 'lucide-react'
import { analysisApi, elkResultsApi, type TriageCluster, type TriageReport } from '@/api/analysis'
import toast from 'react-hot-toast'
import { getErrorMessage } from '@/lib/utils'

const SEV: Record<string, { bg: string; text: string; border: string; icon: React.ElementType }> = {
  critical: { bg: 'bg-red-500/10',    text: 'text-red-400',    border: 'border-red-500/40',    icon: ShieldAlert },
  high:     { bg: 'bg-orange-500/10', text: 'text-orange-400', border: 'border-orange-500/40', icon: AlertTriangle },
  medium:   { bg: 'bg-amber-500/10',  text: 'text-amber-400',  border: 'border-amber-500/40',  icon: AlertTriangle },
  low:      { bg: 'bg-sky-500/10',    text: 'text-sky-400',    border: 'border-sky-500/40',    icon: Info },
  info:     { bg: 'bg-gray-500/10',   text: 'text-gray-400',   border: 'border-gray-600/40',   icon: Info },
}
function sev(s: string) { return SEV[s] ?? SEV.info }

function ClusterCard({ c }: { c: TriageCluster }) {
  const s = sev(c.severity)
  const Icon = s.icon
  return (
    <div className={`rounded-lg border ${s.border} ${s.bg} p-3 ${c.false_positive ? 'opacity-60' : ''}`}>
      <div className="flex items-start justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className={`h-4 w-4 shrink-0 ${s.text}`} />
          <span className="font-medium text-gray-100 truncate">{c.title}</span>
        </div>
        <div className="flex items-center gap-1.5 shrink-0">
          {c.false_positive && <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-700 text-gray-300">FP</span>}
          <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${s.bg} ${s.text}`}>{c.severity}</span>
          {c.confidence && <span className="text-[10px] text-gray-500">conf: {c.confidence}</span>}
        </div>
      </div>
      {c.rationale && <p className="text-xs text-gray-400 mt-2 leading-relaxed">{c.rationale}</p>}
      <div className="flex flex-wrap gap-1.5 mt-2">
        {(c.hosts ?? []).map((h) => <span key={h} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-gray-300">{h}</span>)}
        {(c.iocs ?? []).map((i) => <span key={i} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800 text-emerald-300">{i}</span>)}
        {typeof c.hit_count === 'number' && <span className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400">{c.hit_count} hits</span>}
      </div>
      {c.recommended_action && (
        <div className="mt-2 flex items-start gap-1.5 text-xs text-gray-300">
          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0 mt-0.5" />
          <span>{c.recommended_action}</span>
        </div>
      )}
    </div>
  )
}

// HitTriagePanel runs AI triage over a saved ELK hunt result and renders the
// ranked clusters. The raw hits remain the source of truth — this is an AI
// assessment layer to prioritize what an analyst looks at first.
export default function HitTriagePanel({ resultId, initial }: { resultId: string; initial?: TriageReport | null }) {
  const [providerId, setProviderId] = useState('')
  const [report, setReport] = useState<TriageReport | null>(initial ?? null)

  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })
  const active = providers.filter((p) => p.is_active)

  const triageMut = useMutation({
    mutationFn: () => elkResultsApi.triage(resultId, providerId),
    onSuccess: (d) => {
      setReport(d.triage)
      toast.success(`Triage xong — ${d.clusters} cụm (${d.tokens} tokens)`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/40 p-3 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <Sparkles className="h-4 w-4 text-emerald-400" /> AI Triage hit
        </h3>
        <div className="flex items-center gap-2">
          {active.length === 0 ? (
            <a href="/ai-providers" className="text-xs text-yellow-400 underline">Cấu hình AI provider</a>
          ) : (
            <select
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
              className="text-xs bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
            >
              <option value="">Chọn provider…</option>
              {active.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )}
          <button
            className="btn-primary text-xs disabled:opacity-50"
            disabled={!providerId || triageMut.isPending}
            onClick={() => triageMut.mutate()}
          >
            {triageMut.isPending ? 'Đang triage…' : report ? 'Triage lại' : 'Run triage'}
          </button>
        </div>
      </div>

      {report ? (
        <div className="space-y-2">
          {report.summary && <p className="text-xs text-gray-400 italic">{report.summary}</p>}
          {[...report.clusters]
            .sort((a, b) => ['critical', 'high', 'medium', 'low', 'info'].indexOf(a.severity) - ['critical', 'high', 'medium', 'low', 'info'].indexOf(b.severity))
            .map((c, i) => <ClusterCard key={i} c={c} />)}
        </div>
      ) : (
        <p className="text-xs text-gray-500">Chạy triage để AI xếp hạng &amp; gom cụm các hit theo mức nghi ngờ — đọc vài lead ưu tiên thay vì lọc tay.</p>
      )}
    </div>
  )
}
