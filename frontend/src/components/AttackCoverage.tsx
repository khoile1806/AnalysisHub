import { useQuery } from '@tanstack/react-query'
import { Grid3x3, Target } from 'lucide-react'
import { timelineApi, type AttackTechnique, type TimelineSeverity } from '@/api/timeline'

// Severity palette — mirrors AttackTimeline so the two views read consistently.
const SEV: Record<TimelineSeverity, { text: string; bg: string; border: string }> = {
  critical: { text: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30' },
  high:     { text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  medium:   { text: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/30' },
  low:      { text: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/30' },
  info:     { text: 'text-gray-400',   bg: 'bg-gray-500/10',   border: 'border-gray-700' },
}

function techLabel(t: AttackTechnique): string {
  if (t.id === '(unspecified)') return 'No technique ID'
  return t.id
}

// AttackCoverage renders an ATT&CK-matrix-style view of a case: one column per
// tactic that the reconstructed timeline touched, with technique chips colored
// by the worst severity seen. Pure read over the timeline — self-hides when no
// event carries a tactic/technique mapping.
export default function AttackCoverage({ caseId }: { caseId: string }) {
  const { data, isLoading } = useQuery({
    queryKey: ['attack-coverage', caseId],
    queryFn: () => timelineApi.attackCoverage(caseId),
  })

  if (isLoading) {
    return (
      <div className="card p-4">
        <div className="h-4 w-48 bg-gray-800 rounded animate-pulse" />
        <div className="mt-4 h-24 bg-gray-900 rounded animate-pulse" />
      </div>
    )
  }

  if (!data || data.summary.mapped_events === 0) {
    return (
      <div className="card p-6 text-center">
        <Grid3x3 className="h-8 w-8 text-gray-600 mx-auto mb-2" />
        <p className="text-sm text-gray-400 font-medium">No ATT&CK coverage yet</p>
        <p className="text-xs text-gray-500 mt-1">
          Tag timeline events with a tactic / technique (T-code) — or let AI extraction
          populate them — and the matrix will build automatically.
        </p>
      </div>
    )
  }

  const { summary, tactics } = data

  return (
    <div className="card p-4 space-y-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <Target className="h-4 w-4 text-emerald-400" /> MITRE ATT&CK Coverage
        </h3>
        <div className="flex items-center gap-4 text-[11px] text-gray-400">
          <span><span className="text-gray-200 font-semibold">{summary.tactics}</span> tactics</span>
          <span><span className="text-gray-200 font-semibold">{summary.techniques}</span> techniques</span>
          <span><span className="text-gray-200 font-semibold">{summary.mapped_events}</span>/{summary.total_events} events mapped</span>
        </div>
      </div>

      {/* Horizontally scrollable matrix: each tactic is a column. */}
      <div className="overflow-x-auto pb-2">
        <div className="flex gap-3 min-w-min">
          {tactics.map((col) => (
            <div key={col.id} className="w-[200px] shrink-0 flex flex-col">
              <div className="rounded-t-lg bg-gray-800/80 border border-gray-700 px-2.5 py-2">
                <p className="text-[11px] font-bold text-gray-100 uppercase tracking-wide truncate" title={col.name}>
                  {col.name}
                </p>
                <p className="text-[10px] text-gray-400">{col.event_count} event{col.event_count !== 1 ? 's' : ''}</p>
              </div>
              <div className="flex flex-col gap-1.5 p-1.5 border border-t-0 border-gray-800 rounded-b-lg bg-gray-950/40 flex-1">
                {col.techniques.map((t) => {
                  const sev = SEV[t.severity] ?? SEV.info
                  return (
                    <div
                      key={t.id}
                      className={`rounded-md border ${sev.border} ${sev.bg} px-2 py-1.5`}
                      title={t.sample_titles.join('\n') || undefined}
                    >
                      <div className="flex items-center justify-between gap-1.5">
                        <span className={`text-[11px] font-mono font-semibold ${sev.text} truncate`}>
                          {techLabel(t)}
                        </span>
                        <span className="text-[10px] text-gray-400 shrink-0">×{t.count}</span>
                      </div>
                      {t.sample_titles[0] && (
                        <p className="text-[10px] text-gray-500 mt-0.5 line-clamp-2">{t.sample_titles[0]}</p>
                      )}
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      </div>

      <p className="text-[11px] text-gray-500">
        Aggregated from this case's attack-timeline events. Severity = worst seen per technique.
        Techniques with no T-code appear under "No technique ID"; events whose tactic isn't a
        standard enterprise tactic are grouped under "Unmapped".
      </p>
    </div>
  )
}
