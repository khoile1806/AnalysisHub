import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ShieldCheck, Sparkles, Download, Trash2, X, AlertTriangle, Info,
  TrendingUp, TrendingDown, Minus, User, Calendar, Clock,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { analysisApi } from '@/api/analysis'
import {
  complianceApi, type AssessItem, type ComplianceFinding, type FindingStatus,
  type RemediationStatus,
} from '@/api/compliance'
import { COMPLIANCE_ITEM_MAP } from '@/data/complianceChecklist'
import { getErrorMessage } from '@/lib/utils'

const REM_STATUS: Record<RemediationStatus, { label: string; cls: string }> = {
  open:          { label: 'Open',         cls: 'text-red-400' },
  in_progress:   { label: 'In progress',  cls: 'text-amber-400' },
  resolved:      { label: 'Resolved',     cls: 'text-emerald-400' },
  accepted_risk: { label: 'Accepted risk', cls: 'text-gray-400' },
}

function isOverdue(f: ComplianceFinding): boolean {
  if (!f.due_date || f.remediation_status === 'resolved' || f.remediation_status === 'accepted_risk') return false
  return new Date(f.due_date).getTime() < Date.now()
}

const STATUS_META: Record<FindingStatus, { label: string; cls: string; dot: string }> = {
  compliant:     { label: 'PASS',    cls: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/30', dot: 'bg-emerald-500' },
  non_compliant: { label: 'FAIL',    cls: 'text-red-400 bg-red-500/10 border-red-500/30',             dot: 'bg-red-500' },
  partial:       { label: 'PARTIAL', cls: 'text-amber-400 bg-amber-500/10 border-amber-500/30',       dot: 'bg-amber-500' },
  na:            { label: 'N/A',     cls: 'text-gray-400 bg-gray-500/10 border-gray-700',             dot: 'bg-gray-500' },
}

const SEV_CLS: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-amber-400', low: 'text-blue-400', info: 'text-gray-400',
}

// Build AI-assess items from the case's compliance checklist runs by matching
// each batch's item_ids back to the compliance checklist metadata.
function buildAssessItems(checklistRuns: any[], agents: any[]): AssessItem[] {
  const agentName: Record<string, string> = {}
  for (const a of agents ?? []) agentName[a.id] = a.hostname || a.name
  const byId = new Map<string, AssessItem>()

  for (const run of checklistRuns ?? []) {
    const host = agentName[run.agent_id] ?? ''
    for (const batch of run.batches ?? []) {
      if (!batch.output) continue
      let ids: string[] = []
      try { ids = JSON.parse(batch.item_ids || '[]') } catch { /* ignore */ }
      for (const id of ids) {
        const meta = COMPLIANCE_ITEM_MAP[id]
        if (!meta) continue // not a compliance item
        byId.set(id, {
          item_id: id,
          control: meta.control,
          frameworks: meta.frameworks,
          title: meta.label,
          purpose: meta.purpose,
          output: batch.output,
          host,
        })
      }
    }
  }
  return Array.from(byId.values())
}

// ── Assess panel ────────────────────────────────────────────────────────────
function AssessPanel({ caseId, items, onDone }: { caseId: string; items: AssessItem[]; onDone: () => void }) {
  const qc = useQueryClient()
  const [providerId, setProviderId] = useState('')
  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })

  const assessMut = useMutation({
    mutationFn: () => complianceApi.assess(caseId, providerId, items, true),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['compliance-findings', caseId] })
      qc.invalidateQueries({ queryKey: ['compliance-snapshots', caseId] })
      if (res.assessed > 0) { toast.success(`Assessed ${res.assessed} control(s)`); onDone() }
      else toast(res.note ?? 'AI returned no verdicts', { icon: 'ℹ️' })
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="card p-4 space-y-3 border-emerald-500/30">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Sparkles className="h-4 w-4 text-emerald-400" /> AI Assess — chấm Đạt/Không đạt
        </h4>
        <button onClick={onDone} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
      </div>
      <p className="text-xs text-gray-500">
        AI đọc output từng compliance check + baseline kỳ vọng → kết luận <strong>Pass/Fail/Partial</strong> + lý do + cách khắc phục.
        Tìm thấy <strong className="text-emerald-300">{items.length}</strong> control có bằng chứng.
      </p>
      {items.length === 0 ? (
        <div className="flex items-start gap-2 text-xs text-amber-300/80 bg-amber-500/5 border border-amber-500/20 rounded p-2">
          <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
          <span>Chưa có bằng chứng compliance. Hãy chạy <strong>Evidence & Compliance → Compliance Audit</strong> trên agent thuộc case này trước.</span>
        </div>
      ) : providers.length === 0 ? (
        <p className="text-xs text-yellow-400">No AI providers configured. <a href="/ai-providers" className="underline">Add one first.</a></p>
      ) : (
        <div className="flex items-center gap-2">
          <select className="input flex-1" value={providerId} onChange={(e) => setProviderId(e.target.value)}>
            <option value="">Select provider…</option>
            {providers.filter((p) => p.is_active).map((p) => (
              <option key={p.id} value={p.id}>{p.name} — {p.model}</option>
            ))}
          </select>
          <button className="btn-primary whitespace-nowrap" disabled={!providerId || assessMut.isPending}
            onClick={() => assessMut.mutate()}>
            {assessMut.isPending ? 'Đang chấm…' : 'Assess'}
          </button>
        </div>
      )}
    </div>
  )
}

// ── Coverage matrix ─────────────────────────────────────────────────────────
function CoverageMatrix({ findings }: { findings: ComplianceFinding[] }) {
  const rows = useMemo(() => {
    const m: Record<string, { total: number; pass: number; fail: number; partial: number; na: number }> = {}
    for (const f of findings) {
      for (const fw of f.frameworks.split(',').map((s) => s.trim()).filter(Boolean)) {
        const r = (m[fw] ??= { total: 0, pass: 0, fail: 0, partial: 0, na: 0 })
        r.total++
        if (f.status === 'compliant') r.pass++
        else if (f.status === 'non_compliant') r.fail++
        else if (f.status === 'partial') r.partial++
        else r.na++
      }
    }
    return Object.entries(m).sort(([a], [b]) => a.localeCompare(b))
  }, [findings])

  if (rows.length === 0) return null
  const score = (r: { total: number; pass: number; partial: number }) =>
    r.total ? Math.round((r.pass * 100 + r.partial * 50) / r.total) : 0
  const scoreCls = (s: number) => (s >= 80 ? 'text-emerald-400' : s >= 50 ? 'text-amber-400' : 'text-red-400')

  return (
    <div className="card overflow-hidden">
      <table className="w-full text-sm">
        <thead className="bg-gray-900/60 border-b border-gray-800 text-[10px] text-gray-500 uppercase tracking-wider">
          <tr>
            <th className="text-left py-2.5 px-4">Framework</th>
            <th className="px-2">Total</th><th className="px-2 text-emerald-500">Pass</th>
            <th className="px-2 text-red-500">Fail</th><th className="px-2 text-amber-500">Partial</th>
            <th className="px-2">N/A</th><th className="px-3 text-right">Score</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800">
          {rows.map(([fw, r]) => {
            const s = score(r)
            return (
              <tr key={fw} className="hover:bg-gray-900/30">
                <td className="py-2.5 px-4 font-medium text-gray-200">{fw}</td>
                <td className="px-2 text-center text-gray-400">{r.total}</td>
                <td className="px-2 text-center text-emerald-400">{r.pass}</td>
                <td className="px-2 text-center text-red-400">{r.fail}</td>
                <td className="px-2 text-center text-amber-400">{r.partial}</td>
                <td className="px-2 text-center text-gray-500">{r.na}</td>
                <td className={`px-3 text-right font-bold ${scoreCls(s)}`}>{s}%</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ── Main ────────────────────────────────────────────────────────────────────
export default function ComplianceAssessment({
  caseId, checklistRuns, agents,
}: { caseId: string; checklistRuns: any[]; agents: any[] }) {
  const qc = useQueryClient()
  const [showAssess, setShowAssess] = useState(false)
  const [statusFilter, setStatusFilter] = useState<FindingStatus | ''>('')

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['compliance-findings', caseId],
    queryFn: () => complianceApi.listFindings(caseId),
  })

  const { data: snapshots = [] } = useQuery({
    queryKey: ['compliance-snapshots', caseId],
    queryFn: () => complianceApi.listSnapshots(caseId),
  })

  const assessItems = useMemo(() => buildAssessItems(checklistRuns, agents), [checklistRuns, agents])

  // Generic patch for verdict override + POA&M fields.
  const patchMut = useMutation({
    mutationFn: ({ id, ...payload }: { id: string } & Parameters<typeof complianceApi.updateFinding>[1]) =>
      complianceApi.updateFinding(id, payload),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['compliance-findings', caseId] }),
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  // Score trend vs previous assessment (drift).
  const prevScore = snapshots.length >= 2 ? snapshots[snapshots.length - 2].score : null
  const overdueCount = useMemo(() => findings.filter(isOverdue).length, [findings])
  const openCount = useMemo(
    () => findings.filter((f) => (f.status === 'non_compliant' || f.status === 'partial') && f.remediation_status !== 'resolved' && f.remediation_status !== 'accepted_risk').length,
    [findings],
  )

  const clearMut = useMutation({
    mutationFn: () => complianceApi.clearFindings(caseId),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['compliance-findings', caseId] }); toast.success('Cleared findings') },
  })

  const counts = useMemo(() => {
    const c = { compliant: 0, non_compliant: 0, partial: 0, na: 0 }
    for (const f of findings) c[f.status]++
    return c
  }, [findings])
  const total = findings.length
  const score = total ? Math.round((counts.compliant * 100 + counts.partial * 50) / total) : 0

  const filtered = statusFilter ? findings.filter((f) => f.status === statusFilter) : findings

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          {total > 0 && (
            <>
              <span className={`text-sm font-bold ${score >= 80 ? 'text-emerald-400' : score >= 50 ? 'text-amber-400' : 'text-red-400'}`}>
                Score {score}%
              </span>
              {prevScore !== null && score !== prevScore && (
                <span className={`flex items-center gap-0.5 text-[11px] ${score > prevScore ? 'text-emerald-400' : 'text-red-400'}`}
                  title={`Lần trước: ${prevScore}%`}>
                  {score > prevScore ? <TrendingUp className="h-3 w-3" /> : <TrendingDown className="h-3 w-3" />}
                  {score > prevScore ? '+' : ''}{score - prevScore}%
                </span>
              )}
              {prevScore !== null && score === prevScore && (
                <span className="flex items-center gap-0.5 text-[11px] text-gray-500" title={`Lần trước: ${prevScore}%`}><Minus className="h-3 w-3" /></span>
              )}
              {openCount > 0 && (
                <span className="text-xs px-2 py-1 rounded-full border border-red-500/30 bg-red-500/10 text-red-300">
                  {openCount} cần khắc phục{overdueCount > 0 ? ` · ${overdueCount} quá hạn` : ''}
                </span>
              )}
              {(['compliant', 'non_compliant', 'partial', 'na'] as FindingStatus[]).map((s) =>
                counts[s] ? (
                  <button key={s} onClick={() => setStatusFilter(statusFilter === s ? '' : s)}
                    className={`text-xs px-2 py-1 rounded-full border transition ${STATUS_META[s].cls} ${statusFilter === s ? 'ring-1 ring-current' : ''}`}>
                    {counts[s]} {STATUS_META[s].label}
                  </button>
                ) : null,
              )}
            </>
          )}
        </div>
        <div className="flex items-center gap-2">
          {total > 0 && (
            <>
              <button onClick={() => complianceApi.downloadReport(caseId).catch((e) => toast.error(getErrorMessage(e)))}
                className="btn-secondary text-xs py-1.5"><Download className="h-3.5 w-3.5" /> Export Report</button>
              <button onClick={() => { if (confirm('Clear all findings?')) clearMut.mutate() }}
                className="btn-secondary text-xs py-1.5 text-red-400"><Trash2 className="h-3.5 w-3.5" /></button>
            </>
          )}
          <button onClick={() => setShowAssess((v) => !v)} className="btn-primary text-xs py-1.5">
            <Sparkles className="h-3.5 w-3.5" /> {total > 0 ? 'Re-assess' : 'AI Assess'}
          </button>
        </div>
      </div>

      {showAssess && <AssessPanel caseId={caseId} items={assessItems} onDone={() => setShowAssess(false)} />}

      {isLoading ? (
        <div className="space-y-2">{[...Array(3)].map((_, i) => <div key={i} className="skeleton h-14 rounded-lg" />)}</div>
      ) : total === 0 ? (
        <div className="card p-10 text-center flex flex-col items-center">
          <ShieldCheck className="h-10 w-10 text-gray-700 mb-3" />
          <p className="text-gray-400 font-medium">Chưa có đánh giá compliance</p>
          <p className="text-xs text-gray-500 mt-1 max-w-md">
            Chạy Compliance Audit checklist trên agent thuộc case, rồi bấm <strong>AI Assess</strong> để AI chấm Đạt/Không đạt và sinh ma trận phủ control + báo cáo.
          </p>
        </div>
      ) : (
        <>
          <CoverageMatrix findings={findings} />

          <div className="space-y-2">
            {filtered.map((f) => {
              const meta = STATUS_META[f.status]
              const needsFix = f.status === 'non_compliant' || f.status === 'partial'
              const overdue = isOverdue(f)
              return (
                <div key={f.id} className={`card p-3 ${overdue ? 'border-red-500/30' : ''}`}>
                  <div className="flex items-start gap-3">
                    <span className={`mt-0.5 text-[10px] font-bold px-2 py-0.5 rounded border ${meta.cls} shrink-0`}>{meta.label}</span>
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2 flex-wrap">
                        <span className="text-sm font-medium text-gray-200">{f.title}</span>
                        <span className={`text-[10px] font-bold uppercase ${SEV_CLS[f.severity] ?? ''}`}>{f.severity}</span>
                        {f.host && <span className="text-[10px] text-gray-500">· {f.host}</span>}
                      </div>
                      <div className="text-[11px] font-mono text-gray-500 mt-0.5">{f.control}</div>
                      {f.rationale && <p className="text-xs text-gray-400 mt-1">{f.rationale}</p>}
                      {needsFix && f.remediation && (
                        <p className="text-xs text-red-300/80 mt-1"><span className="text-gray-500">Khắc phục: </span>{f.remediation}</p>
                      )}
                      {f.evidence_hash && (
                        <p className="text-[10px] font-mono text-gray-600 mt-1" title={`SHA-256: ${f.evidence_hash}`}>
                          🔒 {f.evidence_hash.slice(0, 16)}…
                        </p>
                      )}

                      {/* POA&M — owner / deadline / remediation status (fail/partial only) */}
                      {needsFix && (
                        <div className="flex items-center gap-2 flex-wrap mt-2 pt-2 border-t border-gray-800">
                          <label className="flex items-center gap-1 text-[10px] text-gray-500">
                            <User className="h-3 w-3" />
                            <input
                              defaultValue={f.owner ?? ''}
                              placeholder="Owner"
                              onBlur={(e) => { if (e.target.value !== (f.owner ?? '')) patchMut.mutate({ id: f.id, owner: e.target.value }) }}
                              className="bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-[10px] text-gray-300 w-24"
                            />
                          </label>
                          <label className="flex items-center gap-1 text-[10px] text-gray-500">
                            <Calendar className="h-3 w-3" />
                            <input
                              type="date"
                              defaultValue={f.due_date ? f.due_date.slice(0, 10) : ''}
                              onChange={(e) => patchMut.mutate({ id: f.id, due_date: e.target.value ? new Date(e.target.value).toISOString() : undefined })}
                              className={`bg-gray-800 border rounded px-1.5 py-0.5 text-[10px] ${overdue ? 'border-red-500/50 text-red-400' : 'border-gray-700 text-gray-300'}`}
                            />
                          </label>
                          {overdue && <span className="flex items-center gap-0.5 text-[10px] text-red-400"><Clock className="h-3 w-3" /> Quá hạn</span>}
                          <select
                            value={f.remediation_status}
                            onChange={(e) => patchMut.mutate({ id: f.id, remediation_status: e.target.value as RemediationStatus })}
                            className={`bg-gray-800 border border-gray-700 rounded px-1.5 py-0.5 text-[10px] ${REM_STATUS[f.remediation_status]?.cls ?? 'text-gray-300'}`}
                          >
                            {(Object.keys(REM_STATUS) as RemediationStatus[]).map((k) => (
                              <option key={k} value={k}>{REM_STATUS[k].label}</option>
                            ))}
                          </select>
                        </div>
                      )}
                    </div>
                    {/* Verdict override */}
                    <select
                      value={f.status}
                      onChange={(e) => patchMut.mutate({ id: f.id, status: e.target.value as FindingStatus })}
                      title="Override verdict"
                      className="bg-gray-800 border border-gray-700 rounded px-1.5 py-1 text-[10px] text-gray-300 shrink-0"
                    >
                      <option value="compliant">PASS</option>
                      <option value="non_compliant">FAIL</option>
                      <option value="partial">PARTIAL</option>
                      <option value="na">N/A</option>
                    </select>
                  </div>
                </div>
              )
            })}
          </div>

          <p className="text-[11px] text-gray-600 flex items-center gap-1.5 pt-1">
            <Info className="h-3 w-3" /> Verdict do AI đề xuất — analyst có thể chỉnh tay qua ô bên phải. Báo cáo HTML kèm Compliance Matrix + Findings.
          </p>
        </>
      )}
    </div>
  )
}
