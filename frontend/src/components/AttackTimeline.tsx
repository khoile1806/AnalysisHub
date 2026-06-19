import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Clock, Plus, Trash2, Crosshair, Server, ShieldAlert,
  BrainCircuit, Search, PenLine, Filter, X, Wand2, AlertTriangle,
  FolderUp, FileText, Download, Sparkles, HardDrive, Paperclip,
} from 'lucide-react'
import toast from 'react-hot-toast'
import {
  timelineApi, MITRE_TACTICS, parseAttachments,
  type TimelineEvent, type TimelineSeverity, type CreateTimelineEvent, type TimelineAttachment,
} from '@/api/timeline'
import { AttachmentsEditor, AttachmentsView } from '@/components/TimelineAttachments'
import { elkResultsApi, analysisApi } from '@/api/analysis'
import { evidenceApi, type CaseEvidence } from '@/api/evidence'
import { casesApi } from '@/api/cases'
import { safeFormat, getErrorMessage, formatBytes } from '@/lib/utils'

const SEVERITY_STYLE: Record<TimelineSeverity, { dot: string; text: string; bg: string; border: string }> = {
  critical: { dot: 'bg-red-500',    text: 'text-red-400',    bg: 'bg-red-500/10',    border: 'border-red-500/30' },
  high:     { dot: 'bg-orange-500', text: 'text-orange-400', bg: 'bg-orange-500/10', border: 'border-orange-500/30' },
  medium:   { dot: 'bg-amber-500',  text: 'text-amber-400',  bg: 'bg-amber-500/10',  border: 'border-amber-500/30' },
  low:      { dot: 'bg-blue-500',   text: 'text-blue-400',   bg: 'bg-blue-500/10',   border: 'border-blue-500/30' },
  info:     { dot: 'bg-gray-500',   text: 'text-gray-400',   bg: 'bg-gray-500/10',   border: 'border-gray-700' },
}

const SOURCE_ICON = {
  manual: PenLine,
  elk:    Search,
  ai:     BrainCircuit,
  job:    Server,
} as const

const SEVERITIES: TimelineSeverity[] = ['critical', 'high', 'medium', 'low', 'info']

// ── Add event modal (inline, lightweight) ──────────────────────────────────
function AddEventForm({ caseId, onDone }: { caseId: string; onDone: () => void }) {
  const qc = useQueryClient()
  const now = new Date()
  const localDT = new Date(now.getTime() - now.getTimezoneOffset() * 60000).toISOString().slice(0, 16)

  const [form, setForm] = useState<CreateTimelineEvent>({
    event_time: localDT,
    title: '',
    severity: 'medium',
    host: '',
    tactic: '',
    technique: '',
    detail: '',
  })
  const [attachments, setAttachments] = useState<TimelineAttachment[]>([])

  const createMut = useMutation({
    mutationFn: () => timelineApi.create(caseId, {
      ...form,
      event_time: new Date(form.event_time).toISOString(),
      attachments: attachments.length ? JSON.stringify(attachments) : undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['timeline', caseId] })
      toast.success('Event added')
      onDone()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="card p-4 space-y-3 border-emerald-500/30">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-200">Add timeline event</h4>
        <button onClick={onDone} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
      </div>
      <div className="grid grid-cols-2 gap-3">
        <div>
          <label className="label text-xs">When (real activity time) *</label>
          <input type="datetime-local" className="input" value={form.event_time}
            onChange={(e) => setForm({ ...form, event_time: e.target.value })} />
        </div>
        <div>
          <label className="label text-xs">Severity</label>
          <select className="input" value={form.severity}
            onChange={(e) => setForm({ ...form, severity: e.target.value as TimelineSeverity })}>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
        </div>
      </div>
      <div>
        <label className="label text-xs">Title *</label>
        <input className="input" placeholder="e.g. Webshell uploaded to /uploads/x.php" value={form.title}
          onChange={(e) => setForm({ ...form, title: e.target.value })} />
      </div>
      <div className="grid grid-cols-3 gap-3">
        <div>
          <label className="label text-xs">Host</label>
          <input className="input" placeholder="WEB-01" value={form.host}
            onChange={(e) => setForm({ ...form, host: e.target.value })} />
        </div>
        <div>
          <label className="label text-xs">MITRE Tactic</label>
          <select className="input" value={form.tactic}
            onChange={(e) => setForm({ ...form, tactic: e.target.value })}>
            <option value="">—</option>
            {MITRE_TACTICS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <label className="label text-xs">Technique</label>
          <input className="input" placeholder="T1505.003" value={form.technique}
            onChange={(e) => setForm({ ...form, technique: e.target.value })} />
        </div>
      </div>
      <div>
        <label className="label text-xs">Detail</label>
        <textarea className="input min-h-[60px]" placeholder="Evidence / notes…" value={form.detail}
          onChange={(e) => setForm({ ...form, detail: e.target.value })} />
      </div>
      <AttachmentsEditor caseId={caseId} host={form.host} value={attachments} onChange={setAttachments} />
      <div className="flex justify-end gap-2">
        <button className="btn-secondary" onClick={onDone}>Cancel</button>
        <button className="btn-primary" disabled={!form.title || createMut.isPending}
          onClick={() => createMut.mutate()}>
          {createMut.isPending ? 'Saving…' : 'Add event'}
        </button>
      </div>
    </div>
  )
}

// ── Import-from-ELK picker ─────────────────────────────────────────────────
function ELKImport({ caseId, onDone }: { caseId: string; onDone: () => void }) {
  const qc = useQueryClient()
  const [selected, setSelected] = useState('')

  const { data: results = [] } = useQuery({
    queryKey: ['elk-hunt-results'],
    queryFn: elkResultsApi.list,
  })

  const promoteMut = useMutation({
    mutationFn: () => timelineApi.promoteELK(selected, caseId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['timeline', caseId] })
      toast.success(`Imported ${res.imported} event(s) from ELK hits`)
      onDone()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const done = results.filter((r) => r.status === 'done' && r.total_hits > 0)

  return (
    <div className="card p-4 space-y-3 border-sky-500/30">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Search className="h-4 w-4 text-sky-400" /> Import from ELK hunt
        </h4>
        <button onClick={onDone} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
      </div>
      <p className="text-xs text-gray-500">
        Each hit carries a real <code className="bg-gray-800 px-1 rounded">@timestamp</code> — promoted as high-severity timeline events (max 200).
      </p>
      {done.length === 0 ? (
        <p className="text-xs text-gray-500 py-2">No completed ELK hunt results with hits.</p>
      ) : (
        <div className="flex items-center gap-2">
          <select className="input flex-1" value={selected} onChange={(e) => setSelected(e.target.value)}>
            <option value="">Select a hunt result…</option>
            {done.map((r) => (
              <option key={r.id} value={r.id}>{r.title} — {r.total_hits} hits</option>
            ))}
          </select>
          <button className="btn-primary" disabled={!selected || promoteMut.isPending}
            onClick={() => promoteMut.mutate()}>
            {promoteMut.isPending ? 'Importing…' : 'Import'}
          </button>
        </div>
      )}
    </div>
  )
}

// ── AI extraction picker ───────────────────────────────────────────────────
function AIExtract({ caseId, onDone }: { caseId: string; onDone: () => void }) {
  const qc = useQueryClient()
  const [providerId, setProviderId] = useState('')
  const [jobId, setJobId] = useState('')

  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })
  const { data: summary } = useQuery({ queryKey: ['case-summary', caseId], queryFn: () => casesApi.getSummary(caseId) })
  const jobs: any[] = summary?.jobs ?? []

  const extractMut = useMutation({
    mutationFn: () => timelineApi.aiExtract(caseId, providerId, jobId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['timeline', caseId] })
      if (res.imported > 0) toast.success(`AI extracted ${res.imported} event(s)`)
      else toast(res.note ?? 'AI found no time-stamped events', { icon: 'ℹ️' })
      onDone()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="card p-4 space-y-3 border-violet-500/30">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <BrainCircuit className="h-4 w-4 text-violet-400" /> AI extract from evidence
        </h4>
        <button onClick={onDone} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
      </div>
      <p className="text-xs text-gray-500">
        AI reads a tool/job output (incl. offline-imported results) and pulls out time-stamped attack events.
      </p>
      {providers.length === 0 ? (
        <p className="text-xs text-yellow-400">No AI providers configured. <a href="/ai-providers" className="underline">Add one first.</a></p>
      ) : (
        <>
          <div>
            <label className="label text-xs">AI Provider</label>
            <select className="input" value={providerId} onChange={(e) => setProviderId(e.target.value)}>
              <option value="">Select provider…</option>
              {providers.filter((p) => p.is_active).map((p) => (
                <option key={p.id} value={p.id}>{p.name} — {p.model}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="label text-xs">Job / Evidence</label>
            <select className="input" value={jobId} onChange={(e) => setJobId(e.target.value)}>
              <option value="">Select a job…</option>
              {jobs.map((j) => (
                <option key={j.id} value={j.id}>
                  {(j.tool?.name ?? 'Tool')} — {(j.agent?.name ?? 'agent')} — {j.status}
                </option>
              ))}
            </select>
          </div>
          <div className="flex justify-end">
            <button className="btn-primary" disabled={!providerId || !jobId || extractMut.isPending}
              onClick={() => extractMut.mutate()}>
              {extractMut.isPending ? 'Analyzing…' : 'Extract timeline'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ── AI Rebuild panel ───────────────────────────────────────────────────────
function AIRebuild({ caseId, eventCount, onDone }: { caseId: string; eventCount: number; onDone: () => void }) {
  const qc = useQueryClient()
  const [providerId, setProviderId] = useState('')
  const [mode, setMode] = useState<'replace' | 'append'>('replace')

  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })

  const rebuildMut = useMutation({
    mutationFn: () => timelineApi.aiRebuild(caseId, providerId, mode),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['timeline', caseId] })
      if (res.imported > 0) {
        toast.success(`Rebuilt timeline — ${res.imported} event(s)${res.replaced ? ' (replaced old)' : ''}`)
        onDone()
      } else {
        toast(res.note ?? 'AI returned no events — timeline unchanged', { icon: 'ℹ️' })
      }
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="card p-4 space-y-3 border-amber-500/30">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <Wand2 className="h-4 w-4 text-amber-400" /> AI rebuild full timeline
        </h4>
        <button onClick={onDone} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
      </div>
      <p className="text-xs text-gray-500">
        AI reviews <strong>all evidence in this case</strong> plus your existing {eventCount} event(s),
        then produces one clean, deduplicated, professionally-worded timeline in correct order.
      </p>

      {providers.length === 0 ? (
        <p className="text-xs text-yellow-400">No AI providers configured. <a href="/ai-providers" className="underline">Add one first.</a></p>
      ) : (
        <>
          <div>
            <label className="label text-xs">AI Provider</label>
            <select className="input" value={providerId} onChange={(e) => setProviderId(e.target.value)}>
              <option value="">Select provider…</option>
              {providers.filter((p) => p.is_active).map((p) => (
                <option key={p.id} value={p.id}>{p.name} — {p.model}</option>
              ))}
            </select>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <button onClick={() => setMode('replace')}
              className={`p-2.5 rounded-lg border text-left text-xs transition ${mode === 'replace' ? 'border-amber-500/60 bg-amber-500/10' : 'border-gray-700'}`}>
              <span className="font-semibold text-gray-200">Replace</span>
              <p className="text-gray-500 mt-0.5">Overwrite with the clean rebuilt set</p>
            </button>
            <button onClick={() => setMode('append')}
              className={`p-2.5 rounded-lg border text-left text-xs transition ${mode === 'append' ? 'border-amber-500/60 bg-amber-500/10' : 'border-gray-700'}`}>
              <span className="font-semibold text-gray-200">Append</span>
              <p className="text-gray-500 mt-0.5">Keep old events, add rebuilt ones</p>
            </button>
          </div>

          {mode === 'replace' && eventCount > 0 && (
            <div className="flex items-start gap-2 text-[11px] text-amber-300/80 bg-amber-500/5 border border-amber-500/20 rounded p-2">
              <AlertTriangle className="h-3.5 w-3.5 flex-shrink-0 mt-0.5" />
              <span>Your existing {eventCount} event(s) will be removed and replaced. Their content is fed to the AI first, so nothing is lost — it's refined into the new timeline.</span>
            </div>
          )}

          <div className="flex justify-end">
            <button className="btn-primary" disabled={!providerId || rebuildMut.isPending}
              onClick={() => rebuildMut.mutate()}>
              {rebuildMut.isPending ? 'Rebuilding…' : 'Rebuild timeline'}
            </button>
          </div>
        </>
      )}
    </div>
  )
}

// ── Evidence files panel ────────────────────────────────────────────────────
function EvidencePanel({ caseId, agents, onDone }: { caseId: string; agents: any[]; onDone: () => void }) {
  const qc = useQueryClient()
  const [host, setHost] = useState('')
  const [notes, setNotes] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [providerId, setProviderId] = useState('')

  const { data: evidence = [] } = useQuery({ queryKey: ['case-evidence', caseId], queryFn: () => evidenceApi.list(caseId) })
  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })

  const uploadMut = useMutation({
    mutationFn: () => evidenceApi.upload(caseId, file!, host.trim(), notes.trim() || undefined),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['case-evidence', caseId] })
      toast.success('Evidence uploaded')
      setFile(null); setNotes('')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const extractMut = useMutation({
    mutationFn: (id: string) => evidenceApi.extractTimeline(caseId, id, providerId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['timeline', caseId] })
      qc.invalidateQueries({ queryKey: ['case-evidence', caseId] })
      if (res.imported > 0) toast.success(`Trích ${res.imported} sự kiện từ ${res.host}`)
      else toast(`Không tìm thấy sự kiện có mốc thời gian (${res.host})`, { icon: 'ℹ️' })
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const removeMut = useMutation({
    mutationFn: (id: string) => evidenceApi.remove(id),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['case-evidence', caseId] }); toast.success('Removed') },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const hostNames = Array.from(new Set((agents ?? []).map((a) => a.hostname || a.name).filter(Boolean)))

  return (
    <div className="card p-4 space-y-3 border-sky-500/30">
      <div className="flex items-center justify-between">
        <h4 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <HardDrive className="h-4 w-4 text-sky-400" /> Evidence / Result files
        </h4>
        <button onClick={onDone} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
      </div>

      {/* Upload form — host is required */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-2">
        <div>
          <label className="label text-xs">Result thuộc máy nào? *</label>
          <input className="input" list="evidence-hosts" placeholder="VD: WEB-01"
            value={host} onChange={(e) => setHost(e.target.value)} />
          <datalist id="evidence-hosts">{hostNames.map((h) => <option key={h} value={h} />)}</datalist>
        </div>
        <div>
          <label className="label text-xs">Ghi chú (tuỳ chọn)</label>
          <input className="input" placeholder="VD: output Autoruns" value={notes} onChange={(e) => setNotes(e.target.value)} />
        </div>
      </div>
      <div className="flex items-center gap-2">
        <label className="flex-1 flex items-center gap-2 border border-dashed border-gray-700 rounded-lg px-3 py-2 cursor-pointer hover:border-sky-500/50 text-xs text-gray-400">
          <FolderUp className="h-4 w-4 text-gray-500" />
          {file ? <span className="text-sky-400 truncate">{file.name}</span> : 'Chọn file result/evidence…'}
          <input type="file" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <button className="btn-primary text-xs py-2" disabled={!file || !host.trim() || uploadMut.isPending}
          onClick={() => uploadMut.mutate()}>
          {uploadMut.isPending ? 'Đang tải…' : 'Upload'}
        </button>
      </div>
      {!host.trim() && file && <p className="text-[11px] text-amber-400">⚠ Phải nhập máy (host) trước khi upload.</p>}

      {/* Provider for AI extraction */}
      {evidence.length > 0 && (
        <div className="flex items-center gap-2 pt-1">
          <span className="text-[11px] text-gray-500">AI provider (để trích timeline):</span>
          <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300 flex-1"
            value={providerId} onChange={(e) => setProviderId(e.target.value)}>
            <option value="">Select provider…</option>
            {providers.filter((p) => p.is_active).map((p) => <option key={p.id} value={p.id}>{p.name} — {p.model}</option>)}
          </select>
        </div>
      )}

      {/* File list */}
      <div className="space-y-1.5">
        {evidence.length === 0 ? (
          <p className="text-xs text-gray-500 py-2 text-center">Chưa có file evidence nào.</p>
        ) : (
          evidence.map((ev: CaseEvidence) => (
            <div key={ev.id} className="flex items-center gap-2 bg-gray-900/40 border border-gray-800 rounded-lg px-3 py-2">
              <FileText className="h-3.5 w-3.5 text-gray-500 shrink-0" />
              <div className="min-w-0 flex-1">
                <div className="flex items-center gap-2">
                  <span className="text-xs text-gray-200 truncate">{ev.file_name}</span>
                  {ev.extracted && <span className="text-[9px] text-emerald-400 border border-emerald-500/30 rounded px-1">extracted</span>}
                </div>
                <div className="text-[10px] text-gray-500 flex items-center gap-2">
                  <span className="flex items-center gap-0.5"><Server className="h-2.5 w-2.5" />{ev.host}</span>
                  <span>{formatBytes(ev.size)}</span>
                  <span>{safeFormat(ev.created_at, 'MMM dd, HH:mm')}</span>
                  {ev.notes && <span className="truncate">· {ev.notes}</span>}
                </div>
              </div>
              <button title="AI trích timeline" disabled={!providerId || extractMut.isPending}
                onClick={() => extractMut.mutate(ev.id)}
                className="text-[10px] px-2 py-1 rounded border border-violet-500/40 text-violet-300 hover:bg-violet-500/10 disabled:opacity-40 shrink-0 flex items-center gap-1">
                <Sparkles className="h-3 w-3" /> Extract
              </button>
              <a href={evidenceApi.downloadUrl(ev.id)} className="text-gray-500 hover:text-gray-300 shrink-0" title="Download"><Download className="h-3.5 w-3.5" /></a>
              <button onClick={() => { if (confirm('Remove this file?')) removeMut.mutate(ev.id) }}
                className="text-gray-600 hover:text-red-400 shrink-0"><Trash2 className="h-3.5 w-3.5" /></button>
            </div>
          ))
        )}
      </div>
    </div>
  )
}

// ── Main timeline ──────────────────────────────────────────────────────────
export default function AttackTimeline({ caseId, agents = [] }: { caseId: string; agents?: any[] }) {
  const qc = useQueryClient()
  const [adding, setAdding] = useState(false)
  const [elkImport, setElkImport] = useState(false)
  const [aiExtract, setAiExtract] = useState(false)
  const [aiRebuild, setAiRebuild] = useState(false)
  const [evidenceOpen, setEvidenceOpen] = useState(false)
  const [hostFilter, setHostFilter] = useState('')
  const [sevFilter, setSevFilter] = useState<TimelineSeverity | ''>('')
  const [editAttachFor, setEditAttachFor] = useState<string | null>(null)

  const { data: events = [], isLoading } = useQuery({
    queryKey: ['timeline', caseId],
    queryFn: () => timelineApi.list(caseId),
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => timelineApi.remove(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['timeline', caseId] })
      toast.success('Event removed')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const updateAttachMut = useMutation({
    mutationFn: ({ id, attachments }: { id: string; attachments: string }) =>
      timelineApi.update(id, { attachments }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['timeline', caseId] }),
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const hosts = useMemo(
    () => Array.from(new Set(events.map((e) => e.host).filter(Boolean))) as string[],
    [events],
  )

  const filtered = useMemo(() => {
    return events.filter((e) => {
      if (hostFilter && e.host !== hostFilter) return false
      if (sevFilter && e.severity !== sevFilter) return false
      return true
    })
  }, [events, hostFilter, sevFilter])

  // Group events by calendar day for readable separators.
  const grouped = useMemo(() => {
    const map = new Map<string, TimelineEvent[]>()
    for (const e of filtered) {
      const day = safeFormat(e.event_time, 'yyyy-MM-dd')
      if (!map.has(day)) map.set(day, [])
      map.get(day)!.push(e)
    }
    return Array.from(map.entries())
  }, [filtered])

  const sevCounts = useMemo(() => {
    const c: Record<string, number> = {}
    for (const e of events) c[e.severity] = (c[e.severity] ?? 0) + 1
    return c
  }, [events])

  return (
    <div className="space-y-4">
      {/* Toolbar */}
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          {SEVERITIES.map((s) => (
            sevCounts[s] ? (
              <span key={s} className={`text-xs px-2 py-1 rounded-full border ${SEVERITY_STYLE[s].bg} ${SEVERITY_STYLE[s].text} ${SEVERITY_STYLE[s].border}`}>
                {sevCounts[s]} {s}
              </span>
            ) : null
          ))}
          {events.length === 0 && <span className="text-xs text-gray-500">No events yet</span>}
        </div>
        <div className="flex items-center gap-2">
          {hosts.length > 0 && (
            <div className="flex items-center gap-1.5 text-xs">
              <Filter className="h-3.5 w-3.5 text-gray-500" />
              <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300"
                value={hostFilter} onChange={(e) => setHostFilter(e.target.value)}>
                <option value="">All hosts</option>
                {hosts.map((h) => <option key={h} value={h}>{h}</option>)}
              </select>
            </div>
          )}
          <select className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-xs text-gray-300"
            value={sevFilter} onChange={(e) => setSevFilter(e.target.value as TimelineSeverity | '')}>
            <option value="">All severity</option>
            {SEVERITIES.map((s) => <option key={s} value={s}>{s}</option>)}
          </select>
          <button onClick={() => setEvidenceOpen((v) => !v)} className="btn-secondary text-xs py-1.5 border-sky-500/40 text-sky-300">
            <HardDrive className="h-3.5 w-3.5" /> Evidence
          </button>
          <button onClick={() => setAiRebuild((v) => !v)} className="btn-secondary text-xs py-1.5 border-amber-500/40 text-amber-300">
            <Wand2 className="h-3.5 w-3.5" /> AI Rebuild
          </button>
          <button onClick={() => setAiExtract((v) => !v)} className="btn-secondary text-xs py-1.5">
            <BrainCircuit className="h-3.5 w-3.5" /> AI Extract
          </button>
          <button onClick={() => setElkImport((v) => !v)} className="btn-secondary text-xs py-1.5">
            <Search className="h-3.5 w-3.5" /> Import ELK
          </button>
          <button onClick={() => setAdding(true)} className="btn-primary text-xs py-1.5">
            <Plus className="h-3.5 w-3.5" /> Add event
          </button>
        </div>
      </div>

      {evidenceOpen && <EvidencePanel caseId={caseId} agents={agents} onDone={() => setEvidenceOpen(false)} />}
      {aiRebuild && <AIRebuild caseId={caseId} eventCount={events.length} onDone={() => setAiRebuild(false)} />}
      {aiExtract && <AIExtract caseId={caseId} onDone={() => setAiExtract(false)} />}
      {elkImport && <ELKImport caseId={caseId} onDone={() => setElkImport(false)} />}
      {adding && <AddEventForm caseId={caseId} onDone={() => setAdding(false)} />}

      {/* Timeline */}
      {isLoading ? (
        <div className="space-y-2">
          {[...Array(3)].map((_, i) => <div key={i} className="skeleton h-16 rounded-lg" />)}
        </div>
      ) : filtered.length === 0 ? (
        <div className="card p-10 text-center flex flex-col items-center">
          <Crosshair className="h-10 w-10 text-gray-700 mb-3" />
          <p className="text-gray-400 font-medium">No attack timeline events</p>
          <p className="text-xs text-gray-500 mt-1 max-w-sm">
            Add events manually, promote ELK hits, or let AI Analysis extract them from evidence.
          </p>
        </div>
      ) : (
        <div className="space-y-6">
          {grouped.map(([day, dayEvents]) => (
            <div key={day}>
              <div className="flex items-center gap-2 mb-3">
                <span className="text-xs font-bold text-gray-400 bg-gray-800 px-2.5 py-1 rounded-full">{day}</span>
                <div className="flex-1 h-px bg-gray-800" />
              </div>
              <div className="relative pl-6 space-y-3 before:absolute before:left-[7px] before:top-1 before:bottom-1 before:w-px before:bg-gray-800">
                {dayEvents.map((e) => {
                  const st = SEVERITY_STYLE[e.severity]
                  const Icon = SOURCE_ICON[e.source] ?? PenLine
                  return (
                    <div key={e.id} className="relative">
                      <span className={`absolute -left-[19px] top-2 h-3.5 w-3.5 rounded-full ${st.dot} ring-4 ring-gray-950`} />
                      <div className={`card p-3 ${st.border} hover:border-opacity-60 transition group`}>
                        <div className="flex items-start justify-between gap-3">
                          <div className="min-w-0 flex-1">
                            <div className="flex items-center gap-2 flex-wrap">
                              <span className="font-mono text-xs text-gray-400 flex items-center gap-1">
                                <Clock className="h-3 w-3" />{safeFormat(e.event_time, 'HH:mm:ss')}
                              </span>
                              <span className={`text-[10px] uppercase font-bold px-1.5 py-0.5 rounded ${st.bg} ${st.text}`}>
                                {e.severity}
                              </span>
                              {e.tactic && (
                                <span className="text-[10px] px-1.5 py-0.5 rounded bg-violet-500/10 text-violet-300 border border-violet-500/20">
                                  {e.tactic}{e.technique ? ` · ${e.technique}` : ''}
                                </span>
                              )}
                              <span className="text-[10px] text-gray-600 flex items-center gap-1" title={`Source: ${e.source}`}>
                                <Icon className="h-3 w-3" />{e.source}
                              </span>
                            </div>
                            <p className="text-sm text-gray-200 font-medium mt-1">{e.title}</p>
                            {e.detail && <p className="text-xs text-gray-500 mt-1 whitespace-pre-wrap break-words">{e.detail}</p>}
                            {e.host && (
                              <div className="text-[10px] text-gray-500 flex items-center gap-1 mt-1.5">
                                <Server className="h-3 w-3" />{e.host}
                              </div>
                            )}
                            {/* Attachments view */}
                            <AttachmentsView attachments={parseAttachments(e.attachments)} />
                            {/* Inline attachments editor */}
                            {editAttachFor === e.id && (
                              <div className="mt-2">
                                <AttachmentsEditor
                                  caseId={caseId}
                                  host={e.host}
                                  value={parseAttachments(e.attachments)}
                                  onChange={(next) => updateAttachMut.mutate({ id: e.id, attachments: JSON.stringify(next) })}
                                />
                              </div>
                            )}
                          </div>
                          <div className="flex flex-col items-center gap-1.5 shrink-0">
                            <button
                              onClick={() => setEditAttachFor(editAttachFor === e.id ? null : e.id)}
                              title="Đính kèm evidence / ảnh / link"
                              className={`transition ${editAttachFor === e.id ? 'text-emerald-400' : 'text-gray-600 hover:text-emerald-400 opacity-0 group-hover:opacity-100'}`}
                            >
                              <Paperclip className="h-3.5 w-3.5" />
                            </button>
                            <button
                              onClick={() => { if (confirm('Remove this event?')) deleteMut.mutate(e.id) }}
                              className="opacity-0 group-hover:opacity-100 text-gray-600 hover:text-red-400 transition"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          </div>
                        </div>
                      </div>
                    </div>
                  )
                })}
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Hint footer */}
      {events.length > 0 && (
        <p className="text-[11px] text-gray-600 flex items-center gap-1.5 pt-2">
          <ShieldAlert className="h-3 w-3" />
          Sorted by real activity time (event_time), oldest → newest. Lower severity = informational only.
        </p>
      )}
    </div>
  )
}
