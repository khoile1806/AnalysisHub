import { useMemo, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, keepPreviousData } from '@tanstack/react-query'
import {
  ScrollText, ShieldCheck, Users, Download, Loader2, XCircle,
  ChevronLeft, ChevronRight, Search, RefreshCw, HardDriveDownload,
  PackageOpen, Server, Trash2, Activity, Clock, Sparkles,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { auditApi, type AuditRow, type AuditUserSummary, type AuditListParams } from '@/api/audit'
import { useAuthStore } from '@/store/auth'
import { safeDistanceToNow, safeFormat, getErrorMessage } from '@/lib/utils'
import { printMarkdownAsPdf } from '@/lib/reportPdf'

const PAGE_SIZE = 100
const CSV_LIMIT = 5000 // export cap — plenty for an auditor, avoids pulling the whole table

// The literal actor the backend records for platform/agent-driven activity that
// no human triggered. Rendered distinctly so it never reads as a person.
const SYSTEM_ACTOR = 'system / automated'

// ──────────────────────────────────────────────────────────────────────────────
// Action chip coloring — grouped by dot-namespaced prefix. Data movement
// (evidence off an agent) and destructive actions are the ones that must stand out.
// ──────────────────────────────────────────────────────────────────────────────

function actionChipClass(action: string): string {
  if (action.startsWith('auth.')) return 'text-sky-300 border-sky-700/40 bg-sky-900/20'
  // Destructive first, so it wins over any other prefix a delete action carries.
  if (action.includes('delete') || action.includes('cleanup') || action.includes('kill')) return 'text-red-300 border-red-700/40 bg-red-900/20'
  // Data movement — anything that takes collected data off the platform, whether
  // it's evidence, a job artifact, or a tool result. This is the accountability
  // signal, so it must not hide inside the generic "job." colour.
  if (action.startsWith('agent.fs.') || action.startsWith('evidence.') ||
      action.endsWith('.download') || action.startsWith('tool_result.')) return 'text-amber-300 border-amber-700/40 bg-amber-900/20'
  // Endpoint scans / forensic collection run a tool ON an agent (edge forensics,
  // EVTX/registry queries, IOC sweeps) — distinct from taking data off the box.
  if (action.startsWith('agent.edge.') || action.startsWith('agent.evtx.') ||
      action.startsWith('agent.registry.') || action.startsWith('agent.ioc.') ||
      action.startsWith('agent.sigma.') || action.startsWith('fleet.') ||
      action.startsWith('agent.logs.')) return 'text-teal-300 border-teal-700/40 bg-teal-900/20'
  if (action.startsWith('job.')) return 'text-violet-300 border-violet-700/40 bg-violet-900/20'
  return 'text-gray-400 border-gray-700/50 bg-gray-800/40'
}

const ROLE_BADGE: Record<string, string> = {
  admin: 'text-emerald-300 border-emerald-600/40 bg-emerald-900/20',
  analyst: 'text-sky-300 border-sky-700/40 bg-sky-900/20',
}

function RoleBadge({ role }: { role: string }) {
  const cls = ROLE_BADGE[role] ?? 'text-gray-400 border-gray-700/50 bg-gray-800/40'
  return <span className={`text-[10px] font-mono uppercase px-1.5 py-0.5 rounded border ${cls}`}>{role || '—'}</span>
}

// system/automated activity has a null user_id and this sentinel email
function isSystemActor(email: string, userId: string | null): boolean {
  return userId == null && (email === SYSTEM_ACTOR || email === '' || email === 'system')
}

// ──────────────────────────────────────────────────────────────────────────────
// CSV helpers
// ──────────────────────────────────────────────────────────────────────────────

function csvCell(val: string | number | null): string {
  const s = val == null ? '' : String(val)
  // Quote if it contains a quote, comma, or newline; escape inner quotes by doubling.
  if (/[",\n\r]/.test(s)) return `"${s.replace(/"/g, '""')}"`
  return s
}

function rowsToCsv(rows: AuditRow[]): string {
  const header = ['id', 'created_at', 'user_email', 'user_name', 'user_role', 'action', 'agent_host', 'resource', 'detail', 'ip', 'forwarded', 'user_agent']
  const lines = [header.join(',')]
  for (const r of rows) {
    lines.push([
      r.id, r.created_at, r.user_email, r.user_name, r.user_role,
      r.action, r.agent_host, r.resource, r.detail, r.ip, r.forwarded, r.user_agent,
    ].map(csvCell).join(','))
  }
  return lines.join('\r\n')
}

function downloadBlob(filename: string, content: string, mime: string) {
  const blob = new Blob([content], { type: mime })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}

function downloadCsv(filename: string, csv: string) {
  downloadBlob(filename, csv, 'text/csv;charset=utf-8;')
}

// buildUserReport renders one operator's activity as a self-contained Markdown
// accountability report: identity, the headline data-movement numbers, and the
// full action list. This is the factual record; the AI narrative is a separate
// AI Analysis session.
function buildUserReport(u: AuditUserSummary, rows: AuditRow[]): string {
  const L: string[] = []
  const actor = isSystemActor(u.user_email, u.user_id) ? SYSTEM_ACTOR : u.user_email
  L.push(`# User Activity Report — ${actor}`)
  L.push('')
  if (u.user_name) L.push(`- **Name:** ${u.user_name}`)
  L.push(`- **Role:** ${u.user_role || 'unknown'}`)
  if (u.user_id) L.push(`- **User ID:** ${u.user_id}`)
  L.push(`- **First seen:** ${safeFormat(u.first_seen, 'yyyy-MM-dd HH:mm:ss')}`)
  L.push(`- **Last seen:** ${safeFormat(u.last_seen, 'yyyy-MM-dd HH:mm:ss')}`)
  L.push(`- **Generated:** ${new Date().toISOString()}`)
  L.push('')
  L.push('## Summary')
  L.push('')
  L.push(`- Total actions: **${u.total_actions}**`)
  L.push(`- Agents touched: **${u.agents_touched}**`)
  L.push(`- Evidence pulled to store: **${u.evidence_pulled}**`)
  L.push(`- Evidence downloaded to a machine: **${u.evidence_download}**`)
  L.push(`- Jobs run: **${u.jobs_run}**`)
  L.push(`- Deletions: **${u.deletions}**`)
  L.push('')
  L.push(`## Full activity (${rows.length} record${rows.length === 1 ? '' : 's'}, newest first)`)
  L.push('')
  L.push('| Time (UTC) | Action | Agent | Resource | Detail | IP |')
  L.push('|---|---|---|---|---|---|')
  for (const r of rows) {
    const cell = (s: string) => (s || '').replace(/\|/g, '\\|').replace(/\n/g, ' ')
    L.push(`| ${r.created_at} | ${cell(r.action)} | ${cell(r.agent_host)} | ${cell(r.resource)} | ${cell(r.detail)} | ${cell(r.ip)} |`)
  }
  if (rows.length >= 5000) L.push('\n_Note: capped at 5000 most-recent records._')
  return L.join('\n')
}

// ──────────────────────────────────────────────────────────────────────────────
// Stat pill for the per-user cards
// ──────────────────────────────────────────────────────────────────────────────

function StatPill({ icon: Icon, label, value, tone = 'gray' }: {
  icon: React.ElementType
  label: string
  value: number
  tone?: 'gray' | 'amber' | 'red'
}) {
  const toneCls = {
    gray: 'text-gray-300 border-gray-800 bg-gray-900/40',
    amber: 'text-amber-300 border-amber-700/40 bg-amber-900/15',
    red: 'text-red-300 border-red-700/40 bg-red-900/15',
  }[tone]
  return (
    <div className={`flex items-center gap-2 rounded-lg border px-2.5 py-1.5 ${toneCls}`} title={label}>
      <Icon className="h-3.5 w-3.5 shrink-0 opacity-70" />
      <span className="text-sm font-bold tabular-nums">{value.toLocaleString()}</span>
      <span className="text-[10px] uppercase tracking-wider opacity-70">{label}</span>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// A) By-user summary view
// ──────────────────────────────────────────────────────────────────────────────

function ByUserView({ onPickUser }: { onPickUser: (userId: string | null, email: string) => void }) {
  const navigate = useNavigate()
  const { data = [], isLoading, isFetching, error, refetch } = useQuery({
    queryKey: ['audit-summary'],
    queryFn: () => auditApi.summary(),
    staleTime: 30_000,
  })

  const sorted = useMemo(
    () => [...data].sort((a, b) => b.total_actions - a.total_actions),
    [data],
  )

  const [reportFor, setReportFor] = useState<string | null>(null)

  // downloadUserReport pulls the user's full trail (bounded) and produces a
  // self-contained PDF accountability report for that operator.
  const downloadUserReport = async (u: AuditUserSummary) => {
    const key = u.user_id ?? u.user_email
    setReportFor(key)
    try {
      const res = await auditApi.list({ user_id: u.user_id ?? '', limit: 5000 })
      const md = buildUserReport(u, res.data)
      const slug = (u.user_email || 'system').replace(/[^a-z0-9-_]+/gi, '_').slice(0, 60)
      printMarkdownAsPdf(`user-activity-${slug}`, md)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setReportFor(null)
    }
  }

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-600">
          One row per operator, aggregated across the whole trail. Click a user to see their full activity.
        </span>
        <button onClick={() => refetch()} disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-800/60 border border-gray-700/50 rounded-lg transition disabled:opacity-50">
          <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} /> Refresh
        </button>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-gray-500 py-8 justify-center">
          <Loader2 className="h-5 w-5 animate-spin" /><span className="text-sm">Loading summary…</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-900/10 p-4 text-sm text-red-400 flex items-center gap-2">
          <XCircle className="h-4 w-4 shrink-0" /> {getErrorMessage(error)}
        </div>
      )}

      {!isLoading && !error && sorted.length === 0 && (
        <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-5 py-10 text-center">
          <Users className="h-8 w-8 text-gray-700 mx-auto mb-3" />
          <p className="text-sm text-gray-600">No recorded activity yet.</p>
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
        {sorted.map((u: AuditUserSummary) => {
          const system = isSystemActor(u.user_email, u.user_id)
          return (
            <div
              key={u.user_id ?? u.user_email}
              onClick={() => onPickUser(u.user_id, u.user_email)}
              className="text-left rounded-xl border border-gray-800/60 bg-gray-900/50 p-4 hover:border-emerald-500/30 hover:bg-gray-900/80 transition-colors group cursor-pointer"
            >
              {/* Identity */}
              <div className="flex items-start justify-between gap-3 mb-3">
                <div className="min-w-0">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className={`text-sm font-semibold truncate ${system ? 'text-gray-400 italic' : 'text-gray-100 group-hover:text-emerald-300'}`}>
                      {system ? SYSTEM_ACTOR : (u.user_email || '—')}
                    </span>
                    {!system && <RoleBadge role={u.user_role} />}
                  </div>
                  {!system && u.user_name && <div className="text-[11px] text-gray-600 truncate">{u.user_name}</div>}
                </div>
                <div className="flex items-center gap-2 shrink-0">
                  {/* Factual Markdown report of everything this operator did. */}
                  <button
                    onClick={(e) => { e.stopPropagation(); downloadUserReport(u) }}
                    disabled={reportFor === (u.user_id ?? u.user_email)}
                    title="Download an accountability report for this operator (PDF)"
                    className="flex items-center gap-1 px-2 py-1 rounded-lg border border-gray-700 bg-gray-800/60 text-gray-300 hover:bg-gray-700 text-[11px] disabled:opacity-50">
                    {reportFor === (u.user_id ?? u.user_email)
                      ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                      : <Download className="h-3.5 w-3.5" />} Report
                  </button>
                  {/* Runs the same session pipeline as evidence analysis: creates
                      a persisted AI Analysis session and streams the narrative. */}
                  {!system && u.user_id && (
                    <button
                      onClick={(e) => { e.stopPropagation(); navigate(`/ai-analysis?source=user_activity&id=${u.user_id}`) }}
                      title="AI summary of this operator's activity (saved as an AI Analysis session)"
                      className="flex items-center gap-1 px-2 py-1 rounded-lg border border-violet-700/40 bg-violet-900/20 text-violet-300 hover:bg-violet-900/40 text-[11px]">
                      <Sparkles className="h-3.5 w-3.5" /> AI summary
                    </button>
                  )}
                  <div className="text-right">
                    <div className="text-lg font-bold text-gray-200 tabular-nums">{u.total_actions.toLocaleString()}</div>
                    <div className="text-[10px] text-gray-600 uppercase tracking-wider">actions</div>
                  </div>
                </div>
              </div>

              {/* Accountability numbers — evidence movement highlighted */}
              <div className="flex flex-wrap gap-2 mb-3">
                <StatPill icon={PackageOpen} label="evidence pulled" value={u.evidence_pulled} tone="amber" />
                <StatPill icon={HardDriveDownload} label="downloaded" value={u.evidence_download} tone="amber" />
                <StatPill icon={Server} label="agents" value={u.agents_touched} />
                <StatPill icon={Activity} label="jobs" value={u.jobs_run} />
                <StatPill icon={Trash2} label="deletions" value={u.deletions} tone={u.deletions > 0 ? 'red' : 'gray'} />
              </div>

              {/* Timespan */}
              <div className="flex items-center gap-4 text-[11px] text-gray-600">
                <span className="flex items-center gap-1"><Clock className="h-3 w-3" /> first {safeDistanceToNow(u.first_seen, { addSuffix: true })}</span>
                <span>last {safeDistanceToNow(u.last_seen, { addSuffix: true })}</span>
              </div>
            </div>
          )
        })}
      </div>

    </div>
  )
}


// ──────────────────────────────────────────────────────────────────────────────
// B) Activity log view
// ──────────────────────────────────────────────────────────────────────────────

function ActivityLogView({
  initialUserId,
}: {
  initialUserId: string | null | undefined
}) {
  const [userId, setUserId] = useState<string>(initialUserId ?? '')
  const [action, setAction] = useState('')
  const [qInput, setQInput] = useState('')
  const [q, setQ] = useState('')
  const [from, setFrom] = useState('')
  const [to, setTo] = useState('')
  const [page, setPage] = useState(0)
  const [exporting, setExporting] = useState(false)
  const [selected, setSelected] = useState<AuditRow | null>(null)

  const offset = page * PAGE_SIZE

  const filters: AuditListParams = {
    user_id: userId || undefined,
    action: action || undefined,
    q: q || undefined,
    from: from || undefined,
    to: to || undefined,
  }

  const { data, isLoading, isFetching, error } = useQuery({
    queryKey: ['audit-log', userId, action, q, from, to, offset],
    queryFn: () => auditApi.list({ ...filters, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  })

  // Dropdowns: users from the summary, actions from the distinct-actions endpoint.
  const { data: summary = [] } = useQuery({ queryKey: ['audit-summary'], queryFn: () => auditApi.summary(), staleTime: 30_000 })
  const { data: actions = [] } = useQuery({ queryKey: ['audit-actions'], queryFn: () => auditApi.actions(), staleTime: 60_000 })

  const rows = data?.data ?? []
  const total = data?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const resetPage = () => setPage(0)
  const applySearch = () => { setQ(qInput); resetPage() }

  const doExport = async () => {
    setExporting(true)
    try {
      const res = await auditApi.list({ ...filters, limit: CSV_LIMIT, offset: 0 })
      if (res.data.length === 0) { toast.error('No rows to export for these filters'); return }
      downloadCsv(`user-activity-${new Date().toISOString().slice(0, 19).replace(/[:T]/g, '-')}.csv`, rowsToCsv(res.data))
      toast.success(`Exported ${res.data.length.toLocaleString()} row(s)${res.total > res.data.length ? ` of ${res.total.toLocaleString()}` : ''}`)
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setExporting(false)
    }
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
          <input
            value={qInput}
            onChange={(e) => setQInput(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter') applySearch() }}
            placeholder="Search action / resource / detail / IP / email…"
            className="input pl-9 w-full"
          />
          {isFetching && <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 animate-spin text-gray-600" />}
        </div>

        <select className="input max-w-[220px]" value={userId} onChange={(e) => { setUserId(e.target.value); resetPage() }}>
          <option value="">All users</option>
          {summary.filter((u) => u.user_id).map((u) => (
            <option key={u.user_id} value={u.user_id as string}>{u.user_email || u.user_name || u.user_id}</option>
          ))}
        </select>

        <select className="input max-w-[200px]" value={action} onChange={(e) => { setAction(e.target.value); resetPage() }}>
          <option value="">All actions</option>
          {actions.map((a) => <option key={a} value={a}>{a}</option>)}
        </select>

        <input type="date" className="input max-w-[150px]" value={from} onChange={(e) => { setFrom(e.target.value); resetPage() }} title="From date" />
        <input type="date" className="input max-w-[150px]" value={to} onChange={(e) => { setTo(e.target.value); resetPage() }} title="To date" />

        <button onClick={applySearch} className="btn-secondary text-sm">Search</button>

        <button onClick={doExport} disabled={exporting}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm text-emerald-300 hover:text-emerald-200 bg-emerald-500/10 border border-emerald-500/20 rounded-lg transition disabled:opacity-50">
          {exporting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Download className="h-4 w-4" />} Export CSV
        </button>
      </div>

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-900/10 p-4 text-sm text-red-400 flex items-center gap-2">
          <XCircle className="h-4 w-4 shrink-0" /> {getErrorMessage(error)}
        </div>
      )}

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">{[...Array(8)].map((_, i) => <div key={i} className="skeleton h-9 rounded" />)}</div>
      ) : rows.length === 0 ? (
        <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-5 py-10 text-center">
          <ScrollText className="h-8 w-8 text-gray-700 mx-auto mb-3" />
          <p className="text-sm text-gray-600">No activity matches these filters.</p>
        </div>
      ) : (
        <>
          <div className="overflow-auto max-h-[62vh] rounded-lg border border-gray-800">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-900 z-10">
                <tr className="border-b border-gray-800 text-gray-500">
                  <th className="px-3 py-2 text-left font-medium whitespace-nowrap">Time</th>
                  <th className="px-3 py-2 text-left font-medium">Actor</th>
                  <th className="px-3 py-2 text-left font-medium">Action</th>
                  <th className="px-3 py-2 text-left font-medium">Agent</th>
                  <th className="px-3 py-2 text-left font-medium">Resource</th>
                  <th className="px-3 py-2 text-left font-medium">Detail</th>
                  <th className="px-3 py-2 text-left font-medium whitespace-nowrap">IP</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((r: AuditRow) => {
                  const system = isSystemActor(r.user_email, r.user_id)
                  return (
                    <tr key={r.id} onClick={() => setSelected(r)}
                      className="border-b border-gray-900 hover:bg-white/5 align-top cursor-pointer">
                      <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap" title={r.created_at}>
                        {safeFormat(r.created_at, 'MMM dd, HH:mm:ss')}
                      </td>
                      <td className="px-3 py-1.5">
                        {system ? (
                          <span className="text-[11px] font-mono italic text-gray-500">{SYSTEM_ACTOR}</span>
                        ) : (
                          <div className="flex items-center gap-1.5 flex-wrap">
                            <span className="text-gray-200 truncate max-w-[180px]">{r.user_email || '—'}</span>
                            <RoleBadge role={r.user_role} />
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-1.5">
                        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border whitespace-nowrap ${actionChipClass(r.action)}`}>{r.action}</span>
                      </td>
                      <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">{r.agent_host || '—'}</td>
                      <td className="px-3 py-1.5 text-gray-400 break-all max-w-[220px]">{r.resource || '—'}</td>
                      <td className="px-3 py-1.5 text-gray-500 font-mono truncate max-w-[280px]" title={r.detail}>{r.detail || '—'}</td>
                      <td className="px-3 py-1.5 text-gray-500 font-mono whitespace-nowrap">{r.ip || '—'}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>{(offset + 1).toLocaleString()}–{Math.min(offset + rows.length, total).toLocaleString()} of {total.toLocaleString()}</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}
                className="flex items-center gap-1 px-2.5 py-1 rounded border border-gray-700 bg-gray-800 hover:bg-gray-700 disabled:opacity-40"><ChevronLeft className="h-3.5 w-3.5" /> Prev</button>
              <span>Page {page + 1} / {totalPages}</span>
              <button onClick={() => setPage((p) => (p + 1 < totalPages ? p + 1 : p))} disabled={page + 1 >= totalPages}
                className="flex items-center gap-1 px-2.5 py-1 rounded border border-gray-700 bg-gray-800 hover:bg-gray-700 disabled:opacity-40">Next <ChevronRight className="h-3.5 w-3.5" /></button>
            </div>
          </div>
        </>
      )}

      {selected && <AuditDetailModal row={selected} onClose={() => setSelected(null)} />}
    </div>
  )
}

// AuditDetailModal shows one entry in full: the truncated table columns
// (resource, detail) untruncated, plus the client fingerprint (User-Agent and
// the raw X-Forwarded-For chain) that the row does not have room for — the
// evidence that answers "which client, from which address" beyond the one IP
// the row shows.
function AuditDetailModal({ row, onClose }: { row: AuditRow; onClose: () => void }) {
  const navigate = useNavigate()
  const copy = (v: string) => { navigator.clipboard?.writeText(v); toast.success('Copied') }

  // An audit.summarize row now stores the generated narrative in its detail, so
  // render it as prose rather than trying to parse it into key/value fields.
  const isSummaryRow = row.action === 'audit.summarize'
  const fields = isSummaryRow ? [] : parseDetailPairs(row.detail)
  const canSummarize = !isSystemActor(row.user_email, row.user_id) && !!row.user_id

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[85vh] overflow-auto rounded-xl border border-gray-700 bg-gray-900 shadow-2xl"
        onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between border-b border-gray-800 px-5 py-3">
          <div className="flex items-center gap-2">
            <span className={`text-[11px] font-mono px-1.5 py-0.5 rounded border ${actionChipClass(row.action)}`}>{row.action}</span>
            <span className="text-xs text-gray-500">#{row.id}</span>
          </div>
          <div className="flex items-center gap-2">
            {canSummarize && (
              <button onClick={() => navigate(`/ai-analysis?source=user_activity&id=${row.user_id}`)}
                title="Generate an AI narrative of this operator's activity (saved as an AI Analysis session)"
                className="flex items-center gap-1 px-2 py-1 rounded-lg border border-violet-700/40 bg-violet-900/20 text-violet-300 hover:bg-violet-900/40 text-[11px]">
                <Sparkles className="h-3.5 w-3.5" /> AI summary
              </button>
            )}
            <button onClick={onClose} className="text-gray-500 hover:text-gray-200"><XCircle className="h-5 w-5" /></button>
          </div>
        </div>

        <div className="p-5 space-y-4 text-sm">
          <DetailRow label="When" value={`${safeFormat(row.created_at, 'yyyy-MM-dd HH:mm:ss')}  (${safeDistanceToNow(row.created_at)})`} />
          <DetailRow label="Operator" value={isSystemActor(row.user_email, row.user_id) ? SYSTEM_ACTOR : `${row.user_email}${row.user_name ? ` (${row.user_name})` : ''}  [${row.user_role || 'unknown'}]`} />
          <DetailRow label="Source IP" value={row.ip || '—'} mono onCopy={row.ip ? () => copy(row.ip) : undefined} />
          {row.forwarded && <DetailRow label="Forwarded chain" value={row.forwarded} mono hint="X-Forwarded-For — left-most is the real client" />}
          {row.user_agent && <DetailRow label="Client" value={row.user_agent} mono />}
          <DetailRow label="Target agent" value={row.agent_host ? `${row.agent_host}${row.agent_id ? `  (${row.agent_id})` : ''}` : '—'} mono />
          <DetailRow label={isSummaryRow ? 'Summarized user' : 'Resource'} value={row.resource || '—'} mono onCopy={row.resource ? () => copy(row.resource) : undefined} />

          {isSummaryRow && row.detail ? (
            // The stored AI narrative of what the summarized user did.
            <div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-1 flex items-center gap-1">
                <Sparkles className="h-3 w-3 text-violet-400" /> AI summary
              </div>
              <div className="rounded-lg border border-violet-800/30 bg-violet-950/10 p-3 text-sm text-gray-200 whitespace-pre-wrap leading-relaxed">
                {row.detail}
              </div>
            </div>
          ) : fields.length > 0 ? (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-1">Detail</div>
              <div className="rounded-lg border border-gray-800 divide-y divide-gray-800/60">
                {fields.map(([k, v], i) => (
                  <div key={i} className="flex gap-3 px-3 py-1.5 text-xs">
                    <span className="text-gray-500 shrink-0 w-32">{k}</span>
                    <span className="text-gray-200 font-mono break-all">{v}</span>
                  </div>
                ))}
              </div>
            </div>
          ) : row.detail ? (
            <DetailRow label="Detail" value={row.detail} mono />
          ) : null}
        </div>
      </div>
    </div>
  )
}

function DetailRow({ label, value, mono, hint, onCopy }: {
  label: string; value: string; mono?: boolean; hint?: string; onCopy?: () => void
}) {
  return (
    <div className="flex gap-3">
      <span className="text-gray-500 shrink-0 w-28 text-xs pt-0.5">{label}</span>
      <div className="min-w-0 flex-1">
        <div className="flex items-start gap-2">
          <span className={`text-gray-200 break-all ${mono ? 'font-mono text-xs' : ''}`}>{value}</span>
          {onCopy && <button onClick={onCopy} className="text-gray-600 hover:text-gray-300 shrink-0 text-[10px] border border-gray-700 rounded px-1">copy</button>}
        </div>
        {hint && <div className="text-[10px] text-gray-600 mt-0.5">{hint}</div>}
      </div>
    </div>
  )
}

// parseDetailPairs turns "a=1 b=two words c=3" into [[a,1],[b,two words],[c,3]].
// The handlers write detail as space-separated key=value, but values can contain
// spaces (a command line, a path), so a token only starts a new field when it
// looks like key=…; everything else appends to the current value.
function parseDetailPairs(detail: string): Array<[string, string]> {
  const s = (detail || '').trim()
  if (!s || !/\w+=/.test(s)) return []
  const out: Array<[string, string]> = []
  for (const tok of s.split(' ')) {
    const m = tok.match(/^([a-z_]{2,}[a-z0-9_]*)=(.*)$/i)
    if (m) {
      out.push([m[1], m[2]])
    } else if (out.length > 0) {
      out[out.length - 1][1] += ' ' + tok
    }
  }
  return out
}

// ──────────────────────────────────────────────────────────────────────────────
// Page
// ──────────────────────────────────────────────────────────────────────────────

type Tab = 'by-user' | 'log'

export default function UserActivityPage() {
  const { user } = useAuthStore()
  const [tab, setTab] = useState<Tab>('by-user')
  // Set when a user card is clicked — pre-filters the log view to that user.
  const [logUserId, setLogUserId] = useState<string | null | undefined>(undefined)

  // Client-side gate for a clean UX only — the backend already 403s non-admins,
  // so this is presentation, not the security boundary.
  if (user?.role !== 'admin') {
    return (
      <div className="space-y-5">
        <div>
          <h1 className="text-lg font-bold text-gray-100 flex items-center gap-2">
            <ShieldCheck className="h-5 w-5 text-emerald-400" /> User Activity
          </h1>
        </div>
        <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-5 py-12 text-center">
          <ShieldCheck className="h-10 w-10 text-gray-700 mx-auto mb-3" />
          <p className="text-sm text-gray-300 font-medium">Restricted to administrators</p>
          <p className="text-xs text-gray-600 mt-1">The audit trail is only visible to admin accounts.</p>
        </div>
      </div>
    )
  }

  const pickUser = (userId: string | null, _email: string) => {
    setLogUserId(userId)
    setTab('log')
  }

  const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
    { id: 'by-user', label: 'By user', icon: Users },
    { id: 'log', label: 'Activity log', icon: ScrollText },
  ]

  return (
    <div className="space-y-5">
      {/* Header */}
      <div>
        <h1 className="text-lg font-bold text-gray-100 flex items-center gap-2">
          <ShieldCheck className="h-5 w-5 text-emerald-400" /> User Activity
        </h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Every action is recorded with the operator, time, source IP, and target — this is the record of who accessed what.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800/60">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 -mb-px transition-colors ${
              tab === id ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-gray-700'
            }`}
          >
            <Icon className="h-4 w-4" /> {label}
          </button>
        ))}
      </div>

      {tab === 'by-user' && <ByUserView onPickUser={pickUser} />}
      {/* key forces a fresh mount when the pre-filter user changes, so the
          filter state initializes to the picked user. */}
      {tab === 'log' && <ActivityLogView key={String(logUserId)} initialUserId={logUserId} />}
    </div>
  )
}
