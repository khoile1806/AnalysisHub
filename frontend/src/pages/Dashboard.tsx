import { useMemo, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Server, ClipboardList, ShieldAlert, Bug, ArrowRight, ArrowUpRight,
  LayoutDashboard, Plus, Settings2, Trash2, X, Shield, Lock, Activity,
  Crosshair, Network, Cpu, BookOpen, Briefcase,
} from 'lucide-react'
import { safeDistanceToNow } from '@/lib/utils'
import { agentsApi } from '@/api/agents'
import { jobsApi } from '@/api/jobs'
import { cveCollectionApi } from '@/api/cve_collection'
import { openctiApi } from '@/api/opencti'
import { casesApi } from '@/api/cases'
import { elkResultsApi } from '@/api/analysis'
import {
  dashboardUsecasesApi, parseWidgets, WIDGET_CATALOG, USECASE_ICONS, USECASE_COLORS,
  type DashboardUsecase, type UpsertUsecase,
} from '@/api/dashboard_usecases'
import { JobStatusBadge } from '@/components/StatusBadge'
import toast from 'react-hot-toast'
import { getErrorMessage } from '@/lib/utils'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'

const ICONS: Record<string, React.ElementType> = {
  Shield, Lock, Activity, Crosshair, Network, Bug, ShieldAlert, Cpu,
}

const COLORS: Record<string, { text: string; bg: string; border: string; active: string }> = {
  emerald: { text: 'text-emerald-400', bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', active: 'border-emerald-500 text-emerald-400' },
  rose:    { text: 'text-rose-400',    bg: 'bg-rose-500/10',    border: 'border-rose-500/30',    active: 'border-rose-500 text-rose-400' },
  sky:     { text: 'text-sky-400',     bg: 'bg-sky-500/10',     border: 'border-sky-500/30',     active: 'border-sky-500 text-sky-400' },
  amber:   { text: 'text-amber-400',   bg: 'bg-amber-500/10',   border: 'border-amber-500/30',   active: 'border-amber-500 text-amber-400' },
  violet:  { text: 'text-violet-400',  bg: 'bg-violet-500/10',  border: 'border-violet-500/30',  active: 'border-violet-500 text-violet-400' },
  cyan:    { text: 'text-cyan-400',    bg: 'bg-cyan-500/10',    border: 'border-cyan-500/30',    active: 'border-cyan-500 text-cyan-400' },
}

function ucColor(c: string) { return COLORS[c] ?? COLORS.sky }
function ucIcon(name: string) { return ICONS[name] ?? Activity }

interface StatCardProps {
  label: string; value: number | string; sub?: string
  icon: React.ElementType; color: string; loading: boolean
}

function StatCard({ label, value, sub, icon: Icon, color, loading }: StatCardProps) {
  return (
    <div className="card p-5 flex items-start justify-between">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-gray-400 mb-1 truncate">{label}</p>
        {loading ? <div className="skeleton h-8 w-16 rounded" /> : (
          <div className="flex items-baseline gap-2">
            <p className="text-2xl font-bold text-gray-100">{value}</p>
            {sub && <span className="text-[10px] text-gray-500 font-medium truncate">{sub}</span>}
          </div>
        )}
      </div>
      <div className={`flex h-10 w-10 items-center justify-center rounded-lg shrink-0 ${color}`}>
        <Icon className="h-5 w-5" />
      </div>
    </div>
  )
}

// Minimal playbook renderer: headings (##), bold (**…**), paragraphs.
function Playbook({ text }: { text: string }) {
  if (!text.trim()) return <p className="text-xs text-gray-500">No playbook notes.</p>
  return (
    <div className="text-sm text-gray-300 leading-relaxed max-h-[600px] overflow-y-auto pr-2 custom-scrollbar">
      <ReactMarkdown 
        remarkPlugins={[remarkGfm]}
        components={{
          h1: ({node, ...props}) => <h1 className="text-xl font-bold text-gray-100 mt-6 mb-3 pb-2 border-b border-gray-800" {...props} />,
          h2: ({node, ...props}) => <h2 className="text-lg font-bold text-emerald-400 mt-5 mb-2" {...props} />,
          h3: ({node, ...props}) => <h3 className="text-base font-semibold text-gray-200 mt-4 mb-2" {...props} />,
          h4: ({node, ...props}) => <h4 className="text-sm font-semibold text-gray-300 mt-3 mb-1" {...props} />,
          p: ({node, ...props}) => <p className="mb-3 text-gray-400" {...props} />,
          ul: ({node, ...props}) => <ul className="list-disc list-inside mb-4 space-y-1 text-gray-400" {...props} />,
          ol: ({node, ...props}) => <ol className="list-decimal list-inside mb-4 space-y-1 text-gray-400" {...props} />,
          li: ({node, ...props}) => <li className="text-sm" {...props} />,
          strong: ({node, ...props}) => <strong className="font-semibold text-gray-200" {...props} />,
          a: ({node, ...props}) => <a className="text-blue-400 hover:text-blue-300 underline underline-offset-2" target="_blank" rel="noreferrer" {...props} />,
          code: ({node, inline, className, children, ...props}: any) => {
            return !inline ? (
              <pre className="bg-[#1c2030] p-3 rounded-lg overflow-x-auto text-xs font-mono text-gray-300 border border-gray-800 mb-4"><code className={className} {...props}>{children}</code></pre>
            ) : (
              <code className="bg-gray-800 text-gray-200 px-1.5 py-0.5 rounded text-xs font-mono" {...props}>{children}</code>
            )
          }
        }}
      >
        {text}
      </ReactMarkdown>
    </div>
  )
}

// ── Manage usecase modal ────────────────────────────────────────────────────
function UsecaseModal({ usecase, onClose }: { usecase: DashboardUsecase | null; onClose: () => void }) {
  const qc = useQueryClient()
  const editing = !!usecase
  const [form, setForm] = useState<UpsertUsecase>({
    name: usecase?.name ?? '',
    incident_type: usecase?.incident_type ?? 'custom',
    description: usecase?.description ?? '',
    icon: usecase?.icon ?? 'Activity',
    color: usecase?.color ?? 'sky',
    playbook: usecase?.playbook ?? '',
  })
  const [widgets, setWidgets] = useState<string[]>(
    usecase ? parseWidgets(usecase.widgets) : ['agents-stat', 'jobs-stat', 'recent-jobs', 'playbook'],
  )

  const toggleWidget = (k: string) =>
    setWidgets((prev) => prev.includes(k) ? prev.filter((w) => w !== k) : [...prev, k])

  const saveMut = useMutation({
    mutationFn: () => {
      const payload = { ...form, widgets: JSON.stringify(widgets) }
      return editing
        ? dashboardUsecasesApi.update(usecase!.id, payload)
        : dashboardUsecasesApi.create(payload)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dashboard-usecases'] })
      toast.success(editing ? 'Usecase updated' : 'Usecase created')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const delMut = useMutation({
    mutationFn: () => dashboardUsecasesApi.remove(usecase!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['dashboard-usecases'] })
      toast.success('Usecase deleted')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="fixed inset-0 z-50 bg-black/70 backdrop-blur-sm flex items-center justify-center p-4" onClick={onClose}>
      <div className="bg-gray-900 border border-gray-700 rounded-xl shadow-2xl w-full max-w-2xl max-h-[90vh] overflow-y-auto" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center justify-between p-5 border-b border-gray-800">
          <h3 className="font-semibold text-gray-100">{editing ? 'Edit usecase' : 'New usecase'}</h3>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
        </div>
        <div className="p-5 space-y-4">
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label text-xs">Name *</label>
              <input className="input" value={form.name} onChange={(e) => setForm({ ...form, name: e.target.value })} placeholder="e.g. Phishing Incident" />
            </div>
            <div>
              <label className="label text-xs">Incident type</label>
              <input className="input" value={form.incident_type} onChange={(e) => setForm({ ...form, incident_type: e.target.value })} placeholder="webshell / ransomware / custom" />
            </div>
          </div>
          <div>
            <label className="label text-xs">Description</label>
            <input className="input" value={form.description} onChange={(e) => setForm({ ...form, description: e.target.value })} />
          </div>
          <div className="grid grid-cols-2 gap-3">
            <div>
              <label className="label text-xs">Icon</label>
              <div className="flex gap-1.5 flex-wrap">
                {USECASE_ICONS.map((ic) => {
                  const I = ucIcon(ic)
                  return (
                    <button key={ic} onClick={() => setForm({ ...form, icon: ic })}
                      className={`p-2 rounded border ${form.icon === ic ? 'border-emerald-500 bg-emerald-500/10 text-emerald-400' : 'border-gray-700 text-gray-400'}`}>
                      <I className="h-4 w-4" />
                    </button>
                  )
                })}
              </div>
            </div>
            <div>
              <label className="label text-xs">Color</label>
              <div className="flex gap-1.5 flex-wrap">
                {USECASE_COLORS.map((cl) => (
                  <button key={cl} onClick={() => setForm({ ...form, color: cl })}
                    className={`h-8 w-8 rounded border ${ucColor(cl).bg} ${form.color === cl ? 'ring-2 ring-offset-2 ring-offset-gray-900 ' + ucColor(cl).text.replace('text', 'ring') : 'border-gray-700'}`} />
                ))}
              </div>
            </div>
          </div>
          <div>
            <label className="label text-xs">Widgets</label>
            <div className="grid grid-cols-2 gap-1.5">
              {WIDGET_CATALOG.map((w) => (
                <label key={w.key} className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer p-1.5 rounded hover:bg-gray-800">
                  <input type="checkbox" checked={widgets.includes(w.key)} onChange={() => toggleWidget(w.key)} className="accent-emerald-500" />
                  {w.label}
                </label>
              ))}
            </div>
          </div>
          <div>
            <label className="label text-xs">Playbook (markdown: ## heading, **bold**)</label>
            <textarea className="input min-h-[120px] font-mono text-xs" value={form.playbook} onChange={(e) => setForm({ ...form, playbook: e.target.value })} />
          </div>
        </div>
        <div className="flex items-center justify-between p-5 border-t border-gray-800">
          {editing ? (
            <button onClick={() => { if (confirm('Delete this usecase?')) delMut.mutate() }} className="text-xs text-red-400 hover:text-red-300 flex items-center gap-1">
              <Trash2 className="h-3.5 w-3.5" /> Delete
            </button>
          ) : <span />}
          <div className="flex gap-2">
            <button className="btn-secondary" onClick={onClose}>Cancel</button>
            <button className="btn-primary" disabled={!form.name || saveMut.isPending} onClick={() => saveMut.mutate()}>
              {saveMut.isPending ? 'Saving…' : 'Save'}
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────────
export default function DashboardPage() {
  const [activeSlug, setActiveSlug] = useState<string>('overview')
  const [modalUsecase, setModalUsecase] = useState<DashboardUsecase | null>(null)
  const [modalOpen, setModalOpen] = useState(false)

  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: () => agentsApi.list(), refetchInterval: 20_000 })
  const jobsQ   = useQuery({ queryKey: ['jobs'],   queryFn: () => jobsApi.list(),   refetchInterval: 20_000 })
  const cvesQ   = useQuery({ queryKey: ['cve-coll'], queryFn: () => cveCollectionApi.getAll() })
  const iocsQ   = useQuery({ queryKey: ['iocs'],   queryFn: () => openctiApi.listIOCs() })
  const casesQ  = useQuery({ queryKey: ['cases'],  queryFn: () => casesApi.list() })
  const elkQ    = useQuery({ queryKey: ['elk-hunt-results'], queryFn: elkResultsApi.list })
  const usecasesQ = useQuery({ queryKey: ['dashboard-usecases'], queryFn: dashboardUsecasesApi.list })

  const agents = agentsQ.data ?? []
  const jobs   = jobsQ.data   ?? []
  const cves   = cvesQ.data   ?? []
  const iocs   = iocsQ.data   ?? []
  const cases  = casesQ.data  ?? []
  const elkResults = elkQ.data ?? []
  const usecases = usecasesQ.data ?? []

  const onlineAgents = useMemo(() => agents.filter((a) => a.status === 'online'), [agents])
  const kevCves      = useMemo(() => cves.filter((c) => c.is_kev), [cves])
  const openCases    = useMemo(() => cases.filter((c) => c.status === 'open'), [cases])
  const recentJobs   = jobs.slice(0, 6)

  const activeUsecase = usecases.find((u) => u.slug === activeSlug) ?? null
  const enabledWidgets = activeUsecase ? parseWidgets(activeUsecase.widgets) : null
  const show = (key: string) => !enabledWidgets || enabledWidgets.includes(key)

  // Widget render blocks ------------------------------------------------------
  const statCards = (
    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
      {show('agents-stat') && (
        <Link to="/agents"><StatCard label="Agents · online" value={onlineAgents.length}
          sub={`/ ${agents.length} total`} icon={Server}
          color="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" loading={agentsQ.isLoading} /></Link>
      )}
      {show('jobs-stat') && (
        <Link to="/jobs"><StatCard label="Jobs" value={jobs.length} icon={ClipboardList}
          color="bg-blue-500/10 text-blue-400 border border-blue-500/30" loading={jobsQ.isLoading} /></Link>
      )}
      {show('cves-stat') && (
        <Link to="/cve-collection"><StatCard label="CVEs · KEV" value={kevCves.length}
          sub={`/ ${cves.length} collected`} icon={Bug}
          color="bg-amber-500/10 text-amber-400 border border-amber-500/30" loading={cvesQ.isLoading} /></Link>
      )}
      {show('iocs-stat') && (
        <Link to="/opencti"><StatCard label="IOCs" value={iocs.length} icon={ShieldAlert}
          color="bg-purple-500/10 text-purple-400 border border-purple-500/30" loading={iocsQ.isLoading} /></Link>
      )}
    </div>
  )

  const hasStat = show('agents-stat') || show('jobs-stat') || show('cves-stat') || show('iocs-stat')

  return (
    <div className="space-y-6">
      <div className="flex items-start justify-between gap-4">
        <div>
          <h1 className="text-2xl font-bold text-gray-100">
            {activeUsecase ? activeUsecase.name : 'DFIR Overview'}
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            {activeUsecase ? (activeUsecase.description || 'Incident-specific view') : 'Forensic & Hunting platform · live tally.'}
          </p>
        </div>
        <button onClick={() => { setModalUsecase(null); setModalOpen(true) }}
          className="btn-secondary text-xs shrink-0">
          <Plus className="h-3.5 w-3.5" /> New usecase
        </button>
      </div>

      {/* Usecase tab bar */}
      <div className="flex items-center gap-1 border-b border-gray-800 overflow-x-auto">
        <button onClick={() => setActiveSlug('overview')}
          className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px flex items-center gap-2 whitespace-nowrap transition ${
            activeSlug === 'overview' ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-gray-400 hover:text-gray-200'
          }`}>
          <LayoutDashboard className="h-4 w-4" /> Overview
        </button>
        {usecases.map((u) => {
          const I = ucIcon(u.icon)
          const col = ucColor(u.color)
          const active = activeSlug === u.slug
          return (
            <button key={u.id} onClick={() => setActiveSlug(u.slug)}
              className={`px-4 py-2 text-sm font-medium border-b-2 -mb-px flex items-center gap-2 whitespace-nowrap transition group ${
                active ? col.active : 'border-transparent text-gray-400 hover:text-gray-200'
              }`}>
              <I className="h-4 w-4" /> {u.name}
              {active && (
                <span onClick={(e) => { e.stopPropagation(); setModalUsecase(u); setModalOpen(true) }}
                  className="ml-1 text-gray-500 hover:text-gray-200" title="Edit usecase">
                  <Settings2 className="h-3.5 w-3.5" />
                </span>
              )}
            </button>
          )
        })}
      </div>

      {hasStat && statCards}

      {/* Playbook panel (usecase only) */}
      {activeUsecase && show('playbook') && (
        <section className="card p-4">
          <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-200 mb-3">
            <BookOpen className={`h-4 w-4 ${ucColor(activeUsecase.color).text}`} /> Playbook
          </h2>
          <Playbook text={activeUsecase.playbook} />
        </section>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {show('recent-jobs') && (
          <section className="card p-4">
            <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
              <span>Recent jobs</span>
              <Link to="/jobs" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
            </h2>
            {recentJobs.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No jobs yet</div> : (
              <ul className="space-y-2">
                {recentJobs.map((j) => (
                  <li key={j.id}>
                    <Link to={`/jobs/${j.id}`} className="flex items-center justify-between text-xs p-2 rounded hover:bg-gray-800/60">
                      <span className="truncate text-gray-300">{j.tool?.name ?? j.id.slice(0, 8)}</span>
                      <div className="flex items-center gap-3 shrink-0">
                        <JobStatusBadge status={j.status} />
                        <span className="text-[10px] text-gray-500">{j.created_at && safeDistanceToNow(j.created_at, { addSuffix: true })}</span>
                      </div>
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {show('kev-cves') && (
          <section className="card p-4">
            <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
              <span>KEV CVEs</span>
              <Link to="/cve-collection" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
            </h2>
            {kevCves.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No KEV-flagged CVEs</div> : (
              <ul className="space-y-2">
                {kevCves.slice(0, 6).map((c) => (
                  <li key={c.id} className="text-xs p-2 rounded hover:bg-gray-800/60">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-gray-200">{c.id}</span>
                      <span className="text-[10px] text-amber-400">KEV</span>
                    </div>
                    {c.description && <div className="text-gray-500 text-[11px] mt-0.5 line-clamp-1">{c.description}</div>}
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {show('iocs-list') && (
          <section className="card p-4">
            <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
              <span>Recent IOCs</span>
              <Link to="/opencti" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
            </h2>
            {iocs.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No IOCs</div> : (
              <ul className="space-y-2">
                {iocs.slice(0, 6).map((ioc: any) => (
                  <li key={ioc.id} className="text-xs p-2 rounded hover:bg-gray-800/60 flex items-center justify-between">
                    <span className="font-mono text-gray-300 truncate">{ioc.value}</span>
                    <span className="text-[10px] text-purple-400 shrink-0 ml-2">{ioc.type}</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {show('elk-results') && (
          <section className="card p-4">
            <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
              <span>ELK hunt results</span>
              <Link to="/opencti" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
            </h2>
            {elkResults.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No hunt results</div> : (
              <ul className="space-y-2">
                {elkResults.slice(0, 6).map((r) => (
                  <li key={r.id} className="text-xs p-2 rounded hover:bg-gray-800/60 flex items-center justify-between">
                    <span className="text-gray-300 truncate">{r.title}</span>
                    <span className="text-[10px] text-sky-400 shrink-0 ml-2">{r.total_hits} hits</span>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}

        {show('open-cases') && (
          <section className="card p-4">
            <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
              <span>Open cases</span>
              <Link to="/cases" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
            </h2>
            {openCases.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No open cases</div> : (
              <ul className="space-y-2">
                {openCases.slice(0, 6).map((cs) => (
                  <li key={cs.id}>
                    <Link to={`/cases/${cs.id}`} className="flex items-center justify-between text-xs p-2 rounded hover:bg-gray-800/60">
                      <span className="truncate text-gray-300 flex items-center gap-1.5"><Briefcase className="h-3 w-3 text-gray-500" />{cs.name}</span>
                      <ArrowUpRight className="h-3 w-3 text-gray-600 shrink-0" />
                    </Link>
                  </li>
                ))}
              </ul>
            )}
          </section>
        )}
      </div>

      {modalOpen && <UsecaseModal usecase={modalUsecase} onClose={() => setModalOpen(false)} />}
    </div>
  )
}
