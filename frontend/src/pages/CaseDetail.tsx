import { useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { casesApi } from '@/api/cases'
import { toolsApi } from '@/api/tools'
import { generateOfflineBundle } from '@/api/offline_bundles'
import {
  Briefcase, Activity, Server, ChevronRight, User, Wrench,
  ClipboardList, Lock, Unlock, Package, Monitor, Terminal,
  Globe, CheckSquare, Square, Download, BrainCircuit, Crosshair, ShieldCheck,
  Fingerprint, FileText, Sparkles, Loader2,
} from 'lucide-react'
import { analysisApi } from '@/api/analysis'
import AttackTimeline from '@/components/AttackTimeline'
import AttackCoverage from '@/components/AttackCoverage'
import ComplianceAssessment from '@/components/ComplianceAssessment'
import { AgentStatusBadge, JobStatusBadge } from '@/components/StatusBadge'
import { CategoryBadge, PlatformBadge } from '@/components/StatusBadge'
import { formatBytes } from '@/lib/utils'
import toast from 'react-hot-toast'
import { getErrorMessage, safeFormat } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogBody,
} from '@/components/ui/dialog'

type BundlePlatform = 'windows' | 'linux' | 'both'

const PLATFORM_OPTIONS: { value: BundlePlatform; label: string; icon: React.ReactNode }[] = [
  { value: 'windows', label: 'Windows', icon: <Monitor className="w-3.5 h-3.5" /> },
  { value: 'linux',   label: 'Linux',   icon: <Terminal className="w-3.5 h-3.5" /> },
  { value: 'both',    label: 'Both',    icon: <Globe className="w-3.5 h-3.5" /> },
]

// ── Offline Bundle Modal ───────────────────────────────────────────────────
function OfflineBundleModal({
  open, onClose, caseId, caseName,
}: {
  open: boolean
  onClose: () => void
  caseId: string
  caseName: string
}) {
  const [platform, setPlatform] = useState<BundlePlatform>('windows')
  const [selectedIDs, setSelectedIDs] = useState<Set<string>>(new Set())
  const [generating, setGenerating] = useState(false)

  const { data: tools = [] } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list(),
    enabled: open,
  })

  const toggleTool = (id: string) =>
    setSelectedIDs((prev) => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })

  const toggleAll = () =>
    setSelectedIDs(selectedIDs.size === tools.length ? new Set() : new Set(tools.map((t) => t.id)))

  const handleGenerate = async () => {
    if (selectedIDs.size === 0) { toast.error('Select at least one tool'); return }
    setGenerating(true)
    const tid = toast.loading('Generating bundle…')
    try {
      await generateOfflineBundle({
        name: `${caseName} — Offline Hunt`,
        tool_ids: Array.from(selectedIDs),
        platform,
        case_id: caseId,
        case_name: caseName,
      })
      toast.success('Bundle downloaded!', { id: tid })
      onClose()
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed', { id: tid })
    } finally {
      setGenerating(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Package className="w-4 h-4 text-purple-400" />
            Generate Offline Bundle
          </DialogTitle>
          <DialogDescription>
            Bundle selected tools for offline hunting on endpoints related to{' '}
            <span className="text-purple-300 font-medium">{caseName}</span>.
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-4">
          {/* Platform */}
          <div>
            <label className="label mb-2">Target Platform</label>
            <div className="flex gap-2">
              {PLATFORM_OPTIONS.map((opt) => (
                <button
                  key={opt.value}
                  onClick={() => setPlatform(opt.value)}
                  className={`flex items-center gap-1.5 px-3 py-2 rounded-lg border text-sm transition-colors flex-1 justify-center font-medium ${
                    platform === opt.value
                      ? 'border-purple-500/60 bg-purple-500/10 text-purple-300'
                      : 'border-border bg-card text-muted-foreground hover:text-foreground'
                  }`}
                >
                  {opt.icon}
                  {opt.label}
                </button>
              ))}
            </div>
          </div>

          {/* Tool selector */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="label">Select Tools</label>
              <button
                onClick={toggleAll}
                className="flex items-center gap-1 text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {selectedIDs.size === tools.length && tools.length > 0
                  ? <><CheckSquare className="w-3.5 h-3.5" /> Deselect all</>
                  : <><Square className="w-3.5 h-3.5" /> Select all</>}
              </button>
            </div>
            <div className="border border-border rounded-lg overflow-hidden max-h-64 overflow-y-auto">
              {tools.length === 0 ? (
                <div className="p-6 text-center text-sm text-muted-foreground">
                  No tools found. Upload tools first.
                </div>
              ) : (
                tools.map((tool, i) => {
                  const selected = selectedIDs.has(tool.id)
                  return (
                    <div
                      key={tool.id}
                      onClick={() => toggleTool(tool.id)}
                      className={`flex items-center gap-3 px-3 py-2.5 cursor-pointer transition-colors ${
                        i > 0 ? 'border-t border-border' : ''
                      } ${selected ? 'bg-purple-500/5' : 'hover:bg-gray-800/50'}`}
                    >
                      <div className={`w-4 h-4 rounded border flex-shrink-0 flex items-center justify-center transition-colors ${
                        selected ? 'bg-purple-500 border-purple-500' : 'border-muted-foreground/40'
                      }`}>
                        {selected && (
                          <svg className="w-2.5 h-2.5 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <span className="font-medium text-sm text-foreground flex-1">{tool.name}</span>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <CategoryBadge category={tool.category} />
                        <PlatformBadge platform={tool.platform} />
                        {tool.file_size > 0 && (
                          <span className="text-xs text-muted-foreground">{formatBytes(tool.file_size)}</span>
                        )}
                      </div>
                    </div>
                  )
                })
              )}
            </div>
            {selectedIDs.size > 0 && (
              <p className="text-xs text-muted-foreground mt-1.5">
                {selectedIDs.size} tool{selectedIDs.size > 1 ? 's' : ''} selected
              </p>
            )}
          </div>

          {/* Info */}
          <div className="flex gap-2 bg-blue-500/5 border border-blue-500/20 rounded-lg p-3 text-xs text-blue-300/80 leading-relaxed">
            <Package className="w-3.5 h-3.5 flex-shrink-0 mt-0.5 text-blue-400" />
            <span>
              Bundle will be tagged with case <strong>{caseName}</strong> — visible in the offline report.
              No internet connection required on the target machine.
            </span>
          </div>
        </DialogBody>

        <DialogFooter>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn-primary flex items-center gap-2 disabled:opacity-40 disabled:cursor-not-allowed"
            style={{ background: '#7c3aed' }}
            onClick={handleGenerate}
            disabled={generating || selectedIDs.size === 0}
          >
            {generating ? (
              <>
                <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                </svg>
                Generating…
              </>
            ) : (
              <>
                <Download className="w-4 h-4" />
                Download Bundle
              </>
            )}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ── CaseDetail page ────────────────────────────────────────────────────────
type TabKey = 'timeline' | 'attack' | 'jobs' | 'compliance' | 'osint' | 'offline'

// ReportActions — open the self-contained incident report (HTML→PDF) and,
// optionally, have an AI provider draft the executive narrative into it first.
function ReportActions({ caseId }: { caseId: string }) {
  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })
  const active = providers.filter((p) => p.is_active)
  const aiMut = useMutation({
    mutationFn: () => casesApi.generateAiSummary(caseId, active[0].id),
    onSuccess: () => toast.success('AI summary saved — it now appears in the report'),
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  return (
    <>
      {active.length > 0 && (
        <button
          onClick={() => aiMut.mutate()}
          disabled={aiMut.isPending}
          title="Draft an AI executive summary into the incident report"
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border bg-gray-800 hover:bg-gray-700 text-gray-300 border-gray-700 hover:text-emerald-400 hover:border-emerald-500/40 transition disabled:opacity-50"
        >
          {aiMut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Sparkles className="h-3 w-3" />} AI Summary
        </button>
      )}
      <a
        href={casesApi.reportUrl(caseId)}
        target="_blank" rel="noopener noreferrer"
        title="Open the full incident report (print to PDF from the browser)"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border bg-gray-800 hover:bg-gray-700 text-gray-300 border-gray-700 hover:text-emerald-400 hover:border-emerald-500/40 transition"
      >
        <FileText className="h-3 w-3" /> Incident Report
      </a>
      <a
        href={casesApi.reportUrl(caseId, 'pdf')}
        target="_blank" rel="noopener noreferrer"
        title="Download as PDF (requires PDF renderer; falls back to HTML otherwise)"
        className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border bg-gray-800 hover:bg-gray-700 text-gray-300 border-gray-700 hover:text-emerald-400 hover:border-emerald-500/40 transition"
      >
        <Download className="h-3 w-3" /> PDF
      </a>
    </>
  )
}

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState<TabKey>('timeline')
  const [bundleModalOpen, setBundleModalOpen] = useState(false)

  const { data, isLoading } = useQuery({
    queryKey: ['case-summary', id],
    queryFn: () => casesApi.getSummary(id!),
    enabled: !!id,
    refetchInterval: 3000,
  })

  const toggleStatusMutation = useMutation({
    mutationFn: (newStatus: 'open' | 'closed') =>
      casesApi.update(id!, { status: newStatus }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['case-summary', id] })
      qc.invalidateQueries({ queryKey: ['cases'] })
      toast.success(`Case ${updated.status === 'open' ? 'reopened' : 'closed'}`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const importMutation = useMutation({
    mutationFn: (file: File) => casesApi.importOfflineReport(id!, file),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['case-summary', id] })
      toast.success(`Imported ${res.imported_jobs} tool result(s) from ${res.hostname}`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  if (isLoading) {
    return (
      <div className="p-10 text-center">
        <div className="skeleton h-8 w-64 mx-auto rounded mb-4" />
        <div className="skeleton h-32 w-full max-w-4xl mx-auto rounded" />
      </div>
    )
  }

  if (!data) return <div className="p-10 text-center text-red-400">Case not found</div>

  const { case: caseObj, agents, deployments, jobs, checklist_runs, osint } = data

  const activities: any[] = []
  if (deployments) {
    deployments.forEach((d: any) =>
      activities.push({ ...d, _type: 'deployment', _time: new Date(d.created_at).getTime() })
    )
  }
  if (jobs) {
    jobs.forEach((j: any) =>
      activities.push({ ...j, _type: 'job', _time: new Date(j.created_at).getTime() })
    )
  }
  if (checklist_runs) {
    checklist_runs.forEach((r: any) =>
      activities.push({ ...r, _type: 'checklist', _time: new Date(r.created_at).getTime() })
    )
  }
  activities.sort((a, b) => b._time - a._time)

  const isOpen = caseObj.status === 'open'

  const TABS: { key: TabKey; label: string; icon: typeof Activity }[] = [
    { key: 'timeline',   label: 'Activity Timeline', icon: Activity },
    { key: 'attack',     label: 'Attack Timeline',   icon: Crosshair },
    { key: 'jobs',       label: 'Hunting Results',   icon: ClipboardList },
    { key: 'compliance', label: 'Compliance',        icon: ShieldCheck },
    { key: 'osint',      label: 'OSINT',             icon: Fingerprint },
    { key: 'offline',    label: 'Offline Bundle',    icon: Package },
  ]

  return (
    <div className="space-y-6 w-full">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs text-gray-500 mb-2">
            <Link to="/cases" className="hover:text-emerald-400 flex items-center gap-1">
              <Briefcase className="h-3.5 w-3.5" /> Cases
            </Link>
            <ChevronRight className="h-3 w-3" />
            <span className="text-gray-300 font-mono">{caseObj.id.split('-')[0]}</span>
          </div>
          <h1 className="text-2xl font-bold text-gray-100">{caseObj.name}</h1>
          <p className="text-sm text-gray-400 mt-1">{caseObj.description || 'No description'}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <ReportActions caseId={caseObj.id} />
          <span
            className={`text-xs uppercase font-bold px-3 py-1 rounded-full ${
              isOpen ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-300'
            }`}
          >
            {caseObj.status}
          </span>
          <button
            onClick={() => toggleStatusMutation.mutate(isOpen ? 'closed' : 'open')}
            disabled={toggleStatusMutation.isPending}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border transition disabled:opacity-50 ${
              isOpen
                ? 'bg-gray-800 hover:bg-gray-700 text-gray-300 border-gray-700 hover:text-red-400 hover:border-red-500/40'
                : 'bg-emerald-900/30 hover:bg-emerald-900/50 text-emerald-400 border-emerald-500/30'
            }`}
          >
            {isOpen ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
            {isOpen ? 'Close Case' : 'Reopen'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6">
        {/* Agents List */}
        <div className="col-span-1 space-y-4">
          <h3 className="font-semibold text-gray-200 flex items-center gap-2">
            <Server className="h-4 w-4 text-emerald-400" />
            Associated Agents
          </h3>
          <div className="card divide-y divide-gray-800/60">
            {agents && agents.length > 0 ? (
              agents.map((a: any) => (
                <div key={a.id} className="p-4 flex items-center justify-between">
                  <div>
                    <Link
                      to={`/agents/${a.id}`}
                      className="font-medium text-sm text-gray-200 hover:text-emerald-400"
                    >
                      {a.name}
                    </Link>
                    <div className="text-xs text-gray-500 font-mono">{a.ip_address}</div>
                  </div>
                  <AgentStatusBadge status={a.status} />
                </div>
              ))
            ) : (
              <div className="p-6 text-center text-sm text-gray-500">
                No agents linked to this case.
              </div>
            )}
          </div>
        </div>

        {/* Main Content */}
        <div className="col-span-1 lg:col-span-3 space-y-4">
          <div className="flex items-center gap-1 border-b border-gray-800">
            {TABS.map((t) => (
              <button
                key={t.key}
                onClick={() => setTab(t.key)}
                className={`px-4 py-2 text-sm font-medium transition flex items-center gap-2 border-b-2 -mb-px ${
                  tab === t.key
                    ? t.key === 'offline'
                      ? 'border-purple-500 text-purple-400'
                      : t.key === 'attack'
                        ? 'border-rose-500 text-rose-400'
                        : t.key === 'compliance'
                          ? 'border-amber-500 text-amber-400'
                          : 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                }`}
              >
                <t.icon className="h-4 w-4" />
                {t.label}
              </button>
            ))}
          </div>

          {/* Timeline tab */}
          {tab === 'timeline' && (
            <div className="card p-5">
              <div className="space-y-6 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-gray-800 before:to-transparent">
                {activities.length > 0 ? (
                  activities.map((act) => (
                    <div
                      key={act.id}
                      className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active"
                    >
                      <div className="flex items-center justify-center w-10 h-10 rounded-full border border-gray-800 bg-gray-900 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 text-emerald-400 relative z-10">
                        {act._type === 'deployment' ? (
                          <Activity className="h-4 w-4" />
                        ) : act._type === 'job' ? (
                          <Wrench className="h-4 w-4" />
                        ) : (
                          <ClipboardList className="h-4 w-4" />
                        )}
                      </div>
                      <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] card p-4 group-odd:text-right group-odd:items-end flex flex-col hover:border-emerald-500/30 transition-colors">
                        <div className="flex items-center gap-2 text-[10px] text-gray-500 font-mono mb-1">
                          <span>{safeFormat(act.created_at, 'MMM dd, HH:mm:ss')}</span>
                        </div>
                        <h4 className="font-semibold text-sm text-gray-200 mb-1">
                          {act._type === 'deployment' ? (
                            `Deployed ${act.scenario?.name || 'Scenario'}`
                          ) : act._type === 'job' ? (
                            <Link
                              to={`/jobs/${act.id}`}
                              className="hover:text-emerald-400 flex items-center gap-1 group-odd:justify-end transition-colors"
                            >
                              Executed {act.tool?.name || 'Tool'} <ChevronRight className="h-3 w-3" />
                            </Link>
                          ) : (
                            'Ran Evidence Checklist'
                          )}
                        </h4>
                        {act._type === 'job' && act.status && (
                          <div className="mt-1 mb-1">
                            <JobStatusBadge status={act.status} />
                          </div>
                        )}
                        <div className="text-xs text-gray-400 flex items-center gap-1.5 mt-1">
                          <Server className="h-3 w-3" />{' '}
                          {act.agent?.name ||
                            agents?.find((a: any) => a.id === act.agent_id)?.name ||
                            'Agent'}
                        </div>
                        <div className="text-[10px] text-emerald-400/80 flex items-center gap-1.5 mt-2 bg-emerald-950/30 px-2 py-1 rounded inline-flex">
                          <User className="h-3 w-3" />
                          {act.created_by_user?.name ||
                            act.created_by_user?.email ||
                            act.analyst ||
                            'System'}
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center text-sm text-gray-500 py-8 relative z-10">
                    No activities recorded yet.
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Attack Timeline tab */}
          {tab === 'attack' && (
            <div className="space-y-4">
              <AttackCoverage caseId={caseObj.id} />
              <AttackTimeline caseId={caseObj.id} agents={agents ?? []} />
            </div>
          )}

          {/* Compliance tab */}
          {tab === 'compliance' && (
            <ComplianceAssessment caseId={caseObj.id} checklistRuns={checklist_runs ?? []} agents={agents ?? []} />
          )}

          {/* OSINT tab */}
          {tab === 'osint' && (
            <div className="space-y-4">
              <div className="flex items-center gap-4 text-sm text-gray-400">
                <span className="flex items-center gap-1.5">
                  <Fingerprint className="h-4 w-4 text-emerald-400" />
                  {osint?.investigations?.length ?? 0} investigation(s)
                </span>
                <span>·</span>
                <span>{osint?.total_scans ?? 0} total scans (incl. auto-pivot)</span>
                <span>·</span>
                <span>{osint?.total_findings ?? 0} findings</span>
              </div>
              {osint && osint.investigations.length > 0 ? (
                <div className="space-y-2">
                  {osint.investigations.map((s) => (
                    <Link
                      key={s.id}
                      to={`/osint/${s.id}`}
                      className="card flex items-center gap-4 p-4 hover:border-emerald-700/50 transition-colors"
                    >
                      <Fingerprint className="h-4 w-4 text-gray-600 shrink-0" />
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-gray-100 truncate">{s.name}</div>
                        <div className="flex items-center gap-2 mt-0.5">
                          <span className="font-mono text-xs text-emerald-400">{s.target}</span>
                          <span className="text-[10px] font-mono text-gray-600 uppercase">{s.target_type}</span>
                        </div>
                      </div>
                      <span className="text-[10px] px-2 py-0.5 rounded-full font-mono uppercase bg-gray-800 text-gray-400 shrink-0">
                        {s.status}
                      </span>
                      <ChevronRight className="h-4 w-4 text-gray-600" />
                    </Link>
                  ))}
                </div>
              ) : (
                <div className="card flex flex-col items-center justify-center py-16 text-center gap-3">
                  <Fingerprint className="h-9 w-9 text-gray-700" />
                  <p className="text-gray-500 text-sm">No OSINT investigations filed under this case.</p>
                  <Link to="/osint" className="btn-secondary text-sm">Open OSINT Footprinting</Link>
                </div>
              )}
            </div>
          )}

          {/* Hunting Results tab */}
          {tab === 'jobs' && (
            <div className="space-y-4">
              {jobs && jobs.length > 0 ? (
                <div className="card overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-900/60 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                      <tr>
                        <th className="text-left py-3 px-4 font-medium">Job Tool</th>
                        <th className="text-left py-3 px-4 font-medium">Agent</th>
                        <th className="text-left py-3 px-4 font-medium">Status</th>
                        <th className="text-left py-3 px-4 font-medium">Time</th>
                        <th className="text-right py-3 px-4 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {jobs.map((j: any) => (
                        <tr key={j.id} className="hover:bg-gray-900/30 transition-colors">
                          <td className="py-3 px-4 font-medium text-gray-200">
                            {j.tool?.name || 'Unknown Tool'}
                          </td>
                          <td className="py-3 px-4 text-gray-400 text-xs">
                            <div className="flex items-center gap-1.5">
                              <Server className="h-3.5 w-3.5" />
                              {j.agent?.name ||
                                agents?.find((a: any) => a.id === j.agent_id)?.name ||
                                'Agent'}
                            </div>
                          </td>
                          <td className="py-3 px-4">
                            <JobStatusBadge status={j.status} />
                          </td>
                          <td className="py-3 px-4 text-xs text-gray-500 font-mono">
                            {safeFormat(j.created_at, 'MMM dd, HH:mm')}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <Link
                              to={`/jobs/${j.id}`}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-200 rounded transition border border-gray-700"
                            >
                              <Wrench className="h-3.5 w-3.5" /> View Result
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="card p-10 text-center flex flex-col items-center justify-center">
                  <Wrench className="h-10 w-10 text-gray-700 mb-3" />
                  <p className="text-gray-400 font-medium">No hunting jobs found</p>
                  <p className="text-xs text-gray-500 mt-1">
                    Deploy a scenario from the Hunting page and link it to this case.
                  </p>
                </div>
              )}
            </div>
          )}

          {/* Offline Bundle tab */}
          {tab === 'offline' && (
            <div className="space-y-4">
              <div className="card p-6 flex flex-col items-center text-center gap-4">
                <div className="w-14 h-14 rounded-full bg-purple-500/10 border border-purple-500/20 flex items-center justify-center">
                  <Package className="w-7 h-7 text-purple-400" />
                </div>
                <div>
                  <h3 className="font-semibold text-gray-200 text-base">Offline Hunting Bundle</h3>
                  <p className="text-sm text-gray-400 mt-1 max-w-sm">
                    Generate a self-contained bundle for endpoints that cannot reach the ForensicHub
                    server. The bundle includes selected tools, a local UI, and auto-generates a
                    report tagged to this case.
                  </p>
                </div>

                <div className="grid grid-cols-3 gap-3 w-full max-w-sm text-xs text-gray-400">
                  {[
                    { icon: <Monitor className="w-4 h-4 text-blue-400" />, text: 'Windows: browser UI' },
                    { icon: <Terminal className="w-4 h-4 text-green-400" />, text: 'Linux: CLI or browser' },
                    { icon: <Package className="w-4 h-4 text-purple-400" />, text: 'No internet needed' },
                  ].map((item, i) => (
                    <div key={i} className="flex flex-col items-center gap-1.5 p-3 bg-gray-900/40 rounded-lg border border-gray-800">
                      {item.icon}
                      <span>{item.text}</span>
                    </div>
                  ))}
                </div>

                <button
                  onClick={() => setBundleModalOpen(true)}
                  className="flex items-center gap-2 px-5 py-2.5 bg-purple-600 hover:bg-purple-500 text-white font-semibold rounded-lg transition text-sm"
                >
                  <Download className="w-4 h-4" />
                  Generate Bundle for this Case
                </button>
              </div>

              {/* Instructions */}
              <div className="card p-4 space-y-2 text-xs text-gray-400">
                <p className="font-semibold text-gray-300 text-sm">How to use</p>
                <ol className="space-y-1.5 list-decimal list-inside">
                  <li>Click <strong className="text-gray-200">Generate Bundle</strong> and select tools + platform</li>
                  <li>Transfer the ZIP to the target endpoint (USB, RDP, SCP)</li>
                  <li>
                    <strong className="text-gray-200">Windows:</strong> extract and run{' '}
                    <code className="bg-gray-800 px-1 rounded">run.bat</code> — browser opens automatically
                  </li>
                  <li>
                    <strong className="text-gray-200">Linux SSH:</strong> run{' '}
                    <code className="bg-gray-800 px-1 rounded">./agent-offline-linux --cli</code>
                  </li>
                  <li>
                    Run tools, then click <strong className="text-gray-200">Generate Report</strong> — saves{' '}
                    <code className="bg-gray-800 px-1 rounded">.html</code> +{' '}
                    <code className="bg-gray-800 px-1 rounded">.json</code> tagged with this case
                  </li>
                  <li>
                    Bring the <code className="bg-gray-800 px-1 rounded">.json</code> back and upload it to{' '}
                    <strong className="text-gray-200">AI Analysis</strong> for automated forensic review
                  </li>
                </ol>
              </div>

              {/* Import offline report */}
              <div className="card p-4">
                <div className="flex items-center gap-3 mb-3">
                  <div className="w-9 h-9 rounded-lg bg-emerald-500/10 border border-emerald-500/20 flex items-center justify-center flex-shrink-0">
                    <Download className="w-4 h-4 text-emerald-400 rotate-180" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-200">Import Offline Report</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      Upload <code className="bg-gray-800 px-1 rounded">report-*.json</code> — each tool result becomes a job in this case
                    </p>
                  </div>
                </div>
                <label
                  className={`flex flex-col items-center justify-center gap-2 border-2 border-dashed rounded-lg p-5 cursor-pointer transition ${
                    importMutation.isPending
                      ? 'border-emerald-500/40 bg-emerald-500/5 cursor-wait'
                      : 'border-gray-700 hover:border-emerald-500/50 hover:bg-emerald-500/5'
                  }`}
                >
                  <input
                    type="file"
                    accept=".json"
                    className="hidden"
                    disabled={importMutation.isPending}
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) importMutation.mutate(file)
                      e.target.value = ''
                    }}
                  />
                  {importMutation.isPending ? (
                    <>
                      <svg className="w-5 h-5 animate-spin text-emerald-400" viewBox="0 0 24 24" fill="none">
                        <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                        <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                      </svg>
                      <span className="text-xs text-emerald-400">Importing…</span>
                    </>
                  ) : (
                    <>
                      <Download className="w-5 h-5 text-gray-500 rotate-180" />
                      <span className="text-xs text-gray-400">Drop <code className="bg-gray-800 px-1 rounded">report.json</code> here or click to browse</span>
                    </>
                  )}
                </label>
              </div>

              {/* AI Analysis shortcut */}
              <div className="card p-4 flex items-center justify-between gap-4">
                <div className="flex items-center gap-3">
                  <div className="w-9 h-9 rounded-lg bg-violet-500/10 border border-violet-500/20 flex items-center justify-center flex-shrink-0">
                    <BrainCircuit className="w-4 h-4 text-violet-400" />
                  </div>
                  <div>
                    <p className="text-sm font-semibold text-gray-200">Analyze with AI</p>
                    <p className="text-xs text-gray-500 mt-0.5">
                      Upload the <code className="bg-gray-800 px-1 rounded">report-*.json</code> for automated forensic analysis
                    </p>
                  </div>
                </div>
                <button
                  onClick={() => navigate('/ai-analysis?source=offline_report')}
                  className="flex-shrink-0 flex items-center gap-1.5 px-3 py-2 bg-violet-600 hover:bg-violet-500 text-white text-xs font-semibold rounded-lg transition"
                >
                  <BrainCircuit className="w-3.5 h-3.5" />
                  Open AI Analysis
                </button>
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Offline bundle modal */}
      <OfflineBundleModal
        open={bundleModalOpen}
        onClose={() => setBundleModalOpen(false)}
        caseId={caseObj.id}
        caseName={caseObj.name}
      />
    </div>
  )
}
