import { useState, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, ClipboardList, Eye, Wrench, Crosshair, Rocket } from 'lucide-react'
import toast from 'react-hot-toast'
import { jobsApi, type JobStatus } from '@/api/jobs'
import { agentsApi } from '@/api/agents'
import { toolsApi, TOOL_CATEGORIES } from '@/api/tools'
import { huntingApi } from '@/api/hunting'
import { JobStatusBadge } from '@/components/StatusBadge'
import { formatDuration, getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
  SelectGroup,
  SelectLabel,
} from '@/components/ui/select'

const JOB_STATUSES: { value: JobStatus; label: string }[] = [
  { value: 'pending', label: 'Pending' },
  { value: 'running', label: 'Running' },
  { value: 'done',    label: 'Done' },
  { value: 'failed',  label: 'Failed' },
]

// ---- New Job Modal ----
interface NewJobModalProps {
  open: boolean
  onClose: () => void
}

function NewJobModal({ open, onClose }: NewJobModalProps) {
  const qc = useQueryClient()
  const [mode, setMode] = useState<'tool' | 'scenario'>('tool')
  const [agentId, setAgentId] = useState('')
  const [toolId, setToolId] = useState('')
  const [args, setArgs] = useState('')
  const [scenarioId, setScenarioId] = useState('')
  const [cpuLimit, setCpuLimit] = useState<number | ''>('')
  const [ramLimit, setRamLimit] = useState<number | ''>('')
  const [priority, setPriority] = useState('normal')

  const { data: agents = [] } = useQuery({
    queryKey: ['agents'],
    queryFn: agentsApi.list,
    enabled: open,
  })

  const { data: tools = [] } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list(),
    enabled: open,
  })

  const { data: scenarios = [] } = useQuery({
    queryKey: ['hunting-scenarios'],
    queryFn: () => huntingApi.listScenarios(),
    enabled: open,
  })

  const resetState = () => {
    setMode('tool'); setAgentId(''); setToolId(''); setArgs(''); setScenarioId(''); setCpuLimit(''); setRamLimit(''); setPriority('normal')
  }

  // Auto-fill args when tool changes
  const handleToolChange = (id: string) => {
    setToolId(id)
    const t = tools.find((t) => t.id === id)
    if (t?.args) setArgs(t.args)
  }

  const createMutation = useMutation({
    mutationFn: jobsApi.create,
    onSuccess: (job) => {
      qc.invalidateQueries({ queryKey: ['jobs'] })
      toast.success(`Job created: ${job.id.slice(0, 8)}…`)
      resetState()
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const deployMutation = useMutation({
    mutationFn: () => huntingApi.deploy(scenarioId, agentId),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['jobs'] })
      qc.invalidateQueries({ queryKey: ['hunting-deployments'] })
      const errs = res.dispatch_errors ?? []
      if (errs.length > 0) {
        toast.error(`Deployed with ${errs.length} dispatch error(s)`)
      } else {
        toast.success(`Deployed scenario — ${res.jobs.length} job(s) created`)
      }
      resetState()
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const selectedScenario = scenarios.find((s) => s.id === scenarioId)

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!agentId) { toast.error('Select an agent'); return }
    if (mode === 'tool') {
      if (!toolId) { toast.error('Select a tool'); return }
      createMutation.mutate({
        agent_id: agentId,
        tool_id: toolId,
        args: args || undefined,
        cpu_limit: cpuLimit ? Number(cpuLimit) : undefined,
        ram_limit: ramLimit ? Number(ramLimit) : undefined,
        priority: priority !== 'normal' ? priority : undefined
      })
    } else {
      if (!scenarioId) { toast.error('Select a scenario'); return }
      if (!selectedScenario || (selectedScenario.tools ?? []).length === 0) {
        toast.error('Scenario has no tools attached'); return
      }
      deployMutation.mutate()
    }
  }

  // Group tools by category for the dropdown
  const toolsByCategory = TOOL_CATEGORIES.reduce<Record<string, typeof tools>>((acc, cat) => {
    const catTools = tools.filter((t) => t.category === cat)
    if (catTools.length) acc[cat] = catTools
    return acc
  }, {})

  const onlineAgents = agents.filter((a) => a.status === 'online')
  const offlineAgents = agents.filter((a) => a.status === 'offline')

  const isPending = createMutation.isPending || deployMutation.isPending

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { resetState(); onClose() } }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create New Job</DialogTitle>
          <DialogDescription>
            {mode === 'tool'
              ? 'Dispatch a single forensic tool to a remote agent.'
              : 'Deploy every tool in a hunting scenario at once.'}
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            {/* Mode tabs */}
            <div className="flex items-center gap-1 p-1 bg-gray-900/60 rounded-lg border border-gray-800">
              <button
                type="button"
                onClick={() => setMode('tool')}
                className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded transition ${
                  mode === 'tool'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : 'text-gray-400 hover:text-gray-200 border border-transparent'
                }`}
              >
                <Wrench className="h-3.5 w-3.5" /> Single Tool
              </button>
              <button
                type="button"
                onClick={() => setMode('scenario')}
                className={`flex-1 flex items-center justify-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded transition ${
                  mode === 'scenario'
                    ? 'bg-emerald-500/10 text-emerald-400 border border-emerald-500/30'
                    : 'text-gray-400 hover:text-gray-200 border border-transparent'
                }`}
              >
                <Crosshair className="h-3.5 w-3.5" /> Scenario
              </button>
            </div>

            {/* Agent select (shared) */}
            <div>
              <label className="label">Target Agent *</label>
              <Select value={agentId} onValueChange={setAgentId}>
                <SelectTrigger>
                  <SelectValue placeholder="Select an agent…" />
                </SelectTrigger>
                <SelectContent>
                  {onlineAgents.length > 0 && (
                    <SelectGroup>
                      <SelectLabel>Online</SelectLabel>
                      {onlineAgents.map((a) => (
                        <SelectItem key={a.id} value={a.id}>
                          <span className="flex items-center gap-2">
                            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500 shrink-0" />
                            {a.name}
                            {a.hostname && <span className="text-gray-500 text-xs">({a.hostname})</span>}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  )}
                  {offlineAgents.length > 0 && (
                    <SelectGroup>
                      <SelectLabel>Offline</SelectLabel>
                      {offlineAgents.map((a) => (
                        <SelectItem key={a.id} value={a.id} disabled>
                          <span className="flex items-center gap-2 opacity-50">
                            <span className="h-1.5 w-1.5 rounded-full bg-gray-500 shrink-0" />
                            {a.name}
                          </span>
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  )}
                  {agents.length === 0 && (
                    <SelectItem value="__none__" disabled>No agents available</SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>

            {mode === 'tool' ? (
              <>
                {/* Tool select */}
                <div>
                  <label className="label">Tool *</label>
                  <Select value={toolId} onValueChange={handleToolChange}>
                    <SelectTrigger>
                      <SelectValue placeholder="Select a tool…" />
                    </SelectTrigger>
                    <SelectContent>
                      {Object.entries(toolsByCategory).map(([cat, catTools]) => (
                        <SelectGroup key={cat}>
                          <SelectLabel>{cat}</SelectLabel>
                          {catTools.map((t) => (
                            <SelectItem key={t.id} value={t.id}>
                              {t.name}
                              <span className="text-gray-500 text-xs ml-1">v{t.version}</span>
                            </SelectItem>
                          ))}
                        </SelectGroup>
                      ))}
                      {tools.length === 0 && (
                        <SelectItem value="__none__" disabled>No tools available</SelectItem>
                      )}
                    </SelectContent>
                  </Select>
                </div>

                {/* Args */}
                <div>
                  <label className="label">
                    Arguments
                    <span className="ml-1 text-xs text-gray-500">(optional — overrides tool defaults)</span>
                  </label>
                  <input
                    className="input font-mono text-xs"
                    value={args}
                    onChange={(e) => setArgs(e.target.value)}
                    placeholder="e.g. -f evidence.raw imageinfo"
                  />
                </div>

                <div className="grid grid-cols-3 gap-3">
                  <div>
                    <label className="label">CPU Limit (%)</label>
                    <input type="number" min="1" max="100" className="input text-xs" value={cpuLimit} onChange={(e) => setCpuLimit(e.target.value ? Number(e.target.value) : '')} placeholder="Uncapped" />
                  </div>
                  <div>
                    <label className="label">RAM Limit (MB)</label>
                    <input type="number" min="1" className="input text-xs" value={ramLimit} onChange={(e) => setRamLimit(e.target.value ? Number(e.target.value) : '')} placeholder="Uncapped" />
                  </div>
                  <div>
                    <label className="label">Priority</label>
                    <Select value={priority} onValueChange={setPriority}>
                      <SelectTrigger className="text-xs"><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="normal">Normal</SelectItem>
                        <SelectItem value="idle">Idle (Soft)</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                </div>

                {/* Preview */}
                {toolId && agentId && (
                  <div className="bg-gray-950 rounded-lg border border-gray-800 p-3">
                    <p className="text-xs text-gray-500 mb-1.5 font-mono">PREVIEW</p>
                    <code className="text-xs text-emerald-400 font-mono">
                      {tools.find((t) => t.id === toolId)?.name ?? toolId}
                      {args && <span className="text-amber-400"> {args}</span>}
                    </code>
                    <p className="text-xs text-gray-600 mt-1">→ {agents.find((a) => a.id === agentId)?.name ?? agentId}</p>
                  </div>
                )}
              </>
            ) : (
              <>
                {/* Scenario select */}
                <div>
                  <label className="label">Scenario *</label>
                  <Select value={scenarioId} onValueChange={setScenarioId}>
                    <SelectTrigger>
                      <SelectValue placeholder={scenarios.length === 0 ? 'No scenarios available' : 'Select a scenario…'} />
                    </SelectTrigger>
                    <SelectContent>
                      {scenarios.map((sc) => {
                        const count = sc.tools?.length ?? 0
                        return (
                          <SelectItem key={sc.id} value={sc.id} disabled={count === 0}>
                            {sc.name}
                            <span className="text-gray-500 text-xs ml-1">— {count} tool{count === 1 ? '' : 's'}</span>
                          </SelectItem>
                        )
                      })}
                    </SelectContent>
                  </Select>
                  <p className="text-xs text-gray-500 mt-1.5">
                    Manage scenarios in <Link to="/hunting" className="text-emerald-400 hover:underline">Scenario Hunting</Link>.
                  </p>
                </div>

                {/* Tools preview */}
                {selectedScenario && (
                  <div className="bg-gray-950 rounded-lg border border-gray-800 p-3 space-y-1.5">
                    <p className="text-xs text-gray-500 font-mono">
                      WILL DEPLOY {(selectedScenario.tools ?? []).length} TOOL(S)
                    </p>
                    {(selectedScenario.tools ?? []).length === 0 ? (
                      <p className="text-xs text-amber-400">This scenario has no tools — attach some first.</p>
                    ) : (
                      <ul className="space-y-0.5">
                        {selectedScenario.tools!.map((link) => (
                          <li key={link.id} className="text-xs text-gray-300 flex items-center gap-2">
                            <span className="text-emerald-400">›</span>
                            <span className="truncate">{link.tool?.name ?? '—'}</span>
                            {link.tool?.args && (
                              <code className="text-[10px] text-amber-400/70 font-mono truncate">{link.tool.args}</code>
                            )}
                          </li>
                        ))}
                      </ul>
                    )}
                    {agentId && (
                      <p className="text-xs text-gray-600 pt-1 border-t border-gray-800/60 mt-2">
                        → {agents.find((a) => a.id === agentId)?.name ?? agentId}
                      </p>
                    )}
                  </div>
                )}
              </>
            )}
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={() => { resetState(); onClose() }}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={isPending}>
              {isPending ? (
                <><span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> Dispatching…</>
              ) : mode === 'tool' ? (
                <><Plus className="h-4 w-4" /> Create Job</>
              ) : (
                <><Rocket className="h-4 w-4" /> Deploy Scenario</>
              )}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Main Page ----
export default function JobsPage() {
  const [newOpen, setNewOpen] = useState(false)
  const [filterAgent, setFilterAgent] = useState('all')
  const [filterStatus, setFilterStatus] = useState('all')

  const { data: jobs = [], isLoading } = useQuery({
    queryKey: ['jobs'],
    queryFn: () => jobsApi.list(),
    refetchInterval: 5_000,
  })

  const { data: agents = [] } = useQuery({
    queryKey: ['agents'],
    queryFn: agentsApi.list,
  })

  const filtered = jobs.filter((j) => {
    const matchAgent = filterAgent === 'all' || j.agent_id === filterAgent
    const matchStatus = filterStatus === 'all' || j.status === filterStatus
    return matchAgent && matchStatus
  })

  const sorted = [...filtered].sort(
    (a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
  )

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Jobs</h1>
          <p className="text-sm text-gray-400 mt-0.5">{jobs.length} job{jobs.length !== 1 ? 's' : ''} total</p>
        </div>
        <button className="btn-primary" onClick={() => setNewOpen(true)}>
          <Plus className="h-4 w-4" /> New Job
        </button>
      </div>

      {/* Filters */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={filterAgent} onValueChange={setFilterAgent}>
          <SelectTrigger className="w-48"><SelectValue placeholder="Filter by agent" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Agents</SelectItem>
            {agents.map((a) => (
              <SelectItem key={a.id} value={a.id}>{a.name}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        <Select value={filterStatus} onValueChange={setFilterStatus}>
          <SelectTrigger className="w-40"><SelectValue placeholder="Filter by status" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Statuses</SelectItem>
            {JOB_STATUSES.map((s) => (
              <SelectItem key={s.value} value={s.value}>{s.label}</SelectItem>
            ))}
          </SelectContent>
        </Select>
        {(filterAgent !== 'all' || filterStatus !== 'all') && (
          <button
            className="text-xs text-gray-400 hover:text-gray-200 transition-colors"
            onClick={() => { setFilterAgent('all'); setFilterStatus('all') }}
          >
            Clear filters
          </button>
        )}
        <span className="ml-auto text-xs text-gray-500">{sorted.length} result{sorted.length !== 1 ? 's' : ''}</span>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6 space-y-3">
              {[...Array(6)].map((_, i) => <div key={i} className="skeleton h-12 w-full rounded" />)}
            </div>
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-500">
              <ClipboardList className="h-10 w-10 mb-3 opacity-30" />
              <p className="text-sm">{jobs.length === 0 ? 'No jobs dispatched yet' : 'No jobs match filters'}</p>
              {jobs.length === 0 && (
                <button className="mt-4 btn-primary text-xs" onClick={() => setNewOpen(true)}>
                  <Plus className="h-3.5 w-3.5" /> Create your first job
                </button>
              )}
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-5 py-3">Job ID</th>
                  <th className="table-header text-left px-5 py-3">Tool</th>
                  <th className="table-header text-left px-5 py-3 hidden sm:table-cell">Agent</th>
                  <th className="table-header text-left px-5 py-3">Status</th>
                  <th className="table-header text-left px-5 py-3 hidden md:table-cell">Duration</th>
                  <th className="table-header text-left px-5 py-3 hidden lg:table-cell">Created</th>
                  <th className="table-header text-left px-5 py-3 hidden lg:table-cell">Analyst</th>
                  <th className="table-header text-right px-5 py-3">View</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((job: any) => (
                  <tr key={job.id} className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3">
                      <span className="font-mono text-xs text-gray-400">{job.id.slice(0, 8)}…</span>
                    </td>
                    <td className="px-5 py-3">
                      <div className="text-sm font-medium text-gray-200">{job.tool?.name ?? job.tool_id}</div>
                      {job.args && (
                        <code className="text-[10px] text-amber-400/70 font-mono mt-0.5 block truncate max-w-[180px]">
                          {job.args}
                        </code>
                      )}
                    </td>
                    <td className="px-5 py-3 hidden sm:table-cell text-sm text-gray-400">
                      {job.agent?.name ?? job.agent_id}
                    </td>
                    <td className="px-5 py-3">
                      <JobStatusBadge status={job.status} />
                    </td>
                    <td className="px-5 py-3 hidden md:table-cell text-xs text-gray-400 font-mono">
                      {job.started_at
                        ? formatDuration(job.started_at, job.finished_at)
                        : '—'}
                    </td>
                    <td className="px-5 py-3 hidden lg:table-cell text-xs text-gray-500">
                      {safeDistanceToNow(job.created_at, { addSuffix: true })}
                    </td>
                    <td className="px-5 py-3 hidden lg:table-cell text-xs text-gray-400">
                      {job.created_by_user?.name || job.created_by_user?.email || '—'}
                    </td>
                    <td className="px-5 py-3 text-right">
                      <Link
                        to={`/jobs/${job.id}`}
                        className="inline-flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300 transition-colors"
                      >
                        <Eye className="h-3.5 w-3.5" /> View
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <NewJobModal open={newOpen} onClose={() => setNewOpen(false)} />
    </div>
  )
}
