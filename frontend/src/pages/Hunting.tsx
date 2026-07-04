import { useState, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Crosshair,
  Plus,
  Pencil,
  Trash2,
  Rocket,
  Play,
  Square,
  ExternalLink,
  X,
  ListChecks,
  PackageOpen,
  Shield,
  Lock,
  Network,
  RefreshCw,
  Cpu,
  Eye,
  Activity,
  Loader2,
  AlertTriangle,
  CalendarPlus,
  Radar,
  Database,
  GitBranch,
} from 'lucide-react'
import { Link } from 'react-router-dom'
import { safeDistanceToNow } from '@/lib/utils'
import toast from 'react-hot-toast'
import {
  huntingApi,
  type HuntingScenario,
  type HuntingDeployment,
} from '@/api/hunting'
import { toolsApi } from '@/api/tools'
import { agentsApi } from '@/api/agents'
import { jobsApi } from '@/api/jobs'
import { casesApi } from '@/api/cases'
import { traceApi } from '@/api/trace'
import TraceOriginModal from '@/components/Agent/TraceOriginModal'
import { openctiApi } from '@/api/opencti'
import type { IOCSweepResult } from '@/api/agents'
import { JobStatusBadge, AgentStatusBadge } from '@/components/StatusBadge'
import { getErrorMessage } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
  DialogFooter,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const ICON_MAP: Record<string, typeof Shield> = {
  Shield, Lock, Network, RefreshCw, Cpu, Crosshair, Activity, Eye,
}

const COLOR_MAP: Record<string, { bg: string; text: string; border: string; ring: string }> = {
  emerald: { bg: 'bg-emerald-500/10', text: 'text-emerald-400', border: 'border-emerald-500/30', ring: 'hover:border-emerald-500/60' },
  rose:    { bg: 'bg-rose-500/10',    text: 'text-rose-400',    border: 'border-rose-500/30',    ring: 'hover:border-rose-500/60' },
  sky:     { bg: 'bg-sky-500/10',     text: 'text-sky-400',     border: 'border-sky-500/30',     ring: 'hover:border-sky-500/60' },
  amber:   { bg: 'bg-amber-500/10',   text: 'text-amber-400',   border: 'border-amber-500/30',   ring: 'hover:border-amber-500/60' },
  violet:  { bg: 'bg-violet-500/10',  text: 'text-violet-400',  border: 'border-violet-500/30',  ring: 'hover:border-violet-500/60' },
  cyan:    { bg: 'bg-cyan-500/10',    text: 'text-cyan-400',    border: 'border-cyan-500/30',    ring: 'hover:border-cyan-500/60' },
}

const AVAILABLE_ICONS = ['Shield', 'Lock', 'Network', 'RefreshCw', 'Cpu', 'Crosshair', 'Activity', 'Eye']
const AVAILABLE_COLORS = ['emerald', 'rose', 'sky', 'amber', 'violet', 'cyan']

function getIcon(name: string) {
  return ICON_MAP[name] ?? Crosshair
}
function getColor(name: string) {
  return COLOR_MAP[name] ?? COLOR_MAP.emerald
}

// ---------------------------------------------------------------------------
// Scenario edit modal (create or update)
// ---------------------------------------------------------------------------
function ScenarioFormModal({
  open,
  onClose,
  scenario,
}: {
  open: boolean
  onClose: () => void
  scenario?: HuntingScenario | null
}) {
  const qc = useQueryClient()
  const isEdit = !!scenario
  const [name, setName] = useState(scenario?.name ?? '')
  const [description, setDescription] = useState(scenario?.description ?? '')
  const [icon, setIcon] = useState(scenario?.icon ?? 'Crosshair')
  const [color, setColor] = useState(scenario?.color ?? 'emerald')

  const mutation = useMutation({
    mutationFn: () => {
      const payload = { name, description, icon, color }
      return isEdit
        ? huntingApi.updateScenario(scenario!.id, payload)
        : huntingApi.createScenario(payload)
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-scenarios'] })
      toast.success(isEdit ? 'Scenario updated' : 'Scenario created')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) { toast.error('Name is required'); return }
    mutation.mutate()
  }

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent>
        <form onSubmit={handleSubmit}>
          <DialogHeader>
            <DialogTitle>{isEdit ? 'Edit Scenario' : 'New Hunting Scenario'}</DialogTitle>
            <DialogDescription>
              Group tools under an attack scenario for one-click deployment.
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Name *</label>
              <input
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. Webshell Hunt"
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-gray-400 mb-1">Description</label>
              <textarea
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                rows={3}
                className="w-full px-3 py-2 bg-gray-900 border border-gray-700 rounded text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Icon</label>
                <Select value={icon} onValueChange={setIcon}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {AVAILABLE_ICONS.map((ic) => {
                      const Ic = getIcon(ic)
                      return (
                        <SelectItem key={ic} value={ic}>
                          <span className="flex items-center gap-2">
                            <Ic className="h-3.5 w-3.5" /> {ic}
                          </span>
                        </SelectItem>
                      )
                    })}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="block text-xs font-medium text-gray-400 mb-1">Color</label>
                <Select value={color} onValueChange={setColor}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {AVAILABLE_COLORS.map((co) => (
                      <SelectItem key={co} value={co}>
                        <span className="flex items-center gap-2">
                          <span className={`inline-block h-3 w-3 rounded-full ${getColor(co).bg} border ${getColor(co).border}`} />
                          {co}
                        </span>
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded disabled:opacity-50"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save' : 'Create'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Scenario detail modal — manage tools + deploy
// ---------------------------------------------------------------------------
function ScenarioDetailModal({
  open,
  onClose,
  scenario,
}: {
  open: boolean
  onClose: () => void
  scenario: HuntingScenario | null
}) {
  const qc = useQueryClient()
  const [pendingToolId, setPendingToolId] = useState<string>('')
  const [deployAgentId, setDeployAgentId] = useState<string>('')
  const [deployCaseId, setDeployCaseId] = useState<string>('__none__')

  const { data: allTools = [] } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list(),
    enabled: open,
  })
  const { data: agents = [] } = useQuery({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list(),
    enabled: open,
  })
  const { data: cases = [] } = useQuery({
    queryKey: ['cases'],
    queryFn: () => casesApi.list(),
    enabled: open,
  })

  const attachMutation = useMutation({
    mutationFn: () => huntingApi.addTool(scenario!.id, pendingToolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-scenarios'] })
      qc.invalidateQueries({ queryKey: ['hunting-scenario', scenario?.id] })
      setPendingToolId('')
      toast.success('Tool attached')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const removeMutation = useMutation({
    mutationFn: (toolId: string) => huntingApi.removeTool(scenario!.id, toolId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-scenarios'] })
      qc.invalidateQueries({ queryKey: ['hunting-scenario', scenario?.id] })
      toast.success('Tool detached')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const deployMutation = useMutation({
    mutationFn: () => huntingApi.deploy(scenario!.id, deployAgentId, deployCaseId === '__none__' ? undefined : deployCaseId || undefined),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['hunting-deployments'] })
      qc.invalidateQueries({ queryKey: ['jobs'] })
      if (deployCaseId) qc.invalidateQueries({ queryKey: ['case-summary', deployCaseId] })
      const errs = res.dispatch_errors
      if (errs && errs.length > 0) {
        toast.error(`Deployed with ${errs.length} dispatch error(s)`)
      } else {
        toast.success(`Deployed ${res.jobs.length} tool(s) — switch to Deployments tab`)
      }
      setDeployAgentId('')
      setDeployCaseId('__none__')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  if (!scenario) return null
  const Icon = getIcon(scenario.icon)
  const col = getColor(scenario.color)
  const attachedIds = new Set((scenario.tools ?? []).map((t) => t.tool_id))
  const availableTools = allTools.filter((t) => !attachedIds.has(t.id))
  const onlineAgents = agents.filter((a) => a.status === 'online')

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-3">
            <span className={`inline-flex items-center justify-center h-9 w-9 rounded-lg ${col.bg} border ${col.border}`}>
              <Icon className={`h-4 w-4 ${col.text}`} />
            </span>
            {scenario.name}
          </DialogTitle>
          {scenario.description && (
            <DialogDescription>{scenario.description}</DialogDescription>
          )}
        </DialogHeader>

        <DialogBody className="space-y-5">
          {/* Tools list */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider">Attached Tools ({(scenario.tools ?? []).length})</h4>
            </div>
            {(scenario.tools ?? []).length === 0 ? (
              <div className="text-sm text-gray-500 italic p-3 bg-gray-900/50 rounded border border-gray-800 text-center">
                No tools attached yet — pick one below.
              </div>
            ) : (
              <ul className="space-y-1.5">
                {scenario.tools!.map((link) => (
                  <li key={link.id} className="flex items-center justify-between gap-2 px-3 py-2 bg-gray-900/50 border border-gray-800 rounded">
                    <div className="min-w-0 flex-1">
                      <div className="text-sm text-gray-200 truncate">{link.tool?.name ?? '—'}</div>
                      <div className="text-xs text-gray-500 truncate font-mono">{link.tool?.args || '(no default args)'}</div>
                    </div>
                    <button
                      onClick={() => removeMutation.mutate(link.tool_id)}
                      className="text-gray-500 hover:text-red-400 p-1 rounded transition"
                      title="Remove from scenario"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </li>
                ))}
              </ul>
            )}
          </div>

          {/* Add tool */}
          <div className="border-t border-gray-800 pt-4">
            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-2">Add Tool</h4>
            <div className="flex gap-2">
              <div className="flex-1">
                <Select value={pendingToolId} onValueChange={setPendingToolId}>
                  <SelectTrigger>
                    <SelectValue placeholder={availableTools.length === 0 ? 'No tools available' : 'Select a tool…'} />
                  </SelectTrigger>
                  <SelectContent>
                    {availableTools.map((t) => (
                      <SelectItem key={t.id} value={t.id}>{t.name} <span className="text-gray-500">— {t.platform}</span></SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
              <button
                onClick={() => attachMutation.mutate()}
                disabled={!pendingToolId || attachMutation.isPending}
                className="px-3 py-2 text-sm bg-gray-800 hover:bg-gray-700 text-gray-200 rounded disabled:opacity-40 flex items-center gap-1.5"
              >
                <Plus className="h-3.5 w-3.5" /> Add
              </button>
            </div>
          </div>

          {/* Deploy */}
          <div className="border-t border-gray-800 pt-4">
            <h4 className="text-xs font-bold text-gray-400 uppercase tracking-wider mb-3">Deploy to Agent</h4>
            <div className="space-y-2">
              <Select value={deployAgentId} onValueChange={setDeployAgentId}>
                <SelectTrigger>
                  <SelectValue placeholder={onlineAgents.length === 0 ? 'No online agents' : 'Select an online agent…'} />
                </SelectTrigger>
                <SelectContent>
                  {onlineAgents.map((a) => (
                    <SelectItem key={a.id} value={a.id}>{a.name} <span className="text-gray-500">— {a.hostname}</span></SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={deployCaseId} onValueChange={setDeployCaseId}>
                <SelectTrigger>
                  <SelectValue placeholder="Link to case (optional)" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="__none__">No case</SelectItem>
                  {cases.filter((ca) => ca.status === 'open').map((ca) => (
                    <SelectItem key={ca.id} value={ca.id}>{ca.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <button
                onClick={() => deployMutation.mutate()}
                disabled={!deployAgentId || deployMutation.isPending || (scenario.tools ?? []).length === 0}
                className="w-full px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded disabled:opacity-40 flex items-center justify-center gap-1.5"
              >
                <Rocket className="h-3.5 w-3.5" />
                {deployMutation.isPending ? 'Deploying…' : 'Deploy'}
              </button>
            </div>
            <p className="text-xs text-gray-500 mt-2">
              Creates 1 job per tool with the tool's default args. Run each job individually from the Deployments tab.
            </p>
          </div>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}

// ---------------------------------------------------------------------------
// Scenarios tab
// ---------------------------------------------------------------------------
function ScenariosTab() {
  const qc = useQueryClient()
  const [creating, setCreating] = useState(false)
  const [editing, setEditing] = useState<HuntingScenario | null>(null)
  const [viewing, setViewing] = useState<HuntingScenario | null>(null)

  const { data: scenarios = [], isLoading } = useQuery({
    queryKey: ['hunting-scenarios'],
    queryFn: () => huntingApi.listScenarios(),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => huntingApi.deleteScenario(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-scenarios'] })
      toast.success('Scenario deleted')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="text-sm text-gray-400">
          Pick a scenario and deploy its tool set to an agent in one click.
        </div>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded transition"
        >
          <Plus className="h-3.5 w-3.5" /> New Scenario
        </button>
      </div>

      {isLoading ? (
        <div className="text-center text-gray-500 py-12">Loading…</div>
      ) : scenarios.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-gray-800 rounded">
          <Crosshair className="h-8 w-8 text-gray-700 mx-auto mb-2" />
          <p className="text-gray-500 text-sm">No scenarios yet. Create one to get started.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
          {scenarios.map((sc) => {
            const Icon = getIcon(sc.icon)
            const col = getColor(sc.color)
            const toolCount = sc.tools?.length ?? 0
            return (
              <div
                key={sc.id}
                onClick={() => setViewing(sc)}
                className={`group cursor-pointer p-4 bg-gray-900/50 border ${col.border} ${col.ring} rounded-lg transition`}
              >
                <div className="flex items-start justify-between mb-2">
                  <span className={`inline-flex items-center justify-center h-9 w-9 rounded-lg ${col.bg} border ${col.border}`}>
                    <Icon className={`h-4 w-4 ${col.text}`} />
                  </span>
                  <div className="flex items-center gap-1 opacity-0 group-hover:opacity-100 transition">
                    <button
                      onClick={(e) => { e.stopPropagation(); setEditing(sc) }}
                      className="text-gray-500 hover:text-gray-300 p-1 rounded"
                      title="Edit"
                    >
                      <Pencil className="h-3.5 w-3.5" />
                    </button>
                    <button
                      onClick={(e) => {
                        e.stopPropagation()
                        if (confirm(`Delete scenario "${sc.name}"?`)) deleteMutation.mutate(sc.id)
                      }}
                      className="text-gray-500 hover:text-red-400 p-1 rounded"
                      title="Delete"
                    >
                      <Trash2 className="h-3.5 w-3.5" />
                    </button>
                  </div>
                </div>
                <h3 className="text-sm font-medium text-gray-200 mb-1">{sc.name}</h3>
                <p className="text-xs text-gray-500 mb-3 line-clamp-2 min-h-[2rem]">{sc.description || '—'}</p>
                <div className="flex items-center justify-between text-xs text-gray-500">
                  <span className="flex items-center gap-1.5">
                    <PackageOpen className="h-3.5 w-3.5" /> {toolCount} tool{toolCount === 1 ? '' : 's'}
                  </span>
                  <span className={`flex items-center gap-1 ${col.text}`}>
                    Manage <ExternalLink className="h-3 w-3" />
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {creating && <ScenarioFormModal open={creating} onClose={() => setCreating(false)} />}
      {editing && <ScenarioFormModal open={!!editing} onClose={() => setEditing(null)} scenario={editing} />}
      {viewing && <ScenarioDetailModal open={!!viewing} onClose={() => setViewing(null)} scenario={scenarios.find((s) => s.id === viewing.id) ?? viewing} />}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Deployment job row — Run / Stop / view
// ---------------------------------------------------------------------------
function DeploymentJobRow({ job }: { job: NonNullable<HuntingDeployment['jobs']>[number] }) {
  const qc = useQueryClient()

  const runMutation = useMutation({
    mutationFn: () => jobsApi.run(job.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-deployments'] })
      toast.success(`Running ${job.tool?.name ?? 'job'}`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const stopMutation = useMutation({
    mutationFn: () => jobsApi.stop(job.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-deployments'] })
      toast.success('Stop signal sent')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const canRun = job.status === 'ready' || job.status === 'stopped'
  const canStop = job.status === 'running'

  return (
    <tr className="border-t border-gray-800 hover:bg-gray-900/30">
      <td className="py-2 px-3 text-sm text-gray-200">{job.tool?.name ?? '—'}</td>
      <td className="py-2 px-3"><JobStatusBadge status={job.status} /></td>
      <td className="py-2 px-3 text-xs text-gray-500 font-mono truncate max-w-[200px]">{job.args || '—'}</td>
      <td className="py-2 px-3 text-right">
        <div className="flex items-center justify-end gap-1.5">
          {canRun && (
            <button
              onClick={() => runMutation.mutate()}
              disabled={runMutation.isPending}
              className="px-2 py-1 text-xs bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-700/40 rounded flex items-center gap-1"
            >
              <Play className="h-3 w-3" /> Run
            </button>
          )}
          {canStop && (
            <button
              onClick={() => stopMutation.mutate()}
              disabled={stopMutation.isPending}
              className="px-2 py-1 text-xs bg-red-600/20 hover:bg-red-600/40 text-red-300 border border-red-700/40 rounded flex items-center gap-1"
            >
              <Square className="h-3 w-3" /> Stop
            </button>
          )}
          <Link
            to={`/jobs/${job.id}`}
            className="px-2 py-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded flex items-center gap-1"
            title="Open job detail"
          >
            <Eye className="h-3 w-3" /> View
          </Link>
        </div>
      </td>
    </tr>
  )
}

// ---------------------------------------------------------------------------
// Deployments tab
// ---------------------------------------------------------------------------
function DeploymentsTab() {
  const qc = useQueryClient()
  const { data: deployments = [], isLoading } = useQuery({
    queryKey: ['hunting-deployments'],
    queryFn: () => huntingApi.listDeployments(),
    refetchInterval: 5000,
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => huntingApi.deleteDeployment(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['hunting-deployments'] })
      toast.success('Deployment record deleted')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  if (isLoading) return <div className="text-center text-gray-500 py-12">Loading…</div>
  if (deployments.length === 0) {
    return (
      <div className="text-center py-12 border border-dashed border-gray-800 rounded">
        <ListChecks className="h-8 w-8 text-gray-700 mx-auto mb-2" />
        <p className="text-gray-500 text-sm">No deployments yet. Deploy a scenario from the Scenarios tab.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {deployments.map((dep) => {
        const Icon = getIcon(dep.scenario?.icon ?? 'Crosshair')
        const col = getColor(dep.scenario?.color ?? 'emerald')
        const jobs = dep.jobs ?? []
        const done = jobs.filter((j) => j.status === 'done').length
        return (
          <div key={dep.id} className="bg-gray-900/40 border border-gray-800 rounded-lg overflow-hidden">
            <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900/60">
              <div className="flex items-center gap-3 min-w-0">
                <span className={`inline-flex items-center justify-center h-8 w-8 rounded-lg ${col.bg} border ${col.border} shrink-0`}>
                  <Icon className={`h-4 w-4 ${col.text}`} />
                </span>
                <div className="min-w-0">
                  <div className="text-sm font-medium text-gray-200 truncate">
                    {dep.scenario?.name ?? 'Unknown scenario'}
                  </div>
                  <div className="text-xs text-gray-500 truncate">
                    Agent: <span className="text-gray-300">{dep.agent?.name ?? '—'}</span>
                    {dep.agent && <span className="ml-2">{<AgentStatusBadge status={dep.agent.status} />}</span>}
                    <span className="mx-2">·</span>
                    {safeDistanceToNow(dep.created_at, { addSuffix: true })}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <span className="text-xs text-gray-400">{done}/{jobs.length} done</span>
                <button
                  onClick={() => {
                    if (confirm('Delete this deployment record? Underlying jobs are preserved.')) {
                      deleteMutation.mutate(dep.id)
                    }
                  }}
                  className="text-gray-500 hover:text-red-400 p-1 rounded"
                  title="Delete deployment record"
                >
                  <X className="h-4 w-4" />
                </button>
              </div>
            </div>
            {jobs.length === 0 ? (
              <div className="p-4 text-sm text-gray-500 text-center italic">No jobs in this deployment.</div>
            ) : (
              <table className="w-full text-sm">
                <thead className="text-xs text-gray-500 uppercase tracking-wider">
                  <tr>
                    <th className="text-left py-2 px-3 font-medium">Tool</th>
                    <th className="text-left py-2 px-3 font-medium">Status</th>
                    <th className="text-left py-2 px-3 font-medium">Args</th>
                    <th className="text-right py-2 px-3 font-medium">Actions</th>
                  </tr>
                </thead>
                <tbody>
                  {jobs.map((j) => <DeploymentJobRow key={j.id} job={j} />)}
                </tbody>
              </table>
            )}
          </div>
        )
      })}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Live IOC Sweep tab — push indicators to an agent, collect live artifacts and
// match server-side. Bridges threat-intel → endpoint.
// ---------------------------------------------------------------------------
const SWEEP_TYPES: { key: string; label: string }[] = [
  { key: 'processes', label: 'Processes' },
  { key: 'dlls', label: 'Loaded DLLs' },
  { key: 'netconn', label: 'Network' },
  { key: 'browser', label: 'Browser' },
  { key: 'autoruns', label: 'Autoruns' },
  { key: 'shimcache', label: 'Shimcache' },
  { key: 'prefetch', label: 'Prefetch' },
]

const IND_BADGE: Record<string, string> = {
  hash: 'text-purple-300 border-purple-700/50 bg-purple-900/20',
  ip: 'text-cyan-300 border-cyan-700/50 bg-cyan-900/20',
  domain: 'text-blue-300 border-blue-700/50 bg-blue-900/20',
  filename: 'text-amber-300 border-amber-700/50 bg-amber-900/20',
}

function IOCSweepTab() {
  const { data: agents = [] } = useQuery({ queryKey: ['agents'], queryFn: () => agentsApi.list() })
  const { data: cases = [] } = useQuery({ queryKey: ['cases'], queryFn: () => casesApi.list() })
  const online = agents.filter((a) => a.status === 'online')

  const [agentId, setAgentId] = useState('')
  const [text, setText] = useState('')
  const [types, setTypes] = useState<Set<string>>(new Set(['processes', 'dlls', 'netconn', 'browser', 'autoruns']))
  const [result, setResult] = useState<IOCSweepResult | null>(null)
  const [running, setRunning] = useState(false)
  const [caseId, setCaseId] = useState('')
  const [useStore, setUseStore] = useState(false)
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)

  const { data: facets } = useQuery({ queryKey: ['ioc-facets'], queryFn: openctiApi.iocFacets })
  const storeTotal = facets?.total ?? 0

  const toggle = (k: string) => setTypes((p) => { const n = new Set(p); n.has(k) ? n.delete(k) : n.add(k); return n })
  const indicators = text.split(/[\s,;]+/).map((s) => s.trim()).filter(Boolean)
  const agent = agents.find((a) => a.id === agentId)

  const run = async () => {
    if (!agentId) { toast.error('Select an online agent'); return }
    if (indicators.length === 0 && !useStore) { toast.error('Enter indicators or enable "Match against entire IOC Store"'); return }
    if (types.size === 0) { toast.error('Select at least one artifact'); return }
    setRunning(true); setResult(null)
    try {
      toast('Sweeping endpoint — one UAC prompt, collecting + matching…', { icon: '🛡️' })
      const r = await agentsApi.iocSweep(agentId, indicators, Array.from(types), useStore)
      setResult(r)
      toast.success(r.matches.length > 0
        ? `${r.matches.length} match(es) found across ${r.indicators} indicator(s)`
        : `No matches — ${r.indicators} indicator(s) clean on this host`)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally { setRunning(false) }
  }

  const addMut = useMutation({
    mutationFn: () => traceApi.addToCase(caseId, {
      host: agent?.hostname || agent?.name || '',
      target: 'IOC sweep',
      events: (result?.matches ?? []).map((m) => ({
        time: new Date().toISOString(),
        kind: 'log' as const,
        title: `IOC match: ${m.indicator} (${m.indicator_type}) in ${m.artifact}`,
        detail: m.context,
        source: 'ioc-sweep',
      })),
    }),
    onSuccess: (r) => toast.success(`Added ${r.events_created} match(es) to the case timeline`),
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="space-y-4">
      <div className="card p-4 space-y-3">
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-3">
          <div>
            <label className="label text-xs">Target agent (online)</label>
            <select className="input" value={agentId} onChange={(e) => setAgentId(e.target.value)}>
              <option value="">Select agent…</option>
              {online.map((a) => <option key={a.id} value={a.id}>{a.name} — {a.hostname || a.ip_address}</option>)}
            </select>
            {online.length === 0 && <p className="text-[11px] text-yellow-400 mt-1">No online agent.</p>}
            <div className="mt-3">
              <label className="label text-xs">Artifacts to sweep</label>
              <div className="flex flex-wrap gap-2 mt-1">
                {SWEEP_TYPES.map((t) => (
                  <label key={t.key} className={`flex items-center gap-1.5 text-xs rounded-lg border px-2.5 py-1 cursor-pointer ${types.has(t.key) ? 'border-emerald-500/50 bg-emerald-900/15 text-emerald-300' : 'border-gray-700 text-gray-400'}`}>
                    <input type="checkbox" checked={types.has(t.key)} onChange={() => toggle(t.key)} /> {t.label}
                  </label>
                ))}
              </div>
            </div>
          </div>
          <div>
            <label className="label text-xs">Indicators (one per line — hashes / IPs / domains / file names; type auto-detected)</label>
            <textarea className="input font-mono text-xs min-h-[120px]" placeholder={'evil.exe\n45.77.12.34\nbad-c2.com\n<sha256>'}
              value={text} onChange={(e) => setText(e.target.value)} />
            <p className="text-[11px] text-gray-500 mt-1">{indicators.length} indicator(s) parsed</p>
            <label className={`mt-2 flex items-start gap-2 rounded-lg border px-3 py-2 cursor-pointer text-xs ${useStore ? 'border-emerald-500/50 bg-emerald-900/15' : 'border-gray-700'}`}>
              <input type="checkbox" className="mt-0.5" checked={useStore} onChange={(e) => setUseStore(e.target.checked)} />
              <span>
                <span className="text-gray-200 flex items-center gap-1.5"><Database className="h-3.5 w-3.5 text-emerald-400" /> Match against entire IOC Store ({storeTotal.toLocaleString()})</span>
                <span className="block text-[11px] text-gray-500 mt-0.5">Matched server-side against the whole store by indexed lookup — the store is never downloaded, so it scales to a very large (TB) store.</span>
              </span>
            </label>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={run} disabled={running || !agentId || (indicators.length === 0 && !useStore)}
            className="btn-primary flex items-center gap-2 disabled:opacity-50">
            {running ? <><Loader2 className="h-4 w-4 animate-spin" /> Sweeping…</> : <><Radar className="h-4 w-4" /> Run sweep</>}
          </button>
          <p className="text-[11px] text-gray-600">Collects live artifacts on the endpoint (one UAC prompt) and matches server-side. Works on Windows &amp; Linux agents.</p>
        </div>
      </div>

      {result && (
        <div className="card p-4 space-y-3">
          <div className="flex items-center gap-3 flex-wrap text-xs">
            <span className="text-gray-400">{result.indicators} indicator(s)</span>
            {(result.store_matched ?? 0) > 0 && <span className="text-gray-500">({result.store_matched} from store present on host)</span>}
            {result.matches.length > 0
              ? <span className="flex items-center gap-1 text-red-400 font-semibold"><AlertTriangle className="h-3.5 w-3.5" /> {result.matches.length} match(es)</span>
              : <span className="flex items-center gap-1 text-emerald-400 font-semibold">No matches — host clean</span>}
            <span className="text-gray-600 ml-auto">
              scanned: {Object.entries(result.scanned).map(([k, v]) => `${k} ${v}`).join(' · ')}
            </span>
          </div>

          {result.matches.length > 0 && (
            <>
              <div className="overflow-auto max-h-[480px] rounded-lg border border-gray-800">
                <table className="w-full text-xs">
                  <thead className="sticky top-0 bg-gray-900 z-10">
                    <tr className="border-b border-gray-800">
                      <th className="px-3 py-2 text-left text-gray-500 font-medium">Indicator</th>
                      <th className="px-3 py-2 text-left text-gray-500 font-medium">Type</th>
                      <th className="px-3 py-2 text-left text-gray-500 font-medium">Artifact</th>
                      <th className="px-3 py-2 text-left text-gray-500 font-medium">Where found</th>
                      <th className="px-3 py-2 text-right text-gray-500 font-medium w-10"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {result.matches.map((m, i) => (
                      <tr key={i} className="group border-b border-gray-900 hover:bg-white/5 bg-red-500/5">
                        <td className="px-3 py-1.5 font-mono text-red-300 break-all max-w-[220px]">{m.indicator}</td>
                        <td className="px-3 py-1.5"><span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${IND_BADGE[m.indicator_type] ?? 'text-gray-400 border-slate-700'}`}>{m.indicator_type}</span></td>
                        <td className="px-3 py-1.5 text-gray-400">{m.artifact}</td>
                        <td className="px-3 py-1.5 font-mono text-gray-300 break-all">{m.context}</td>
                        <td className="px-2 py-1.5 text-right">
                          {agent && (
                            <button onClick={() => setTraceTarget({ target: m.indicator, pid: 0 })}
                              title="Trace origin of this indicator on the endpoint (parent chain, download URL, execution)"
                              className="text-gray-500 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity">
                              <GitBranch className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
              <div className="flex items-center gap-2">
                <select className="input text-xs py-1.5 max-w-[200px]" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                  <option value="">Select case…</option>
                  {cases.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <button onClick={() => addMut.mutate()} disabled={!caseId || addMut.isPending}
                  className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50">
                  {addMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CalendarPlus className="h-3.5 w-3.5" />} Add matches to case timeline
                </button>
              </div>
            </>
          )}
        </div>
      )}

      {traceTarget && agent && (
        <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// Page shell with tabs
// ---------------------------------------------------------------------------
export default function HuntingPage() {
  const [tab, setTab] = useState<'scenarios' | 'deployments' | 'ioc-sweep'>('scenarios')

  return (
    <div className="space-y-5">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
          <Crosshair className="h-6 w-6 text-emerald-400" />
          Scenario Hunting
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Pre-built attack-scenario playbooks. One click deploys the full tool set to an agent;
          you then run each tool individually from the Deployments tab.
        </p>
      </div>

      <div className="flex items-center gap-1 border-b border-gray-800">
        {[
          { key: 'scenarios', label: 'Scenarios' },
          { key: 'deployments', label: 'Deployments' },
          { key: 'ioc-sweep', label: 'IOC Sweep' },
        ].map((t) => (
          <button
            key={t.key}
            onClick={() => setTab(t.key as 'scenarios' | 'deployments' | 'ioc-sweep')}
            className={`px-4 py-2 text-sm font-medium transition border-b-2 -mb-px ${
              tab === t.key
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-gray-400 hover:text-gray-200'
            }`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {tab === 'scenarios' && <ScenariosTab />}
      {tab === 'deployments' && <DeploymentsTab />}
      {tab === 'ioc-sweep' && <IOCSweepTab />}
    </div>
  )
}
