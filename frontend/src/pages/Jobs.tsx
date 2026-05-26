import { useState, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import { Plus, ClipboardList, Eye } from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { jobsApi, type JobStatus } from '@/api/jobs'
import { agentsApi } from '@/api/agents'
import { toolsApi, TOOL_CATEGORIES } from '@/api/tools'
import { JobStatusBadge } from '@/components/StatusBadge'
import { formatDuration, getErrorMessage } from '@/lib/utils'
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
  const [agentId, setAgentId] = useState('')
  const [toolId, setToolId] = useState('')
  const [args, setArgs] = useState('')

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
      onClose()
      setAgentId(''); setToolId(''); setArgs('')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!agentId) { toast.error('Select an agent'); return }
    if (!toolId)  { toast.error('Select a tool');  return }
    createMutation.mutate({ agent_id: agentId, tool_id: toolId, args: args || undefined })
  }

  // Group tools by category for the dropdown
  const toolsByCategory = TOOL_CATEGORIES.reduce<Record<string, typeof tools>>((acc, cat) => {
    const catTools = tools.filter((t) => t.category === cat)
    if (catTools.length) acc[cat] = catTools
    return acc
  }, {})

  const onlineAgents = agents.filter((a) => a.status === 'online')
  const offlineAgents = agents.filter((a) => a.status === 'offline')

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { setAgentId(''); setToolId(''); setArgs(''); onClose() } }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create New Job</DialogTitle>
          <DialogDescription>Dispatch a forensic tool to a remote agent</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            {/* Agent select */}
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
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={() => { setAgentId(''); setToolId(''); setArgs(''); onClose() }}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
              {createMutation.isPending ? (
                <><span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> Dispatching…</>
              ) : (
                <><Plus className="h-4 w-4" /> Create Job</>
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
                  <th className="table-header text-right px-5 py-3">View</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((job) => (
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
                      {formatDistanceToNow(new Date(job.created_at), { addSuffix: true })}
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
