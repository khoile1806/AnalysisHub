import { useState, useEffect, useMemo, useRef, type FormEvent } from 'react'
import { useParams, useNavigate, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Plus, Eye, Server, Network, Cpu, ClipboardList, Trash2, Eraser, Play, Square, Terminal as TerminalIcon, FolderTree, Briefcase, Shield, Database, HardDrive, GitBranch, ScrollText } from 'lucide-react'
import toast from 'react-hot-toast'
import { agentsApi, type Agent } from '@/api/agents'
import { logsearchApi } from '@/api/logsearch'
import { casesApi } from '@/api/cases'
import { jobsApi, type Job } from '@/api/jobs'
import { toolsApi, TOOL_CATEGORIES } from '@/api/tools'
import { AgentStatusBadge, JobStatusBadge } from '@/components/StatusBadge'
import { AgentTerminal } from '@/components/AgentTerminal'
import { FileBrowser } from '@/components/FileBrowser'
import { YaraScanner } from '@/components/Agent/YaraScanner'
import { RegistryViewer } from '@/components/Agent/RegistryViewer'
import { EvtxViewer } from '@/components/Agent/EvtxViewer'
import TraceOriginModal from '@/components/Agent/TraceOriginModal'
import { EdgeForensics } from '@/components/Agent/EdgeForensics'
import { formatDuration, getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
  DialogDescription, DialogFooter, DialogBody,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger,
  SelectValue, SelectGroup, SelectLabel,
} from '@/components/ui/select'
import { useAuthStore } from '@/store/auth'

// Types for monitor data
interface ProcessInfo { pid: number; ppid: number; name: string; mem_kb: number; cmdline: string }
interface NetConn { proto: string; local: string; remote: string; state: string }
interface DiskInfo { name: string; total_gb: number; free_gb: number }
interface SysInfo { cpu_model: string; cpu_cores: number; ram_total_mb: number; ram_free_mb: number; disks: DiskInfo[] }

// ---- Keep Alive Tab Wrapper ----
function KeepAliveTab({ active, children }: { active: boolean; children: React.ReactNode }) {
  const [mounted, setMounted] = useState(active)
  useEffect(() => {
    if (active && !mounted) setMounted(true)
  }, [active, mounted])

  if (!mounted) return null
  return <div className={active ? 'block' : 'hidden'} style={{ height: '100%' }}>{children}</div>
}

// ---- Create Job Modal (pre-filled with agentId) ----
function CreateJobModal({ agentId, open, onClose }: { agentId: string; open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [toolId, setToolId] = useState('')
	const [args, setArgs] = useState('')
	const [cpuLimit, setCpuLimit] = useState<number | ''>('')
	const [ramLimit, setRamLimit] = useState<number | ''>('')
	const [priority, setPriority] = useState('normal')

  const { data: tools = [] } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list(),
    enabled: open,
  })

  const handleToolChange = (id: string) => {
    setToolId(id)
    const t = tools.find((t) => t.id === id)
    if (t?.args) setArgs(t.args)
  }

  const createMutation = useMutation({
    mutationFn: jobsApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-jobs', agentId] })
      toast.success('Job dispatched')
      onClose()
      setToolId('')
      setArgs('')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!toolId) { toast.error('Select a tool'); return }
		createMutation.mutate({
			agent_id: agentId,
			tool_id: toolId,
			args: args || undefined,
			cpu_limit: cpuLimit ? Number(cpuLimit) : undefined,
			ram_limit: ramLimit ? Number(ramLimit) : undefined,
			priority: priority !== 'normal' ? priority : undefined
		})
  }

  const toolsByCategory = TOOL_CATEGORIES.reduce<Record<string, typeof tools>>((acc, cat) => {
    const catTools = tools.filter((t) => t.category === cat)
    if (catTools.length) acc[cat] = catTools
    return acc
  }, {})

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { setToolId(''); setArgs(''); onClose() } }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Dispatch Job</DialogTitle>
          <DialogDescription>Run a forensic tool on this agent</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div>
              <label className="label">Tool *</label>
              <Select value={toolId} onValueChange={handleToolChange}>
                <SelectTrigger><SelectValue placeholder="Select a tool…" /></SelectTrigger>
                <SelectContent>
                  {Object.entries(toolsByCategory).map(([cat, catTools]) => (
                    <SelectGroup key={cat}>
                      <SelectLabel>{cat}</SelectLabel>
                      {catTools.map((t) => (
                        <SelectItem key={t.id} value={t.id}>
                          {t.name} <span className="text-gray-500 text-xs ml-1">v{t.version}</span>
                        </SelectItem>
                      ))}
                    </SelectGroup>
                  ))}
                  {tools.length === 0 && <SelectItem value="__none__" disabled>No tools available</SelectItem>}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="label">Arguments <span className="text-xs text-gray-500">(optional)</span></label>
              <input className="input font-mono text-xs" value={args} onChange={(e) => setArgs(e.target.value)} placeholder="e.g. -f evidence.raw" />
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
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
              {createMutation.isPending
                ? <><span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> Dispatching…</>
                : <><Plus className="h-4 w-4" /> Dispatch</>}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Delete Job Modal ----
function DeleteJobModal({ job, onClose }: { job: Job | null; onClose: () => void }) {
  const qc = useQueryClient()
  const deleteMutation = useMutation({
    mutationFn: () => jobsApi.delete(job!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agent-jobs', job!.agent_id] })
      toast.success('Job deleted')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <Dialog open={!!job} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Delete Job</DialogTitle>
          <DialogDescription>This action cannot be undone.</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <p className="text-sm text-gray-300">
            Delete job <span className="font-mono text-white">{job?.id.slice(0, 8)}…</span>? The output and any artifacts will be removed.
          </p>
        </DialogBody>
        <DialogFooter>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button className="btn-danger" onClick={() => deleteMutation.mutate()} disabled={deleteMutation.isPending}>
            {deleteMutation.isPending ? 'Deleting…' : 'Delete Job'}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- Jobs Tab ----
function JobsTab({ agent }: { agent: Agent }) {
  const qc = useQueryClient()
  const [newJobOpen, setNewJobOpen] = useState(false)
  const [deleteTarget, setDeleteTarget] = useState<Job | null>(null)

  const { data: jobs = [], isLoading } = useQuery({
    queryKey: ['agent-jobs', agent.id],
    queryFn: () => jobsApi.list({ agent_id: agent.id }),
    refetchInterval: 5_000,
  })

  const runMutation = useMutation({
    mutationFn: (id: string) => jobsApi.run(id),
    onSuccess: () => {
      toast.success('Job started')
      qc.invalidateQueries({ queryKey: ['agent-jobs', agent.id] })
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const stopMutation = useMutation({
    mutationFn: (id: string) => jobsApi.stop(id),
    onSuccess: () => {
      toast.success('Job stopped')
      qc.invalidateQueries({ queryKey: ['agent-jobs', agent.id] })
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const sorted = useMemo(
    () => [...jobs].sort((a, b) => new Date(b.created_at).getTime() - new Date(a.created_at).getTime()),
    [jobs],
  )

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">{jobs.length} job{jobs.length !== 1 ? 's' : ''} total</p>
        <button className="btn-primary" onClick={() => setNewJobOpen(true)} disabled={agent.status !== 'online'}>
          <Plus className="h-4 w-4" /> New Job
        </button>
      </div>

      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6 space-y-3">{[...Array(4)].map((_, i) => <div key={i} className="skeleton h-12 w-full rounded" />)}</div>
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-gray-500">
              <ClipboardList className="h-8 w-8 mb-2 opacity-30" />
              <p className="text-sm">No jobs for this agent yet</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-4 py-3">Job ID</th>
                  <th className="table-header text-left px-4 py-3">Tool</th>
                  <th className="table-header text-left px-4 py-3">Status</th>
                  <th className="table-header text-left px-4 py-3 hidden md:table-cell">Duration</th>
                  <th className="table-header text-left px-4 py-3 hidden lg:table-cell">Created</th>
                  <th className="table-header text-right px-4 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((job) => (
                  <tr key={job.id} className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
                    <td className="px-4 py-3"><span className="font-mono text-xs text-gray-400">{job.id.slice(0, 8)}…</span></td>
                    <td className="px-4 py-3">
                      <div className="text-sm font-medium text-gray-200">{job.tool?.name ?? job.tool_id}</div>
                      {job.args && <code className="text-[10px] text-amber-400/70 font-mono mt-0.5 block truncate max-w-[180px]">{job.args}</code>}
                    </td>
                    <td className="px-4 py-3"><JobStatusBadge status={job.status} /></td>
                    <td className="px-4 py-3 hidden md:table-cell text-xs text-gray-400 font-mono">
                      {job.started_at ? formatDuration(job.started_at, job.finished_at) : '—'}
                    </td>
                    <td className="px-4 py-3 hidden lg:table-cell text-xs text-gray-500">
                      {safeDistanceToNow(job.created_at, { addSuffix: true })}
                    </td>
                    <td className="px-4 py-3 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <Link
                          to={`/jobs/${job.id}`}
                          className="inline-flex items-center gap-1 p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors"
                          title="View job"
                        >
                          <Eye className="h-3.5 w-3.5" />
                        </Link>
                        {(job.status === 'ready' || job.status === 'stopped') && (
                          <button
                            onClick={() => runMutation.mutate(job.id)}
                            disabled={runMutation.isPending || agent.status !== 'online'}
                            className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                            title={job.status === 'stopped' ? 'Run again' : 'Run job'}
                          >
                            <Play className="h-3.5 w-3.5" />
                          </button>
                        )}
                        {job.status === 'running' && (
                          <button
                            onClick={() => stopMutation.mutate(job.id)}
                            disabled={stopMutation.isPending}
                            className="p-1.5 text-gray-400 hover:text-amber-400 hover:bg-amber-900/20 rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                            title="Stop job"
                          >
                            <Square className="h-3.5 w-3.5" />
                          </button>
                        )}
                        {(job.status === 'done' || job.status === 'failed' || job.status === 'stopped') && (
                          <button
                            onClick={() => setDeleteTarget(job)}
                            className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors"
                            title="Delete job"
                          >
                            <Trash2 className="h-3.5 w-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <CreateJobModal agentId={agent.id} open={newJobOpen} onClose={() => setNewJobOpen(false)} />
      <DeleteJobModal job={deleteTarget} onClose={() => setDeleteTarget(null)} />
    </div>
  )
}

// ---- System Info Tab ----
function SysInfoTab({ agent }: { agent: Agent }) {
  const isOnline = agent.status === 'online'
  const { data: sysInfoArr } = useRealtimeSSE<SysInfo>(agent.id, 'sysinfo', isOnline)
  // sysinfo payload is a single object wrapped in an array by the generic hook
  const hw = sysInfoArr?.[0] ?? null

  const machineFields = [
    { label: 'Hostname',    value: agent.hostname   || '—' },
    { label: 'OS',          value: agent.os         || '—' },
    { label: 'IP Address',  value: agent.ip_address || '—' },
    { label: 'Status',      value: agent.status },
    { label: 'Last Seen',   value: agent.last_seen ? safeDistanceToNow(agent.last_seen, { addSuffix: true }) : 'Never' },
    { label: 'Agent ID',    value: agent.id },
  ]

  return (
    <div className="space-y-4">
      {/* Machine identity */}
      <div className="card p-0 overflow-hidden">
        <div className="px-5 py-3 border-b border-gray-800">
          <h3 className="text-sm font-medium text-gray-200 flex items-center gap-2">
            <Server className="h-4 w-4 text-emerald-400" /> Machine Information
          </h3>
        </div>
        <dl className="divide-y divide-gray-800">
          {machineFields.map(({ label, value }) => (
            <div key={label} className="px-5 py-3 flex items-center justify-between">
              <dt className="text-xs text-gray-500 font-medium w-32 shrink-0">{label}</dt>
              <dd className="text-sm text-gray-200 font-mono text-right break-all">{value}</dd>
            </div>
          ))}
        </dl>
      </div>

      {/* Hardware — only when agent is online and data arrives */}
      {!isOnline ? (
        <div className="card flex items-center justify-center py-8 text-gray-500 text-sm">
          Agent offline — hardware info available when connected
        </div>
      ) : !hw ? (
        <div className="card p-5 space-y-3">
          {[...Array(4)].map((_, i) => <div key={i} className="skeleton h-8 w-full rounded" />)}
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* CPU + RAM */}
          <div className="card p-0 overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-800 text-sm font-medium text-gray-200">CPU / Memory</div>
            <dl className="divide-y divide-gray-800">
              <div className="px-5 py-3 flex items-center justify-between">
                <dt className="text-xs text-gray-500 w-28 shrink-0">CPU Model</dt>
                <dd className="text-xs text-gray-200 font-mono text-right">{hw.cpu_model || '—'}</dd>
              </div>
              <div className="px-5 py-3 flex items-center justify-between">
                <dt className="text-xs text-gray-500 w-28 shrink-0">CPU Cores</dt>
                <dd className="text-xs text-gray-200 font-mono">{hw.cpu_cores}</dd>
              </div>
              <div className="px-5 py-3 flex items-center justify-between">
                <dt className="text-xs text-gray-500 w-28 shrink-0">RAM Total</dt>
                <dd className="text-xs text-gray-200 font-mono">{(hw.ram_total_mb / 1024).toFixed(1)} GB</dd>
              </div>
              <div className="px-5 py-3 flex items-center justify-between">
                <dt className="text-xs text-gray-500 w-28 shrink-0">RAM Free</dt>
                <dd className="text-xs text-gray-200 font-mono">
                  {(hw.ram_free_mb / 1024).toFixed(1)} GB
                  <span className="text-gray-500 ml-1">
                    ({hw.ram_total_mb > 0 ? Math.round((hw.ram_free_mb / hw.ram_total_mb) * 100) : 0}% free)
                  </span>
                </dd>
              </div>
            </dl>
          </div>

          {/* Disks */}
          <div className="card p-0 overflow-hidden">
            <div className="px-5 py-3 border-b border-gray-800 text-sm font-medium text-gray-200">
              Disks <span className="text-gray-500 font-normal text-xs ml-1">({hw.disks?.length ?? 0} volume{hw.disks?.length !== 1 ? 's' : ''})</span>
            </div>
            {hw.disks?.length ? (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-gray-800">
                      <th className="table-header text-left px-4 py-2">Drive</th>
                      <th className="table-header text-right px-4 py-2">Total</th>
                      <th className="table-header text-right px-4 py-2">Free</th>
                      <th className="table-header text-right px-4 py-2">Used%</th>
                    </tr>
                  </thead>
                  <tbody>
                    {hw.disks.map((d) => {
                      const usedPct = d.total_gb > 0 ? Math.round(((d.total_gb - d.free_gb) / d.total_gb) * 100) : 0
                      return (
                        <tr key={d.name} className="border-b border-gray-800/40">
                          <td className="px-4 py-2 text-xs font-mono text-emerald-400">{d.name}</td>
                          <td className="px-4 py-2 text-xs font-mono text-gray-300 text-right">{d.total_gb.toFixed(1)} GB</td>
                          <td className="px-4 py-2 text-xs font-mono text-gray-300 text-right">{d.free_gb.toFixed(1)} GB</td>
                          <td className="px-4 py-2 text-xs font-mono text-right">
                            <span className={usedPct > 90 ? 'text-red-400' : usedPct > 70 ? 'text-amber-400' : 'text-gray-400'}>
                              {usedPct}%
                            </span>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            ) : (
              <div className="px-5 py-4 text-xs text-gray-500">No disk data</div>
            )}
          </div>
        </div>
      )}
    </div>
  )
}

// ---- Realtime SSE hook ----
function useRealtimeSSE<T>(agentId: string, dataType: 'processes' | 'netstat' | 'sysinfo', enabled: boolean) {
  const [data, setData] = useState<T[] | null>(null)
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const token = useAuthStore((s) => s.token)

  useEffect(() => {
    if (!enabled) return

    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const tokenParam = token ? `&token=${encodeURIComponent(token)}` : ''
    const url = `${base}/api/v1/agents/${agentId}/monitor?type=${dataType}${tokenParam}`
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data)
        // sysinfo payload is an object; others are arrays
        setData(Array.isArray(parsed) ? (parsed as T[]) : [parsed as T])
        setConnected(true)
      } catch {
        // ignore parse errors
      }
    }
    es.onerror = () => {
      setConnected(false)
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [agentId, dataType, enabled, token])

  return { data, connected }
}

// ---- Network Tab ----
function NetworkTab({ agent }: { agent: Agent }) {
  const isOnline = agent.status === 'online'
  const { data: conns, connected } = useRealtimeSSE<NetConn>(agent.id, 'netstat', isOnline)

  if (!isOnline) {
    return (
      <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
        <Network className="h-10 w-10 mb-3 opacity-30" />
        <p className="text-sm">Agent is offline — connect the agent to view network data</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs text-gray-400">
        <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
        {connected ? 'Receiving live data' : 'Waiting for agent data…'}
      </div>
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {!conns ? (
            <div className="p-6 space-y-2">{[...Array(6)].map((_, i) => <div key={i} className="skeleton h-8 w-full rounded" />)}</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-4 py-2">Proto</th>
                  <th className="table-header text-left px-4 py-2">Local Address</th>
                  <th className="table-header text-left px-4 py-2">Remote Address</th>
                  <th className="table-header text-left px-4 py-2">State</th>
                </tr>
              </thead>
              <tbody>
                {conns.map((c, i) => (
                  <tr key={i} className="border-b border-gray-800/40 hover:bg-gray-800/20">
                    <td className="px-4 py-2 text-xs font-mono text-emerald-400">{c.proto}</td>
                    <td className="px-4 py-2 text-xs font-mono text-gray-300">{c.local}</td>
                    <td className="px-4 py-2 text-xs font-mono text-gray-300">{c.remote}</td>
                    <td className="px-4 py-2 text-xs text-gray-400">{c.state}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
      <p className="text-xs text-gray-600">Updated every 1 second · {conns?.length ?? 0} connections</p>
    </div>
  )
}

// ---- Processes Tab ----
function ProcessesTab({ agent }: { agent: Agent }) {
  const isOnline = agent.status === 'online'
  const { data: procs, connected } = useRealtimeSSE<ProcessInfo>(agent.id, 'processes', isOnline)
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)

  const sorted = useMemo(() => (procs ? [...procs].sort((a, b) => b.mem_kb - a.mem_kb) : null), [procs])

  if (!isOnline) {
    return (
      <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
        <Cpu className="h-10 w-10 mb-3 opacity-30" />
        <p className="text-sm">Agent is offline — connect the agent to view process data</p>
      </div>
    )
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-2 text-xs text-gray-400">
        <span className={`h-2 w-2 rounded-full ${connected ? 'bg-emerald-400 animate-pulse' : 'bg-gray-600'}`} />
        {connected ? 'Receiving live data' : 'Waiting for agent data…'}
      </div>
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {!sorted ? (
            <div className="p-6 space-y-2">{[...Array(8)].map((_, i) => <div key={i} className="skeleton h-8 w-full rounded" />)}</div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-4 py-2">PID</th>
                  <th className="table-header text-left px-4 py-2">PPID</th>
                  <th className="table-header text-left px-4 py-2">Name</th>
                  <th className="table-header text-right px-4 py-2">Memory</th>
                  <th className="table-header text-left px-4 py-2 hidden xl:table-cell">Command Line</th>
                  <th className="table-header text-right px-4 py-2 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((p, i) => (
                  <tr key={i} className="group border-b border-gray-800/40 hover:bg-gray-800/20">
                    <td className="px-4 py-1.5 text-xs font-mono text-gray-500">{p.pid}</td>
                    <td className="px-4 py-1.5 text-xs font-mono text-gray-600">{p.ppid || '—'}</td>
                    <td className="px-4 py-1.5 text-xs font-mono text-gray-200">{p.name}</td>
                    <td className="px-4 py-1.5 text-xs font-mono text-right text-gray-400">
                      {p.mem_kb >= 1024 ? `${(p.mem_kb / 1024).toFixed(1)} MB` : `${p.mem_kb} KB`}
                    </td>
                    <td className="px-4 py-1.5 text-xs font-mono text-gray-500 hidden xl:table-cell max-w-xs truncate" title={p.cmdline}>
                      {p.cmdline || '—'}
                    </td>
                    <td className="px-2 py-1.5 text-right">
                      <button
                        onClick={() => setTraceTarget({ target: p.name, pid: p.pid })}
                        title="Trace this process's origin (parent chain, user, when)"
                        className="text-gray-500 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity"
                      >
                        <GitBranch className="h-3.5 w-3.5" />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>
      <p className="text-xs text-gray-600">Updated every 1 second · {sorted?.length ?? 0} processes · sorted by memory</p>
      {traceTarget && <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />}
    </div>
  )
}

// ---- Main Page ----
type TabId = 'jobs' | 'sysinfo' | 'network' | 'processes' | 'terminal' | 'files' | 'scanner' | 'registry' | 'evtx' | 'edge-forensics'

const TABS: { id: TabId; label: string; icon: typeof Server }[] = [
  { id: 'jobs',      label: 'Jobs',        icon: ClipboardList },
  { id: 'sysinfo',   label: 'System Info', icon: Server },
  { id: 'network',   label: 'Network',     icon: Network },
  { id: 'processes', label: 'Processes',   icon: Cpu },
  { id: 'terminal',  label: 'Terminal',    icon: TerminalIcon },
  { id: 'files',     label: 'Files',       icon: FolderTree },
  { id: 'scanner',   label: 'Scanner',     icon: Shield as any },
  { id: 'registry',  label: 'Registry Viewer', icon: Database as any },
  { id: 'evtx',      label: 'EVTX Logs',   icon: Server as any },
  { id: 'edge-forensics', label: 'Edge Forensics', icon: HardDrive as any },
]

export default function AgentDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [activeTab, setActiveTab] = useState<TabId>('jobs')
  const [cleanupOpen, setCleanupOpen] = useState(false)
  const [linkCaseOpen, setLinkCaseOpen] = useState(false)
  const [selectedCaseId, setSelectedCaseId] = useState('__none__')

  const { data: cases = [] } = useQuery({
    queryKey: ['cases'],
    queryFn: casesApi.list,
    enabled: !!id, // always loaded so the header can show the linked case name
  })

  const linkCaseMutation = useMutation({
    mutationFn: (caseId: string) => agentsApi.update(id!, { case_id: caseId === '__none__' ? '' : caseId }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents', id] })
      qc.invalidateQueries({ queryKey: ['cases'] })
      setLinkCaseOpen(false)
      toast.success(selectedCaseId !== '__none__' ? 'Agent linked to case' : 'Agent unlinked from case')
    },
    onError: (err: unknown) => toast.error(getErrorMessage(err)),
  })

  const { data: agent, isLoading, error } = useQuery({
    queryKey: ['agents', id],
    queryFn: () => agentsApi.get(id!),
    refetchInterval: 10_000,
    enabled: !!id,
  })

  const collectLogsMutation = useMutation({
    mutationFn: () => {
      const linked = cases.find((c: any) => c.id === agent?.case_id)
      return logsearchApi.collectFromAgent(id!, { case: linked?.name, days: 7 })
    },
    onSuccess: (r) =>
      toast.success(`Collecting OS logs from ${r.host || 'host'} → Log Ingest (case "${r.case}")`),
    onError: (err: unknown) => toast.error(getErrorMessage(err)),
  })

  const cleanupMutation = useMutation({
    mutationFn: () => agentsApi.cleanup(id!),
    onSuccess: () => {
      toast.success('Cleanup dispatched — agent is removing itself')
      qc.invalidateQueries({ queryKey: ['agents'] })
      setCleanupOpen(false)
      navigate('/agents')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  if (isLoading) {
    return (
      <div className="space-y-5">
        <div className="skeleton h-10 w-64 rounded" />
        <div className="skeleton h-40 w-full rounded" />
      </div>
    )
  }

  if (error || !agent) {
    return (
      <div className="flex flex-col items-center justify-center py-24 text-gray-500">
        <Server className="h-12 w-12 mb-3 opacity-30" />
        <p className="text-sm">Agent not found</p>
        <button className="mt-4 btn-secondary text-xs" onClick={() => navigate('/agents')}>Back to Agents</button>
      </div>
    )
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
        <div className="flex items-center gap-3">
          <button
            onClick={() => navigate('/agents')}
            className="p-1.5 text-gray-400 hover:text-gray-200 hover:bg-gray-800 rounded transition-colors"
          >
            <ArrowLeft className="h-4 w-4" />
          </button>
          <div>
            <div className="flex items-center gap-3">
              <h1 className="text-xl font-semibold text-gray-100">{agent.name}</h1>
              <AgentStatusBadge status={agent.status} />
            </div>
            <p className="text-sm text-gray-400 mt-0.5 font-mono">
              {agent.hostname || 'no hostname'} · {agent.ip_address || 'no IP'} · {agent.os || 'unknown OS'}
            </p>
          </div>
        </div>
        {/* Action group — kept together on the right so the header reads
            [identity] … [Link to Case] [Cleanup] rather than scattering. */}
        <div className="flex items-center gap-2 shrink-0 self-start">
          {(() => {
            const linkedCase = cases.find((c: any) => c.id === agent.case_id)
            const isLinked = !!agent.case_id
            return (
              <button
                onClick={() => { setSelectedCaseId(agent.case_id ?? '__none__'); setLinkCaseOpen(true) }}
                className={`text-xs flex items-center gap-1.5 px-3 py-1.5 rounded-lg border transition-colors max-w-[240px] ${
                  isLinked
                    ? 'bg-emerald-500/10 border-emerald-500/30 text-emerald-300 hover:bg-emerald-500/15'
                    : 'btn-secondary'
                }`}
                title={isLinked ? `Linked to case "${linkedCase?.name ?? agent.case_id}" — click to change or unlink` : 'Link this agent to a case'}
              >
                <Briefcase className="h-3.5 w-3.5 shrink-0" />
                {isLinked ? (
                  <span className="truncate">Case: <span className="font-medium">{linkedCase?.name ?? 'linked'}</span></span>
                ) : 'Link to Case'}
              </button>
            )
          })()}
          <button
            onClick={() => collectLogsMutation.mutate()}
            disabled={agent.status !== 'online' || collectLogsMutation.isPending}
            className="btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
            title={agent.status !== 'online'
              ? 'Agent must be online'
              : 'Auto-detect OS and collect all logs into Log Ingest (grouped by this host)'}
          >
            <ScrollText className="h-3.5 w-3.5" />
            {collectLogsMutation.isPending ? 'Collecting…' : 'Collect Logs'}
          </button>
          <button
            onClick={() => setCleanupOpen(true)}
            disabled={agent.status !== 'online'}
            className="btn-danger text-xs flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
            title={agent.status !== 'online' ? 'Agent must be online' : 'Remove all agent files and self-uninstall'}
          >
            <Eraser className="h-3.5 w-3.5" />
            Cleanup & Uninstall
          </button>
        </div>
      </div>

      {/* Link to Case Dialog */}
      <Dialog open={linkCaseOpen} onOpenChange={setLinkCaseOpen}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Link Agent to Case</DialogTitle>
            <DialogDescription>
              Associating this agent with a case will include its jobs and checklist results in the case timeline.
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <label className="label">Select Case</label>
            <Select value={selectedCaseId} onValueChange={setSelectedCaseId}>
              <SelectTrigger>
                <SelectValue placeholder="No case (unlink)" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="__none__">No case (unlink)</SelectItem>
                {cases.filter(c => c.status === 'open').map(c => (
                  <SelectItem key={c.id} value={c.id}>{c.name}</SelectItem>
                ))}
              </SelectContent>
            </Select>
          </DialogBody>
          <DialogFooter>
            <button className="btn-secondary text-xs" onClick={() => setLinkCaseOpen(false)}>Cancel</button>
            <button
              className="btn-primary text-xs"
              onClick={() => linkCaseMutation.mutate(selectedCaseId)}
              disabled={linkCaseMutation.isPending}
            >
              {linkCaseMutation.isPending ? 'Saving…' : 'Save'}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      <Dialog open={cleanupOpen} onOpenChange={setCleanupOpen}>
        <DialogContent className="max-w-md">
          <DialogHeader>
            <DialogTitle>Cleanup & Uninstall Agent</DialogTitle>
            <DialogDescription>
              This will command the agent to delete every file it created (tools, work directory, logs, config) and then remove its own binary. The target machine will be restored to its pre-install state.
            </DialogDescription>
          </DialogHeader>
          <DialogBody>
            <div className="rounded border border-red-900/50 bg-red-950/20 p-3 text-xs text-red-300">
              This action is irreversible. The agent record will be removed from the dashboard and any running jobs will be marked as failed.
            </div>
          </DialogBody>
          <DialogFooter>
            <button className="btn-secondary text-xs" onClick={() => setCleanupOpen(false)} disabled={cleanupMutation.isPending}>
              Cancel
            </button>
            <button
              className="btn-danger text-xs"
              onClick={() => cleanupMutation.mutate()}
              disabled={cleanupMutation.isPending}
            >
              {cleanupMutation.isPending ? 'Dispatching…' : 'Cleanup & Uninstall'}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Tabs */}
      <div className="border-b border-gray-800">
        <nav className="flex gap-1 -mb-px overflow-x-auto whitespace-nowrap">
          {TABS.map(({ id: tabId, label, icon: Icon }) => (
            <button
              key={tabId}
              onClick={() => setActiveTab(tabId)}
              className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
                activeTab === tabId
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-gray-400 hover:text-gray-200 hover:border-gray-600'
              }`}
            >
              <Icon className="h-4 w-4" />
              {label}
            </button>
          ))}
        </nav>
      </div>

      {/* Tab content */}
      <KeepAliveTab active={activeTab === 'jobs'}><JobsTab agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'sysinfo'}><SysInfoTab agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'network'}><NetworkTab agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'processes'}><ProcessesTab agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'terminal'}><AgentTerminal agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'files'}><FileBrowser agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'scanner'}><YaraScanner agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'registry'}><RegistryViewer agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'evtx'}><EvtxViewer agent={agent} /></KeepAliveTab>
      <KeepAliveTab active={activeTab === 'edge-forensics'}><EdgeForensics agent={agent} /></KeepAliveTab>
    </div>
  )
}
