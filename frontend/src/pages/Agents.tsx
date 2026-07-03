import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Copy, Server, Trash2, Settings, CheckCircle, Terminal } from 'lucide-react'
import toast from 'react-hot-toast'
import { agentsApi, type Agent } from '@/api/agents'
import { AgentStatusBadge } from '@/components/StatusBadge'
import Pagination from '@/components/ui/Pagination'
import { getErrorMessage, copyToClipboard, safeDistanceToNow } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogBody,
} from '@/components/ui/dialog'

// Build the one-liner install command for a given platform.
// VITE_API_URL is the backend origin (e.g. http://192.168.1.10:8080).
// When not set (production behind nginx), fall back to window.location.origin
// since nginx proxies /api/ to the backend on the same origin.
function buildInstallCmd(agent: { id: string; token?: string; name: string }, platform: 'windows' | 'linux'): string {
  const base = (import.meta.env.VITE_API_URL as string | undefined) || window.location.origin
  const url = `${base}/api/v1/agents/${agent.id}/install.${platform === 'windows' ? 'ps1' : 'sh'}?token=${agent.token ?? ''}`
  if (platform === 'windows') {
    return `iex (irm "${url}")`
  }
  return `curl -fsSL "${url}" | bash`
}

// ---- New Agent Modal ----
interface NewAgentModalProps {
  open: boolean
  onClose: () => void
}

function NewAgentModal({ open, onClose }: NewAgentModalProps) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')
  const [caseId, setCaseId] = useState<string>('')
  const [newAgent, setNewAgent] = useState<Agent | null>(null)
  const [installPlatform, setInstallPlatform] = useState<'windows' | 'linux'>('windows')

  const { data: cases = [] } = useQuery({
    queryKey: ['cases'],
    queryFn: async () => {
      const { data } = await import('@/api/client').then(m => m.default.get('/cases'));
      return data;
    },
  })

  const createMutation = useMutation({
    mutationFn: (payload: any) => agentsApi.create(payload),
    onSuccess: (agent) => {
      qc.invalidateQueries({ queryKey: ['agents'] })
      setNewAgent(agent)
      toast.success('Agent created successfully')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) { toast.error('Agent name is required'); return }
    createMutation.mutate({ name: name.trim(), description, case_id: caseId || null })
  }

  const handleClose = () => {
    setName(''); setDescription(''); setCaseId(''); setNewAgent(null)
    onClose()
  }

  const copyToken = async () => {
    if (newAgent?.token) {
      const success = await copyToClipboard(newAgent.token)
      if (success) toast.success('Token copied to clipboard')
      else toast.error('Failed to copy token')
    }
  }

  const copyInstallCmd = async () => {
    if (!newAgent?.token) return
    const success = await copyToClipboard(buildInstallCmd(newAgent, installPlatform))
    if (success) toast.success('Install command copied to clipboard')
    else toast.error('Failed to copy command')
  }

  // After creation, show the token + one-click install command
  if (newAgent) {
    return (
      <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose() }}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <CheckCircle className="h-5 w-5 text-emerald-400" />
              Agent Created
            </DialogTitle>
            <DialogDescription>
              Save the agent token — it will only be shown once.
            </DialogDescription>
          </DialogHeader>
          <DialogBody className="space-y-4">
            <div className="rounded-lg bg-yellow-900/20 border border-yellow-700/40 p-3">
              <p className="text-xs text-yellow-400 font-medium">
                ⚠ Copy the token or install command now. The token cannot be retrieved again.
              </p>
            </div>

            {/* Token */}
            <div>
              <label className="label">Agent Token</label>
              <div className="relative">
                <code className="block input bg-gray-950 font-mono text-xs text-emerald-400 break-all pr-10">
                  {newAgent.token}
                </code>
                <button
                  onClick={copyToken}
                  className="absolute right-2 top-2 p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
                  title="Copy token"
                >
                  <Copy className="h-4 w-4" />
                </button>
              </div>
            </div>

            {/* One-click install command */}
            <div>
              <div className="flex items-center gap-2 mb-2">
                <Terminal className="h-3.5 w-3.5 text-emerald-400" />
                <label className="label mb-0">One-Click Install</label>
              </div>

              {/* Platform tabs */}
              <div className="flex gap-1 mb-2">
                {(['windows', 'linux'] as const).map((p) => (
                  <button
                    key={p}
                    onClick={() => setInstallPlatform(p)}
                    className={`px-3 py-1 text-xs rounded font-mono transition-colors ${
                      installPlatform === p
                        ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-700/50'
                        : 'text-gray-500 hover:text-gray-300 border border-transparent'
                    }`}
                  >
                    {p === 'windows' ? 'Windows (PowerShell)' : 'Linux (bash)'}
                  </button>
                ))}
              </div>

              <div className="relative">
                <pre className="input bg-gray-950 font-mono text-xs text-amber-400 break-all whitespace-pre-wrap pr-10 leading-relaxed">
                  {buildInstallCmd(newAgent, installPlatform)}
                </pre>
                <button
                  onClick={copyInstallCmd}
                  className="absolute right-2 top-2 p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
                  title="Copy command"
                >
                  <Copy className="h-4 w-4" />
                </button>
              </div>
              <p className="text-xs text-gray-500 mt-1.5">
                Run this on the target machine — it downloads the agent binary and starts it automatically.
              </p>
            </div>
          </DialogBody>
          <DialogFooter>
            <button className="btn-primary" onClick={handleClose}>Done</button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    )
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Register New Agent</DialogTitle>
          <DialogDescription>Add a new endpoint to AnalysisHub</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div>
              <label className="label">Agent Name *</label>
              <input
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. workstation-01"
                required
              />
            </div>
            <div>
              <label className="label">Assign to Case (Optional)</label>
              <select
                className="input"
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
              >
                <option value="">-- No Case --</option>
                {cases.map((c: any) => (
                  <option key={c.id} value={c.id}>
                    {c.name}
                  </option>
                ))}
              </select>
              <p className="text-[10px] text-gray-500 mt-1">
                Link this agent to an investigation case to track hunting actions. Create new cases in the Case Manager tab.
              </p>
            </div>
            <div>
              <label className="label">Description</label>
              <textarea
                className="input resize-none"
                rows={2}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Optional description for this agent"
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={handleClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
              {createMutation.isPending ? (
                <><span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> Creating…</>
              ) : (
                <><Plus className="h-4 w-4" /> Create Agent</>
              )}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Installer Config Modal ----
interface InstallerModalProps {
  agentId: string | null
  onClose: () => void
}

function InstallerModal({ agentId, onClose }: InstallerModalProps) {
  const [platform, setPlatform] = useState<'windows' | 'linux'>('windows')

  const { data, isLoading, error } = useQuery({
    queryKey: ['agent-installer', agentId],
    queryFn: () => agentsApi.getInstaller(agentId!),
    enabled: !!agentId,
  })

  const installCmd = data
    ? platform === 'windows'
      ? `iex (irm "${data.server_url}/api/v1/agents/${data.agent_id}/install.ps1?token=${data.token}")`
      : `curl -fsSL "${data.server_url}/api/v1/agents/${data.agent_id}/install.sh?token=${data.token}" | bash`
    : ''

  const configText = data
    ? `SERVER_URL=${data.server_url}\nAGENT_TOKEN=${data.token}\nAGENT_NAME=${data.agent_name}`
    : ''

  const copyCmd = async () => {
    const success = await copyToClipboard(installCmd)
    if (success) toast.success('Install command copied!')
    else toast.error('Failed to copy command')
  }

  const copyConfig = async () => {
    const success = await copyToClipboard(configText)
    if (success) toast.success('Config copied to clipboard')
    else toast.error('Failed to copy config')
  }

  return (
    <Dialog open={!!agentId} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="h-5 w-5 text-emerald-400" />
            Deploy Agent
          </DialogTitle>
          <DialogDescription>
            Run the command below on the target machine — the agent will be downloaded and started automatically.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-5">
          {isLoading ? (
            <div className="space-y-3">
              {[...Array(4)].map((_, i) => <div key={i} className="skeleton h-10 w-full rounded" />)}
            </div>
          ) : error ? (
            <p className="text-sm text-red-400">{getErrorMessage(error)}</p>
          ) : data ? (
            <>
              {/* Platform tabs */}
              <div className="flex gap-1">
                {(['windows', 'linux'] as const).map((p) => (
                  <button
                    key={p}
                    onClick={() => setPlatform(p)}
                    className={`px-3 py-1.5 text-xs rounded font-mono transition-colors ${
                      platform === p
                        ? 'bg-emerald-900/40 text-emerald-400 border border-emerald-700/50'
                        : 'text-gray-500 hover:text-gray-300 border border-gray-700/50'
                    }`}
                  >
                    {p === 'windows' ? '⊞ Windows (PowerShell)' : '$ Linux (bash)'}
                  </button>
                ))}
              </div>

              {/* One-click install command — primary section */}
              <div>
                <p className="text-xs text-gray-400 mb-2 font-medium">
                  {platform === 'windows'
                    ? 'Open PowerShell as Administrator and run:'
                    : 'Open a terminal and run:'}
                </p>
                <div className="relative group">
                  <pre className="bg-gray-950 border border-emerald-800/40 rounded-lg px-4 py-3 text-sm font-mono text-amber-400 whitespace-pre-wrap break-all leading-relaxed pr-12">
                    {installCmd}
                  </pre>
                  <button
                    onClick={copyCmd}
                    className="absolute top-2.5 right-2.5 p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
                    title="Copy command"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                </div>
                <p className="text-xs text-gray-500 mt-2">
                  This command downloads the agent binary from this server, writes the configuration, and starts the agent in the background.
                </p>
              </div>

              {/* Divider */}
              <div className="border-t border-gray-800" />

              {/* Manual config — secondary section */}
              <div>
                <p className="text-xs text-gray-400 mb-2 font-medium">
                  Or configure manually — copy to <code className="text-gray-300">analysishub-agent.conf</code> next to the binary:
                </p>
                <div className="relative">
                  <pre className="bg-gray-950 border border-gray-700/50 rounded-lg p-4 text-xs font-mono text-emerald-400 overflow-x-auto">
                    {configText}
                  </pre>
                  <button
                    onClick={copyConfig}
                    className="absolute top-2.5 right-2.5 p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
                    title="Copy config"
                  >
                    <Copy className="h-4 w-4" />
                  </button>
                </div>
              </div>
            </>
          ) : null}
        </DialogBody>
        <DialogFooter>
          <button className="btn-secondary" onClick={onClose}>Close</button>
          {data && (
            <button className="btn-primary" onClick={copyCmd}>
              <Copy className="h-4 w-4" /> Copy Install Command
            </button>
          )}
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- Delete confirmation ----
interface DeleteModalProps {
  agent: Agent | null
  onClose: () => void
}

function DeleteAgentModal({ agent, onClose }: DeleteModalProps) {
  const qc = useQueryClient()
  const deleteMutation = useMutation({
    mutationFn: () => agentsApi.delete(agent!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['agents'] })
      toast.success('Agent deleted')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <Dialog open={!!agent} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Delete Agent</DialogTitle>
          <DialogDescription>This will remove the agent registration.</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <div className="space-y-3">
            <p className="text-sm text-gray-300">
              Delete agent <span className="font-semibold text-white">{agent?.name}</span>?
            </p>
            {agent?.status === 'online' ? (
              <div className="rounded border border-amber-900/50 bg-amber-950/20 p-3 text-[11px] text-amber-300 leading-relaxed">
                <strong>Remote Cleanup:</strong> The agent is currently online. Selecting delete will also command the agent to remove its own binary, configuration, and work directory from the target machine.
              </div>
            ) : (
              <div className="rounded border border-gray-700 bg-gray-800/40 p-3 text-[11px] text-gray-400">
                <strong>Note:</strong> The agent is offline. Only the registration will be removed from the dashboard. If the agent comes back online, it will no longer be able to connect.
              </div>
            )}
          </div>
        </DialogBody>
        <DialogFooter>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn-danger"
            onClick={() => deleteMutation.mutate()}
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? 'Deleting…' : 'Delete Agent'}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- Main Page ----
export default function AgentsPage() {
  const navigate = useNavigate()
  const [newOpen, setNewOpen] = useState(false)
  const [installerAgentId, setInstallerAgentId] = useState<string | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Agent | null>(null)

  const { data: agents = [], isLoading } = useQuery({
    queryKey: ['agents'],
    queryFn: agentsApi.list,
    refetchInterval: 15_000,
  })

  // Client-side pagination — bounds rows rendered for large fleets.
  const PAGE_SIZE = 25
  const [page, setPage] = useState(1)
  const totalPages = Math.max(1, Math.ceil(agents.length / PAGE_SIZE))
  const pageClamped = Math.min(page, totalPages)
  const pagedAgents = agents.slice((pageClamped - 1) * PAGE_SIZE, pageClamped * PAGE_SIZE)

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Agent Management</h1>
          <p className="text-sm text-gray-400 mt-0.5">
            {agents.filter((a) => a.status === 'online').length} online / {agents.length} total
          </p>
        </div>
        <button className="btn-primary" onClick={() => setNewOpen(true)}>
          <Plus className="h-4 w-4" /> New Agent
        </button>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6 space-y-3">
              {[...Array(5)].map((_, i) => <div key={i} className="skeleton h-14 w-full rounded" />)}
            </div>
          ) : agents.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-500">
              <Server className="h-10 w-10 mb-3 opacity-30" />
              <p className="text-sm">No agents registered yet</p>
              <button
                className="mt-4 btn-primary text-xs"
                onClick={() => setNewOpen(true)}
              >
                <Plus className="h-3.5 w-3.5" /> Register your first agent
              </button>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-5 py-3">Name</th>
                  <th className="table-header text-left px-5 py-3 hidden sm:table-cell">Hostname</th>
                  <th className="table-header text-left px-5 py-3 hidden md:table-cell">OS</th>
                  <th className="table-header text-left px-5 py-3 hidden lg:table-cell">IP Address</th>
                  <th className="table-header text-left px-5 py-3">Status</th>
                  <th className="table-header text-left px-5 py-3 hidden md:table-cell">Last Seen</th>
                  <th className="table-header text-right px-5 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {pagedAgents.map((agent) => (
                  <tr
                    key={agent.id}
                    className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors cursor-pointer"
                    onClick={() => navigate(`/agents/${agent.id}`)}
                  >
                    <td className="px-5 py-3">
                      <div className="font-medium text-gray-200 text-sm">{agent.name}</div>
                      {agent.description && (
                        <div className="text-xs text-gray-500 mt-0.5">{agent.description}</div>
                      )}
                    </td>
                    <td className="px-5 py-3 hidden sm:table-cell">
                      <span className="text-sm text-gray-300 font-mono">{agent.hostname || '—'}</span>
                    </td>
                    <td className="px-5 py-3 hidden md:table-cell text-sm text-gray-400">{agent.os || '—'}</td>
                    <td className="px-5 py-3 hidden lg:table-cell">
                      <span className="font-mono text-xs text-gray-400">{agent.ip_address || '—'}</span>
                    </td>
                    <td className="px-5 py-3">
                      <AgentStatusBadge status={agent.status} />
                    </td>
                    <td className="px-5 py-3 hidden md:table-cell text-xs text-gray-500">
                      {agent.last_seen
                        ? safeDistanceToNow(agent.last_seen, { addSuffix: true })
                        : 'Never'}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-1" onClick={(e) => e.stopPropagation()}>
                        <button
                          onClick={() => setInstallerAgentId(agent.id)}
                          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors"
                          title="Get installer config"
                        >
                          <Settings className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => setDeleteTarget(agent)}
                          className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors"
                          title="Delete agent"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
        {!isLoading && agents.length > 0 && (
          <Pagination page={pageClamped} pageSize={PAGE_SIZE} totalItems={agents.length} onPageChange={setPage} />
        )}
      </div>

      <NewAgentModal open={newOpen} onClose={() => setNewOpen(false)} />
      <InstallerModal agentId={installerAgentId} onClose={() => setInstallerAgentId(null)} />
      <DeleteAgentModal agent={deleteTarget} onClose={() => setDeleteTarget(null)} />
    </div>
  )
}
