import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { 
  Shield, 
  Search, 
  Terminal as TerminalIcon, 
  FileText, 
  Download, 
  Play, 
  Loader2, 
  AlertCircle,
  CheckCircle2,
  Server
} from 'lucide-react'
import { agentsApi, type Agent } from '@/api/agents'
import { jobsApi, type Job } from '@/api/jobs'
import { toolsApi, type Tool } from '@/api/tools'
import toast from 'react-hot-toast'
import { getErrorMessage } from '@/lib/utils'
import TerminalOutput from '@/components/Terminal'
import { useAuthStore } from '@/store/auth'

export default function WebshellScannerPage() {
  const qc = useQueryClient()
  const [selectedAgentId, setSelectedAgentId] = useState<string>('')
  const [targetPath, setTargetPath] = useState<string>('C:\\inetpub\\wwwroot') // Default for IIS
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'process' | 'report'>('process')
  const [output, setOutput] = useState<string[]>([])
  const [isDebug, setIsDebug] = useState<boolean>(false)
  const [isProvisioning, setIsProvisioning] = useState<boolean>(false)
  const [pendingRun, setPendingRun] = useState<boolean>(false)

  // Fetch online agents
  const { data: agents = [] } = useQuery<Agent[]>({
    queryKey: ['agents'],
    queryFn: () => agentsApi.list(),
    select: (data) => data.filter(a => a.status === 'online')
  })

  // Fetch scanner tool
  const { data: tools = [] } = useQuery<Tool[]>({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list()
  })
  const selectedAgent = agents.find(a => a.id === selectedAgentId)
  const scannerCandidates = tools.filter(t =>
    t.name.toLowerCase().replace(/[\s_-]/g, '').includes('webshellscanner')
  )
  const compatible = selectedAgent
    ? scannerCandidates.filter(
        t => t.platform === selectedAgent.os || t.platform === 'both'
      )
    : scannerCandidates
  const scannerTool =
    compatible.find(t => selectedAgent && t.platform === selectedAgent.os) ??
    compatible.find(t => t.platform === 'both') ??
    compatible[0]

  // SSE for output — JWT must be passed via query param since EventSource
  // cannot set custom headers.
  useEffect(() => {
    if (!activeJobId) return

    const base = (import.meta.env.VITE_API_URL as string | undefined) || window.location.origin
    const token = useAuthStore.getState().token ?? ''
    const url = `${base}/api/v1/jobs/${activeJobId}/output?token=${encodeURIComponent(token)}`
    const eventSource = new EventSource(url)

    eventSource.onmessage = (event) => {
      if (event.data === '__DONE__') {
        eventSource.close()
        qc.invalidateQueries({ queryKey: ['job', activeJobId] })
        setIsProvisioning(false)
        toast.success('Ready to scan!')
        return
      }
      setOutput(prev => [...prev, event.data])
    }
    
    eventSource.onerror = (e) => {
      console.error('SSE Error:', e)
      setIsProvisioning(false)
      eventSource.close()
    }

    return () => eventSource.close()
  }, [activeJobId, qc])

  // Mutations
  // Step 1: create job — agent starts downloading the tool. Status begins at
  // "pending" and the hub flips it to "ready" once the agent finishes download
  // (job_status WS message). We must NOT call /run before that — the backend
  // returns 409 "job must be in status 'ready' or 'stopped' to run".
  const createJobMutation = useMutation({
    mutationFn: jobsApi.create,
    onSuccess: (job) => {
      setActiveJobId(job.id)
      setOutput([])
      setPendingRun(true)
      if (viewMode === 'report') setViewMode('process')
    },
    onError: (err) => {
      toast.error(getErrorMessage(err))
      setIsProvisioning(false)
    }
  })

  const runJobMutation = useMutation({
    mutationFn: jobsApi.run,
    onSuccess: () => {
      setPendingRun(false)
    },
    onError: (err) => {
      toast.error(getErrorMessage(err))
      setIsProvisioning(false)
      setPendingRun(false)
    }
  })

  const handleStartScan = () => {
    if (!selectedAgentId) {
      toast.error('Please select an agent')
      return
    }
    if (!scannerTool) {
      toast.error('Webshell Scanner tool not found in library')
      return
    }

    // Command: scan <path> --out report --format html,json
    // The agent will find report/report.html and upload it.
    let args = `scan "${targetPath}" --out report --format html,json`
    if (isDebug) args += " --verbose"
    
    createJobMutation.mutate({
      agent_id: selectedAgentId,
      tool_id: scannerTool.id,
      args
    })
  }

  const handleTestEnvironment = () => {
    if (!selectedAgentId) {
      toast.error('Please select an agent first')
      return
    }
    if (!scannerTool) {
      toast.error('Scanner tool not found')
      return
    }

    // Run health check to verify tool is working on agent
    setIsProvisioning(true)
    setOutput(["[*] Initializing tool deployment...", "[*] Detecting OS and downloading binary..."])
    createJobMutation.mutate({
      agent_id: selectedAgentId,
      tool_id: scannerTool.id,
      args: "health"
    })
    toast.loading('Preparing scanner environment on agent...', { id: 'test-env', duration: 3000 })
  }

  // Trigger health check automatically when agent changes
  useEffect(() => {
    if (selectedAgentId && scannerTool) {
      handleTestEnvironment()
    } else {
      setIsProvisioning(false)
      setOutput([])
    }
  }, [selectedAgentId, scannerTool])

  // Active job status — poll while the job is still in motion
  const { data: activeJob } = useQuery<Job>({
    queryKey: ['job', activeJobId],
    queryFn: () => jobsApi.get(activeJobId!),
    enabled: !!activeJobId,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'pending' || status === 'ready' || status === 'running' ? 1500 : false
    }
  })

  // Auto-trigger /run once the agent reports the tool is ready
  useEffect(() => {
    if (!pendingRun || !activeJob) return
    if (activeJob.status === 'ready' && !runJobMutation.isPending) {
      runJobMutation.mutate(activeJob.id)
    } else if (activeJob.status === 'failed') {
      toast.error('Tool preparation failed on agent')
      setPendingRun(false)
      setIsProvisioning(false)
    }
  }, [pendingRun, activeJob?.status, activeJob?.id])

  const isScanning =
    activeJob?.status === 'running' ||
    activeJob?.status === 'pending' ||
    activeJob?.status === 'ready'
  const hasReport = activeJob?.status === 'done' && activeJob.artifact_path

  return (
    <div className="flex flex-col h-full gap-6">
      {/* Header & Controls */}
      <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4 p-6 bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm">
        <div className="flex items-center gap-4">
          <div className="p-3 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
            <Shield className="h-6 w-6 text-emerald-500" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-100">Webshell Scanner</h1>
            <p className="text-sm text-gray-400">Hunt for backdoors and malicious shells across your infrastructure</p>
          </div>
        </div>

        <div className="flex flex-wrap items-center gap-3">
          {/* Agent Select */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Target Agent</label>
            <div className="relative">
              <Server className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <select 
                className="input pl-9 h-10 min-w-[200px]"
                value={selectedAgentId}
                onChange={(e) => setSelectedAgentId(e.target.value)}
                disabled={isScanning}
              >
                <option value="">Select an online agent...</option>
                {agents.map(a => (
                  <option key={a.id} value={a.id}>
                    {a.os === 'windows' ? '🪟' : '🐧'} {a.name} ({a.hostname})
                  </option>
                ))}
              </select>
            </div>
          </div>

          {/* Path Input */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Scan Path</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input 
                className="input pl-9 h-10 w-[300px]"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder="C:\inetpub\wwwroot"
                disabled={isScanning}
              />
            </div>
          </div>

          {/* Start Button */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Actions</label>
            <div className="flex items-center gap-2">
              <button 
                className="btn-primary h-10 px-6 flex items-center gap-2 group"
                onClick={handleStartScan}
                disabled={isScanning || !selectedAgentId || isProvisioning}
              >
                {isScanning ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <Play className="h-4 w-4 group-hover:scale-110 transition-transform" />
                )}
                {isScanning ? 'Scanning...' : 'Start Scan'}
              </button>

              <button 
                className={`h-10 px-4 rounded-lg flex items-center gap-2 border transition-all shadow-lg ${
                  isProvisioning 
                    ? 'bg-amber-600 text-white border-amber-500 animate-pulse scale-105' 
                    : 'bg-gray-800 hover:bg-gray-700 text-gray-300 border-gray-700'
                }`}
                onClick={handleTestEnvironment}
                disabled={isScanning || !selectedAgentId}
                title="Verify scanner binary and dependencies on target agent"
              >
                {isProvisioning ? <Loader2 className="h-4 w-4 animate-spin" /> : <TerminalIcon className="h-4 w-4" />}
                {isProvisioning ? 'PROVISIONING...' : 'Test Env'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex flex-col min-h-0 bg-gray-900/30 rounded-xl border border-gray-800 overflow-hidden">
        {/* Tabs */}
        <div className="flex items-center gap-1 p-2 bg-gray-900/50 border-b border-gray-800">
          <button 
            onClick={() => setViewMode('process')}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-all ${
              viewMode === 'process' 
                ? 'bg-gray-800 text-emerald-400 shadow-sm' 
                : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <TerminalIcon className="h-4 w-4" />
            Process View
          </button>
          <button 
            onClick={() => setViewMode('report')}
            disabled={!hasReport}
            className={`flex items-center gap-2 px-4 py-2 text-sm font-medium rounded-lg transition-all ${
              viewMode === 'report' 
                ? 'bg-gray-800 text-emerald-400 shadow-sm' 
                : !hasReport ? 'opacity-30 cursor-not-allowed' : 'text-gray-500 hover:text-gray-300'
            }`}
          >
            <FileText className="h-4 w-4" />
            Report Viewer
          </button>

          <div className="flex-1" />

          {hasReport && (
            <a 
              href={jobsApi.getArtifactUrl(activeJobId!)}
              className="flex items-center gap-2 px-4 py-2 text-sm font-medium text-emerald-400 hover:bg-emerald-500/10 rounded-lg transition-all"
              download
            >
              <Download className="h-4 w-4" />
            </a>
          )}

          <div className="h-6 w-px bg-gray-800 mx-2" />

          <label className="flex items-center gap-2 px-3 py-1 bg-gray-800/50 rounded-lg border border-gray-700 cursor-pointer hover:bg-gray-800 transition-all select-none">
            <input 
              type="checkbox" 
              className="accent-emerald-500"
              checked={isDebug}
              onChange={(e) => setIsDebug(e.target.checked)}
            />
            <span className="text-[10px] font-bold uppercase tracking-tight text-gray-400">Debug Mode</span>
          </label>
        </div>

        {/* Tab Content */}
        <div className="flex-1 min-h-0 relative">
          {viewMode === 'process' ? (
            <TerminalOutput
              lines={output}
              isRunning={isScanning || isProvisioning}
              className="absolute inset-0 rounded-none border-0"
            />
          ) : (
            <div className="absolute inset-0 bg-white">
              <iframe 
                src={activeJobId ? jobsApi.getArtifactContentUrl(activeJobId) : ''}
                className="w-full h-full border-none"
                title="Scan Report"
              />
            </div>
          )}
        </div>

        {/* Footer Status */}
        <div className="px-6 py-3 bg-gray-900/50 border-t border-gray-800 flex items-center justify-between text-xs">
          <div className="flex items-center gap-4">
            <div className="flex items-center gap-1.5">
              <span className="text-gray-500 uppercase">Status:</span>
              {isScanning ? (
                <span className="flex items-center gap-1 text-amber-400">
                  <Loader2 className="h-3 w-3 animate-spin" />
                  In Progress
                </span>
              ) : activeJob?.status === 'done' ? (
                <span className="flex items-center gap-1 text-emerald-400 font-bold">
                  <CheckCircle2 className="h-3 w-3" />
                  Completed
                </span>
              ) : activeJob?.status === 'failed' ? (
                <span className="flex items-center gap-1 text-red-400 font-bold">
                  <AlertCircle className="h-3 w-3" />
                  Failed
                </span>
              ) : (
                <span className="text-gray-600">Idle</span>
              )}
            </div>
            {activeJob && (
              <div className="flex items-center gap-1.5">
                <span className="text-gray-500 uppercase">Job ID:</span>
                <span className="text-gray-400 font-mono">{activeJob.id}</span>
              </div>
            )}
          </div>

          <div className="text-gray-500 italic">
            Powered by Webshell-Scanner Engine v0.1.0
          </div>
        </div>
      </div>
    </div>
  )
}
