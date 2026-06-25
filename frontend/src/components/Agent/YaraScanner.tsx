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
  CheckCircle2
} from 'lucide-react'
import { type Agent } from '@/api/agents'
import { jobsApi, type Job } from '@/api/jobs'
import { toolsApi, type Tool } from '@/api/tools'
import toast from 'react-hot-toast'
import { getErrorMessage } from '@/lib/utils'
import TerminalOutput from '@/components/Terminal'
import { useAuthStore } from '@/store/auth'

// Threat-hunt scenarios. The `id` MUST match a rule file stem under the
// scanner's rules/yara/scenarios/<id>.yar (or be the special 'general'/'all').
// 'general' = base webshell/malware rules only (default, no --scenario flag).
const SCAN_SCENARIOS: { id: string; label: string; desc: string }[] = [
  { id: 'general',          label: 'General / Webshell',   desc: 'Webshells & generic malware in source files (default).' },
  { id: 'ransomware',       label: 'Ransomware',           desc: 'Ransom notes, encryptors, shadow-copy/backup destruction.' },
  { id: 'credential_theft', label: 'Credential Theft',     desc: 'Mimikatz, LSASS dumping, hive/NTDS theft, Kerberoast.' },
  { id: 'persistence',      label: 'Persistence (Windows)',desc: 'Run keys, scheduled tasks, services, WMI, IFEO backdoors.' },
  { id: 'lateral_movement', label: 'Lateral Movement',     desc: 'PsExec, WMIC, WinRM, Impacket, remote service creation.' },
  { id: 'powershell',       label: 'PowerShell / Fileless',desc: 'Encoded cmds, download cradles, AMSI bypass, reflection.' },
  { id: 'linux',            label: 'Linux Threats',        desc: 'Reverse shells, crypto-miners, rootkits, ELF backdoors.' },
  { id: 'c2',               label: 'C2 Frameworks',        desc: 'Cobalt Strike, Meterpreter, Sliver, Empire, Covenant.' },
  { id: 'all',              label: 'All Scenarios (deep)', desc: 'Every scenario rule set at once — broadest, slower.' },
]

export function YaraScanner({ agent }: { agent: Agent }) {
  const qc = useQueryClient()
  const [targetPath, setTargetPath] = useState<string>(agent.os === 'windows' ? 'C:\\' : '/')
  const [activeJobId, setActiveJobId] = useState<string | null>(null)
  const [viewMode, setViewMode] = useState<'process' | 'report'>('process')
  const [output, setOutput] = useState<string[]>([])
  const [isDebug, setIsDebug] = useState<boolean>(false)
  const [isProvisioning, setIsProvisioning] = useState<boolean>(false)
  const [pendingRun, setPendingRun] = useState<boolean>(false)
  const [cpuLimit, setCpuLimit] = useState<number | ''>('')
  const [ramLimit, setRamLimit] = useState<number | ''>('')
  const [priority, setPriority] = useState<string>('normal')
  const [isAdvanced, setIsAdvanced] = useState<boolean>(false)
  const [customYaraName, setCustomYaraName] = useState<string>('')
  const [customYaraBase64, setCustomYaraBase64] = useState<string>('')
  const [scenario, setScenario] = useState<string>('general')

  // Fetch scanner tool
  const { data: tools = [] } = useQuery<Tool[]>({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list()
  })

  const scannerCandidates = tools.filter(t => {
    const norm = t.name.toLowerCase().replace(/[\s_-]/g, '')
    return norm.includes('yarascanner') || norm.includes('webshellscanner')
  })
  const compatible = scannerCandidates.filter(
    t => t.platform === agent.os || t.platform === 'both'
  )
  const scannerTool =
    compatible.find(t => t.platform === agent.os) ??
    compatible.find(t => t.platform === 'both') ??
    compatible[0]

  // SSE for output
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
    if (!scannerTool) {
      toast.error('YARA Scanner tool not found in library')
      return
    }

    const parts = [`scan "${targetPath}" --out report --format html,json`]
    if (isDebug) parts.push("--verbose")

    const useScenario = scenario !== 'general'
    if (useScenario) parts.push(`--scenario ${scenario}`)

    // Scenario rules target binaries, ransom notes and scripts that fall outside
    // the default source-file extension whitelist, so a scenario scan (like
    // advanced mode) must inspect all files to be effective.
    if (useScenario || isAdvanced) parts.push("--all-files")

    if (isAdvanced && customYaraBase64) parts.push(`--yara-base64 ${customYaraBase64}`)

    const args = parts.join(" ")

    createJobMutation.mutate({
      agent_id: agent.id,
      tool_id: scannerTool.id,
      args,
      cpu_limit: cpuLimit ? Number(cpuLimit) : undefined,
      ram_limit: ramLimit ? Number(ramLimit) : undefined,
      priority: priority !== 'normal' ? priority : undefined
    })
  }

  const handleTestEnvironment = () => {
    if (!scannerTool) {
      toast.error('Scanner tool not found')
      return
    }

    setIsProvisioning(true)
    setOutput(["[*] Initializing tool deployment...", "[*] Detecting OS and downloading binary..."])
    createJobMutation.mutate({
      agent_id: agent.id,
      tool_id: scannerTool.id,
      args: "health"
    })
    toast.loading('Preparing scanner environment on agent...', { id: 'test-env', duration: 3000 })
  }

  // Trigger health check automatically when agent changes
  useEffect(() => {
    if (scannerTool && agent.id) {
      handleTestEnvironment()
    } else {
      setIsProvisioning(false)
      setOutput([])
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [agent.id])

  // Active job status
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
  }, [pendingRun, activeJob?.status, activeJob?.id, runJobMutation])

  // Automatically switch to report view when scan is done
  useEffect(() => {
    if (activeJob?.status === 'done' && activeJob.artifact_path && !isProvisioning) {
      setViewMode('report')
    }
  }, [activeJob?.status, activeJob?.artifact_path, isProvisioning])

  const isScanning =
    activeJob?.status === 'running' ||
    activeJob?.status === 'pending' ||
    activeJob?.status === 'ready'
  const hasReport = activeJob?.status === 'done' && activeJob.artifact_path

  return (
    <div className="flex flex-col h-full min-h-[700px] gap-4">
      {/* Header & Controls */}
      <div className="flex flex-col gap-3 p-4 bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm shrink-0">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
          <div className="p-3 bg-emerald-500/10 rounded-lg border border-emerald-500/20">
            <Shield className="h-6 w-6 text-emerald-500" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-gray-100">YARA Scanner</h1>
            <p className="text-xs text-gray-400">Hunt for backdoors and shells on {agent.name}</p>
          </div>
        </div>

        <div className="flex flex-wrap items-end justify-end gap-3 flex-1">
          {/* Path Input */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Scan Path</label>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input 
                className="input pl-9 h-10 w-[300px]"
                value={targetPath}
                onChange={(e) => setTargetPath(e.target.value)}
                placeholder={agent.os === 'windows' ? 'C:\\' : '/'}
                disabled={isScanning}
              />
            </div>
            <div className="flex items-center gap-2 mt-1">
              {agent.os === 'windows' ? (
                <>
                  <button onClick={() => setTargetPath('C:\\')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">C:\</button>
                  <button onClick={() => setTargetPath('C:\\inetpub\\wwwroot')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">IIS</button>
                  <button onClick={() => setTargetPath('C:\\Users')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">Users</button>
                </>
              ) : (
                <>
                  <button onClick={() => setTargetPath('/')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">/</button>
                  <button onClick={() => setTargetPath('/var/www')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">/var/www</button>
                  <button onClick={() => setTargetPath('/home')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">/home</button>
                  <button onClick={() => setTargetPath('/tmp')} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors">/tmp</button>
                </>
              )}
            </div>
          </div>

          {/* Threat scenario */}
          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Scenario</label>
            <select
              className="input h-10 w-[210px] text-xs"
              value={scenario}
              onChange={(e) => setScenario(e.target.value)}
              disabled={isScanning}
              title={SCAN_SCENARIOS.find((s) => s.id === scenario)?.desc}
            >
              {SCAN_SCENARIOS.map((s) => (
                <option key={s.id} value={s.id}>{s.label}</option>
              ))}
            </select>
            <span className="text-[10px] text-gray-500 ml-1 max-w-[210px] truncate" title={SCAN_SCENARIOS.find((s) => s.id === scenario)?.desc}>
              {scenario === 'general'
                ? 'Default source-file rules'
                : 'Includes specialized rules · scans all files'}
            </span>
          </div>

          <div className="flex flex-col gap-1.5">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Limits</label>
            <div className="flex items-center gap-2">
              <input type="number" min="1" max="100" className="input h-10 w-20 text-xs px-2" value={cpuLimit} onChange={(e) => setCpuLimit(e.target.value ? Number(e.target.value) : '')} placeholder="CPU %" disabled={isScanning} />
              <input type="number" min="1" className="input h-10 w-20 text-xs px-2" value={ramLimit} onChange={(e) => setRamLimit(e.target.value ? Number(e.target.value) : '')} placeholder="RAM MB" disabled={isScanning} />
              <select className="input h-10 w-24 text-xs px-2" value={priority} onChange={(e) => setPriority(e.target.value)} disabled={isScanning}>
                <option value="normal">Normal</option>
                <option value="idle">Idle</option>
              </select>
            </div>
          </div>

          {/* Start Button */}
          <div className="flex flex-col gap-1.5 ml-auto md:ml-0">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Actions</label>
            <div className="flex items-center gap-2">
              <button 
                className="btn-primary h-10 px-6 flex items-center gap-2 group"
                onClick={handleStartScan}
                disabled={isScanning || isProvisioning || agent.status !== 'online'}
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
                disabled={isScanning || agent.status !== 'online'}
                title="Verify scanner binary and dependencies on target agent"
              >
                {isProvisioning ? <Loader2 className="h-4 w-4 animate-spin" /> : <TerminalIcon className="h-4 w-4" />}
                {isProvisioning ? 'PROVISIONING...' : 'Test Env'}
              </button>
            </div>
          </div>
        </div>
        </div>
        {/* Advanced Options Toggle */}
        <div className="w-full pt-2 border-t border-gray-800/50 flex flex-col md:flex-row items-start md:items-center justify-between gap-3">
          <label className="flex items-center gap-2 cursor-pointer w-fit text-sm text-gray-400 hover:text-gray-200 transition-colors">
            <input 
              type="checkbox" 
              className="rounded border-gray-700 bg-gray-900 text-purple-500 focus:ring-purple-500/20"
              checked={isAdvanced}
              onChange={(e) => setIsAdvanced(e.target.checked)}
              disabled={isScanning}
            />
            Advanced Mode (Scan all files + Custom YARA)
          </label>
          
          {isAdvanced && (
            <div className="flex items-center gap-4 bg-gray-900/80 p-3 rounded-lg border border-gray-800">
              <div className="flex flex-col gap-1">
                <span className="text-xs font-semibold text-gray-300">Custom YARA Rule</span>
                <span className="text-[10px] text-gray-500">Upload a .yar file to scan alongside built-in rules</span>
              </div>
              <div className="flex-1 flex items-center gap-2">
                <input 
                  type="file" 
                  accept=".yar,.yara"
                  className="hidden"
                  id="yara-upload"
                  disabled={isScanning}
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (!file) return
                    setCustomYaraName(file.name)
                    const reader = new FileReader()
                    reader.onload = (ev) => {
                      const text = ev.target?.result as string
                      setCustomYaraBase64(btoa(text))
                    }
                    reader.readAsText(file)
                  }}
                />
                <label 
                  htmlFor="yara-upload"
                  className={`btn-secondary py-1.5 px-3 text-xs cursor-pointer ${isScanning ? 'opacity-50 pointer-events-none' : ''}`}
                >
                  Choose File
                </label>
                {customYaraName && (
                  <div className="flex items-center gap-2 bg-purple-500/10 text-purple-400 px-2 py-1 rounded text-xs border border-purple-500/20">
                    <FileText className="w-3 h-3" />
                    <span className="truncate max-w-[200px]">{customYaraName}</span>
                    <button 
                      onClick={() => {
                        setCustomYaraName('')
                        setCustomYaraBase64('')
                      }}
                      className="ml-2 text-purple-400 hover:text-purple-300"
                      disabled={isScanning}
                    >
                      &times;
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
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
        <div className="px-6 py-3 bg-gray-900/50 border-t border-gray-800 flex items-center justify-between text-xs shrink-0">
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
