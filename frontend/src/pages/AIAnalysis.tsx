import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { useSearchParams } from 'react-router-dom'
import {
  BrainCircuit, Plus, Trash2, Upload,
  FileText, Server, ClipboardList, Search, Settings2,
  Activity, Package, ArrowLeft,
} from 'lucide-react'
import AIProviderSettings from '@/pages/AIProviderSettings'
import toast from 'react-hot-toast'
import {
  analysisApi, elkResultsApi,
  type AnalysisSession, type ChainStep, type SessionSourceType,
} from '@/api/analysis'
import { jobsApi } from '@/api/jobs'
import { checklistApi } from '@/api/checklist'
import { getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import AnalysisChain from '@/components/analysis/AnalysisChain'
import AnalysisStream from '@/components/analysis/AnalysisStream'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogBody, DialogFooter,
} from '@/components/ui/dialog'
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from '@/components/ui/select'

const SOURCE_ICONS: Record<SessionSourceType, typeof FileText> = {
  job: Server,
  checklist_run: ClipboardList,
  elk_result: Search,
  upload: Upload,
  offline_report: Package,
}

const SOURCE_LABELS: Record<SessionSourceType, string> = {
  job: 'Tool Job',
  checklist_run: 'Evidence Checklist',
  elk_result: 'ELK Hunt Result',
  upload: 'File Upload',
  offline_report: 'Offline Report',
}

function statusColor(status: AnalysisSession['status']) {
  switch (status) {
    case 'done':    return 'text-emerald-400'
    case 'running': return 'text-blue-400'
    case 'failed':  return 'text-red-400'
    default:        return 'text-gray-500'
  }
}

// ──────────────────────────────────────────────────────────────
// New Analysis Modal
// ──────────────────────────────────────────────────────────────
function NewAnalysisModal({
  open, onClose, preSourceType, preSourceId,
}: {
  open: boolean
  onClose: () => void
  preSourceType?: SessionSourceType
  preSourceId?: string
}) {
  const qc = useQueryClient()
  const [providerId, setProviderId] = useState('')
  const [sourceType, setSourceType] = useState<SessionSourceType>(preSourceType ?? 'job')
  const [sourceId, setSourceId] = useState(preSourceId ?? '')
  const [title, setTitle] = useState('')
  const [file, setFile] = useState<File | null>(null)
  const [dragOver, setDragOver] = useState(false)
  const [offlinePreview, setOfflinePreview] = useState<{ bundleName: string; caseName: string; hostname: string } | null>(null)
  const fileRef = useRef<HTMLInputElement>(null)

  const fileSizeMB = file ? file.size / (1024 * 1024) : 0
  const isLargeFile = fileSizeMB > 100

  const handleOfflineFile = (f: File) => {
    setFile(f)
    setOfflinePreview(null)
    const reader = new FileReader()
    reader.onload = (e) => {
      try {
        const data = JSON.parse(e.target?.result as string)
        if (data.bundle_name) {
          setOfflinePreview({
            bundleName: data.bundle_name ?? '',
            caseName: data.case_name ?? '',
            hostname: data.hostname ?? '',
          })
        }
      } catch { /* not valid JSON, ignore */ }
    }
    reader.readAsText(f)
  }

  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders, enabled: open })
  const { data: jobs = [] } = useQuery({ queryKey: ['jobs'], queryFn: () => jobsApi.list(), enabled: open && sourceType === 'job' })
  const { data: runs = [] } = useQuery({ queryKey: ['checklist-runs'], queryFn: () => checklistApi.listRuns(), enabled: open && sourceType === 'checklist_run' })
  const { data: elkResults = [] } = useQuery({ queryKey: ['elk-hunt-results'], queryFn: elkResultsApi.list, enabled: open && sourceType === 'elk_result' })

  const createMutation = useMutation({
    mutationFn: () => analysisApi.createSession({
      provider_id: providerId,
      source_type: sourceType,
      source_id: (sourceType !== 'upload' && sourceType !== 'offline_report') ? sourceId : undefined,
      title: title || undefined,
      file: file || undefined,
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai-sessions'] })
      toast.success('Analysis session created')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setDragOver(false)
    const f = e.dataTransfer.files[0]
    if (f) {
      if (sourceType === 'offline_report') handleOfflineFile(f)
      else setFile(f)
    }
  }

  const canSubmit = providerId && (
    (sourceType === 'upload' || sourceType === 'offline_report') ? !!file : !!sourceId
  )

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>New AI Analysis</DialogTitle>
          <DialogDescription>Select a data source and AI provider to begin analysis.</DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          {/* Provider */}
          <div>
            <label className="label">AI Provider *</label>
            {providers.length === 0 ? (
              <p className="text-xs text-yellow-400 mt-1">No providers configured. <a href="/ai-providers" className="underline">Add one first.</a></p>
            ) : (
              <Select value={providerId} onValueChange={setProviderId}>
                <SelectTrigger><SelectValue placeholder="Select provider…" /></SelectTrigger>
                <SelectContent>
                  {providers.filter(p => p.is_active).map(p => (
                    <SelectItem key={p.id} value={p.id}>{p.name} <span className="text-gray-500">— {p.model}</span></SelectItem>
                  ))}
                </SelectContent>
              </Select>
            )}
          </div>

          {/* Source type */}
          <div>
            <label className="label">Source Type *</label>
            <div className="grid grid-cols-4 gap-2">
              {(Object.keys(SOURCE_LABELS) as SessionSourceType[]).map((t) => {
                const Icon = SOURCE_ICONS[t]
                return (
                  <button
                    key={t}
                    type="button"
                    onClick={() => { setSourceType(t); setSourceId(''); setFile(null); setOfflinePreview(null) }}
                    className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border text-xs font-medium transition ${
                      sourceType === t ? 'border-emerald-500/60 bg-emerald-900/20 text-emerald-400' : 'border-gray-700 text-gray-400 hover:border-gray-600'
                    }`}
                  >
                    <Icon className="h-4 w-4" />
                    {SOURCE_LABELS[t]}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Source picker */}
          {sourceType === 'job' && (
            <div>
              <label className="label">Select Job *</label>
              <Select value={sourceId} onValueChange={setSourceId}>
                <SelectTrigger><SelectValue placeholder="Select a completed job…" /></SelectTrigger>
                <SelectContent>
                  {jobs.filter(j => j.status === 'done' || j.status === 'failed').map(j => (
                    <SelectItem key={j.id} value={j.id}>
                      {j.tool?.name ?? 'Tool'} — {j.agent?.name ?? 'Agent'} — {j.status}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {sourceType === 'checklist_run' && (
            <div>
              <label className="label">Select Checklist Run *</label>
              <Select value={sourceId} onValueChange={setSourceId}>
                <SelectTrigger><SelectValue placeholder="Select a checklist run…" /></SelectTrigger>
                <SelectContent>
                  {runs.filter(r => r.status === 'done').map(r => (
                    <SelectItem key={r.id} value={r.id}>
                      {r.label || r.id.split('-')[0]} — {r.platform} — {r.status}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {sourceType === 'elk_result' && (
            <div>
              <label className="label">Select ELK Hunt Result *</label>
              <Select value={sourceId} onValueChange={setSourceId}>
                <SelectTrigger><SelectValue placeholder="Select a hunt result…" /></SelectTrigger>
                <SelectContent>
                  {elkResults.filter(r => r.status === 'done').map(r => (
                    <SelectItem key={r.id} value={r.id}>
                      {r.title} — {r.total_hits} hits
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
          )}

          {sourceType === 'upload' && (
            <div>
              <label className="label">Upload File *</label>
              <div
                className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition ${
                  dragOver ? 'border-emerald-400 bg-emerald-900/10' : 'border-gray-700 hover:border-gray-600'
                }`}
                onClick={() => fileRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
              >
                <Upload className="h-6 w-6 mx-auto text-gray-500 mb-2" />
                {file ? (
                  <div>
                    <p className="text-sm text-emerald-400 font-medium">{file.name}</p>
                    <p className="text-xs text-gray-500 mt-0.5">{fileSizeMB.toFixed(1)} MB</p>
                  </div>
                ) : (
                  <>
                    <p className="text-sm text-gray-400">Drop file here or click to browse</p>
                    <p className="text-xs text-gray-600 mt-1">.txt .csv .json .xml .html .log .man · .raw .dmp .vmem .mem (strings extracted)</p>
                  </>
                )}
                {isLargeFile && (
                  <div className="mt-3 rounded-md bg-amber-900/20 border border-amber-500/30 px-3 py-2 text-left">
                    <p className="text-xs text-amber-300 font-medium">File lớn — {fileSizeMB.toFixed(0)} MB</p>
                    <p className="text-[11px] text-amber-400/70 mt-0.5">
                      File sẽ được lưu đầy đủ lên server. Khi phân tích, hệ thống tự động lấy mẫu 2 MB
                      (đầu + giữa + cuối) để trích xuất strings — không load toàn bộ vào RAM.
                      Upload có thể mất vài phút.
                    </p>
                  </div>
                )}
                <input ref={fileRef} type="file" className="hidden"
                  accept=".txt,.csv,.json,.xml,.html,.htm,.log,.man,.raw,.dmp,.vmem,.mem,.bin"
                  onChange={(e) => { if (e.target.files?.[0]) setFile(e.target.files[0]) }} />
              </div>
            </div>
          )}

          {sourceType === 'offline_report' && (
            <div>
              <label className="label">Upload Offline Report (JSON) *</label>
              <div
                className={`border-2 border-dashed rounded-lg p-6 text-center cursor-pointer transition ${
                  dragOver ? 'border-purple-400 bg-purple-900/10' : 'border-gray-700 hover:border-gray-600'
                }`}
                onClick={() => fileRef.current?.click()}
                onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
                onDragLeave={() => setDragOver(false)}
                onDrop={handleDrop}
              >
                <Package className="h-6 w-6 mx-auto text-purple-500/60 mb-2" />
                {file ? (
                  <div className="space-y-1">
                    <p className="text-sm text-purple-400 font-medium">{file.name}</p>
                    {offlinePreview ? (
                      <div className="text-xs text-gray-400 space-y-0.5 mt-2">
                        <p><span className="text-gray-600">Bundle:</span> {offlinePreview.bundleName}</p>
                        {offlinePreview.caseName && <p><span className="text-gray-600">Case:</span> {offlinePreview.caseName}</p>}
                        {offlinePreview.hostname && <p><span className="text-gray-600">Host:</span> {offlinePreview.hostname}</p>}
                      </div>
                    ) : (
                      <p className="text-xs text-yellow-500 mt-1">⚠ Not a valid offline report JSON</p>
                    )}
                  </div>
                ) : (
                  <>
                    <p className="text-sm text-gray-400">Drop <code className="text-purple-400">report-*.json</code> here or click to browse</p>
                    <p className="text-xs text-gray-600 mt-1">File generated by the offline agent's "Generate Report" button</p>
                  </>
                )}
                <input ref={fileRef} type="file" className="hidden" accept=".json"
                  onChange={(e) => { if (e.target.files?.[0]) handleOfflineFile(e.target.files[0]) }} />
              </div>
            </div>
          )}

          {/* Optional title */}
          <div>
            <label className="label">Session Title <span className="text-gray-500">(optional)</span></label>
            <input className="input" value={title} onChange={(e) => setTitle(e.target.value)} placeholder="Auto-generated if blank" />
          </div>
        </DialogBody>
        <DialogFooter>
          <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
          <button
            onClick={() => createMutation.mutate()}
            disabled={!canSubmit || createMutation.isPending}
            className="btn-primary"
          >
            {createMutation.isPending ? 'Creating…' : 'Create & Analyze'}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ──────────────────────────────────────────────────────────────
// Active Session Panel
// ──────────────────────────────────────────────────────────────
// ──────────────────────────────────────────────────────────────
// Live Activity Panel
// ──────────────────────────────────────────────────────────────
interface LogEntry { ts: string; level: string; message: string }

function LiveActivityPanel({ logs, liveTokens, isStreaming }: {
  logs: LogEntry[]
  liveTokens: string
  isStreaming: boolean
}) {
  const logBottomRef  = useRef<HTMLDivElement>(null)
  const tokenBottomRef = useRef<HTMLDivElement>(null)

  useEffect(() => {
    logBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [logs.length])

  useEffect(() => {
    tokenBottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [liveTokens])

  const levelStyle = (level: string) => {
    switch (level) {
      case 'success': return 'text-emerald-400'
      case 'warn':    return 'text-amber-400'
      case 'ai':      return 'text-violet-400'
      default:        return 'text-sky-400'
    }
  }
  const levelPrefix = (level: string) => {
    switch (level) {
      case 'success': return '✓'
      case 'warn':    return '⚠'
      case 'ai':      return '▶'
      default:        return '·'
    }
  }

  return (
    <div className="rounded-xl border border-gray-700/60 bg-[#0a0e18] overflow-hidden">
      {/* Header */}
      <div className="flex items-center justify-between px-4 py-2 border-b border-gray-700/50 bg-[#0f1420]">
        <div className="flex items-center gap-2">
          <Activity className="h-3.5 w-3.5 text-emerald-400" />
          <span className="text-[11px] font-semibold text-gray-300 uppercase tracking-wider">Live Activity</span>
        </div>
        {isStreaming && (
          <span className="flex items-center gap-1.5 text-[10px] text-emerald-400">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-400 animate-pulse" />
            LIVE
          </span>
        )}
      </div>

      <div className="grid grid-cols-2 divide-x divide-gray-700/50" style={{ height: '160px' }}>

        {/* Left: Activity log */}
        <div className="overflow-y-auto px-3 py-2 space-y-0.5 custom-scrollbar font-mono text-[11px]">
          <p className="text-[9px] text-gray-700 uppercase tracking-widest mb-1.5 select-none">Pipeline Log</p>
          {logs.length === 0 ? (
            <p className="text-gray-700 italic text-center pt-3">Chờ bắt đầu…</p>
          ) : (
            logs.map((entry, i) => (
              <div key={i} className="flex items-start gap-1.5 leading-[1.6]">
                <span className="text-gray-700 shrink-0 select-none text-[10px]">{entry.ts}</span>
                <span className={`shrink-0 ${levelStyle(entry.level)}`}>{levelPrefix(entry.level)}</span>
                <span className={`${levelStyle(entry.level)} break-words min-w-0`}>{entry.message}</span>
              </div>
            ))
          )}
          <div ref={logBottomRef} />
        </div>

        {/* Right: Live AI thinking stream */}
        <div className="overflow-y-auto px-3 py-2 custom-scrollbar">
          <p className="text-[9px] text-gray-700 uppercase tracking-widest mb-1.5 select-none font-mono">AI Thinking</p>
          {!liveTokens && !isStreaming ? (
            <p className="text-[11px] text-gray-700 italic font-mono text-center pt-3">AI chưa bắt đầu…</p>
          ) : (
            <p className="text-[12px] text-violet-300/80 font-mono leading-[1.65] whitespace-pre-wrap break-words">
              {liveTokens}
              {isStreaming && (
                <span className="inline-block w-[2px] h-[13px] bg-violet-400 animate-pulse align-text-bottom ml-px rounded-sm" />
              )}
            </p>
          )}
          <div ref={tokenBottomRef} />
        </div>

      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────
// Session Panel
// ──────────────────────────────────────────────────────────────
// Remove <think>/<thinking> blocks that reasoning models (DeepSeek-R1, Qwen)
// insert inline. These appear in liveTokens (thinking panel) but must not
// leak into the final Forensic Analysis Report.
function filterThinkBlocks(text: string): string {
  return text.replace(/<think(?:ing)?>[\s\S]*?<\/think(?:ing)?>/gi, '').trim()
}

function SessionPanel({ session, onDeleted }: { session: AnalysisSession; onDeleted: () => void }) {
  const qc = useQueryClient()
  const [steps, setSteps] = useState<ChainStep[]>(analysisApi.parseSteps(session.steps))
  const [result, setResult] = useState(filterThinkBlocks(session.result ?? ''))
  const [isStreaming, setIsStreaming] = useState(false)
  const [streamError, setStreamError] = useState('')
  const [logs, setLogs] = useState<LogEntry[]>([])
  const [liveTokens, setLiveTokens] = useState('')
  const esRef = useRef<EventSource | null>(null)

  const addLog = (entry: LogEntry) =>
    setLogs(prev => [...prev.slice(-99), entry]) // keep last 100

  const startStream = useCallback(() => {
    if (esRef.current) esRef.current.close()
    setIsStreaming(true)
    setStreamError('')
    setLogs([])
    setLiveTokens('')

    const es = analysisApi.streamSession(session.id)
    esRef.current = es

    // Full chain received at stream start — replace steps entirely
    es.addEventListener('init', (e: MessageEvent) => {
      const initSteps: ChainStep[] = JSON.parse(e.data)
      setSteps(initSteps)
    })

    // Individual step status update
    es.addEventListener('step', (e: MessageEvent) => {
      const step: ChainStep = JSON.parse(e.data)
      setSteps(prev => {
        const exists = prev.some(s => s.id === step.id)
        if (exists) return prev.map(s => s.id === step.id ? step : s)
        return [...prev, step]
      })
    })

    // Activity log entry
    es.addEventListener('log', (e: MessageEvent) => {
      const entry: LogEntry = JSON.parse(e.data)
      addLog(entry)
    })

    // AI token stream — accumulate result separately from live preview
    es.addEventListener('token', (e: MessageEvent) => {
      const { content } = JSON.parse(e.data) as { content: string }
      setResult(prev => prev + content)
      // Show ALL generated tokens in the thinking window (not just last N)
      setLiveTokens(prev => prev + content)
    })

    es.addEventListener('done', () => {
      es.close()
      setIsStreaming(false)
      setLiveTokens('')
      // Strip any think blocks that accumulated during streaming before showing in report
      setResult(prev => filterThinkBlocks(prev))
      qc.invalidateQueries({ queryKey: ['ai-sessions'] })
      qc.invalidateQueries({ queryKey: ['ai-session', session.id] })
    })

    es.addEventListener('error', (e: MessageEvent) => {
      try {
        const { message } = JSON.parse(e.data) as { message: string }
        setStreamError(message)
        addLog({ ts: new Date().toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' }), level: 'warn', message })
      } catch { /* ignore */ }
      es.close()
      setIsStreaming(false)
    })

    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) setIsStreaming(false)
    }
  }, [session.id, qc])

  // Auto-start stream for pending/running sessions
  useEffect(() => {
    if (session.status === 'pending' || session.status === 'running') {
      startStream()
    } else if (session.result) {
      setResult(filterThinkBlocks(session.result))
      setSteps(analysisApi.parseSteps(session.steps))
    }
    return () => esRef.current?.close()
  }, [session.id]) // eslint-disable-line

  const deleteMutation = useMutation({
    mutationFn: () => analysisApi.deleteSession(session.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai-sessions'] })
      onDeleted()
      toast.success('Session deleted')
    },
  })

  const Icon = SOURCE_ICONS[session.source_type]

  return (
    <div className="flex flex-col gap-3 h-full">
      {/* Session header */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className="h-4 w-4 text-emerald-400 shrink-0" />
          <div className="min-w-0">
            <h2 className="text-base font-semibold text-gray-100 truncate">{session.title || session.id.split('-')[0]}</h2>
            <p className="text-xs text-gray-500">
              {SOURCE_LABELS[session.source_type]} ·{' '}
              {session.provider?.name ?? 'AI Provider'} ·{' '}
              <span className={statusColor(session.status)}>{session.status}</span>
            </p>
          </div>
        </div>
        <div className="flex items-center gap-1 shrink-0">
          {session.status === 'failed' && (
            <button onClick={startStream} className="px-3 py-1.5 text-xs bg-blue-900/40 hover:bg-blue-900/60 text-blue-300 rounded border border-blue-700/40 transition">
              Retry
            </button>
          )}
          <button onClick={() => { if (confirm('Delete this session?')) deleteMutation.mutate() }}
            className="p-1.5 text-gray-500 hover:text-red-400 rounded transition">
            <Trash2 className="h-4 w-4" />
          </button>
        </div>
      </div>

      {/* Chain of work */}
      <div className="card p-4">
        <h3 className="text-[10px] font-bold text-gray-600 uppercase tracking-widest mb-3">Chain of Work</h3>
        {steps.length > 0
          ? <AnalysisChain steps={steps} />
          : <p className="text-xs text-gray-600 italic">Đang khởi tạo pipeline…</p>
        }
      </div>

      {/* Live Activity Panel — show while streaming OR if logs exist */}
      {(isStreaming || logs.length > 0) && (
        <LiveActivityPanel logs={logs} liveTokens={liveTokens} isStreaming={isStreaming} />
      )}

      {/* Error */}
      {streamError && (
        <div className="rounded-lg border border-red-500/30 bg-red-900/10 px-4 py-3 text-sm text-red-400">
          {streamError}
        </div>
      )}

      {/* Real-time output */}
      <div className="flex-1 min-h-0">
        {/* Pass empty content while streaming — output only shows final result */}
        <AnalysisStream content={isStreaming ? '' : result} isStreaming={isStreaming} />
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────
// Main Page
// ──────────────────────────────────────────────────────────────
export default function AIAnalysisPage() {
  const [searchParams] = useSearchParams()
  const [newOpen, setNewOpen] = useState(false)
  const [activeSessionId, setActiveSessionId] = useState<string | null>(null)
  const [view, setView] = useState<'sessions' | 'providers'>('sessions')

  // Support deep-link: /ai-analysis?source=job&id=<jobId>
  const preSourceType = (searchParams.get('source') as SessionSourceType | null) ?? undefined
  const preSourceId = searchParams.get('id') ?? undefined

  const { data: sessions = [], isLoading } = useQuery({
    queryKey: ['ai-sessions'],
    queryFn: analysisApi.listSessions,
    refetchInterval: 5000,
  })

  const activeSession = sessions.find(s => s.id === activeSessionId) ?? sessions[0] ?? null

  useEffect(() => {
    if (!activeSessionId && sessions.length > 0) {
      setActiveSessionId(sessions[0].id)
    }
  }, [sessions.length]) // eslint-disable-line

  // Auto-open modal if navigated from another page with source params.
  // offline_report only needs source (no preSourceId since user uploads the file).
  useEffect(() => {
    if (preSourceType && (preSourceId || preSourceType === 'offline_report')) {
      setNewOpen(true)
    }
  }, []) // eslint-disable-line

  return (
    <div className="flex h-full gap-4 min-h-[calc(100vh-120px)]">
      {/* Sidebar */}
      <div className="w-64 shrink-0 flex flex-col gap-3">
        <div className="flex items-center justify-between">
          <h1 className="text-sm font-bold text-gray-100 flex items-center gap-2">
            <BrainCircuit className="h-4 w-4 text-emerald-400" />
            AI Analysis
          </h1>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setView((v) => (v === 'providers' ? 'sessions' : 'providers'))}
              className={`p-1.5 rounded transition ${view === 'providers' ? 'text-emerald-400 bg-emerald-900/20' : 'text-gray-500 hover:text-gray-300'}`}
              title="AI Providers (configuration)"
            >
              <Settings2 className="h-4 w-4" />
            </button>
          </div>
        </div>

        <button onClick={() => setNewOpen(true)} className="btn-primary w-full justify-center">
          <Plus className="h-4 w-4" /> New Analysis
        </button>

        <div className="flex-1 overflow-y-auto space-y-1 custom-scrollbar">
          {isLoading ? (
            [...Array(3)].map((_, i) => <div key={i} className="skeleton h-14 rounded-lg" />)
          ) : sessions.length === 0 ? (
            <p className="text-xs text-gray-600 text-center mt-6">No sessions yet</p>
          ) : (
            sessions.map(s => {
              const Icon = SOURCE_ICONS[s.source_type]
              const isActive = s.id === (activeSession?.id)
              return (
                <button
                  key={s.id}
                  onClick={() => setActiveSessionId(s.id)}
                  className={`w-full text-left p-3 rounded-lg border transition ${
                    isActive ? 'border-emerald-500/40 bg-emerald-900/10' : 'border-transparent hover:border-gray-700 hover:bg-gray-900/40'
                  }`}
                >
                  <div className="flex items-start gap-2">
                    <Icon className={`h-3.5 w-3.5 mt-0.5 shrink-0 ${isActive ? 'text-emerald-400' : 'text-gray-500'}`} />
                    <div className="min-w-0 flex-1">
                      <div className="text-xs font-medium text-gray-200 truncate">{s.title || s.id.split('-')[0]}</div>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <span className={`text-[10px] ${statusColor(s.status)}`}>{s.status}</span>
                        <span className="text-[10px] text-gray-600">·</span>
                        <span className="text-[10px] text-gray-600">{safeDistanceToNow(s.created_at, { addSuffix: true })}</span>
                      </div>
                    </div>
                  </div>
                </button>
              )
            })
          )}
        </div>
      </div>

      {/* Main panel */}
      <div className="flex-1 min-w-0 overflow-y-auto">
        {view === 'providers' ? (
          <div>
            <button
              onClick={() => setView('sessions')}
              className="flex items-center gap-1.5 text-xs text-gray-400 hover:text-emerald-400 mb-4 transition"
            >
              <ArrowLeft className="h-3.5 w-3.5" /> Back to analysis
            </button>
            <AIProviderSettings />
          </div>
        ) : activeSession ? (
          <SessionPanel
            key={activeSession.id}
            session={activeSession}
            onDeleted={() => setActiveSessionId(null)}
          />
        ) : (
          <div className="flex flex-col items-center justify-center h-full text-center">
            <BrainCircuit className="h-14 w-14 text-gray-700 mb-4" />
            <h2 className="text-lg font-semibold text-gray-400">AI Analysis</h2>
            <p className="text-sm text-gray-600 mt-2 max-w-sm">
              Analyze tool results, evidence checklists, ELK hunt results, or upload external files (Redline, Volatility output, etc.)
            </p>
            <div className="flex items-center gap-2 mt-5">
              <button className="btn-primary" onClick={() => setNewOpen(true)}>
                <Plus className="h-4 w-4" /> New Analysis Session
              </button>
              <button className="btn-secondary" onClick={() => setView('providers')}>
                <Settings2 className="h-4 w-4" /> Configure AI Providers
              </button>
            </div>
          </div>
        )}
      </div>

      <NewAnalysisModal
        open={newOpen}
        onClose={() => setNewOpen(false)}
        preSourceType={preSourceType}
        preSourceId={preSourceId}
      />
    </div>
  )
}
