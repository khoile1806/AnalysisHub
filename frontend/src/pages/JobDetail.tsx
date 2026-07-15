import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { ArrowLeft, Download, Clock, Server, Wrench, Calendar, RefreshCw, BrainCircuit, Terminal as TerminalIcon, FileText } from 'lucide-react'
import toast from 'react-hot-toast'
import { jobsApi } from '@/api/jobs'
import { JobStatusBadge } from '@/components/StatusBadge'
import TerminalOutput from '@/components/Terminal'
import { formatDuration, safeDistanceToNow, safeFormat } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import { useNavigate } from 'react-router-dom'

function InfoRow({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: React.ReactNode }) {
  return (
    <div className="flex items-start gap-3 py-3 border-b border-gray-800 last:border-0">
      <div className="flex h-7 w-7 items-center justify-center rounded bg-gray-800 shrink-0 mt-0.5">
        <Icon className="h-3.5 w-3.5 text-gray-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-xs text-gray-500 mb-0.5">{label}</p>
        <div className="text-sm text-gray-200">{value}</div>
      </div>
    </div>
  )
}

function ToolResultsPanel({ jobId }: { jobId: string }) {
  const qc = useQueryClient()
  const { data: results } = useQuery({
    queryKey: ['job-results', jobId],
    queryFn: () => jobsApi.listResults(jobId),
    enabled: !!jobId,
    refetchInterval: 5_000,
  })
  const aiMut = useMutation({
    mutationFn: ({ rid, forAI }: { rid: string; forAI: boolean }) => jobsApi.setResultAI(rid, forAI),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['job-results', jobId] }),
  })
  const analyzeMut = useMutation({
    mutationFn: () => jobsApi.analyzeResults(jobId),
    onSuccess: (d) => {
      toast.success(d.note ?? `AI: ${d.created} timeline event(s), ${d.iocs_promoted} IOC(s) from ${d.findings} finding(s)`)
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : 'AI analysis failed'),
  })
  const bulkAiMut = useMutation({
    mutationFn: (forAI: boolean) => jobsApi.setJobResultsAI(jobId, forAI),
    onSuccess: (d) => {
      qc.invalidateQueries({ queryKey: ['job-results', jobId] })
      toast.success(`${d.for_ai ? 'Flagged' : 'Cleared'} ${d.updated} result(s) for AI`)
    },
    onError: (e: unknown) => toast.error(e instanceof Error ? e.message : 'Update failed'),
  })
  if (!results || results.length === 0) return null
  const anyForAI = results.some((r) => r.for_ai && r.process_status === 'done')
  const allForAI = results.every((r) => r.for_ai)
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between gap-2 mb-3">
        <h2 className="text-sm font-semibold text-gray-200">
          Collected Results <span className="text-gray-500 font-normal">({results.length})</span>
        </h2>
        <div className="flex items-center gap-2">
          {results.length > 1 && (
            <button
              onClick={() => bulkAiMut.mutate(!allForAI)}
              disabled={bulkAiMut.isPending}
              className="px-2 py-1 text-[11px] text-gray-400 hover:text-gray-200 border border-gray-700 rounded-md transition disabled:opacity-50"
              title="Toggle the for-AI flag on every collected result at once"
            >
              {allForAI ? 'Clear all AI' : 'Flag all for AI'}
            </button>
          )}
          {anyForAI && (
            <button
              onClick={() => analyzeMut.mutate()}
              disabled={analyzeMut.isPending}
              className="flex items-center gap-1.5 px-2.5 py-1 text-[11px] bg-violet-900/30 hover:bg-violet-900/50 text-violet-300 border border-violet-500/30 rounded-md transition disabled:opacity-50"
              title="Run AI over the for-AI results and add findings to the case timeline"
            >
              <BrainCircuit className="h-3 w-3" />
              {analyzeMut.isPending ? 'Analyzing…' : 'Extract findings → timeline'}
            </button>
          )}
        </div>
      </div>
      <div className="space-y-2">
        {results.map((r) => (
          <div key={r.id} className="rounded-lg border border-gray-800 bg-gray-900/40 p-2.5">
            <div className="flex items-center justify-between gap-2">
              <span className="text-xs font-mono text-gray-200 truncate" title={r.file_name}>{r.file_name}</span>
              <span className="text-[10px] uppercase tracking-wide text-gray-500 shrink-0">{r.kind}</span>
            </div>
            <div className="flex items-center gap-2 mt-1 text-[11px] text-gray-500">
              <span className={
                r.process_status === 'done' ? 'text-emerald-400'
                  : r.process_status === 'error' ? 'text-red-400'
                  : 'text-amber-400'
              } title={r.process_error || ''}>
                {r.process_status === 'done' ? '● parsed'
                  : r.process_status === 'error' ? '● error'
                  : r.process_status === 'processing' ? '◌ processing' : '◌ queued'}
              </span>
              <span>· {r.processor || 'none'}</span>
              {r.row_count > 0 && <span>· {r.row_count} rows</span>}
              <span>· {(r.size_bytes / 1024).toFixed(0)} KB</span>
            </div>
            {r.summary && (
              <p className="text-[11px] text-gray-500 mt-1 whitespace-pre-wrap line-clamp-3">{r.summary}</p>
            )}
            {(r.tool_version || r.cmdline || r.exit_code !== undefined) && (
              <div className="text-[10px] text-gray-600 mt-1 flex flex-wrap items-center gap-x-2 gap-y-0.5">
                {r.tool_version && <span>v{r.tool_version}</span>}
                {r.exit_code !== undefined && <span className={r.exit_code === 0 ? '' : 'text-amber-500'}>exit {r.exit_code}</span>}
                {r.cmdline && <span className="font-mono truncate max-w-[280px]" title={r.cmdline}>$ {r.cmdline}</span>}
              </div>
            )}
            <div className="flex items-center justify-between mt-2">
              <label className="flex items-center gap-1.5 cursor-pointer text-[11px] text-gray-400">
                <input
                  type="checkbox"
                  checked={r.for_ai}
                  onChange={(e) => aiMut.mutate({ rid: r.id, forAI: e.target.checked })}
                />
                Use for AI
              </label>
              <a href={jobsApi.resultDownloadUrl(r.id)} download className="text-[11px] text-emerald-400 hover:underline">
                Download
              </a>
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

export default function JobDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [outputLines, setOutputLines] = useState<string[]>([])
  const [sseConnected, setSseConnected] = useState(false)
  const [viewMode, setViewMode] = useState<'process' | 'report'>('process')
  const eventSourceRef = useRef<EventSource | null>(null)
  const token = useAuthStore((s) => s.token)

  const { data: job, isLoading, refetch } = useQuery({
    queryKey: ['job', id],
    queryFn: () => jobsApi.get(id!),
    enabled: !!id,
    refetchInterval: (query) => {
      const status = query.state.data?.status
      return status === 'running' || status === 'pending' ? 3_000 : false
    },
  })

  const isRunning = job?.status === 'running'
  const isTerminal = job?.status === 'done' || job?.status === 'failed'

  // When job output is loaded and not running, split stored output into lines
  useEffect(() => {
    if (job && isTerminal && job.output) {
      setOutputLines(job.output.split('\n'))
    }
  }, [job, isTerminal])

  // SSE connection for live output
  const connectSSE = useCallback(() => {
    if (!id || !isRunning) return
    if (eventSourceRef.current) {
      eventSourceRef.current.close()
    }

    const base = `${import.meta.env.VITE_API_URL ?? ''}/api/v1`
    const url = `${base}/jobs/${id}/output${token ? `?token=${encodeURIComponent(token)}` : ''}`

    const es = new EventSource(url)
    eventSourceRef.current = es

    es.onopen = () => setSseConnected(true)

    es.onmessage = (event) => {
      if (event.data === '[DONE]') {
        es.close()
        setSseConnected(false)
        refetch()
        return
      }
      setOutputLines((prev) => [...prev, event.data])
    }

    es.addEventListener('line', (event) => {
      setOutputLines((prev) => [...prev, (event as MessageEvent).data])
    })

    es.onerror = () => {
      setSseConnected(false)
      es.close()
    }

    return () => {
      es.close()
      setSseConnected(false)
    }
  }, [id, isRunning, token, refetch])

  useEffect(() => {
    if (isRunning) {
      setOutputLines([])
      const cleanup = connectSSE()
      return cleanup
    }
    return () => {
      eventSourceRef.current?.close()
    }
  }, [isRunning, connectSSE])

  // Cleanup on unmount
  useEffect(() => {
    return () => {
      eventSourceRef.current?.close()
    }
  }, [])

  if (isLoading) {
    return (
      <div className="space-y-5">
        <div className="skeleton h-8 w-48 rounded" />
        <div className="skeleton h-32 w-full rounded" />
        <div className="skeleton h-64 w-full rounded" />
      </div>
    )
  }

  if (!job) {
    return (
      <div className="flex flex-col items-center justify-center py-20 text-gray-500">
        <p className="text-sm">Job not found</p>
        <Link to="/jobs" className="mt-4 btn-secondary text-xs">
          <ArrowLeft className="h-3.5 w-3.5" /> Back to Jobs
        </Link>
      </div>
    )
  }

  const artifactDownloadUrl = (() => {
    if (!job.artifact_path) return null
    const base = `${import.meta.env.VITE_API_URL ?? ''}/api/v1`
    return `${base}/jobs/${job.id}/artifact`
  })()

  return (
    <div className="space-y-5 max-w-5xl">
      {/* Back link + header */}
      <div>
        <Link
          to="/jobs"
          className="inline-flex items-center gap-1.5 text-sm text-gray-400 hover:text-gray-200 transition-colors mb-3"
        >
          <ArrowLeft className="h-4 w-4" /> Back to Jobs
        </Link>
        <div className="flex flex-wrap items-center justify-between gap-3">
          <div>
            <h1 className="text-xl font-semibold text-gray-100 font-mono">
              Job{' '}
              <span className="text-emerald-400">{job.id.slice(0, 8)}…</span>
            </h1>
            <p className="text-sm text-gray-400 mt-0.5">
              Created {safeDistanceToNow(job.created_at, { addSuffix: true })}
            </p>
          </div>
          <div className="flex items-center gap-3">
            <JobStatusBadge status={job.status} />
            {(job.status === 'running' || job.status === 'pending') && (
              <button
                onClick={() => refetch()}
                className="btn-secondary text-xs"
                title="Refresh"
              >
                <RefreshCw className="h-3.5 w-3.5" />
              </button>
            )}
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-3 gap-5">
        {/* Left: metadata */}
        <div className="lg:col-span-1 space-y-4">
          <div className="card p-0 overflow-hidden">
            <div className="px-4 py-3 border-b border-gray-800">
              <h2 className="text-sm font-semibold text-gray-200">Job Details</h2>
            </div>
            <div className="px-4">
              <InfoRow
                icon={Wrench}
                label="Tool"
                value={
                  <Link
                    to="/tools"
                    className="text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    {job.tool?.name ?? job.tool_id}
                  </Link>
                }
              />
              <InfoRow
                icon={Server}
                label="Agent"
                value={
                  <Link
                    to="/agents"
                    className="text-emerald-400 hover:text-emerald-300 transition-colors"
                  >
                    {job.agent?.name ?? job.agent_id}
                  </Link>
                }
              />
              {job.args && (
                <InfoRow
                  icon={Wrench}
                  label="Arguments"
                  value={
                    <code className="text-xs font-mono text-amber-400 break-all">{job.args}</code>
                  }
                />
              )}
              <InfoRow
                icon={Calendar}
                label="Created"
                value={safeFormat(job.created_at, 'PPpp')}
              />
              {job.started_at && (
                <InfoRow
                  icon={Clock}
                  label="Started"
                  value={safeFormat(job.started_at, 'PPpp')}
                />
              )}
              {job.finished_at && (
                <InfoRow
                  icon={Clock}
                  label="Finished"
                  value={safeFormat(job.finished_at, 'PPpp')}
                />
              )}
              {job.started_at && (
                <InfoRow
                  icon={Clock}
                  label="Duration"
                  value={
                    <span className="font-mono text-xs">
                      {formatDuration(job.started_at, job.finished_at)}
                    </span>
                  }
                />
              )}
            </div>
          </div>

          {/* Artifact download */}
          {artifactDownloadUrl && (
            <div className="card p-4">
              <h2 className="text-sm font-semibold text-gray-200 mb-3">Artifact</h2>
              <p className="text-xs text-gray-500 mb-3 font-mono break-all">{job.artifact_path}</p>
              <a
                href={artifactDownloadUrl}
                download
                className="btn-primary w-full justify-center text-sm"
              >
                <Download className="h-4 w-4" /> Download Artifact
              </a>
            </div>
          )}

          {/* AI narrative report (free-form). For structured findings that go on
              the case timeline, use "Extract findings → timeline" in Collected
              Results below. */}
          {isTerminal && (
            <div className="card p-4">
              <h2 className="text-sm font-semibold text-gray-200 mb-1">AI Narrative Report</h2>
              <p className="text-xs text-gray-500 mb-3">Open a free-form AI forensic write-up of this job's output. For findings on the case timeline, use "Extract findings → timeline" in Collected Results.</p>
              <button
                onClick={() => navigate(`/ai-analysis?source=job&id=${job.id}`)}
                className="flex items-center gap-2 w-full justify-center px-3 py-2 text-sm bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded-lg transition"
              >
                <BrainCircuit className="h-4 w-4" />
                Open AI narrative report
              </button>
            </div>
          )}

          {/* Agent info */}
          {job.agent && (
            <div className="card p-4">
              <h2 className="text-sm font-semibold text-gray-200 mb-3">Agent Info</h2>
              <div className="space-y-2 text-xs">
                <div className="flex justify-between">
                  <span className="text-gray-500">Hostname</span>
                  <span className="text-gray-300 font-mono">{job.agent.hostname || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">OS</span>
                  <span className="text-gray-300">{job.agent.os || '—'}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-gray-500">IP Address</span>
                  <span className="text-gray-300 font-mono">{job.agent.ip_address || '—'}</span>
                </div>
              </div>
            </div>
          )}

          {/* Collected result files (auto-pulled per the tool's output spec) */}
          <ToolResultsPanel jobId={job.id} />
        </div>

        {/* Right: terminal output / report viewer */}
        <div className="lg:col-span-2 flex flex-col h-full min-h-[500px]">
          <div className="flex items-center gap-2 mb-3 bg-gray-900/50 p-1.5 rounded-lg border border-gray-800 self-start">
            <button 
              onClick={() => setViewMode('process')}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                viewMode === 'process' 
                  ? 'bg-gray-800 text-emerald-400 shadow-sm' 
                  : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <TerminalIcon className="h-3.5 w-3.5" />
              Process Output
            </button>
            <button 
              onClick={() => setViewMode('report')}
              disabled={!artifactDownloadUrl}
              className={`flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                viewMode === 'report' 
                  ? 'bg-gray-800 text-emerald-400 shadow-sm' 
                  : !artifactDownloadUrl ? 'opacity-30 cursor-not-allowed' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              <FileText className="h-3.5 w-3.5" />
              Report Viewer
            </button>
          </div>

          <div className="flex-1 flex flex-col min-h-0 bg-gray-900/30 rounded-xl border border-gray-800 overflow-hidden relative">
            {viewMode === 'process' ? (
              <div className="flex flex-col h-full">
                <div className="flex items-center justify-between p-3 border-b border-gray-800">
                  <h2 className="text-sm font-semibold text-gray-200">Terminal Output</h2>
                  {sseConnected && (
                    <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
                      <span className="relative flex h-1.5 w-1.5">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                        <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                      </span>
                      Streaming live
                    </span>
                  )}
                  {!sseConnected && outputLines.length > 0 && (
                    <span className="text-xs text-gray-500">{outputLines.length} lines</span>
                  )}
                </div>
                <TerminalOutput
                  lines={outputLines}
                  isRunning={isRunning || job.status === 'pending'}
                  className="flex-1 border-0 rounded-none"
                />
              </div>
            ) : (
              <iframe
                src={job.id ? `${import.meta.env.VITE_API_URL ?? ''}/api/v1/jobs/${job.id}/artifact/content?token=${encodeURIComponent(token ?? '')}` : ''}
                className="absolute inset-0 w-full h-full border-none bg-white"
                title="Artifact Report"
                // Report HTML is tool-generated and may embed attacker-controlled
                // strings; sandbox it (no allow-scripts) so it can't run JS in our
                // origin and read the auth token from localStorage.
                sandbox="allow-same-origin"
              />
            )}
          </div>

          {job.status === 'failed' && (
            <div className="mt-3 rounded-lg bg-red-900/20 border border-red-800/40 p-3 shrink-0">
              <p className="text-xs text-red-400 font-medium">
                Job failed. Check the output above for error details.
              </p>
            </div>
          )}
          {job.status === 'done' && viewMode === 'process' && (
            <div className="mt-3 rounded-lg bg-emerald-900/20 border border-emerald-800/40 p-3 shrink-0">
              <p className="text-xs text-emerald-400 font-medium">
                Job completed successfully in {formatDuration(job.started_at, job.finished_at)}.
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
