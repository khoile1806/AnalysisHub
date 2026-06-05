import { useEffect, useRef, useState, useCallback } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import { ArrowLeft, Download, Clock, Server, Wrench, Calendar, RefreshCw, BrainCircuit } from 'lucide-react'
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

export default function JobDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const [outputLines, setOutputLines] = useState<string[]>([])
  const [sseConnected, setSseConnected] = useState(false)
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

          {/* AI Analysis */}
          {isTerminal && (
            <div className="card p-4">
              <h2 className="text-sm font-semibold text-gray-200 mb-1">AI Analysis</h2>
              <p className="text-xs text-gray-500 mb-3">Send this job's output and artifact to an AI provider for forensic analysis.</p>
              <button
                onClick={() => navigate(`/ai-analysis?source=job&id=${job.id}`)}
                className="flex items-center gap-2 w-full justify-center px-3 py-2 text-sm bg-violet-900/30 hover:bg-violet-900/50 text-violet-300 border border-violet-500/30 rounded-lg transition"
              >
                <BrainCircuit className="h-4 w-4" />
                Analyze with AI
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
        </div>

        {/* Right: terminal output */}
        <div className="lg:col-span-2">
          <div className="flex items-center justify-between mb-2">
            <h2 className="text-sm font-semibold text-gray-200">Output</h2>
            {sseConnected && (
              <span className="text-xs text-emerald-400 font-mono flex items-center gap-1.5">
                <span className="relative flex h-1.5 w-1.5">
                  <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
                  <span className="relative inline-flex rounded-full h-1.5 w-1.5 bg-emerald-500" />
                </span>
                Streaming live
              </span>
            )}
            {outputLines.length > 0 && (
              <span className="text-xs text-gray-500">{outputLines.length} lines</span>
            )}
          </div>

          <TerminalOutput
            lines={outputLines}
            isRunning={isRunning || job.status === 'pending'}
            className="min-h-[400px]"
          />

          {job.status === 'failed' && (
            <div className="mt-3 rounded-lg bg-red-900/20 border border-red-800/40 p-3">
              <p className="text-xs text-red-400 font-medium">
                Job failed. Check the output above for error details.
              </p>
            </div>
          )}
          {job.status === 'done' && (
            <div className="mt-3 rounded-lg bg-emerald-900/20 border border-emerald-800/40 p-3">
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
