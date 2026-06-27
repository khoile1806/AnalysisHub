import { useState, Component, type ReactNode } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Activity, BrainCircuit, Database, HardDrive,
  RefreshCw, Server, Wifi, CheckCircle2, AlertTriangle,
  XCircle, Clock, Loader2, Zap, BarChart3, Cpu,
  History, ChevronDown, ChevronUp, MemoryStick,
} from 'lucide-react'
import { systemApi, type ComponentStatus, type ProviderTokenStat, type RecentSession, type ServerResources, type AgentResource } from '@/api/system'
import { safeDistanceToNow, safeFormat } from '@/lib/utils'

// ──────────────────────────────────────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────────────────────────────────────

function fmtUptime(secs: number): string {
  const d = Math.floor(secs / 86400)
  const h = Math.floor((secs % 86400) / 3600)
  const m = Math.floor((secs % 3600) / 60)
  const s = secs % 60
  if (d > 0) return `${d}d ${h}h ${m}m`
  if (h > 0) return `${h}h ${m}m ${s}s`
  if (m > 0) return `${m}m ${s}s`
  return `${s}s`
}

function fmtTokens(n: number): string {
  if (n >= 1_000_000) return (n / 1_000_000).toFixed(2) + 'M'
  if (n >= 1_000)     return (n / 1_000).toFixed(1) + 'K'
  return String(n)
}

function latencyColor(ms: number) {
  if (ms < 50)  return 'text-emerald-400'
  if (ms < 200) return 'text-yellow-400'
  return 'text-red-400'
}

const SOURCE_LABELS: Record<string, string> = {
  job: 'Tool Job',
  checklist_run: 'Checklist',
  elk_result: 'ELK Hunt',
  upload: 'File Upload',
}

const PROVIDER_TYPE_COLORS: Record<string, string> = {
  openai:    'bg-emerald-500/10 text-emerald-400 border-emerald-500/20',
  anthropic: 'bg-amber-500/10  text-amber-400  border-amber-500/20',
  google:    'bg-sky-500/10    text-sky-400    border-sky-500/20',
}

// ──────────────────────────────────────────────────────────────────────────────
// Component status card
// ──────────────────────────────────────────────────────────────────────────────

const COMP_ICONS: Record<string, React.ElementType> = {
  PostgreSQL:       Database,
  Redis:            Server,
  Storage:          HardDrive,
  'WebSocket Hub':  Wifi,
}

function ComponentCard({ comp }: { comp: ComponentStatus }) {
  const Icon = COMP_ICONS[comp.name] ?? Cpu
  const statusCfg = {
    ok:    { icon: CheckCircle2, color: 'text-emerald-400', bg: 'bg-emerald-500/5',  border: 'border-emerald-500/20', label: 'OK' },
    warn:  { icon: AlertTriangle, color: 'text-yellow-400', bg: 'bg-yellow-500/5',   border: 'border-yellow-500/20',  label: 'WARN' },
    error: { icon: XCircle,       color: 'text-red-400',    bg: 'bg-red-500/5',       border: 'border-red-500/20',     label: 'ERROR' },
  }[comp.status]

  const StatusIcon = statusCfg.icon

  return (
    <div className={`rounded-xl border ${statusCfg.border} ${statusCfg.bg} p-4 flex flex-col gap-3`}>
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2.5">
          <span className={`flex items-center justify-center h-8 w-8 rounded-lg bg-gray-800/60 border border-gray-700/50`}>
            <Icon className="h-4 w-4 text-gray-400" />
          </span>
          <span className="text-sm font-semibold text-gray-200">{comp.name}</span>
        </div>
        <div className="flex items-center gap-2">
          <StatusIcon className={`h-4 w-4 ${statusCfg.color}`} />
          <span className={`text-[11px] font-bold ${statusCfg.color}`}>{statusCfg.label}</span>
        </div>
      </div>

      <div className="flex items-center justify-between">
        <span className="text-[12px] text-gray-500 truncate max-w-[180px]">{comp.detail}</span>
        {comp.latency_ms > 0 && (
          <span className={`text-[11px] font-mono font-medium ${latencyColor(comp.latency_ms)} bg-gray-800/50 px-2 py-0.5 rounded border border-gray-700/40`}>
            {comp.latency_ms} ms
          </span>
        )}
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Stat mini-card
// ──────────────────────────────────────────────────────────────────────────────

function StatCard({ icon: Icon, label, value, sub, color = 'text-gray-200' }: {
  icon: React.ElementType
  label: string
  value: string | number
  sub?: string
  color?: string
}) {
  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/50 p-4 flex items-center gap-3">
      <span className="flex items-center justify-center h-9 w-9 rounded-lg bg-gray-800/60 border border-gray-700/40 shrink-0">
        <Icon className="h-4 w-4 text-gray-500" />
      </span>
      <div className="min-w-0">
        <div className={`text-xl font-bold ${color} truncate`}>{value}</div>
        <div className="text-[11px] text-gray-600 truncate">{label}</div>
        {sub && <div className="text-[10px] text-gray-700 truncate">{sub}</div>}
      </div>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Token usage bar
// ──────────────────────────────────────────────────────────────────────────────

function TokenBar({ value, max, color }: { value: number; max: number; color: string }) {
  const pct = max > 0 ? Math.round((value / max) * 100) : 0
  return (
    <div className="flex items-center gap-2 min-w-0">
      <div className="flex-1 h-1.5 rounded-full bg-gray-800 overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-[10px] text-gray-600 font-mono shrink-0 w-8 text-right">{pct}%</span>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Resource gauge (CPU / RAM / Disk)
// ──────────────────────────────────────────────────────────────────────────────

function resourceBarColor(pct: number) {
  if (pct < 50)  return 'bg-emerald-500'
  if (pct < 80)  return 'bg-yellow-500'
  return 'bg-red-500'
}

function resourceTextColor(pct: number) {
  if (pct < 50)  return 'text-emerald-400'
  if (pct < 80)  return 'text-yellow-400'
  return 'text-red-400'
}

function ResourceGauge({
  icon: Icon, label, percent, detail, subDetail,
}: {
  icon: React.ElementType
  label: string
  percent: number
  detail: string
  subDetail?: string
}) {
  const pct = Math.min(100, Math.round(percent))
  const barColor = resourceBarColor(pct)
  const textColor = resourceTextColor(pct)

  return (
    <div className="rounded-xl border border-gray-800/60 bg-gray-900/50 p-4 space-y-3">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className="flex items-center justify-center h-8 w-8 rounded-lg bg-gray-800/60 border border-gray-700/40 shrink-0">
            <Icon className="h-4 w-4 text-gray-500" />
          </span>
          <div>
            <div className="text-xs font-semibold text-gray-300">{label}</div>
            {subDetail && <div className="text-[10px] text-gray-600">{subDetail}</div>}
          </div>
        </div>
        <span className={`text-xl font-bold font-mono ${textColor}`}>{pct}%</span>
      </div>

      <div>
        <div className="h-2 rounded-full bg-gray-800 overflow-hidden">
          <div
            className={`h-full rounded-full transition-all ${barColor}`}
            style={{ width: `${pct}%` }}
          />
        </div>
        <div className="mt-1.5 text-[11px] text-gray-500">{detail}</div>
      </div>
    </div>
  )
}

function fmtMB(mb: number): string {
  if (mb >= 1024) return (mb / 1024).toFixed(1) + ' GB'
  return mb + ' MB'
}

function fmtGB(gb: number): string {
  if (gb >= 1024) return (gb / 1024).toFixed(1) + ' TB'
  return gb.toFixed(1) + ' GB'
}

// ──────────────────────────────────────────────────────────────────────────────
// Server Resources section
// ──────────────────────────────────────────────────────────────────────────────

function ServerResourcesSection({ res }: { res: ServerResources }) {
  const hasData = res.ram_total_mb > 0 || res.disk_total_gb > 0 || res.cpu_count > 0

  if (!hasData) {
    return (
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-5 py-6 text-center">
        <Cpu className="h-6 w-6 text-gray-700 mx-auto mb-2" />
        <p className="text-xs text-gray-600">Server resource stats unavailable (Linux only).</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
      <ResourceGauge
        icon={Cpu}
        label="CPU Usage"
        percent={res.cpu_percent}
        detail={res.cpu_percent > 0 ? `${res.cpu_percent.toFixed(1)}% across ${res.cpu_count} logical core(s)` : `${res.cpu_count} logical core(s) — no delta sample yet`}
        subDetail={`${res.cpu_count} core(s)`}
      />
      <ResourceGauge
        icon={MemoryStick}
        label="RAM"
        percent={res.ram_percent}
        detail={`${fmtMB(res.ram_used_mb)} / ${fmtMB(res.ram_total_mb)}`}
        subDetail="System memory"
      />
      <ResourceGauge
        icon={HardDrive}
        label="Storage Disk"
        percent={res.disk_percent}
        detail={`${fmtGB(res.disk_used_gb)} / ${fmtGB(res.disk_total_gb)}`}
        subDetail="Storage partition"
      />
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Agent Resources table
// ──────────────────────────────────────────────────────────────────────────────

function AgentResourcesTable({ agents }: { agents: AgentResource[] }) {
  if (agents.length === 0) {
    return (
      <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-5 py-6 text-center">
        <Server className="h-6 w-6 text-gray-700 mx-auto mb-2" />
        <p className="text-xs text-gray-600">No agents online or none reporting resource telemetry yet.</p>
        <p className="text-[11px] text-gray-700 mt-1">Agents must send <code className="font-mono">resource_report</code> to appear here.</p>
      </div>
    )
  }

  return (
    <div className="rounded-xl border border-gray-800/60 overflow-hidden">
      <table className="w-full text-sm">
        <thead>
          <tr className="bg-gray-900/60 border-b border-gray-800/60">
            <th className="text-left px-4 py-3 text-[11px] font-bold text-gray-600 uppercase tracking-wider">Agent</th>
            <th className="text-left px-4 py-3 text-[11px] font-bold text-gray-600 uppercase tracking-wider hidden sm:table-cell">OS / Host</th>
            <th className="px-4 py-3 text-[11px] font-bold text-gray-600 uppercase tracking-wider w-32">CPU</th>
            <th className="px-4 py-3 text-[11px] font-bold text-gray-600 uppercase tracking-wider w-40">RAM</th>
            <th className="px-4 py-3 text-[11px] font-bold text-gray-600 uppercase tracking-wider w-40 hidden md:table-cell">Disk</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-gray-800/40">
          {agents.map(agent => {
            const ramPct = agent.mem_total_mb > 0 ? (agent.mem_used_mb / agent.mem_total_mb) * 100 : 0
            const diskPct = agent.disk_total_gb > 0 ? (agent.disk_used_gb / agent.disk_total_gb) * 100 : 0
            return (
              <tr key={agent.id} className="hover:bg-gray-800/20 transition-colors">
                <td className="px-4 py-3">
                  <div className="flex items-center gap-2.5">
                    <span className="h-2 w-2 rounded-full bg-emerald-400 shrink-0" />
                    <div>
                      <div className="text-[13px] font-medium text-gray-200">{agent.name}</div>
                      <div className="text-[10px] text-gray-600 font-mono">{agent.id.slice(0, 8)}</div>
                    </div>
                  </div>
                </td>
                <td className="px-4 py-3 hidden sm:table-cell">
                  <div className="text-[12px] text-gray-400">{agent.hostname || '—'}</div>
                  <div className="text-[10px] text-gray-600">{agent.os || '—'}</div>
                </td>
                <td className="px-4 py-3">
                  {agent.cpu_percent > 0 ? (
                    <div className="space-y-1">
                      <div className={`text-xs font-mono font-semibold ${resourceTextColor(agent.cpu_percent)}`}>
                        {agent.cpu_percent.toFixed(1)}%
                      </div>
                      <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden w-20">
                        <div
                          className={`h-full rounded-full ${resourceBarColor(agent.cpu_percent)}`}
                          style={{ width: `${Math.min(100, agent.cpu_percent)}%` }}
                        />
                      </div>
                    </div>
                  ) : (
                    <span className="text-[11px] text-gray-700">—</span>
                  )}
                </td>
                <td className="px-4 py-3">
                  {agent.mem_total_mb > 0 ? (
                    <div className="space-y-1">
                      <div className="flex items-baseline gap-1.5">
                        <span className={`text-xs font-mono font-semibold ${resourceTextColor(ramPct)}`}>
                          {fmtMB(agent.mem_used_mb)}
                        </span>
                        <span className="text-[10px] text-gray-600">/ {fmtMB(agent.mem_total_mb)}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden w-24">
                        <div
                          className={`h-full rounded-full ${resourceBarColor(ramPct)}`}
                          style={{ width: `${Math.min(100, ramPct)}%` }}
                        />
                      </div>
                    </div>
                  ) : (
                    <span className="text-[11px] text-gray-700">—</span>
                  )}
                </td>
                <td className="px-4 py-3 hidden md:table-cell">
                  {agent.disk_total_gb > 0 ? (
                    <div className="space-y-1">
                      <div className="flex items-baseline gap-1.5">
                        <span className={`text-xs font-mono font-semibold ${resourceTextColor(diskPct)}`}>
                          {fmtGB(agent.disk_used_gb)}
                        </span>
                        <span className="text-[10px] text-gray-600">/ {fmtGB(agent.disk_total_gb)}</span>
                      </div>
                      <div className="h-1.5 rounded-full bg-gray-800 overflow-hidden w-24">
                        <div
                          className={`h-full rounded-full ${resourceBarColor(diskPct)}`}
                          style={{ width: `${Math.min(100, diskPct)}%` }}
                        />
                      </div>
                    </div>
                  ) : (
                    <span className="text-[11px] text-gray-700">—</span>
                  )}
                </td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Per-tab error boundary — prevents one tab's crash from killing the whole page
// ──────────────────────────────────────────────────────────────────────────────

class TabErrorBoundary extends Component<
  { label: string; children: ReactNode },
  { hasError: boolean; msg: string }
> {
  state = { hasError: false, msg: '' }

  static getDerivedStateFromError(err: unknown) {
    const msg = err instanceof Error ? err.message : String(err)
    return { hasError: true, msg }
  }

  render() {
    if (this.state.hasError) {
      return (
        <div className="rounded-xl border border-red-500/30 bg-red-900/10 p-5 space-y-2">
          <div className="flex items-center gap-2 text-red-400">
            <XCircle className="h-4 w-4 shrink-0" />
            <span className="text-sm font-medium">Failed to render tab {this.props.label}</span>
          </div>
          <p className="text-xs text-red-400/70 font-mono break-all">{this.state.msg}</p>
          <button
            onClick={() => this.setState({ hasError: false, msg: '' })}
            className="text-xs text-red-400 hover:text-red-300 underline"
          >
            Retry
          </button>
        </div>
      )
    }
    return this.props.children
  }
}

// ──────────────────────────────────────────────────────────────────────────────
// Health Check tab
// ──────────────────────────────────────────────────────────────────────────────

function HealthTab() {
  const { data, isLoading, isFetching, error, refetch, dataUpdatedAt } = useQuery({
    queryKey: ['system-health'],
    queryFn: systemApi.getHealth,
    refetchInterval: 30_000,
    staleTime: 10_000,
  })

  const overallOK = data?.status === 'ok'

  return (
    <div className="space-y-5">
      {/* Header bar */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          {data && (() => {
            const warn = data.status === 'warn'
            const cls = overallOK ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/20'
              : warn ? 'bg-yellow-500/10 text-yellow-400 border-yellow-500/20'
              : 'bg-red-500/10 text-red-400 border-red-500/20'
            const dot = overallOK ? 'bg-emerald-400 animate-pulse' : warn ? 'bg-yellow-400' : 'bg-red-400'
            const label = overallOK ? 'All Systems Operational' : warn ? 'Degraded — Resource Pressure' : 'System Degraded'
            return (
              <span className={`flex items-center gap-1.5 text-xs font-semibold px-3 py-1.5 rounded-full border ${cls}`}>
                <span className={`h-1.5 w-1.5 rounded-full ${dot}`} />
                {label}
              </span>
            )
          })()}
          {dataUpdatedAt > 0 && (
            <span className="text-[11px] text-gray-600">
              Updated {safeDistanceToNow(dataUpdatedAt, { addSuffix: true })}
            </span>
          )}
        </div>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-800/60 border border-gray-700/50 rounded-lg transition disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-gray-500 py-8 justify-center">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-sm">Checking system…</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-900/10 p-4 text-sm text-red-400">
          Cannot reach backend: {(error as Error).message}
        </div>
      )}

      {data && (
        <>
          {/* Uptime + quick stats */}
          <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
            <StatCard icon={Clock}    label="Uptime"          value={fmtUptime(data.uptime_seconds)} color="text-sky-300" />
            <StatCard icon={Wifi}     label="Agents Online"   value={data.agents_online} color="text-emerald-400"
              sub={`${data.agents_total} registered`} />
            <StatCard icon={Activity} label="Agents (DB)"     value={data.agents_db_online}
              sub={`${data.agents_total} total`} />
            <StatCard icon={Zap}      label="Jobs Running"    value={data.jobs_running} color={data.jobs_running > 0 ? 'text-blue-400' : 'text-gray-400'}
              sub={`${data.jobs_total} total`} />
            <StatCard icon={BrainCircuit} label="AI Sessions" value={data.sessions_total} />
            <StatCard icon={CheckCircle2} label="Checked At"  value={safeFormat(data.checked_at, 'HH:mm:ss')} />
          </div>

          {/* Component cards */}
          <div>
            <h3 className="text-[11px] font-bold text-gray-600 uppercase tracking-widest mb-3">Subsystem Status</h3>
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
              {data.components.map(comp => (
                <ComponentCard key={comp.name} comp={comp} />
              ))}
            </div>
          </div>

          {/* Platform internals — DB pool, runtime, activity, integrations */}
          {(data.db_pool || data.runtime || data.activity || data.integrations) && (
            <div>
              <h3 className="text-[11px] font-bold text-gray-600 uppercase tracking-widest mb-3">
                Platform Internals
                {data.version && <span className="ml-2 text-gray-500 normal-case font-normal">v{data.version}</span>}
              </h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-3">
                {data.db_pool && (
                  <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
                    <div className="text-[11px] font-bold text-gray-500 uppercase mb-2">DB Pool</div>
                    <div className="text-xs text-gray-300 space-y-1 font-mono">
                      <div>in use: <span className={data.db_pool.in_use >= data.db_pool.max_open && data.db_pool.max_open > 0 ? 'text-red-400' : 'text-emerald-400'}>{data.db_pool.in_use}</span> / {data.db_pool.max_open}</div>
                      <div>idle: {data.db_pool.idle} · open: {data.db_pool.open}</div>
                      <div className={data.db_pool.wait_count > 0 ? 'text-yellow-400' : 'text-gray-500'}>waits: {data.db_pool.wait_count} ({data.db_pool.wait_ms}ms)</div>
                    </div>
                  </div>
                )}
                {data.runtime && (
                  <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
                    <div className="text-[11px] font-bold text-gray-500 uppercase mb-2">Go Runtime</div>
                    <div className="text-xs text-gray-300 space-y-1 font-mono">
                      <div>goroutines: <span className={data.runtime.goroutines > 5000 ? 'text-red-400' : 'text-gray-300'}>{data.runtime.goroutines}</span></div>
                      <div>heap: {data.runtime.heap_mb} MB</div>
                      <div className="text-gray-500">{data.runtime.go_version}</div>
                    </div>
                  </div>
                )}
                {data.activity && (
                  <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
                    <div className="text-[11px] font-bold text-gray-500 uppercase mb-2">Activity</div>
                    <div className="text-xs text-gray-300 space-y-1 font-mono">
                      <div>jobs: {data.activity.jobs_running} running · {data.activity.jobs_pending} pending</div>
                      <div>OSINT scans: {data.activity.osint_running} running</div>
                      <div>AI sessions: {data.activity.sessions_total}</div>
                    </div>
                  </div>
                )}
                {data.integrations && (
                  <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
                    <div className="text-[11px] font-bold text-gray-500 uppercase mb-2">Integrations (active)</div>
                    <div className="text-xs text-gray-300 space-y-1 font-mono">
                      <div>SIEM: ELK {data.integrations.elk} · Splunk {data.integrations.splunk} · QRadar {data.integrations.qradar}</div>
                      <div>OpenCTI: {data.integrations.opencti}</div>
                      <div>AI providers: {data.integrations.ai_providers}</div>
                    </div>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Server resources */}
          {data.server && (
            <div>
              <h3 className="text-[11px] font-bold text-gray-600 uppercase tracking-widest mb-3">Server Resources</h3>
              <ServerResourcesSection res={data.server} />
            </div>
          )}

          {/* Agent resource telemetry */}
          <div>
            <h3 className="text-[11px] font-bold text-gray-600 uppercase tracking-widest mb-3">
              Agent Resources
              {data.agent_resources && data.agent_resources.length > 0 && (
                <span className="ml-2 text-emerald-500 normal-case font-normal">
                  {data.agent_resources.length} online
                </span>
              )}
            </h3>
            <AgentResourcesTable agents={data.agent_resources ?? []} />
          </div>

          {/* Latency summary */}
          <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 p-4">
            <h3 className="text-[11px] font-bold text-gray-600 uppercase tracking-widest mb-3">Response Latency</h3>
            <div className="space-y-2.5">
              {data.components.filter(c => c.latency_ms > 0).map(c => {
                const maxMs = 500
                const pct = Math.min(100, Math.round((c.latency_ms / maxMs) * 100))
                const barColor = c.latency_ms < 50 ? 'bg-emerald-500' : c.latency_ms < 200 ? 'bg-yellow-500' : 'bg-red-500'
                return (
                  <div key={c.name} className="flex items-center gap-3">
                    <span className="text-xs text-gray-500 w-28 shrink-0">{c.name}</span>
                    <div className="flex-1 h-1.5 rounded-full bg-gray-800 overflow-hidden">
                      <div className={`h-full rounded-full ${barColor}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className={`text-[11px] font-mono w-14 text-right shrink-0 ${latencyColor(c.latency_ms)}`}>
                      {c.latency_ms} ms
                    </span>
                  </div>
                )
              })}
            </div>
          </div>
        </>
      )}
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Token Usage tab
// ──────────────────────────────────────────────────────────────────────────────

function TokenUsageTab() {
  const [showAll, setShowAll] = useState(false)

  const { data, isLoading, isFetching, refetch, error } = useQuery({
    queryKey: ['system-token-stats'],
    queryFn: systemApi.getTokenStats,
    staleTime: 60_000,
  })

  const maxTokens = (data?.by_provider ?? []).reduce((m, p) => Math.max(m, p.total_tokens), 0)

  const providerBarColors = [
    'bg-violet-500', 'bg-sky-500', 'bg-emerald-500',
    'bg-amber-500', 'bg-rose-500', 'bg-teal-500',
  ]

  const recentVisible = showAll
    ? (data?.recent ?? [])
    : (data?.recent ?? []).slice(0, 5)

  return (
    <div className="space-y-5">
      {/* Toolbar */}
      <div className="flex items-center justify-between">
        <span className="text-xs text-gray-600">Stats from all completed analysis sessions</span>
        <button
          onClick={() => refetch()}
          disabled={isFetching}
          className="flex items-center gap-1.5 px-3 py-1.5 text-xs text-gray-400 hover:text-white bg-gray-800/60 border border-gray-700/50 rounded-lg transition disabled:opacity-50"
        >
          <RefreshCw className={`h-3.5 w-3.5 ${isFetching ? 'animate-spin' : ''}`} />
          Refresh
        </button>
      </div>

      {isLoading && (
        <div className="flex items-center gap-2 text-gray-500 py-8 justify-center">
          <Loader2 className="h-5 w-5 animate-spin" />
          <span className="text-sm">Loading stats…</span>
        </div>
      )}

      {error && (
        <div className="rounded-xl border border-red-500/30 bg-red-900/10 p-4 text-sm text-red-400 flex items-center gap-2">
          <XCircle className="h-4 w-4 shrink-0" />
          Failed to load token stats: {(error as Error).message}
        </div>
      )}

      {data && (
        <>
          {/* Summary cards */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
            <div className="rounded-xl border border-violet-500/20 bg-violet-500/5 p-5 flex items-center gap-4">
              <span className="flex items-center justify-center h-10 w-10 rounded-xl bg-violet-500/10 border border-violet-500/20 shrink-0">
                <BrainCircuit className="h-5 w-5 text-violet-400" />
              </span>
              <div>
                <div className="text-2xl font-bold text-violet-300">{fmtTokens(data.total_tokens)}</div>
                <div className="text-[11px] text-gray-500">Total Tokens Used</div>
                <div className="text-[10px] text-gray-700">{data.total_tokens.toLocaleString()} tokens</div>
              </div>
            </div>
            <div className="rounded-xl border border-sky-500/20 bg-sky-500/5 p-5 flex items-center gap-4">
              <span className="flex items-center justify-center h-10 w-10 rounded-xl bg-sky-500/10 border border-sky-500/20 shrink-0">
                <BarChart3 className="h-5 w-5 text-sky-400" />
              </span>
              <div>
                <div className="text-2xl font-bold text-sky-300">{data.total_sessions}</div>
                <div className="text-[11px] text-gray-500">Analysis Sessions</div>
                <div className="text-[10px] text-gray-700">{data.by_provider.length} provider(s) used</div>
              </div>
            </div>
            <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-5 flex items-center gap-4">
              <span className="flex items-center justify-center h-10 w-10 rounded-xl bg-emerald-500/10 border border-emerald-500/20 shrink-0">
                <Zap className="h-5 w-5 text-emerald-400" />
              </span>
              <div>
                <div className="text-2xl font-bold text-emerald-300">
                  {data.total_sessions > 0
                    ? fmtTokens(Math.round(data.total_tokens / data.total_sessions))
                    : '—'}
                </div>
                <div className="text-[11px] text-gray-500">Avg Tokens / Session</div>
              </div>
            </div>
          </div>

          {/* Per-provider breakdown */}
          {data.by_provider.length > 0 && (
            <div className="rounded-xl border border-gray-800/60 overflow-hidden">
              <div className="px-5 py-3 bg-gray-900/60 border-b border-gray-800/60 flex items-center gap-2">
                <BrainCircuit className="h-4 w-4 text-violet-400" />
                <span className="text-sm font-semibold text-gray-200">Theo Provider</span>
              </div>
              <div className="divide-y divide-gray-800/60">
                {data.by_provider.map((row: ProviderTokenStat, idx) => (
                  <div key={row.provider_id} className="px-5 py-4">
                    <div className="flex items-start gap-4 mb-2.5">
                      {/* Index */}
                      <span className="shrink-0 text-[11px] font-bold text-gray-700 w-4 mt-0.5">#{idx + 1}</span>

                      {/* Provider info */}
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 flex-wrap mb-1">
                          <span className="text-sm font-semibold text-gray-200">{row.provider_name}</span>
                          {row.provider_type && (
                            <span className={`text-[10px] font-medium px-1.5 py-0.5 rounded border ${PROVIDER_TYPE_COLORS[row.provider_type] ?? 'bg-gray-800 text-gray-400 border-gray-700'}`}>
                              {row.provider_type}
                            </span>
                          )}
                          {row.model && (
                            <span className="text-[11px] text-gray-500 font-mono">{row.model}</span>
                          )}
                        </div>
                        <TokenBar
                          value={row.total_tokens}
                          max={maxTokens}
                          color={providerBarColors[idx % providerBarColors.length]}
                        />
                      </div>

                      {/* Stats */}
                      <div className="flex items-center gap-5 shrink-0 text-right">
                        <div>
                          <div className="text-sm font-bold text-gray-200">{fmtTokens(row.total_tokens)}</div>
                          <div className="text-[10px] text-gray-600">total</div>
                        </div>
                        <div>
                          <div className="text-sm font-medium text-gray-400">{row.sessions}</div>
                          <div className="text-[10px] text-gray-600">sessions</div>
                        </div>
                        <div>
                          <div className="text-sm font-medium text-gray-500">{fmtTokens(Math.round(row.avg_tokens))}</div>
                          <div className="text-[10px] text-gray-600">avg/session</div>
                        </div>
                        <div className="hidden sm:block">
                          <div className="text-[11px] text-gray-600">
                            {row.last_used
                              ? safeDistanceToNow(row.last_used, { addSuffix: true })
                              : '—'}
                          </div>
                          <div className="text-[10px] text-gray-700">last used</div>
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {data.by_provider.length === 0 && (
            <div className="rounded-xl border border-gray-800/60 bg-gray-900/40 px-5 py-10 text-center">
              <BrainCircuit className="h-8 w-8 text-gray-700 mx-auto mb-3" />
              <p className="text-sm text-gray-600">No completed sessions yet.</p>
              <p className="text-xs text-gray-700 mt-1">Run an AI Analysis to see token stats.</p>
            </div>
          )}

          {/* Recent sessions */}
          {data.recent.length > 0 && (
            <div className="rounded-xl border border-gray-800/60 overflow-hidden">
              <div className="px-5 py-3 bg-gray-900/60 border-b border-gray-800/60 flex items-center gap-2">
                <History className="h-4 w-4 text-gray-500" />
                <span className="text-sm font-semibold text-gray-200">Recent history</span>
                <span className="text-[10px] text-gray-600 ml-auto">
                  {showAll ? data.recent.length : Math.min(5, data.recent.length)} / {data.recent.length}
                </span>
              </div>
              <div className="divide-y divide-gray-800/40">
                {recentVisible.map((row: RecentSession) => (
                  <div key={row.id} className="px-5 py-3 flex items-center gap-4 hover:bg-gray-800/20 transition-colors">
                    <span className="text-[10px] text-gray-600 font-mono w-16 shrink-0">{row.id.slice(0, 8)}</span>
                    <span className="flex-1 min-w-0 text-[13px] text-gray-300 truncate">{row.title || row.id}</span>
                    <span className="text-[11px] text-gray-600 bg-gray-800/50 px-1.5 py-0.5 rounded shrink-0">
                      {SOURCE_LABELS[row.source_type] ?? row.source_type}
                    </span>
                    <span className="text-[12px] font-medium text-violet-400 shrink-0 w-16 text-right font-mono">
                      {fmtTokens(row.tokens_used)}
                    </span>
                    <span className="text-[11px] text-gray-600 shrink-0 w-24 text-right hidden sm:block">
                      {row.finished_at
                        ? safeDistanceToNow(row.finished_at, { addSuffix: true })
                        : '—'}
                    </span>
                  </div>
                ))}
              </div>
              {data.recent.length > 5 && (
                <button
                  onClick={() => setShowAll(s => !s)}
                  className="w-full flex items-center justify-center gap-1.5 px-5 py-2.5 text-xs text-gray-500 hover:text-gray-300 hover:bg-gray-800/30 border-t border-gray-800/40 transition-colors"
                >
                  {showAll
                    ? <><ChevronUp className="h-3.5 w-3.5" /> Collapse</>
                    : <><ChevronDown className="h-3.5 w-3.5" /> Show {data.recent.length - 5} more session(s)</>
                  }
                </button>
              )}
            </div>
          )}
        </>
      )}
    </div>
  )
}

// ──────────────────────────────────────────────────────────────────────────────
// Main Page
// ──────────────────────────────────────────────────────────────────────────────

type Tab = 'health' | 'tokens'

const TABS: { id: Tab; label: string; icon: React.ElementType }[] = [
  { id: 'health', label: 'Health Check',  icon: Activity },
  { id: 'tokens', label: 'Token Usage',   icon: BrainCircuit },
]

export default function SystemHealthPage() {
  const [tab, setTab] = useState<Tab>('health')

  return (
    <div className="space-y-5">
      {/* Page header */}
      <div>
        <h1 className="text-lg font-bold text-gray-100 flex items-center gap-2">
          <Activity className="h-5 w-5 text-emerald-400" />
          System Health
        </h1>
        <p className="text-sm text-gray-500 mt-0.5">
          Subsystem status and AI token usage stats.
        </p>
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-gray-800/60 pb-0">
        {TABS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setTab(id)}
            className={`flex items-center gap-2 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors
              ${tab === id
                ? 'border-emerald-500 text-emerald-400'
                : 'border-transparent text-gray-500 hover:text-gray-300 hover:border-gray-700'
              }`}
          >
            <Icon className="h-4 w-4" />
            {label}
          </button>
        ))}
      </div>

      {/* Tab content — each tab has its own error boundary so a crash
          in one tab doesn't kill the whole page */}
      {tab === 'health' && (
        <TabErrorBoundary label="Health Check">
          <HealthTab />
        </TabErrorBoundary>
      )}
      {tab === 'tokens' && (
        <TabErrorBoundary label="Token Usage">
          <TokenUsageTab />
        </TabErrorBoundary>
      )}
    </div>
  )
}
