import apiClient from './client'

export interface ComponentStatus {
  name: string
  status: 'ok' | 'warn' | 'error'
  latency_ms: number
  detail: string
}

export interface ServerResources {
  cpu_count: number
  cpu_percent: number
  ram_total_mb: number
  ram_used_mb: number
  ram_percent: number
  disk_total_gb: number
  disk_used_gb: number
  disk_percent: number
}

export interface AgentResource {
  id: string
  name: string
  hostname: string
  os: string
  cpu_percent: number
  mem_used_mb: number
  mem_total_mb: number
  disk_used_gb: number
  disk_total_gb: number
}

export interface DBPool {
  max_open: number; open: number; in_use: number; idle: number
  wait_count: number; wait_ms: number
}
export interface RuntimeInfo { go_version: string; goroutines: number; heap_mb: number }
export interface Integrations { elk: number; splunk: number; qradar: number; opencti: number; ai_providers: number }
export interface Activity { jobs_pending: number; jobs_running: number; osint_running: number; sessions_total: number }

export interface HealthData {
  status: 'ok' | 'degraded' | 'warn'
  version?: string
  uptime_seconds: number
  components: ComponentStatus[]
  agents_online: number
  agents_total: number
  agents_db_online: number
  jobs_total: number
  jobs_running: number
  sessions_total: number
  checked_at: string
  server: ServerResources
  agent_resources: AgentResource[]
  db_pool?: DBPool
  runtime?: RuntimeInfo
  integrations?: Integrations
  activity?: Activity
}

export interface ProviderTokenStat {
  provider_id: string
  provider_name: string
  model: string
  provider_type: 'openai' | 'anthropic' | 'google' | ''
  sessions: number
  total_tokens: number
  avg_tokens: number
  last_used: string | null
}

export interface RecentSession {
  id: string
  title: string
  source_type: string
  tokens_used: number
  finished_at: string | null
  provider_id: string
  duration_ms?: number
}

// One row of the per-FEATURE breakdown — the question the old panel could not
// answer, because it only counted AI Analysis sessions and every other AI feature
// in the platform spent tokens invisibly.
export interface FeatureTokenStat {
  feature: string
  calls: number
  failed: number
  total_tokens: number
  avg_tokens: number
  avg_ms: number
  last_used: string | null
}

export interface DailyTokenPoint {
  day: string
  calls: number
  total_tokens: number
}

export interface TokenStatsData {
  window_days: number
  // total_sessions now counts COMPLETIONS, which is what a provider bills for.
  total_sessions: number
  total_tokens: number
  failed_calls: number
  input_tokens: number
  output_tokens: number
  cache_read_tokens: number
  by_provider: ProviderTokenStat[]
  by_feature: FeatureTokenStat[]
  daily: DailyTokenPoint[]
  recent: RecentSession[]
}

export interface ProxyHealth {
  healthy: boolean
  last_check: string
  latency_ms: number
  error?: string
}

export interface ProxyStatus {
  outbound_configured: boolean
  outbound_proxy: string
  no_proxy: string
  fallback_direct: boolean
  health: ProxyHealth
  tor_configured: boolean
  tor_proxy: string
  darkweb_sources: number
}

export interface UpdaterStatus {
  name: string
  description: string
  category: string
  interval_seconds: number
  running: boolean
  runs: number
  last_run?: string
  last_success: boolean
  last_error?: string
  last_duration_ms: number
  next_run?: string
  attempt: number
  next_retry?: string
}

export interface SystemEvent {
  id: string
  category: string
  severity: 'info' | 'warn' | 'error'
  source: string
  message: string
  detail?: string
  count: number
  created_at: string
  updated_at: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const systemApi = {
  getEvents: async (params?: { category?: string; severity?: string; limit?: number }): Promise<SystemEvent[]> => {
    const { data } = await apiClient.get<ApiResponse<SystemEvent[]>>('/system/events', { params })
    return data.data
  },

  getHealth: async (): Promise<HealthData> => {
    const { data } = await apiClient.get<ApiResponse<HealthData>>('/system/health')
    return data.data
  },

  getTokenStats: async (days?: number): Promise<TokenStatsData> => {
    const { data } = await apiClient.get<ApiResponse<TokenStatsData>>('/system/token-stats',
      { params: days ? { days } : undefined })
    return data.data
  },

  getProxy: async (): Promise<ProxyStatus> => {
    const { data } = await apiClient.get<ApiResponse<ProxyStatus>>('/system/proxy')
    return data.data
  },

  setProxy: async (body: { proxy_url: string; no_proxy?: string; fallback_direct?: boolean }): Promise<ProxyStatus> => {
    const { data } = await apiClient.patch<ApiResponse<ProxyStatus>>('/system/proxy', body)
    return data.data
  },

  checkProxy: async (): Promise<ProxyStatus> => {
    const { data } = await apiClient.post<ApiResponse<ProxyStatus>>('/system/proxy/check')
    return data.data
  },

  getUpdaters: async (): Promise<UpdaterStatus[]> => {
    const { data } = await apiClient.get<ApiResponse<UpdaterStatus[]>>('/system/updaters')
    return data.data
  },

  runUpdater: async (name: string): Promise<void> => {
    await apiClient.post(`/system/updaters/${encodeURIComponent(name)}/run`)
  },
}
