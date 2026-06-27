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
}

export interface TokenStatsData {
  total_sessions: number
  total_tokens: number
  by_provider: ProviderTokenStat[]
  recent: RecentSession[]
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const systemApi = {
  getHealth: async (): Promise<HealthData> => {
    const { data } = await apiClient.get<ApiResponse<HealthData>>('/system/health')
    return data.data
  },

  getTokenStats: async (): Promise<TokenStatsData> => {
    const { data } = await apiClient.get<ApiResponse<TokenStatsData>>('/system/token-stats')
    return data.data
  },
}
