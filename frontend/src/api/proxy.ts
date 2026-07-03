import apiClient from './client'

// Proxy Manager API — the egress proxy pool (add / switch / health-check) and the
// outbound flow log. Mirrors the backend routes under /system/proxies and
// /system/proxy/flows.

export interface ProxyProfile {
  id: number
  name: string
  url: string // masked (credentials stripped) — server never returns the raw URL
  no_proxy: string
  fallback_direct: boolean
  is_active: boolean
  healthy: boolean
  latency_ms: number
  last_error: string
  last_check: string | null
  exit_ip: string
  exit_country: string
  exit_org: string
  is_tor: boolean
  exit_checked_at: string | null
  created_at: string
  updated_at: string
}

export interface ProxyFlow {
  id: number
  created_at: string
  proxy_label: string
  via_proxy: boolean
  leaked: boolean
  source: string
  method: string
  scheme: string
  host: string
  url: string
  status: number
  content_type: string
  tls_version: string
  bytes_out: number
  bytes_in: number
  duration_ms: number
  dns_ms: number
  connect_ms: number
  tls_ms: number
  ttfb_ms: number
  error: string
}

export interface ProxyFlowStats {
  count: number
  bytes_in: number
  bytes_out: number
  errors: number
  proxied: number
  direct: number
  leaked: number
  coverage_pct: number
  by_proxy: Record<string, number>
}

export interface ProxyPoolMode {
  id: number
  mode: 'manual' | 'failover' | 'rotate'
  interval_sec: number
}

export interface ProxyAnalytics {
  since_hours: number
  total: number
  proxied: number
  leaked: number
  coverage_pct: number
  top_hosts: { host: string; count: number; bytes: number }[]
  per_proxy: { proxy_label: string; count: number; errors: number; bytes_in: number; bytes_out: number; avg_ms: number }[]
}

export interface ProxyProfilePayload {
  name: string
  url: string
  no_proxy?: string
  fallback_direct?: boolean
}

interface ApiResponse<T> {
  success: boolean
  data: T
  source?: string
}

export const proxyApi = {
  list: async (): Promise<ProxyProfile[]> => {
    const { data } = await apiClient.get<ApiResponse<ProxyProfile[]>>('/system/proxies')
    return data.data
  },

  create: async (body: ProxyProfilePayload): Promise<ProxyProfile> => {
    const { data } = await apiClient.post<ApiResponse<ProxyProfile>>('/system/proxies', body)
    return data.data
  },

  update: async (id: number, body: ProxyProfilePayload): Promise<ProxyProfile> => {
    const { data } = await apiClient.patch<ApiResponse<ProxyProfile>>(`/system/proxies/${id}`, body)
    return data.data
  },

  remove: async (id: number): Promise<void> => {
    await apiClient.delete(`/system/proxies/${id}`)
  },

  activate: async (id: number): Promise<ProxyProfile> => {
    const { data } = await apiClient.post<ApiResponse<ProxyProfile>>(`/system/proxies/${id}/activate`)
    return data.data
  },

  deactivate: async (): Promise<void> => {
    await apiClient.post('/system/proxies/deactivate')
  },

  check: async (id: number): Promise<ProxyProfile> => {
    const { data } = await apiClient.post<ApiResponse<ProxyProfile>>(`/system/proxies/${id}/check`)
    return data.data
  },

  identity: async (id: number): Promise<ProxyProfile> => {
    const { data } = await apiClient.post<ApiResponse<ProxyProfile>>(`/system/proxies/${id}/identity`)
    return data.data
  },

  getMode: async (): Promise<ProxyPoolMode> => {
    const { data } = await apiClient.get<ApiResponse<ProxyPoolMode>>('/system/proxies/mode')
    return data.data
  },

  setMode: async (body: { mode: string; interval_sec?: number }): Promise<ProxyPoolMode> => {
    const { data } = await apiClient.post<ApiResponse<ProxyPoolMode>>('/system/proxies/mode', body)
    return data.data
  },

  analytics: async (sinceHours = 24): Promise<ProxyAnalytics> => {
    const { data } = await apiClient.get<ApiResponse<ProxyAnalytics>>(`/system/proxy/analytics?since_hours=${sinceHours}`)
    return data.data
  },

  flows: async (opts?: { limit?: number; history?: boolean; host?: string; leaked?: boolean }): Promise<ProxyFlow[]> => {
    const params = new URLSearchParams()
    if (opts?.limit) params.set('limit', String(opts.limit))
    if (opts?.history) params.set('history', 'true')
    if (opts?.host) params.set('host', opts.host)
    if (opts?.leaked) params.set('leaked', 'true')
    const qs = params.toString()
    const { data } = await apiClient.get<ApiResponse<ProxyFlow[]>>(`/system/proxy/flows${qs ? `?${qs}` : ''}`)
    return data.data
  },

  exportCsv: async (opts?: { host?: string; leaked?: boolean }): Promise<Blob> => {
    const params = new URLSearchParams()
    if (opts?.host) params.set('host', opts.host)
    if (opts?.leaked) params.set('leaked', 'true')
    const { data } = await apiClient.get(`/system/proxy/flows/export?${params.toString()}`, { responseType: 'blob' })
    return data as Blob
  },

  flowStats: async (): Promise<ProxyFlowStats> => {
    const { data } = await apiClient.get<ApiResponse<ProxyFlowStats>>('/system/proxy/flows/stats')
    return data.data
  },

  clearFlows: async (): Promise<void> => {
    await apiClient.delete('/system/proxy/flows')
  },
}
