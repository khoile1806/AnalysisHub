import apiClient from './client'
import { useAuthStore } from '@/store/auth'

// OOB ("Catch") interaction server — Interactsh / Burp-Collaborator style.

export interface OobConfig {
  enabled: boolean
  running: boolean
  configured: boolean
  domain: string
  public_ip: string
  ns_name: string
  listeners: string[]
  https_ready: boolean
  webhook_ready: boolean
  webhook_base: string
}

export interface OobClient {
  id: string
  correlation_id: string
  secret?: string
  name: string
  note?: string
  case_id?: string | null
  interaction_count: number
  last_seen_at?: string | null
  resp_status: number
  resp_content_type: string
  resp_body: string
  resp_delay_ms: number
  resp_headers: string
  notify_url: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface OobPayload {
  unique_id: string
  webhook: string
  // Full-OAST variants — only present when OOB_DOMAIN is configured.
  host?: string
  http?: string
  https?: string
  dns?: string
  smtp?: string
  jndi_ldap?: string
  jndi_rmi?: string
}

export type OobProtocol = 'dns' | 'http' | 'https' | 'smtp' | 'ldap' | 'rmi'

export interface OobRule {
  id: string
  client_id: string
  name: string
  priority: number
  match_method?: string
  match_path_prefix?: string
  match_path_sub?: string
  status: number
  content_type: string
  body: string
  headers?: string
  delay_ms: number
  created_at: string
  updated_at: string
}

export type OobRuleInput = {
  name?: string
  priority?: number
  match_method?: string
  match_path_prefix?: string
  match_path_sub?: string
  status?: number
  content_type?: string
  body?: string
  headers?: Record<string, string>
  delay_ms?: number
}

export interface OobInteraction {
  id: string
  client_id: string
  correlation_id: string
  protocol: OobProtocol
  full_host: string
  unique_id?: string
  remote_addr?: string
  remote_ip?: string
  query_type?: string
  method?: string
  path?: string
  user_agent?: string
  smtp_from?: string
  smtp_to?: string
  raw_request?: string
  // triage state
  seen?: boolean
  starred?: boolean
  note?: string
  tags?: string
  // source-IP enrichment
  geo_country?: string
  geo_city?: string
  asn?: string
  isp?: string
  rdns?: string
  is_proxy?: boolean
  is_hosting?: boolean
  created_at: string
}

export const oobApi = {
  config: () =>
    apiClient.get<{ data: OobConfig }>('/osint/oob/config').then(r => r.data.data),

  listClients: () =>
    apiClient.get<{ data: OobClient[] }>('/osint/oob/clients').then(r => r.data.data),

  getClient: (id: string) =>
    apiClient.get<{ data: OobClient }>(`/osint/oob/clients/${id}`).then(r => r.data.data),

  register: (body: { name?: string; note?: string; case_id?: string | null }) =>
    apiClient
      .post<{ data: { client: OobClient; payload: OobPayload } }>('/osint/oob/register', body)
      .then(r => r.data.data),

  deleteClient: (id: string) => apiClient.delete(`/osint/oob/clients/${id}`),

  rename: (id: string, body: { name?: string; note?: string }) =>
    apiClient.patch(`/osint/oob/clients/${id}`, body),

  clearInteractions: (id: string) =>
    apiClient.delete(`/osint/oob/clients/${id}/interactions`),

  deleteInteraction: (id: string, iid: string) =>
    apiClient.delete(`/osint/oob/clients/${id}/interactions/${iid}`),

  /** SSE stream URL for live interactions (token in query — EventSource can't set headers). */
  streamUrl: (id: string) => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token
    return `${base}/api/v1/osint/oob/clients/${id}/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`
  },

  generatePayload: (id: string) =>
    apiClient
      .post<{ data: OobPayload }>(`/osint/oob/clients/${id}/payload`)
      .then(r => r.data.data),

  updateResponse: (
    id: string,
    body: { status?: number; content_type?: string; body?: string; delay_ms?: number; headers?: Record<string, string> },
  ) => apiClient.patch<{ data: OobClient }>(`/osint/oob/clients/${id}/response`, body).then(r => r.data.data),

  interactions: (id: string, params?: { after?: string; protocol?: string; method?: string; starred?: string; limit?: number; q?: string }) =>
    apiClient
      .get<{ data: OobInteraction[]; server_time: string }>(`/osint/oob/clients/${id}/interactions`, { params })
      .then(r => r.data),

  patchInteraction: (id: string, iid: string, body: { seen?: boolean; starred?: boolean; note?: string; tags?: string }) =>
    apiClient.patch(`/osint/oob/clients/${id}/interactions/${iid}`, body),

  markAllSeen: (id: string) => apiClient.post(`/osint/oob/clients/${id}/seen`),

  promoteIOC: (id: string, iid: string) =>
    apiClient.post<{ data: { value: string; type: string } }>(`/osint/oob/clients/${id}/interactions/${iid}/promote-ioc`).then(r => r.data.data),

  listRules: (id: string) =>
    apiClient.get<{ data: OobRule[] }>(`/osint/oob/clients/${id}/rules`).then(r => r.data.data),
  createRule: (id: string, body: OobRuleInput) =>
    apiClient.post<{ data: OobRule }>(`/osint/oob/clients/${id}/rules`, body).then(r => r.data.data),
  updateRule: (id: string, rid: string, body: OobRuleInput) =>
    apiClient.patch<{ data: OobRule }>(`/osint/oob/clients/${id}/rules/${rid}`, body).then(r => r.data.data),
  deleteRule: (id: string, rid: string) =>
    apiClient.delete(`/osint/oob/clients/${id}/rules/${rid}`),

  updateNotify: (id: string, notifyUrl: string) =>
    apiClient
      .patch<{ data: OobClient }>(`/osint/oob/clients/${id}/notify`, { notify_url: notifyUrl })
      .then(r => r.data.data),

  /** Downloads interactions as a CSV blob through the authenticated client and
   *  triggers a browser save (the bearer token is attached by the interceptor). */
  downloadCsv: async (id: string, name: string, params?: { protocol?: string; q?: string }) => {
    const res = await apiClient.get(`/osint/oob/clients/${id}/interactions`, {
      params: { ...params, format: 'csv' },
      responseType: 'blob',
    })
    const url = URL.createObjectURL(res.data as Blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `oob-${name || id}.csv`
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
  },
}
