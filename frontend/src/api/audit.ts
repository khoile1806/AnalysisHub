import apiClient from './client'

// Audit trail — the accountability record of who did what on the platform.
// Backend is admin-only; every route returns { success, data, ... }.

export interface AuditRow {
  id: number
  user_id: string | null
  user_email: string
  user_name: string
  user_role: string
  agent_id: string | null
  agent_host: string
  action: string
  resource: string
  detail: string
  ip: string
  user_agent: string
  forwarded: string
  created_at: string
}

export interface AuditUserSummary {
  user_id: string | null
  user_email: string
  user_name: string
  user_role: string
  total_actions: number
  agents_touched: number
  evidence_pulled: number
  evidence_download: number
  jobs_run: number
  deletions: number
  first_seen: string | null
  last_seen: string | null
}

export interface AuditListParams {
  user_id?: string
  action?: string
  action_prefix?: string
  agent_id?: string
  from?: string
  to?: string
  q?: string
  limit?: number
  offset?: number
}

export interface AuditListResult {
  data: AuditRow[]
  total: number
  limit: number
  offset: number
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

interface AuditListResponse {
  success: boolean
  data: AuditRow[]
  total: number
  limit: number
  offset: number
}

// Drop empty/undefined params so we don't send `?action=&q=` noise.
function cleanParams(params: AuditListParams): Record<string, string | number> {
  const out: Record<string, string | number> = {}
  for (const [k, v] of Object.entries(params)) {
    if (v === undefined || v === null || v === '') continue
    out[k] = v as string | number
  }
  return out
}

export const auditApi = {
  list: async (params: AuditListParams = {}): Promise<AuditListResult> => {
    const { data } = await apiClient.get<AuditListResponse>('/audit', { params: cleanParams(params) })
    return { data: data.data, total: data.total, limit: data.limit, offset: data.offset }
  },

  summary: async (params: { from?: string; to?: string } = {}): Promise<AuditUserSummary[]> => {
    const { data } = await apiClient.get<ApiResponse<AuditUserSummary[]>>('/audit/summary', { params: cleanParams(params) })
    return data.data
  },

  actions: async (): Promise<string[]> => {
    const { data } = await apiClient.get<ApiResponse<string[]>>('/audit/actions')
    return data.data
  },

  // AI summary of one user's activity — "what has this operator done".
  summarize: async (params: { user_id: string | null; from?: string; to?: string; provider_id?: string }): Promise<AuditAiSummary> => {
    const { data } = await apiClient.post<ApiResponse<AuditAiSummary>>('/audit/summarize', {
      user_id: params.user_id ?? '', from: params.from, to: params.to, provider_id: params.provider_id,
    }, { timeout: 200_000 })
    return data.data
  },
}

export interface AuditAiSummary {
  summary: string
  actions_count: number
  capped?: boolean
  from?: string
  to?: string
}
