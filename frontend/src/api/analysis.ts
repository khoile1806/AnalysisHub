import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export interface AIProvider {
  id: string
  name: string
  provider_type: 'openai' | 'anthropic' | 'google'
  base_url: string
  has_key: boolean
  model: string
  max_tokens: number
  is_active: boolean
  created_by: string
  created_at: string
  updated_at: string
}

export interface ChainStep {
  id: string
  label: string
  status: 'pending' | 'running' | 'done' | 'failed'
  detail: string
}

export type SessionSourceType = 'job' | 'checklist_run' | 'elk_result' | 'upload' | 'offline_report' | 'evidence'

export interface AnalysisSession {
  id: string
  provider_id: string
  provider?: AIProvider
  title: string
  source_type: SessionSourceType
  source_id: string
  upload_path?: string
  upload_name?: string
  status: 'pending' | 'running' | 'done' | 'failed'
  steps: string  // JSON-encoded ChainStep[]
  result: string
  tokens_used: number
  created_by: string
  created_at: string
  finished_at?: string
}

export interface CreateProviderData {
  name: string
  provider_type: 'openai' | 'anthropic' | 'google'
  base_url?: string
  api_key?: string
  model?: string
  max_tokens?: number
  is_active?: boolean
}

export interface UpdateProviderData extends Partial<CreateProviderData> {}

export interface CreateSessionData {
  provider_id: string
  source_type: SessionSourceType
  source_id?: string
  title?: string
  file?: File
}

interface ApiResponse<T> {
  success: boolean
  data: T
  error?: string
}

export const analysisApi = {
  // Provider management
  listProviders: async (): Promise<AIProvider[]> => {
    const { data } = await apiClient.get<ApiResponse<AIProvider[]>>('/ai/providers')
    return data.data
  },

  createProvider: async (payload: CreateProviderData): Promise<AIProvider> => {
    const { data } = await apiClient.post<ApiResponse<AIProvider>>('/ai/providers', payload)
    return data.data
  },

  updateProvider: async (id: string, payload: UpdateProviderData): Promise<AIProvider> => {
    const { data } = await apiClient.put<ApiResponse<AIProvider>>(`/ai/providers/${id}`, payload)
    return data.data
  },

  deleteProvider: async (id: string): Promise<void> => {
    await apiClient.delete(`/ai/providers/${id}`)
  },

  testProvider: async (id: string): Promise<{ success: boolean; error?: string }> => {
    const { data } = await apiClient.post<{ success: boolean; error?: string; message?: string }>(`/ai/providers/${id}/test`)
    return data
  },

  // Sessions
  listSessions: async (): Promise<AnalysisSession[]> => {
    const { data } = await apiClient.get<ApiResponse<AnalysisSession[]>>('/ai/sessions')
    return data.data
  },

  getSession: async (id: string): Promise<AnalysisSession> => {
    const { data } = await apiClient.get<ApiResponse<AnalysisSession>>(`/ai/sessions/${id}`)
    return data.data
  },

  createSession: async (payload: CreateSessionData): Promise<AnalysisSession> => {
    const form = new FormData()
    form.append('provider_id', payload.provider_id)
    form.append('source_type', payload.source_type)
    if (payload.source_id) form.append('source_id', payload.source_id)
    if (payload.title) form.append('title', payload.title)
    if (payload.file) form.append('file', payload.file)
    const { data } = await apiClient.post<ApiResponse<AnalysisSession>>('/ai/sessions', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  deleteSession: async (id: string): Promise<void> => {
    await apiClient.delete(`/ai/sessions/${id}`)
  },

  // SSE stream — returns an EventSource that emits step/token/done/error events
  streamSession: (sessionId: string): EventSource => {
    const token = useAuthStore.getState().token ?? ''
    const baseURL = (apiClient.defaults.baseURL ?? '').replace(/\/$/, '')
    return new EventSource(`${baseURL}/ai/sessions/${sessionId}/stream?token=${encodeURIComponent(token)}`)
  },

  // Parse the JSON-encoded steps from a session
  parseSteps: (stepsJSON: string): ChainStep[] => {
    if (!stepsJSON) return []
    try {
      return JSON.parse(stepsJSON) as ChainStep[]
    } catch {
      return []
    }
  },
}

// ELK Hunt Results API
export interface ELKHuntResult {
  id: string
  config_id: number
  title: string
  iocs_used: number
  total_hits: number
  results: string  // JSON string of hits
  status: 'running' | 'done' | 'failed'
  created_by: string
  created_at: string
  finished_at?: string
}

export const elkResultsApi = {
  list: async (): Promise<ELKHuntResult[]> => {
    const { data } = await apiClient.get<ApiResponse<ELKHuntResult[]>>('/elk/hunt/results')
    return data.data
  },

  get: async (id: string): Promise<ELKHuntResult> => {
    const { data } = await apiClient.get<ApiResponse<ELKHuntResult>>(`/elk/hunt/results/${id}`)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/elk/hunt/results/${id}`)
  },
}
