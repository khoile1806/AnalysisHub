import apiClient from './client'
import { Agent } from './agents'
import type { OsintScan } from './osint'
import { useAuthStore } from '@/store/auth'

export interface Case {
  id: string
  name: string
  description: string
  status: string
  created_by: string
  created_at: string
  updated_at: string
}

interface CaseOsintSummary {
  investigations: OsintScan[]
  total_scans: number
  total_findings: number
}

export interface CaseSummaryResponse {
  case: Case
  agents: Agent[]
  deployments?: any[]
  jobs?: any[]
  checklist_runs?: any[]
  osint?: CaseOsintSummary
}

export interface CreateCaseData {
  name: string
  description: string
}

export interface UpdateCaseData {
  name?: string
  description?: string
  status?: 'open' | 'closed'
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const casesApi = {
  list: async (): Promise<Case[]> => {
    const { data } = await apiClient.get<ApiResponse<Case[]>>('/cases')
    return data.data
  },

  create: async (payload: CreateCaseData): Promise<Case> => {
    const { data } = await apiClient.post<ApiResponse<Case>>('/cases', payload)
    return data.data
  },

  update: async (id: string, payload: UpdateCaseData): Promise<Case> => {
    const { data } = await apiClient.patch<ApiResponse<Case>>(`/cases/${id}`, payload)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete<ApiResponse<void>>(`/cases/${id}`)
  },

  getSummary: async (id: string): Promise<CaseSummaryResponse> => {
    const { data } = await apiClient.get<ApiResponse<CaseSummaryResponse>>(`/cases/${id}/summary`)
    return data.data
  },

  // reportUrl builds an authenticated link to the self-contained incident report
  // (HTML, print-to-PDF). Token is in the query because the page is opened in a
  // new tab where headers can't be set (same pattern as the OSINT report).
  reportUrl: (id: string, format?: 'pdf'): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token ?? ''
    const fmt = format ? `&format=${format}` : ''
    return `${base}/api/v1/cases/${id}/report?token=${encodeURIComponent(token)}${fmt}`
  },

  // generateAiSummary asks an AI provider to draft the incident executive
  // narrative and saves it on the case (appears in the report).
  generateAiSummary: async (id: string, providerId: string): Promise<{ summary: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ summary: string }>>(
      `/cases/${id}/report/ai-summary`, { provider_id: providerId },
    )
    return data.data
  },

  importOfflineReport: async (id: string, file: File): Promise<ImportOfflineResult> => {
    const form = new FormData()
    form.append('file', file)
    const { data } = await apiClient.post<ApiResponse<ImportOfflineResult>>(
      `/cases/${id}/import-offline-report`, form,
      { headers: { 'Content-Type': 'multipart/form-data' } },
    )
    return data.data
  },
}

export interface ImportOfflineResult {
  agent_id: string
  agent_name: string
  imported_jobs: number
  bundle_name: string
  hostname: string
}
