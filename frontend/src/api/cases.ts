import apiClient from './client'
import { Agent } from './agents'
import type { OsintScan } from './osint'

export interface Case {
  id: string
  name: string
  description: string
  status: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface CaseOsintSummary {
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
