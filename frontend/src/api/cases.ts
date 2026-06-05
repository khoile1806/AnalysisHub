import apiClient from './client'
import { Agent } from './agents'

export interface Case {
  id: string
  name: string
  description: string
  status: string
  created_by: string
  created_at: string
  updated_at: string
}

export interface CaseSummaryResponse {
  case: Case
  agents: Agent[]
  deployments?: any[]
  jobs?: any[]
  checklist_runs?: any[]
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

  getSummary: async (id: string): Promise<CaseSummaryResponse> => {
    const { data } = await apiClient.get<ApiResponse<{ case: Case; agents: Agent[]; deployments?: any[]; jobs?: any[]; checklist_runs?: any[] }>>(`/cases/${id}/summary`)
    return data.data
  },
}
