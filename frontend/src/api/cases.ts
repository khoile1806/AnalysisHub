import apiClient from './client'
import { Agent } from './agents'

export interface Case {
  id: string
  name: string
  description: string
  status: string
  created_by: string
  created_at: string
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

export const casesApi = {
  list: async (): Promise<Case[]> => {
    const { data } = await apiClient.get<Case[]>('/cases')
    return data
  },

  create: async (payload: CreateCaseData): Promise<Case> => {
    const { data } = await apiClient.post<Case>('/cases', payload)
    return data
  },

  getSummary: async (id: string): Promise<CaseSummaryResponse> => {
    const { data } = await apiClient.get<CaseSummaryResponse>(`/cases/${id}/summary`)
    return data
  },
}
