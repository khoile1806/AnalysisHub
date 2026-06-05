import apiClient from './client'
import type { Tool } from './tools'
import type { Agent } from './agents'
import type { Job } from './jobs'

export interface ScenarioToolLink {
  id: string
  scenario_id: string
  tool_id: string
  tool?: Tool
  sort_order: number
  created_at: string
}

export interface HuntingScenario {
  id: string
  name: string
  slug: string
  description: string
  icon: string
  color: string
  created_at: string
  updated_at: string
  tools?: ScenarioToolLink[]
}

export interface HuntingDeployment {
  id: string
  scenario_id: string
  scenario?: HuntingScenario
  agent_id: string
  agent?: Agent
  case_id?: string
  created_at: string
  jobs?: Job[]
}

export interface DeployResult {
  deployment: HuntingDeployment
  jobs: Job[]
  dispatch_errors: string[]
}

export interface ScenarioPayload {
  name: string
  description?: string
  icon?: string
  color?: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const huntingApi = {
  listScenarios: async (): Promise<HuntingScenario[]> => {
    const { data } = await apiClient.get<ApiResponse<HuntingScenario[]>>('/hunting/scenarios')
    return data.data
  },

  getScenario: async (id: string): Promise<HuntingScenario> => {
    const { data } = await apiClient.get<ApiResponse<HuntingScenario>>(`/hunting/scenarios/${id}`)
    return data.data
  },

  createScenario: async (payload: ScenarioPayload): Promise<HuntingScenario> => {
    const { data } = await apiClient.post<ApiResponse<HuntingScenario>>('/hunting/scenarios', payload)
    return data.data
  },

  updateScenario: async (id: string, payload: ScenarioPayload): Promise<HuntingScenario> => {
    const { data } = await apiClient.put<ApiResponse<HuntingScenario>>(`/hunting/scenarios/${id}`, payload)
    return data.data
  },

  deleteScenario: async (id: string): Promise<void> => {
    await apiClient.delete(`/hunting/scenarios/${id}`)
  },

  addTool: async (scenarioId: string, toolId: string, sortOrder = 0): Promise<ScenarioToolLink> => {
    const { data } = await apiClient.post<ApiResponse<ScenarioToolLink>>(
      `/hunting/scenarios/${scenarioId}/tools`,
      { tool_id: toolId, sort_order: sortOrder },
    )
    return data.data
  },

  removeTool: async (scenarioId: string, toolId: string): Promise<void> => {
    await apiClient.delete(`/hunting/scenarios/${scenarioId}/tools/${toolId}`)
  },

  deploy: async (scenarioId: string, agentId: string, caseId?: string): Promise<DeployResult> => {
    const { data } = await apiClient.post<ApiResponse<DeployResult>>(
      `/hunting/scenarios/${scenarioId}/deploy`,
      { agent_id: agentId, case_id: caseId ?? '' },
    )
    return data.data
  },

  listDeployments: async (params?: { scenario_id?: string; agent_id?: string }): Promise<HuntingDeployment[]> => {
    const { data } = await apiClient.get<ApiResponse<HuntingDeployment[]>>('/hunting/deployments', { params })
    return data.data
  },

  getDeployment: async (id: string): Promise<HuntingDeployment> => {
    const { data } = await apiClient.get<ApiResponse<HuntingDeployment>>(`/hunting/deployments/${id}`)
    return data.data
  },

  deleteDeployment: async (id: string): Promise<void> => {
    await apiClient.delete(`/hunting/deployments/${id}`)
  },
}
