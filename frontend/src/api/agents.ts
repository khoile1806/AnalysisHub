import apiClient from './client'

export type AgentStatus = 'online' | 'offline'

export interface Agent {
  id: string
  name: string
  hostname: string
  os: string
  ip_address: string
  status: AgentStatus
  last_seen: string
  description: string
  token?: string
  created_at: string
}

export interface CreateAgentData {
  name: string
  description: string
  case_id?: string | null
}

export interface AgentInstallerConfig {
  agent_id: string
  agent_name: string
  token: string
  server_url: string
  ws_url: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const agentsApi = {
  list: async (): Promise<Agent[]> => {
    const { data } = await apiClient.get<ApiResponse<Agent[]>>('/agents')
    return data.data
  },

  create: async (payload: CreateAgentData): Promise<Agent> => {
    const { data } = await apiClient.post<ApiResponse<Agent>>('/agents', payload)
    return data.data
  },

  get: async (id: string): Promise<Agent> => {
    const { data } = await apiClient.get<ApiResponse<Agent>>(`/agents/${id}`)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/agents/${id}`)
  },

  getInstaller: async (id: string): Promise<AgentInstallerConfig> => {
    const { data } = await apiClient.get<ApiResponse<AgentInstallerConfig>>(`/agents/${id}/installer`)
    return data.data
  },

  cleanup: async (id: string): Promise<void> => {
    await apiClient.post(`/agents/${id}/cleanup`, {})
  },
}
