import apiClient from './client'

export type ToolCategory = 'memory' | 'triage' | 'process' | 'network' | 'disk' | 'log' | 'other'
export type ToolPlatform = 'windows' | 'linux' | 'both'

export interface Tool {
  id: string
  name: string
  category: ToolCategory
  platform: ToolPlatform
  version: string
  description: string
  file_name: string
  file_size: number
  args: string
  executable_path: string
  created_at: string
}

export interface ToolFilters {
  category?: ToolCategory
  platform?: ToolPlatform
}

export const TOOL_CATEGORIES: ToolCategory[] = [
  'memory', 'triage', 'process', 'network', 'disk', 'log', 'other',
]

export const TOOL_PLATFORMS: ToolPlatform[] = ['windows', 'linux', 'both']

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const toolsApi = {
  list: async (params?: ToolFilters): Promise<Tool[]> => {
    const { data } = await apiClient.get<ApiResponse<Tool[]>>('/tools', { params })
    return data.data
  },

  upload: async (formData: FormData): Promise<Tool> => {
    const { data } = await apiClient.post<ApiResponse<Tool>>('/tools', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  get: async (id: string): Promise<Tool> => {
    const { data } = await apiClient.get<ApiResponse<Tool>>(`/tools/${id}`)
    return data.data
  },

  update: async (id: string, payload: {
    name: string
    category: ToolCategory
    platform: ToolPlatform
    version: string
    description: string
    args: string
    executable_path: string
  }): Promise<Tool> => {
    const { data } = await apiClient.put<ApiResponse<Tool>>(`/tools/${id}`, payload)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/tools/${id}`)
  },

  downloadUrl: (id: string): string => {
    const base = `${import.meta.env.VITE_API_URL ?? ''}/api/v1`
    return `${base}/tools/${id}/download`
  },
}
