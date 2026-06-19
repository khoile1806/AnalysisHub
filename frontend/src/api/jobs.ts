import apiClient from './client'
import type { Agent } from './agents'
import type { Tool } from './tools'
import { useAuthStore } from '@/store/auth'

export type JobStatus = 'pending' | 'ready' | 'running' | 'done' | 'failed' | 'stopped'

export interface Job {
  id: string
  agent_id: string
  tool_id: string
  agent: Agent
  tool: Tool
  args: string
  cpu_limit?: number
  ram_limit?: number
  priority?: string
  status: JobStatus
  output: string
  artifact_path: string
  started_at: string
  finished_at: string
  created_at: string
}

export interface JobFilters {
  agent_id?: string
  status?: JobStatus
}

export interface CreateJobData {
  agent_id: string
  tool_id: string
  args?: string
  cpu_limit?: number
  ram_limit?: number
  priority?: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const jobsApi = {
  list: async (params?: JobFilters): Promise<Job[]> => {
    const { data } = await apiClient.get<ApiResponse<Job[]>>('/jobs', { params })
    return data.data
  },

  create: async (payload: CreateJobData): Promise<Job> => {
    const { data } = await apiClient.post<ApiResponse<Job>>('/jobs', payload)
    return data.data
  },

  get: async (id: string): Promise<Job> => {
    const { data } = await apiClient.get<ApiResponse<Job>>(`/jobs/${id}`)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/jobs/${id}`)
  },

  run: async (id: string): Promise<Job> => {
    const { data } = await apiClient.post<ApiResponse<Job>>(`/jobs/${id}/run`)
    return data.data
  },

  stop: async (id: string): Promise<Job> => {
    const { data } = await apiClient.post<ApiResponse<Job>>(`/jobs/${id}/stop`)
    return data.data
  },

  getArtifactUrl: (id: string): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) || window.location.origin
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/jobs/${id}/artifact/download?token=${encodeURIComponent(token)}`
  },

  getArtifactContentUrl: (id: string): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) || window.location.origin
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/jobs/${id}/artifact/content?token=${encodeURIComponent(token)}`
  },

  streamOutput: (jobId: string): EventSource => {
    const token = useAuthStore.getState().token ?? ''
    const baseURL = (apiClient.defaults.baseURL ?? '').replace(/\/$/, '')
    return new EventSource(`${baseURL}/jobs/${jobId}/output?token=${encodeURIComponent(token)}`)
  },
}
