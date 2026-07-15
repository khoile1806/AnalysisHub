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

export interface ToolResult {
  id: string
  job_id: string
  agent_id: string
  tool_id: string
  tool_name: string
  file_name: string
  kind: string
  processor: string
  size_bytes: number
  row_count: number
  summary: string
  sha256: string
  process_status: string
  process_error: string
  for_ai: boolean
  ai_status: string
  created_at: string
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

  // Collected tool result files (auto-pulled per the tool's output spec).
  listResults: async (jobId: string): Promise<ToolResult[]> => {
    const { data } = await apiClient.get<ApiResponse<ToolResult[]>>(`/jobs/${jobId}/results`)
    return data.data
  },

  setResultAI: async (resultId: string, forAI: boolean): Promise<ToolResult> => {
    const { data } = await apiClient.patch<ApiResponse<ToolResult>>(`/tool-results/${resultId}`, { for_ai: forAI })
    return data.data
  },

  // Bulk-toggle the for-AI flag for every result of a job in one click.
  setJobResultsAI: async (jobId: string, forAI: boolean): Promise<{ updated: number; for_ai: boolean }> => {
    const { data } = await apiClient.patch<ApiResponse<{ updated: number; for_ai: boolean }>>(
      `/jobs/${jobId}/results/for-ai`, { for_ai: forAI },
    )
    return data.data
  },

  analyzeResults: async (
    jobId: string,
    body?: { provider_id?: string; case_id?: string },
  ): Promise<{ findings: number; created: number; iocs_promoted: number; note?: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ findings: number; created: number; iocs_promoted: number; note?: string }>>(
      `/jobs/${jobId}/analyze-results`, body ?? {},
    )
    return data.data
  },

  resultDownloadUrl: (resultId: string, parsed = false): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) || window.location.origin
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/tool-results/${resultId}/download?token=${encodeURIComponent(token)}${parsed ? '&parsed=true' : ''}`
  },
}
