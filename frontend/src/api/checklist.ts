import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export interface ChecklistBatch {
  id: string
  run_id: string
  agent_id: string
  batch_key: string
  batch_label: string
  item_ids: string
  command: string
  platform: string
  status: 'pending' | 'running' | 'done' | 'failed' | 'stopped'
  output?: string
  started_at?: string
  finished_at?: string
  created_at: string
  updated_at: string
}

export interface ChecklistRun {
  id: string
  agent_id: string
  label: string
  platform: string
  case_id: string
  analyst: string
  status: 'running' | 'done' | 'failed'
  batches?: ChecklistBatch[]
  created_by: string
  created_at: string
  updated_at: string
}

interface BatchInput {
  batch_key: string
  batch_label: string
  item_ids: string[]
  command: string
}

export interface RunChecklistRequest {
  agent_id: string
  platform: string
  label: string
  case_id: string
  analyst: string
  batches: BatchInput[]
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const checklistApi = {
  run: async (req: RunChecklistRequest): Promise<{ run_id: string; batches: ChecklistBatch[] }> => {
    const { data } = await apiClient.post<ApiResponse<{ run_id: string; batches: ChecklistBatch[] }>>(
      '/checklist/run',
      req
    )
    return data.data
  },

  listRuns: async (agentId?: string): Promise<ChecklistRun[]> => {
    const params = agentId ? { agent_id: agentId } : {}
    const { data } = await apiClient.get<ApiResponse<ChecklistRun[]>>('/checklist/runs', { params })
    return data.data
  },

  getRun: async (id: string): Promise<ChecklistRun> => {
    const { data } = await apiClient.get<ApiResponse<ChecklistRun>>(`/checklist/runs/${id}`)
    return data.data
  },

  streamBatchOutput: (batchId: string): EventSource => {
    const token = useAuthStore.getState().token ?? ''
    const baseURL = (apiClient.defaults.baseURL ?? '').replace(/\/$/, '')
    return new EventSource(`${baseURL}/checklist/batches/${batchId}/output?token=${encodeURIComponent(token)}`)
  },

  downloadBatchOutput: async (batchId: string): Promise<string> => {
    const { data } = await apiClient.get<string>(`/checklist/batches/${batchId}/download`, {
      responseType: 'text',
    })
    return data
  },
}
