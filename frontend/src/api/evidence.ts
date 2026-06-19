import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export interface CaseEvidence {
  id: string
  case_id: string
  host: string
  file_name: string
  size: number
  notes?: string
  extracted: boolean
  uploaded_by: string
  created_at: string
}

interface ApiResponse<T> { success: boolean; data: T }

export const evidenceApi = {
  list: async (caseId: string): Promise<CaseEvidence[]> => {
    const { data } = await apiClient.get<ApiResponse<CaseEvidence[]>>(`/cases/${caseId}/evidence`)
    return data.data
  },

  upload: async (caseId: string, file: File, host: string, notes?: string): Promise<CaseEvidence> => {
    const form = new FormData()
    form.append('file', file)
    form.append('host', host)
    if (notes) form.append('notes', notes)
    const { data } = await apiClient.post<ApiResponse<CaseEvidence>>(`/cases/${caseId}/evidence`, form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  remove: async (id: string): Promise<void> => {
    await apiClient.delete(`/evidence/${id}`)
  },

  // AI: extract timeline events from an evidence file (host auto-attributed).
  extractTimeline: async (caseId: string, evidenceId: string, providerId: string): Promise<{ imported: number; host: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ imported: number; host: string }>>(
      `/cases/${caseId}/evidence/${evidenceId}/extract-timeline`, { provider_id: providerId },
    )
    return data.data
  },

  downloadUrl: (id: string): string => {
    const base = apiClient.defaults.baseURL ?? ''
    const token = useAuthStore.getState().token ?? ''
    return `${base}/evidence/${id}/download?token=${encodeURIComponent(token)}`
  },

  // Inline view (for <img> thumbnails / preview).
  viewUrl: (id: string): string => {
    const base = apiClient.defaults.baseURL ?? ''
    const token = useAuthStore.getState().token ?? ''
    return `${base}/evidence/${id}/view?token=${encodeURIComponent(token)}`
  },
}

export const IMAGE_EXT = /\.(png|jpe?g|gif|webp|bmp|svg)$/i
