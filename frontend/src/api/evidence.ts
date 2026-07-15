import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export type EvidenceKind = 'upload' | 'tool-result' | 'checklist' | 'edge-forensics'

export interface CaseEvidence {
  id: string
  case_id?: string
  agent_id?: string
  host: string
  kind: EvidenceKind
  source?: string
  file_name: string
  size: number
  sha256?: string
  notes?: string
  extracted: boolean
  uploaded_by: string
  created_at: string
}

export interface EvidenceFacets {
  total: number
  kinds: { value: string; count: number }[]
  hosts: { value: string; count: number }[]
}

interface ApiResponse<T> { success: boolean; data: T }

export const evidenceApi = {
  list: async (caseId: string): Promise<CaseEvidence[]> => {
    const { data } = await apiClient.get<ApiResponse<CaseEvidence[]>>(`/cases/${caseId}/evidence`)
    return data.data
  },

  // Central Evidence Store: global list across cases/agents with server-side
  // filtering + pagination.
  listAll: async (params: {
    kind?: string; host?: string; case_id?: string; agent_id?: string; search?: string
    limit?: number; offset?: number
  }): Promise<{ data: CaseEvidence[]; total: number }> => {
    const { data } = await apiClient.get<ApiResponse<CaseEvidence[]> & { total: number }>('/evidence', { params })
    return { data: data.data, total: data.total }
  },

  facets: async (): Promise<EvidenceFacets> => {
    const { data } = await apiClient.get<ApiResponse<EvidenceFacets>>('/evidence-facets')
    return data.data
  },

  // Upload a file straight into the store (multipart: file, host?, kind?, source?, notes?, case_id?, agent_id?).
  uploadGlobal: async (formData: FormData): Promise<CaseEvidence> => {
    const { data } = await apiClient.post<ApiResponse<CaseEvidence>>('/evidence', formData, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
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

  // AI: extract structured findings from an evidence file. When the file is
  // linked to a case, findings are promoted onto that case's timeline (+IOC).
  analyze: async (id: string, providerId?: string): Promise<{ findings: number; created: number; iocs_promoted?: number; note?: string; case_id?: string; truncated?: boolean }> => {
    const { data } = await apiClient.post<ApiResponse<{ findings: number; created: number; iocs_promoted?: number; note?: string; case_id?: string; truncated?: boolean }>>(
      `/evidence/${id}/analyze`, providerId ? { provider_id: providerId } : {},
    )
    return data.data
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
