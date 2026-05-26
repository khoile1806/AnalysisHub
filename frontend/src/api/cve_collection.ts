import apiClient from './client'
import type { Severity } from './cve'

export interface CollectedCVE {
  id: string
  description: string
  severity: Severity
  cvss_score: number
  epss_score?: number
  is_kev?: boolean
  exploit_status?: string
  published_date: string
  poc_links: string[]
  tags: string[]
  added_at: string
  source?: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const cveCollectionApi = {
  getAll: async (): Promise<CollectedCVE[]> => {
    const { data } = await apiClient.get<ApiResponse<CollectedCVE[]>>('/cve-collection')
    return data.data
  },

  add: async (cve: Partial<CollectedCVE>): Promise<CollectedCVE> => {
    const { data } = await apiClient.post<ApiResponse<CollectedCVE>>('/cve-collection', cve)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/cve-collection/${id}`)
  },
}
