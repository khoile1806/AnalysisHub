import apiClient from './client'
import { type IOC } from './opencti'

export type Severity = 'critical' | 'high' | 'medium' | 'low' | 'none'

export interface CveSummary {
  id: string
  description: string
  cvss_score: number
  severity: Severity
  epss_score: number
  epss_percentile: number
  is_kev: boolean
  published_date: string
  last_modified: string
  affected_products: string[]
}

interface CveReference {
  url: string
  source?: string
  tags?: string[]
}

export interface CveDetail extends CveSummary {
  references: CveReference[]
  configurations: string[]
}

export interface PocRepo {
  name: string
  html_url: string
  description: string
  stars: number
  owner: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const cveApi = {
  search: async (q: string, version?: string, limit = 200): Promise<CveSummary[]> => {
    const params: Record<string, string | number> = { q, limit }
    if (version) params.version = version
    const { data } = await apiClient.get<ApiResponse<CveSummary[]>>('/cve/search', { params })
    return data.data
  },

  get: async (id: string): Promise<CveDetail> => {
    const { data } = await apiClient.get<ApiResponse<CveDetail>>(`/cve/${id}`)
    return data.data
  },

  getPocs: async (id: string): Promise<PocRepo[]> => {
    const { data } = await apiClient.get<ApiResponse<PocRepo[]>>(`/cve/${id}/pocs`)
    return data.data
  },
  
  getRelatedIOCs: async (id: string): Promise<IOC[]> => {
    const { data } = await apiClient.get<ApiResponse<IOC[]>>(`/cve/${id}/iocs`)
    return data.data
  },
}
