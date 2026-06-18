import apiClient from './client'

export interface DashboardUsecase {
  id: string
  name: string
  slug: string
  incident_type: string
  description: string
  icon: string
  color: string
  widgets: string   // JSON array of widget keys
  playbook: string
  sort_order: number
  created_by: string
  created_at: string
  updated_at: string
}

export interface UpsertUsecase {
  name: string
  incident_type?: string
  description?: string
  icon?: string
  color?: string
  widgets?: string
  playbook?: string
  sort_order?: number
}

interface ApiResponse<T> { success: boolean; data: T }

// Widget catalog — keys map to render blocks in Dashboard.tsx.
export const WIDGET_CATALOG: { key: string; label: string }[] = [
  { key: 'agents-stat',  label: 'Agents stat' },
  { key: 'jobs-stat',    label: 'Jobs stat' },
  { key: 'cves-stat',    label: 'KEV CVEs stat' },
  { key: 'iocs-stat',    label: 'IOCs stat' },
  { key: 'recent-jobs',  label: 'Recent jobs list' },
  { key: 'kev-cves',     label: 'KEV CVEs list' },
  { key: 'iocs-list',    label: 'Recent IOCs list' },
  { key: 'elk-results',  label: 'ELK hunt results' },
  { key: 'open-cases',   label: 'Open cases' },
  { key: 'playbook',     label: 'Playbook panel' },
]

export const USECASE_ICONS = ['Shield', 'Lock', 'Activity', 'Crosshair', 'Network', 'Bug', 'ShieldAlert', 'Cpu']
export const USECASE_COLORS = ['emerald', 'rose', 'sky', 'amber', 'violet', 'cyan']

export function parseWidgets(json: string): string[] {
  try {
    const arr = JSON.parse(json || '[]')
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}

export const dashboardUsecasesApi = {
  list: async (): Promise<DashboardUsecase[]> => {
    const { data } = await apiClient.get<ApiResponse<DashboardUsecase[]>>('/dashboard/usecases')
    return data.data
  },
  create: async (payload: UpsertUsecase): Promise<DashboardUsecase> => {
    const { data } = await apiClient.post<ApiResponse<DashboardUsecase>>('/dashboard/usecases', payload)
    return data.data
  },
  update: async (id: string, payload: Partial<UpsertUsecase>): Promise<DashboardUsecase> => {
    const { data } = await apiClient.put<ApiResponse<DashboardUsecase>>(`/dashboard/usecases/${id}`, payload)
    return data.data
  },
  remove: async (id: string): Promise<void> => {
    await apiClient.delete(`/dashboard/usecases/${id}`)
  },
}
