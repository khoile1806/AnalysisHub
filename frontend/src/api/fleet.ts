import apiClient from './client'

// Collections that can be dispatched in bulk or on a schedule.
export type FleetCollection =
  | 'mft' | 'prefetch' | 'processes' | 'autoruns'
  | 'netconn' | 'dlls' | 'shimcache' | 'registry' | 'evtx'

export const FLEET_COLLECTIONS: FleetCollection[] = [
  'mft', 'prefetch', 'processes', 'autoruns', 'netconn', 'dlls', 'shimcache', 'registry', 'evtx',
]

export interface CountItem { name: string; count: number }

export interface FleetSelector {
  collection: FleetCollection
  agent_ids?: string[]
  group?: string
  tag?: string
}

export interface DispatchStatus {
  agent_id: string
  name: string
  status: 'dispatched' | 'offline'
  result_id?: string
}

export interface FleetCollectionResult {
  id: string
  scheduled_id?: string
  agent_id: string
  agent_name: string
  collection: FleetCollection
  status: 'pending' | 'done' | 'error' | 'offline' | 'timeout'
  error?: string
  data?: string // only present on the single-result endpoint
  started_at: string
  finished_at?: string
}

export interface ScheduledCollection {
  id: string
  name: string
  collection: FleetCollection
  agent_ids: string // JSON array string
  group: string
  tag: string
  interval_minutes: number
  enabled: boolean
  last_run?: string
  next_run?: string
  created_at: string
}

interface ApiResponse<T> { success: boolean; data: T }

export const fleetApi = {
  groups: async (): Promise<{ groups: CountItem[]; tags: CountItem[] }> => {
    const { data } = await apiClient.get<ApiResponse<{ groups: CountItem[]; tags: CountItem[] }>>('/agents/groups')
    return data.data
  },

  setTags: async (agentId: string, payload: { group_name?: string; tags?: string[] }): Promise<void> => {
    await apiClient.patch(`/agents/${agentId}/tags`, payload)
  },

  bulkCollect: async (sel: FleetSelector): Promise<{ collection: string; dispatched: DispatchStatus[] }> => {
    const { data } = await apiClient.post<ApiResponse<{ collection: string; dispatched: DispatchStatus[] }>>(
      '/agents/bulk/collect', sel,
    )
    return data.data
  },

  results: async (params?: { scheduled_id?: string; agent_id?: string }): Promise<FleetCollectionResult[]> => {
    const { data } = await apiClient.get<ApiResponse<FleetCollectionResult[]>>('/agents/fleet/results', { params })
    return data.data
  },

  result: async (id: string): Promise<FleetCollectionResult> => {
    const { data } = await apiClient.get<ApiResponse<FleetCollectionResult>>(`/agents/fleet/results/${id}`)
    return data.data
  },

  listSchedules: async (): Promise<ScheduledCollection[]> => {
    const { data } = await apiClient.get<ApiResponse<ScheduledCollection[]>>('/agents/scheduled-collections')
    return data.data
  },

  createSchedule: async (payload: {
    name: string
    collection: FleetCollection
    agent_ids?: string[]
    group?: string
    tag?: string
    interval_minutes?: number
    enabled?: boolean
  }): Promise<ScheduledCollection> => {
    const { data } = await apiClient.post<ApiResponse<ScheduledCollection>>('/agents/scheduled-collections', payload)
    return data.data
  },

  updateSchedule: async (
    id: string,
    payload: Partial<{ name: string; interval_minutes: number; enabled: boolean; group: string; tag: string }>,
  ): Promise<ScheduledCollection> => {
    const { data } = await apiClient.patch<ApiResponse<ScheduledCollection>>(`/agents/scheduled-collections/${id}`, payload)
    return data.data
  },

  deleteSchedule: async (id: string): Promise<void> => {
    await apiClient.delete(`/agents/scheduled-collections/${id}`)
  },
}
