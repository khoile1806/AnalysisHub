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

  // Fleet-wide Sigma sweep. Returns as soon as the work is dispatched; per-agent
  // results arrive asynchronously as ordinary fleet results and are read back
  // through sigmaSweepSummary.
  sigmaSweep: async (payload: {
    agent_ids?: string[]
    group?: string
    tag?: string
    hours?: number
    max_per_source?: number
  }): Promise<FleetSigmaDispatch> => {
    const { data } = await apiClient.post<ApiResponse<FleetSigmaDispatch>>('/agents/fleet/sigma-sweep', payload)
    return data.data
  },

  sigmaSweepSummary: async (params: { scheduled_id?: string; since?: string } = {}): Promise<FleetSigmaSummaryResponse> => {
    const { data } = await apiClient.get<ApiResponse<FleetSigmaSummaryResponse>>('/agents/fleet/sigma-sweep/summary', { params })
    return data.data
  },
}

export interface FleetSigmaDispatch {
  run_id: string
  collection: string
  hours: number
  max_per_source: number
  rules_count: number
  sources: number
  concurrency: number
  dispatched: Array<{ agent_id: string; name: string; status: string; result_id?: string }>
}

// FleetSigmaRule is the point of a fleet sweep: one row per rule, telling you
// which machines show the technique rather than which events matched.
export interface FleetSigmaRule {
  rule_id?: string
  rule_title: string
  rule_level: string
  mitre_techniques?: string[]
  mitre_tactics?: string[]
  agent_count: number
  hosts: string[]
  event_count: number
  agents?: Array<{ agent_id: string; agent_name: string; event_count: number }>
}

export interface FleetSigmaSummaryResponse {
  scheduled_id?: string
  since?: string
  truncated?: boolean
  summary: {
    total_agents: number
    done: number
    error: number
    offline: number
    pending: number
    timeout: number
    events_scanned: number
    agents_with_alerts: number
    rules_triggered: number
    total_alerts: number
    rules: FleetSigmaRule[]
  }
}
