import apiClient from './client'

export interface TraceProc {
  pid: number
  ppid: number
  name: string
  parent_name?: string
  user?: string
  created?: string
  cmdline?: string
  path?: string
}

export interface TraceEvent {
  time: string
  kind: 'process' | 'prefetch' | 'file' | 'shimcache' | 'log'
  title: string
  detail?: string
  source: string
}

export interface TraceResult {
  target: string
  found: boolean
  ancestry: TraceProc[]
  timeline: TraceEvent[]
  summary: {
    user?: string
    parent?: string
    created?: string
    origin?: string
    event_count?: number
    chain_depth?: number
  }
}

export interface TraceSource {
  type: 'processes' | 'prefetch' | 'mft' | 'shimcache' | 'evtx'
  data: unknown
}

interface ApiResponse<T> { success: boolean; data: T }

export const traceApi = {
  // entity reconstructs the origin/lineage of a process/file/app from collected
  // EdgeForensics/EVTX artifacts (parent chain + related traces, chronological).
  entity: async (target: string, pid: number, sources: TraceSource[]): Promise<TraceResult> => {
    const { data } = await apiClient.post<ApiResponse<TraceResult>>('/trace/entity', { target, pid, sources })
    return data.data
  },

  // addToCase persists a trace's focused timeline onto a case's attack timeline.
  addToCase: async (caseId: string, payload: { host: string; target: string; events: TraceEvent[] }):
    Promise<{ events_created: number; skipped: number }> => {
    const { data } = await apiClient.post<ApiResponse<{ events_created: number; skipped: number }>>(
      `/cases/${caseId}/timeline/from-trace`, payload)
    return data.data
  },
}
