import api from './client'
import type { SigmaAlert } from './hunting'

export interface LogIngestJob {
  id: string
  case: string
  host?: string
  source?: 'upload' | 'agent'
  filename: string
  log_type: string
  detected_type: string
  index: string
  status: 'queued' | 'running' | 'done' | 'error' | 'skipped'
  docs_indexed: number
  docs_failed: number
  message: string
  created_at: string
  finished_at?: string
}

export interface HostSummary {
  host: string
  files: number
  docs_indexed: number
  running: number
  errors: number
  sources: string[]
  last_activity?: string
}

export interface LogIndex {
  index: string
  docs: string
  size: string
}

export interface LogSearchMeta {
  log_types: string[]
  index_prefix: string
  es_up: boolean
}

export interface ContainerState {
  name: string
  running: boolean
  status: string
}

export interface AutoShutdown {
  enabled: boolean
  timeout_sec: number
  idle_sec?: number
  stops_in_sec?: number
  manual_off?: boolean
}

export interface ELKStatus {
  control_enabled: boolean
  hint?: string
  elasticsearch?: ContainerState
  kibana?: ContainerState
  auto_shutdown?: AutoShutdown
}

export interface LogSearchHealth {
  elasticsearch: { up: boolean; status: string }
  kibana: { up: boolean }
  indices: number
  documents: number
  elk_control: boolean
}

export interface LogBucket { key: string; count: number }
export interface LogSummary {
  total: number
  min_time: string
  max_time: string
  by_category: LogBucket[]
  by_log_type: LogBucket[]
  top_source_ip: LogBucket[]
  top_event_code: LogBucket[]
}

export const logsearchApi = {
  meta: async (): Promise<LogSearchMeta> => {
    const { data } = await api.get('/logsearch/meta')
    return data
  },
  health: async (): Promise<LogSearchHealth> => {
    const { data } = await api.get('/logsearch/health')
    return data
  },
  summary: async (caseName?: string): Promise<LogSummary> => {
    const { data } = await api.get('/logsearch/summary', { params: caseName ? { case: caseName } : {} })
    return data
  },
  listJobs: async (caseName?: string, caseId?: string): Promise<LogIngestJob[]> => {
    const params: Record<string, string> = {}
    if (caseName) params.case = caseName
    if (caseId) params.case_id = caseId
    const { data } = await api.get('/logsearch/jobs', { params })
    return data.jobs ?? []
  },
  listIndices: async (): Promise<LogIndex[]> => {
    const { data } = await api.get('/logsearch/indices')
    return data.indices ?? []
  },
  deleteIndex: async (index: string): Promise<{ deleted: string }> => {
    const { data } = await api.delete(`/logsearch/indices/${encodeURIComponent(index)}`)
    return data
  },
  elkStatus: async (): Promise<ELKStatus> => {
    const { data } = await api.get('/logsearch/elk/status')
    return data
  },
  elkPower: async (verb: 'start' | 'stop'): Promise<{ ok: boolean }> => {
    const { data } = await api.post(`/logsearch/elk/${verb}`)
    return data
  },
  sandboxStatus: async (): Promise<{ control_enabled: boolean; hint?: string; sandbox?: ContainerState; auto_shutdown?: AutoShutdown }> => {
    const { data } = await api.get('/logsearch/sandbox/status')
    return data
  },
  sandboxPower: async (verb: 'start' | 'stop'): Promise<{ ok: boolean }> => {
    const { data } = await api.post(`/logsearch/sandbox/${verb}`)
    return data
  },
  // Heartbeat that keeps a managed service alive while its page is open and
  // auto-starts it on demand. svc = 'elk' | 'sandbox'.
  keepalive: async (svc: 'elk' | 'sandbox'): Promise<{ ok: boolean; starting?: boolean; manual_off?: boolean }> => {
    const { data } = await api.post(`/logsearch/keepalive/${svc}`)
    return data
  },
  upload: async (
    caseName: string,
    logType: string,
    files: File[],
    caseId?: string,
    timezone?: string,
  ): Promise<{ jobs: LogIngestJob[] }> => {
    const fd = new FormData()
    fd.append('case', caseName)
    fd.append('log_type', logType)
    if (caseId) fd.append('case_id', caseId)
    if (timezone) fd.append('timezone', timezone)
    files.forEach((f) => fd.append('files', f))
    const { data } = await api.post('/logsearch/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },
  enrich: async (caseName?: string): Promise<{ configured: boolean; results: EnrichedIOC[] }> => {
    const { data } = await api.post('/logsearch/enrich', {}, { params: caseName ? { case: caseName } : {} })
    return data
  },
  hosts: async (caseName?: string): Promise<HostSummary[]> => {
    const { data } = await api.get('/logsearch/hosts', { params: caseName ? { case: caseName } : {} })
    return data.hosts ?? []
  },
  deleteHost: async (host: string): Promise<{ host: string; deleted_indices: string[]; removed_jobs: number }> => {
    const { data } = await api.delete(`/logsearch/hosts/${encodeURIComponent(host)}`)
    return data
  },
  collectFromAgent: async (
    agentId: string,
    opts?: { case?: string; days?: number },
  ): Promise<{ ok: boolean; job_id: string; case: string; host: string; days: number }> => {
    const { data } = await api.post(`/logsearch/agents/${agentId}/collect`, opts ?? {})
    return data
  },

  // Sigma over already-ingested logs — the dead-box path: run the detection
  // ruleset against an .evtx that was uploaded from a machine with no agent, or
  // re-hunt logs collected weeks ago.
  sigmaTargets: async (params: { case_id?: string; host?: string } = {}): Promise<SigmaOfflineTarget[]> => {
    const { data } = await api.get('/logsearch/sigma/targets', { params })
    return data.targets ?? []
  },

  sigmaScanOffline: async (payload: {
    index?: string
    job_id?: string
    case_id?: string
    host?: string
    hours?: number
    max?: number
    all_events?: boolean
  }): Promise<SigmaOfflineResult> => {
    const { data } = await api.post('/logsearch/sigma/scan', payload, { timeout: 600_000 })
    return data
  },
}

export interface SigmaOfflineTarget {
  job_id: string
  filename: string
  host: string
  case?: string
  case_id?: string
  index: string
  log_type: string
  docs_indexed: number
  created_at: string
}

export interface SigmaOfflineResult {
  alerts: SigmaAlert[]
  events_scanned: number
  index: string
  indices?: string[]
  rules_count: number
  hours?: number
  filtered?: boolean
  channels?: string[]
  // True when the event cap was reached, so the result is a sample rather than
  // full coverage of the index.
  truncated?: boolean
  load_stats?: { files: number; loaded: number; unsupported: number; errors: number }
}

export interface EnrichFinding {
  Source: string
  Score: number
  Malicious: boolean
  Summary: string
}
export interface EnrichedIOC {
  IOC: string
  Type: string
  Threat: boolean
  MaxScore: number
  Findings: EnrichFinding[]
}
