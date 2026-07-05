import api from './client'

export interface LogIngestJob {
  id: string
  case: string
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

export interface ELKStatus {
  control_enabled: boolean
  hint?: string
  elasticsearch?: ContainerState
  kibana?: ContainerState
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
  sandboxStatus: async (): Promise<{ control_enabled: boolean; hint?: string; sandbox?: ContainerState }> => {
    const { data } = await api.get('/logsearch/sandbox/status')
    return data
  },
  sandboxPower: async (verb: 'start' | 'stop'): Promise<{ ok: boolean }> => {
    const { data } = await api.post(`/logsearch/sandbox/${verb}`)
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
