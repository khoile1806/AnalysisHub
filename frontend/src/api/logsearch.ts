import api from './client'

export interface LogIngestJob {
  id: string
  case: string
  filename: string
  log_type: string
  detected_type: string
  index: string
  status: 'queued' | 'running' | 'done' | 'error'
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

export const logsearchApi = {
  meta: async (): Promise<LogSearchMeta> => {
    const { data } = await api.get('/logsearch/meta')
    return data
  },
  listJobs: async (caseName?: string): Promise<LogIngestJob[]> => {
    const { data } = await api.get('/logsearch/jobs', {
      params: caseName ? { case: caseName } : {},
    })
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
  upload: async (
    caseName: string,
    logType: string,
    files: File[],
    caseId?: string,
  ): Promise<{ jobs: LogIngestJob[] }> => {
    const fd = new FormData()
    fd.append('case', caseName)
    fd.append('log_type', logType)
    if (caseId) fd.append('case_id', caseId)
    files.forEach((f) => fd.append('files', f))
    const { data } = await api.post('/logsearch/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },
}
