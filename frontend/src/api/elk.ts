import api from './client'

export interface ELKConfig {
  id: number
  name: string
  description: string
  url: string
  username: string
  is_active: boolean
  has_auth: boolean
  created_at: string
  updated_at: string
}

export interface ELKConfigPayload {
  name?: string
  description?: string
  url: string
  username: string
  password?: string
  api_key?: string
}

export interface ELKHit {
  _index: string
  _id: string
  _score: number
  _source: Record<string, any>
}

export interface ELKSearchResponse {
  took: number
  timed_out: boolean
  hits: {
    total: { value: number; relation: string }
    hits: ELKHit[]
  }
}

export type HuntMode = 'lucene' | 'dsl'

export interface ManualHuntPayload {
  mode: HuntMode
  query?: string
  body?: Record<string, any>
}

export interface AutoHuntProgress {
  batch: number
  total_batches: number
  bucket: string
  batch_hits: number
  total_hits: number
}

export interface AutoHuntHitsEvent {
  batch: number
  bucket: string
  hits: ELKHit[]
}

export interface AutoHuntErrorEvent {
  batch: number
  bucket: string
  error: string
}

export interface AutoHuntDoneEvent {
  total_hits: number
  total_batches: number
  total_iocs: number
  took_ms: number
}

export interface AutoHuntHandlers {
  onProgress?: (p: AutoHuntProgress) => void
  onHits?: (h: AutoHuntHitsEvent) => void
  onError?: (e: AutoHuntErrorEvent) => void
  onDone?: (d: AutoHuntDoneEvent) => void
  onTransportError?: (err: Event) => void
}

// File IOC parser response
export interface FileIOC {
  value: string
  type: string
  line_no: number
  original?: string
}

export interface SkippedLine {
  line_no: number
  line: string
  reason: string
}

export interface FileIOCParseResponse {
  iocs: FileIOC[]
  skipped: SkippedLine[]
  counts: Record<string, number>
  total_lines: number
}

function attachSseHandlers(es: EventSource, handlers: AutoHuntHandlers) {
  const parse = <T,>(e: MessageEvent): T | null => {
    try {
      return JSON.parse(e.data) as T
    } catch {
      return null
    }
  }
  es.addEventListener('progress', (e) => {
    const d = parse<AutoHuntProgress>(e as MessageEvent)
    if (d) handlers.onProgress?.(d)
  })
  es.addEventListener('hits', (e) => {
    const d = parse<AutoHuntHitsEvent>(e as MessageEvent)
    if (d) handlers.onHits?.(d)
  })
  es.addEventListener('error', (e) => {
    const me = e as MessageEvent
    if (me.data) {
      const d = parse<AutoHuntErrorEvent>(me)
      if (d) handlers.onError?.(d)
    } else {
      handlers.onTransportError?.(e)
    }
  })
  es.addEventListener('done', (e) => {
    const d = parse<AutoHuntDoneEvent>(e as MessageEvent)
    if (d) handlers.onDone?.(d)
    es.close()
  })
}

// Base64url encode arbitrary string content for EventSource query param.
function base64url(text: string): string {
  const utf8 = new TextEncoder().encode(text)
  let bin = ''
  for (const b of utf8) bin += String.fromCharCode(b)
  return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '')
}

export const elkApi = {
  // Legacy singular config (returns the active profile)
  getConfig: async (): Promise<ELKConfig> => {
    const { data } = await api.get('/elk/config')
    return data
  },
  saveConfig: async (payload: ELKConfigPayload): Promise<{ message: string }> => {
    const { data } = await api.put('/elk/config', payload)
    return data
  },

  // Multi-profile CRUD
  listConfigs: async (): Promise<ELKConfig[]> => {
    const { data } = await api.get('/elk/configs')
    return data
  },
  createConfig: async (payload: ELKConfigPayload): Promise<ELKConfig> => {
    const { data } = await api.post('/elk/configs', payload)
    return data
  },
  updateConfig: async (id: number, payload: ELKConfigPayload): Promise<ELKConfig> => {
    const { data } = await api.put(`/elk/configs/${id}`, payload)
    return data
  },
  deleteConfig: async (id: number): Promise<{ message: string }> => {
    const { data } = await api.delete(`/elk/configs/${id}`)
    return data
  },
  activateConfig: async (id: number): Promise<ELKConfig> => {
    const { data } = await api.post(`/elk/configs/${id}/activate`)
    return data
  },

  manualHunt: async (payload: ManualHuntPayload): Promise<ELKSearchResponse> => {
    const { data } = await api.post('/elk/hunt', payload)
    return data
  },

  streamAutoHunt: (token: string, handlers: AutoHuntHandlers): EventSource => {
    const baseUrl = (api.defaults.baseURL || '').replace(/\/+$/, '')
    const url = `${baseUrl}/elk/hunt/stream?token=${encodeURIComponent(token)}`
    const es = new EventSource(url)
    attachSseHandlers(es, handlers)
    return es
  },

  // File IOC workflow
  parseIOCFile: async (file: File): Promise<FileIOCParseResponse> => {
    const fd = new FormData()
    fd.append('file', file)
    const { data } = await api.post('/elk/iocs/parse', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data
  },

  streamFileHunt: (token: string, iocs: FileIOC[], handlers: AutoHuntHandlers): EventSource => {
    const baseUrl = (api.defaults.baseURL || '').replace(/\/+$/, '')
    const payload = base64url(JSON.stringify({ iocs }))
    const url = `${baseUrl}/elk/hunt/file-stream?token=${encodeURIComponent(token)}&iocs=${encodeURIComponent(payload)}`
    const es = new EventSource(url)
    attachSseHandlers(es, handlers)
    return es
  },
}
