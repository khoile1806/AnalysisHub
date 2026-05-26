import api from './client'

export interface ELKConfig {
  url: string
  username: string
  has_auth: boolean
}

export interface ELKConfigPayload {
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

export const elkApi = {
  getConfig: async (): Promise<ELKConfig> => {
    const { data } = await api.get('/elk/config')
    return data
  },
  saveConfig: async (payload: ELKConfigPayload): Promise<{ message: string }> => {
    const { data } = await api.put('/elk/config', payload)
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
      // Both upstream-batch errors and EventSource transport errors land here.
      // Batch errors arrive as MessageEvent with parseable data; transport
      // errors do not.
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

    return es
  },
}
