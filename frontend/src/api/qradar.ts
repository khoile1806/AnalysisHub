import api from './client'
import {
  attachSseHandlers,
  base64url,
  type AutoHuntHandlers,
  type FileIOC,
} from './elk'

export interface QRadarConfig {
  id: number
  name: string
  description: string
  url: string
  username: string
  is_active: boolean
  has_auth: boolean
}

export const qradarApi = {
  getConfigs: async () => {
    const { data } = await api.get('/qradar/configs')
    return data as QRadarConfig[]
  },
  activateConfig: async (id: number) => {
    const { data } = await api.post(`/qradar/configs/${id}/activate`)
    return data as QRadarConfig
  },
  createConfig: async (payload: any) => {
    const { data } = await api.post('/qradar/configs', payload)
    return data as QRadarConfig
  },
  updateConfig: async (id: number, payload: any) => {
    const { data } = await api.put(`/qradar/configs/${id}`, payload)
    return data as QRadarConfig
  },
  deleteConfig: async (id: number) => {
    const { data } = await api.delete(`/qradar/configs/${id}`)
    return data
  },
  manualHunt: async (payload: { query: string; timeRange: string }) => {
    const { data } = await api.post('/qradar/hunt', payload)
    return data
  },

  // Auto-hunt: stream all stored IOCs against QRadar via SSE. QRadar searches
  // the full event payload (no index selection), so `indices` is ignored.
  streamAutoHunt: (token: string, _indices: string, timeRange: string, handlers: AutoHuntHandlers): EventSource => {
    const baseUrl = (api.defaults.baseURL || '').replace(/\/+$/, '')
    let url = `${baseUrl}/qradar/hunt/stream?token=${encodeURIComponent(token)}`
    if (timeRange) url += `&timeRange=${encodeURIComponent(timeRange)}`
    const es = new EventSource(url)
    attachSseHandlers(es, handlers)
    return es
  },

  // File-hunt: stream a client-supplied IOC list (base64-JSON) against QRadar.
  streamFileHunt: (token: string, iocs: FileIOC[], _indices: string, timeRange: string, handlers: AutoHuntHandlers): EventSource => {
    const baseUrl = (api.defaults.baseURL || '').replace(/\/+$/, '')
    const payload = base64url(JSON.stringify({ iocs }))
    let url = `${baseUrl}/qradar/hunt/file-stream?token=${encodeURIComponent(token)}&iocs=${encodeURIComponent(payload)}`
    if (timeRange) url += `&timeRange=${encodeURIComponent(timeRange)}`
    const es = new EventSource(url)
    attachSseHandlers(es, handlers)
    return es
  },
}
