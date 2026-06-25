import api from './client'
import {
  attachSseHandlers,
  base64url,
  type AutoHuntHandlers,
  type FileIOC,
} from './elk'

export interface SplunkConfig {
  id: number
  name: string
  description: string
  url: string
  username: string
  is_active: boolean
  has_auth: boolean
}

export const splunkApi = {
  getConfigs: async () => {
    const { data } = await api.get('/splunk/configs')
    return data as SplunkConfig[]
  },
  activateConfig: async (id: number) => {
    const { data } = await api.post(`/splunk/configs/${id}/activate`)
    return data as SplunkConfig
  },
  createConfig: async (payload: any) => {
    const { data } = await api.post('/splunk/configs', payload)
    return data as SplunkConfig
  },
  updateConfig: async (id: number, payload: any) => {
    const { data } = await api.put(`/splunk/configs/${id}`, payload)
    return data as SplunkConfig
  },
  deleteConfig: async (id: number) => {
    const { data } = await api.delete(`/splunk/configs/${id}`)
    return data
  },
  getIndices: async () => {
    const { data } = await api.get('/splunk/indices')
    return data as string[]
  },
  manualHunt: async (payload: { query: string; indices: string; timeRange: string }) => {
    const { data } = await api.post('/splunk/hunt', payload)
    return data
  },

  // Auto-hunt: stream all stored IOCs against Splunk via SSE.
  streamAutoHunt: (token: string, indices: string, timeRange: string, handlers: AutoHuntHandlers): EventSource => {
    const baseUrl = (api.defaults.baseURL || '').replace(/\/+$/, '')
    let url = `${baseUrl}/splunk/hunt/stream?token=${encodeURIComponent(token)}`
    if (indices) url += `&indices=${encodeURIComponent(indices)}`
    if (timeRange) url += `&timeRange=${encodeURIComponent(timeRange)}`
    const es = new EventSource(url)
    attachSseHandlers(es, handlers)
    return es
  },

  // File-hunt: stream a client-supplied IOC list (base64-JSON) against Splunk.
  streamFileHunt: (token: string, iocs: FileIOC[], indices: string, timeRange: string, handlers: AutoHuntHandlers): EventSource => {
    const baseUrl = (api.defaults.baseURL || '').replace(/\/+$/, '')
    const payload = base64url(JSON.stringify({ iocs }))
    let url = `${baseUrl}/splunk/hunt/file-stream?token=${encodeURIComponent(token)}&iocs=${encodeURIComponent(payload)}`
    if (indices) url += `&indices=${encodeURIComponent(indices)}`
    if (timeRange) url += `&timeRange=${encodeURIComponent(timeRange)}`
    const es = new EventSource(url)
    attachSseHandlers(es, handlers)
    return es
  },
}
