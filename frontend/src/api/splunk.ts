import axios from 'axios'

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
    const { data } = await axios.get('/api/v1/splunk/configs')
    return data as SplunkConfig[]
  },
  activateConfig: async (id: number) => {
    const { data } = await axios.post(`/api/v1/splunk/configs/${id}/activate`)
    return data as SplunkConfig
  },
  createConfig: async (payload: any) => {
    const { data } = await axios.post('/api/v1/splunk/configs', payload)
    return data as SplunkConfig
  },
  updateConfig: async (id: number, payload: any) => {
    const { data } = await axios.put(`/api/v1/splunk/configs/${id}`, payload)
    return data as SplunkConfig
  },
  deleteConfig: async (id: number) => {
    const { data } = await axios.delete(`/api/v1/splunk/configs/${id}`)
    return data
  },
  getIndices: async () => {
    const { data } = await axios.get('/api/v1/splunk/indices')
    return data as string[]
  },
  manualHunt: async (payload: { query: string; indices: string; timeRange: string }) => {
    const { data } = await axios.post('/api/v1/splunk/hunt', payload)
    return data
  }
}
