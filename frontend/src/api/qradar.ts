import axios from 'axios'

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
    const { data } = await axios.get('/api/v1/qradar/configs')
    return data as QRadarConfig[]
  },
  activateConfig: async (id: number) => {
    const { data } = await axios.post(`/api/v1/qradar/configs/${id}/activate`)
    return data as QRadarConfig
  },
  createConfig: async (payload: any) => {
    const { data } = await axios.post('/api/v1/qradar/configs', payload)
    return data as QRadarConfig
  },
  updateConfig: async (id: number, payload: any) => {
    const { data } = await axios.put(`/api/v1/qradar/configs/${id}`, payload)
    return data as QRadarConfig
  },
  deleteConfig: async (id: number) => {
    const { data } = await axios.delete(`/api/v1/qradar/configs/${id}`)
    return data
  },
  manualHunt: async (payload: { query: string; timeRange: string }) => {
    const { data } = await axios.post('/api/v1/qradar/hunt', payload)
    return data
  }
}
