import api from './client'

export interface OpenCTIConfig {
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

export interface OpenCTIConfigPayload {
  name?: string
  description?: string
  url: string
  username: string
  password?: string
  token?: string
}

export interface IOC {
  id: number
  value: string
  type: string
  source: string
  description: string
  created_at: string
}

export interface ManualIOCPayload {
  type: string
  value: string
  description?: string
}

export const openctiApi = {
  // Legacy singular (still returns the active profile, used elsewhere).
  getConfig: async (): Promise<OpenCTIConfig> => {
    const { data } = await api.get('/opencti/config')
    return data
  },
  saveConfig: async (payload: OpenCTIConfigPayload): Promise<{ message: string }> => {
    const { data } = await api.put('/opencti/config', payload)
    return data
  },

  // Multi-profile CRUD
  listConfigs: async (): Promise<OpenCTIConfig[]> => {
    const { data } = await api.get('/opencti/configs')
    return data
  },
  createConfig: async (payload: OpenCTIConfigPayload): Promise<OpenCTIConfig> => {
    const { data } = await api.post('/opencti/configs', payload)
    return data
  },
  updateConfig: async (id: number, payload: OpenCTIConfigPayload): Promise<OpenCTIConfig> => {
    const { data } = await api.put(`/opencti/configs/${id}`, payload)
    return data
  },
  deleteConfig: async (id: number): Promise<{ message: string }> => {
    const { data } = await api.delete(`/opencti/configs/${id}`)
    return data
  },
  activateConfig: async (id: number): Promise<OpenCTIConfig> => {
    const { data } = await api.post(`/opencti/configs/${id}/activate`)
    return data
  },

  sync: async (): Promise<{ message: string; added: number }> => {
    const { data } = await api.post('/opencti/sync')
    return data
  },
  listIOCs: async (): Promise<IOC[]> => {
    const { data } = await api.get('/iocs')
    return data
  },
  addManualIOC: async (payload: ManualIOCPayload): Promise<{ message: string; ioc: IOC }> => {
    const { data } = await api.post('/iocs', payload)
    return data
  },
}
