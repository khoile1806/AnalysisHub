import api from './client'

export interface OpenCTIConfig {
  url: string
  username: string
  has_auth: boolean
}

export interface OpenCTIConfigPayload {
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
  getConfig: async (): Promise<OpenCTIConfig> => {
    const { data } = await api.get('/opencti/config')
    return data
  },
  saveConfig: async (payload: OpenCTIConfigPayload): Promise<{ message: string }> => {
    const { data } = await api.put('/opencti/config', payload)
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
