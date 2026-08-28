import apiClient from './client'

// One source's verdict on an indicator (VirusTotal / AbuseIPDB / OTX / Shodan).
export interface IntelFinding {
  Source: string
  Score: number
  Malicious: boolean
  Summary: string
  Labels?: string[]
  Extra?: Record<string, string>
}

export interface IntelLookupResult {
  success: boolean
  indicator: string
  type: string // hash | ip | domain | url
  vt_url: string
  configured: boolean
  message?: string
  threat?: boolean
  max_score?: number
  findings?: IntelFinding[]
  // complete=false means at least one source could not be consulted, so an
  // absence of findings below is not a clean verdict.
  complete?: boolean
  unavailable?: string[]
}

export interface IocMatch {
  type: string
  source: string
  description: string
}

export interface IocMatchResult {
  count: number
  matches: Record<string, IocMatch> // keyed by lowercased value
}

export const intelApi = {
  // Live threat-intel lookup for a single indicator (auto-detects type).
  lookup: async (indicator: string, type?: string): Promise<IntelLookupResult> => {
    const { data } = await apiClient.get<IntelLookupResult>('/intel/lookup', {
      params: { indicator, ...(type ? { type } : {}) },
    })
    return data
  },

  // Batch-check raw values against the IOC store. Returns matched values keyed
  // (lowercased) so any scan view can highlight known indicators.
  matchIOCs: async (values: string[]): Promise<IocMatchResult> => {
    const { data } = await apiClient.post<IocMatchResult & { success: boolean }>('/iocs/match', { values })
    return { count: data.count, matches: data.matches }
  },
}
