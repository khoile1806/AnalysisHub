import apiClient from './client'

// A canary token: an administrator-created tracking link. When its public link
// (/c/<slug>) is opened, the server records the visitor and 302-redirects to a
// benign target chosen by the operator.
export interface CanaryToken {
  id: string
  slug: string
  name: string
  target_url: string
  base_url?: string
  description?: string
  active: boolean
  collect_details: boolean
  request_location: boolean
  case_id?: string | null
  hit_count: number
  unique_visitors: number
  last_hit_at?: string | null
  created_by: string
  created_at: string
  updated_at: string
  link: string // fully-qualified public URL, built by the server
}

// A single recorded visit to a canary link.
export interface CanaryHit {
  id: string
  token_id: string
  ip: string
  forwarded_for?: string
  remote_addr?: string
  user_agent?: string
  browser?: string
  os?: string
  device_type?: string
  is_bot?: boolean
  referer?: string
  accept_language?: string
  country?: string
  country_code?: string
  city?: string
  isp?: string
  asn?: string
  lat?: number
  lon?: number
  mobile?: boolean
  proxy?: boolean
  hosting?: boolean
  // Precise GPS (browser Geolocation API, with consent)
  geo_lat?: number
  geo_lon?: number
  geo_accuracy?: number
  geo_error?: string
  // Device / browser fingerprint (interstitial JS)
  timezone?: string
  languages?: string
  screen_w?: number
  screen_h?: number
  viewport_w?: number
  viewport_h?: number
  pixel_ratio?: number
  platform?: string
  cpu_cores?: number
  device_memory?: number
  gpu_vendor?: string
  gpu_renderer?: string
  conn_type?: string
  battery_level?: number
  client_data?: string // full raw JSON dump
  created_at: string
}

export interface CreateCanaryToken {
  name: string
  target_url: string
  description?: string
  slug?: string // optional custom slug; random if omitted
  base_url?: string // optional link domain; falls back to server default
  case_id?: string // optional Case to attach to
  collect_details?: boolean // serve JS interstitial to gather rich client data
  request_location?: boolean // also prompt for precise GPS
}

export interface BulkCreateCanaryTokens {
  targets: string[] // one redirect URL per link
  name_prefix?: string // optional; default label = target host
  base_url?: string
  description?: string
  collect_details?: boolean
  request_location?: boolean
}

export interface BulkCreateResult {
  created: CanaryToken[]
  errors: { target: string; error: string }[]
}

export interface UpdateCanaryToken {
  name?: string
  target_url?: string
  description?: string
  active?: boolean
  base_url?: string
  case_id?: string | null // "" / null detaches; a uuid attaches
  collect_details?: boolean
  request_location?: boolean
}

export const canaryApi = {
  async list(): Promise<CanaryToken[]> {
    const { data } = await apiClient.get('/canary/tokens')
    return data.data
  },

  async create(input: CreateCanaryToken): Promise<CanaryToken> {
    const { data } = await apiClient.post('/canary/tokens', input)
    return data.data
  },

  async createBulk(input: BulkCreateCanaryTokens): Promise<BulkCreateResult> {
    const { data } = await apiClient.post('/canary/tokens/bulk', input)
    return data.data
  },

  async update(id: string, input: UpdateCanaryToken): Promise<CanaryToken> {
    const { data } = await apiClient.patch(`/canary/tokens/${id}`, input)
    return data.data
  },

  async remove(id: string): Promise<void> {
    await apiClient.delete(`/canary/tokens/${id}`)
  },

  async hits(id: string): Promise<CanaryHit[]> {
    const { data } = await apiClient.get(`/canary/tokens/${id}/hits`)
    return data.data
  },

  async clearHits(id: string): Promise<void> {
    await apiClient.delete(`/canary/tokens/${id}/hits`)
  },

  // Pivot a captured visitor IP into an OSINT scan; returns the new scan id.
  async scanHit(tokenId: string, hitId: string): Promise<string> {
    const { data } = await apiClient.post(`/canary/tokens/${tokenId}/hits/${hitId}/scan`)
    return data.data.scan_id
  },
}
