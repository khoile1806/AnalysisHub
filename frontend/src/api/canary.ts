import apiClient from './client'

// A canary token: an administrator-created tracking link. When its public link
// (/c/<slug>) is opened, the server records the visitor and 302-redirects to a
// benign target chosen by the operator.
export type CanaryKind = 'link' | 'image' | 'document'

export interface CanaryToken {
  id: string
  slug: string
  name: string
  kind: CanaryKind
  target_url: string
  base_url?: string
  description?: string
  active: boolean
  collect_details: boolean
  request_location: boolean
  case_id?: string | null
  file_name?: string
  file_mime?: string
  alert_count: number
  hit_count: number
  unique_visitors: number
  last_hit_at?: string | null
  created_by: string
  created_at: string
  updated_at: string
  link: string // fully-qualified public URL, built by the server
  download_url?: string // authed path to fetch the served image / weaponised doc
}

// A raised alert when a human opens a token's link/image/document.
export interface CanaryAlert {
  id: string
  token_id: string
  hit_id: string
  token_name: string
  title: string
  summary: string
  ip?: string
  severity: 'low' | 'medium' | 'high' | 'critical'
  seen: boolean
  created_at: string
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
  severity?: 'low' | 'medium' | 'high' | 'critical'
  risk_flags?: string
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
  kind?: CanaryKind // 'link' (default) or 'image' (blank pixel; upload via createFile)
  target_url?: string // required for kind=link
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

  // Create an image or document token from a REAL uploaded file. The system
  // stores the real image (served verbatim) or weaponises the .docx and returns
  // it for download. Fields beyond name/kind/file are optional.
  async createFile(input: {
    kind: 'image' | 'document'
    name: string
    file: File
    slug?: string
    base_url?: string
    case_id?: string
    description?: string
  }): Promise<CanaryToken> {
    const fd = new FormData()
    fd.append('kind', input.kind)
    fd.append('name', input.name)
    fd.append('file', input.file)
    if (input.slug) fd.append('slug', input.slug)
    if (input.base_url) fd.append('base_url', input.base_url)
    if (input.case_id) fd.append('case_id', input.case_id)
    if (input.description) fd.append('description', input.description)
    const { data } = await apiClient.post('/canary/tokens/upload', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  // Download the served artefact (real image / weaponised document) as a Blob
  // and trigger a browser save with the token's filename.
  async downloadFile(id: string, filename: string): Promise<void> {
    const res = await apiClient.get(`/canary/tokens/${id}/file`, { responseType: 'blob' })
    const url = URL.createObjectURL(res.data as Blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename || 'canary-file'
    document.body.appendChild(a)
    a.click()
    a.remove()
    URL.revokeObjectURL(url)
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

  // -- Alerts (in-app feed/badge for human hits) --------------------------------
  async alerts(unseenOnly = false): Promise<CanaryAlert[]> {
    const { data } = await apiClient.get('/canary/alerts', {
      params: unseenOnly ? { unseen: 1 } : undefined,
    })
    return data.data
  },

  async alertCount(): Promise<number> {
    const { data } = await apiClient.get('/canary/alerts/count')
    return data.data.unseen
  },

  async markAlertsSeen(input: { all?: boolean; ids?: string[] }): Promise<void> {
    await apiClient.post('/canary/alerts/seen', input)
  },
}
