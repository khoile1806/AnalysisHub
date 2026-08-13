import apiClient from './client'

interface ApiResponse<T> { success: boolean; data: T }

export interface NetChainStep { id: string; label: string; status: 'pending' | 'running' | 'done' | 'failed'; detail: string }

// The rendered report carries BOTH language editions with an in-document switch.
export interface NetworkReportDoc { html: string; markdown: string; title: string; lang: string; languages: string[] }
// One normalised indicator from a capture. Confidence follows provenance: what a
// detector flagged is actionable, what was merely observed is not.
export interface NetIOC { type: string; value: string; context?: string; confidence?: string }

export interface NetFlow { src: string; sport: number; dst: string; dport: number; proto: string; app: string; bytes: number; to_server?: number; to_client?: number; pkts?: number; start?: string; end?: string; state: string }
export interface NetAlert { signature: string; category: string; severity: number; sid: number; src: string; dst: string; dport: number; proto: string }
export interface NetDNS { query: string; type: string; src: string; rcode?: string; answers?: string[] }
export interface NetTLS { sni: string; ja3: string; ja3s: string; subject: string; issuer: string; version: string; dst: string }
export interface NetHTTP { host: string; url: string; method: string; ua: string; status: number; dst: string }
export interface NetFile { filename: string; magic: string; size: number; sha256: string; md5: string; src: string; dst: string; yara?: string[]; decrypted?: boolean }
export interface NetFronting { sni: string; host: string; src: string; dst: string }
export interface NetGraphNode { id: string; kind: string }
export interface NetGraphEdge { src: string; dst: string; proto: string; bytes: number; flows: number; ports: string[] }
export interface NetProtoStat { name: string; level: number; frames: number; bytes: number }
export interface NetConversation { a: string; b: string; a_internal: boolean; first_seen?: string; last_seen?: string; count: number; bytes: number; protos?: string[]; ports?: string[] }
export interface NetTimelineBucket { t: number; packets: number; bytes: number; flows: number }
export interface NetTimeline { start_ts: string; duration_sec: number; bucket_sec: number; buckets: NetTimelineBucket[] }
export interface NetGeo { asn: string; cc: string; org: string }
export interface NetZeekNotice { note: string; msg: string; sub: string; src: string; dst: string }
export interface NetZeekFile { tx: string; rx: string; source: string; mime: string; filename: string; sha256: string; md5: string; bytes: number }
export interface NetZeekSSL { server_name: string; version: string; ja3: string; ja3s: string; subject: string; issuer: string; validation: string; dst: string }
export interface NetZeekAuth { client: string; service: string; success: boolean | null; src: string; dst: string }
export interface NetZeekNTLM { user: string; host: string; domain: string; src: string; dst: string }
export interface NetZeekSMB { action: string; path: string; name: string; src: string; dst: string }
export interface NetZeekSSH { success: boolean | null; client: string; server: string; src: string; dst: string }
export interface NetZeek {
  notices?: NetZeekNotice[]
  files?: NetZeekFile[]
  ssl?: NetZeekSSL[]
  kerberos?: NetZeekAuth[]
  ntlm?: NetZeekNTLM[]
  smb?: NetZeekSMB[]
  ssh?: NetZeekSSH[]
}
export interface NetworkResult {
  stats: Record<string, number>
  flows?: NetFlow[]
  alerts?: NetAlert[]
  dns?: NetDNS[]
  tls?: NetTLS[]
  http?: NetHTTP[]
  files?: NetFile[]
  protocols?: NetProtoStat[]
  conversations?: NetConversation[]
  timeline?: NetTimeline
  zeek?: NetZeek
  geo?: Record<string, NetGeo>
  decrypted_http?: NetHTTP[]
  domain_fronting?: NetFronting[]
  graph?: { nodes: NetGraphNode[]; edges: NetGraphEdge[] }
  iocs?: { ips: string[]; domains: string[] }
  max_severity?: number
}
export interface NetworkFinding { severity: string; category: string; title: string; detail: string; source: string; indicator?: string }

export interface NetScoreSignal { source: string; detail: string; impact: string; weight?: number }
export interface NetVerdict {
  verdict: string
  confidence: number
  family?: string
  threat_score: number
  attck_techniques?: string[]
  behavior_summary: string
  key_indicators?: string[]
  independent_findings?: string[]
  recommendations?: string[]
  signal_agreement?: string
  signals?: NetScoreSignal[]
}

export interface NetworkScan {
  id: string
  file_name: string
  size: number
  sha256?: string
  status: 'pending' | 'running' | 'done' | 'failed'
  error?: string
  steps: string        // JSON []NetChainStep
  result?: string      // JSON NetworkResult
  findings?: string    // JSON []NetworkFinding
  network_ai?: string  // JSON NetVerdict
  network_ai_status?: '' | 'running' | 'done' | 'failed'
  auto_summary?: string
  auto_summary_kind?: 'ai' | 'heuristic'
  verdict: string
  threat_score: number
  summary?: string
  alert_count: number
  c2_count: number
  flow_count: number
  created_at: string
  finished_at?: string
}

export interface CarvedPreview {
  name: string
  size: number
  sha256: string
  type: string
  truncated: boolean
  hex: string
  strings: string[]
  string_cap: number
}

export function nsafeParse<T>(raw?: string): T | null {
  if (!raw) return null
  try { return JSON.parse(raw) as T } catch { return null }
}

export const networkApi = {
  analyze: async (file: File, caseId?: string, keylog?: File | null): Promise<{ scan_id: string; decrypt?: boolean }> => {
    const fd = new FormData()
    fd.append('file', file)
    if (caseId) fd.append('case_id', caseId)
    if (keylog) fd.append('keylog', keylog)
    const { data } = await apiClient.post<ApiResponse<{ scan_id: string; decrypt?: boolean }>>('/network/analyze', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },
  list: async (): Promise<NetworkScan[]> => {
    const { data } = await apiClient.get<ApiResponse<NetworkScan[]>>('/network')
    return data.data
  },
  get: async (id: string): Promise<NetworkScan> => {
    const { data } = await apiClient.get<ApiResponse<NetworkScan>>(`/network/${id}`)
    return data.data
  },
  aiAnalyze: async (id: string, providerId?: string): Promise<{ status: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ status: string }>>(`/network/${id}/ai-analyze`, { provider_id: providerId || '' })
    return data.data
  },
  previewFile: async (id: string, sha: string): Promise<CarvedPreview> => {
    const { data } = await apiClient.get<ApiResponse<CarvedPreview>>(`/network/${id}/files/${sha}/preview`)
    return data.data
  },
  downloadFile: async (id: string, sha: string, name: string): Promise<void> => {
    const res = await apiClient.get(`/network/${id}/files/${sha}/download`, { responseType: 'blob' })
    const url = window.URL.createObjectURL(res.data as Blob)
    const a = document.createElement('a')
    a.href = url; a.download = name || `${sha.slice(0, 12)}.bin`
    document.body.appendChild(a); a.click(); a.remove()
    window.URL.revokeObjectURL(url)
  },
  analyzeInMalware: async (id: string, sha: string): Promise<{ malware_scan_id: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ malware_scan_id: string }>>(`/network/${id}/files/${sha}/analyze-malware`)
    return data.data
  },
  // Quick review: open the rendered report in a new tab. The document carries
  // both language editions with an in-page switch, so no language is chosen here.
  openReport: async (id: string): Promise<void> => {
    const res = await apiClient.get(`/network/${id}/report`, { responseType: 'blob' })
    const url = window.URL.createObjectURL(res.data as Blob)
    const win = window.open(url, '_blank')
    if (!win) {
      window.URL.revokeObjectURL(url)
      throw new Error('Pop-up blocked — allow pop-ups for this site to open the report')
    }
    setTimeout(() => window.URL.revokeObjectURL(url), 60_000)
  },
  // The same document as JSON, for the preview dialog.
  report: async (id: string, opts: { lang?: string; tlp?: string; case_ref?: string } = {}): Promise<NetworkReportDoc> => {
    const { data } = await apiClient.get<ApiResponse<NetworkReportDoc>>(`/network/${id}/report`, {
      params: { ...opts, format: 'json' },
    })
    return data.data
  },
  // Download the report (html | md) with the server's filename.
  reportDownload: async (id: string, format: 'html' | 'md', opts: { lang?: string; tlp?: string; case_ref?: string } = {}): Promise<{ blob: Blob; filename: string }> => {
    const res = await apiClient.get(`/network/${id}/report`, {
      params: { ...opts, download: format },
      responseType: 'blob',
    })
    const disp = String(res.headers['content-disposition'] ?? '')
    const m = /filename="?([^"]+)"?/.exec(disp)
    return { blob: res.data as Blob, filename: m?.[1] ?? `${id}-report.${format}` }
  },
  // Normalised indicators for this capture (block list / hunt input).
  iocs: async (id: string): Promise<NetIOC[]> => {
    const { data } = await apiClient.get<ApiResponse<NetIOC[]>>(`/network/${id}/iocs`)
    return data.data
  },
  iocsDownload: async (id: string, format: 'csv' | 'suricata'): Promise<{ blob: Blob; filename: string }> => {
    const res = await apiClient.get(`/network/${id}/iocs`, { params: { format }, responseType: 'blob' })
    const disp = String(res.headers['content-disposition'] ?? '')
    const m = /filename="?([^"]+)"?/.exec(disp)
    return { blob: res.data as Blob, filename: m?.[1] ?? `${id}-iocs.${format === 'csv' ? 'csv' : 'rules'}` }
  },
  remove: async (id: string): Promise<void> => { await apiClient.delete(`/network/${id}`) },
  config: async (): Promise<{ available: boolean; rules: number }> => {
    const { data } = await apiClient.get<ApiResponse<{ available: boolean; rules: number }>>('/network/config')
    return data.data
  },

  // ── Operator Suricata rulesets + retro-hunt ────────────────────────────────
  // Intel arrives after the traffic does: a rule added today has to be replayed
  // over the captures already stored, or it only ever describes future traffic.
  rulesList: async (): Promise<SuricataInventory> => {
    const { data } = await apiClient.get<ApiResponse<SuricataInventory>>('/network/rules')
    return data.data
  },
  ruleGet: async (id: number): Promise<SuricataRuleset> => {
    const { data } = await apiClient.get<ApiResponse<SuricataRuleset>>(`/network/rules/${id}`)
    return data.data
  },
  ruleCreate: async (body: { name?: string; content?: string; file?: File }): Promise<SuricataCreated> => {
    if (body.file) {
      const fd = new FormData()
      fd.append('file', body.file)
      if (body.name) fd.append('name', body.name)
      const { data } = await apiClient.post<ApiResponse<SuricataCreated>>('/network/rules', fd, {
        headers: { 'Content-Type': 'multipart/form-data' },
      })
      return data.data
    }
    const { data } = await apiClient.post<ApiResponse<SuricataCreated>>('/network/rules',
      { name: body.name, content: body.content })
    return data.data
  },
  ruleUpdate: async (id: number, body: { enabled?: boolean; content?: string; name?: string }): Promise<void> => {
    await apiClient.put(`/network/rules/${id}`, body)
  },
  ruleDelete: async (id: number): Promise<void> => { await apiClient.delete(`/network/rules/${id}`) },
  ruleRetroHunt: async (id: number, limit?: number): Promise<RetroHuntResult> => {
    const { data } = await apiClient.post<ApiResponse<RetroHuntResult>>(
      `/network/rules/${id}/retrohunt${limit ? `?limit=${limit}` : ''}`)
    return data.data
  },
  // Stored samples related to this capture (file carried over the wire, or a
  // shared C2 address).
  malwareMatches: async (id: string): Promise<{ matches: NetCorrelationHit[]; hashes_seen: number; hosts_seen: number }> => {
    const { data } = await apiClient.get<ApiResponse<{ matches: NetCorrelationHit[]; hashes_seen: number; hosts_seen: number }>>(
      `/network/${id}/malware-matches`)
    return data.data
  },
}

// SuricataRuleset is an operator-managed detection ruleset for captures.
export interface SuricataRuleset {
  id: number
  name: string
  content?: string
  enabled: boolean
  validated: boolean
  sid_list?: string[]
  msg_list?: string[]
  size?: number
  note?: string
  source?: string
  created_at: string
  hunted_at?: string
}

export interface SuricataInventory {
  rulesets: SuricataRuleset[]
  replayable: number      // captures whose pcap is still on disk
  analyzer_enabled: boolean
}

export interface SuricataCreated {
  id: number
  sids: string[]
  msgs: string[]
  validated: boolean
  retrohunt_targets?: number
}

export interface RetroMatch {
  scan_id: string
  file_name: string
  alerts: number
  signatures: string[]
}

export interface RetroHuntResult {
  scanned: number
  matches: RetroMatch[]
  match_count: number
}

export interface NetCorrelationHit {
  id: string
  name: string
  verdict?: string
  when?: string
  indicators: string[]
  via: string
}
