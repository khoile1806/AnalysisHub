import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export type OsintTargetType = 'ip' | 'domain' | 'email' | 'phone' | 'username' | 'hash' | 'wallet' | 'name'
type OsintStatus = 'pending' | 'running' | 'done' | 'stopped' | 'failed'
type OsintCollectorStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped'
type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'

export interface OsintCollector {
  id: string
  scan_id: string
  name: string
  status: OsintCollectorStatus
  findings_count: number
  error?: string
  started_at: string | null
  finished_at: string | null
}

export interface OsintScan {
  id: string
  name: string
  target: string
  target_type: OsintTargetType
  status: OsintStatus
  case_id?: string | null
  exposure_score?: number
  exposure_grade?: 'minimal' | 'low' | 'elevated' | 'high' | 'critical' | ''
  created_by: string
  created_at: string
  updated_at: string
  finished_at: string | null
  collectors?: OsintCollector[]
}

// Continuous-monitoring watch (A4).
export interface OsintWatch {
  id: string
  name: string
  target: string
  target_type: OsintTargetType
  interval_minutes: number
  auto_pivot: boolean
  max_depth: number
  case_id?: string | null
  enabled: boolean
  last_scan_id?: string | null
  last_run_at: string | null
  next_run_at: string | null
  alert_count: number
  created_at: string
}

export interface OsintWatchAlert {
  id: string
  watch_id: string
  scan_id: string
  category: string
  source: string
  title: string
  value: string
  severity: string
  confidence?: string
  seen: boolean
  created_at: string
}

export interface CreateWatchData {
  name?: string
  target: string
  interval_minutes?: number
  auto_pivot?: boolean
  max_depth?: number
  case_id?: string
}

// RelatedEntity is a pivot — an identifier discovered while investigating the
// target that the operator can launch a fresh investigation against.
export interface RelatedEntity {
  type: OsintTargetType
  value: string
}

export interface OsintFinding {
  id: string
  scan_id: string
  collector_id: string
  source: string
  category: string
  title: string
  value: string
  data?: string
  source_url?: string // link to where the trace was discovered (e.g. breach search)
  severity?: Severity
  confidence?: 'verified' | 'likely' | 'unverified' | ''
  verify_note?: string
  related_entities?: string // JSON array of RelatedEntity
  created_at: string
}

export interface CreateOsintScanData {
  name?: string
  target: string
  auto_pivot?: boolean  // recursively investigate discovered entities
  max_depth?: number    // pivot depth limit (default 2)
  case_id?: string      // optional: file this investigation under a DFIR case
}

export interface DetectResult {
  target_type: OsintTargetType
  collectors: string[]
  // Collectors that will be skipped because their optional API key is unset.
  skipped_no_key?: string[]
}

// Investigation graph (auto-pivot): nodes are scans, edges are pivot links.
export interface OsintGraphNode {
  id: string
  target: string
  type: OsintTargetType
  status: OsintStatus
  depth: number
  findings: number
  root: boolean
}
interface OsintGraphEdge {
  from: string
  to: string
  label: string
}
export interface OsintGraph {
  root: string
  nodes: OsintGraphNode[]
  edges: OsintGraphEdge[]
}

// Correlation: an indicator value that links 2+ investigated entities.
export interface OsintCorrelation {
  value: string
  count: number
  entities: { id: string; target: string; type: OsintTargetType }[]
}

// ImageExtraction is the result of OCR + IOC extraction on an uploaded image:
// the OCR transcript plus validated, scannable OSINT target candidates.
export interface ImageExtraction {
  ocr_text: string
  candidates: { value: string; type: OsintTargetType }[]
}

// CATEGORY_LABELS maps a finding category to its display heading.
export const CATEGORY_LABELS: Record<string, string> = {
  registration: 'Registration / WHOIS',
  dns:          'DNS Records',
  certificate:  'Certificate Transparency',
  historical:   'Historical (Web Archive)',
  geolocation:  'Geolocation',
  network:      'Network / ASN',
  ports:        'Exposed Services',
  techstack:    'Technology Stack',
  vulnerability: 'Known Vulnerabilities (CVE)',
  cloud_exposure: 'Cloud Storage Exposure',
  reputation:   'Reputation / Threat Intel',
  ransomware:   'Ransomware Leak-Site',
  darkweb:      'Dark-Web Exposure',
  breach:       'Breach Exposure',
  identity:     'Identity',
  social:       'Social Media Presence',
  search:       'Search Pivots',
}

// COLLECTOR_LABELS gives each collector a friendly name for the UI.
export const COLLECTOR_LABELS: Record<string, string> = {
  rdap:              'RDAP / WHOIS',
  dns:               'DNS Records',
  crtsh:             'Certificate Transparency',
  wayback:           'Wayback Machine',
  virustotal:        'VirusTotal',
  reverse_dns:       'Reverse DNS',
  geoip:             'Geolocation',
  shodan_internetdb: 'Shodan InternetDB',
  shodan:            'Shodan',
  abuseipdb:         'AbuseIPDB',
  email_validate:    'Email Validation',
  gravatar:          'Gravatar',
  email_social:      'Email → Social Accounts',
  hibp:              'Have I Been Pwned',
  xposed:            'XposedOrNot Breaches',
  phone_meta:        'Phone Metadata',
  numverify:         'NumVerify',
  social_search:     'Social Media Check',
  search_links:      'Search Pivots',
  maigret:           'Maigret (3000+ sites)',
  github_intel:      'GitHub Identity Leak',
  breach_leak:       'Breach / Paste Leak',
  stealer_intel:     'Info-Stealer Exposure',
  exposure_search:   'Brand Exposure Search',
  threatintel:       'Threat-Intel Consensus',
  threatfox:         'ThreatFox (abuse.ch)',
  urlhaus:           'URLhaus (abuse.ch)',
  malwarebazaar:     'MalwareBazaar (abuse.ch)',
  pulsedive:         'Pulsedive Risk',
  greynoise:         'GreyNoise Context',
  ransomwatch:       'Ransomware Leak-Site Watch',
  urlscan:           'URLScan (brand abuse / phishing)',
  darkweb:           'Dark-Web Monitoring',
  reverse_ip:        'Reverse IP (co-hosted)',
  host_search:       'Subdomain Search',
  subbrute:          'Subdomain Brute-force (DNS)',
  typosquat:         'Look-alike / Typosquat Domains',
  cloud:             'Cloud Storage Exposure (S3/GCS/Azure)',
  hashlookup:        'CIRCL Hashlookup (NSRL)',
  webtech:           'Tech-Stack Fingerprint + CVE',
  portscan:          'Active Port / Service Scan + CVE',
  blockchain:        'Blockchain Explorer',
  opencti:           'OpenCTI / IOC Store',
  local_intel:       'Local Threat-Intel Store',
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const osintApi = {
  list: async (): Promise<OsintScan[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintScan[]>>('/osint')
    return data.data
  },

  create: async (payload: CreateOsintScanData): Promise<OsintScan> => {
    const { data } = await apiClient.post<ApiResponse<OsintScan>>('/osint', payload)
    return data.data
  },

  get: async (id: string): Promise<OsintScan> => {
    const { data } = await apiClient.get<ApiResponse<OsintScan>>(`/osint/${id}`)
    return data.data
  },

  stop: async (id: string): Promise<void> => {
    await apiClient.post(`/osint/${id}/stop`)
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/osint/${id}`)
  },

  findings: async (id: string): Promise<OsintFinding[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintFinding[]>>(`/osint/${id}/findings`)
    return data.data
  },

  detect: async (target: string): Promise<DetectResult> => {
    const { data } = await apiClient.post<ApiResponse<DetectResult>>('/osint/detect', { target })
    return data.data
  },

  // promoteIOC adds an OSINT-discovered indicator to the IOC store so the ELK
  // auto-hunt and other defensive tooling can act on it. Only ip/domain/email/
  // hash are promotable. created=false means it was already in the store.
  promoteIOC: async (value: string, type: OsintTargetType, description?: string): Promise<{ created: boolean }> => {
    const { data } = await apiClient.post<ApiResponse<{ created: boolean }>>('/osint/promote-ioc', { value, type, description })
    return data.data
  },

  // triage asks AI to summarize the scan's findings from a defensive angle.
  triage: async (id: string, providerId: string): Promise<{ summary: string; tokens: number }> => {
    const { data } = await apiClient.post<ApiResponse<{ summary: string; tokens: number }>>(`/osint/${id}/triage`, { provider_id: providerId })
    return data.data
  },

  // graph returns the investigation graph (nodes + auto-pivot edges).
  graph: async (id: string): Promise<OsintGraph> => {
    const { data } = await apiClient.get<ApiResponse<OsintGraph>>(`/osint/${id}/graph`)
    return data.data
  },

  // correlations returns shared indicators that link 2+ entities in the graph.
  correlations: async (id: string): Promise<OsintCorrelation[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintCorrelation[]>>(`/osint/${id}/correlations`)
    return data.data
  },

  streamUrl: (id: string): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/osint/${id}/stream?token=${encodeURIComponent(token)}`
  },

  reportUrl: (id: string): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/osint/${id}/report?token=${encodeURIComponent(token)}`
  },

  // exportUrl builds a download link for the machine-readable export of a scan's
  // indicators: STIX 2.1 bundle (default), CSV, or JSON, for TIP/MISP hand-off.
  exportUrl: (id: string, format: 'stix' | 'csv' | 'json' = 'stix'): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/osint/${id}/export?format=${format}&token=${encodeURIComponent(token)}`
  },

  // graphExportUrl builds a download link for the whole investigation graph as
  // GraphML, importable into Maltego / Gephi / yEd / Cytoscape for link analysis.
  graphExportUrl: (id: string): string => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token ?? ''
    return `${base}/api/v1/osint/${id}/graph/export?format=graphml&token=${encodeURIComponent(token)}`
  },

  // extractImage runs OCR + IOC extraction on an uploaded image (ransom note,
  // phishing screenshot) via a Claude vision provider and returns scannable
  // candidates the analyst can launch footprinting scans against.
  extractImage: async (file: File, providerId: string): Promise<ImageExtraction> => {
    const form = new FormData()
    form.append('image', file)
    form.append('provider_id', providerId)
    const { data } = await apiClient.post<ApiResponse<ImageExtraction>>('/osint/extract-image', form, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  // ── Watchlist (A4 continuous monitoring) ──────────────────────────────────
  watches: async (): Promise<OsintWatch[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintWatch[]>>('/osint/watches')
    return data.data
  },
  createWatch: async (payload: CreateWatchData): Promise<OsintWatch> => {
    const { data } = await apiClient.post<ApiResponse<OsintWatch>>('/osint/watches', payload)
    return data.data
  },
  updateWatch: async (id: string, payload: Partial<{ name: string; enabled: boolean; interval_minutes: number }>): Promise<OsintWatch> => {
    const { data } = await apiClient.patch<ApiResponse<OsintWatch>>(`/osint/watches/${id}`, payload)
    return data.data
  },
  deleteWatch: async (id: string): Promise<void> => {
    await apiClient.delete(`/osint/watches/${id}`)
  },
  runWatch: async (id: string): Promise<void> => {
    await apiClient.post(`/osint/watches/${id}/run`)
  },
  watchAlerts: async (id: string): Promise<OsintWatchAlert[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintWatchAlert[]>>(`/osint/watches/${id}/alerts`)
    return data.data
  },
  markAlertsSeen: async (id: string): Promise<void> => {
    await apiClient.post(`/osint/watches/${id}/alerts/seen`)
  },
}

// parseRelated safely decodes the related_entities JSON of a finding.
export function parseRelated(raw?: string): RelatedEntity[] {
  if (!raw) return []
  try {
    const arr = JSON.parse(raw)
    return Array.isArray(arr) ? arr : []
  } catch {
    return []
  }
}
