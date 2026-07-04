import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export type OsintTargetType = 'ip' | 'domain' | 'email' | 'phone' | 'username' | 'hash' | 'wallet' | 'name' | 'social_profile'
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
  // scope_override optionally tightens the admin scope policy for this one scan
  // (all | passive_only | block). May only make the scan MORE restrictive.
  scope_override?: ScopeMode
}

export type ScopeMode = 'all' | 'passive_only' | 'block'

// ScopeDecision is what the admin scope policy resolved for a target: which
// collectors may run and why. Surfaced on the launch form before the scan starts.
export interface ScopeDecision {
  mode: ScopeMode
  allowed_collectors: string[]
  blocked_collectors: string[]
  require_proxy: boolean
  anonymized: boolean          // current OSINT egress state
  scope: 'internal' | 'external'
  enforced: boolean            // false when the master switch is off
  matched_rule: string
  reason: string
}

export interface DetectResult {
  target_type: OsintTargetType
  collectors: string[]
  // Collectors that will be skipped because their optional API key is unset.
  skipped_no_key?: string[]
  // Admin scope-policy decision for this target (null when unavailable).
  policy?: ScopeDecision | null
  // Whether the operator may tighten the decision at launch (policy-permitting).
  allow_override?: boolean
}

// ── OSINT scope policy (admin) ─────────────────────────────────────────────
export interface OsintScopeRule {
  id: number
  priority: number
  name: string
  enabled: boolean
  match_target_type: string
  match_scope: string
  match_egress: string
  action: ScopeMode
  require_proxy: boolean
  created_at?: string
  updated_at?: string
}

export interface OsintScopeSettings {
  id: number
  enforce: boolean
  allow_override: boolean
  internal_domains: string
  updated_at?: string
}

export type OsintScopeRulePayload = Omit<OsintScopeRule, 'id' | 'created_at' | 'updated_at'>

export const osintPolicyApi = {
  listRules: async (): Promise<OsintScopeRule[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintScopeRule[]>>('/osint/policy/rules')
    return data.data
  },
  createRule: async (body: OsintScopeRulePayload): Promise<OsintScopeRule> => {
    const { data } = await apiClient.post<ApiResponse<OsintScopeRule>>('/osint/policy/rules', body)
    return data.data
  },
  updateRule: async (id: number, body: OsintScopeRulePayload): Promise<OsintScopeRule> => {
    const { data } = await apiClient.patch<ApiResponse<OsintScopeRule>>(`/osint/policy/rules/${id}`, body)
    return data.data
  },
  deleteRule: async (id: number): Promise<void> => {
    await apiClient.delete(`/osint/policy/rules/${id}`)
  },
  getSettings: async (): Promise<OsintScopeSettings> => {
    const { data } = await apiClient.get<ApiResponse<OsintScopeSettings>>('/osint/policy/settings')
    return data.data
  },
  updateSettings: async (body: Partial<Pick<OsintScopeSettings, 'enforce' | 'allow_override' | 'internal_domains'>>): Promise<OsintScopeSettings> => {
    const { data } = await apiClient.put<ApiResponse<OsintScopeSettings>>('/osint/policy/settings', body)
    return data.data
  },
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
  avatar_url?: string
  vulns?: number
  has_kev?: boolean
}

export interface OsintVulnHost {
  host: string
  count: number
  kev: boolean
  max_severity: string
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
  kind?: '' | 'avatar'
  entities: { id: string; target: string; type: OsintTargetType; avatar_url?: string }[]
}

// ImageExtraction is the result of OCR + IOC extraction on an uploaded image:
// the OCR transcript plus validated, scannable OSINT target candidates.
export interface ImageExtraction {
  ocr_text: string
  candidates: { value: string; type: OsintTargetType }[]
}

// A single located observation about the target.
export interface GeoPoint {
  lat: number
  lon: number
  place?: string
  precision: 'exact' | 'city' | 'region' | 'country'
  source: 'exif' | 'geoip' | 'phone' | 'whois' | 'profile'
  confidence: 'high' | 'medium' | 'low'
  target?: string
  source_url?: string
}

// OsintLocation is the aggregated location intel for an investigation graph.
export interface OsintLocation {
  found: boolean
  count: number
  points: GeoPoint[]
  best?: GeoPoint
  maps_url?: string
}

// ImageGeoResult is the native EXIF-GPS extraction outcome for one photo.
export interface ImageGeoResult {
  found: boolean
  lat?: number
  lon?: number
  maps_url?: string
  precision?: 'exact'
  source?: 'exif'
  note?: string
}

// EmailCandidate is one generated address + its MX validation verdict.
export interface EmailCandidate {
  email: string
  pattern: string
  status: 'deliverable' | 'rejected' | 'catch_all' | 'unverified'
  confidence: 'high' | 'medium' | 'low'
  note?: string
}
export interface EmailPermuteResult {
  domain: string
  candidates: EmailCandidate[]
}

// DocMetaResult is the author/tool metadata recovered from a document.
export interface DocMetaResult {
  metadata: {
    format: string
    creator?: string
    last_modified_by?: string
    company?: string
    application?: string
    title?: string
    created?: string
    modified?: string
    found: boolean
  }
  candidates: { value: string; type: OsintTargetType }[]
}

// ReverseImageResult — reverse/face image-search links (+ fingerprint on upload).
export interface ReverseImageResult {
  image_url?: string
  engines?: { name: string; url: string }[]      // URL-prefill engines
  face_engines?: { name: string; url: string }[] // face search (manual upload)
  fingerprint?: string                            // dHash of an uploaded image
  note?: string
}

// IdentityConfidence scores how strongly the graph corroborates one identity.
export interface IdentitySignal { key: string; label: string; weight: number; detail?: string }
export interface IdentityConfidence {
  score: number
  grade: 'strong' | 'moderate' | 'weak' | 'minimal'
  signals: IdentitySignal[]
  summary: string
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
  exposure:     'Public Exposure (Code / Paste)',
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
  leakcheck:         'LeakCheck (breaches)',
  phone_meta:        'Phone Metadata',
  numverify:         'NumVerify',
  social_search:     'Social Media Check',
  search_links:      'Search Pivots',
  maigret:           'Maigret (3000+ sites)',
  github_intel:      'GitHub Identity Leak',
  keybase:           'Keybase (proven linked accounts)',
  username_variants: 'Handle Variants',
  social_profile:    'Social Profile Enrichment',
  passive_dns:       'Passive DNS (history)',
  wallet_label:      'Wallet Labeling / Abuse',
  codeleak:          'Public-Code Secret Exposure',
  paste:             'Paste-Site Monitoring',
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
  favicon:           'Favicon Hash Pivot (Shodan)',
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

  // vulnFindings returns per-host vulnerability roll-ups across the investigation
  // (powers the "vulns: N / KEV" badges on discovered hosts + graph nodes).
  vulnFindings: async (id: string): Promise<OsintVulnHost[]> => {
    const { data } = await apiClient.get<ApiResponse<OsintVulnHost[]>>(`/osint/${id}/vuln-findings`)
    return data.data
  },

  // location aggregates every located finding across the graph (IP geo, EXIF GPS,
  // phone region) into the single best coordinate estimate + all points for a map.
  location: async (id: string): Promise<OsintLocation> => {
    const { data } = await apiClient.get<ApiResponse<OsintLocation>>(`/osint/${id}/location`)
    return data.data
  },

  // addScanPhotoGeo reads a photo's EXIF GPS and, if present, saves it as an
  // exact location finding ON the scan (appears on the map). Image not stored.
  addScanPhotoGeo: async (scanId: string, file: File): Promise<ImageGeoResult> => {
    const fd = new FormData()
    fd.append('image', file)
    const { data } = await apiClient.post<ApiResponse<ImageGeoResult>>(`/osint/${scanId}/add-photo-geo`, fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  // extractImageGeo reads a photo's EXIF GPS tags (exact coordinates) natively —
  // no AI provider required. Returns { found:false } when EXIF was stripped.
  extractImageGeo: async (file: File): Promise<ImageGeoResult> => {
    const fd = new FormData()
    fd.append('image', file)
    const { data } = await apiClient.post<ApiResponse<ImageGeoResult>>('/osint/extract-image-geo', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  // emailPermute generates corporate e-mail patterns for a name@domain and
  // validates each via MX + catch-all detection.
  emailPermute: async (name: string, domain: string, validate = true): Promise<EmailPermuteResult> => {
    const { data } = await apiClient.post<ApiResponse<EmailPermuteResult>>('/osint/email-permute', { name, domain, validate })
    return data.data
  },

  // extractDocMeta recovers author/tool metadata from a DOCX/XLSX/PPTX/PDF.
  extractDocMeta: async (file: File): Promise<DocMetaResult> => {
    const fd = new FormData()
    fd.append('file', file)
    const { data } = await apiClient.post<ApiResponse<DocMetaResult>>('/osint/extract-doc-meta', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
    return data.data
  },

  // identity scores how strongly the graph corroborates one identity.
  identity: async (id: string): Promise<IdentityConfidence> => {
    const { data } = await apiClient.get<ApiResponse<IdentityConfidence>>(`/osint/${id}/identity`)
    return data.data
  },

  // reverseImage builds reverse-image-search deep-links for a public image URL
  // (URL-prefill engines + face-search engines).
  reverseImage: async (imageURL: string): Promise<ReverseImageResult> => {
    const { data } = await apiClient.post<ApiResponse<ReverseImageResult>>('/osint/reverse-image', { image_url: imageURL })
    return data.data
  },

  // reverseImageUpload fingerprints a local image and returns face-search engines
  // to upload it into (no public re-hosting of the file).
  reverseImageUpload: async (file: File): Promise<ReverseImageResult> => {
    const fd = new FormData()
    fd.append('image', file)
    const { data } = await apiClient.post<ApiResponse<ReverseImageResult>>('/osint/reverse-image', fd, {
      headers: { 'Content-Type': 'multipart/form-data' },
    })
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
