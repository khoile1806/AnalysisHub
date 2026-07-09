import apiClient from './client'
import { useAuthStore } from '@/store/auth'

// Vulnerability scanner — httpx + nuclei over assets discovered by OSINT.
// Active/intrusive: create/stop/delete are admin-only on the backend.

export type VulnStatus = 'pending' | 'running' | 'done' | 'stopped' | 'failed'
export type VulnToolStatus = 'pending' | 'running' | 'done' | 'failed' | 'skipped'

export interface VulnTool {
  id: string
  scan_id: string
  name: string
  status: VulnToolStatus
  findings_count: number
  error?: string
  command?: string // exact CLI invocation the engine ran (proxy creds redacted)
  started_at?: string | null
  finished_at?: string | null
}

export interface VulnScan {
  id: string
  name: string
  status: VulnStatus
  source_scan_id?: string
  case_id?: string
  targets?: string // JSON array string
  target_count: number
  tools?: string
  severities?: string
  profile?: string
  proxy_choice?: string
  proxy_mode?: string
  summary?: string // JSON {severity: count}
  created_at: string
  finished_at?: string | null
  tool_runs?: VulnTool[]
}

export interface VulnFinding {
  id: string
  scan_id: string
  tool: string
  template_id?: string
  name: string
  severity: string
  host: string
  matched_at?: string
  type?: string
  description?: string
  reference?: string
  tags?: string
  cve_id?: string
  epss_score?: number
  is_kev?: boolean
  confirmed?: boolean
  status?: 'open' | 'confirmed' | 'false_positive' | 'fixed'
  note?: string
  data?: string // raw tool JSON line
  created_at: string
}

// priorityScore ranks a finding for triage by folding severity, known-exploited
// (KEV), exploit probability (EPSS) and independent verification into one number.
export function priorityScore(f: VulnFinding): number {
  const sevBase: Record<string, number> = { critical: 90, high: 70, medium: 45, low: 20, info: 5, unknown: 5 }
  let s = sevBase[f.severity] ?? 5
  if (f.is_kev) s += 40
  if (typeof f.epss_score === 'number') s += Math.round(f.epss_score * 30)
  if (f.confirmed) s += 10
  return s
}

export function priorityLabel(score: number): { label: string; cls: string } {
  if (score >= 110) return { label: 'critical', cls: 'bg-red-500/15 text-red-400 border-red-500/40' }
  if (score >= 75) return { label: 'high', cls: 'bg-orange-500/15 text-orange-400 border-orange-500/30' }
  if (score >= 40) return { label: 'medium', cls: 'bg-amber-500/15 text-amber-400 border-amber-500/30' }
  return { label: 'low', cls: 'bg-sky-500/15 text-sky-400 border-sky-500/30' }
}

export type AssetScope = 'in' | 'private' | 'mixed' | 'unresolved' | 'deferred'

export interface VulnAsset {
  value: string
  type: 'ip' | 'domain'
  // Scope classification from the backend (same strict policy the engine enforces
  // at scan time). `keep` is false for assets that will be excluded.
  scope?: AssetScope
  keep?: boolean
  reason?: string
}

export interface CreateVulnScanRequest {
  name?: string
  source_scan_id?: string
  targets?: string[]
  case_id?: string
  severities?: string
  profile?: 'quick' | 'full' | 'cve-only' | 'deep' | 'aggressive'
  tags?: string
  proxy_choice?: 'tor' | 'direct'
  allow_private?: boolean // allow scanning private/loopback/LAN targets (internal scan)
}

export interface AdHocNucleiRequest {
  url: string
  name?: string
  severities?: string
  exclude_severity?: string
  tags?: string
  include_tags?: string
  exclude_tags?: string
  cve_ids?: string[]
  template_ids?: string[]
  exclude_ids?: string[]
  templates?: string[]
  authors?: string
  protocols?: string
  headers?: string[]
  vars?: string[]
  rate_limit?: number
  concurrency?: number
  timeout?: number
  retries?: number
  new_templates?: boolean
  extra_args?: string[]
  proxy_choice?: 'tor' | 'direct'
  allow_private?: boolean
  dast?: boolean
}

export const vulnscanApi = {
  list: (caseId?: string) =>
    apiClient
      .get('/vulnscan', { params: caseId ? { case_id: caseId } : undefined })
      .then((r) => r.data.data as VulnScan[]),
  // listForOsint returns vuln scans launched from anywhere in an OSINT
  // investigation (its whole pivot tree) — powers the investigation's Vuln tab.
  listForOsint: (osintScanId: string) =>
    apiClient.get(`/osint/${osintScanId}/vulnscans`).then((r) => r.data.data as VulnScan[]),
  get: (id: string) => apiClient.get(`/vulnscan/${id}`).then((r) => r.data.data as VulnScan),
  findings: (id: string, params?: { severity?: string; tool?: string }) =>
    apiClient.get(`/vulnscan/${id}/findings`, { params }).then((r) => r.data.data as VulnFinding[]),
  create: (body: CreateVulnScanRequest) =>
    apiClient.post('/vulnscan', body).then((r) => r.data.data as VulnScan),
  // createAdHocNuclei runs nuclei against a single URL with custom filters (chosen
  // CVE/template ids, severities, tags) — no full pipeline.
  createAdHocNuclei: (body: AdHocNucleiRequest) =>
    apiClient.post('/vulnscan/nuclei', body).then((r) => r.data.data as VulnScan),
  // previewNuclei returns the exact nuclei command a run would execute (validated),
  // plus any requested template/CVE ids that have no matching nuclei template.
  previewNuclei: (body: AdHocNucleiRequest) =>
    apiClient.post('/vulnscan/nuclei/preview', body).then((r) => r.data.data as { command: string; args: string[]; missing_templates?: string[] }),
  updateFinding: (id: string, body: { status?: string; note?: string }) =>
    apiClient.patch(`/vuln-findings/${id}`, body).then((r) => r.data.data as VulnFinding),
  stop: (id: string) => apiClient.post(`/vulnscan/${id}/stop`).then((r) => r.data),
  remove: (id: string) => apiClient.delete(`/vulnscan/${id}`).then((r) => r.data),
  previewAssets: (osintScanId: string, allowPrivate?: boolean) =>
    apiClient
      .get('/vulnscan/preview-assets', {
        params: { osint_scan_id: osintScanId, ...(allowPrivate ? { allow_private: 'true' } : {}) },
      })
      .then((r) => r.data.data as VulnAsset[]),
  streamUrl: (id: string) => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token
    return `${base}/api/v1/vulnscan/${id}/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`
  },
  exportUrl: (id: string, params?: { severity?: string; tool?: string }) => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token
    const qs = new URLSearchParams()
    if (token) qs.set('token', token)
    if (params?.severity) qs.set('severity', params.severity)
    if (params?.tool) qs.set('tool', params.tool)
    return `${base}/api/v1/vulnscan/${id}/findings/export?${qs.toString()}`
  },
}

export const SEVERITY_ORDER = ['critical', 'high', 'medium', 'low', 'info', 'unknown']

export const SEVERITY_COLOR: Record<string, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-amber-500/15 text-amber-400 border-amber-500/30',
  low: 'bg-sky-500/15 text-sky-400 border-sky-500/30',
  info: 'bg-slate-500/15 text-slate-300 border-slate-500/30',
  unknown: 'bg-slate-500/15 text-slate-400 border-slate-500/30',
}
