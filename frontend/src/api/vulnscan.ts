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
  created_at: string
}

export interface VulnAsset {
  value: string
  type: 'ip' | 'domain'
}

export interface CreateVulnScanRequest {
  name?: string
  source_scan_id?: string
  targets?: string[]
  case_id?: string
  severities?: string
  profile?: 'quick' | 'full' | 'cve-only'
  tags?: string
  proxy_choice?: 'tor' | 'direct'
}

export const vulnscanApi = {
  list: (caseId?: string) =>
    apiClient
      .get('/vulnscan', { params: caseId ? { case_id: caseId } : undefined })
      .then((r) => r.data.data as VulnScan[]),
  get: (id: string) => apiClient.get(`/vulnscan/${id}`).then((r) => r.data.data as VulnScan),
  findings: (id: string, params?: { severity?: string; tool?: string }) =>
    apiClient.get(`/vulnscan/${id}/findings`, { params }).then((r) => r.data.data as VulnFinding[]),
  create: (body: CreateVulnScanRequest) =>
    apiClient.post('/vulnscan', body).then((r) => r.data.data as VulnScan),
  stop: (id: string) => apiClient.post(`/vulnscan/${id}/stop`).then((r) => r.data),
  remove: (id: string) => apiClient.delete(`/vulnscan/${id}`).then((r) => r.data),
  previewAssets: (osintScanId: string) =>
    apiClient
      .get('/vulnscan/preview-assets', { params: { osint_scan_id: osintScanId } })
      .then((r) => r.data.data as VulnAsset[]),
  streamUrl: (id: string) => {
    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const token = useAuthStore.getState().token
    return `${base}/api/v1/vulnscan/${id}/stream${token ? `?token=${encodeURIComponent(token)}` : ''}`
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
