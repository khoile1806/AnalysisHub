import apiClient from './client'
import { useAuthStore } from '@/store/auth'

export type FindingStatus = 'compliant' | 'non_compliant' | 'partial' | 'na'
export type FindingSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type RemediationStatus = 'open' | 'in_progress' | 'resolved' | 'accepted_risk'

export interface ComplianceFinding {
  id: string
  case_id: string
  item_id: string
  control: string
  frameworks: string // comma-joined
  title: string
  host?: string
  status: FindingStatus
  severity: FindingSeverity
  rationale: string
  remediation: string
  evidence: string
  evidence_hash?: string
  owner?: string
  due_date?: string | null
  remediation_status: RemediationStatus
  source: 'ai' | 'manual'
  created_at: string
  updated_at: string
}

export interface ComplianceSnapshot {
  id: string
  case_id: string
  total: number
  pass: number
  fail: number
  partial: number
  na: number
  score: number
  created_at: string
}

// One check sent for AI assessment.
export interface AssessItem {
  item_id: string
  control: string
  frameworks: string[]
  title: string
  purpose: string
  output: string
  host?: string
}

interface ApiResponse<T> { success: boolean; data: T }

export const complianceApi = {
  assess: async (
    caseId: string, providerId: string, items: AssessItem[], replace = true,
  ): Promise<{ assessed: number; note?: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ assessed: number; note?: string }>>(
      `/cases/${caseId}/compliance/assess`, { provider_id: providerId, items, replace },
    )
    return data.data
  },

  listFindings: async (caseId: string): Promise<ComplianceFinding[]> => {
    const { data } = await apiClient.get<ApiResponse<ComplianceFinding[]>>(`/cases/${caseId}/compliance/findings`)
    return data.data
  },

  updateFinding: async (
    id: string,
    payload: {
      status?: FindingStatus; severity?: FindingSeverity; remediation?: string
      owner?: string; due_date?: string; remediation_status?: RemediationStatus
    },
  ): Promise<ComplianceFinding> => {
    const { data } = await apiClient.patch<ApiResponse<ComplianceFinding>>(`/compliance/findings/${id}`, payload)
    return data.data
  },

  listSnapshots: async (caseId: string): Promise<ComplianceSnapshot[]> => {
    const { data } = await apiClient.get<ApiResponse<ComplianceSnapshot[]>>(`/cases/${caseId}/compliance/snapshots`)
    return data.data
  },

  clearFindings: async (caseId: string): Promise<void> => {
    await apiClient.delete(`/cases/${caseId}/compliance/findings`)
  },

  // Trigger a report download (HTML) using the auth token.
  downloadReport: async (caseId: string): Promise<void> => {
    const token = useAuthStore.getState().token
    const baseURL = apiClient.defaults.baseURL ?? ''
    const res = await fetch(`${baseURL}/cases/${caseId}/compliance/report`, {
      headers: token ? { Authorization: `Bearer ${token}` } : {},
    })
    if (!res.ok) throw new Error(await res.text() || `Server ${res.status}`)
    const disposition = res.headers.get('Content-Disposition') ?? ''
    const match = disposition.match(/filename="?([^";\n]+)"?/)
    const filename = match ? match[1] : `compliance-report-${Date.now()}.html`
    const blob = await res.blob()
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = filename
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  },
}
