import apiClient from './client'

export type TimelineSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
export type TimelineSource = 'manual' | 'elk' | 'ai' | 'job'

// An enrichment attached to a timeline node: an existing/uploaded evidence file
// (possibly an image) or an external link.
export interface TimelineAttachment {
  type: 'evidence' | 'link'
  evidence_id?: string
  url?: string
  label?: string
  is_image?: boolean
}

export interface TimelineEvent {
  id: string
  case_id: string
  event_time: string
  source: TimelineSource
  source_ref?: string
  host?: string
  tactic?: string
  technique?: string
  severity: TimelineSeverity
  title: string
  detail?: string
  attachments?: string // JSON array of TimelineAttachment
  created_by: string
  created_at: string
}

export interface CreateTimelineEvent {
  event_time: string
  host?: string
  tactic?: string
  technique?: string
  severity?: TimelineSeverity
  title: string
  detail?: string
  attachments?: string
}

export function parseAttachments(json?: string): TimelineAttachment[] {
  if (!json) return []
  try {
    const a = JSON.parse(json)
    return Array.isArray(a) ? a : []
  } catch {
    return []
  }
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

// MITRE ATT&CK tactics (enterprise) — used for the dropdown + color grouping.
export const MITRE_TACTICS = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
] as const

export const timelineApi = {
  list: async (caseId: string): Promise<TimelineEvent[]> => {
    const { data } = await apiClient.get<ApiResponse<TimelineEvent[]>>(`/cases/${caseId}/timeline`)
    return data.data
  },

  create: async (caseId: string, payload: CreateTimelineEvent): Promise<TimelineEvent> => {
    const { data } = await apiClient.post<ApiResponse<TimelineEvent>>(`/cases/${caseId}/timeline`, payload)
    return data.data
  },

  update: async (eventId: string, payload: Partial<CreateTimelineEvent>): Promise<TimelineEvent> => {
    const { data } = await apiClient.patch<ApiResponse<TimelineEvent>>(`/timeline/${eventId}`, payload)
    return data.data
  },

  remove: async (eventId: string): Promise<void> => {
    await apiClient.delete(`/timeline/${eventId}`)
  },

  // Promote an ELK hunt result's hits into a case timeline (Phase 3 step 2).
  promoteELK: async (resultId: string, caseId: string): Promise<{ imported: number }> => {
    const { data } = await apiClient.post<ApiResponse<{ imported: number }>>(
      `/elk/hunt/results/${resultId}/promote-timeline`, { case_id: caseId },
    )
    return data.data
  },

  // Ask AI to extract a structured timeline from a job's output (Phase 3 step 3).
  aiExtract: async (caseId: string, providerId: string, jobId: string): Promise<{ imported: number; note?: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ imported: number; note?: string }>>(
      `/cases/${caseId}/timeline/ai-extract`, { provider_id: providerId, job_id: jobId },
    )
    return data.data
  },

  // Ask AI to review ALL case evidence + existing events and rebuild one clean,
  // standardized timeline. mode "replace" overwrites; "append" keeps old events.
  aiRebuild: async (
    caseId: string, providerId: string, mode: 'replace' | 'append',
  ): Promise<{ imported: number; replaced: boolean; note?: string }> => {
    const { data } = await apiClient.post<ApiResponse<{ imported: number; replaced: boolean; note?: string }>>(
      `/cases/${caseId}/timeline/ai-rebuild`, { provider_id: providerId, mode },
    )
    return data.data
  },
}
