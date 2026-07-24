import apiClient from './client'

export type TimelineSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'
// "edge:*" sources are produced by the super-timeline builder (e.g. "edge:mft").
type TimelineSource = 'manual' | 'elk' | 'ai' | 'job' | 'import' | string

// One raw EdgeForensics artifact result block fed to the super-timeline builder.
export interface SuperArtifactSource {
  type: 'mft' | 'prefetch' | 'shimcache' | 'processes' | 'evtx'
  data: unknown // raw JSON returned by the agent EdgeForensics endpoint
}

export interface SuperTimelineSummary {
  total: number
  by_source: Record<string, number>
  by_severity: Record<string, number>
  hosts: string[]
  first_event?: string | null
  last_event?: string | null
}

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

// ─── ATT&CK coverage matrix ─────────────────────────────────────────────────
export interface AttackTechnique {
  id: string // e.g. "T1059" or "(unspecified)"
  count: number
  severity: TimelineSeverity
  sample_titles: string[]
  last_seen?: string
}

export interface AttackTacticColumn {
  id: string // normalized, e.g. "execution" | "unmapped"
  name: string // display, e.g. "Execution"
  event_count: number
  techniques: AttackTechnique[]
}

export interface AttackCoverage {
  summary: {
    total_events: number
    mapped_events: number
    techniques: number
    tactics: number
  }
  tactics: AttackTacticColumn[]
}

export const timelineApi = {
  list: async (caseId: string): Promise<TimelineEvent[]> => {
    const { data } = await apiClient.get<ApiResponse<TimelineEvent[]>>(`/cases/${caseId}/timeline`)
    return data.data
  },

  // Merged timeline + aggregates (counts by source/severity, hosts, time span).
  super: async (caseId: string): Promise<{ events: TimelineEvent[]; summary: SuperTimelineSummary }> => {
    const { data } = await apiClient.get<ApiResponse<{ events: TimelineEvent[]; summary: SuperTimelineSummary }>>(
      `/cases/${caseId}/timeline/super`,
    )
    return data.data
  },

  // Explode raw EdgeForensics artifacts (MFT/Prefetch/Shimcache/processes/EVTX)
  // into one chronological timeline in a single call.
  buildSuper: async (
    caseId: string,
    payload: { host?: string; only_suspicious?: boolean; sources: SuperArtifactSource[] },
  ): Promise<{ events_created: number; skipped: number; per_source: Record<string, number> }> => {
    const { data } = await apiClient.post<
      ApiResponse<{ events_created: number; skipped: number; per_source: Record<string, number> }>
    >(`/cases/${caseId}/timeline/build-super`, payload)
    return data.data
  },

  // ATT&CK coverage aggregated from the case's timeline events.
  attackCoverage: async (caseId: string): Promise<AttackCoverage> => {
    const { data } = await apiClient.get<ApiResponse<AttackCoverage>>(`/cases/${caseId}/attack-coverage`)
    return data.data
  },

  // Batch-import scan artifacts (e.g. Edge Forensics findings) onto a case
  // timeline, optionally promoting each to the IOC store.
  importArtifacts: async (
    caseId: string,
    payload: {
      source: string
      host?: string
      items: Array<{
        title: string
        detail?: string
        event_time?: string
        severity?: TimelineSeverity
        // ATT&CK mapping, when the source already knows it (Sigma rule tags).
        // Without it the case's attack-coverage view cannot see the finding.
        technique?: string
        tactic?: string
        value?: string
        ioc_type?: string
        promote_ioc?: boolean
      }>
    },
  ): Promise<{ events_created: number; iocs_promoted: number }> => {
    const { data } = await apiClient.post<ApiResponse<{ events_created: number; iocs_promoted: number }>>(
      `/cases/${caseId}/import-artifacts`, payload,
    )
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
