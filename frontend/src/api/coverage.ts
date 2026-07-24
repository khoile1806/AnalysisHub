import apiClient from './client'

// Detection coverage: which of the loaded Sigma rules can actually fire, given
// the telemetry the endpoints really produce. Mirrors the shapes in
// backend/internal/api/handlers/detection_coverage.go.

export type ChannelVerdict = 'covered' | 'partial' | 'missing' | 'unknown'
export type HostCoverageStatus = 'covered' | 'partial' | 'blind' | 'unknown'

export interface CoverageRuleset {
  loaded: boolean
  rules_loaded: number
  rules_unsupported: number
  files_scanned: number
  files_unreadable: number
  channels_required: number
}

export interface CoverageHeadline {
  rules_at_risk: number
  rules_unmeasured: number
  rules_reachable: number
  channel_rule_total: number
  channels_covered: number
  channels_partial: number
  channels_missing: number
  channels_unknown: number
  hosts_total: number
  hosts_swept: number
  hosts_never_swept: number
  hosts_blind: number
  coverage_percent: number
}

export interface CoverageChannel {
  log_name: string
  rules: number
  event_ids?: number[]
  in_ruleset: boolean
  hosts_reporting: number
  hosts_with_events: number
  hosts_silent: number
  hosts_failed: number
  events: number
  verdict: ChannelVerdict
  sample_error?: string
  note?: string
}

export interface CoverageHost {
  agent_id: string
  agent_name: string
  hostname?: string
  os?: string
  agent_status?: string
  status: HostCoverageStatus
  measured: boolean
  sweep_status?: string
  last_swept?: string
  coverage_percent: number
  rules_reachable: number
  rules_blocked: number
  channels_ok: string[]
  channels_silent: string[]
  channels_failed: string[]
  note?: string
}

export interface CoverageTechnique {
  technique: string
  hosts: number
  rules: number
}

export interface CoverageAttack {
  ruleset_measurable: boolean
  note: string
  techniques_observed: CoverageTechnique[]
  tactics_observed: string[]
}

export interface DetectionCoverage {
  measured_from: string
  no_data: boolean
  truncated: boolean
  ruleset: CoverageRuleset
  headline: CoverageHeadline
  channels: CoverageChannel[]
  hosts: CoverageHost[]
  attack: CoverageAttack
  notes: string[]
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const coverageApi = {
  // days: sweep lookback (1-90, default 7 server-side).
  detection: async (days?: number): Promise<DetectionCoverage> => {
    const { data } = await apiClient.get<ApiResponse<DetectionCoverage>>('/detection/coverage', {
      params: days ? { days } : undefined,
    })
    return data.data
  },
}
