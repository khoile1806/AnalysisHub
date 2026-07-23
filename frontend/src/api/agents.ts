import apiClient from './client'

export type AgentStatus = 'online' | 'offline'

export interface Agent {
  id: string
  name: string
  hostname: string
  os: string
  ip_address: string
  status: AgentStatus
  last_seen: string
  description: string
  case_id?: string
  token?: string
  created_at: string
  group_name?: string
  tags?: string // JSON array string
}

export interface BrowserEntry {
  browser: string
  profile: string
  url: string
  title?: string
  visit_count: number
  last_visit?: string
  suspicious?: string[]
}

export interface TriageArtifact {
  type: string
  count: number
  error?: string
  data?: unknown
}

export interface TriageResult {
  collected_at: string
  hostname?: string
  artifacts: TriageArtifact[]
}

export interface IOCMatch {
  indicator: string
  indicator_type: string
  artifact: string
  context: string
}

export interface IOCSweepResult {
  indicators: number
  store_matched?: number
  scanned: Record<string, number>
  matches: IOCMatch[]
}

export interface CreateAgentData {
  name: string
  description: string
  case_id?: string | null
}

export interface UpdateAgentData {
  description?: string
  case_id?: string | null  // empty string to unlink, UUID to link
}

export interface AgentInstallerConfig {
  agent_id: string
  agent_name: string
  token: string
  server_url: string
  ws_url: string
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

export const agentsApi = {
  list: async (): Promise<Agent[]> => {
    const { data } = await apiClient.get<ApiResponse<Agent[]>>('/agents')
    return data.data
  },

  create: async (payload: CreateAgentData): Promise<Agent> => {
    const { data } = await apiClient.post<ApiResponse<Agent>>('/agents', payload)
    return data.data
  },

  get: async (id: string): Promise<Agent> => {
    const { data } = await apiClient.get<ApiResponse<Agent>>(`/agents/${id}`)
    return data.data
  },

  update: async (id: string, payload: UpdateAgentData): Promise<Agent> => {
    const { data } = await apiClient.patch<ApiResponse<Agent>>(`/agents/${id}`, payload)
    return data.data
  },

  delete: async (id: string): Promise<void> => {
    await apiClient.delete(`/agents/${id}`)
  },

  getInstaller: async (id: string): Promise<AgentInstallerConfig> => {
    const { data } = await apiClient.get<ApiResponse<AgentInstallerConfig>>(`/agents/${id}/installer`)
    return data.data
  },

  cleanup: async (id: string): Promise<void> => {
    await apiClient.post(`/agents/${id}/cleanup`, {})
  },

  parseRegistry: async (id: string, root: string, path: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/registry`, { root, path }, { timeout: 600_000 })
    return data
  },

  parseEvtx: async (
    id: string,
    query: { log_name: string; event_ids?: number[]; event_id?: string; hours?: number; max?: number; keyword?: string },
  ): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/evtx`, query, { timeout: 600_000 })
    return data
  },

  parseMFT: async (id: string, path?: string): Promise<any> => {
    // Edge Forensics scans (UAC prompt + on-device walk/hash) can run well past
    // the default 120s, so give these a generous timeout.
    const { data } = await apiClient.post(`/agents/${id}/mft`, undefined, {
      params: path ? { path } : undefined,
      timeout: 600_000,
    })
    return data
  },

  parsePrefetch: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/prefetch`, undefined, { timeout: 600_000 })
    return data
  },

  // Detailed running-process snapshot (lineage + owner + cmdline + exe hashes).
  parseProcessScan: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/processes-scan`, undefined, { timeout: 600_000 })
    return data
  },

  // Native autoruns / persistence enumeration (+ hash + Authenticode signature).
  parseAutoruns: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/autoruns`, undefined, { timeout: 600_000 })
    return data
  },

  // Container forensics (Linux): running/stopped containers + misconfiguration
  // (privileged, docker-socket mount, host namespaces, dangerous caps).
  parseContainers: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/containers`, undefined, { timeout: 600_000 })
    return data
  },

  // Linux triage: persistence + execution history + privesc artifacts.
  parseLinuxTriage: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/linux-triage`, undefined, { timeout: 600_000 })
    return data
  },

  // Native network snapshot: TCP/UDP connections w/ owning process + image path
  // + reverse DNS, plus the DNS resolver cache (NetworkMiner-style). No UAC.
  parseNetwork: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/netscan`, undefined, { timeout: 600_000 })
    return data
  },

  // Native loaded-module enumeration (ListDLLs-style): every process's DLLs,
  // deduped + hashed + Authenticode-checked, with DLL-hijack / injection flags.
  parseDlls: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/dlls`, undefined, { timeout: 600_000 })
    return data
  },

  // Containment: terminate a process on the endpoint (elevates if needed).
  killProcess: async (id: string, pid: number): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/kill`, { pid }, { timeout: 120_000 })
    return data
  },

  // AppCompatCache (Shimcache) execution-evidence parse.
  parseShimcache: async (id: string): Promise<any> => {
    const { data } = await apiClient.post(`/agents/${id}/shimcache`, undefined, { timeout: 600_000 })
    return data
  },

  // Browser history across all local user profiles (Chrome/Edge/Brave/Firefox).
  parseBrowser: async (id: string): Promise<BrowserEntry[]> => {
    const { data } = await apiClient.post(`/agents/${id}/browser`, undefined, { timeout: 600_000 })
    return data
  },

  // 1-click triage collection (KAPE-style): a curated artifact bundle gathered
  // in one elevated pass. `types` empty → agent's default set.
  collectTriage: async (id: string, types?: string[]): Promise<TriageResult> => {
    const { data } = await apiClient.post(`/agents/${id}/triage`, { types: types ?? [] }, { timeout: 900_000 })
    return data
  },

  // Live IOC sweep: push indicators to the agent, collect live artifacts and
  // match them server-side. Returns the hits with attribution.
  iocSweep: async (id: string, indicators: string[], types?: string[], useStore?: boolean): Promise<IOCSweepResult> => {
    const { data } = await apiClient.post<{ success: boolean; data: IOCSweepResult }>(
      `/agents/${id}/ioc-sweep`, { indicators, types: types ?? [], use_store: !!useStore }, { timeout: 900_000 })
    return data.data
  },

  // Baseline & drift: store a known-good snapshot, fetch it to diff later.
  setBaseline: async (id: string, kind: string, data: string): Promise<any> => {
    const { data: res } = await apiClient.post(`/agents/${id}/baseline`, { kind, data })
    return res
  },
  getBaseline: async (id: string, kind: string): Promise<{ data: string; created_at: string; updated_at: string }> => {
    const { data } = await apiClient.get(`/agents/${id}/baseline`, { params: { kind } })
    return data.data
  }
}
