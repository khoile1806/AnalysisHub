import apiClient from './client'

export interface FsEntry {
  name: string
  size: number
  is_dir: boolean
  mod_time: string
  mode?: string
}

export interface FsListResult {
  path: string
  entries: FsEntry[]
  truncated?: boolean
}

// The agent filesystem API deliberately has NO browser-download method. Pulling
// agent data straight to the operator's machine bypassed the Evidence Store and
// left no provenance record — a security gap. Every download now routes through
// collectToEvidence; the operator downloads (zipped, audited) from the Evidence
// Store instead.
export const fsApi = {
  list: async (agentId: string, path: string): Promise<FsListResult> => {
    const { data } = await apiClient.get<{ success: boolean; data: FsListResult }>(
      `/agents/${agentId}/fs`,
      { params: { path }, timeout: 120_000 },
    )
    return data.data
  },

  // collectToEvidence pulls a file from the agent straight into the central
  // Evidence Store as the ORIGINAL, uncompressed bytes (not to the browser).
  // The operator can then download it (zipped) from IOC Store → Evidence Store.
  collectToEvidence: async (agentId: string, path: string): Promise<{ id: string; file_name: string; size: number }> => {
    const { data } = await apiClient.post<{ success: boolean; data: { id: string; file_name: string; size: number } }>(
      `/agents/${agentId}/fs/collect`, undefined, { params: { path }, timeout: 600_000 },
    )
    return data.data
  },
}
