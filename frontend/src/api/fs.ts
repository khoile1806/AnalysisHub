import apiClient from './client'
import { useAuthStore } from '@/store/auth'

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

export interface DownloadResult {
  filename: string
  size: number
}

interface ApiResponse<T> {
  success: boolean
  data: T
}

const apiBase = (): string =>
  ((import.meta.env.VITE_API_URL as string | undefined) ?? '') + '/api/v1'

// Hard ceiling for a single download. The browser holds the whole blob in
// memory anyway (1 GB backend cap), so anything past 10 min almost certainly
// means a stuck connection — abort and surface a clear error to the user.
const DOWNLOAD_TIMEOUT_MS = 10 * 60 * 1000

export const fsApi = {
  list: async (agentId: string, path: string): Promise<FsListResult> => {
    const { data } = await apiClient.get<ApiResponse<FsListResult>>(
      `/agents/${agentId}/fs`,
      { params: { path }, timeout: 120_000 },
    )
    return data.data
  },

  // downloadUrl returns a direct GET URL with the JWT in the query string.
  // Kept for backwards compatibility; prefer download() which surfaces errors
  // via toast instead of silently navigating the browser on failure.
  downloadUrl: (agentId: string, path: string, asArchive: boolean): string => {
    const token = useAuthStore.getState().token ?? ''
    const params = new URLSearchParams({ path, token })
    if (asArchive) params.set('archive', 'tar.gz')
    return `${apiBase()}/agents/${agentId}/fs/download?${params.toString()}`
  },

  // download fetches a single file (raw) or folder (tar.gz) from the agent and
  // triggers a browser save. Aborts after DOWNLOAD_TIMEOUT_MS so a stuck
  // stream never leaves the UI spinner turning forever.
  download: async (
    agentId: string,
    path: string,
    asArchive: boolean,
  ): Promise<DownloadResult> => {
    const token = useAuthStore.getState().token ?? ''
    const params = new URLSearchParams({ path })
    if (asArchive) params.set('archive', 'tar.gz')
    return runDownload(
      `${apiBase()}/agents/${agentId}/fs/download?${params.toString()}`,
      { headers: { Authorization: `Bearer ${token}` } },
      fallbackFilename(path, asArchive),
    )
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

  // downloadBundle POSTs a list of paths and triggers a browser download of
  // the resulting zip blob. Returns filename + size for history.
  downloadBundle: async (agentId: string, paths: string[]): Promise<DownloadResult> => {
    const token = useAuthStore.getState().token ?? ''
    return runDownload(
      `${apiBase()}/agents/${agentId}/fs/download-bundle`,
      {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          Authorization: `Bearer ${token}`,
        },
        body: JSON.stringify({ paths }),
      },
      `bundle-${Date.now()}.zip`,
    )
  },
}

// runDownload wraps fetch with a hard timeout via AbortController. On abort
// (timeout or page unload) we throw a readable error so the caller's toast
// reflects "download timed out" rather than the browser's raw AbortError.
async function runDownload(
  url: string,
  init: RequestInit,
  fallbackName: string,
): Promise<DownloadResult> {
  const ctrl = new AbortController()
  const timer = setTimeout(() => ctrl.abort(), DOWNLOAD_TIMEOUT_MS)
  try {
    const resp = await fetch(url, { ...init, signal: ctrl.signal })
    return await triggerBlobDownload(resp, fallbackName)
  } catch (err) {
    if (err instanceof DOMException && err.name === 'AbortError') {
      throw new Error(
        `download timed out after ${Math.round(DOWNLOAD_TIMEOUT_MS / 60000)} minutes — agent may be unresponsive`,
      )
    }
    throw err
  } finally {
    clearTimeout(timer)
  }
}

// triggerBlobDownload pipes a fetch Response to the browser's download UI.
// On non-OK it throws with the backend's error message. Filename comes from
// Content-Disposition; fallbackName is used if the header is missing.
async function triggerBlobDownload(
  resp: Response,
  fallbackName: string,
): Promise<DownloadResult> {
  if (!resp.ok) {
    let msg = `download failed (${resp.status})`
    try {
      const j = await resp.json()
      if (j?.error) msg = j.error
    } catch { /* response body wasn't JSON */ }
    throw new Error(msg)
  }
  const blob = await resp.blob()
  const cd = resp.headers.get('Content-Disposition') ?? ''
  const m = /filename="([^"]+)"/.exec(cd)
  const filename = m?.[1] ?? fallbackName
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
  return { filename, size: blob.size }
}

// fallbackFilename derives a sensible save name from an absolute agent path
// when the server's Content-Disposition is absent. Folders get a .zip
// suffix so the archive is opened with the right tool.
function fallbackFilename(path: string, asArchive: boolean): string {
  const normalised = path.replace(/\\/g, '/').replace(/\/+$/, '')
  const base = normalised.split('/').pop() || 'download'
  return asArchive ? `${base}.zip` : base
}
