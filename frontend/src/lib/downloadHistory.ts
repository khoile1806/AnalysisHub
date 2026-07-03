import { useEffect, useState } from 'react'

const STORAGE_KEY = 'analysishub_download_history'
const MAX_ENTRIES = 200
const CHANGE_EVENT = 'analysishub-download-history-changed'

export interface DownloadHistoryEntry {
  id: string
  agent_id: string
  agent_name: string
  source_path: string
  filename: string
  size: number
  is_archive: boolean
  downloaded_at: string
}

function read(): DownloadHistoryEntry[] {
  try {
    const raw = localStorage.getItem(STORAGE_KEY)
    if (!raw) return []
    const parsed = JSON.parse(raw) as unknown
    return Array.isArray(parsed) ? (parsed as DownloadHistoryEntry[]) : []
  } catch {
    return []
  }
}

function write(entries: DownloadHistoryEntry[]): void {
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(entries))
  } catch {
    // ignore quota / serialization errors
  }
  window.dispatchEvent(new CustomEvent(CHANGE_EVENT))
}

export const downloadHistory = {
  list: (): DownloadHistoryEntry[] => read(),

  listByAgent: (agentId: string): DownloadHistoryEntry[] =>
    read().filter((e) => e.agent_id === agentId),

  add: (entry: Omit<DownloadHistoryEntry, 'id' | 'downloaded_at'>): DownloadHistoryEntry => {
    const full: DownloadHistoryEntry = {
      ...entry,
      id: `${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
      downloaded_at: new Date().toISOString(),
    }
    const next = [full, ...read()].slice(0, MAX_ENTRIES)
    write(next)
    return full
  },

  remove: (id: string): void => {
    write(read().filter((e) => e.id !== id))
  },

  clear: (agentId?: string): void => {
    write(agentId ? read().filter((e) => e.agent_id !== agentId) : [])
  },
}

// useDownloadHistory subscribes to both in-tab updates (CustomEvent) and
// cross-tab updates (storage event) so every panel instance stays in sync.
export function useDownloadHistory(agentId?: string): DownloadHistoryEntry[] {
  const [entries, setEntries] = useState<DownloadHistoryEntry[]>(() =>
    agentId ? downloadHistory.listByAgent(agentId) : downloadHistory.list(),
  )

  useEffect(() => {
    const reload = () => {
      setEntries(agentId ? downloadHistory.listByAgent(agentId) : downloadHistory.list())
    }
    window.addEventListener(CHANGE_EVENT, reload)
    window.addEventListener('storage', reload)
    return () => {
      window.removeEventListener(CHANGE_EVENT, reload)
      window.removeEventListener('storage', reload)
    }
  }, [agentId])

  return entries
}
