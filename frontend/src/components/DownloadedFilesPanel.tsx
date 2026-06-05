import { useMemo, useState } from 'react'
import { Trash2, History, RefreshCw, Loader2 } from 'lucide-react'
import { safeDistanceToNow } from '@/lib/utils'
import toast from 'react-hot-toast'
import {
  downloadHistory,
  useDownloadHistory,
  type DownloadHistoryEntry,
} from '@/lib/downloadHistory'
import { fsApi } from '@/api/fs'
import { formatBytes, getErrorMessage } from '@/lib/utils'

interface Props {
  agentId: string
  agentName: string
  agentOnline: boolean
}

export function DownloadedFilesPanel({ agentId, agentName, agentOnline }: Props) {
  const entries = useDownloadHistory(agentId)
  const [redownloading, setRedownloading] = useState<Set<string>>(new Set())

  const sorted = useMemo(
    () =>
      [...entries].sort(
        (a, b) => new Date(b.downloaded_at).getTime() - new Date(a.downloaded_at).getTime(),
      ),
    [entries],
  )

  const markBusy = (id: string, on: boolean) => {
    setRedownloading((prev) => {
      const next = new Set(prev)
      if (on) next.add(id)
      else next.delete(id)
      return next
    })
  }

  // Re-download re-runs the original request against the live agent. The
  // original file we saved to disk isn't addressable by us (browser sandbox),
  // so "re-download" means "fetch again from the agent into browser downloads".
  const redownload = async (entry: DownloadHistoryEntry) => {
    if (!agentOnline) {
      toast.error('Agent is offline')
      return
    }
    if (redownloading.has(entry.id)) return
    markBusy(entry.id, true)
    try {
      const result = await fsApi.download(agentId, entry.source_path, entry.is_archive)
      downloadHistory.add({
        agent_id: agentId,
        agent_name: agentName,
        source_path: entry.source_path,
        filename: result.filename,
        size: result.size,
        is_archive: entry.is_archive,
      })
      toast.success(`Downloaded ${result.filename}`)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      markBusy(entry.id, false)
    }
  }

  const removeEntry = (id: string) => {
    downloadHistory.remove(id)
  }

  const clearAll = () => {
    if (sorted.length === 0) return
    if (!confirm(`Clear ${sorted.length} download record${sorted.length !== 1 ? 's' : ''} for this agent?`)) return
    downloadHistory.clear(agentId)
    toast.success('History cleared')
  }

  return (
    <div className="card p-0 overflow-hidden">
      <div className="px-4 py-3 border-b border-gray-800 flex items-center justify-between">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
          <History className="h-4 w-4 text-emerald-400" />
          Downloaded Files
          <span className="text-xs font-normal text-gray-500">
            ({sorted.length} record{sorted.length !== 1 ? 's' : ''})
          </span>
        </h3>
        {sorted.length > 0 && (
          <button
            onClick={clearAll}
            className="text-xs text-gray-400 hover:text-red-400 hover:bg-red-900/20 px-2 py-1 rounded transition-colors"
            title="Clear all history for this agent"
          >
            Clear all
          </button>
        )}
      </div>

      {sorted.length === 0 ? (
        <div className="flex flex-col items-center justify-center py-10 text-gray-500">
          <History className="h-8 w-8 mb-2 opacity-30" />
          <p className="text-sm">No downloads yet for this agent</p>
          <p className="text-xs text-gray-600 mt-1">
            Files saved via the browser's download folder will be tracked here.
          </p>
        </div>
      ) : (
        <div className="overflow-x-auto">
          <table className="w-full">
            <thead>
              <tr className="border-b border-gray-800">
                <th className="table-header text-left px-3 py-2">File</th>
                <th className="table-header text-left px-3 py-2 hidden md:table-cell">Source path</th>
                <th className="table-header text-right px-3 py-2 w-24">Size</th>
                <th className="table-header text-left px-3 py-2 w-40 hidden lg:table-cell">Downloaded</th>
                <th className="table-header text-right px-3 py-2 w-24">Actions</th>
              </tr>
            </thead>
            <tbody>
              {sorted.map((e) => {
                const busy = redownloading.has(e.id)
                return (
                  <tr
                    key={e.id}
                    className="border-b border-gray-800/40 hover:bg-gray-800/30"
                  >
                    <td className="px-3 py-1.5">
                      <div className="text-sm font-mono text-gray-200 truncate max-w-[20rem]" title={e.filename}>
                        {e.filename}
                      </div>
                      {e.is_archive && (
                        <span className="text-[10px] text-amber-400/70 font-mono">archive</span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 hidden md:table-cell">
                      <span
                        className="text-xs font-mono text-gray-500 truncate max-w-[20rem] inline-block align-middle"
                        title={e.source_path}
                      >
                        {e.source_path}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-xs font-mono text-right text-gray-400">
                      {formatBytes(e.size)}
                    </td>
                    <td className="px-3 py-1.5 text-xs text-gray-500 hidden lg:table-cell" title={new Date(e.downloaded_at).toLocaleString()}>
                      {safeDistanceToNow(e.downloaded_at, { addSuffix: true })}
                    </td>
                    <td className="px-3 py-1.5 text-right">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => redownload(e)}
                          disabled={busy || !agentOnline}
                          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors disabled:opacity-40 disabled:cursor-not-allowed"
                          title={agentOnline ? 'Re-download from agent' : 'Agent offline'}
                        >
                          {busy
                            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            : <RefreshCw className="h-3.5 w-3.5" />}
                        </button>
                        <button
                          onClick={() => removeEntry(e.id)}
                          className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors"
                          title="Remove from history"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      <p className="px-4 py-2 text-[11px] text-gray-600 border-t border-gray-800/60">
        Files land in your browser's default download folder. This panel only tracks history — the record staying here does not guarantee the file still exists on disk.
      </p>
    </div>
  )
}
