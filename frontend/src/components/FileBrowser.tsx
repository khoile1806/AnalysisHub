import { useEffect, useMemo, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Folder, FileIcon, ChevronRight, Home, Download, Loader2, FolderOpen,
  FolderArchive, Inbox, RefreshCw, GitBranch,
} from 'lucide-react'
import toast from 'react-hot-toast'
import type { Agent } from '@/api/agents'
import { fsApi, type FsEntry } from '@/api/fs'
import { getErrorMessage } from '@/lib/utils'
import TraceOriginModal from '@/components/Agent/TraceOriginModal'

type Sep = '/' | '\\'

function detectSeparator(os: string, path: string): Sep {
  // If the user-typed path uses Windows-style separators or starts with a drive
  // letter, honour that even if agent.os is misreported.
  if (/^[A-Za-z]:[\\/]/.test(path) || path.includes('\\')) return '\\'
  if (path.startsWith('/')) return '/'
  return os.toLowerCase().includes('windows') ? '\\' : '/'
}

function defaultRoot(os: string): string {
  return os.toLowerCase().includes('windows') ? 'C:\\' : '/'
}

function joinPath(base: string, name: string, sep: Sep): string {
  if (base === '' || base === '/') return sep === '/' ? '/' + name : name
  if (base.endsWith(sep)) return base + name
  return base + sep + name
}

// pathSegments produces clickable breadcrumb segments. Each segment carries
// the absolute path to navigate to when clicked.
function pathSegments(path: string, sep: Sep): { label: string; path: string }[] {
  const segments: { label: string; path: string }[] = []
  if (sep === '\\') {
    // Windows: "C:\Users\Foo" → ["C:\", "C:\Users", "C:\Users\Foo"]
    const drive = /^[A-Za-z]:/.exec(path)?.[0] ?? ''
    if (drive) segments.push({ label: drive + '\\', path: drive + '\\' })
    const rest = path.replace(/^[A-Za-z]:[\\/]?/, '').replace(/\\/g, '/').split('/').filter(Boolean)
    let cur = drive + '\\'
    for (const s of rest) {
      cur = cur.endsWith('\\') ? cur + s : cur + '\\' + s
      segments.push({ label: s, path: cur })
    }
  } else {
    segments.push({ label: '/', path: '/' })
    const parts = path.split('/').filter(Boolean)
    let cur = ''
    for (const s of parts) {
      cur = cur + '/' + s
      segments.push({ label: s, path: cur })
    }
  }
  return segments
}

function parentOf(path: string, sep: Sep): string | null {
  if (sep === '\\') {
    if (/^[A-Za-z]:[\\/]?$/.test(path)) return null
    const trimmed = path.replace(/[\\/]+$/, '')
    const idx = Math.max(trimmed.lastIndexOf('\\'), trimmed.lastIndexOf('/'))
    if (idx <= 2) return trimmed.slice(0, 3) // back to "C:\"
    return trimmed.slice(0, idx)
  }
  if (path === '/' || path === '') return null
  const trimmed = path.replace(/\/+$/, '')
  const idx = trimmed.lastIndexOf('/')
  return idx <= 0 ? '/' : trimmed.slice(0, idx)
}

function formatSize(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

// FOLDER_KEY is a sentinel used in the `downloading` set to represent the
// "download current folder as tar.gz" button (which has no entry.name).
const FOLDER_KEY = '__current_folder__'

export function FileBrowser({ agent }: { agent: Agent }) {
  const [path, setPath] = useState<string>(defaultRoot(agent.os))
  const [pathInput, setPathInput] = useState<string>(path)
  const [selected, setSelected] = useState<Set<string>>(new Set()) // entry name → selected
  const [bundling, setBundling] = useState(false)
  const [downloading, setDownloading] = useState<Set<string>>(new Set())
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)

  const markDownloading = (key: string, on: boolean) => {
    setDownloading(prev => {
      const next = new Set(prev)
      if (on) next.add(key)
      else next.delete(key)
      return next
    })
  }

  const sep = useMemo(() => detectSeparator(agent.os, path), [agent.os, path])
  const isOnline = agent.status === 'online'

  // Fetch the listing for the current path.
  const { data, isLoading, error, refetch, isFetching } = useQuery({
    queryKey: ['agent-fs', agent.id, path],
    queryFn: () => fsApi.list(agent.id, path),
    enabled: isOnline && path.length > 0,
    retry: false,
  })

  // Reset selection whenever the directory changes.
  useEffect(() => { setSelected(new Set()) }, [path])
  useEffect(() => { setPathInput(path) }, [path])

  const entries = data?.entries ?? []
  const sorted = useMemo(() => {
    const arr = [...entries]
    arr.sort((a, b) => {
      if (a.is_dir !== b.is_dir) return a.is_dir ? -1 : 1
      return a.name.localeCompare(b.name)
    })
    return arr
  }, [entries])

  const navigateInto = (entry: FsEntry) => {
    if (!entry.is_dir) return
    setPath(joinPath(path, entry.name, sep))
  }

  const navigateTo = (target: string) => setPath(target)

  const goUp = () => {
    const p = parentOf(path, sep)
    if (p) setPath(p)
  }

  const submitPathInput = (e: React.FormEvent) => {
    e.preventDefault()
    const trimmed = pathInput.trim()
    if (trimmed) setPath(trimmed)
  }

  const toggleEntry = (name: string) => {
    setSelected(prev => {
      const next = new Set(prev)
      if (next.has(name)) next.delete(name)
      else next.add(name)
      return next
    })
  }

  const toggleAll = () => {
    if (selected.size === sorted.length) setSelected(new Set())
    else setSelected(new Set(sorted.map(e => e.name)))
  }

  // Every download from an agent's filesystem must go through the Evidence Store
  // — pulling data straight to the operator's machine as a zip left no evidence
  // record and no audit of what was taken, which is a provenance bypass. So a
  // file is collected as its original uncompressed bytes, and a folder is walked
  // and each file inside it collected the same way. Zipping happens only later,
  // when the operator downloads FROM the Evidence Store (which is audited).
  const COLLECT_MAX_FILES = 500
  const COLLECT_MAX_DEPTH = 8

  type CollectCounter = { files: number; capped: boolean }

  // collectTree sends a file, or every file under a folder, into the Evidence
  // Store. Bounded in breadth and depth so selecting a huge tree cannot spawn an
  // unbounded pull; the cap is surfaced rather than silently truncated.
  const collectTree = async (fullPath: string, isDir: boolean, depth: number, counter: CollectCounter): Promise<void> => {
    if (counter.files >= COLLECT_MAX_FILES) { counter.capped = true; return }
    if (!isDir) {
      await fsApi.collectToEvidence(agent.id, fullPath)
      counter.files++
      return
    }
    if (depth >= COLLECT_MAX_DEPTH) { counter.capped = true; return }
    const listing = await fsApi.list(agent.id, fullPath)
    for (const child of listing.entries ?? []) {
      if (counter.files >= COLLECT_MAX_FILES) { counter.capped = true; break }
      await collectTree(joinPath(fullPath, child.name, sep), child.is_dir, depth + 1, counter)
    }
  }

  // reportCollected shows the result of a collect run pointing at the Evidence Store.
  const reportCollected = (counter: CollectCounter) => {
    if (counter.files === 0) {
      toast.error('Nothing collected — no files found')
      return
    }
    const capNote = counter.capped ? ` (capped at ${COLLECT_MAX_FILES} — collect deeper folders separately)` : ''
    toast.success(`${counter.files} file(s) sent to Evidence Store${capNote} — download from IOC Store → Evidence Store`)
  }

  // Single-item download. A file or a folder is collected into the Evidence Store
  // as original, uncompressed bytes — never zipped to the operator's machine.
  const downloadEntry = async (entry: FsEntry) => {
    const key = entry.name
    if (downloading.has(key)) return
    markDownloading(key, true)
    try {
      const fullPath = joinPath(path, entry.name, sep)
      const counter: CollectCounter = { files: 0, capped: false }
      await collectTree(fullPath, entry.is_dir, 0, counter)
      reportCollected(counter)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      markDownloading(key, false)
    }
  }

  // Collect every file in the current folder into the Evidence Store.
  const downloadCurrentFolder = async () => {
    if (downloading.has(FOLDER_KEY)) return
    markDownloading(FOLDER_KEY, true)
    try {
      const counter: CollectCounter = { files: 0, capped: false }
      await collectTree(path, true, 0, counter)
      reportCollected(counter)
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      markDownloading(FOLDER_KEY, false)
    }
  }

  // Multi-select: send each selected file (and each file inside selected folders)
  // to the Evidence Store individually, uncompressed. This closes the bypass where
  // selecting many files zipped them straight to the operator's machine.
  const downloadSelected = async () => {
    const names = [...selected]
    if (names.length === 0) return
    setBundling(true)
    try {
      const counter: CollectCounter = { files: 0, capped: false }
      const byName = new Map(entries.map(e => [e.name, e]))
      for (const n of names) {
        if (counter.files >= COLLECT_MAX_FILES) { counter.capped = true; break }
        // is_dir is known from the current listing; fall back to file if unknown.
        const isDir = byName.get(n)?.is_dir ?? false
        await collectTree(joinPath(path, n, sep), isDir, 0, counter)
      }
      reportCollected(counter)
      setSelected(new Set())
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setBundling(false)
    }
  }

  const folderDownloading = downloading.has(FOLDER_KEY)

  if (!isOnline) {
    return (
      <div className="space-y-3">
        <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
          <Inbox className="h-10 w-10 mb-3 opacity-30" />
          <p className="text-sm">Agent is offline — file browser requires an active connection.</p>
        </div>
      </div>
    )
  }

  const segments = pathSegments(path, sep)

  return (
    <div className="space-y-3">
      {/* Path input + actions */}
      <form className="flex items-center gap-2" onSubmit={submitPathInput}>
        <button
          type="button"
          onClick={() => setPath(defaultRoot(agent.os))}
          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
          title="Go to root"
        >
          <Home className="h-4 w-4" />
        </button>
        <button
          type="button"
          onClick={goUp}
          className="px-2 py-1.5 text-xs text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
          title="Parent directory"
        >
          ..
        </button>
        <input
          className="input font-mono text-xs flex-1"
          value={pathInput}
          onChange={(e) => setPathInput(e.target.value)}
          placeholder="Absolute path on agent (e.g. C:\Users or /etc)"
        />
        <button type="submit" className="btn-secondary text-xs">Go</button>
        <button
          type="button"
          onClick={() => refetch()}
          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-gray-800 rounded transition-colors"
          title="Refresh"
        >
          <RefreshCw className={`h-4 w-4 ${isFetching ? 'animate-spin' : ''}`} />
        </button>
      </form>

      {/* Breadcrumb */}
      <div className="card px-3 py-2 flex items-center gap-1 overflow-x-auto">
        {segments.map((s, i) => (
          <div key={s.path + i} className="flex items-center gap-1 shrink-0">
            {i > 0 && <ChevronRight className="h-3 w-3 text-gray-600" />}
            <button
              onClick={() => navigateTo(s.path)}
              className="text-xs font-mono text-gray-300 hover:text-emerald-400 px-1 py-0.5 rounded hover:bg-gray-800"
            >
              {s.label}
            </button>
          </div>
        ))}
      </div>

      {/* Action bar */}
      <div className="flex items-center justify-between gap-2">
        <div className="text-xs text-gray-400">
          {selected.size > 0
            ? `${selected.size} item${selected.size !== 1 ? 's' : ''} selected`
            : `${sorted.length} entr${sorted.length !== 1 ? 'ies' : 'y'} in this folder`}
        </div>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={downloadCurrentFolder}
            disabled={folderDownloading}
            className="btn-secondary text-xs flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Send every file in this folder to the Evidence Store (uncompressed)"
          >
            {folderDownloading
              ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
              : <FolderArchive className="h-3.5 w-3.5" />}
            {folderDownloading ? 'Collecting…' : 'Collect folder → Evidence'}
          </button>
          <button
            type="button"
            onClick={downloadSelected}
            disabled={selected.size === 0 || bundling}
            className="btn-primary text-xs flex items-center gap-1.5 disabled:opacity-50 disabled:cursor-not-allowed"
            title="Send each selected file to the Evidence Store (uncompressed, one record each)"
          >
            {bundling
              ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
              : <Download className="h-3.5 w-3.5" />}
            {bundling ? 'Collecting…' : `Collect selected → Evidence (${selected.size})`}
          </button>
        </div>
      </div>

      {/* Truncation warning */}
      {data?.truncated && (
        <div className="rounded border border-yellow-700/50 bg-yellow-900/20 px-3 py-2 text-xs text-yellow-400">
          Listing truncated to 5000 entries. Navigate to a more specific path to see remaining files.
        </div>
      )}

      {/* Listing */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6 space-y-2">{[...Array(8)].map((_, i) => <div key={i} className="skeleton h-8 w-full rounded" />)}</div>
          ) : error ? (
            <div className="p-6 text-sm text-red-400">
              <p className="font-medium">Failed to list directory</p>
              <p className="text-xs text-red-400/80 mt-1 font-mono">{getErrorMessage(error)}</p>
            </div>
          ) : sorted.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-12 text-gray-500">
              <FolderOpen className="h-8 w-8 mb-2 opacity-30" />
              <p className="text-sm">Empty directory</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-3 py-2 w-8">
                    <input
                      type="checkbox"
                      checked={selected.size > 0 && selected.size === sorted.length}
                      ref={(el) => {
                        if (el) el.indeterminate = selected.size > 0 && selected.size < sorted.length
                      }}
                      onChange={toggleAll}
                      className="accent-emerald-500"
                    />
                  </th>
                  <th className="table-header text-left px-3 py-2">Name</th>
                  <th className="table-header text-right px-3 py-2 w-28">Size</th>
                  <th className="table-header text-left px-3 py-2 w-44 hidden md:table-cell">Modified</th>
                  <th className="table-header text-right px-3 py-2 w-24">Actions</th>
                </tr>
              </thead>
              <tbody>
                {sorted.map((e) => {
                  const checked = selected.has(e.name)
                  const isDownloading = downloading.has(e.name)
                  return (
                    <tr
                      key={e.name}
                      className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${checked ? 'bg-emerald-900/10' : ''}`}
                    >
                      <td className="px-3 py-1.5">
                        <input
                          type="checkbox"
                          checked={checked}
                          onChange={() => toggleEntry(e.name)}
                          className="accent-emerald-500"
                        />
                      </td>
                      <td className="px-3 py-1.5">
                        <button
                          type="button"
                          className={`flex items-center gap-2 text-sm font-mono ${
                            e.is_dir ? 'text-emerald-400 hover:text-emerald-300' : 'text-gray-200 hover:text-white'
                          } text-left`}
                          onClick={() => e.is_dir ? navigateInto(e) : downloadEntry(e)}
                          title={e.is_dir ? 'Open folder' : 'Collect file to Evidence Store'}
                        >
                          {e.is_dir
                            ? <Folder className="h-4 w-4 shrink-0" />
                            : <FileIcon className="h-4 w-4 shrink-0 text-gray-500" />}
                          <span className="truncate max-w-[28rem]">{e.name}</span>
                        </button>
                      </td>
                      <td className="px-3 py-1.5 text-xs font-mono text-right text-gray-400">
                        {e.is_dir ? '—' : formatSize(e.size)}
                      </td>
                      <td className="px-3 py-1.5 text-xs font-mono text-gray-500 hidden md:table-cell">
                        {e.mod_time ? e.mod_time.replace('T', ' ').replace('Z', '') : '—'}
                      </td>
                      <td className="px-3 py-1.5 text-right whitespace-nowrap">
                        {!e.is_dir && (
                          <button
                            onClick={() => setTraceTarget({ target: e.name, pid: 0 })}
                            className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors"
                            title="Trace origin (which process wrote/ran this, download URL, when)"
                          >
                            <GitBranch className="h-3.5 w-3.5" />
                          </button>
                        )}
                        <button
                          onClick={() => downloadEntry(e)}
                          disabled={isDownloading}
                          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                          title={e.is_dir ? 'Collect folder to Evidence Store' : 'Collect file to Evidence Store'}
                        >
                          {isDownloading
                            ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            : <Download className="h-3.5 w-3.5" />}
                        </button>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <p className="text-xs text-gray-600">
        Files / folders up to 1 GB · symlinks recorded as-is, never followed · audit log captures every list and download.
      </p>

      {traceTarget && <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />}
    </div>
  )
}
