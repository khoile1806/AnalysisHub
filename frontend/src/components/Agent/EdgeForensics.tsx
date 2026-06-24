import { useState } from 'react'
import { HardDrive, Clock, ShieldAlert, Play, Search, Trash2, File, Folder, AlertTriangle } from 'lucide-react'
import { agentsApi, type Agent } from '@/api/agents'
import toast from 'react-hot-toast'

// ── MFT types ──────────────────────────────────────────────────────────────
interface MFTEntry {
  file_path: string
  size: number
  is_dir: boolean
  mod_time: string
  is_deleted: boolean
}

// ── Prefetch types ─────────────────────────────────────────────────────────
interface PrefetchEntry {
  executable: string
  last_run_time: string
  hash: string
  prefetch_file: string
}

// ── Helpers ─────────────────────────────────────────────────────────────────
function fmtSize(bytes: number) {
  if (bytes === 0) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`
}

function fmtTime(iso: string) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}

// ── MFT result table ────────────────────────────────────────────────────────
function MFTTable({ data }: { data: MFTEntry[] }) {
  const [filter, setFilter] = useState('')
  const [showDeletedOnly, setShowDeletedOnly] = useState(false)

  const deletedCount = data.filter(e => e.is_deleted).length

  const filtered = data.filter(e => {
    const matchFilter = !filter || e.file_path.toLowerCase().includes(filter.toLowerCase())
    const matchDeleted = !showDeletedOnly || e.is_deleted
    return matchFilter && matchDeleted
  })

  return (
    <div className="space-y-3">
      {/* Stats bar */}
      <div className="flex items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length.toLocaleString()} total entries</span>
        {deletedCount > 0 && (
          <span className="flex items-center gap-1 text-rose-400 font-medium">
            <Trash2 className="h-3 w-3" /> {deletedCount} deleted artifacts found
          </span>
        )}
      </div>

      {/* Toolbar */}
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input
            type="text"
            value={filter}
            onChange={e => setFilter(e.target.value)}
            placeholder="Filter by path..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60"
          />
        </div>
        {deletedCount > 0 && (
          <button
            onClick={() => setShowDeletedOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${
              showDeletedOnly
                ? 'bg-rose-500/20 border-rose-500/40 text-rose-400'
                : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'
            }`}
          >
            <Trash2 className="h-3 w-3" />
            Deleted Only
          </button>
        )}
      </div>

      {/* Table */}
      <div className="overflow-auto max-h-[500px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-3 py-2 text-left text-gray-500 font-medium w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Path</th>
              <th className="px-3 py-2 text-right text-gray-500 font-medium">Size</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Modified</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-gray-600">No results match your filter</td>
              </tr>
            ) : (
              filtered.map((entry, i) => (
                <tr
                  key={i}
                  className={`border-b border-gray-800/40 hover:bg-gray-800/20 transition-colors ${
                    entry.is_deleted ? 'bg-rose-950/20' : ''
                  }`}
                >
                  <td className="px-3 py-1.5">
                    {entry.is_dir
                      ? <Folder className="h-3.5 w-3.5 text-yellow-500/60" />
                      : <File className="h-3.5 w-3.5 text-gray-600" />}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-300 break-all max-w-xs">
                    {entry.file_path}
                  </td>
                  <td className="px-3 py-1.5 font-mono text-gray-400 text-right whitespace-nowrap">
                    {fmtSize(entry.size)}
                  </td>
                  <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">
                    {fmtTime(entry.mod_time)}
                  </td>
                  <td className="px-3 py-1.5 text-center">
                    {entry.is_deleted ? (
                      <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-rose-500/20 border border-rose-500/30 text-rose-400 text-xs font-medium">
                        <Trash2 className="h-2.5 w-2.5" /> Deleted
                      </span>
                    ) : (
                      <span className="text-emerald-500/60 text-xs">Active</span>
                    )}
                  </td>
                </tr>
              ))
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Prefetch result table ───────────────────────────────────────────────────
function PrefetchTable({ data }: { data: PrefetchEntry[] }) {
  const [filter, setFilter] = useState('')

  const filtered = data.filter(e =>
    !filter || e.executable.toLowerCase().includes(filter.toLowerCase())
  )

  // Suspicious heuristics: run after midnight, unknown hash, etc.
  const isHighlighted = (e: PrefetchEntry) => {
    const suspicious = ['mimikatz', 'pwdump', 'wce', 'gsecdump', 'procdump', 'nc.exe', 'netcat', 'nmap', 'psexec', 'cobalt']
    return suspicious.some(s => e.executable.toLowerCase().includes(s))
  }

  return (
    <div className="space-y-3">
      {/* Stats */}
      <div className="flex items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length} prefetch entries found</span>
        <span className="text-gray-600">Execution history from <code className="text-purple-400 bg-purple-500/10 px-1 rounded">C:\Windows\Prefetch</code></span>
      </div>

      {/* Toolbar */}
      <div className="relative">
        <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
        <input
          type="text"
          value={filter}
          onChange={e => setFilter(e.target.value)}
          placeholder="Filter by executable name..."
          className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60"
        />
      </div>

      {/* Table */}
      <div className="overflow-auto max-h-[500px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-3 py-2 text-left text-gray-500 font-medium w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Executable</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Last Run Time</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Hash</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Prefetch File</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-8 text-center text-gray-600">No results</td>
              </tr>
            ) : (
              filtered.map((entry, i) => {
                const flagged = isHighlighted(entry)
                return (
                  <tr
                    key={i}
                    className={`border-b border-gray-800/40 hover:bg-gray-800/20 transition-colors ${
                      flagged ? 'bg-amber-950/20' : ''
                    }`}
                  >
                    <td className="px-3 py-1.5">
                      {flagged
                        ? <AlertTriangle className="h-3.5 w-3.5 text-amber-400" />
                        : <Clock className="h-3.5 w-3.5 text-gray-700" />}
                    </td>
                    <td className="px-3 py-1.5 font-mono font-medium">
                      <span className={flagged ? 'text-amber-300' : 'text-gray-200'}>
                        {entry.executable}
                      </span>
                      {flagged && (
                        <span className="ml-2 inline-flex items-center px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs">
                          Suspicious
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap font-mono">
                      {fmtTime(entry.last_run_time)}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-gray-600">
                      {entry.hash || '—'}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-gray-500 text-xs">
                      {entry.prefetch_file}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Main component ──────────────────────────────────────────────────────────
export function EdgeForensics({ agent }: { agent: Agent }) {
  const [activeTab, setActiveTab] = useState<'mft' | 'prefetch'>('mft')
  const [loading, setLoading] = useState(false)
  const [mftResults, setMftResults] = useState<MFTEntry[] | null>(null)
  const [prefetchResults, setPrefetchResults] = useState<PrefetchEntry[] | null>(null)

  const handleMftScan = async () => {
    setLoading(true)
    setMftResults(null)
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseMFT(agent.id)
      const arr: MFTEntry[] = Array.isArray(data) ? data : [data]
      setMftResults(arr)
      toast.success(`MFT scan complete — ${arr.length} entries`)
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err.message || 'MFT Scan failed')
    } finally {
      setLoading(false)
    }
  }

  const handlePrefetchScan = async () => {
    setLoading(true)
    setPrefetchResults(null)
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parsePrefetch(agent.id)
      const arr: PrefetchEntry[] = Array.isArray(data) ? data : [data]
      setPrefetchResults(arr)
      toast.success(`Prefetch scan complete — ${arr.length} entries`)
    } catch (err: any) {
      toast.error(err?.response?.data?.error || err.message || 'Prefetch Scan failed')
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full bg-[#151515]">
      {/* Header Tabs */}
      <div className="border-b border-gray-800 bg-[#1C1C1E] p-4 flex items-center justify-between">
        <div className="flex gap-4">
          <button
            onClick={() => setActiveTab('mft')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${
              activeTab === 'mft' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
            }`}
          >
            <HardDrive className="h-4 w-4" />
            MFT Scan
          </button>
          <button
            onClick={() => setActiveTab('prefetch')}
            className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${
              activeTab === 'prefetch' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
            }`}
          >
            <Clock className="h-4 w-4" />
            Prefetch Scan
          </button>
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-auto p-6">
        <div className="max-w-6xl mx-auto space-y-6">
          <div className="bg-[#1C1C1E] border border-gray-800 rounded-xl p-6">
            {/* Card header */}
            <div className="flex items-start justify-between mb-6">
              <div>
                <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
                  {activeTab === 'mft' ? <HardDrive className="h-5 w-5 text-purple-400" /> : <Clock className="h-5 w-5 text-purple-400" />}
                  {activeTab === 'mft' ? 'Master File Table (MFT)' : 'Prefetch Analysis'}
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  {activeTab === 'mft'
                    ? 'Scan the raw NTFS volume to find deleted or hidden files. Requires UAC elevation.'
                    : 'Parse application execution history and timestamps. Requires UAC elevation.'}
                </p>
              </div>
              <button
                onClick={activeTab === 'mft' ? handleMftScan : handlePrefetchScan}
                disabled={loading || agent.status !== 'online'}
                className="bg-purple-600 hover:bg-purple-700 text-white flex items-center gap-2 px-4 py-2 rounded-md font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {loading ? (
                  <>
                    <span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" />
                    Scanning...
                  </>
                ) : (
                  <>
                    <Play className="h-4 w-4" />
                    Run Scan
                  </>
                )}
              </button>
            </div>

            {/* Offline warning */}
            {agent.status !== 'online' && (
              <div className="flex items-center gap-3 p-4 rounded-lg bg-orange-500/10 border border-orange-500/20 mb-6">
                <ShieldAlert className="h-5 w-5 text-orange-400 flex-shrink-0" />
                <p className="text-sm text-orange-200">Agent is offline. Edge Forensics cannot be performed.</p>
              </div>
            )}

            {/* Results */}
            {activeTab === 'mft' && mftResults && mftResults.length > 0 && (
              <div className="mt-2 border-t border-gray-800 pt-6">
                <MFTTable data={mftResults} />
              </div>
            )}
            {activeTab === 'prefetch' && prefetchResults && prefetchResults.length > 0 && (
              <div className="mt-2 border-t border-gray-800 pt-6">
                <PrefetchTable data={prefetchResults} />
              </div>
            )}

            {activeTab === 'mft' && mftResults && mftResults.length === 0 && (
              <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12">
                <Search className="h-8 w-8 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">Scan completed — no entries found.</p>
              </div>
            )}
            {activeTab === 'prefetch' && prefetchResults && prefetchResults.length === 0 && (
              <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12">
                <Search className="h-8 w-8 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-500 text-sm">Scan completed — no entries found.</p>
              </div>
            )}

            {/* Empty state */}
            {((activeTab === 'mft' && !mftResults) || (activeTab === 'prefetch' && !prefetchResults)) && !loading && agent.status === 'online' && (
              <div className="text-center py-12 border-2 border-dashed border-gray-800 rounded-lg">
                <Search className="h-8 w-8 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-400 text-sm">Click "Run Scan" to trigger the UAC prompt on the agent.</p>
                <p className="text-gray-600 text-xs mt-1">Results are analysed on-device and only metadata is transmitted.</p>
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
