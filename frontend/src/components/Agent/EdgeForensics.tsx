import { useState, useEffect, useMemo, Fragment } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery } from '@tanstack/react-query'
import {
  HardDrive, Clock, ShieldAlert, Play, Search, File, Folder, AlertTriangle,
  ChevronRight, Copy, Hash, ShieldQuestion, Database, Save, Cpu, Power,
  Network, Globe, Radio, Server, Crosshair, Zap, Boxes, Ban, History, GitBranch,
  Archive, X, Loader2, CalendarPlus, Download, ArrowLeft, BrainCircuit,
} from 'lucide-react'
import { agentsApi, type Agent, type BrowserEntry, type TriageResult } from '@/api/agents'
import TraceOriginModal from '@/components/Agent/TraceOriginModal'
import { intelApi } from '@/api/intel'
import { osintApi } from '@/api/osint'
import { timelineApi, type TimelineSeverity } from '@/api/timeline'
import { casesApi } from '@/api/cases'
import { evidenceApi } from '@/api/evidence'
import { copyToClipboard, getErrorMessage } from '@/lib/utils'
import { useRealtimeSSE } from '@/hooks/useRealtimeSSE'
import IntelLookupModal from '@/components/IntelLookupModal'
import toast from 'react-hot-toast'

// ── Types (match agent parser JSON) ──────────────────────────────────────────
interface MFTEntry {
  file_path: string
  name: string
  ext: string
  size: number
  is_dir: boolean
  created: string
  mod_time: string
  accessed: string
  attributes?: string[]
  md5?: string
  sha1?: string
  sha256?: string
  hashed: boolean
  signature?: string // Signed | Unsigned | Untrusted (executables only)
  suspicious?: string[]
}

interface PrefetchEntry {
  executable: string
  run_count: number
  last_run_time: string
  last_run_times?: string[]
  hash: string
  version: string
  compressed: boolean
  prefetch_file: string
  size: number
  md5: string
  sha256: string
  pf_mod_time: string
  parsed: boolean
  suspicious: boolean
  exe_path?: string
  exe_md5?: string
  exe_sha256?: string
  exe_hashed?: boolean
}

interface ProcessEntry {
  pid: number
  ppid: number
  name: string
  parent_name: string
  path: string
  cmdline: string
  user: string
  mem_kb: number
  created: string
  md5?: string
  sha256?: string
  hashed: boolean
  signature?: string // Signed | Unsigned | Untrusted
  suspicious?: string[]
}

interface AutorunEntry {
  category: string
  name: string
  location: string
  command: string
  image_path: string
  user?: string
  enabled: boolean
  md5?: string
  sha256?: string
  hashed: boolean
  signature?: string // Signed | Unsigned | Untrusted
  suspicious?: string[]
}

interface ShimEntry {
  path: string
  name: string
  last_modified?: string
  suspicious?: string[]
}

interface DllEntry {
  name: string
  path: string
  process_count: number
  processes: string[]
  md5?: string
  sha256?: string
  hashed: boolean
  signature?: string // Signed | Unsigned | Untrusted
  suspicious?: string[]
}

interface Connection {
  proto: string
  local_addr: string
  local_port: number
  remote_addr: string
  remote_port: number
  state: string
  pid: number
  process: string
  image_path?: string
  remote_host?: string
  direction: string
}
interface DNSCacheEntry { name: string; type: string; data: string }
interface NetworkResult { connections: Connection[]; dns: DNSCacheEntry[] }

type LookupTarget = { indicator: string; type?: string }

// ── Helpers ───────────────────────────────────────────────────────────────────
function fmtSize(bytes: number) {
  if (!bytes) return '—'
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}
function fmtTime(iso?: string) {
  if (!iso) return '—'
  const d = new Date(iso)
  if (isNaN(d.getTime()) || d.getFullYear() < 1971) return '—'
  return d.toLocaleString()
}
function shortHash(h?: string) {
  if (!h) return '—'
  return h.length > 16 ? `${h.slice(0, 8)}…${h.slice(-8)}` : h
}
async function copy(label: string, value?: string) {
  if (!value) return
  const ok = await copyToClipboard(value)
  ok ? toast.success(`${label} copied`) : toast.error('Copy failed')
}

function HashRow({ algo, value, onLookup }: { algo: string; value?: string; onLookup?: (t: LookupTarget) => void }) {
  if (!value) return null
  return (
    <div className="flex items-center gap-2 text-xs">
      <span className="w-16 shrink-0 text-gray-500 uppercase font-medium">{algo}</span>
      <code className="font-mono text-emerald-300 break-all flex-1">{value}</code>
      {onLookup && (
        <button onClick={() => onLookup({ indicator: value, type: 'hash' })} className="shrink-0 text-gray-500 hover:text-purple-400" title="Look up on VirusTotal">
          <ShieldQuestion className="h-3.5 w-3.5" />
        </button>
      )}
      <button onClick={() => copy(algo.toUpperCase(), value)} className="shrink-0 text-gray-500 hover:text-emerald-400" title={`Copy ${algo}`}>
        <Copy className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

// ── MFT / File-forensic table ─────────────────────────────────────────────────
function MFTTable({ data, iocMatches, onLookup, selected, onToggle, onTrace }: {
  data: MFTEntry[]
  iocMatches: Set<string>
  onLookup: (t: LookupTarget) => void
  selected: Set<number>
  onToggle: (i: number) => void
  onTrace: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [suspiciousOnly, setSuspiciousOnly] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const toggleExp = (i: number) => setExpanded(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const isKnownIOC = (e: MFTEntry) =>
    [e.sha256, e.md5, e.sha1].some(h => h && iocMatches.has(h.toLowerCase()))

  const suspiciousCount = data.filter(e => (e.suspicious?.length ?? 0) > 0).length
  const hashedCount = data.filter(e => e.hashed).length
  const iocCount = data.filter(isKnownIOC).length

  const filtered = data
    .map((e, i) => ({ e, i }))
    .filter(({ e }) => {
      const f = filter.toLowerCase()
      const matchFilter = !f || e.file_path.toLowerCase().includes(f) ||
        e.md5?.toLowerCase() === f || e.sha1?.toLowerCase() === f || e.sha256?.toLowerCase() === f
      const matchSus = !suspiciousOnly || (e.suspicious?.length ?? 0) > 0 || isKnownIOC(e)
      return matchFilter && matchSus
    })

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length.toLocaleString()} files</span>
        <span className="text-gray-500 flex items-center gap-1"><Hash className="h-3 w-3" /> {hashedCount.toLocaleString()} hashed</span>
        {iocCount > 0 && <span className="flex items-center gap-1 text-red-400 font-medium"><Database className="h-3 w-3" /> {iocCount} known IOC</span>}
        {suspiciousCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {suspiciousCount} suspicious</span>}
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by path or paste a hash..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        {(suspiciousCount > 0 || iocCount > 0) && (
          <button onClick={() => setSuspiciousOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${suspiciousOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
      </div>

      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Path</th>
              <th className="px-3 py-2 text-right text-gray-500 font-medium">Size</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Modified</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">SHA-256</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Signed</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600">No results</td></tr>
            ) : filtered.map(({ e, i }) => {
              const flagged = (e.suspicious?.length ?? 0) > 0
              const known = isKnownIOC(e)
              const isOpen = expanded.has(i)
              const rowTint = known ? 'bg-red-950/30' : flagged ? 'bg-amber-950/20' : ''
              return (
                <Fragment key={i}>
                  <tr className={`border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors ${rowTint}`}>
                    <td className="px-2 py-1.5 text-center">
                      <input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" disabled={e.is_dir} />
                    </td>
                    <td className="px-2 py-1.5 text-gray-600 cursor-pointer" onClick={() => toggleExp(i)}>
                      <ChevronRight className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} />
                    </td>
                    <td className="px-3 py-1.5 font-mono text-gray-300 break-all max-w-md cursor-pointer" onClick={() => toggleExp(i)}>
                      <span className="inline-flex items-center gap-1.5">
                        {e.is_dir ? <Folder className="h-3.5 w-3.5 text-yellow-500/60 shrink-0" /> : <File className="h-3.5 w-3.5 text-gray-600 shrink-0" />}
                        {e.file_path}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 font-mono text-gray-400 text-right whitespace-nowrap">{fmtSize(e.size)}</td>
                    <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{fmtTime(e.mod_time)}</td>
                    <td className="px-3 py-1.5 font-mono text-emerald-300/80 whitespace-nowrap">
                      {e.hashed ? (
                        <span className="inline-flex items-center gap-1.5">
                          {shortHash(e.sha256)}
                          <button onClick={() => onLookup({ indicator: e.sha256!, type: 'hash' })} className="text-gray-600 hover:text-purple-400" title="Look up on VirusTotal"><ShieldQuestion className="h-3 w-3" /></button>
                          <button onClick={() => copy('SHA-256', e.sha256)} className="text-gray-600 hover:text-emerald-400"><Copy className="h-3 w-3" /></button>
                        </span>
                      ) : <span className="text-gray-600">{e.is_dir ? '—' : 'not hashed'}</span>}
                    </td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">{e.signature ? <span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature}</span> : <span className="text-gray-600">—</span>}</td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">
                      {known && <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 text-xs font-medium"><Database className="h-2.5 w-2.5" /> Known IOC</span>}
                      {!known && flagged && <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-medium"><AlertTriangle className="h-2.5 w-2.5" /> Suspicious</span>}
                      {!known && !flagged && <span className="text-emerald-500/50 text-xs">OK</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-gray-950/60">
                      <td colSpan={2}></td>
                      <td colSpan={6} className="px-4 py-3 space-y-2">
                        <div className="grid grid-cols-1 lg:grid-cols-3 gap-x-6 gap-y-1 text-xs">
                          <div><span className="text-gray-500">Created:</span> <span className="text-gray-300">{fmtTime(e.created)}</span></div>
                          {e.signature && <div><span className="text-gray-500">Signature:</span> <span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature}</span></div>}
                          <div><span className="text-gray-500">Modified:</span> <span className="text-gray-300">{fmtTime(e.mod_time)}</span></div>
                          <div><span className="text-gray-500">Accessed:</span> <span className="text-gray-300">{fmtTime(e.accessed)}</span></div>
                        </div>
                        {(e.attributes?.length ?? 0) > 0 && (
                          <div className="flex flex-wrap items-center gap-1.5">
                            <span className="text-gray-500 text-xs">Attributes:</span>
                            {e.attributes!.map(a => <span key={a} className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 text-[10px]">{a}</span>)}
                          </div>
                        )}
                        {e.hashed ? (
                          <div className="space-y-1 pt-1">
                            <HashRow algo="md5" value={e.md5} onLookup={onLookup} />
                            <HashRow algo="sha1" value={e.sha1} onLookup={onLookup} />
                            <HashRow algo="sha256" value={e.sha256} onLookup={onLookup} />
                          </div>
                        ) : <p className="text-gray-600 text-xs">{e.is_dir ? 'Directory — no content hash.' : 'File not hashed (too large or unreadable).'}</p>}
                        {flagged && (
                          <div className="flex flex-wrap items-center gap-1.5 pt-1">
                            <span className="text-amber-400 text-xs font-medium">Flags:</span>
                            {e.suspicious!.map((r, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px]">{r}</span>)}
                          </div>
                        )}
                        {!e.is_dir && (
                          <div className="pt-2">
                            <button onClick={() => onTrace(e.name, 0)} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-700/80 hover:bg-emerald-700 text-white" title="Reconstruct where this file came from (which process created/ran it, when)">
                              <GitBranch className="h-3.5 w-3.5" /> Trace origin
                            </button>
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Prefetch table ────────────────────────────────────────────────────────────
function PrefetchTable({ data, iocMatches, onLookup, selected, onToggle, onTrace }: {
  data: PrefetchEntry[]
  iocMatches: Set<string>
  onLookup: (t: LookupTarget) => void
  selected: Set<number>
  onToggle: (i: number) => void
  onTrace: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const toggleExp = (i: number) => setExpanded(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const isKnownIOC = (e: PrefetchEntry) =>
    [e.exe_sha256, e.sha256].some(h => h && iocMatches.has(h.toLowerCase()))
  const isThreat = (e: PrefetchEntry) => e.suspicious || isKnownIOC(e)
  const filtered = data.map((e, i) => ({ e, i })).filter(({ e }) =>
    (!filter || e.executable.toLowerCase().includes(filter.toLowerCase())) && (!threatsOnly || isThreat(e)))
  const suspiciousCount = data.filter(e => e.suspicious).length
  const iocCount = data.filter(isKnownIOC).length
  const threatCount = data.filter(isThreat).length

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length} prefetch entries</span>
        {iocCount > 0 && <span className="flex items-center gap-1 text-red-400 font-medium"><Database className="h-3 w-3" /> {iocCount} known IOC</span>}
        {suspiciousCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {suspiciousCount} suspicious</span>}
        <span className="text-gray-600">from <code className="text-purple-400 bg-purple-500/10 px-1 rounded">C:\Windows\Prefetch</code></span>
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by executable name..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        {threatCount > 0 && (
          <button onClick={() => setThreatsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${threatsOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
      </div>

      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Executable</th>
              <th className="px-3 py-2 text-right text-gray-500 font-medium">Runs</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Last Run</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Version</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">SHA-256 (exe)</th>
            </tr>
          </thead>
          <tbody>
            {filtered.length === 0 ? (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-gray-600">No results</td></tr>
            ) : filtered.map(({ e, i }) => {
              const isOpen = expanded.has(i)
              const known = isKnownIOC(e)
              return (
                <Fragment key={i}>
                  <tr className={`border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors ${known ? 'bg-red-950/30' : e.suspicious ? 'bg-amber-950/20' : ''}`}>
                    <td className="px-2 py-1.5 text-center">
                      <input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" />
                    </td>
                    <td className="px-2 py-1.5 text-gray-600 cursor-pointer" onClick={() => toggleExp(i)}><ChevronRight className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} /></td>
                    <td className="px-3 py-1.5 font-mono font-medium cursor-pointer" onClick={() => toggleExp(i)}>
                      <span className="inline-flex items-center gap-2">
                        {known ? <Database className="h-3.5 w-3.5 text-red-400 shrink-0" /> : e.suspicious ? <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" /> : <Clock className="h-3.5 w-3.5 text-gray-700 shrink-0" />}
                        <span className={known ? 'text-red-300' : e.suspicious ? 'text-amber-300' : 'text-gray-200'}>{e.executable}</span>
                        {known && <span className="px-1.5 py-0.5 rounded bg-red-500/20 border border-red-500/40 text-red-400 text-[10px]">Known IOC</span>}
                        {!known && e.suspicious && <span className="px-1.5 py-0.5 rounded bg-amber-500/20 border border-amber-500/30 text-amber-400 text-[10px]">Suspicious</span>}
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-gray-300">{e.run_count > 0 ? e.run_count : '—'}</td>
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap font-mono">{fmtTime(e.last_run_time)}</td>
                    <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{e.version || '—'}{e.compressed && <span className="ml-1 text-[10px] text-gray-600">(MAM)</span>}</td>
                    <td className="px-3 py-1.5 font-mono text-emerald-300/80 whitespace-nowrap">
                      {(() => {
                        const primary = e.exe_hashed ? e.exe_sha256! : e.sha256
                        const isExe = !!e.exe_hashed
                        return (
                          <span className="inline-flex items-center gap-1.5" title={isExe ? `Executable: ${e.exe_path}` : 'Hash of the .pf artifact (executable not resolved)'}>
                            {shortHash(primary)}
                            <span className={`text-[9px] px-1 rounded ${isExe ? 'bg-emerald-500/15 text-emerald-400' : 'bg-gray-700 text-gray-400'}`}>{isExe ? 'exe' : '.pf'}</span>
                            <button onClick={() => onLookup({ indicator: primary, type: 'hash' })} className="text-gray-600 hover:text-purple-400" title="Look up on VirusTotal"><ShieldQuestion className="h-3 w-3" /></button>
                            <button onClick={() => copy('SHA-256', primary)} className="text-gray-600 hover:text-emerald-400"><Copy className="h-3 w-3" /></button>
                          </span>
                        )
                      })()}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-gray-950/60">
                      <td colSpan={2}></td>
                      <td colSpan={5} className="px-4 py-3 space-y-2">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-1 text-xs">
                          <div><span className="text-gray-500">Prefetch file:</span> <span className="font-mono text-gray-300">{e.prefetch_file}</span></div>
                          <div><span className="text-gray-500">Prefetch hash:</span> <span className="font-mono text-gray-300">{e.hash || '—'}</span></div>
                          <div><span className="text-gray-500">.pf size:</span> <span className="text-gray-300">{fmtSize(e.size)}</span></div>
                          <div><span className="text-gray-500">.pf modified:</span> <span className="text-gray-300">{fmtTime(e.pf_mod_time)}</span></div>
                        </div>
                        {(e.last_run_times?.length ?? 0) > 0 && (
                          <div className="pt-1">
                            <span className="text-gray-500 text-xs">Last {e.last_run_times!.length} run times:</span>
                            <div className="flex flex-wrap gap-1.5 mt-1">
                              {e.last_run_times!.map((t, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 font-mono text-[10px]">{fmtTime(t)}</span>)}
                            </div>
                          </div>
                        )}
                        {!e.parsed && <p className="text-amber-400/70 text-[11px]">Binary body could not be fully decoded — showing filename + hashes only.</p>}
                        {e.exe_hashed ? (
                          <div className="pt-1 space-y-1">
                            <div className="text-xs"><span className="text-gray-500">Executable:</span> <span className="font-mono text-gray-300 break-all">{e.exe_path}</span></div>
                            <p className="text-[10px] text-emerald-400/70">Resolved executable on disk — true content hash:</p>
                            <HashRow algo="exe md5" value={e.exe_md5} onLookup={onLookup} />
                            <HashRow algo="exe sha256" value={e.exe_sha256} onLookup={onLookup} />
                          </div>
                        ) : (
                          <p className="text-[11px] text-gray-600 pt-1">{e.exe_path ? `Referenced exe: ${e.exe_path} (not found on disk to hash)` : 'Executable path not resolved.'}</p>
                        )}
                        <div className="space-y-1 pt-1">
                          <p className="text-[10px] text-gray-500">Prefetch artifact (.pf) hashes:</p>
                          <HashRow algo="md5" value={e.md5} onLookup={onLookup} />
                          <HashRow algo="sha256" value={e.sha256} onLookup={onLookup} />
                        </div>
                        <div className="pt-2">
                          <button onClick={() => onTrace(e.executable, 0)} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-700/80 hover:bg-emerald-700 text-white" title="Reconstruct this executable's origin (which process/user ran it, when)">
                            <GitBranch className="h-3.5 w-3.5" /> Trace origin
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Process table (lineage tree + lineage/owner/cmdline/hash) ─────────────────
function ProcessTable({ data, iocMatches, onLookup, selected, onToggle, onKill, onTrace }: {
  data: ProcessEntry[]
  iocMatches: Set<string>
  onLookup: (t: LookupTarget) => void
  selected: Set<number>
  onToggle: (i: number) => void
  onKill: (pid: number, name: string) => void
  onTrace: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const toggleExp = (i: number) => setExpanded(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const isKnownIOC = (e: ProcessEntry) => !!e.sha256 && iocMatches.has(e.sha256.toLowerCase())
  const isThreat = (e: ProcessEntry) => isKnownIOC(e) || (e.suspicious?.length ?? 0) > 0

  // Index by original position so selection/expansion keys stay stable.
  const indexed = data.map((e, i) => ({ e, i }))
  const pidSet = new Set(data.map(e => e.pid))

  // Build a process-tree ordering (DFS) with depth, unless filtering/searching.
  const filtering = !!filter || threatsOnly
  let rows: { e: ProcessEntry; i: number; depth: number }[]
  if (filtering) {
    const f = filter.toLowerCase()
    rows = indexed
      .filter(({ e }) => {
        const matchF = !f || e.name.toLowerCase().includes(f) || e.cmdline.toLowerCase().includes(f) ||
          e.user.toLowerCase().includes(f) || String(e.pid).includes(f) || e.sha256?.toLowerCase() === f
        return matchF && (!threatsOnly || isThreat(e))
      })
      .map(({ e, i }) => ({ e, i, depth: 0 }))
  } else {
    const childrenOf = new Map<number, { e: ProcessEntry; i: number }[]>()
    for (const it of indexed) {
      const arr = childrenOf.get(it.e.ppid) ?? []
      arr.push(it); childrenOf.set(it.e.ppid, arr)
    }
    const roots = indexed.filter(({ e }) => e.ppid === 0 || !pidSet.has(e.ppid))
    rows = []
    const seen = new Set<number>()
    const walk = (it: { e: ProcessEntry; i: number }, depth: number) => {
      if (seen.has(it.e.pid)) return
      seen.add(it.e.pid)
      rows.push({ ...it, depth })
      for (const ch of (childrenOf.get(it.e.pid) ?? [])) walk(ch, depth + 1)
    }
    roots.forEach(r => walk(r, 0))
    // Any process not reached (orphaned cycle) — append flat.
    indexed.forEach(it => { if (!seen.has(it.e.pid)) rows.push({ ...it, depth: 0 }) })
  }

  const threatCount = data.filter(isThreat).length
  const iocCount = data.filter(isKnownIOC).length

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length} processes</span>
        {iocCount > 0 && <span className="flex items-center gap-1 text-red-400 font-medium"><Database className="h-3 w-3" /> {iocCount} known IOC</span>}
        {threatCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {threatCount} flagged</span>}
        {!filtering && <span className="text-gray-600">tree view (parent → child)</span>}
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by name / cmdline / user / PID / hash..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        {threatCount > 0 && (
          <button onClick={() => setThreatsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${threatsOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
      </div>

      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 w-6"></th>
              <th className="px-3 py-2 text-right text-gray-500 font-medium">PID</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Process</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">User</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Parent</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Command Line</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Signed</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={9} className="px-3 py-8 text-center text-gray-600">No results</td></tr>
            ) : rows.map(({ e, i, depth }) => {
              const known = isKnownIOC(e)
              const flagged = (e.suspicious?.length ?? 0) > 0
              const isOpen = expanded.has(i)
              const tint = known ? 'bg-red-950/30' : flagged ? 'bg-amber-950/20' : ''
              return (
                <Fragment key={i}>
                  <tr className={`border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors ${tint}`}>
                    <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" /></td>
                    <td className="px-2 py-1.5 text-gray-600 cursor-pointer" onClick={() => toggleExp(i)}><ChevronRight className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} /></td>
                    <td className="px-3 py-1.5 text-right font-mono text-gray-400">{e.pid}</td>
                    <td className="px-3 py-1.5 font-mono cursor-pointer" onClick={() => toggleExp(i)} style={{ paddingLeft: `${12 + depth * 16}px` }}>
                      <span className="inline-flex items-center gap-1.5">
                        {known ? <Database className="h-3.5 w-3.5 text-red-400 shrink-0" /> : flagged ? <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" /> : <span className="text-gray-700">{depth > 0 ? '└' : '●'}</span>}
                        <span className={known ? 'text-red-300 font-medium' : flagged ? 'text-amber-300 font-medium' : 'text-gray-200'}>{e.name}</span>
                      </span>
                    </td>
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">{e.user || '—'}</td>
                    <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{e.parent_name || '—'}<span className="text-gray-700"> ({e.ppid})</span></td>
                    <td className="px-3 py-1.5 font-mono text-gray-400 max-w-xs truncate" title={e.cmdline}>{e.cmdline || '—'}</td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">{e.signature ? <span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature}</span> : <span className="text-gray-600">—</span>}</td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">
                      {known ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 text-xs font-medium"><Database className="h-2.5 w-2.5" /> IOC</span>
                        : flagged ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-medium"><AlertTriangle className="h-2.5 w-2.5" /> Flag</span>
                        : <span className="text-emerald-500/50 text-xs">OK</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-gray-950/60">
                      <td colSpan={2}></td>
                      <td colSpan={7} className="px-4 py-3 space-y-2">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-1 text-xs">
                          <div><span className="text-gray-500">Image path:</span> <span className="font-mono text-gray-300 break-all">{e.path || '—'}</span></div>
                          <div><span className="text-gray-500">Signature:</span> <span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature || '—'}</span></div>
                          <div><span className="text-gray-500">User:</span> <span className="text-gray-300">{e.user || '—'}</span></div>
                          <div><span className="text-gray-500">Parent:</span> <span className="text-gray-300">{e.parent_name || '—'} (PID {e.ppid})</span></div>
                          <div><span className="text-gray-500">Started:</span> <span className="text-gray-300">{fmtTime(e.created)}</span></div>
                          <div><span className="text-gray-500">Memory:</span> <span className="text-gray-300">{fmtSize(e.mem_kb * 1024)}</span></div>
                        </div>
                        <div className="text-xs">
                          <span className="text-gray-500">Command line:</span>
                          <div className="flex items-start gap-2 mt-0.5">
                            <code className="font-mono text-amber-300/80 break-all flex-1">{e.cmdline || '—'}</code>
                            {e.cmdline && <button onClick={() => copy('Command line', e.cmdline)} className="text-gray-600 hover:text-emerald-400 shrink-0"><Copy className="h-3.5 w-3.5" /></button>}
                          </div>
                        </div>
                        {e.hashed ? (
                          <div className="space-y-1 pt-1">
                            <p className="text-[10px] text-emerald-400/70">Executable hash (for IOC / VirusTotal):</p>
                            <HashRow algo="md5" value={e.md5} onLookup={onLookup} />
                            <HashRow algo="sha256" value={e.sha256} onLookup={onLookup} />
                          </div>
                        ) : <p className="text-[11px] text-gray-600 pt-1">{e.path ? 'Executable not hashed (protected / too large).' : 'No image path (protected/system process).'}</p>}
                        {flagged && (
                          <div className="flex flex-wrap items-center gap-1.5 pt-1">
                            <span className="text-amber-400 text-xs font-medium">Flags:</span>
                            {e.suspicious!.map((r, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px]">{r}</span>)}
                          </div>
                        )}
                        <div className="pt-2 flex items-center gap-2">
                          <button onClick={() => onTrace(e.name, e.pid)} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-700/80 hover:bg-emerald-700 text-white" title="Reconstruct where this process came from (parent chain, user, start time, related traces)">
                            <GitBranch className="h-3.5 w-3.5" /> Trace origin
                          </button>
                          <button onClick={() => onKill(e.pid, e.name)} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-red-600/90 hover:bg-red-600 text-white" title="Terminate this process on the endpoint (containment)">
                            <Ban className="h-3.5 w-3.5" /> Terminate process
                          </button>
                        </div>
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Autoruns / Persistence table ──────────────────────────────────────────────
const sigBadge = (s?: string) =>
  s === 'Signed' ? 'bg-emerald-500/15 text-emerald-400'
  : s === 'Untrusted' ? 'bg-red-500/20 text-red-400'
  : s === 'Unsigned' ? 'bg-gray-700 text-gray-300'
  : 'bg-gray-800 text-gray-500'

// autorunKey is the stable identity of an autostart entry, used to diff a scan
// against the saved baseline (drift detection).
const autorunKey = (e: AutorunEntry) => `${e.category}|${e.location}|${e.command}`.toLowerCase()

function AutorunsTable({ data, iocMatches, onLookup, selected, onToggle, driftKeys, onTrace }: {
  data: AutorunEntry[]
  iocMatches: Set<string>
  onLookup: (t: LookupTarget) => void
  selected: Set<number>
  onToggle: (i: number) => void
  driftKeys?: Set<string> | null
  onTrace: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [cat, setCat] = useState('all')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const [driftOnly, setDriftOnly] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const toggleExp = (i: number) => setExpanded(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const isKnownIOC = (e: AutorunEntry) => !!e.sha256 && iocMatches.has(e.sha256.toLowerCase())
  const isThreat = (e: AutorunEntry) => isKnownIOC(e) || (e.suspicious?.length ?? 0) > 0
  const isNew = (e: AutorunEntry) => !!driftKeys && driftKeys.has(autorunKey(e))
  const categories = Array.from(new Set(data.map(e => e.category)))

  const rows = data.map((e, i) => ({ e, i })).filter(({ e }) => {
    const f = filter.toLowerCase()
    const mf = !f || e.name.toLowerCase().includes(f) || e.command.toLowerCase().includes(f) || e.image_path.toLowerCase().includes(f) || e.sha256?.toLowerCase() === f
    return mf && (cat === 'all' || e.category === cat) && (!threatsOnly || isThreat(e)) && (!driftOnly || isNew(e))
  })
  const threatCount = data.filter(isThreat).length
  const iocCount = data.filter(isKnownIOC).length

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length} autostart entries</span>
        {iocCount > 0 && <span className="flex items-center gap-1 text-red-400 font-medium"><Database className="h-3 w-3" /> {iocCount} known IOC</span>}
        {threatCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {threatCount} flagged</span>}
        <span className="text-gray-600">{categories.length} categories</span>
      </div>

      <div className="flex flex-wrap items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by name / command / path / hash…"
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        <select value={cat} onChange={e => setCat(e.target.value)} className="text-xs bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-gray-200 focus:outline-none focus:border-purple-500/60">
          <option value="all">All categories</option>
          {categories.map(c => <option key={c} value={c}>{c}</option>)}
        </select>
        {threatCount > 0 && (
          <button onClick={() => setThreatsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${threatsOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
        {driftKeys && driftKeys.size > 0 && (
          <button onClick={() => setDriftOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${driftOnly ? 'bg-orange-500/20 border-orange-500/40 text-orange-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <Zap className="h-3 w-3" /> Drift only ({driftKeys.size})
          </button>
        )}
      </div>

      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Category</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Name</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Image / Command</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Signature</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">SHA-256</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={8} className="px-3 py-8 text-center text-gray-600">No results</td></tr>
            ) : rows.map(({ e, i }) => {
              const known = isKnownIOC(e)
              const flagged = (e.suspicious?.length ?? 0) > 0
              const drifted = isNew(e)
              const isOpen = expanded.has(i)
              const tint = known ? 'bg-red-950/30' : flagged ? 'bg-amber-950/20' : drifted ? 'bg-orange-950/20' : ''
              return (
                <Fragment key={i}>
                  <tr className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${tint}`}>
                    <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" /></td>
                    <td className="px-2 py-1.5 text-gray-600 cursor-pointer" onClick={() => toggleExp(i)}><ChevronRight className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} /></td>
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap"><span className="px-1.5 py-0.5 rounded bg-purple-500/10 text-purple-300 text-[10px]">{e.category}</span></td>
                    <td className="px-3 py-1.5 font-medium text-gray-200 cursor-pointer" onClick={() => toggleExp(i)}>{e.name}{drifted && <span className="ml-1.5 px-1.5 py-0.5 rounded bg-orange-500/20 border border-orange-500/40 text-orange-300 text-[9px] font-bold uppercase">New</span>}{e.user && <span className="text-gray-600 text-[10px] ml-1">({e.user.length > 12 ? '…' + e.user.slice(-10) : e.user})</span>}</td>
                    <td className="px-3 py-1.5 font-mono text-gray-400 max-w-xs truncate cursor-pointer" title={e.command} onClick={() => toggleExp(i)}>{e.image_path || e.command || '—'}</td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap"><span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature || '—'}</span></td>
                    <td className="px-3 py-1.5 font-mono text-emerald-300/80 whitespace-nowrap">
                      {e.hashed ? (
                        <span className="inline-flex items-center gap-1.5">
                          {shortHash(e.sha256)}
                          <button onClick={() => onLookup({ indicator: e.sha256!, type: 'hash' })} className="text-gray-600 hover:text-purple-400" title="Look up on VirusTotal"><ShieldQuestion className="h-3 w-3" /></button>
                          <button onClick={() => copy('SHA-256', e.sha256)} className="text-gray-600 hover:text-emerald-400"><Copy className="h-3 w-3" /></button>
                        </span>
                      ) : <span className="text-gray-600">—</span>}
                    </td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">
                      {known ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 text-xs font-medium"><Database className="h-2.5 w-2.5" /> IOC</span>
                        : flagged ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-medium"><AlertTriangle className="h-2.5 w-2.5" /> Flag</span>
                        : <span className="text-emerald-500/50 text-xs">OK</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-gray-950/60">
                      <td colSpan={2}></td>
                      <td colSpan={6} className="px-4 py-3 space-y-2">
                        <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-6 gap-y-1 text-xs">
                          <div><span className="text-gray-500">Location:</span> <span className="font-mono text-gray-300 break-all">{e.location}</span></div>
                          <div><span className="text-gray-500">Image path:</span> <span className="font-mono text-gray-300 break-all">{e.image_path || '—'}</span></div>
                          <div><span className="text-gray-500">Signature:</span> <span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature || '—'}</span></div>
                          <div><span className="text-gray-500">Enabled:</span> <span className="text-gray-300">{e.enabled ? 'yes' : 'no'}</span></div>
                        </div>
                        <div className="text-xs">
                          <span className="text-gray-500">Command:</span>
                          <div className="flex items-start gap-2 mt-0.5"><code className="font-mono text-amber-300/80 break-all flex-1">{e.command || '—'}</code>{e.command && <button onClick={() => copy('Command', e.command)} className="text-gray-600 hover:text-emerald-400 shrink-0"><Copy className="h-3.5 w-3.5" /></button>}</div>
                          <div className="pt-2"><button onClick={() => onTrace(e.image_path || e.name, 0)} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-700/80 hover:bg-emerald-700 text-white" title="Reconstruct this autostart entry's origin (which process/user, when)"><GitBranch className="h-3.5 w-3.5" /> Trace origin</button></div>
                        </div>
                        {e.hashed && (
                          <div className="space-y-1 pt-1">
                            <HashRow algo="md5" value={e.md5} onLookup={onLookup} />
                            <HashRow algo="sha256" value={e.sha256} onLookup={onLookup} />
                          </div>
                        )}
                        {flagged && (
                          <div className="flex flex-wrap items-center gap-1.5 pt-1">
                            <span className="text-amber-400 text-xs font-medium">Flags:</span>
                            {e.suspicious!.map((r, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px]">{r}</span>)}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Main component ──────────────────────────────────────────────────────────
export function EdgeForensics({ agent }: { agent: Agent }) {
  const [activeTab, setActiveTab] = useState<'mft' | 'prefetch' | 'processes' | 'autoruns' | 'network' | 'dlls' | 'shimcache' | 'browser' | 'containers' | 'linux-triage'>(
    (agent.os || '').toLowerCase().includes('linux') ? 'processes' : 'mft',
  )
  const [loading, setLoading] = useState(false)
  const [mftResults, setMftResults] = useState<MFTEntry[] | null>(null)
  const [prefetchResults, setPrefetchResults] = useState<PrefetchEntry[] | null>(null)
  const [processResults, setProcessResults] = useState<ProcessEntry[] | null>(null)
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)
  const [autorunResults, setAutorunResults] = useState<AutorunEntry[] | null>(null)
  const [dllResults, setDllResults] = useState<DllEntry[] | null>(null)
  const [shimResults, setShimResults] = useState<ShimEntry[] | null>(null)
  const [browserResults, setBrowserResults] = useState<BrowserEntry[] | null>(null)
  const [containerResults, setContainerResults] = useState<any[] | null>(null)
  const [linuxResults, setLinuxResults] = useState<any[] | null>(null)
  const isLinux = (agent.os || '').toLowerCase().includes('linux')
  const [showTriage, setShowTriage] = useState(false)
  const [mftPath, setMftPath] = useState<string>('C:\\Windows\\System32')
  const [iocMatches, setIocMatches] = useState<Set<string>>(new Set())
  const [lookup, setLookup] = useState<LookupTarget | null>(null)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [saveCaseId, setSaveCaseId] = useState<string>(agent.case_id ?? '')
  const [saving, setSaving] = useState(false)
  const [aiTriaging, setAiTriaging] = useState(false)
  const [processLive, setProcessLive] = useState(false)
  const [triaging, setTriaging] = useState(false)
  const [driftKeys, setDriftKeys] = useState<Set<string> | null>(null)
  const [baselineBusy, setBaselineBusy] = useState(false)

  const { data: cases = [] } = useQuery({ queryKey: ['cases'], queryFn: casesApi.list })

  const resetForScan = () => { setSelected(new Set()); setIocMatches(new Set()) }
  const switchTab = (t: 'mft' | 'prefetch' | 'processes' | 'autoruns' | 'network' | 'dlls' | 'shimcache' | 'browser' | 'containers' | 'linux-triage') => { setActiveTab(t); setSelected(new Set()) }
  const toggleSelect = (i: number) => setSelected(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  // After a scan, check all hashes against the IOC store to highlight matches.
  const checkIOCs = async (values: string[]) => {
    const uniq = Array.from(new Set(values.filter(Boolean).map(v => v.toLowerCase()))).slice(0, 5000)
    if (uniq.length === 0) return
    try {
      const res = await intelApi.matchIOCs(uniq)
      if (res.count > 0) {
        setIocMatches(new Set(Object.keys(res.matches)))
        toast.error(`${res.count} value(s) match your IOC database`, { icon: '🚨' })
      }
    } catch { /* non-fatal */ }
  }

  const handleMftScan = async () => {
    setLoading(true); setMftResults(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseMFT(agent.id, mftPath.trim() || undefined)
      const arr: MFTEntry[] = Array.isArray(data) ? data : [data]
      setMftResults(arr)
      toast.success(`File scan complete — ${arr.length} files`)
      checkIOCs(arr.flatMap(e => [e.sha256, e.md5, e.sha1].filter(Boolean) as string[]))
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const handlePrefetchScan = async () => {
    setLoading(true); setPrefetchResults(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parsePrefetch(agent.id)
      const arr: PrefetchEntry[] = Array.isArray(data) ? data : [data]
      setPrefetchResults(arr)
      toast.success(`Prefetch scan complete — ${arr.length} entries`)
      checkIOCs(arr.flatMap(e => [e.exe_sha256, e.sha256].filter(Boolean) as string[]))
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const handleProcessScan = async () => {
    setLoading(true); setProcessResults(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseProcessScan(agent.id)
      const arr: ProcessEntry[] = Array.isArray(data) ? data : [data]
      setProcessResults(arr)
      toast.success(`Process snapshot complete — ${arr.length} processes`)
      checkIOCs(arr.map(e => e.sha256).filter(Boolean) as string[])
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  // Baseline & drift (autoruns): save a known-good snapshot, then compare a later
  // scan against it to highlight NEW autostart entries (persistence drift).
  const handleSetBaseline = async () => {
    if (!autorunResults?.length) { toast.error('Run an Autoruns scan first'); return }
    setBaselineBusy(true)
    try {
      await agentsApi.setBaseline(agent.id, 'autoruns', JSON.stringify(autorunResults))
      toast.success('Autoruns baseline saved for this agent')
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setBaselineBusy(false) }
  }
  const handleCompareBaseline = async () => {
    if (driftKeys) { setDriftKeys(null); return } // toggle comparison off
    if (!autorunResults?.length) { toast.error('Run an Autoruns scan first'); return }
    setBaselineBusy(true)
    try {
      const bl = await agentsApi.getBaseline(agent.id, 'autoruns')
      const baseArr: AutorunEntry[] = JSON.parse(bl.data || '[]')
      const baseSet = new Set(baseArr.map(autorunKey))
      const newKeys = new Set(autorunResults.filter(e => !baseSet.has(autorunKey(e))).map(autorunKey))
      setDriftKeys(newKeys)
      if (newKeys.size) toast.error(`${newKeys.size} new autostart entr${newKeys.size === 1 ? 'y' : 'ies'} since baseline`, { icon: '🚨' })
      else toast.success('No drift — autoruns match the baseline')
    } catch (err: any) {
      if (err?.response?.status === 404) toast.error('No baseline set yet — click "Set baseline" first')
      else toast.error(getErrorMessage(err))
    } finally { setBaselineBusy(false) }
  }

  const handleContainerScan = async () => {
    setLoading(true); setContainerResults(null); resetForScan()
    try {
      const data = await agentsApi.parseContainers(agent.id)
      const arr: any[] = Array.isArray(data) ? data : [data]
      setContainerResults(arr)
      toast.success(`Container scan complete — ${arr.length} container(s)`)
      // Look up the full digests as well: a 12-char short image id can never
      // match a sha256 indicator held in the IOC store.
      checkIOCs(arr.flatMap(c => [c.image_digest, c.image_repo_digest, c.image_id]).filter(Boolean) as string[])
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const handleLinuxTriageScan = async () => {
    setLoading(true); setLinuxResults(null); resetForScan()
    try {
      const data = await agentsApi.parseLinuxTriage(agent.id)
      const arr: any[] = Array.isArray(data) ? data : [data]
      setLinuxResults(arr)
      toast.success(`Linux triage complete — ${arr.length} artifact(s)`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const handleAutorunsScan = async () => {
    setLoading(true); setAutorunResults(null); setDriftKeys(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseAutoruns(agent.id)
      const arr: AutorunEntry[] = Array.isArray(data) ? data : [data]
      setAutorunResults(arr)
      toast.success(`Autoruns scan complete — ${arr.length} entries`)
      checkIOCs(arr.map(e => e.sha256).filter(Boolean) as string[])
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  // Containment: terminate a process on the endpoint (confirm first).
  const handleKill = async (pid: number, name: string) => {
    if (!window.confirm(`Terminate "${name}" (PID ${pid}) on ${agent.name}?\n\nThis kills the process on the endpoint and cannot be undone.`)) return
    try {
      await agentsApi.killProcess(agent.id, pid)
      toast.success(`Process ${pid} terminated — re-run the scan to refresh`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    }
  }

  const handleDllsScan = async () => {
    setLoading(true); setDllResults(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseDlls(agent.id)
      const arr: DllEntry[] = Array.isArray(data) ? data : [data]
      setDllResults(arr)
      toast.success(`Loaded-DLL scan complete — ${arr.length} modules`)
      checkIOCs(arr.map(e => e.sha256).filter(Boolean) as string[])
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const handleShimScan = async () => {
    setLoading(true); setShimResults(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseShimcache(agent.id)
      const arr: ShimEntry[] = Array.isArray(data) ? data : [data]
      setShimResults(arr)
      toast.success(`Shimcache parsed — ${arr.length} records`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const handleBrowserScan = async () => {
    setLoading(true); setBrowserResults(null); resetForScan()
    try {
      toast('Requesting UAC Elevation on Agent...', { icon: '🛡️' })
      const data = await agentsApi.parseBrowser(agent.id)
      const arr: BrowserEntry[] = Array.isArray(data) ? data : (data ? [data] : [])
      setBrowserResults(arr)
      toast.success(`Browser history parsed — ${arr.length} URLs`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  // Quick Triage: one click runs Processes + Autoruns + Prefetch + Network back
  // to back, auto-matches IOCs, populates the tabs, and (if a case is linked)
  // auto-saves a triage summary plus every flagged / IOC-matched artifact.
  const handleQuickTriage = async () => {
    if (agent.status !== 'online') { toast.error('Agent is offline'); return }
    setTriaging(true)
    const caseId = saveCaseId || agent.case_id || ''
    const failed: string[] = []
    // Each step runs independently: a failure (e.g. a 502 / gateway timeout on one
    // scan) is recorded and skipped so the rest of the triage still completes and
    // partial results are kept.
    const step = async <T,>(label: string, fn: () => Promise<any>, set: (v: T[]) => void): Promise<T[]> => {
      try {
        const d = await fn()
        const arr: T[] = Array.isArray(d) ? d : (d ? [d] : [])
        set(arr)
        return arr
      } catch (err: any) {
        failed.push(`${label} (${err?.response?.status || err?.message || 'error'})`)
        return []
      }
    }
    try {
      toast('Quick Triage — Processes → Autoruns → Prefetch → Network…', { icon: '🚑' })
      const procs = await step<ProcessEntry>('Processes', () => agentsApi.parseProcessScan(agent.id), setProcessResults)
      const autos = await step<AutorunEntry>('Autoruns', () => agentsApi.parseAutoruns(agent.id), setAutorunResults)
      const pfs = await step<PrefetchEntry>('Prefetch', () => agentsApi.parsePrefetch(agent.id), setPrefetchResults)
      let hosts: ReturnType<typeof aggregateHosts> = []
      try {
        const netData = await agentsApi.parseNetwork(agent.id)
        hosts = aggregateHosts(netData?.connections ?? [])
      } catch (err: any) {
        failed.push(`Network (${err?.response?.status || err?.message || 'error'})`)
      }

      const hashes = [...procs.map(p => p.sha256), ...autos.map(a => a.sha256), ...pfs.map(p => p.exe_sha256)].filter(Boolean) as string[]
      const extHosts = hosts.filter(h => h.routable)
      let iocSet = new Set<string>()
      try {
        const m = await intelApi.matchIOCs([...hashes, ...extHosts.map(h => h.addr)].map(v => v.toLowerCase()).slice(0, 5000))
        if (m.count > 0) iocSet = new Set(Object.keys(m.matches))
      } catch { /* non-fatal */ }
      setIocMatches(iocSet)

      if (failed.length) toast.error(`Skipped: ${failed.join(', ')}`, { duration: 6000 })

      const isIoc = (h?: string) => !!h && iocSet.has(h.toLowerCase())
      const flProc = procs.filter(p => (p.suspicious?.length ?? 0) > 0 || isIoc(p.sha256))
      const flAuto = autos.filter(a => (a.suspicious?.length ?? 0) > 0 || isIoc(a.sha256))
      const flPf = pfs.filter(p => p.suspicious || isIoc(p.exe_sha256))
      const flHosts = extHosts.filter(h => iocSet.has(h.addr.toLowerCase()))

      if (caseId && (procs.length || autos.length || pfs.length || extHosts.length)) {
        const items: any[] = [{
          title: `Quick Triage — ${agent.hostname || agent.name}`,
          detail: `Processes: ${procs.length} (${flProc.length} flagged)\nAutoruns: ${autos.length} (${flAuto.length} flagged)\nPrefetch: ${pfs.length} (${flPf.length} flagged)\nExternal hosts: ${extHosts.length} (${flHosts.length} known IOC)`,
          severity: (flHosts.length || flProc.some(p => isIoc(p.sha256)) ? 'high' : 'info') as TimelineSeverity,
          promote_ioc: false,
        }]
        flProc.forEach(p => items.push({
          title: `Process: ${p.name} (PID ${p.pid})`,
          detail: `Image: ${p.path || '—'}\nSignature: ${p.signature || '—'}\nCmd: ${p.cmdline || '—'}${p.suspicious?.length ? `\nFlags: ${p.suspicious.join(', ')}` : ''}`,
          event_time: p.created || undefined,
          severity: (isIoc(p.sha256) ? 'critical' : 'high') as TimelineSeverity,
          value: p.sha256 || undefined, ioc_type: p.sha256 ? 'File-Hash' : undefined, promote_ioc: !!p.sha256,
        }))
        flAuto.forEach(a => items.push({
          title: `Autorun: ${a.name} (${a.category})`,
          detail: `Command: ${a.command}\nImage: ${a.image_path || '—'}\nSignature: ${a.signature || '—'}${a.suspicious?.length ? `\nFlags: ${a.suspicious.join(', ')}` : ''}`,
          severity: (isIoc(a.sha256) ? 'critical' : 'high') as TimelineSeverity,
          value: a.sha256 || undefined, ioc_type: a.sha256 ? 'File-Hash' : undefined, promote_ioc: !!a.sha256,
        }))
        flHosts.forEach(h => items.push({
          title: `Network host: ${h.host || h.addr}`,
          detail: `Remote: ${h.addr}\nReverse DNS: ${h.host || '—'}\nProcesses: ${h.processes.join(', ') || '—'}`,
          severity: 'critical' as TimelineSeverity,
          value: h.addr, ioc_type: h.addr.includes(':') ? 'IPv6-Addr' : 'IPv4-Addr', promote_ioc: true,
        }))
        const res = await timelineApi.importArtifacts(caseId, { source: 'edge-forensics:triage', host: agent.hostname || agent.name, items })
        toast.success(`Triage saved — ${res.events_created} event(s) · ${res.iocs_promoted} new IOC(s)${failed.length ? ` · ${failed.length} step(s) skipped` : ''}`)
      } else {
        toast.success(`Triage done — ${flProc.length + flAuto.length + flPf.length + flHosts.length} flagged${failed.length ? ` · ${failed.length} step(s) skipped` : ''}. ${caseId ? '' : 'Link a case to auto-save.'}`)
      }
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setTriaging(false) }
  }

  // Build timeline items from the currently-selected rows of the active tab.
  // Shared by "Save to Case" (direct import) and "AI triage" (findings extraction).
  const buildSelectedItems = (): any[] => {
      let items: any[] | undefined
      if (activeTab === 'mft' && mftResults) {
        items = Array.from(selected).map(i => mftResults[i]).filter(Boolean).map(e => {
          const known = [e.sha256, e.md5, e.sha1].some(h => h && iocMatches.has(h.toLowerCase()))
          const sev: TimelineSeverity = known ? 'critical' : (e.suspicious?.length ? 'high' : 'info')
          return {
            title: `File: ${e.name}`,
            detail: `Path: ${e.file_path}\nSize: ${e.size}\nSHA256: ${e.sha256 || '—'}\nMD5: ${e.md5 || '—'}\nSHA1: ${e.sha1 || '—'}${e.signature ? `\nSignature: ${e.signature}` : ''}${e.suspicious?.length ? `\nFlags: ${e.suspicious.join(', ')}` : ''}`,
            event_time: e.mod_time,
            severity: sev,
            value: e.sha256 || undefined,
            ioc_type: e.sha256 ? 'File-Hash' : undefined,
            promote_ioc: !!e.sha256,
          }
        })
      } else if (activeTab === 'prefetch' && prefetchResults) {
        items = Array.from(selected).map(i => prefetchResults[i]).filter(Boolean).map(e => {
          const known = [e.exe_sha256, e.sha256].some(h => h && iocMatches.has(h.toLowerCase()))
          // Prefer the resolved executable hash as the promoted IOC; fall back to
          // the executable name when the binary couldn't be located on disk.
          const value = e.exe_hashed ? e.exe_sha256 : e.executable
          const ioc_type = e.exe_hashed ? 'File-Hash' : 'File-Name'
          return {
            title: `Executed: ${e.executable}`,
            detail: `Runs: ${e.run_count}\nLast run: ${fmtTime(e.last_run_time)}\nPrefetch: ${e.prefetch_file}\nVersion: ${e.version}` +
              (e.exe_hashed ? `\nExe path: ${e.exe_path}\nExe SHA256: ${e.exe_sha256}\nExe MD5: ${e.exe_md5}` : '') +
              `\nSHA256(.pf): ${e.sha256}`,
            event_time: e.last_run_time,
            severity: (known ? 'critical' : e.suspicious ? 'high' : 'info') as TimelineSeverity,
            value,
            ioc_type,
            promote_ioc: true,
          }
        })
      } else if (activeTab === 'autoruns' && autorunResults) {
        items = Array.from(selected).map(i => autorunResults[i]).filter(Boolean).map(e => {
          const known = !!e.sha256 && iocMatches.has(e.sha256.toLowerCase())
          return {
            title: `Autorun: ${e.name} (${e.category})`,
            detail: `Category: ${e.category}\nLocation: ${e.location}\nCommand: ${e.command}\nImage: ${e.image_path || '—'}\nSignature: ${e.signature || '—'}` +
              (e.hashed ? `\nSHA256: ${e.sha256}\nMD5: ${e.md5}` : '') +
              (e.suspicious?.length ? `\nFlags: ${e.suspicious.join(', ')}` : ''),
            event_time: undefined,
            severity: (known ? 'critical' : e.suspicious?.length ? 'high' : 'info') as TimelineSeverity,
            value: e.sha256 || undefined,
            ioc_type: e.sha256 ? 'File-Hash' : undefined,
            promote_ioc: !!e.sha256,
          }
        })
      } else if (activeTab === 'dlls' && dllResults) {
        items = Array.from(selected).map(i => dllResults[i]).filter(Boolean).map(e => {
          const known = !!e.sha256 && iocMatches.has(e.sha256.toLowerCase())
          return {
            title: `DLL: ${e.name}`,
            detail: `Path: ${e.path}\nSignature: ${e.signature || '—'}\nLoaded by: ${e.process_count} process(es)${e.processes?.length ? ` (${e.processes.slice(0, 8).join(', ')})` : ''}` +
              (e.hashed ? `\nSHA256: ${e.sha256}\nMD5: ${e.md5}` : '') +
              (e.suspicious?.length ? `\nFlags: ${e.suspicious.join(', ')}` : ''),
            event_time: undefined,
            severity: (known ? 'critical' : e.suspicious?.length ? 'high' : 'info') as TimelineSeverity,
            value: e.sha256 || undefined,
            ioc_type: e.sha256 ? 'File-Hash' : undefined,
            promote_ioc: !!e.sha256,
          }
        })
      } else if (activeTab === 'shimcache' && shimResults) {
        items = Array.from(selected).map(i => shimResults[i]).filter(Boolean).map(e => ({
          title: `Shimcache: ${e.name}`,
          detail: `Path: ${e.path}\nFile modified: ${e.last_modified ? fmtTime(e.last_modified) : '—'}${e.suspicious?.length ? `\nFlags: ${e.suspicious.join(', ')}` : ''}`,
          event_time: e.last_modified || undefined,
          severity: (e.suspicious?.length ? 'high' : 'info') as TimelineSeverity,
          value: e.path,
          ioc_type: 'File-Name',
          promote_ioc: true,
        }))
      } else if (activeTab === 'processes' && processResults) {
        items = Array.from(selected).map(i => processResults[i]).filter(Boolean).map(e => {
          const known = !!e.sha256 && iocMatches.has(e.sha256.toLowerCase())
          return {
            title: `Process: ${e.name} (PID ${e.pid})`,
            detail: `User: ${e.user || '—'}\nParent: ${e.parent_name || '—'} (PID ${e.ppid})\nImage: ${e.path || '—'}\nSignature: ${e.signature || '—'}\nCommand line: ${e.cmdline || '—'}\nStarted: ${fmtTime(e.created)}` +
              (e.hashed ? `\nSHA256: ${e.sha256}\nMD5: ${e.md5}` : '') +
              (e.suspicious?.length ? `\nFlags: ${e.suspicious.join(', ')}` : ''),
            event_time: e.created || undefined,
            severity: (known ? 'critical' : e.suspicious?.length ? 'high' : 'info') as TimelineSeverity,
            value: e.sha256 || undefined,
            ioc_type: e.sha256 ? 'File-Hash' : undefined,
            promote_ioc: !!e.sha256,
          }
        })
      } else if (activeTab === 'containers' && containerResults) {
        items = Array.from(selected).map(i => containerResults[i]).filter(Boolean).map((c: any) => {
          const flags = containerFlags(c, iocMatches)
          const known = flags.includes('IOC-MATCH:image')
          const drift = c.changes_summary
          // Only the full digest is a usable indicator; the short id is a
          // display value and would never match anything downstream.
          const digest = c.image_digest || c.image_repo_digest
          const labels = c.labels && Object.keys(c.labels).length
            ? Object.entries(c.labels).map(([k, v]) => `${k}=${v}`).join(', ')
            : ''
          return {
            title: `Container: ${c.name || c.id} (${c.image})`,
            detail: `Image: ${c.image}\nDigest: ${digest || c.image_id || '—'}\nRuntime: ${c.runtime || '—'}\nState: ${c.state}\nCommand: ${c.command || '—'}\nUser: ${c.user || '(root)'}\nPorts: ${(c.ports || []).join(', ') || '—'}\n` +
              `Mounts: ${(c.mounts || []).map((m: any) => `${m.source}→${m.dest}${m.rw ? '(rw)' : ''}`).join('; ') || '—'}\n` +
              (labels ? `Attribution: ${labels}\n` : '') +
              (c.upper_dir ? `Writable layer: ${c.upper_dir}\n` : '') +
              (drift?.total ? `Filesystem drift: +${drift.added} added, ~${drift.modified} modified, -${drift.deleted} deleted\n` : '') +
              ((c.changes || []).length ? `Notable changes: ${(c.changes || []).slice(0, 15).map((ch: any) => `${ch.kind === 'added' ? '+' : ch.kind === 'deleted' ? '-' : '~'}${ch.path}`).join(', ')}\n` : '') +
              (c.secret_env?.length ? `Secret-looking env: ${c.secret_env.join(', ')}\n` : '') +
              (c.inspect_ok === false ? 'NOTE: inspect unavailable — security fields were not collected for this container\n' : '') +
              (flags.length ? `Risk: ${flags.join(', ')}` : ''),
            event_time: c.created_at || undefined,
            severity: (known || isSevereRisk(flags) ? 'critical' : hasRealRisk(flags) ? 'high' : 'info') as TimelineSeverity,
            value: digest || c.image_id || undefined,
            ioc_type: (digest || c.image_id) ? 'File-Hash' : undefined,
            promote_ioc: !!digest,
          }
        })
      } else if (activeTab === 'linux-triage' && linuxResults) {
        items = Array.from(selected).map(i => linuxResults[i]).filter(Boolean).map((a: any) => ({
          title: `${a.type}: ${a.source}`,
          detail: `Type: ${a.type}\nSource: ${a.source}\nUser: ${a.user || '—'}\n${a.detail}` +
            (a.suspicious?.length ? `\nFlags: ${a.suspicious.join(', ')}` : ''),
          event_time: undefined,
          severity: ((a.suspicious || []).some((s: string) => /preload|reverse-shell|module-not-on-disk|download-pipe/i.test(s)) ? 'critical' : a.suspicious?.length ? 'high' : 'info') as TimelineSeverity,
          value: undefined,
          ioc_type: undefined,
          promote_ioc: false,
        }))
      }
      return items ?? []
  }

  // Save selected rows to the chosen case timeline (+ promote to IOC store).
  const handleSaveToCase = async () => {
    if (!saveCaseId) { toast.error('Select a case first'); return }
    if (selected.size === 0) { toast.error('Select at least one row'); return }
    setSaving(true)
    try {
      const items = buildSelectedItems()
      if (items.length === 0) { toast.error('Nothing to save'); return }
      const res = await timelineApi.importArtifacts(saveCaseId, {
        source: `edge-forensics:${activeTab}`,
        host: agent.hostname || agent.name,
        items,
      })
      toast.success(`Saved ${res.events_created} event(s) · ${res.iocs_promoted} new IOC(s)`)
      setSelected(new Set())
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setSaving(false) }
  }

  // AI-triage the selected rows: run findings extraction over the native forensic
  // evidence and add findings straight to the case timeline (no tool job needed).
  const handleAiTriage = async () => {
    if (!saveCaseId) { toast.error('Select a case first'); return }
    if (selected.size === 0) { toast.error('Select at least one row'); return }
    setAiTriaging(true)
    try {
      const items = buildSelectedItems()
      if (items.length === 0) { toast.error('Nothing to analyze'); return }
      const res = await casesApi.analyzeArtifacts(saveCaseId, {
        source: `edge-forensics:${activeTab}`,
        host: agent.hostname || agent.name,
        items,
      })
      toast.success(`AI: ${res.created} finding(s) → timeline · ${res.iocs_promoted} IOC(s)`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setAiTriaging(false) }
  }

  const quickPaths = ['C:\\Windows\\System32', 'C:\\Windows\\Temp', 'C:\\Users', 'C:\\ProgramData', 'C:\\Windows\\Tasks']

  return (
    <div className="flex flex-col h-full bg-[#151515]">
      {/* Header tabs */}
      <div className="border-b border-gray-800 bg-[#1C1C1E] p-4 flex items-center gap-4">
        {!isLinux && (
        <button onClick={() => switchTab('mft')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'mft' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <HardDrive className="h-4 w-4" /> File Forensics
        </button>)}
        {!isLinux && (
        <button onClick={() => switchTab('prefetch')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'prefetch' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Clock className="h-4 w-4" /> Prefetch
        </button>)}
        <button onClick={() => switchTab('processes')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'processes' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Cpu className="h-4 w-4" /> Processes
        </button>
        <button onClick={() => switchTab('autoruns')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'autoruns' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Power className="h-4 w-4" /> Autoruns
        </button>
        <button onClick={() => switchTab('dlls')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'dlls' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Boxes className="h-4 w-4" /> Loaded DLLs
        </button>
        {!isLinux && (
        <button onClick={() => switchTab('shimcache')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'shimcache' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <History className="h-4 w-4" /> Shimcache
        </button>)}
        <button onClick={() => switchTab('browser')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'browser' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Globe className="h-4 w-4" /> Browser
        </button>
        <button onClick={() => switchTab('network')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'network' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Network className="h-4 w-4" /> Network
        </button>
        {isLinux && (
        <button onClick={() => switchTab('containers')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'containers' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <Boxes className="h-4 w-4" /> Containers
        </button>)}
        {isLinux && (
        <button onClick={() => switchTab('linux-triage')} className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-colors ${activeTab === 'linux-triage' ? 'bg-purple-500/20 text-purple-400 border border-purple-500/30' : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'}`}>
          <ShieldAlert className="h-4 w-4" /> Linux Triage
        </button>)}
        <div className="ml-auto flex items-center gap-2">
          <button onClick={() => setShowTriage(true)} disabled={agent.status !== 'online'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium text-xs bg-amber-600 hover:bg-amber-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            title="KAPE-style collection: gather a full artifact bundle in ONE elevated pass (one UAC) and save it to the case as evidence">
            <Archive className="h-3.5 w-3.5" /> Triage Collection
          </button>
          <button onClick={handleQuickTriage} disabled={triaging || agent.status !== 'online'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md font-medium text-xs bg-emerald-600 hover:bg-emerald-500 text-white transition-colors disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap"
            title="One-click IR snapshot: Processes + Autoruns + Prefetch + Network, auto-IOC-matched and saved to the linked case">
            {triaging ? <><span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Triaging…</> : <><Zap className="h-3.5 w-3.5" /> Quick Triage</>}
          </button>
        </div>
      </div>

      <div className="flex-1 overflow-auto p-6">
        <div className="w-full space-y-6">
          {activeTab === 'network' ? (
            <NetworkRecon agent={agent} cases={cases} onLookup={setLookup} />
          ) : (
          <div className="bg-[#1C1C1E] border border-gray-800 rounded-xl p-6">
            <div className="flex items-start justify-between mb-4 gap-4">
              <div className="min-w-0">
                <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
                  {activeTab === 'mft' ? <HardDrive className="h-5 w-5 text-purple-400" /> : activeTab === 'prefetch' ? <Clock className="h-5 w-5 text-purple-400" /> : activeTab === 'processes' ? <Cpu className="h-5 w-5 text-purple-400" /> : activeTab === 'dlls' ? <Boxes className="h-5 w-5 text-purple-400" /> : activeTab === 'shimcache' ? <History className="h-5 w-5 text-purple-400" /> : activeTab === 'browser' ? <Globe className="h-5 w-5 text-purple-400" /> : <Power className="h-5 w-5 text-purple-400" />}
                  {activeTab === 'mft' ? 'File System Forensics' : activeTab === 'prefetch' ? 'Prefetch Analysis' : activeTab === 'processes' ? 'Process Forensics' : activeTab === 'dlls' ? (isLinux ? 'Loaded Modules' : 'Loaded DLLs') : activeTab === 'shimcache' ? 'Shimcache (App Compat Cache)' : activeTab === 'browser' ? 'Browser History' : activeTab === 'containers' ? 'Container Forensics' : activeTab === 'linux-triage' ? 'Linux Triage' : 'Autoruns / Persistence'}
                </h2>
                <p className="text-sm text-gray-400 mt-1">
                  {activeTab === 'mft'
                    ? 'Deep file metadata + content hashing (MD5/SHA-1/SHA-256), NTFS timestamps, attributes; auto-matched against your IOC store. Requires UAC.'
                    : activeTab === 'prefetch'
                    ? 'Decodes .pf binaries (run count, last-run times, version) + hashes; auto-matched against your IOC store. Requires UAC.'
                    : activeTab === 'processes'
                    ? 'Running-process snapshot with full lineage (parent → child tree), owning user, command line, image path and executable hashes; auto-matched against your IOC store. Requires UAC.'
                    : activeTab === 'dlls'
                    ? 'Loaded modules across every process (ListDLLs-style), deduped + hashed + Authenticode-checked, with DLL-hijack / injection flags; auto-matched against your IOC store. Requires UAC.'
                    : activeTab === 'shimcache'
                    ? 'AppCompatCache (Shimcache) execution evidence — binaries the OS recorded as present/run, with file modified times. Complements Prefetch for execution triage. Requires UAC.'
                    : activeTab === 'browser'
                    ? 'Browser history across all local user profiles (Chrome / Edge / Brave / Firefox) — URL, title, visit count, last-visit time, with attribution to the owning user/profile and suspicion flags. Requires UAC to read other users’ profiles.'
                    : activeTab === 'containers'
                    ? 'Running/stopped containers (Docker / containerd / podman) with misconfiguration flags: privileged, docker-socket mount, host namespaces, dangerous capabilities, secrets in env. Read-only. Requires root / docker group.'
                    : activeTab === 'linux-triage'
                    ? 'Linux persistence + execution history + privilege-escalation surface: shell history, cron & timers, SSH authorized_keys, ld.so.preload, SUID binaries, out-of-tree kernel modules. Read-only. Requires root.'
                    : 'Native autostart / persistence enumeration (Run keys, services, scheduled tasks, startup, Winlogon, IFEO…) with executable hashes + Authenticode signature; auto-matched against your IOC store. Requires UAC.'}
                </p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {activeTab === 'processes' && (
                  <button onClick={() => { if (agent.status !== 'online') { toast.error('Agent is offline'); return } setProcessLive(v => !v) }} disabled={agent.status !== 'online'}
                    className={`flex items-center gap-2 px-3 py-2 rounded-md font-medium text-sm transition-colors disabled:opacity-50 ${processLive ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-gray-800 hover:bg-gray-700 text-gray-200'}`}>
                    <Radio className="h-4 w-4" /> {processLive ? 'Stop Live' : 'Go Live'}
                  </button>
                )}
                <button onClick={activeTab === 'mft' ? handleMftScan : activeTab === 'prefetch' ? handlePrefetchScan : activeTab === 'processes' ? handleProcessScan : activeTab === 'dlls' ? handleDllsScan : activeTab === 'shimcache' ? handleShimScan : activeTab === 'browser' ? handleBrowserScan : activeTab === 'containers' ? handleContainerScan : activeTab === 'linux-triage' ? handleLinuxTriageScan : handleAutorunsScan} disabled={loading || agent.status !== 'online' || (activeTab === 'processes' && processLive)}
                  className="bg-purple-600 hover:bg-purple-700 text-white flex items-center gap-2 px-4 py-2 rounded-md font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
                  {loading ? <><span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</> : <><Play className="h-4 w-4" /> Run Scan</>}
                </button>
              </div>
            </div>

            {activeTab === 'autoruns' && (
              <div className="mb-4 flex flex-wrap items-center gap-2">
                <span className="text-[10px] uppercase tracking-wider text-gray-500 font-bold mr-1">Baseline &amp; drift</span>
                <button onClick={handleSetBaseline} disabled={baselineBusy || !autorunResults?.length}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium bg-gray-800 border border-gray-700 text-gray-300 hover:text-white disabled:opacity-50">
                  <Save className="h-3.5 w-3.5" /> Set baseline
                </button>
                <button onClick={handleCompareBaseline} disabled={baselineBusy || !autorunResults?.length}
                  className={`inline-flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors disabled:opacity-50 ${driftKeys ? 'bg-orange-500/20 border-orange-500/40 text-orange-300' : 'bg-gray-800 border-gray-700 text-gray-300 hover:text-white'}`}>
                  <Zap className="h-3.5 w-3.5" /> {driftKeys ? `Drift: ${driftKeys.size} new (clear)` : 'Compare to baseline'}
                </button>
                <span className="text-[10px] text-gray-600">Save a known-good autoruns set, then compare a later scan to spot new persistence.</span>
              </div>
            )}

            {activeTab === 'mft' && (
              <div className="mb-4 space-y-1.5">
                <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Target path</label>
                <input value={mftPath} onChange={e => setMftPath(e.target.value)} disabled={loading}
                  className="w-full px-3 py-2 text-xs font-mono bg-gray-900 border border-gray-700 rounded-lg text-gray-200 focus:outline-none focus:border-purple-500/60" placeholder="C:\\Windows\\System32" />
                <div className="flex flex-wrap items-center gap-1.5">
                  {quickPaths.map(p => <button key={p} onClick={() => setMftPath(p)} className="text-[10px] px-2 py-0.5 rounded bg-gray-800 text-gray-400 hover:text-white hover:bg-gray-700 transition-colors font-mono">{p}</button>)}
                </div>
              </div>
            )}

            {agent.status !== 'online' && (
              <div className="flex items-center gap-3 p-4 rounded-lg bg-orange-500/10 border border-orange-500/20 mb-4">
                <ShieldAlert className="h-5 w-5 text-orange-400 flex-shrink-0" />
                <p className="text-sm text-orange-200">Agent is offline. Edge Forensics cannot be performed.</p>
              </div>
            )}

            {/* Save-to-case toolbar (appears when rows are selected) */}
            {selected.size > 0 && (
              <div className="flex flex-wrap items-center gap-3 mb-4 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
                <span className="text-xs text-emerald-300 font-medium">{selected.size} selected</span>
                <select value={saveCaseId} onChange={e => setSaveCaseId(e.target.value)} className="text-xs bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-gray-200 focus:outline-none focus:border-emerald-500/60">
                  <option value="">Select case…</option>
                  {cases.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <button onClick={handleSaveToCase} disabled={saving || !saveCaseId}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50">
                  {saving ? <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="h-3.5 w-3.5" />}
                  Save to Case + promote IOC
                </button>
                <button onClick={handleAiTriage} disabled={aiTriaging || !saveCaseId}
                  className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-violet-900/40 hover:bg-violet-900/60 text-violet-200 border border-violet-500/30 rounded-lg disabled:opacity-50"
                  title="Run AI over the selected forensic rows and add findings to the case timeline">
                  {aiTriaging ? <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <BrainCircuit className="h-3.5 w-3.5" />}
                  AI triage → timeline
                </button>
                <button onClick={() => setSelected(new Set())} className="text-xs text-gray-500 hover:text-gray-300">Clear</button>
              </div>
            )}

            {/* Results */}
            {activeTab === 'mft' && mftResults && (
              mftResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><MFTTable data={mftResults} iocMatches={iocMatches} onLookup={setLookup} selected={selected} onToggle={toggleSelect} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no files found.</p></div>
            )}
            {activeTab === 'prefetch' && prefetchResults && (
              prefetchResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><PrefetchTable data={prefetchResults} iocMatches={iocMatches} onLookup={setLookup} selected={selected} onToggle={toggleSelect} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no entries found.</p></div>
            )}
            {activeTab === 'processes' && processLive && <LiveProcessMonitor agent={agent} />}
            {activeTab === 'processes' && !processLive && processResults && (
              processResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><ProcessTable data={processResults} iocMatches={iocMatches} onLookup={setLookup} selected={selected} onToggle={toggleSelect} onKill={handleKill} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no processes found.</p></div>
            )}
            {activeTab === 'autoruns' && autorunResults && (
              autorunResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><AutorunsTable data={autorunResults} iocMatches={iocMatches} onLookup={setLookup} selected={selected} onToggle={toggleSelect} driftKeys={driftKeys} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no autostart entries found.</p></div>
            )}
            {activeTab === 'dlls' && dllResults && (
              dllResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><DllsTable data={dllResults} iocMatches={iocMatches} onLookup={setLookup} selected={selected} onToggle={toggleSelect} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no modules found.</p></div>
            )}
            {activeTab === 'shimcache' && shimResults && (
              shimResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><ShimTable data={shimResults} selected={selected} onToggle={toggleSelect} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no Shimcache records found.</p></div>
            )}
            {activeTab === 'browser' && browserResults && (
              browserResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><BrowserTable data={browserResults} onLookup={setLookup} onTrace={(target, pid) => setTraceTarget({ target, pid })} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Search className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no browser history found.</p></div>
            )}
            {activeTab === 'containers' && containerResults && (
              containerResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><ContainersTable data={containerResults} iocMatches={iocMatches} selected={selected} onToggle={toggleSelect} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><Boxes className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no containers found.</p></div>
            )}
            {activeTab === 'linux-triage' && linuxResults && (
              linuxResults.length > 0
                ? <div className="mt-2 border-t border-gray-800 pt-6"><LinuxTriageTable data={linuxResults} selected={selected} onToggle={toggleSelect} /></div>
                : <div className="mt-2 border-t border-gray-800 pt-6 text-center py-12"><ShieldAlert className="h-8 w-8 text-gray-600 mx-auto mb-3" /><p className="text-gray-500 text-sm">Scan completed — no notable artifacts.</p></div>
            )}

            {((activeTab === 'mft' && !mftResults) || (activeTab === 'prefetch' && !prefetchResults) || (activeTab === 'processes' && !processResults && !processLive) || (activeTab === 'autoruns' && !autorunResults) || (activeTab === 'dlls' && !dllResults) || (activeTab === 'shimcache' && !shimResults) || (activeTab === 'browser' && !browserResults) || (activeTab === 'containers' && !containerResults) || (activeTab === 'linux-triage' && !linuxResults)) && !loading && agent.status === 'online' && (
              <div className="text-center py-12 border-2 border-dashed border-gray-800 rounded-lg">
                <Search className="h-8 w-8 text-gray-600 mx-auto mb-3" />
                <p className="text-gray-400 text-sm">Click "Run Scan" to trigger the UAC prompt on the agent.</p>
                <p className="text-gray-600 text-xs mt-1">Analysed on-device; only metadata + hashes are transmitted. Hashes are auto-checked against your IOC store.</p>
              </div>
            )}
          </div>
          )}
        </div>
      </div>

      {lookup && <IntelLookupModal indicator={lookup.indicator} type={lookup.type} onClose={() => setLookup(null)} />}
      {traceTarget && <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />}
      {showTriage && <TriageCollectionModal agent={agent} cases={cases} onClose={() => setShowTriage(false)} />}
    </div>
  )
}

// ── Network Recon (NetworkMiner-style) ───────────────────────────────────────
// Hosts / Sessions / DNS views over native TCP/UDP enumeration. Works in two
// modes: a one-shot enriched snapshot (image paths + DNS cache) or a continuous
// LIVE stream (SSE, refreshing every ~2s) that never blocks on UAC.

function ipv4Octet(ip: string, n: number) { return parseInt(ip.split('.')[n] || '0', 10) }
// A "remote peer" worth showing in Hosts/Sessions (excludes listeners & wildcard).
function hasRemote(c: Connection) {
  return !!c.remote_addr && c.remote_addr !== '0.0.0.0' && c.remote_addr !== '::' && c.state !== 'LISTENING'
}
// Public (routable) address → eligible for reverse DNS / VirusTotal.
function isRoutableIP(ip: string) {
  if (!ip || ip === '0.0.0.0' || ip === '::' || ip === '::1') return false
  if (ip.includes(':')) return !ip.toLowerCase().startsWith('fe80') && !ip.toLowerCase().startsWith('fc') && !ip.toLowerCase().startsWith('fd')
  if (ip.startsWith('127.') || ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('169.254.')) return false
  if (ipv4Octet(ip, 0) === 172 && ipv4Octet(ip, 1) >= 16 && ipv4Octet(ip, 1) <= 31) return false
  if (ipv4Octet(ip, 0) >= 224) return false // multicast / reserved
  return true
}
const ipTypeOf = (ip: string) => (ip.includes(':') ? 'IPv6-Addr' : 'IPv4-Addr')

interface HostAgg {
  addr: string
  host?: string
  ports: number[]
  processes: string[]
  count: number
  states: string[]
  routable: boolean
}
function aggregateHosts(conns: Connection[]): HostAgg[] {
  const map = new Map<string, HostAgg>()
  for (const c of conns) {
    if (!hasRemote(c)) continue
    let h = map.get(c.remote_addr)
    if (!h) { h = { addr: c.remote_addr, host: c.remote_host, ports: [], processes: [], count: 0, states: [], routable: isRoutableIP(c.remote_addr) }; map.set(c.remote_addr, h) }
    h.count++
    if (c.remote_host && !h.host) h.host = c.remote_host
    if (c.remote_port && !h.ports.includes(c.remote_port)) h.ports.push(c.remote_port)
    if (c.process && !h.processes.includes(c.process)) h.processes.push(c.process)
    if (c.state && !h.states.includes(c.state)) h.states.push(c.state)
  }
  return Array.from(map.values()).sort((a, b) => b.count - a.count)
}

const stateStyle = (s: string) =>
  s === 'ESTABLISHED' ? 'bg-emerald-500/10 text-emerald-400'
  : s === 'LISTENING' ? 'bg-blue-500/10 text-blue-400'
  : s === 'TIME_WAIT' || s === 'CLOSE_WAIT' ? 'bg-gray-700 text-gray-400'
  : s.startsWith('SYN') ? 'bg-yellow-500/10 text-yellow-400'
  : 'bg-gray-800 text-gray-400'

function NetworkRecon({ agent, cases, onLookup }: { agent: Agent; cases: any[]; onLookup: (t: LookupTarget) => void }) {
  const navigate = useNavigate()
  const [view, setView] = useState<'hosts' | 'sessions' | 'dns'>('hosts')
  const [live, setLive] = useState(false)
  const [loading, setLoading] = useState(false)
  const [snapConns, setSnapConns] = useState<Connection[] | null>(null)
  const [dns, setDns] = useState<DNSCacheEntry[]>([])
  const [filter, setFilter] = useState('')
  const [iocMatches, setIocMatches] = useState<Set<string>>(new Set())
  const [selected, setSelected] = useState<Set<string>>(new Set())
  const [saveCaseId, setSaveCaseId] = useState<string>(agent.case_id ?? '')
  const [saving, setSaving] = useState(false)
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)

  // Live stream (only active when the toggle is on and the agent is online).
  const { data: liveConns, connected } = useRealtimeSSE<Connection>(agent.id, 'netconn', live && agent.status === 'online')

  const conns: Connection[] = (live ? liveConns : snapConns) ?? []
  const hosts = useMemo(() => aggregateHosts(conns), [conns])
  const sessions = useMemo(() => conns.filter(hasRemote), [conns])

  // Auto-match remote IPs + DNS answers against the IOC store. Re-runs only when
  // the distinct indicator set changes, so the live stream doesn't hammer it.
  const indicatorSig = useMemo(() => {
    const ips = hosts.map(h => h.addr)
    const doms = dns.map(d => d.name)
    return Array.from(new Set([...ips, ...doms])).sort().join('|')
  }, [hosts, dns])
  useEffect(() => {
    const vals = indicatorSig ? indicatorSig.split('|') : []
    if (!vals.length) return
    let cancelled = false
    intelApi.matchIOCs(vals.map(v => v.toLowerCase()).slice(0, 5000))
      .then(res => { if (!cancelled && res.count > 0) setIocMatches(new Set(Object.keys(res.matches))) })
      .catch(() => {})
    return () => { cancelled = true }
  }, [indicatorSig])

  // Pivot a remote IP straight into a full OSINT footprint (RDAP/GeoIP/VT/Shodan
  // /portscan). Turns "endpoint is talking to this IP" into an investigation.
  const investigate = async (ip: string) => {
    try {
      const scan = await osintApi.create({ target: ip, name: `Edge ${agent.name}: ${ip}` })
      toast.success('OSINT investigation started')
      navigate(`/osint/${scan.id}`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    }
  }

  const runSnapshot = async () => {
    setLoading(true); setSelected(new Set()); setIocMatches(new Set())
    try {
      const data: NetworkResult = await agentsApi.parseNetwork(agent.id)
      setSnapConns(data.connections || [])
      setDns(data.dns || [])
      toast.success(`Network snapshot — ${(data.connections || []).length} connections, ${(data.dns || []).length} DNS records`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setLoading(false) }
  }

  const toggleLive = () => {
    if (!live && agent.status !== 'online') { toast.error('Agent is offline'); return }
    setLive(v => !v); setSelected(new Set())
  }

  const isKnown = (v: string) => iocMatches.has(v.toLowerCase())
  const toggleSel = (addr: string) => setSelected(p => { const n = new Set(p); n.has(addr) ? n.delete(addr) : n.add(addr); return n })

  const handleSave = async () => {
    if (!saveCaseId) { toast.error('Select a case first'); return }
    if (selected.size === 0) { toast.error('Select at least one host'); return }
    setSaving(true)
    try {
      const items = hosts.filter(h => selected.has(h.addr)).map(h => {
        const known = isKnown(h.addr)
        return {
          title: `Network host: ${h.host || h.addr}`,
          detail: `Remote: ${h.addr}\nReverse DNS: ${h.host || '—'}\nPorts: ${h.ports.sort((a, b) => a - b).join(', ') || '—'}\nProcesses: ${h.processes.join(', ') || '—'}\nConnections: ${h.count}\nStates: ${h.states.join(', ')}`,
          event_time: undefined,
          severity: (known ? 'critical' : 'info') as TimelineSeverity,
          value: h.addr,
          ioc_type: ipTypeOf(h.addr),
          promote_ioc: true,
        }
      })
      const res = await timelineApi.importArtifacts(saveCaseId, { source: 'edge-forensics:network', host: agent.hostname || agent.name, items })
      toast.success(`Saved ${res.events_created} event(s) · ${res.iocs_promoted} new IOC(s)`)
      setSelected(new Set())
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setSaving(false) }
  }

  const f = filter.toLowerCase()
  const shownHosts = hosts.filter(h => !f || h.addr.toLowerCase().includes(f) || (h.host || '').toLowerCase().includes(f) || h.processes.some(p => p.toLowerCase().includes(f)))
  const shownSessions = sessions.filter(c => !f || c.remote_addr.toLowerCase().includes(f) || (c.remote_host || '').toLowerCase().includes(f) || c.process.toLowerCase().includes(f) || String(c.remote_port).includes(f))
  const shownDns = dns.filter(d => !f || d.name.toLowerCase().includes(f) || d.data.toLowerCase().includes(f))

  const hasData = conns.length > 0 || dns.length > 0

  return (
    <div className="bg-[#1C1C1E] border border-gray-800 rounded-xl p-6">
      <div className="flex items-start justify-between mb-4 gap-4 flex-wrap">
        <div className="min-w-0">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Network className="h-5 w-5 text-purple-400" /> Network Recon
            {live && <span className="inline-flex items-center gap-1 text-[10px] font-bold uppercase tracking-wider px-2 py-0.5 rounded-full bg-red-500/15 text-red-400 border border-red-500/30"><Radio className="h-3 w-3 animate-pulse" /> Live{connected ? '' : ' · connecting'}</span>}
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            Native TCP/UDP enumeration (IP Helper API) with owning process, image path & reverse DNS — NetworkMiner-style Hosts / Sessions / DNS. No UAC required. Remote IPs auto-matched against your IOC store.
          </p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <button onClick={toggleLive} disabled={agent.status !== 'online'}
            className={`flex items-center gap-2 px-3 py-2 rounded-md font-medium text-sm transition-colors disabled:opacity-50 ${live ? 'bg-red-600 hover:bg-red-700 text-white' : 'bg-gray-800 hover:bg-gray-700 text-gray-200'}`}>
            <Radio className="h-4 w-4" /> {live ? 'Stop Live' : 'Go Live'}
          </button>
          <button onClick={runSnapshot} disabled={loading || live || agent.status !== 'online'}
            className="bg-purple-600 hover:bg-purple-700 text-white flex items-center gap-2 px-4 py-2 rounded-md font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed">
            {loading ? <><span className="h-4 w-4 border-2 border-white/30 border-t-white rounded-full animate-spin" /> Scanning...</> : <><Play className="h-4 w-4" /> Snapshot</>}
          </button>
        </div>
      </div>

      {agent.status !== 'online' && (
        <div className="flex items-center gap-3 p-4 rounded-lg bg-orange-500/10 border border-orange-500/20 mb-4">
          <ShieldAlert className="h-5 w-5 text-orange-400 flex-shrink-0" />
          <p className="text-sm text-orange-200">Agent is offline. Network recon unavailable.</p>
        </div>
      )}

      {hasData && (
        <>
          {/* View selector + filter */}
          <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
            <div className="flex items-center gap-1 bg-gray-900/60 rounded-lg p-1">
              <button onClick={() => setView('hosts')} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium ${view === 'hosts' ? 'bg-purple-500/20 text-purple-300' : 'text-gray-400 hover:text-gray-200'}`}><Globe className="h-3.5 w-3.5" /> Hosts <span className="opacity-60">({hosts.length})</span></button>
              <button onClick={() => setView('sessions')} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium ${view === 'sessions' ? 'bg-purple-500/20 text-purple-300' : 'text-gray-400 hover:text-gray-200'}`}><Server className="h-3.5 w-3.5" /> Sessions <span className="opacity-60">({sessions.length})</span></button>
              <button onClick={() => setView('dns')} className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium ${view === 'dns' ? 'bg-purple-500/20 text-purple-300' : 'text-gray-400 hover:text-gray-200'}`} disabled={live} title={live ? 'DNS cache only in snapshot mode' : ''}><Database className="h-3.5 w-3.5" /> DNS <span className="opacity-60">({dns.length})</span></button>
            </div>
            <div className="relative flex-1 min-w-[180px] max-w-xs">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter (ip / host / process / port)…" className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-950 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
            </div>
          </div>

          {/* Save-to-case toolbar (Hosts view) */}
          {view === 'hosts' && selected.size > 0 && (
            <div className="flex flex-wrap items-center gap-3 mb-4 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
              <span className="text-xs text-emerald-300 font-medium">{selected.size} host(s) selected</span>
              <select value={saveCaseId} onChange={e => setSaveCaseId(e.target.value)} className="text-xs bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-gray-200 focus:outline-none focus:border-emerald-500/60">
                <option value="">Select case…</option>
                {cases.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
              <button onClick={handleSave} disabled={saving || !saveCaseId} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50">
                {saving ? <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="h-3.5 w-3.5" />} Save to Case + promote IOC
              </button>
              <button onClick={() => setSelected(new Set())} className="text-xs text-gray-500 hover:text-gray-300">Clear</button>
            </div>
          )}

          {/* HOSTS */}
          {view === 'hosts' && (
            <table className="w-full text-xs">
              <thead className="bg-gray-900/70"><tr className="border-b border-gray-800">
                <th className="px-2 py-2 w-6"></th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Remote host</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Ports</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Process(es)</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Conns</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">VT</th>
              </tr></thead>
              <tbody>
                {shownHosts.map(h => {
                  const known = isKnown(h.addr)
                  return (
                    <tr key={h.addr} className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${known ? 'bg-red-950/30' : ''}`}>
                      <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(h.addr)} onChange={() => toggleSel(h.addr)} className="accent-emerald-500" /></td>
                      <td className="px-3 py-1.5">
                        <div className="font-mono text-gray-200 flex items-center gap-1.5">
                          {h.addr}
                          {known && <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 text-[9px] font-medium"><Database className="h-2.5 w-2.5" /> IOC</span>}
                          {!h.routable && <span className="text-[9px] text-gray-600 uppercase">local</span>}
                          <button onClick={() => copy('IP', h.addr)} className="text-gray-600 hover:text-emerald-400"><Copy className="h-3 w-3" /></button>
                        </div>
                        {h.host && <div className="text-[11px] text-gray-500 truncate max-w-xs">{h.host}</div>}
                      </td>
                      <td className="px-3 py-1.5 font-mono text-gray-400">{h.ports.sort((a, b) => a - b).slice(0, 6).join(', ')}{h.ports.length > 6 ? '…' : ''}</td>
                      <td className="px-3 py-1.5 text-gray-300">{h.processes.slice(0, 3).join(', ')}{h.processes.length > 3 ? '…' : ''}</td>
                      <td className="px-3 py-1.5 text-gray-400">{h.count} <span className="text-gray-600">{h.states.join('/')}</span></td>
                      <td className="px-3 py-1.5">
                        {h.routable && (
                          <div className="flex items-center gap-1.5">
                            <button onClick={() => onLookup({ indicator: h.addr, type: 'ip' })} title="Look up on VirusTotal" className="text-gray-500 hover:text-purple-400"><ShieldQuestion className="h-4 w-4" /></button>
                            <button onClick={() => investigate(h.addr)} title="Investigate this IP in OSINT (RDAP/GeoIP/VT/Shodan/portscan)" className="text-gray-500 hover:text-emerald-400"><Crosshair className="h-4 w-4" /></button>
                          </div>
                        )}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}

          {/* SESSIONS */}
          {view === 'sessions' && (
            <table className="w-full text-xs">
              <thead className="bg-gray-900/70"><tr className="border-b border-gray-800">
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Process</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">PID</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Local</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Remote</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">State</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">VT</th>
              </tr></thead>
              <tbody>
                {shownSessions.map((c, i) => {
                  const known = isKnown(c.remote_addr)
                  const routable = isRoutableIP(c.remote_addr)
                  return (
                    <tr key={i} className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${known ? 'bg-red-950/30' : ''}`}>
                      <td className="px-3 py-1.5 text-gray-200">{c.process || '—'}<span className="ml-1 text-[10px] text-gray-600">{c.proto}</span></td>
                      <td className="px-3 py-1.5 font-mono text-gray-500">{c.pid || '—'}</td>
                      <td className="px-3 py-1.5 font-mono text-gray-400">{c.local_addr}:{c.local_port}</td>
                      <td className="px-3 py-1.5 font-mono text-gray-200">
                        <div className="flex items-center gap-1.5">{c.remote_addr}:{c.remote_port}{known && <Database className="h-3 w-3 text-red-400" />}</div>
                        {c.remote_host && <div className="text-[11px] text-gray-500 truncate max-w-[220px]">{c.remote_host}</div>}
                      </td>
                      <td className="px-3 py-1.5"><span className={`px-1.5 py-0.5 rounded text-[10px] ${stateStyle(c.state)}`}>{c.state || '—'}</span></td>
                      <td className="px-3 py-1.5">
                        <div className="flex items-center gap-1.5">
                          {routable && <button onClick={() => onLookup({ indicator: c.remote_addr, type: 'ip' })} title="Look up on VirusTotal" className="text-gray-500 hover:text-purple-400"><ShieldQuestion className="h-4 w-4" /></button>}
                          {routable && <button onClick={() => investigate(c.remote_addr)} title="Investigate this IP in OSINT" className="text-gray-500 hover:text-emerald-400"><Crosshair className="h-4 w-4" /></button>}
                          {c.process && <button onClick={() => setTraceTarget({ target: c.process, pid: c.pid || 0 })} title="Trace origin of the process behind this connection" className="text-gray-500 hover:text-emerald-400"><GitBranch className="h-4 w-4" /></button>}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}

          {/* DNS */}
          {view === 'dns' && (
            <table className="w-full text-xs">
              <thead className="bg-gray-900/70"><tr className="border-b border-gray-800">
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Queried name</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Type</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">Answer</th>
                <th className="px-3 py-2 text-left text-gray-500 font-medium">VT</th>
              </tr></thead>
              <tbody>
                {shownDns.map((d, i) => {
                  const known = isKnown(d.name)
                  return (
                    <tr key={i} className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${known ? 'bg-red-950/30' : ''}`}>
                      <td className="px-3 py-1.5 font-mono text-gray-200 flex items-center gap-1.5">{d.name}{known && <Database className="h-3 w-3 text-red-400" />}</td>
                      <td className="px-3 py-1.5 text-gray-500">{d.type}</td>
                      <td className="px-3 py-1.5 font-mono text-gray-400 break-all">{d.data}</td>
                      <td className="px-3 py-1.5"><button onClick={() => onLookup({ indicator: d.name, type: 'domain' })} title="Look up on VirusTotal" className="text-gray-500 hover:text-purple-400"><ShieldQuestion className="h-4 w-4" /></button></td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          )}
        </>
      )}

      {!hasData && agent.status === 'online' && !loading && (
        <div className="text-center py-12 border-2 border-dashed border-gray-800 rounded-lg">
          <Network className="h-8 w-8 text-gray-600 mx-auto mb-3" />
          <p className="text-gray-400 text-sm">Run a <b>Snapshot</b> for an enriched one-shot view, or <b>Go Live</b> to stream connections continuously.</p>
          <p className="text-gray-600 text-xs mt-1">No UAC needed — sockets are read in the agent's user context. Remote IPs auto-checked against your IOC store.</p>
        </div>
      )}
      {traceTarget && <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />}
    </div>
  )
}

// ── Live process monitor (SSE) — lightweight continuous view used by the
// Processes tab's "Go Live" toggle. Streams the same telemetry as the dashboard
// (name / pid / parent / memory) every ~1s without a UAC prompt; the deep
// hash/signature snapshot stays on the manual "Run Scan" button.
interface LiveProc { pid: number; ppid: number; name: string; mem_kb: number; cmdline: string }
function LiveProcessMonitor({ agent }: { agent: Agent }) {
  const { data: procs, connected } = useRealtimeSSE<LiveProc>(agent.id, 'processes', agent.status === 'online')
  const [filter, setFilter] = useState('')
  const f = filter.toLowerCase()
  const sorted = (procs ?? []).slice().sort((a, b) => b.mem_kb - a.mem_kb)
  const shown = sorted.filter(p => !f || p.name.toLowerCase().includes(f) || String(p.pid).includes(f) || (p.cmdline || '').toLowerCase().includes(f))
  return (
    <div className="mt-2 border-t border-gray-800 pt-4">
      <div className="flex items-center justify-between gap-3 mb-3 flex-wrap">
        <span className="inline-flex items-center gap-1.5 text-[11px] font-bold uppercase tracking-wider text-red-400">
          <Radio className="h-3.5 w-3.5 animate-pulse" /> Live · {shown.length} processes {connected ? '' : '· connecting'}
        </span>
        <div className="relative flex-1 min-w-[180px] max-w-xs">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter (name / pid / cmdline)…" className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-950 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
      </div>
      <div className="max-h-[480px] overflow-auto">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10"><tr className="border-b border-gray-800">
            <th className="px-3 py-2 text-left text-gray-500 font-medium">Process</th>
            <th className="px-3 py-2 text-left text-gray-500 font-medium">PID</th>
            <th className="px-3 py-2 text-left text-gray-500 font-medium">PPID</th>
            <th className="px-3 py-2 text-right text-gray-500 font-medium">Memory</th>
            <th className="px-3 py-2 text-left text-gray-500 font-medium">Command line</th>
          </tr></thead>
          <tbody>
            {shown.map((p, i) => (
              <tr key={`${p.pid}-${i}`} className="border-b border-gray-800/40 hover:bg-gray-800/30">
                <td className="px-3 py-1.5 text-gray-200">{p.name}</td>
                <td className="px-3 py-1.5 font-mono text-purple-400">{p.pid}</td>
                <td className="px-3 py-1.5 font-mono text-gray-500">{p.ppid}</td>
                <td className="px-3 py-1.5 text-right font-mono text-gray-400">{fmtSize(p.mem_kb * 1024)}</td>
                <td className="px-3 py-1.5 font-mono text-gray-500 truncate max-w-md" title={p.cmdline}>{p.cmdline || '—'}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Shimcache (AppCompatCache) table ─────────────────────────────────────────
function ShimTable({ data, selected, onToggle, onTrace }: {
  data: ShimEntry[]
  selected: Set<number>
  onToggle: (i: number) => void
  onTrace: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const flaggedCount = data.filter(e => (e.suspicious?.length ?? 0) > 0).length
  const f = filter.toLowerCase()
  const rows = data.map((e, i) => ({ e, i })).filter(({ e }) => {
    const mf = !f || e.path.toLowerCase().includes(f)
    return mf && (!threatsOnly || (e.suspicious?.length ?? 0) > 0)
  })
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length.toLocaleString()} records</span>
        {flaggedCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {flaggedCount} flagged</span>}
        <span className="text-gray-600">order = cache order (most-recent activity first)</span>
      </div>
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by path..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        {flaggedCount > 0 && (
          <button onClick={() => setThreatsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${threatsOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
      </div>
      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">#</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Path</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">File modified</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={5} className="px-3 py-8 text-center text-gray-600">No results</td></tr>
            ) : rows.map(({ e, i }) => {
              const flagged = (e.suspicious?.length ?? 0) > 0
              return (
                <tr key={i} className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${flagged ? 'bg-amber-950/20' : ''}`}>
                  <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" /></td>
                  <td className="px-3 py-1.5 font-mono text-gray-600">{i + 1}</td>
                  <td className="px-3 py-1.5 font-mono text-gray-300 break-all">
                    {e.path}
                    {flagged && <span className="ml-2 inline-flex flex-wrap gap-1">{e.suspicious!.map((r, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px]">{r}</span>)}</span>}
                  </td>
                  <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{e.last_modified ? fmtTime(e.last_modified) : '—'}</td>
                  <td className="px-3 py-1.5 text-center whitespace-nowrap">
                    <div className="inline-flex items-center gap-2">
                      {flagged ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-medium"><AlertTriangle className="h-2.5 w-2.5" /> Flag</span> : <span className="text-emerald-500/50 text-xs">OK</span>}
                      <button onClick={() => onTrace(e.path || e.name, 0)} className="text-gray-500 hover:text-emerald-400" title="Trace origin (which process ran this, when)"><GitBranch className="h-3.5 w-3.5" /></button>
                    </div>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Loaded DLLs (ListDLLs-style) table ───────────────────────────────────────
function DllsTable({ data, iocMatches, onLookup, selected, onToggle, onTrace }: {
  data: DllEntry[]
  iocMatches: Set<string>
  onLookup: (t: LookupTarget) => void
  selected: Set<number>
  onToggle: (i: number) => void
  onTrace: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const toggleExp = (i: number) => setExpanded(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const isKnownIOC = (e: DllEntry) => !!e.sha256 && iocMatches.has(e.sha256.toLowerCase())
  const isThreat = (e: DllEntry) => isKnownIOC(e) || (e.suspicious?.length ?? 0) > 0
  const threatCount = data.filter(isThreat).length
  const iocCount = data.filter(isKnownIOC).length

  const f = filter.toLowerCase()
  const rows = data.map((e, i) => ({ e, i })).filter(({ e }) => {
    const mf = !f || e.name.toLowerCase().includes(f) || e.path.toLowerCase().includes(f) ||
      e.processes.some(p => p.toLowerCase().includes(f)) || e.sha256?.toLowerCase() === f
    return mf && (!threatsOnly || isThreat(e))
  })

  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length.toLocaleString()} unique modules</span>
        {iocCount > 0 && <span className="flex items-center gap-1 text-red-400 font-medium"><Database className="h-3 w-3" /> {iocCount} known IOC</span>}
        {threatCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {threatCount} flagged</span>}
      </div>

      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by name / path / loader / hash..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        {threatCount > 0 && (
          <button onClick={() => setThreatsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${threatsOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
      </div>

      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 w-6"></th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Module</th>
              <th className="px-3 py-2 text-right text-gray-500 font-medium">Loaders</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">SHA-256</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Signed</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.length === 0 ? (
              <tr><td colSpan={7} className="px-3 py-8 text-center text-gray-600">No results</td></tr>
            ) : rows.map(({ e, i }) => {
              const known = isKnownIOC(e)
              const flagged = (e.suspicious?.length ?? 0) > 0
              const isOpen = expanded.has(i)
              const tint = known ? 'bg-red-950/30' : flagged ? 'bg-amber-950/20' : ''
              return (
                <Fragment key={i}>
                  <tr className={`border-b border-gray-800/40 hover:bg-gray-800/30 transition-colors ${tint}`}>
                    <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" /></td>
                    <td className="px-2 py-1.5 text-gray-600 cursor-pointer" onClick={() => toggleExp(i)}><ChevronRight className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} /></td>
                    <td className="px-3 py-1.5 font-mono cursor-pointer" onClick={() => toggleExp(i)}>
                      <span className={known ? 'text-red-300 font-medium' : flagged ? 'text-amber-300 font-medium' : 'text-gray-200'}>{e.name}</span>
                      <div className="text-[10px] text-gray-600 break-all max-w-md">{e.path}</div>
                    </td>
                    <td className="px-3 py-1.5 text-right font-mono text-gray-400">{e.process_count}</td>
                    <td className="px-3 py-1.5 font-mono text-emerald-300/80 whitespace-nowrap">
                      {e.hashed ? (
                        <span className="inline-flex items-center gap-1.5">
                          {shortHash(e.sha256)}
                          <button onClick={() => onLookup({ indicator: e.sha256!, type: 'hash' })} className="text-gray-600 hover:text-purple-400" title="Look up on VirusTotal"><ShieldQuestion className="h-3 w-3" /></button>
                          <button onClick={() => copy('SHA-256', e.sha256)} className="text-gray-600 hover:text-emerald-400"><Copy className="h-3 w-3" /></button>
                        </span>
                      ) : <span className="text-gray-600">—</span>}
                    </td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">{e.signature ? <span className={`px-1.5 py-0.5 rounded text-[10px] ${sigBadge(e.signature)}`}>{e.signature}</span> : <span className="text-gray-600">—</span>}</td>
                    <td className="px-3 py-1.5 text-center whitespace-nowrap">
                      {known ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-red-500/20 border border-red-500/40 text-red-400 text-xs font-medium"><Database className="h-2.5 w-2.5" /> IOC</span>
                        : flagged ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400 text-xs font-medium"><AlertTriangle className="h-2.5 w-2.5" /> Flag</span>
                        : <span className="text-emerald-500/50 text-xs">OK</span>}
                    </td>
                  </tr>
                  {isOpen && (
                    <tr className="bg-gray-950/60">
                      <td colSpan={2}></td>
                      <td colSpan={5} className="px-4 py-3 space-y-2">
                        <div><span className="text-gray-500 text-xs">Path:</span> <span className="font-mono text-gray-300 text-xs break-all">{e.path}</span></div>
                        <div className="text-xs">
                          <span className="text-gray-500">Loaded by ({e.process_count}):</span>
                          <div className="flex flex-wrap gap-1 mt-1">
                            {e.processes.map((p, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-gray-800 text-gray-300 text-[10px] font-mono">{p}</span>)}
                          </div>
                        </div>
                        {e.hashed ? (
                          <div className="space-y-1 pt-1">
                            <HashRow algo="md5" value={e.md5} onLookup={onLookup} />
                            <HashRow algo="sha256" value={e.sha256} onLookup={onLookup} />
                          </div>
                        ) : <p className="text-[11px] text-gray-600">Not hashed (too large or unreadable).</p>}
                        <div className="pt-2"><button onClick={() => onTrace(e.name, 0)} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-700/80 hover:bg-emerald-700 text-white" title="Reconstruct this module's origin (which process loaded it, when)"><GitBranch className="h-3.5 w-3.5" /> Trace origin</button></div>
                        {flagged && (
                          <div className="flex flex-wrap items-center gap-1.5 pt-1">
                            <span className="text-amber-400 text-xs font-medium">Flags:</span>
                            {e.suspicious!.map((r, k) => <span key={k} className="px-1.5 py-0.5 rounded bg-amber-500/15 border border-amber-500/30 text-amber-300 text-[10px]">{r}</span>)}
                          </div>
                        )}
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Browser history table ────────────────────────────────────────────────────
function BrowserTable({ data, onLookup, onTrace }: {
  data: BrowserEntry[]
  onLookup?: (t: LookupTarget) => void
  onTrace?: (target: string, pid: number) => void
}) {
  const [filter, setFilter] = useState('')
  const [threatsOnly, setThreatsOnly] = useState(false)
  const flaggedCount = data.filter(e => (e.suspicious?.length ?? 0) > 0).length
  const f = filter.toLowerCase()
  const rows = data.filter(e => {
    const mf = !f || e.url.toLowerCase().includes(f) || (e.title ?? '').toLowerCase().includes(f) || e.profile.toLowerCase().includes(f)
    return mf && (!threatsOnly || (e.suspicious?.length ?? 0) > 0)
  })
  const hostOf = (u: string) => { try { return new URL(u).hostname } catch { return '' } }
  // fileOf extracts the last path segment (a downloaded filename) so Trace origin
  // can correlate the download with its later on-disk execution (prefetch/shimcache).
  const fileOf = (u: string) => { try { return new URL(u).pathname.split('/').filter(Boolean).pop() || '' } catch { return '' } }
  return (
    <div className="space-y-3">
      <div className="flex flex-wrap items-center gap-4 text-xs">
        <span className="text-gray-400">{data.length.toLocaleString()} URLs</span>
        {flaggedCount > 0 && <span className="flex items-center gap-1 text-amber-400 font-medium"><AlertTriangle className="h-3 w-3" /> {flaggedCount} flagged</span>}
        <span className="text-gray-600">most-recent visit first</span>
      </div>
      <div className="flex items-center gap-3">
        <div className="relative flex-1">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter by URL / title / profile..."
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
        </div>
        {flaggedCount > 0 && (
          <button onClick={() => setThreatsOnly(v => !v)}
            className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border transition-colors ${threatsOnly ? 'bg-amber-500/20 border-amber-500/40 text-amber-400' : 'bg-gray-800 border-gray-700 text-gray-400 hover:text-gray-200'}`}>
            <AlertTriangle className="h-3 w-3" /> Threats only
          </button>
        )}
      </div>
      <div className="overflow-auto max-h-[560px] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Browser</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Profile</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">URL / Title</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Visits</th>
              <th className="px-3 py-2 text-left text-gray-500 font-medium">Last visit</th>
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((e, i) => {
              const host = hostOf(e.url)
              return (
                <tr key={i} className="border-b border-gray-900 hover:bg-white/5 group">
                  <td className="px-3 py-2 text-gray-300 whitespace-nowrap">{e.browser}</td>
                  <td className="px-3 py-2 text-gray-500 whitespace-nowrap font-mono">{e.profile}</td>
                  <td className="px-3 py-2 min-w-0 max-w-[520px]">
                    <a href={e.url} target="_blank" rel="noreferrer" className="text-emerald-400/90 hover:text-emerald-300 break-all">{e.url}</a>
                    {e.title && <div className="text-gray-500 truncate" title={e.title}>{e.title}</div>}
                  </td>
                  <td className="px-3 py-2 text-center text-gray-400">{e.visit_count}</td>
                  <td className="px-3 py-2 text-gray-400 whitespace-nowrap font-mono">{e.last_visit ? safeFmt(e.last_visit) : '—'}</td>
                  <td className="px-3 py-2 text-center whitespace-nowrap">
                    {(e.suspicious?.length ?? 0) > 0
                      ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400" title={e.suspicious!.join(', ')}><AlertTriangle className="h-2.5 w-2.5" /> {e.suspicious!.length}</span>
                      : <span className="text-emerald-500/40">OK</span>}
                    {onLookup && host && (
                      <button onClick={() => onLookup({ indicator: host, type: 'domain' })} title={`IOC lookup: ${host}`}
                        className="ml-2 text-gray-600 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity align-middle"><Search className="h-3 w-3 inline" /></button>
                    )}
                    {onTrace && (fileOf(e.url) || host) && (
                      <button onClick={() => onTrace(fileOf(e.url) || host, 0)} title="Trace origin: correlate this download/URL with on-disk execution"
                        className="ml-2 text-gray-600 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity align-middle"><GitBranch className="h-3 w-3 inline" /></button>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// safeFmt renders an RFC3339 timestamp compactly, falling back to the raw string.
function safeFmt(s: string): string {
  const d = new Date(s)
  return isNaN(d.getTime()) ? s : d.toLocaleString()
}

// ── Container Forensics table (Linux) ────────────────────────────────────────
// RISK_CONTEXT are container attributes that are the default for perfectly
// ordinary deployments — nearly every compose stack sets restart: unless-stopped
// and most images run as root. Rendering them like the escape-class risks made
// every container look compromised and buried the findings that matter, so they
// are kept as context but greyed out and excluded from the "risky" count.
const RISK_CONTEXT = /^(restart-always|runs-as-root|image-no-repo-digest)$/i
const RISK_SEVERE = /privileged|docker-socket|host-network|host-pid|host-ipc|host-sensitive-mount|cap:|ioc|preload|rootkit|reverse-shell|module-not-on-disk|masked-paths-disabled|device-passthrough|net-container-share|drift-suspicious-write|userns-host/i

const isSevereRisk = (flags: string[]) => flags.some(f => RISK_SEVERE.test(f))
const hasRealRisk = (flags: string[]) => flags.some(f => !RISK_CONTEXT.test(f))

function RiskChips({ flags }: { flags?: string[] }) {
  if (!flags || flags.length === 0) return <span className="text-gray-600 text-[11px]">—</span>
  return (
    <div className="flex flex-wrap gap-1">
      {flags.map((f, i) => {
        if (RISK_CONTEXT.test(f)) {
          return <span key={i} className="text-[10px] px-1.5 py-0.5 rounded border text-gray-400 border-gray-700/60 bg-gray-800/40">{f}</span>
        }
        const red = RISK_SEVERE.test(f)
        return <span key={i} className={`text-[10px] px-1.5 py-0.5 rounded border ${red ? 'text-red-300 border-red-700/50 bg-red-900/20' : 'text-amber-300 border-amber-700/40 bg-amber-900/20'}`}>{f}</span>
      })}
    </div>
  )
}

// containerFlags merges the agent-side risk list with an IOC hit on the image.
// The full digest is preferred: the short 12-char id can never match a real
// sha256 indicator.
function containerFlags(c: any, iocMatches: Set<string>): string[] {
  const ids = [c.image_digest, c.image_repo_digest, c.image_id].filter(Boolean).map((s: string) => String(s).toLowerCase())
  const known = ids.some(id => iocMatches.has(id))
  return [...(c.suspicious ?? []), ...(known ? ['IOC-MATCH:image'] : [])]
}

function ContainersTable({ data, iocMatches, selected, onToggle }: {
  data: any[]; iocMatches: Set<string>; selected: Set<number>; onToggle: (i: number) => void
}) {
  const [open, setOpen] = useState<Set<number>>(new Set())
  const toggleOpen = (i: number) => setOpen(prev => {
    const n = new Set(prev); n.has(i) ? n.delete(i) : n.add(i); return n
  })

  // Count only containers carrying a real risk — see RISK_CONTEXT above.
  const risky = data.filter(c => hasRealRisk(c.suspicious ?? [])).length
  // A row whose inspect failed (or that came from a CLI fallback) has no
  // security fields at all. Counting it as clean would read as "no risk found"
  // when the truth is "not analysed".
  const limited = data.filter(c => c.inspect_ok === false).length

  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-gray-400">
          {data.length} container(s) · <span className="text-red-400">{risky} risky</span>
          {limited > 0 && <span className="text-amber-400"> · {limited} not analysed (no inspect access)</span>}
        </span>
      </div>
      <div className="overflow-auto max-h-[55vh] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800 text-gray-500">
              <th className="px-2 py-2 w-8"></th>
              <th className="px-2 py-2 w-6"></th>
              <th className="px-2 py-2 text-left">STATE</th>
              <th className="px-2 py-2 text-left">NAME</th>
              <th className="px-2 py-2 text-left">IMAGE</th>
              <th className="px-2 py-2 text-left">PORTS</th>
              <th className="px-2 py-2 text-left">DRIFT</th>
              <th className="px-2 py-2 text-left">RISK</th>
            </tr>
          </thead>
          <tbody>
            {data.map((c, i) => {
              const flags = containerFlags(c, iocMatches)
              const danger = isSevereRisk(flags)
              const drift = c.changes_summary
              const expanded = open.has(i)
              return (
                <Fragment key={c.id || i}>
                  <tr className={`border-b border-gray-900 hover:bg-white/5 ${danger ? 'bg-red-950/20' : ''}`}>
                    <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" /></td>
                    <td className="px-2 py-1.5 text-center">
                      <button onClick={() => toggleOpen(i)} className="text-gray-500 hover:text-gray-200" title="Show forensic detail">
                        <ChevronRight className={`h-3.5 w-3.5 transition-transform ${expanded ? 'rotate-90' : ''}`} />
                      </button>
                    </td>
                    <td className="px-2 py-1.5"><span className={c.state === 'running' ? 'text-emerald-400' : 'text-gray-500'}>{c.state || '—'}</span></td>
                    <td className="px-2 py-1.5 text-gray-200 font-mono">{c.name || c.id}</td>
                    <td className="px-2 py-1.5 text-gray-400 font-mono break-all max-w-[240px]">{c.image}</td>
                    <td className="px-2 py-1.5 text-gray-500 font-mono">{(c.ports || []).join(', ') || '—'}</td>
                    <td className="px-2 py-1.5 font-mono">
                      {drift && drift.total > 0
                        ? <span className={drift.added > 0 ? 'text-amber-400' : 'text-gray-500'}>+{drift.added} ~{drift.modified} -{drift.deleted}</span>
                        : <span className="text-gray-700">—</span>}
                    </td>
                    <td className="px-2 py-1.5">
                      {c.inspect_ok === false
                        ? <span className="text-[10px] px-1.5 py-0.5 rounded border text-amber-300 border-amber-700/40 bg-amber-900/20">not analysed</span>
                        : <RiskChips flags={flags} />}
                    </td>
                  </tr>
                  {expanded && (
                    <tr className="border-b border-gray-900 bg-gray-950/60">
                      <td colSpan={8} className="px-6 py-3">
                        <ContainerDetail c={c} />
                      </td>
                    </tr>
                  )}
                </Fragment>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ContainerDetail surfaces the forensic fields that do not fit in the table:
// the on-host writable layer, filesystem drift, running processes and the
// attribution labels that tie a container back to a compose project or k8s pod.
function ContainerDetail({ c }: { c: any }) {
  const kv = (label: string, value: any) => (value === undefined || value === null || value === '' || (Array.isArray(value) && value.length === 0))
    ? null
    : (
      <div key={label} className="flex gap-2">
        <span className="text-gray-500 shrink-0 w-32">{label}</span>
        <span className="text-gray-300 font-mono break-all">{Array.isArray(value) ? value.join(', ') : String(value)}</span>
      </div>
    )

  const labels = c.labels && Object.keys(c.labels).length
    ? Object.entries(c.labels).map(([k, v]) => `${k}=${v}`)
    : []
  const changes: any[] = c.changes || []
  const procs: any[] = c.processes || []

  return (
    <div className="space-y-3 text-[11px]">
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-x-8 gap-y-1">
        {kv('Image digest', c.image_digest)}
        {kv('Repo digest', c.image_repo_digest)}
        {kv('Image created', c.image_created)}
        {kv('Created', c.created_at)}
        {kv('Runtime', c.runtime)}
        {kv('Host PID', c.pid || undefined)}
        {kv('User', c.user || '(root — image default)')}
        {kv('Entrypoint', c.entrypoint)}
        {kv('Cmd', c.cmd)}
        {kv('Network mode', c.network_mode)}
        {kv('Networks', c.networks)}
        {kv('IPs', c.ips)}
        {kv('Restart policy', c.restart_policy)}
        {kv('AppArmor', c.apparmor)}
        {kv('Seccomp', c.seccomp)}
        {kv('Userns', c.userns_mode)}
        {kv('Cap add', c.cap_add)}
        {kv('Cap drop', c.cap_drop)}
        {kv('Masked paths', c.masked_paths_disabled ? '0 (DISABLED — escape risk)' : c.masked_paths_count)}
        {kv('Readonly rootfs', c.readonly_rootfs ? 'yes' : undefined)}
        {kv('Secret env vars', c.secret_env)}
        {kv('Attribution', labels)}
        {kv('Log path', c.log_path)}
        {/* The writable layer is where anything dropped into the container lives
            on the host — the path an analyst needs to collect or hash. */}
        {kv('Writable layer', c.upper_dir)}
        {kv('Exit code', c.state_detail?.exit_code || undefined)}
        {kv('OOM killed', c.state_detail?.oom_killed ? 'yes' : undefined)}
        {kv('Started', c.state_detail?.started_at)}
        {kv('Finished', c.state_detail?.finished_at)}
      </div>

      {(c.mounts || []).length > 0 && (
        <div>
          <div className="text-gray-500 mb-1">Mounts</div>
          <div className="font-mono text-gray-300 space-y-0.5">
            {(c.mounts || []).map((m: any, i: number) => (
              <div key={i} className={/docker\.sock|^\/(etc|root|proc|sys|boot|dev)\b/.test(m.source || '') ? 'text-red-300' : ''}>
                {m.source} → {m.dest} {m.rw ? '(rw)' : '(ro)'}
              </div>
            ))}
          </div>
        </div>
      )}

      {changes.length > 0 && (
        <div>
          <div className="text-gray-500 mb-1">
            Filesystem drift — files changed since the image was built
            {c.changes_summary?.truncated && <span className="text-amber-400"> (showing the highest-signal {changes.length} of {c.changes_summary.total})</span>}
          </div>
          <div className="font-mono text-gray-300 max-h-40 overflow-auto space-y-0.5">
            {changes.map((ch: any, i: number) => (
              <div key={i}>
                <span className={ch.kind === 'added' ? 'text-amber-400' : ch.kind === 'deleted' ? 'text-red-400' : 'text-gray-500'}>
                  {ch.kind === 'added' ? '+' : ch.kind === 'deleted' ? '-' : '~'}
                </span>{' '}{ch.path}
              </div>
            ))}
          </div>
        </div>
      )}

      {procs.length > 0 && (
        <div>
          <div className="text-gray-500 mb-1">Processes inside the container</div>
          <div className="font-mono text-gray-300 max-h-40 overflow-auto space-y-0.5">
            {procs.map((p: any, i: number) => (
              <div key={i}>{String(p.pid).padStart(6)} {p.user ? `${p.user} ` : ''}{p.cmd}</div>
            ))}
          </div>
        </div>
      )}

      {c.inspect_ok === false && (
        <div className="text-amber-400">
          Security fields were not collected for this container — the agent could not inspect it
          (CLI fallback or insufficient permission). Risk shown as empty does not mean safe.
        </div>
      )}
    </div>
  )
}

// ── Linux Triage table ───────────────────────────────────────────────────────
function LinuxTriageTable({ data, selected, onToggle }: {
  data: any[]; selected: Set<number>; onToggle: (i: number) => void
}) {
  const flagged = data.filter(a => (a.suspicious?.length ?? 0) > 0).length
  const TYPE_COLOR: Record<string, string> = {
    'shell-history': 'text-cyan-300', 'cron': 'text-amber-300', 'ssh-key': 'text-blue-300',
    'preload': 'text-red-300', 'startup': 'text-amber-300', 'suid': 'text-purple-300', 'module': 'text-red-300',
  }
  return (
    <div>
      <div className="flex items-center justify-between mb-3">
        <span className="text-xs text-gray-400">{data.length} artifact(s) · <span className="text-red-400">{flagged} flagged</span></span>
      </div>
      <div className="overflow-auto max-h-[55vh] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800 text-gray-500">
              <th className="px-2 py-2 w-8"></th>
              <th className="px-2 py-2 text-left">TYPE</th>
              <th className="px-2 py-2 text-left">SOURCE</th>
              <th className="px-2 py-2 text-left">USER</th>
              <th className="px-2 py-2 text-left">DETAIL</th>
              <th className="px-2 py-2 text-left">RISK</th>
            </tr>
          </thead>
          <tbody>
            {data.map((a, i) => {
              const danger = (a.suspicious?.length ?? 0) > 0
              return (
                <tr key={i} className={`border-b border-gray-900 hover:bg-white/5 ${danger ? 'bg-red-950/20' : ''}`}>
                  <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => onToggle(i)} className="accent-emerald-500" /></td>
                  <td className="px-2 py-1.5"><span className={`font-mono ${TYPE_COLOR[a.type] ?? 'text-gray-400'}`}>{a.type}</span></td>
                  <td className="px-2 py-1.5 text-gray-400 font-mono break-all max-w-[200px]">{a.source}</td>
                  <td className="px-2 py-1.5 text-gray-400">{a.user || '—'}</td>
                  <td className="px-2 py-1.5 text-gray-300 font-mono break-all max-w-[320px]">{a.detail}</td>
                  <td className="px-2 py-1.5"><RiskChips flags={a.suspicious} /></td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── Triage Collection modal (KAPE-style 1-click bundle) ──────────────────────
const TRIAGE_TYPES: { key: string; label: string; note: string }[] = [
  { key: 'processes', label: 'Processes', note: 'running process tree + hashes' },
  { key: 'autoruns', label: 'Autoruns', note: 'persistence / autostart' },
  { key: 'shimcache', label: 'Shimcache', note: 'execution evidence' },
  { key: 'prefetch', label: 'Prefetch', note: 'execution evidence' },
  { key: 'dlls', label: 'Loaded DLLs', note: 'injected / hijacked modules' },
  { key: 'netconn', label: 'Network', note: 'connections + DNS cache' },
  { key: 'browser', label: 'Browser history', note: 'Chrome/Edge/Brave/Firefox' },
  { key: 'mft', label: 'MFT (slow)', note: 'full file-system metadata — large' },
]

function TriageCollectionModal({ agent, cases, onClose }: {
  agent: Agent
  cases: any[]
  onClose: () => void
}) {
  const [sel, setSel] = useState<Set<string>>(new Set(['processes', 'autoruns', 'shimcache', 'prefetch', 'dlls', 'netconn', 'browser']))
  const [running, setRunning] = useState(false)
  const [result, setResult] = useState<TriageResult | null>(null)
  const [caseId, setCaseId] = useState<string>(agent.case_id ?? '')
  const [saving, setSaving] = useState(false)
  const [viewType, setViewType] = useState<string | null>(null) // artifact being analyzed in-app

  const toggle = (k: string) => setSel(p => { const n = new Set(p); n.has(k) ? n.delete(k) : n.add(k); return n })
  const viewArtifact = (result?.artifacts ?? []).find(a => a.type === viewType) ?? null

  const run = async () => {
    if (sel.size === 0) { toast.error('Select at least one artifact'); return }
    setRunning(true); setResult(null); setViewType(null)
    try {
      toast('Triage — one UAC prompt, collecting in a single pass…', { icon: '🛡️' })
      const r = await agentsApi.collectTriage(agent.id, Array.from(sel))
      setResult(r)
      const total = (r.artifacts ?? []).reduce((s, a) => s + (a.count ?? 0), 0)
      toast.success(`Triage complete — ${total.toLocaleString()} records across ${r.artifacts?.length ?? 0} artifacts`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setRunning(false) }
  }

  const download = () => {
    if (!result) return
    const stamp = new Date().toISOString().replace(/[:.]/g, '-')
    const host = agent.hostname || agent.name
    const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `triage_${host}_${stamp}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const save = async () => {
    if (!caseId || !result) return
    setSaving(true)
    try {
      const stamp = new Date().toISOString().replace(/[:.]/g, '-')
      const host = agent.hostname || agent.name
      const fname = `triage_${host}_${stamp}.json`
      const blob = new Blob([JSON.stringify(result, null, 2)], { type: 'application/json' })
      // NB: `File` is also imported from lucide-react (icon); use window.File for the DOM ctor.
      const file = new window.File([blob], fname, { type: 'application/json' })
      const total = (result.artifacts ?? []).reduce((s, a) => s + (a.count ?? 0), 0)
      await evidenceApi.upload(caseId, file, host, `Triage collection — ${result.artifacts?.length ?? 0} artifacts, ${total} records`)
      toast.success('Saved — view/download it under Case → Attack Timeline → Evidence', { duration: 6000 })
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setSaving(false) }
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-deep-900 border border-slate-700 rounded-xl w-full max-w-5xl max-h-[88vh] shadow-2xl flex flex-col" onClick={e => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
          {viewArtifact && (
            <button onClick={() => setViewType(null)} title="Back to summary" className="text-gray-400 hover:text-emerald-300"><ArrowLeft className="h-4 w-4" /></button>
          )}
          <Archive className="h-4 w-4 text-amber-400" />
          <h3 className="text-sm font-semibold text-gray-200">
            Triage Collection — <span className="text-gray-400">{agent.hostname || agent.name}</span>
            {viewArtifact && <span className="text-gray-500"> · <span className="font-mono text-amber-300">{viewArtifact.type}</span></span>}
          </h3>
          <button onClick={onClose} className="ml-auto text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
        </div>

        <div className="p-4 overflow-y-auto space-y-4 flex-1">
          {viewArtifact ? (
            <TriageArtifactTable type={viewArtifact.type} data={viewArtifact.data} />
          ) : (
          <>
          <p className="text-sm text-gray-400">
            Gather a forensic artifact bundle in <span className="text-gray-200">one elevated pass</span> (a single UAC prompt). Analyze it right here, save it to a case as evidence, or download it.
          </p>

          <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
            {TRIAGE_TYPES.map(t => (
              <label key={t.key} className={`flex items-start gap-2 rounded-lg border px-3 py-2 cursor-pointer transition-colors ${sel.has(t.key) ? 'border-amber-500/50 bg-amber-900/15' : 'border-slate-800 bg-gray-900/40 hover:border-slate-600'}`}>
                <input type="checkbox" checked={sel.has(t.key)} onChange={() => toggle(t.key)} className="mt-0.5" />
                <span className="min-w-0">
                  <span className="text-sm text-gray-200">{t.label}</span>
                  <span className="block text-[11px] text-gray-500">{t.note}</span>
                </span>
              </label>
            ))}
          </div>

          {result && (
            <div className="rounded-lg border border-slate-800 bg-gray-900/40 p-3">
              <div className="text-[11px] uppercase tracking-wide text-gray-500 mb-2">Collected (at {safeFmt(result.collected_at)}) · <span className="text-gray-600 normal-case">click an artifact to analyze</span></div>
              <div className="space-y-1">
                {(result.artifacts ?? []).map((a, i) => {
                  const clickable = !a.error && a.count > 0
                  return (
                    <button key={i} disabled={!clickable} onClick={() => setViewType(a.type)}
                      className={`flex items-center gap-2 text-xs w-full text-left rounded px-1.5 py-1 ${clickable ? 'hover:bg-white/5 cursor-pointer' : 'cursor-default'}`}>
                      <span className="font-mono text-gray-300 w-24 shrink-0">{a.type}</span>
                      {a.error
                        ? <span className="text-red-400 truncate" title={a.error}>error: {a.error}</span>
                        : <span className="text-emerald-400">{a.count.toLocaleString()} records</span>}
                      {clickable && <ChevronRight className="h-3.5 w-3.5 text-gray-600 ml-auto" />}
                    </button>
                  )
                })}
              </div>
            </div>
          )}
          </>
          )}
        </div>

        <div className="flex items-center gap-2 px-4 py-2.5 border-t border-slate-800 bg-gray-950/40 shrink-0">
          <button onClick={run} disabled={running || agent.status !== 'online'}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-amber-600 hover:bg-amber-500 text-white transition-colors disabled:opacity-50 whitespace-nowrap">
            {running ? <><Loader2 className="h-3.5 w-3.5 animate-spin" /> Collecting…</> : <><Archive className="h-3.5 w-3.5" /> {result ? 'Re-collect' : 'Collect triage'}</>}
          </button>
          {result && (
            <div className="flex items-center gap-2 ml-auto min-w-0">
              <button onClick={download} title="Download the triage bundle (JSON) to inspect locally"
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium border border-slate-700 bg-gray-800 text-gray-300 hover:text-white hover:bg-gray-700 transition whitespace-nowrap">
                <Download className="h-3.5 w-3.5" /> Download
              </button>
              <select className="input text-xs py-1.5 max-w-[150px]" value={caseId} onChange={e => setCaseId(e.target.value)}>
                <option value="">Select case…</option>
                {cases.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
              </select>
              <button onClick={save} disabled={!caseId || saving}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap">
                {saving ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CalendarPlus className="h-3.5 w-3.5" />} Save evidence
              </button>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// Preferred column order per artifact type; unknown types fall back to inferred keys.
const TRIAGE_PREFERRED: Record<string, string[]> = {
  processes: ['pid', 'ppid', 'name', 'user', 'path', 'cmdline', 'created', 'mem_kb'],
  autoruns: ['category', 'name', 'command', 'image_path', 'user', 'enabled'],
  shimcache: ['name', 'path', 'last_modified'],
  prefetch: ['executable', 'run_count', 'last_run_time'],
  dlls: ['name', 'path', 'process_count'],
  netconn: ['proto', 'local_addr', 'local_port', 'remote_addr', 'remote_port', 'state', 'process', 'pid'],
  browser: ['browser', 'profile', 'url', 'title', 'visit_count', 'last_visit'],
}

// TriageArtifactTable renders one artifact's records as a generic, filterable
// table so the analyst can inspect the collected data in-app. Columns are chosen
// per type (falling back to inferred scalar keys); `suspicious` becomes a Status
// column. netconn data is an object → its .connections array is shown.
function TriageArtifactTable({ type, data }: { type: string; data: unknown }) {
  const [filter, setFilter] = useState('')

  const rows: any[] = useMemo(() => {
    if (type === 'netconn' && data && typeof data === 'object') return (data as any).connections ?? []
    return Array.isArray(data) ? data : []
  }, [type, data])

  const columns = useMemo(() => {
    if (rows.length === 0) return []
    const sample = rows[0]
    const isScalar = (v: any) => v === null || ['string', 'number', 'boolean'].includes(typeof v)
    const preferred = (TRIAGE_PREFERRED[type] ?? []).filter((k) => k in sample)
    const extra = Object.keys(sample).filter((k) => k !== 'suspicious' && isScalar(sample[k]) && !preferred.includes(k))
    return [...preferred, ...extra].slice(0, 10)
  }, [rows, type])

  const f = filter.toLowerCase()
  const filtered = useMemo(() => (f ? rows.filter((r) => JSON.stringify(r).toLowerCase().includes(f)) : rows), [rows, f])
  const flaggedCount = useMemo(() => rows.filter((r) => Array.isArray(r?.suspicious) && r.suspicious.length).length, [rows])

  if (rows.length === 0) return <p className="text-xs text-gray-500">No records in this artifact.</p>

  const cell = (v: any) => {
    if (v === null || v === undefined || v === '') return '—'
    if (typeof v === 'boolean') return v ? 'yes' : 'no'
    return String(v)
  }

  return (
    <div className="space-y-3">
      <div className="flex items-center gap-3">
        <span className="text-xs text-gray-400">{rows.length.toLocaleString()} records</span>
        {flaggedCount > 0 && <span className="flex items-center gap-1 text-amber-400 text-xs"><AlertTriangle className="h-3 w-3" /> {flaggedCount} flagged</span>}
        <div className="relative flex-1 max-w-md ml-auto">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
          <input value={filter} onChange={(e) => setFilter(e.target.value)} placeholder="Filter records…"
            className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-900 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-amber-500/60" />
        </div>
      </div>
      <div className="overflow-auto max-h-[62vh] rounded-lg border border-gray-800">
        <table className="w-full text-xs">
          <thead className="sticky top-0 bg-gray-900 z-10">
            <tr className="border-b border-gray-800">
              {columns.map((c) => <th key={c} className="px-3 py-2 text-left text-gray-500 font-medium whitespace-nowrap">{c}</th>)}
              <th className="px-3 py-2 text-center text-gray-500 font-medium">Status</th>
            </tr>
          </thead>
          <tbody>
            {filtered.slice(0, 2000).map((r, i) => {
              const flagged = Array.isArray(r?.suspicious) && r.suspicious.length > 0
              return (
                <tr key={i} className={`border-b border-gray-900 hover:bg-white/5 ${flagged ? 'bg-amber-500/5' : ''}`}>
                  {columns.map((c) => {
                    const mono = /path|cmdline|url|command|addr|image/.test(c)
                    return <td key={c} className={`px-3 py-1.5 align-top ${mono ? 'font-mono text-gray-300 break-all max-w-[420px]' : 'text-gray-300 whitespace-nowrap'}`}>{cell(r[c])}</td>
                  })}
                  <td className="px-3 py-1.5 text-center whitespace-nowrap">
                    {flagged
                      ? <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-amber-500/20 border border-amber-500/30 text-amber-400" title={r.suspicious.join(', ')}><AlertTriangle className="h-2.5 w-2.5" /> {r.suspicious.length}</span>
                      : <span className="text-emerald-500/40">OK</span>}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
        {filtered.length > 2000 && <div className="px-3 py-2 text-[11px] text-gray-500">Showing first 2,000 of {filtered.length.toLocaleString()} — use the filter to narrow.</div>}
      </div>
    </div>
  )
}
