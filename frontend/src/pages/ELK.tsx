import { useEffect, useRef, useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { openctiApi, OpenCTIConfig, OpenCTIConfigPayload } from '@/api/opencti'
import {
  elkApi,
  ELKConfig,
  ELKConfigPayload,
  ELKHit,
  AutoHuntProgress,
  AutoHuntDoneEvent,
  FileIOCParseResponse,
} from '@/api/elk'
import { splunkApi, SplunkConfig } from '@/api/splunk'
import { qradarApi, QRadarConfig } from '@/api/qradar'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'
import {
  ShieldAlert, Server, Search,
  Plus, X, Zap, Code2,
  Upload, Pencil, Trash2, CheckCircle2, Rocket, FileSearch, Layers,
  FolderUp, Loader2, Database, AlertTriangle, HardDriveUpload,
  LayoutDashboard, Power, PlayCircle, StopCircle, ChevronRight, ChevronDown, MonitorSmartphone
} from 'lucide-react'
import { JsonViewer } from '@/components/JsonViewer'
import { getErrorMessage } from '@/lib/utils'
import { logsearchApi, LogIngestJob, LogIndex, ELKStatus, type AutoShutdown, type SigmaOfflineResult } from '@/api/logsearch'
import { useKeepalive } from '@/hooks/useKeepalive'
import { casesApi } from '@/api/cases'
import { SigmaAlertRow } from '@/components/Agent/EvtxViewer'

type TabType = 'hunt' | 'ingest' | 'connections'

// ---------------------------------------------------------------------------
// Page shell 
// ---------------------------------------------------------------------------
export default function ELKHuntingPage() {
  const [activeTab, setActiveTab] = useState<TabType>('hunt')
  useKeepalive('elk') // keep ELK alive / auto-start while this page is open

  const tabs: { id: TabType; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'hunt',        label: 'Threat Hunt',   icon: Search },
    { id: 'ingest',      label: 'Log Ingest',    icon: HardDriveUpload },
    { id: 'connections', label: 'Integrations',  icon: Layers },
  ]

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-100 flex items-center gap-2">
            <Search className="h-6 w-6 text-emerald-500" />
            SIEM Threat Hunting
          </h1>
          <p className="text-gray-400 mt-1">
            Hunt indicators across Elasticsearch — from the IOC database, from an uploaded IOC file, or with a manual query.
          </p>
        </div>
        <div className="flex bg-gray-900/60 p-1 border border-gray-800/60 rounded-lg backdrop-blur-sm self-start shadow-sm">
          {tabs.map((t) => {
            const Ic = t.icon
            const active = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  active
                    ? 'bg-gray-800 text-emerald-400 shadow-sm'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
                }`}
              >
                <Ic className="h-4 w-4" />
                {t.label}
              </button>
            )
          })}
        </div>
      </div>

      {activeTab === 'hunt'        && <HuntTab />}
      {activeTab === 'ingest'      && <IngestTab onGoHunt={() => setActiveTab('hunt')} />}
      {activeTab === 'connections' && <ConnectionsTab />}
    </div>
  )
}

// ---------------------------------------------------------------------------
// LOG INGEST TAB — upload collected logs, parse to ECS, index into the built-in
// Elasticsearch. Search happens in the Threat Hunt tab against those hunt-*
// indices (the "Local Log Store" ELK profile).
// ---------------------------------------------------------------------------
const ACCEPT_EXT = ['evtx', 'log', 'txt', 'json', 'ndjson', 'jsonl', 'csv', 'tsv', 'gz', 'zip', 'syslog', 'out']

function extAllowed(name: string): boolean {
  const n = name.toLowerCase()
  if (n.endsWith('.gz') || n.endsWith('.zip')) return true
  const dot = n.lastIndexOf('.')
  if (dot === -1) return true
  return ACCEPT_EXT.includes(n.slice(dot + 1))
}

function walkEntry(entry: any, out: File[]): Promise<void> {
  return new Promise((resolve) => {
    if (entry.isFile) {
      entry.file((f: File) => { out.push(f); resolve() }, () => resolve())
    } else if (entry.isDirectory) {
      const reader = entry.createReader()
      const readBatch = () => reader.readEntries(async (entries: any[]) => {
        if (!entries.length) return resolve()
        await Promise.all(entries.map((en) => walkEntry(en, out)))
        readBatch()
      }, () => resolve())
      readBatch()
    } else resolve()
  })
}

// whenVisible returns a react-query refetchInterval function that only polls
// while the browser tab is visible, so a backgrounded ELK page stops hammering
// the API with status/index polls.
const whenVisible = (ms: number) => () => (document.visibilityState === 'visible' ? ms : false)

function IngestTab({ onGoHunt }: { onGoHunt: () => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [caseName, setCaseName] = useState('')
  const [caseId, setCaseId] = useState('')
  const [logType, setLogType] = useState('auto')
  const [timezone, setTimezone] = useState('')
  const [files, setFiles] = useState<File[]>([])
  const [skipped, setSkipped] = useState(0)
  const [dragOver, setDragOver] = useState(false)
  const fileInput = useRef<HTMLInputElement>(null)
  const folderInput = useRef<HTMLInputElement>(null)

  const { data: meta } = useQuery({ queryKey: ['logsearch-meta'], queryFn: logsearchApi.meta, refetchInterval: whenVisible(30000), refetchIntervalInBackground: false })
  const { data: health } = useQuery({ queryKey: ['logsearch-health'], queryFn: logsearchApi.health, refetchInterval: whenVisible(15000), refetchIntervalInBackground: false })
  const { data: cases } = useQuery({ queryKey: ['cases-list'], queryFn: casesApi.list })
  const { data: summary } = useQuery({
    queryKey: ['logsearch-summary', caseName],
    queryFn: () => logsearchApi.summary(caseName.trim() || undefined),
    refetchInterval: whenVisible(15000),
    refetchIntervalInBackground: false,
  })
  const { data: jobs } = useQuery({
    queryKey: ['logsearch-jobs'],
    queryFn: () => logsearchApi.listJobs(),
    refetchInterval: (q) => {
      if (document.visibilityState !== 'visible') return false
      const list = (q.state.data as LogIngestJob[] | undefined) ?? []
      return list.some((j) => j.status === 'queued' || j.status === 'running') ? 2000 : false
    },
    refetchIntervalInBackground: false,
  })
  const { data: indices } = useQuery({ queryKey: ['logsearch-indices'], queryFn: logsearchApi.listIndices, refetchInterval: whenVisible(15000), refetchIntervalInBackground: false })
  const { data: elk } = useQuery({
    queryKey: ['logsearch-elk-status'],
    queryFn: logsearchApi.elkStatus,
    refetchInterval: whenVisible(15000),
    refetchIntervalInBackground: false,
  })
  const powerMut = useMutation({
    mutationFn: (verb: 'start' | 'stop') => logsearchApi.elkPower(verb),
    onSuccess: (_d, verb) => {
      toast.success(verb === 'start' ? 'Starting ELK…' : 'Stopping ELK…')
      qc.invalidateQueries({ queryKey: ['logsearch-elk-status'] })
    },
    onError: (e: any) => toast.error(getErrorMessage(e)),
  })

  const addFiles = (list: FileList | File[], filter: boolean) => {
    let sk = 0
    setFiles((prev) => {
      const next = [...prev]
      for (const f of Array.from(list)) {
        if (filter && !extAllowed(f.name)) { sk++; continue }
        if (!next.some((x) => x.name === f.name && x.size === f.size)) next.push(f)
      }
      return next
    })
    setSkipped(sk)
  }

  const onDrop = async (e: React.DragEvent) => {
    e.preventDefault(); setDragOver(false)
    const items = e.dataTransfer.items
    if (items && items.length && (items[0] as any).webkitGetAsEntry) {
      const collected: File[] = []
      await Promise.all(Array.from(items).map((it) => {
        const entry = (it as any).webkitGetAsEntry()
        return entry ? walkEntry(entry, collected) : Promise.resolve()
      }))
      addFiles(collected, true)
    } else {
      addFiles(e.dataTransfer.files, true)
    }
  }

  const enrichMut = useMutation({
    mutationFn: () => logsearchApi.enrich(caseName.trim() || undefined),
    onSuccess: (d) => {
      if (!d.configured) toast.error('No threat-intel API keys configured (VT/Shodan/AbuseIPDB)')
      else if (d.results.length === 0) toast('No source IPs to enrich yet')
    },
    onError: (e: any) => toast.error(getErrorMessage(e)),
  })

  const uploadMut = useMutation({
    mutationFn: () => logsearchApi.upload(caseName.trim(), logType, files, caseId || undefined, timezone || undefined),
    onSuccess: () => {
      setFiles([]); setSkipped(0)
      qc.invalidateQueries({ queryKey: ['logsearch-jobs'] })
      toast.success('Upload started — parsing & indexing')
    },
    onError: (e: any) => toast.error(getErrorMessage(e)),
  })

  const delMut = useMutation({
    mutationFn: (index: string) => logsearchApi.deleteIndex(index),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['logsearch-indices'] }); toast.success('Index deleted') },
    onError: (e: any) => toast.error(getErrorMessage(e)),
  })

  // Repository: hosts are expanded/collapsed; deleting a host drops all its logs.
  const [expandedHosts, setExpandedHosts] = useState<Set<string>>(new Set())
  const toggleHost = (h: string) =>
    setExpandedHosts((prev) => {
      const next = new Set(prev)
      next.has(h) ? next.delete(h) : next.add(h)
      return next
    })
  const delHostMut = useMutation({
    mutationFn: (host: string) => logsearchApi.deleteHost(host),
    onSuccess: (r) => {
      qc.invalidateQueries({ queryKey: ['logsearch-jobs'] })
      qc.invalidateQueries({ queryKey: ['logsearch-indices'] })
      qc.invalidateQueries({ queryKey: ['logsearch-summary'] })
      toast.success(`Removed ${r.removed_jobs} file(s) and ${r.deleted_indices.length} index(es) from "${r.host}"`)
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  // Group ingest jobs by source host so Log Ingest reads as a per-host repository.
  const hostGroups = (() => {
    const map = new Map<string, LogIngestJob[]>()
    for (const j of jobs ?? []) {
      const key = j.host && j.host.trim() ? j.host : '(uploads)'
      const arr = map.get(key) ?? []
      arr.push(j)
      map.set(key, arr)
    }
    return Array.from(map.entries()).map(([host, items]) => ({
      host,
      items,
      docs: items.reduce((s, j) => s + (j.docs_indexed || 0), 0),
      running: items.filter((j) => j.status === 'queued' || j.status === 'running').length,
      errors: items.filter((j) => j.status === 'error').length,
      isAgent: items.some((j) => j.source === 'agent'),
    }))
  })()

  const totalMB = (files.reduce((s, f) => s + f.size, 0) / 1048576).toFixed(1)
  const statusColor: Record<string, string> = {
    done: 'text-emerald-400', running: 'text-amber-400', queued: 'text-amber-400',
    error: 'text-rose-400', skipped: 'text-gray-500',
  }

  return (
    <div className="grid gap-6 lg:grid-cols-2">
      {/* Upload card */}
      <div className="space-y-4">
        <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
          <div className="flex items-center gap-2 mb-4">
            <HardDriveUpload className="h-5 w-5 text-emerald-500" />
            <h2 className="font-semibold text-gray-100">Ingest collected logs</h2>
            <div className="ml-auto flex items-center gap-3 text-xs">
              <span className={health?.elasticsearch?.up ? 'text-emerald-400' : 'text-rose-400'}>
                ● ES {health?.elasticsearch?.up ? (health.elasticsearch.status || 'up') : 'down'}
              </span>
              <span className={health?.kibana?.up ? 'text-emerald-400' : 'text-gray-500'}>
                ● Kibana {health?.kibana?.up ? 'up' : 'down'}
              </span>
              {health && <span className="text-gray-500">{health.indices} idx · {health.documents.toLocaleString()} docs</span>}
            </div>
          </div>

          <label className="block text-xs text-gray-400 mb-1">Link to case (optional)</label>
          <select
            value={caseId}
            onChange={(e) => {
              setCaseId(e.target.value)
              const cs = (cases ?? []).find((c) => c.id === e.target.value)
              if (cs) setCaseName(cs.name)
            }}
            className="w-full mb-3 px-3 py-2 rounded-md bg-gray-950 border border-gray-800 text-gray-100 text-sm focus:outline-none focus:border-emerald-500"
          >
            <option value="">— no case (ad-hoc) —</option>
            {(cases ?? []).map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
          </select>

          <label className="block text-xs text-gray-400 mb-1">Case / hunt name</label>
          <input
            value={caseName} onChange={(e) => setCaseName(e.target.value)}
            placeholder="e.g. incident-2026-07"
            className="w-full mb-3 px-3 py-2 rounded-md bg-gray-950 border border-gray-800 text-gray-100 text-sm focus:outline-none focus:border-emerald-500"
          />

          <label className="block text-xs text-gray-400 mb-1">Log type</label>
          <select
            value={logType} onChange={(e) => setLogType(e.target.value)}
            className="w-full mb-3 px-3 py-2 rounded-md bg-gray-950 border border-gray-800 text-gray-100 text-sm focus:outline-none focus:border-emerald-500"
          >
            {(meta?.log_types ?? ['auto']).map((t) => (
              <option key={t} value={t}>{t === 'auto' ? 'auto-detect' : t}</option>
            ))}
          </select>

          <label className="block text-xs text-gray-400 mb-1">Source timezone <span className="text-gray-600">(syslog/undated logs)</span></label>
          <select
            value={timezone} onChange={(e) => setTimezone(e.target.value)}
            className="w-full mb-3 px-3 py-2 rounded-md bg-gray-950 border border-gray-800 text-gray-100 text-sm focus:outline-none focus:border-emerald-500"
          >
            <option value="">UTC (default)</option>
            <option value="+07:00">+07:00 (Asia/Bangkok, Ho Chi Minh)</option>
            <option value="+08:00">+08:00 (Asia/Singapore, Shanghai)</option>
            <option value="+09:00">+09:00 (Asia/Tokyo)</option>
            <option value="+05:30">+05:30 (Asia/Kolkata)</option>
            <option value="+01:00">+01:00 (Europe/Paris)</option>
            <option value="-05:00">-05:00 (US Eastern)</option>
            <option value="-08:00">-08:00 (US Pacific)</option>
          </select>

          <div
            onClick={() => fileInput.current?.click()}
            onDragOver={(e) => { e.preventDefault(); setDragOver(true) }}
            onDragLeave={() => setDragOver(false)}
            onDrop={onDrop}
            className={`mt-1 rounded-lg border-2 border-dashed p-6 text-center cursor-pointer transition-colors ${
              dragOver ? 'border-emerald-500 text-gray-200' : 'border-gray-700 text-gray-400 hover:border-gray-600'
            }`}
          >
            <FolderUp className="h-6 w-6 mx-auto mb-2 opacity-70" />
            Drag &amp; drop <b>files or an entire folder</b> of logs here<br />
            <span className="text-[11px] font-mono">.evtx · access · firewall · syslog · .json/.ndjson · .csv · .gz</span>
            <div className="mt-3 flex items-center justify-center gap-2">
              <button type="button" onClick={(e) => { e.stopPropagation(); fileInput.current?.click() }}
                className="px-3 py-1.5 rounded-md text-xs border border-gray-700 hover:border-emerald-500 text-gray-200">Choose files…</button>
              <button type="button" onClick={(e) => { e.stopPropagation(); folderInput.current?.click() }}
                className="px-3 py-1.5 rounded-md text-xs border border-gray-700 hover:border-emerald-500 text-gray-200">Choose folder…</button>
            </div>
          </div>
          <input ref={fileInput} type="file" multiple hidden
            onChange={(e) => { if (e.target.files) addFiles(e.target.files, false); e.target.value = '' }} />
          <input ref={folderInput} type="file" multiple hidden
            // @ts-expect-error non-standard directory picker attribute
            webkitdirectory=""
            onChange={(e) => { if (e.target.files) addFiles(e.target.files, true); e.target.value = '' }} />

          {files.length > 0 && (
            <div className="mt-3 text-xs text-gray-400">
              <b className="text-gray-200">{files.length} file(s)</b> · {totalMB} MB
              {skipped > 0 && <span className="text-gray-500"> · skipped {skipped} non-log file(s)</span>}
              <div className="mt-1 max-h-28 overflow-auto font-mono">
                {files.slice(0, 40).map((f, i) => <div key={i}>• {f.name} <span className="text-gray-600">({(f.size / 1024).toFixed(0)} KB)</span></div>)}
                {files.length > 40 && <div className="text-gray-500">… and {files.length - 40} more</div>}
              </div>
            </div>
          )}

          <div className="mt-4 flex items-center gap-2">
            <button
              disabled={!caseName.trim() || files.length === 0 || uploadMut.isPending}
              onClick={() => uploadMut.mutate()}
              className="px-4 py-2 rounded-md bg-emerald-600 hover:bg-emerald-500 text-white text-sm font-medium disabled:opacity-50 flex items-center gap-2"
            >
              {uploadMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />}
              Upload &amp; Index
            </button>
            {files.length > 0 && (
              <button onClick={() => { setFiles([]); setSkipped(0) }}
                className="px-3 py-2 rounded-md text-sm border border-gray-700 text-gray-300 hover:border-gray-600">Clear list</button>
            )}
          </div>
        </div>

        {/* Indices */}
        <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
          <div className="flex items-center gap-2 mb-3">
            <Database className="h-4 w-4 text-emerald-500" />
            <h3 className="font-semibold text-gray-100 text-sm">Indexed log stores</h3>
            <div className="ml-auto flex items-center gap-3">
              <button onClick={() => navigate('/kibana')} className="text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1">
                <LayoutDashboard className="h-3.5 w-3.5" /> View in Kibana →
              </button>
              <button onClick={onGoHunt} className="text-xs text-emerald-400 hover:text-emerald-300 flex items-center gap-1">
                <Search className="h-3.5 w-3.5" /> Hunt these logs →
              </button>
            </div>
          </div>
          {(indices ?? []).length === 0
            ? <p className="text-xs text-gray-500">No indices yet. Upload logs to get started.</p>
            : (
              <table className="w-full text-xs">
                <thead><tr className="text-gray-500 text-left"><th className="py-1">Index</th><th>Docs</th><th>Size</th><th></th></tr></thead>
                <tbody>
                  {(indices ?? []).map((ix: LogIndex) => (
                    <tr key={ix.index} className="border-t border-gray-800/60">
                      <td className="py-1.5 font-mono text-gray-300">{ix.index}</td>
                      <td className="text-gray-400">{ix.docs}</td>
                      <td className="text-gray-400">{ix.size}</td>
                      <td className="text-right">
                        <button onClick={() => { if (confirm(`Delete index ${ix.index}?`)) delMut.mutate(ix.index) }}
                          className="text-rose-400/70 hover:text-rose-400"><Trash2 className="h-3.5 w-3.5" /></button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
        </div>

        {/* ELK power toggle — free RAM when idle */}
        <ELKPowerCard elk={elk} esUp={!!meta?.es_up}
          onPower={(v) => powerMut.mutate(v)} pending={powerMut.isPending} />
      </div>

      {/* Right column: triage summary + jobs */}
      <div className="space-y-6">
      {/* Triage summary */}
      {summary && summary.total > 0 && (
        <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
          <div className="flex items-center gap-2 mb-3">
            <FileSearch className="h-4 w-4 text-emerald-500" />
            <h3 className="font-semibold text-gray-100 text-sm">Triage summary{caseName.trim() ? ` · ${caseName.trim()}` : ''}</h3>
            <button
              onClick={() => enrichMut.mutate()}
              disabled={enrichMut.isPending}
              className="ml-auto text-xs text-sky-400 hover:text-sky-300 flex items-center gap-1 disabled:opacity-50"
            >
              {enrichMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />}
              Enrich top IPs
            </button>
            <span className="text-xs text-gray-500">{summary.total.toLocaleString()} docs</span>
          </div>
          <div className="text-xs text-gray-400 mb-3">
            {summary.min_time && summary.max_time
              ? <>time range: <span className="text-gray-300">{new Date(summary.min_time).toLocaleString()}</span> → <span className="text-gray-300">{new Date(summary.max_time).toLocaleString()}</span></>
              : 'no timestamped events'}
          </div>
          <div className="grid grid-cols-2 gap-4 text-xs">
            <SummaryList title="By category" items={summary.by_category} />
            <SummaryList title="By log type" items={summary.by_log_type} />
            <SummaryList title="Top source IPs" items={summary.top_source_ip} mono />
            <SummaryList title="Top event codes" items={summary.top_event_code} mono />
          </div>

          {enrichMut.data && enrichMut.data.results.length > 0 && (
            <div className="mt-4 border-t border-gray-800 pt-3">
              <div className="text-gray-500 text-xs mb-1">Threat-intel (top source IPs)</div>
              <div className="space-y-1">
                {enrichMut.data.results.map((r) => (
                  <div key={r.IOC} className="flex items-center gap-2 text-xs">
                    <span className={`inline-block h-2 w-2 rounded-full ${r.Threat ? 'bg-rose-500' : 'bg-gray-600'}`} />
                    <span className="font-mono text-gray-300">{r.IOC}</span>
                    {r.Threat && <span className="text-rose-400">score {r.MaxScore}</span>}
                    <span className="text-gray-500 truncate">{r.Findings.map((f) => f.Source).join(', ') || 'no data'}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Sigma over stored logs — the dead-box path */}
      <SigmaOfflinePanel caseId={caseId || undefined} />

      {/* Repository — logs grouped by source host */}
      <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
        <div className="flex items-center gap-2 mb-1">
          <Database className="h-4 w-4 text-emerald-500" />
          <h3 className="font-semibold text-gray-100 text-sm">Log repository</h3>
          <span className="ml-auto text-xs text-gray-500">{hostGroups.length} host{hostGroups.length !== 1 ? 's' : ''}</span>
        </div>
        <p className="text-xs text-gray-500 mb-3">
          Logs organised per host. Collect from an agent (Agents → Collect Logs) or upload manually.
          Delete a host to free its indices once the investigation is done.
        </p>
        {hostGroups.length === 0
          ? <p className="text-xs text-gray-500">No logs yet.</p>
          : (
            <div className="space-y-2 max-h-[620px] overflow-auto">
              {hostGroups.map((g) => {
                const open = expandedHosts.has(g.host)
                return (
                  <div key={g.host} className="rounded-md border border-gray-800/60 bg-gray-950/40">
                    <div className="flex items-center gap-2 p-2.5">
                      <button onClick={() => toggleHost(g.host)} className="flex items-center gap-2 min-w-0 flex-1 text-left">
                        {open ? <ChevronDown className="h-4 w-4 text-gray-500 shrink-0" /> : <ChevronRight className="h-4 w-4 text-gray-500 shrink-0" />}
                        <MonitorSmartphone className={`h-4 w-4 shrink-0 ${g.isAgent ? 'text-emerald-400' : 'text-gray-500'}`} />
                        <span className="font-mono text-gray-200 text-xs truncate">{g.host}</span>
                        {g.isAgent && <span className="text-[10px] px-1.5 py-0.5 rounded bg-emerald-500/10 text-emerald-300 border border-emerald-500/20 shrink-0">agent</span>}
                        {g.running > 0 && <Loader2 className="h-3.5 w-3.5 text-amber-400 animate-spin shrink-0" />}
                      </button>
                      <span className="text-[11px] text-gray-500 shrink-0">{g.items.length} file{g.items.length !== 1 ? 's' : ''}</span>
                      <span className="text-[11px] text-gray-400 shrink-0">{g.docs.toLocaleString()} docs</span>
                      {g.errors > 0 && <span className="text-[11px] text-rose-400 shrink-0">{g.errors} err</span>}
                      <button
                        onClick={() => {
                          if (confirm(`Delete ALL logs for host "${g.host}"? This drops its Elasticsearch indices and cannot be undone.`)) {
                            delHostMut.mutate(g.host)
                          }
                        }}
                        disabled={delHostMut.isPending}
                        title="Delete all logs for this host"
                        className="p-1 rounded text-gray-500 hover:text-rose-400 hover:bg-rose-500/10 disabled:opacity-40 shrink-0"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                    {open && (
                      <div className="border-t border-gray-800/60 divide-y divide-gray-800/40">
                        {g.items.map((j) => (
                          <div key={j.id} className="px-3 py-2 text-xs">
                            <div className="flex items-center gap-2">
                              {j.status === 'done' ? <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                                : j.status === 'error' ? <AlertTriangle className="h-3.5 w-3.5 text-rose-400 shrink-0" />
                                : j.status === 'skipped' ? <X className="h-3.5 w-3.5 text-gray-500 shrink-0" />
                                : <Loader2 className="h-3.5 w-3.5 text-amber-400 animate-spin shrink-0" />}
                              <span className="font-mono text-gray-300 truncate">{j.filename}</span>
                              <span className={`ml-auto font-semibold ${statusColor[j.status] ?? 'text-gray-400'}`}>{j.status}</span>
                            </div>
                            <div className="mt-1 flex flex-wrap gap-x-4 gap-y-0.5 text-gray-500">
                              <span>case: <span className="text-gray-400">{j.case}</span></span>
                              <span>type: <span className="text-gray-400">{j.detected_type || j.log_type}</span></span>
                              <span>docs: <span className="text-gray-300">{j.docs_indexed}</span>{j.docs_failed > 0 && <span className="text-rose-400"> (+{j.docs_failed} err)</span>}</span>
                            </div>
                            {j.message && <div className="mt-0.5 text-gray-600 truncate" title={j.message}>{j.message}</div>}
                          </div>
                        ))}
                      </div>
                    )}
                  </div>
                )
              })}
            </div>
          )}
      </div>
      </div>
    </div>
  )
}

// SummaryList renders a compact top-N aggregation column.
function SummaryList({ title, items, mono }: { title: string; items: { key: string; count: number }[]; mono?: boolean }) {
  return (
    <div>
      <div className="text-gray-500 mb-1">{title}</div>
      {(items ?? []).length === 0
        ? <div className="text-gray-600">—</div>
        : (items ?? []).slice(0, 6).map((b, i) => (
          <div key={i} className="flex justify-between gap-2">
            <span className={`truncate ${mono ? 'font-mono' : ''} text-gray-300`}>{b.key}</span>
            <span className="text-gray-500">{b.count.toLocaleString()}</span>
          </div>
        ))}
    </div>
  )
}

// autoShutdownLabel renders the idle-shutdown countdown for the power card header.
function autoShutdownLabel(a: AutoShutdown | undefined, running: boolean): string {
  if (!a || !a.enabled) return 'stop when idle to free RAM'
  if (a.manual_off) return 'auto-shutdown paused (stopped by admin)'
  if (!running) return 'auto-starts on demand'
  if (a.stops_in_sec == null) return `auto-stops after ${Math.round(a.timeout_sec / 60)}m idle`
  const s = a.stops_in_sec
  return s <= 0 ? 'auto-stopping…' : `auto-stops in ${Math.floor(s / 60)}m ${s % 60}s (idle)`
}

// ELKPowerCard — start/stop the built-in ES+Kibana containers to free RAM when
// idle. When in-app control is disabled it degrades to a status + manual hint.
function ELKPowerCard({ elk, esUp, onPower, pending }: {
  elk?: ELKStatus
  esUp: boolean
  onPower: (verb: 'start' | 'stop') => void
  pending: boolean
}) {
  const enabled = !!elk?.control_enabled
  const esRunning = enabled ? !!elk?.elasticsearch?.running : esUp
  const kbRunning = enabled ? !!elk?.kibana?.running : esUp
  const anyRunning = esRunning || kbRunning
  const allRunning = esRunning && kbRunning

  const dot = (on: boolean) => (
    <span className={`inline-block h-2 w-2 rounded-full ${on ? 'bg-emerald-400' : 'bg-gray-600'}`} />
  )

  return (
    <div className="mt-4 rounded-lg border border-gray-800 bg-gray-900/60 p-5">
      <div className="flex items-center gap-2 mb-3">
        <Power className={`h-4 w-4 ${anyRunning ? 'text-emerald-500' : 'text-gray-500'}`} />
        <h3 className="font-semibold text-gray-100 text-sm">ELK system</h3>
        <span className="ml-auto text-xs text-gray-500">{autoShutdownLabel(elk?.auto_shutdown, anyRunning)}</span>
      </div>

      <div className="flex items-center gap-6 text-xs text-gray-300 mb-3">
        <span className="flex items-center gap-2">{dot(esRunning)} Elasticsearch <span className="text-gray-500">{esRunning ? 'running' : 'stopped'}</span></span>
        <span className="flex items-center gap-2">{dot(kbRunning)} Kibana <span className="text-gray-500">{kbRunning ? 'running' : 'stopped'}</span></span>
      </div>

      {enabled ? (
        <div className="flex items-center gap-2">
          <button
            disabled={allRunning || pending}
            onClick={() => onPower('start')}
            className="px-3 py-1.5 rounded-md text-xs bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-40 flex items-center gap-1.5"
          >
            {pending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlayCircle className="h-3.5 w-3.5" />} Start ELK
          </button>
          <button
            disabled={!anyRunning || pending}
            onClick={() => onPower('stop')}
            className="px-3 py-1.5 rounded-md text-xs border border-gray-700 text-gray-200 hover:border-rose-500 hover:text-rose-300 disabled:opacity-40 flex items-center gap-1.5"
          >
            <StopCircle className="h-3.5 w-3.5" /> Stop ELK
          </button>
        </div>
      ) : (
        <div className="text-xs text-gray-500">
          In-app control is off (<code className="text-gray-400">DOCKER_API_URL</code>/docker proxy not configured). Start/stop manually:
          <div className="mt-1 font-mono text-gray-400">docker compose stop elasticsearch kibana</div>
        </div>
      )}
    </div>
  )
}

// ---------------------------------------------------------------------------
// CONNECTIONS TAB — multi-profile manager for ELK + OpenCTI
// ---------------------------------------------------------------------------
function ConnectionsTab() {
  const [sub, setSub] = useState<'elk' | 'splunk' | 'qradar' | 'opencti'>('elk')
  return (
    <div className="space-y-4">
      <div className="flex bg-gray-900/60 p-1 border border-gray-800/60 rounded-lg w-fit backdrop-blur-sm shadow-sm">
        <button
          onClick={() => setSub('elk')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'elk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <Server className="h-4 w-4" /> ELK
        </button>
        <button
          onClick={() => setSub('splunk')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'splunk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <Server className="h-4 w-4" /> Splunk
        </button>
        <button
          onClick={() => setSub('qradar')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'qradar' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <Server className="h-4 w-4" /> QRadar
        </button>
        <button
          onClick={() => setSub('opencti')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'opencti' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <ShieldAlert className="h-4 w-4" /> OpenCTI
        </button>
      </div>
      {sub === 'elk' ? <ELKProfilesList /> : sub === 'splunk' ? <SplunkProfilesList /> : sub === 'qradar' ? <QRadarProfilesList /> : <OpenCTIProfilesList />}
    </div>
  )
}

// ---- Shared profile-card shell ----
function ProfileCard({
  title, url, username, hasAuth, isActive, onActivate, onEdit, onDelete,
}: {
  title: string; url: string; username: string; hasAuth: boolean; isActive: boolean
  onActivate: () => void; onEdit: () => void; onDelete: () => void
}) {
  return (
    <div className={`relative p-5 rounded-2xl border backdrop-blur-sm transition-all duration-300 ${isActive ? 'border-emerald-500/40 bg-emerald-950/10 shadow-[0_0_15px_rgba(16,185,129,0.1)]' : 'border-gray-800/60 bg-gray-900/40 hover:bg-gray-900/60 hover:border-gray-700'}`}>
      {isActive && (
        <span className="absolute top-3 right-3 inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20 uppercase tracking-wider shadow-[0_0_10px_rgba(16,185,129,0.2)]">
          <CheckCircle2 className="h-3 w-3" /> Active
        </span>
      )}
      <div className="flex items-start justify-between gap-2 mb-3 pr-16">
        <h3 className="text-base font-semibold text-gray-100 truncate">{title}</h3>
      </div>
      <div className="text-xs text-gray-400 space-y-1 font-mono break-all bg-gray-950/50 p-3 rounded-lg border border-gray-800/40">
        <div className="flex gap-2"><span className="text-gray-600 shrink-0 w-10">url:</span> <span className="text-gray-300">{url || <span className="text-gray-600 italic">—</span>}</span></div>
        {username && <div className="flex gap-2"><span className="text-gray-600 shrink-0 w-10">user:</span> <span className="text-gray-300">{username}</span></div>}
        <div className={`flex gap-2 ${hasAuth ? 'text-emerald-400/90' : 'text-amber-400/90'}`}>
          <span className="text-gray-600 shrink-0 w-10">auth:</span> <span>{hasAuth ? 'configured' : 'missing'}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 mt-4">
        {!isActive && (
          <button
            onClick={onActivate}
            className="px-3 py-1.5 text-xs font-medium bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 hover:border-emerald-500/40 rounded-lg flex items-center gap-1.5 transition-all"
          >
            <CheckCircle2 className="h-3.5 w-3.5" /> Use
          </button>
        )}
        <button
          onClick={onEdit}
          className="px-3 py-1.5 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded-lg flex items-center gap-1.5 transition-all"
        >
          <Pencil className="h-3.5 w-3.5" /> Edit
        </button>
        <button
          onClick={onDelete}
          className="px-3 py-1.5 text-xs font-medium bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 hover:border-red-500/40 rounded-lg flex items-center gap-1.5 ml-auto transition-all"
        >
          <Trash2 className="h-3.5 w-3.5" /> Delete
        </button>
      </div>
    </div>
  )
}

// ---- ELK profile list + modal ----
function ELKProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<ELKConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['elk-configs'],
    queryFn: () => elkApi.listConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => elkApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['elk-configs'] })
      qc.invalidateQueries({ queryKey: ['elk-config'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const del = useMutation({
    mutationFn: (id: number) => elkApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['elk-configs'] })
      qc.invalidateQueries({ queryKey: ['elk-config'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} ELK profile{profiles.length === 1 ? '' : 's'} saved. The active one is used for every hunt.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add ELK Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <Server className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No ELK profiles yet</p>
          <p className="text-gray-500 text-sm mt-1">Add one to start hunting across Elasticsearch</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              title={p.name}
              url={p.url}
              username={p.username}
              hasAuth={p.has_auth}
              isActive={p.is_active}
              onActivate={() => activate.mutate(p.id)}
              onEdit={() => setEditing(p)}
              onDelete={() => {
                if (confirm(`Delete profile "${p.name}"?`)) del.mutate(p.id)
              }}
            />
          ))}
        </div>
      )}

      {creating && <ELKProfileModal onClose={() => setCreating(false)} />}
      {editing && <ELKProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function ELKProfileModal({ profile, onClose }: { profile?: ELKConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: ELKConfigPayload) =>
      isEdit ? elkApi.updateConfig(profile!.id, payload) : elkApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['elk-configs'] })
      qc.invalidateQueries({ queryKey: ['elk-config'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: ELKConfigPayload = {
      name: (fd.get('name') as string).trim(),
      description: fd.get('description') as string,
      url: fd.get('url') as string,
      username: fd.get('username') as string,
    }
    const password = fd.get('password') as string
    const api_key = fd.get('api_key') as string
    if (password) payload.password = password
    if (api_key) payload.api_key = api_key
    mutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Server className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New ELK Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. DFIR Lab"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">Elasticsearch URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://elastic.example.com:9200"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (Basic Auth)</label>
              <input
                name="username" defaultValue={profile?.username} placeholder="elastic"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OR API Key (base64-encoded)</label>
            <input
              name="api_key" type="password" placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank)' : 'enter API key'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
            <p className="text-[11px] text-gray-500 font-medium">Use either Basic Auth or API Key. Leave blank when editing to keep stored value.</p>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- Splunk profile list + modal ----
function SplunkProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<SplunkConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['splunk-configs'],
    queryFn: () => splunkApi.getConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => splunkApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['splunk-configs'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const del = useMutation({
    mutationFn: (id: number) => splunkApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['splunk-configs'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} Splunk profile{profiles.length === 1 ? '' : 's'} saved.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add Splunk Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <Server className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No Splunk profiles yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              title={p.name}
              url={p.url}
              username={p.username}
              hasAuth={p.has_auth}
              isActive={p.is_active}
              onActivate={() => activate.mutate(p.id)}
              onEdit={() => setEditing(p)}
              onDelete={() => {
                if (confirm(`Delete profile "${p.name}"?`)) del.mutate(p.id)
              }}
            />
          ))}
        </div>
      )}

      {creating && <SplunkProfileModal onClose={() => setCreating(false)} />}
      {editing && <SplunkProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function SplunkProfileModal({ profile, onClose }: { profile?: SplunkConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: any) =>
      isEdit ? splunkApi.updateConfig(profile!.id, payload) : splunkApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['splunk-configs'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: any = {
      name: (fd.get('name') as string).trim(),
      description: fd.get('description') as string,
      url: fd.get('url') as string,
      username: fd.get('username') as string,
    }
    const password = fd.get('password') as string
    const api_key = fd.get('api_key') as string
    if (password) payload.password = password
    if (api_key) payload.api_key = api_key
    mutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Server className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New Splunk Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. Splunk Core"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">Splunk URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://splunk.example.com:8089"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (Basic Auth)</label>
              <input
                name="username" defaultValue={profile?.username} placeholder="admin"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OR API Key (Bearer token)</label>
            <input
              name="api_key" type="password" placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank)' : 'enter API key'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
            <p className="text-[11px] text-gray-500 font-medium">Use either Basic Auth or API Key. Leave blank when editing to keep stored value.</p>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- QRadar profile list + modal ----
function QRadarProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<QRadarConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['qradar-configs'],
    queryFn: () => qradarApi.getConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => qradarApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qradar-configs'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const del = useMutation({
    mutationFn: (id: number) => qradarApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qradar-configs'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} QRadar profile{profiles.length === 1 ? '' : 's'} saved.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add QRadar Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <Server className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No QRadar profiles yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              title={p.name}
              url={p.url}
              username={p.username}
              hasAuth={p.has_auth}
              isActive={p.is_active}
              onActivate={() => activate.mutate(p.id)}
              onEdit={() => setEditing(p)}
              onDelete={() => {
                if (confirm(`Delete profile "${p.name}"?`)) del.mutate(p.id)
              }}
            />
          ))}
        </div>
      )}

      {creating && <QRadarProfileModal onClose={() => setCreating(false)} />}
      {editing && <QRadarProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function QRadarProfileModal({ profile, onClose }: { profile?: QRadarConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: any) =>
      isEdit ? qradarApi.updateConfig(profile!.id, payload) : qradarApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qradar-configs'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: any = {
      name: (fd.get('name') as string).trim(),
      description: fd.get('description') as string,
      url: fd.get('url') as string,
      username: fd.get('username') as string,
    }
    const password = fd.get('password') as string
    const api_key = fd.get('api_key') as string
    if (password) payload.password = password
    if (api_key) payload.api_key = api_key
    mutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Server className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New QRadar Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. QRadar Core"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">QRadar URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://qradar.example.com"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (Basic Auth)</label>
              <input
                name="username" defaultValue={profile?.username} placeholder="admin"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OR SEC Token (SEC header)</label>
            <input
              name="api_key" type="password" placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank)' : 'enter SEC token'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
            <p className="text-[11px] text-gray-500 font-medium">Use either Basic Auth or SEC Token. Leave blank when editing to keep stored value.</p>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- OpenCTI profile list + modal ----
function OpenCTIProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<OpenCTIConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['opencti-configs'],
    queryFn: () => openctiApi.listConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => openctiApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['opencti-configs'] })
      qc.invalidateQueries({ queryKey: ['opencti-config'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const del = useMutation({
    mutationFn: (id: number) => openctiApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['opencti-configs'] })
      qc.invalidateQueries({ queryKey: ['opencti-config'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} OpenCTI profile{profiles.length === 1 ? '' : 's'} saved. The active one is used when syncing IOCs.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add OpenCTI Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <ShieldAlert className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No OpenCTI profiles</p>
          <p className="text-gray-500 text-sm mt-1">Add one to sync IOCs</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              title={p.name}
              url={p.url}
              username={p.username}
              hasAuth={p.has_auth}
              isActive={p.is_active}
              onActivate={() => activate.mutate(p.id)}
              onEdit={() => setEditing(p)}
              onDelete={() => {
                if (confirm(`Delete profile "${p.name}"?`)) del.mutate(p.id)
              }}
            />
          ))}
        </div>
      )}

      {creating && <OpenCTIProfileModal onClose={() => setCreating(false)} />}
      {editing && <OpenCTIProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function OpenCTIProfileModal({ profile, onClose }: { profile?: OpenCTIConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: OpenCTIConfigPayload) =>
      isEdit ? openctiApi.updateConfig(profile!.id, payload) : openctiApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['opencti-configs'] })
      qc.invalidateQueries({ queryKey: ['opencti-config'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: OpenCTIConfigPayload = {
      name: (fd.get('name') as string).trim(),
      description: fd.get('description') as string,
      url: fd.get('url') as string,
      username: fd.get('username') as string,
    }
    const password = fd.get('password') as string
    const token = fd.get('token') as string
    if (password) payload.password = password
    if (token) payload.token = token
    mutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New OpenCTI Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. OpenCTI Prod"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OpenCTI URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://opencti.example.com"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">API Token (Bearer) — recommended</label>
            <input
              name="token" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter API token'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (optional)</label>
              <input
                name="username" defaultValue={profile?.username}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password (optional)</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// HUNT TAB — Auto / File IOC / Manual
// ---------------------------------------------------------------------------
type ManualMode = 'lucene' | 'dsl'
type HuntMode = 'auto' | 'file' | 'manual'

interface HuntState {
  running: boolean
  hits: ELKHit[]
  progress?: AutoHuntProgress
  done?: AutoHuntDoneEvent
  batchErrors: { batch: number; bucket: string; error: string }[]
}

const initialHunt: HuntState = { running: false, hits: [], batchErrors: [] }

function HuntTab() {
  const [targetSiem, setTargetSiem] = useState<'elk' | 'splunk' | 'qradar'>('elk')
  const [targetIndices, setTargetIndices] = useState<string>('*')
  const [timeRange, setTimeRange] = useState<string>('') // empty = All Time
  const token = useAuthStore((s) => s.token)
  const esRef = useRef<EventSource | null>(null)

  const [mode, setMode] = useState<HuntMode>('auto')

  const [manualMode, setManualMode] = useState<ManualMode>('lucene')
  const [luceneQuery, setLuceneQuery] = useState('')
  const [dslText, setDslText] = useState(JSON.stringify({
    query: { match_all: {} },
    size: 50,
    sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'boolean' } }],
  }, null, 2))

  const [auto, setAuto] = useState<HuntState>(initialHunt)
  const [fileHunt, setFileHunt] = useState<HuntState>(initialHunt)
  const [parsedFile, setParsedFile] = useState<FileIOCParseResponse | null>(null)
  const [parsedFileName, setParsedFileName] = useState<string>('')

  useEffect(() => {
    return () => {
      esRef.current?.close()
      esRef.current = null
    }
  }, [])

  const { data: availableIndices } = useQuery({
    queryKey: ['siem-indices', targetSiem],
    queryFn: () => targetSiem === 'splunk' ? splunkApi.getIndices() : targetSiem === 'elk' ? elkApi.getIndices() : Promise.resolve([]),
    retry: false,
    enabled: targetSiem !== 'qradar'
  })

  const manualMutation = useMutation({
    mutationFn: (payload: any) => {
      if (targetSiem === 'splunk') return splunkApi.manualHunt(payload)
      if (targetSiem === 'qradar') return qradarApi.manualHunt(payload)
      return elkApi.manualHunt(payload)
    },
    onSuccess: (data) => toast.success(`Manual hunt completed in ${data.took || 0}ms`),
    onError: (err: any) => toast.error(getErrorMessage(err)),
  })

  const stopAnyStream = () => {
    esRef.current?.close()
    esRef.current = null
  }

  // Pick the streaming client for the selected SIEM. ELK/Splunk/QRadar all share
  // the same SSE event contract (progress/hits/error/done), so the handlers below
  // are identical regardless of target.
  const siemStreamApi = targetSiem === 'splunk' ? splunkApi : targetSiem === 'qradar' ? qradarApi : elkApi

  const startAutoHunt = () => {
    if (!token) { toast.error('Not authenticated'); return }
    if (auto.running || fileHunt.running) { toast.error('A hunt is already running'); return }
    stopAnyStream()
    setAuto({ ...initialHunt, running: true })
    esRef.current = siemStreamApi.streamAutoHunt(token, targetIndices, timeRange, {
      onProgress: (p) => setAuto((s) => ({ ...s, progress: p })),
      onHits:     (h) => setAuto((s) => ({ ...s, hits: [...s.hits, ...h.hits] })),
      onError:    (e) => setAuto((s) => ({ ...s, batchErrors: [...s.batchErrors, { batch: e.batch, bucket: e.bucket, error: e.error }] })),
      onDone:     (d) => {
        setAuto((s) => ({ ...s, running: false, done: d }))
        toast.success(`Auto hunt done — ${d.total_hits} hits across ${d.total_iocs} IOCs`)
      },
      onTransportError: () => {
        setAuto((s) => ({ ...s, running: false }))
        toast.error('Stream closed unexpectedly')
      },
    })
  }

  const stopAutoHunt = () => {
    stopAnyStream()
    setAuto((s) => ({ ...s, running: false }))
  }

  const runManual = () => {
    if (manualMode === 'lucene') {
      if (!luceneQuery.trim()) { toast.error(`Enter a ${targetSiem === 'splunk' ? 'SPL' : targetSiem === 'qradar' ? 'AQL' : 'Lucene'} query string`); return }
      manualMutation.mutate({ mode: 'lucene', query: luceneQuery, indices: targetIndices, timeRange })
      return
    }
    let parsed: Record<string, any>
    try { parsed = JSON.parse(dslText) }
    catch (e: any) { toast.error(`Invalid JSON: ${e.message}`); return }
    if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) { toast.error('DSL body must be a JSON object'); return }
    manualMutation.mutate({ mode: 'dsl', body: parsed, indices: targetIndices, timeRange })
  }

  const parseMutation = useMutation({
    mutationFn: (file: File) => elkApi.parseIOCFile(file),
    onSuccess: (data) => {
      setParsedFile(data)
      toast.success(`Parsed ${data.iocs.length} IOC(s) from ${data.total_lines} line(s)`)
    },
    onError: (err: any) => {
      setParsedFile(null)
      toast.error(getErrorMessage(err))
    },
  })

  const onFilePicked = (file: File | null) => {
    if (!file) return
    setParsedFileName(file.name)
    setFileHunt(initialHunt)
    parseMutation.mutate(file)
  }

  const startFileHunt = () => {
    if (!token) { toast.error('Not authenticated'); return }
    if (!parsedFile || parsedFile.iocs.length === 0) { toast.error('Parse a file first'); return }
    if (auto.running || fileHunt.running) { toast.error('A hunt is already running'); return }
    stopAnyStream()
    setFileHunt({ ...initialHunt, running: true })
    esRef.current = siemStreamApi.streamFileHunt(token, parsedFile.iocs, targetIndices, timeRange, {
      onProgress: (p) => setFileHunt((s) => ({ ...s, progress: p })),
      onHits:     (h) => setFileHunt((s) => ({ ...s, hits: [...s.hits, ...h.hits] })),
      onError:    (e) => setFileHunt((s) => ({ ...s, batchErrors: [...s.batchErrors, { batch: e.batch, bucket: e.bucket, error: e.error }] })),
      onDone:     (d) => {
        setFileHunt((s) => ({ ...s, running: false, done: d }))
        toast.success(`File hunt done — ${d.total_hits} hits across ${d.total_iocs} IOCs`)
      },
      onTransportError: () => {
        setFileHunt((s) => ({ ...s, running: false }))
        toast.error('Stream closed unexpectedly')
      },
    })
  }

  const stopFileHunt = () => {
    stopAnyStream()
    setFileHunt((s) => ({ ...s, running: false }))
  }

  const manualHits = manualMutation.data?.hits.hits ?? []
  const manualTotal = manualMutation.data?.hits.total
  const showManual = manualMutation.data !== undefined
  const showAuto = auto.running || auto.hits.length > 0 || auto.done !== undefined
  const showFile = fileHunt.running || fileHunt.hits.length > 0 || fileHunt.done !== undefined

  const activeHits = mode === 'auto' ? auto.hits : mode === 'file' ? fileHunt.hits : manualHits
  const activeTitle = mode === 'auto' ? "Auto Hunt Results" : mode === 'file' ? "File Hunt Results" : "Manual Hunt Results"
  const activeRunning = mode === 'auto' ? auto.running : mode === 'file' ? fileHunt.running : manualMutation.isPending
  
  let activeTotalLabel = ""
  let activeTookMs: number | undefined = undefined
  if (mode === 'auto') {
    activeTotalLabel = auto.done ? `${auto.done.total_hits} unique hits across ${auto.done.total_iocs} IOCs` : `${auto.hits.length} hits so far`
    activeTookMs = auto.done?.took_ms
  } else if (mode === 'file') {
    activeTotalLabel = fileHunt.done ? `${fileHunt.done.total_hits} hits across ${fileHunt.done.total_iocs} IOCs` : `${fileHunt.hits.length} hits so far`
    activeTookMs = fileHunt.done?.took_ms
  } else if (mode === 'manual') {
    activeTotalLabel = manualTotal ? `${manualTotal.value}${manualTotal.relation === 'gte' ? '+' : ''} matches` : ''
    activeTookMs = manualMutation.data?.took
  }

  const hasData = (mode === 'auto' && showAuto) || (mode === 'file' && showFile) || (mode === 'manual' && showManual)

  return (
    <div className="flex flex-col xl:flex-row gap-6 animate-in fade-in duration-500">
      {/* LEFT PANEL: CONFIG */}
      <div className="w-full xl:w-1/3 flex flex-col gap-5">
        {/* Target SIEM Selector */}
        <div className="bg-gray-900/60 p-4 border border-gray-800/60 rounded-xl flex items-center justify-between backdrop-blur-sm shadow-sm">
          <div className="flex flex-col">
            <span className="text-sm font-bold text-gray-200">Target SIEM</span>
            <span className="text-xs text-gray-500">Select analysis engine</span>
          </div>
          <div className="flex bg-gray-950 rounded-lg p-1 border border-gray-800">
            <button onClick={() => setTargetSiem('elk')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${targetSiem === 'elk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>ELK</button>
            <button onClick={() => setTargetSiem('splunk')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${targetSiem === 'splunk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>Splunk</button>
            <button onClick={() => setTargetSiem('qradar')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${targetSiem === 'qradar' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>QRadar</button>
          </div>
        </div>
        {/* Mode Selector */}
        <div className="bg-gray-900/60 p-1.5 border border-gray-800/60 rounded-xl flex gap-1.5 backdrop-blur-sm shadow-sm">
          <button onClick={() => setMode('auto')} className={`flex-1 flex flex-col items-center justify-center gap-2 py-4 rounded-lg text-sm font-semibold transition-all duration-200 ${mode === 'auto' ? 'bg-gray-800 border-emerald-500/40 shadow-md text-emerald-400' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}`}>
            <Zap className="h-5 w-5" /> Auto DB
          </button>
          <button onClick={() => setMode('file')} className={`flex-1 flex flex-col items-center justify-center gap-2 py-4 rounded-lg text-sm font-semibold transition-all duration-200 ${mode === 'file' ? 'bg-gray-800 border-emerald-500/40 shadow-md text-emerald-400' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}`}>
            <FileSearch className="h-5 w-5" /> File IOC
          </button>
          <button onClick={() => setMode('manual')} className={`flex-1 flex flex-col items-center justify-center gap-2 py-4 rounded-lg text-sm font-semibold transition-all duration-200 ${mode === 'manual' ? 'bg-gray-800 border-emerald-500/40 shadow-md text-emerald-400' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}`}>
            <Code2 className="h-5 w-5" /> Manual
          </button>
        </div>

        {/* Filter Bar */}
        <div className="bg-gray-900/60 p-4 border border-gray-800/60 rounded-xl backdrop-blur-sm shadow-sm space-y-4">
          {targetSiem !== 'qradar' && (<div className="space-y-1.5">
            <label className="text-xs font-semibold text-gray-400 flex items-center gap-2">
              Index Pattern
            </label>
            <select 
              value={targetIndices}
              onChange={e => setTargetIndices(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-emerald-500/50 appearance-none"
            >
              <option value="*">All Indices (*)</option>
              {availableIndices?.map(idx => (
                <option key={idx} value={idx}>{idx}</option>
              ))}
            </select>
          </div>)}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-gray-400 flex items-center gap-2">
              Time Range
            </label>
            <select 
              value={timeRange}
              onChange={e => setTimeRange(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-emerald-500/50 appearance-none"
            >
              <option value="">All Time</option>
              <option value="now-1h">Last 1 Hour</option>
              <option value="now-24h">Last 24 Hours</option>
              <option value="now-7d">Last 7 Days</option>
              <option value="now-30d">Last 30 Days</option>
              <option value="now-90d">Last 90 Days</option>
            </select>
          </div>
        </div>

        {/* Config Container */}
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-6 shadow-sm backdrop-blur-sm flex-1 flex flex-col">
          {mode === 'auto' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-left-2 duration-300">
              <div className="space-y-2">
                <h3 className="text-lg font-semibold text-gray-200 flex items-center gap-2"><Zap className="h-5 w-5 text-emerald-500" /> Auto Hunt (IOC DB)</h3>
                <p className="text-sm text-gray-400 leading-relaxed">Streams across every IOC stored in the database (synced from OpenCTI + manual entries). This is an intensive process.</p>
              </div>
              <div className="pt-2">
                {auto.running ? (
                  <button onClick={stopAutoHunt} className="w-full flex items-center justify-center gap-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 px-5 py-3 rounded-xl font-semibold transition-all shadow-[0_0_15px_rgba(239,68,68,0.15)]">
                    <X className="h-5 w-5" /> Stop Hunt
                  </button>
                ) : (
                  <button onClick={startAutoHunt} className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] px-5 py-3 rounded-xl font-semibold transition-all">
                    <Search className="h-5 w-5" /> Start Auto Hunt
                  </button>
                )}
              </div>
              {(auto.running || auto.progress) && <ProgressBlock state={auto} />}
            </div>
          )}

          {mode === 'file' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-left-2 duration-300">
              <div className="space-y-2">
                <h3 className="text-lg font-semibold text-gray-200 flex items-center gap-2"><FileSearch className="h-5 w-5 text-emerald-500" /> File IOC Hunt</h3>
                <p className="text-sm text-gray-400 leading-relaxed">Upload a <code className="text-emerald-400/90 bg-emerald-500/10 px-1.5 py-0.5 rounded font-mono text-xs border border-emerald-500/20">.txt</code> file — one indicator per line. The server auto-detects types and runs an ephemeral hunt.</p>
              </div>
              
              <label className="flex flex-col items-center justify-center border-2 border-dashed border-gray-700/60 hover:border-emerald-500/50 bg-gray-950/40 hover:bg-emerald-950/10 rounded-xl p-8 cursor-pointer transition-all mt-2 group">
                <Upload className="h-8 w-8 text-gray-500 group-hover:text-emerald-400 mb-3 transition-colors" />
                <span className="text-sm font-semibold text-gray-300 group-hover:text-gray-200">{parseMutation.isPending ? 'Parsing...' : 'Choose .txt file'}</span>
                <span className="text-xs text-gray-600 mt-1.5">Drag and drop or click</span>
                <input type="file" accept=".txt,.csv,.ioc,text/plain" hidden onChange={(e) => onFilePicked(e.target.files?.[0] ?? null)} />
              </label>

              {parsedFile && (
                <div className="pt-2 space-y-4">
                  <div className="flex items-center justify-between bg-gray-950/50 p-3 rounded-lg border border-gray-800/60">
                    <div className="flex flex-col">
                      <span className="text-sm text-emerald-400 font-semibold truncate max-w-[180px]">{parsedFileName}</span>
                      <div className="flex gap-2 text-[10px] font-bold tracking-wider text-gray-500 uppercase mt-1">
                        <span>{parsedFile.iocs.length} PARSED</span>
                        <span>•</span>
                        <span>{parsedFile.skipped.length} SKIPPED</span>
                      </div>
                    </div>
                    <button onClick={() => { setParsedFile(null); setParsedFileName(''); setFileHunt(initialHunt) }} className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-md transition-colors"><Trash2 className="h-4 w-4" /></button>
                  </div>

                  <div className="pt-2">
                    {fileHunt.running ? (
                      <button onClick={stopFileHunt} className="w-full flex items-center justify-center gap-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 px-5 py-3 rounded-xl font-semibold transition-all shadow-[0_0_15px_rgba(239,68,68,0.15)]">
                        <X className="h-5 w-5" /> Stop Hunt
                      </button>
                    ) : (
                      <button onClick={startFileHunt} disabled={parsedFile.iocs.length === 0} className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] px-5 py-3 rounded-xl font-semibold disabled:opacity-50 transition-all">
                        <Rocket className="h-5 w-5" /> Search Indicators
                      </button>
                    )}
                  </div>
                </div>
              )}
              {(fileHunt.running || fileHunt.progress) && <ProgressBlock state={fileHunt} />}
            </div>
          )}

          {mode === 'manual' && (
            <div className="space-y-4 flex flex-col h-full animate-in fade-in slide-in-from-left-2 duration-300">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-lg font-semibold text-gray-200 flex items-center gap-2"><Code2 className="h-5 w-5 text-emerald-500" /> Manual Search</h3>
                <div className="flex bg-gray-950/80 rounded-lg p-1 border border-gray-800/60 shadow-inner">
                  <button onClick={() => setManualMode('lucene')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${manualMode === 'lucene' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>
                    {targetSiem === 'splunk' ? 'SPL' : targetSiem === 'qradar' ? 'AQL' : 'Lucene'}
                  </button>
                  <button onClick={() => setManualMode('dsl')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${manualMode === 'dsl' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>DSL JSON</button>
                </div>
              </div>
              
              <div className="flex-1 min-h-[250px]">
                {manualMode === 'lucene' ? (
                  <textarea
                    value={luceneQuery} onChange={(e) => setLuceneQuery(e.target.value)}
                    placeholder={targetSiem === 'splunk' ? 'search index=* "192.168.1.1"' : targetSiem === 'qradar' ? 'SELECT * FROM events WHERE UTF8(payload) ILIKE \'%192.168.1.1%\'' : 'e.g. source.ip:"192.168.1.1" OR url.domain:"malicious.com"'}
                    className="w-full h-full bg-gray-950/80 border border-gray-800/60 rounded-xl px-5 py-4 text-emerald-400 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 font-mono text-sm resize-none shadow-inner transition-all placeholder:text-gray-700"
                  />
                ) : (
                  <textarea
                    value={dslText} onChange={(e) => setDslText(e.target.value)} spellCheck={false}
                    className="w-full h-full bg-gray-950/80 border border-gray-800/60 rounded-xl px-5 py-4 text-blue-400 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 font-mono text-xs resize-none leading-relaxed shadow-inner transition-all"
                  />
                )}
              </div>
              <button onClick={runManual} disabled={manualMutation.isPending} className="w-full flex items-center justify-center gap-2 mt-4 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] px-5 py-3 rounded-xl font-semibold disabled:opacity-50 transition-all">
                <Search className={`h-5 w-5 ${manualMutation.isPending ? 'animate-pulse' : ''}`} />
                {manualMutation.isPending ? 'Searching...' : 'Run Search'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* RIGHT PANEL: RESULTS */}
      <div className="w-full xl:w-2/3 h-[calc(100vh-140px)]">
        {!hasData && !activeRunning ? (
          <div className="h-full bg-gray-900/40 border border-gray-800/60 rounded-2xl p-12 text-center flex flex-col items-center justify-center backdrop-blur-sm shadow-sm relative overflow-hidden group">
            <div className="absolute inset-0 bg-emerald-500/5 blur-3xl rounded-full scale-0 group-hover:scale-150 transition-transform duration-1000 ease-out pointer-events-none"></div>
            <Search className="h-16 w-16 text-gray-700/40 mb-6 group-hover:text-emerald-500/30 transition-colors" />
            <h3 className="text-xl font-semibold text-gray-200">Ready to Hunt</h3>
            <p className="text-gray-500 text-sm max-w-sm mt-3 leading-relaxed">
              Select your hunt mode on the left and run a search to analyze matching Elasticsearch logs here.
            </p>
          </div>
        ) : (
          <ResultsPanel
            title={activeTitle}
            hits={activeHits}
            totalLabel={activeTotalLabel}
            tookMs={activeTookMs}
            isLoading={activeRunning}
          />
        )}
      </div>
    </div>
  )
}

function ProgressBlock({ state }: { state: HuntState }) {
  return (
    <div className="pt-4 space-y-4 text-sm border-t border-gray-800/60 mt-6">
      <div className="flex flex-wrap gap-3 font-mono text-[11px] font-semibold tracking-wider text-gray-400">
        <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-gray-800">BATCH: <span className="text-emerald-400">{state.progress?.batch ?? 0}</span> / {state.progress?.total_batches ?? '?'}</div>
        <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-gray-800 truncate max-w-[200px]">BUCKET: <span className="text-emerald-400">{state.progress?.bucket ?? '—'}</span></div>
        <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-red-900/30 shadow-[0_0_10px_rgba(239,68,68,0.1)]">HITS: <span className="text-red-400 font-bold">{state.progress?.total_hits ?? state.hits.length}</span></div>
        {state.done && <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-gray-800">TOOK: <span className="text-emerald-400">{state.done.took_ms}ms</span></div>}
      </div>
      <div className="h-2 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-800/60 shadow-inner">
        <div
          className="h-full bg-emerald-500 transition-all duration-300 relative shadow-[0_0_10px_rgba(16,185,129,0.8)]"
          style={{ width: `${state.progress && state.progress.total_batches > 0 ? Math.min(100, (state.progress.batch / state.progress.total_batches) * 100) : 0}%` }}
        >
          <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
        </div>
      </div>
      {state.batchErrors.length > 0 && (
        <details className="text-xs text-amber-400/90 bg-amber-950/30 border border-amber-900/40 rounded-lg p-3 backdrop-blur-sm">
          <summary className="cursor-pointer font-semibold outline-none">{state.batchErrors.length} batch error(s)</summary>
          <ul className="mt-3 space-y-1.5 font-mono max-h-32 overflow-auto custom-scrollbar opacity-80">
            {state.batchErrors.map((e, i) => (<li key={i}>batch {e.batch} [{e.bucket}]: {e.error}</li>))}
          </ul>
        </details>
      )}
    </div>
  )
}

// HUNT_RENDER_CAP bounds how many hit cards are mounted at once. Each card holds a
// JsonViewer, so rendering thousands of hits at once freezes the tab. We render up
// to the cap and let the operator reveal more in increments.
const HUNT_RENDER_CAP = 200

function ResultsPanel({ title, hits, totalLabel, tookMs, isLoading }: { title: string; hits: ELKHit[]; totalLabel: string; tookMs?: number; isLoading: boolean }) {
  const [visible, setVisible] = useState(HUNT_RENDER_CAP)
  // Reset the render window when a fresh hunt clears the accumulator, so a new
  // search doesn't inherit a huge window from the previous one.
  useEffect(() => { if (hits.length === 0) setVisible(HUNT_RENDER_CAP) }, [hits.length])
  const shown = hits.length > visible ? hits.slice(0, visible) : hits
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-2xl flex flex-col h-full shadow-sm backdrop-blur-sm overflow-hidden animate-in fade-in duration-300">
      <div className="p-5 bg-gray-950/40 border-b border-gray-800/60 flex flex-wrap justify-between items-center gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="relative">
            <ShieldAlert className={`h-6 w-6 ${hits.length > 0 ? 'text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 'text-emerald-500'}`} />
            {isLoading && <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping" />}
          </div>
          <span className="text-lg font-semibold text-gray-100">{title}</span>
          <span className="text-[11px] text-gray-400 font-bold tracking-wider px-3 py-1 rounded-md bg-gray-900/80 border border-gray-700/50 shadow-inner">{totalLabel || '0 matches'}</span>
        </div>
        {tookMs !== undefined && <span className="text-[11px] tracking-wider text-gray-500 font-bold bg-gray-950 px-3 py-1 rounded-md border border-gray-800">TOOK: <span className="text-emerald-400">{tookMs}MS</span></span>}
      </div>
      
      <div className="overflow-auto flex-1 p-5 bg-gray-950/20 custom-scrollbar relative">
        {hits.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-500">
            {isLoading ? (
               <div className="flex flex-col items-center gap-3">
                 <div className="h-8 w-8 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
                 <span className="text-sm font-medium animate-pulse">Searching through logs...</span>
               </div>
            ) : (
              <span className="italic">No matches found.</span>
            )}
          </div>
        ) : (
          <div className="space-y-6">
            {shown.map((hit, idx) => (
              <div key={`${hit._index}-${hit._id}-${idx}`} className="bg-gray-900/80 border border-gray-800 hover:border-red-500/40 transition-colors rounded-xl p-0 shadow-sm relative overflow-hidden group">
                {/* Red side indicator */}
                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-red-500 to-red-600/50 opacity-70 group-hover:opacity-100 transition-opacity"></div>
                
                <div className="flex flex-wrap justify-between items-center gap-3 p-3.5 bg-gray-950/60 border-b border-gray-800/60 ml-1.5">
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] font-bold tracking-wider text-gray-500 uppercase">Index</span>
                    <span className="text-xs font-mono bg-gray-900 text-emerald-400 px-2.5 py-1 rounded border border-gray-800">{hit._index}</span>
                  </div>
                  <span className="text-[10px] uppercase tracking-wider text-gray-500 font-bold bg-gray-900 px-2.5 py-1 rounded border border-gray-800">Score: {hit._score?.toFixed(2) ?? '—'}</span>
                </div>
                
                <div className="p-4 ml-1.5 bg-[#0d1117] overflow-x-auto custom-scrollbar">
                  <JsonViewer data={hit._source} className="!bg-transparent !p-0 !border-none !text-[13px] leading-relaxed" />
                </div>
              </div>
            ))}
            {hits.length > visible && (
              <div className="pt-1 pb-2 text-center">
                <button
                  onClick={() => setVisible((v) => v + HUNT_RENDER_CAP)}
                  className="text-xs font-semibold text-emerald-400 hover:text-emerald-300 bg-gray-900/80 border border-gray-700/60 hover:border-emerald-500/40 px-4 py-2 rounded-lg transition-colors"
                >
                  Show more — displaying {visible} of {hits.length}
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// Sigma over stored logs
// ---------------------------------------------------------------------------

// SigmaOfflinePanel runs the detection ruleset against logs that are already in
// the store — an .evtx uploaded from a machine that never had an agent, or logs
// collected weeks ago that are worth re-hunting after a ruleset update. Until
// now Sigma could only see events pulled live from an online agent.
function SigmaOfflinePanel({ caseId }: { caseId?: string }) {
  const [target, setTarget] = useState('')
  const [result, setResult] = useState<SigmaOfflineResult | null>(null)
  const [openAlerts, setOpenAlerts] = useState<Set<number>>(new Set())

  const { data: targets = [] } = useQuery({
    queryKey: ['sigma-offline-targets', caseId],
    queryFn: () => logsearchApi.sigmaTargets(caseId ? { case_id: caseId } : {}),
  })

  const scanMut = useMutation({
    mutationFn: () => logsearchApi.sigmaScanOffline(
      target ? { job_id: target } : { case_id: caseId },
    ),
    onSuccess: (r) => {
      setResult(r)
      const n = r.alerts?.length ?? 0
      n > 0
        ? toast.error(`${n} Sigma alert(s) across ${r.events_scanned.toLocaleString()} stored event(s)`)
        : toast.success(`No Sigma alerts — ${r.events_scanned.toLocaleString()} event(s) scanned with ${r.rules_count} rule(s)`)
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <div className="rounded-lg border border-gray-800 bg-gray-900/60 p-5">
      <div className="flex items-center gap-2 mb-1">
        <ShieldAlert className="h-4 w-4 text-red-400" />
        <h3 className="font-semibold text-gray-100 text-sm">Sigma scan on stored logs</h3>
      </div>
      <p className="text-xs text-gray-500 mb-3">
        Runs the Sigma ruleset against logs already in the store — an .evtx uploaded from a machine with no
        agent, or older logs worth re-hunting after a ruleset update. No agent has to be online.
      </p>

      <div className="flex flex-wrap items-end gap-2">
        <label className="text-xs text-gray-400">Target
          <select className="input mt-1 block min-w-[320px]" value={target} onChange={(e) => setTarget(e.target.value)}>
            <option value="">— every indexed log{caseId ? ' in this case' : ''} —</option>
            {targets.map((t) => (
              <option key={t.job_id} value={t.job_id}>
                {t.host} · {t.filename} ({t.docs_indexed.toLocaleString()} docs)
              </option>
            ))}
          </select>
        </label>
        <button className="btn-primary flex items-center gap-2 bg-red-600 hover:bg-red-500"
          disabled={scanMut.isPending} onClick={() => scanMut.mutate()}>
          {scanMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ShieldAlert className="h-4 w-4" />}
          {scanMut.isPending ? 'Scanning…' : 'Scan with Sigma'}
        </button>
      </div>

      {result && (
        <div className="mt-3 space-y-2">
          <div className="text-xs text-gray-400">
            {result.events_scanned.toLocaleString()} event(s) · {result.rules_count} rule(s) · index{' '}
            <span className="font-mono text-gray-300">{result.index}</span>
            {/* A capped scan is a sample, not full coverage — say so rather than
                letting a clean result imply the whole index was examined. */}
            {result.truncated && <span className="text-amber-400"> · event cap reached, this is a sample of the index</span>}
          </div>
          {result.alerts?.length > 0 ? (
            <div className="flex flex-col gap-1.5 max-h-[420px] overflow-auto">
              {result.alerts.map((a, i) => (
                <SigmaAlertRow key={i} alert={a} expanded={openAlerts.has(i)}
                  onToggle={() => setOpenAlerts((p) => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })} />
              ))}
            </div>
          ) : <p className="text-xs text-gray-500">No alerts.</p>}
        </div>
      )}
    </div>
  )
}
