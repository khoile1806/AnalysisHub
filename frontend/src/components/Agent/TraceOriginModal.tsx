import { useState, useEffect } from 'react'
import { useMutation, useQuery } from '@tanstack/react-query'
import {
  X, GitBranch, Loader2, Clock, User, CornerDownRight, RefreshCw, CalendarPlus,
  Copy, Ban, ArrowLeft, Crosshair, ChevronRight, Pencil, Trash2, Plus, Check,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { agentsApi, type Agent } from '@/api/agents'
import { traceApi, type TraceResult, type TraceSource, type TraceEvent } from '@/api/trace'
import { casesApi } from '@/api/cases'
import { getErrorMessage, safeFormat } from '@/lib/utils'

const KIND_CLS: Record<string, string> = {
  process: 'text-emerald-300 border-emerald-700/50 bg-emerald-900/20',
  prefetch: 'text-blue-300 border-blue-700/50 bg-blue-900/20',
  file: 'text-purple-300 border-purple-700/50 bg-purple-900/20',
  shimcache: 'text-cyan-300 border-cyan-700/50 bg-cyan-900/20',
  log: 'text-yellow-300 border-yellow-700/50 bg-yellow-900/20',
  download: 'text-orange-300 border-orange-700/50 bg-orange-900/20',
  persistence: 'text-red-300 border-red-700/50 bg-red-900/20',
}

// Every trace kind the manual-event editor can assign — mirrors KIND_CLS.
const EVENT_KINDS = ['process', 'prefetch', 'file', 'shimcache', 'log', 'download', 'persistence']

type Entity = { target: string; pid: number }

// TraceOriginModal reconstructs WHERE a selected process/file/app came from:
// it collects the agent's process snapshot (+ prefetch/shimcache, optionally MFT),
// then asks the backend to build the parent-process chain + a focused
// chronological timeline of every related trace. The collected artifacts are
// cached so the analyst can PIVOT (re-trace any ancestor) instantly without a
// second on-device scan.
export default function TraceOriginModal({ agent, target, pid, onClose }: {
  agent: Agent
  target: string
  pid: number
  onClose: () => void
}) {
  const [withMFT, setWithMFT] = useState(false)
  const [step, setStep] = useState('')
  const [result, setResult] = useState<TraceResult | null>(null)
  const [caseId, setCaseId] = useState<string>(agent.case_id ?? '')
  const [sources, setSources] = useState<TraceSource[]>([])
  const [cur, setCur] = useState<Entity>({ target, pid })
  const [history, setHistory] = useState<Entity[]>([])
  // Editable copy of the reconstructed timeline — the analyst can correct /
  // annotate / delete / add nodes by hand before committing to the case.
  const [timeline, setTimeline] = useState<TraceEvent[]>([])
  const [editIdx, setEditIdx] = useState<number | null>(null)

  const online = agent.status === 'online'

  // Re-seed the editable timeline whenever a fresh trace result arrives.
  useEffect(() => { setTimeline(result?.timeline ?? []); setEditIdx(null) }, [result])

  const updateEvent = (i: number, patch: Partial<TraceEvent>) =>
    setTimeline((prev) => prev.map((e, idx) => (idx === i ? { ...e, ...patch } : e)))
  const deleteEvent = (i: number) => {
    setTimeline((prev) => prev.filter((_, idx) => idx !== i))
    setEditIdx(null)
  }
  const addEvent = () => {
    setTimeline((prev) => {
      const next: TraceEvent = { time: '', kind: 'log', title: '', detail: '', source: 'manual' }
      setEditIdx(prev.length)
      return [...prev, next]
    })
  }

  const copy = (label: string, val: string) => {
    if (!val) return
    navigator.clipboard?.writeText(val)
    toast.success(`${label} copied`)
  }

  const { data: cases = [] } = useQuery({ queryKey: ['cases'], queryFn: casesApi.list })

  const addMut = useMutation({
    mutationFn: () => traceApi.addToCase(caseId, {
      host: agent.hostname || agent.name,
      target: cur.target,
      events: timeline,
    }),
    onSuccess: (r) => toast.success(`Added ${r.events_created} event(s) to the case timeline`),
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const killMut = useMutation({
    mutationFn: (p: number) => agentsApi.killProcess(agent.id, p),
    onSuccess: () => toast.success('Terminate command sent to endpoint'),
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  // Full collect (on-device scan) + trace. Used for the first trace and Re-collect.
  const collectMut = useMutation({
    mutationFn: async (e: Entity) => {
      const collected: TraceSource[] = []
      const collect = async (label: string, type: TraceSource['type'], fn: () => Promise<any>) => {
        setStep(`Collecting ${label}…`)
        try { collected.push({ type, data: await fn() }) } catch (err) { toast.error(`${label}: ${getErrorMessage(err)}`) }
      }
      // Collect the sources that exist on this agent's OS. Prefetch / Shimcache /
      // MFT are Windows-only artifacts — skip them on Linux so the trace runs
      // cleanly (using processes, autoruns and browser) instead of erroring.
      const isLinux = (agent.os || '').toLowerCase().includes('linux')
      await collect('processes', 'processes', () => agentsApi.parseProcessScan(agent.id))
      await collect('autoruns', 'autoruns', () => agentsApi.parseAutoruns(agent.id))
      await collect('browser', 'browser', () => agentsApi.parseBrowser(agent.id))
      if (!isLinux) {
        await collect('prefetch', 'prefetch', () => agentsApi.parsePrefetch(agent.id))
        await collect('shimcache', 'shimcache', () => agentsApi.parseShimcache(agent.id))
        if (withMFT) await collect('MFT (slow)', 'mft', () => agentsApi.parseMFT(agent.id))
      }
      setSources(collected)
      setStep('Reconstructing origin…')
      return traceApi.entity(e.target, e.pid, collected)
    },
    onSuccess: (r) => { setResult(r); setStep('') },
    onError: (e) => { setStep(''); toast.error(getErrorMessage(e)) },
  })

  // Instant re-trace over already-collected artifacts (used for pivoting).
  const retraceMut = useMutation({
    mutationFn: (e: Entity) => traceApi.entity(e.target, e.pid, sources),
    onSuccess: (r) => setResult(r),
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const busy = collectMut.isPending
  const pivoting = retraceMut.isPending

  const runTrace = (e: Entity) => {
    if (sources.length) retraceMut.mutate(e)
    else collectMut.mutate(e)
  }

  // pivot re-traces a different entity (e.g. an ancestor process) in place.
  const pivot = (t: string, p: number) => {
    if (t === cur.target && p === cur.pid) return
    setHistory((h) => [...h, cur])
    const next = { target: t, pid: p }
    setCur(next)
    runTrace(next)
  }

  const back = () => {
    if (!history.length) return
    const prev = history[history.length - 1]
    setHistory((h) => h.slice(0, -1))
    setCur(prev)
    runTrace(prev)
  }

  const ancestry = result?.ancestry ?? []

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-deep-900 border border-slate-700 rounded-xl w-full max-w-4xl max-h-[88vh] shadow-2xl flex flex-col" onClick={(e) => e.stopPropagation()}>

        {/* ---- Header (fixed) ---- */}
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800 shrink-0">
          {history.length > 0 && (
            <button onClick={back} title="Back to previous entity" className="text-gray-400 hover:text-emerald-300">
              <ArrowLeft className="h-4 w-4" />
            </button>
          )}
          <GitBranch className="h-4 w-4 text-emerald-400 shrink-0" />
          <h3 className="text-sm font-semibold text-gray-200 truncate">
            Trace origin — <span className="font-mono text-emerald-300">{cur.target}{cur.pid > 0 ? ` (pid ${cur.pid})` : ''}</span>
          </h3>
          {pivoting && <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-400" />}
          <button onClick={onClose} className="ml-auto text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
        </div>

        {/* breadcrumb of the pivot trail */}
        {history.length > 0 && (
          <div className="flex items-center gap-1 flex-wrap px-4 py-1.5 border-b border-slate-800/60 bg-gray-950/40 text-[11px] shrink-0">
            {[...history, cur].map((e, i, arr) => (
              <span key={i} className="flex items-center gap-1">
                {i > 0 && <ChevronRight className="h-3 w-3 text-gray-600" />}
                <span className={`font-mono ${i === arr.length - 1 ? 'text-emerald-300' : 'text-gray-500'}`}>{e.target}</span>
              </span>
            ))}
          </div>
        )}

        {/* ---- Body (scrolls) ---- */}
        <div className="p-4 overflow-y-auto space-y-4 flex-1">
          {!result && !busy && (
            <div className="space-y-3">
              <p className="text-sm text-gray-400">
                Reconstruct the parent-process chain, owner, start time and every related trace
                (prefetch / shimcache / autoruns / browser-download{withMFT ? ' / MFT' : ''}) for <span className="font-mono text-gray-200">{cur.target}</span> on <span className="text-gray-200">{agent.name}</span>.
              </p>
              <label className="flex items-center gap-2 text-xs text-gray-400">
                <input type="checkbox" checked={withMFT} onChange={(e) => setWithMFT(e.target.checked)} /> Include MFT file timestamps (slower)
              </label>
              <button onClick={() => collectMut.mutate(cur)} disabled={!online}
                className="btn-primary flex items-center gap-2 disabled:opacity-50" title={!online ? 'Agent is offline' : ''}>
                <GitBranch className="h-4 w-4" /> Trace origin
              </button>
              {!online && <p className="text-xs text-yellow-400">Agent is offline — bring it online to collect live artifacts.</p>}
            </div>
          )}

          {busy && (
            <div className="flex items-center gap-2 text-sm text-gray-400 py-10 justify-center">
              <Loader2 className="h-4 w-4 animate-spin" /> {step}
            </div>
          )}

          {result && !busy && (
            <>
              {/* Summary */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                <SummaryCell icon={User} label="User" value={result.summary.user || '—'} />
                <SummaryCell icon={CornerDownRight} label="Parent" value={result.summary.parent || '—'} />
                <SummaryCell icon={Clock} label="Started" value={result.summary.created ? safeFormat(result.summary.created, 'MM-dd HH:mm:ss') : '—'} />
                <SummaryCell icon={Clock} label="Earliest trace" value={result.summary.origin || '—'} />
              </div>

              {/* Process lineage — interactive tree */}
              {ancestry.length > 0 && (
                <div>
                  <h4 className="text-[11px] uppercase tracking-wide text-gray-500 mb-2">
                    Process lineage (root → target) · <span className="text-gray-600 normal-case">click a node to trace it</span>
                  </h4>
                  <div className="space-y-1">
                    {ancestry.map((p, i) => {
                      const isCurrent = p.name === cur.target || p.pid === cur.pid
                      return (
                        <div key={i} className="flex items-center gap-2 group" style={{ paddingLeft: `${i * 18}px` }}>
                          {i > 0 && <CornerDownRight className="h-3 w-3 text-gray-600 shrink-0" />}
                          <div className={`flex items-center gap-2 flex-1 min-w-0 rounded border px-2 py-1.5 text-xs transition-colors
                            ${isCurrent ? 'border-emerald-600/60 bg-emerald-900/20' : 'border-slate-800 bg-gray-900/40 hover:border-slate-600'}`}>
                            <span className="font-mono text-gray-100 shrink-0">{p.name}</span>
                            <span className="text-gray-600 shrink-0">pid {p.pid}</span>
                            {p.user && <span className="text-gray-500 shrink-0 hidden sm:inline">· {p.user}</span>}
                            {p.created && <span className="text-gray-600 shrink-0 hidden md:inline">· {safeFormat(p.created, 'HH:mm:ss')}</span>}
                            {p.cmdline && <span className="font-mono text-gray-600 truncate" title={p.cmdline}>· {p.cmdline}</span>}
                            <div className="ml-auto flex items-center gap-1 shrink-0 opacity-0 group-hover:opacity-100 transition-opacity">
                              {!isCurrent && (
                                <button onClick={() => pivot(p.name, p.pid)} title="Trace this process's origin"
                                  className="p-1 rounded text-gray-400 hover:text-emerald-300 hover:bg-emerald-900/30"><Crosshair className="h-3.5 w-3.5" /></button>
                              )}
                              {(p.cmdline || p.path) && (
                                <button onClick={() => copy('Command line', p.cmdline || p.path || '')} title="Copy command line / path"
                                  className="p-1 rounded text-gray-400 hover:text-gray-200 hover:bg-gray-800"><Copy className="h-3.5 w-3.5" /></button>
                              )}
                              {online && p.pid > 0 && (
                                <button
                                  onClick={() => { if (window.confirm(`Terminate ${p.name} (pid ${p.pid}) on ${agent.name}?`)) killMut.mutate(p.pid) }}
                                  title="Terminate this process on the endpoint"
                                  className="p-1 rounded text-gray-400 hover:text-red-400 hover:bg-red-900/30"><Ban className="h-3.5 w-3.5" /></button>
                              )}
                            </div>
                          </div>
                        </div>
                      )
                    })}
                  </div>
                </div>
              )}

              {/* Focused timeline — editable */}
              <div>
                <div className="flex items-center justify-between mb-2">
                  <h4 className="text-[11px] uppercase tracking-wide text-gray-500">Origin timeline ({timeline.length}) · <span className="text-gray-600 normal-case">hover a node to edit</span></h4>
                  <button onClick={addEvent} className="flex items-center gap-1 text-[11px] text-gray-400 hover:text-emerald-300">
                    <Plus className="h-3 w-3" /> Add event
                  </button>
                </div>
                {timeline.length === 0 ? (
                  <p className="text-xs text-gray-500">No time-anchored traces found — use “Add event” to record one by hand.</p>
                ) : (
                  <div className="relative space-y-1.5 before:absolute before:left-[7px] before:top-1 before:bottom-1 before:w-px before:bg-slate-800">
                    {timeline.map((e, i) => (
                      <div key={i} className="group relative flex items-start gap-2 rounded border border-slate-800 bg-gray-900/40 hover:border-slate-600 pl-5 pr-3 py-1.5 transition-colors">
                        <span className="absolute left-[3px] top-3 h-2 w-2 rounded-full bg-emerald-500/70 ring-2 ring-deep-900" />
                        {editIdx === i ? (
                          /* ---- inline editor ---- */
                          <div className="min-w-0 flex-1 space-y-1.5">
                            <div className="flex items-center gap-1.5">
                              <select value={e.kind} onChange={(ev) => updateEvent(i, { kind: ev.target.value as TraceEvent['kind'] })}
                                className="input text-[11px] py-0.5 px-1.5 w-28">
                                {EVENT_KINDS.map((k) => <option key={k} value={k}>{k}</option>)}
                              </select>
                              <input value={e.time} onChange={(ev) => updateEvent(i, { time: ev.target.value })}
                                placeholder="YYYY-MM-DD HH:MM:SS"
                                className="input text-[11px] py-0.5 px-1.5 font-mono flex-1" />
                              <button onClick={() => setEditIdx(null)} title="Done" className="p-1 rounded text-emerald-400 hover:bg-emerald-900/30"><Check className="h-3.5 w-3.5" /></button>
                              <button onClick={() => deleteEvent(i)} title="Delete event" className="p-1 rounded text-red-400 hover:bg-red-900/30"><Trash2 className="h-3.5 w-3.5" /></button>
                            </div>
                            <input value={e.title} onChange={(ev) => updateEvent(i, { title: ev.target.value })}
                              placeholder="Title" className="input text-xs py-0.5 px-1.5 w-full" />
                            <input value={e.detail ?? ''} onChange={(ev) => updateEvent(i, { detail: ev.target.value })}
                              placeholder="Detail (optional)" className="input text-[11px] py-0.5 px-1.5 font-mono w-full" />
                          </div>
                        ) : (
                          /* ---- read view ---- */
                          <>
                            <span className={`text-[9px] font-mono px-1.5 py-0.5 rounded border shrink-0 mt-0.5 ${KIND_CLS[e.kind] ?? 'text-gray-400 border-slate-700'}`}>{e.kind}</span>
                            <div className="min-w-0 flex-1">
                              <div className="text-xs text-gray-200">{e.title || <span className="text-gray-600 italic">untitled</span>}</div>
                              {e.detail && <div className="text-[11px] text-gray-500 font-mono break-all">{e.detail}</div>}
                            </div>
                            <div className="flex items-center gap-0.5 shrink-0 mt-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button onClick={() => setEditIdx(i)} title="Edit this node" className="p-1 rounded text-gray-500 hover:text-emerald-300 hover:bg-emerald-900/30"><Pencil className="h-3 w-3" /></button>
                              <button onClick={() => copy('Entry', e.detail ? `${e.title} — ${e.detail}` : e.title)} title="Copy this entry"
                                className="p-1 rounded text-gray-500 hover:text-gray-200 hover:bg-gray-800"><Copy className="h-3 w-3" /></button>
                              <button onClick={() => deleteEvent(i)} title="Delete this node" className="p-1 rounded text-gray-500 hover:text-red-400 hover:bg-red-900/30"><Trash2 className="h-3 w-3" /></button>
                            </div>
                            <span className="text-[10px] font-mono text-gray-500 shrink-0 mt-0.5">{e.time || '—'}</span>
                          </>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </>
          )}
        </div>

        {/* ---- Footer (fixed) ---- */}
        {result && !busy && (
          <div className="flex items-center gap-2 px-4 py-2.5 border-t border-slate-800 bg-gray-950/40 shrink-0">
            <button onClick={() => { setResult(null); setSources([]); collectMut.mutate(cur) }} disabled={!online}
              className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-md text-xs font-medium border border-slate-700 bg-gray-800 text-gray-300 hover:text-white hover:bg-gray-700 transition disabled:opacity-50 whitespace-nowrap"
              title={!online ? 'Agent is offline' : 'Re-scan the endpoint and trace again'}>
              <RefreshCw className="h-3.5 w-3.5" /> Re-collect
            </button>
            {timeline.length > 0 && (
              <div className="flex items-center gap-2 ml-auto min-w-0">
                <select className="input text-xs py-1.5 max-w-[160px]" value={caseId} onChange={(e) => setCaseId(e.target.value)}>
                  <option value="">Select case…</option>
                  {cases.map((c) => <option key={c.id} value={c.id}>{c.name}</option>)}
                </select>
                <button onClick={() => addMut.mutate()} disabled={!caseId || addMut.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white transition disabled:opacity-50 disabled:cursor-not-allowed whitespace-nowrap">
                  {addMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <CalendarPlus className="h-3.5 w-3.5" />} Add to case
                </button>
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}

function SummaryCell({ icon: Icon, label, value }: { icon: React.ElementType; label: string; value: string }) {
  return (
    <div className="rounded border border-slate-800 bg-gray-900/40 p-2">
      <div className="flex items-center gap-1 text-[10px] uppercase text-gray-500"><Icon className="h-3 w-3" /> {label}</div>
      <div className="text-gray-200 mt-0.5 truncate font-mono" title={value}>{value}</div>
    </div>
  )
}
