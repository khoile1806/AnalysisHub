import { useState, type FormEvent } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  Search, Layers, ShieldAlert, ShieldCheck, Lock, ExternalLink, Loader2,
  AlertTriangle, Boxes, Info, Cloud, FileWarning, Gauge, Github, Clock, Cookie, Globe, Crosshair, History, Trash2,
} from 'lucide-react'
import { osintApi, type TechStackResult, type DetectedTech, type TechCVE, type ExposedPath, type TechRisk, type TechBatchRow, type TechStackSession } from '@/api/osint'
import { vulnscanApi } from '@/api/vulnscan'
import { SeverityBadge } from '@/components/StatusBadge'
import { getErrorMessage, safeDistanceToNow } from '@/lib/utils'

// TechStackPanel is the standalone "paste a URL → tech stack → possible CVEs"
// tool that lives as a tab inside the OSINT page.
export function TechStackPanel() {
  const qc = useQueryClient()
  const [mode, setMode] = useState<'single' | 'batch'>('single')
  const [url, setUrl] = useState('')
  const [batchText, setBatchText] = useState('')
  const [active, setActive] = useState(true)
  const [deep, setDeep] = useState(false)
  // When set, the results area shows a saved session instead of the live lookup.
  const [sessionId, setSessionId] = useState<string | null>(null)

  const sessions = useQuery({ queryKey: ['techstack-sessions'], queryFn: osintApi.techstackSessions })
  const sessionView = useQuery({
    queryKey: ['techstack-session', sessionId],
    queryFn: () => osintApi.techstackSession(sessionId!),
    enabled: !!sessionId,
  })

  const lookup = useMutation({
    mutationFn: (u: string) => osintApi.techstack(u.trim(), active, deep),
    retry: false,
    onSuccess: () => qc.invalidateQueries({ queryKey: ['techstack-sessions'] }),
  })
  const batch = useMutation({
    mutationFn: (urls: string[]) => osintApi.techstackBatch(urls, active, deep),
    retry: false,
  })
  const delSession = useMutation({
    mutationFn: (id: string) => osintApi.deleteTechstackSession(id),
    onSuccess: (_d, id) => {
      if (id === sessionId) setSessionId(null)
      qc.invalidateQueries({ queryKey: ['techstack-sessions'] })
    },
  })

  const onSubmit = (e: FormEvent) => {
    e.preventDefault()
    setSessionId(null) // a new run supersedes any open session
    if (mode === 'single') {
      if (url.trim()) lookup.mutate(url.trim())
    } else {
      const urls = batchText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean)
      if (urls.length) batch.mutate(urls)
    }
  }

  // Drill into one row of a batch result — runs the single lookup (served instantly
  // from the same 1-hour cache).
  const openSingle = (u: string) => {
    setSessionId(null)
    setMode('single')
    setUrl(u)
    lookup.mutate(u)
  }

  const openSession = (s: TechStackSession) => {
    setMode('single')
    setUrl(s.url)
    setSessionId(s.id)
  }

  // The result to render: an opened session takes precedence over the live lookup.
  const result = sessionId ? sessionView.data : lookup.data
  const batchUrlCount = batchText.split(/[\s,]+/).map((s) => s.trim()).filter(Boolean).length

  return (
    <div className="space-y-5">
      <form onSubmit={onSubmit} className="card p-4 space-y-3">
        <div className="flex items-center justify-between gap-3 flex-wrap">
          <div className="flex items-center gap-2 text-sm text-gray-300">
            <Layers className="h-4 w-4 text-emerald-400" />
            <span className="font-medium">Tech-Stack &amp; CVE Lookup</span>
          </div>
          <div className="flex rounded-md border border-gray-800 overflow-hidden text-xs">
            <button type="button" onClick={() => setMode('single')}
              className={`px-3 py-1 ${mode === 'single' ? 'bg-emerald-900/40 text-emerald-300' : 'text-gray-400 hover:text-gray-200'}`}>
              Single URL
            </button>
            <button type="button" onClick={() => setMode('batch')}
              className={`px-3 py-1 border-l border-gray-800 ${mode === 'batch' ? 'bg-emerald-900/40 text-emerald-300' : 'text-gray-400 hover:text-gray-200'}`}>
              Batch
            </button>
          </div>
        </div>

        {mode === 'single' ? (
          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto] gap-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
              <input className="input pl-9" placeholder="https://example.com" value={url}
                onChange={(e) => setUrl(e.target.value)} maxLength={2048}
                autoCapitalize="off" autoCorrect="off" spellCheck={false} />
            </div>
            <button type="submit" className="btn-primary" disabled={!url.trim() || lookup.isPending}>
              {lookup.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Analyze
            </button>
          </div>
        ) : (
          <div className="space-y-2">
            <textarea className="input font-mono text-xs min-h-[110px]" placeholder={"One URL per line (max 25)\nexample.com\nhttps://another.site"}
              value={batchText} onChange={(e) => setBatchText(e.target.value)} spellCheck={false} />
            <button type="submit" className="btn-primary" disabled={batchUrlCount === 0 || batch.isPending}>
              {batch.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Layers className="h-4 w-4" />}
              Scan {batchUrlCount > 0 ? `${Math.min(batchUrlCount, 25)} URL(s)` : ''}
            </button>
          </div>
        )}

        <div className="flex flex-col gap-1.5">
          <label className="inline-flex items-center gap-2 text-xs text-gray-400 cursor-pointer select-none">
            <input type="checkbox" checked={active} onChange={(e) => setActive(e.target.checked)} className="accent-emerald-500" />
            Active probing — fetch known CMS version files for more accurate versions
          </label>
          <label className="inline-flex items-center gap-2 text-xs text-amber-500/90 cursor-pointer select-none">
            <input type="checkbox" checked={deep} onChange={(e) => setDeep(e.target.checked)} className="accent-amber-500" />
            <FileWarning className="h-3.5 w-3.5" />
            Deep scan — probe for exposed files &amp; panels (.git, .env, actuator, phpMyAdmin). Aggressive — authorized targets only.
          </label>
        </div>
        <p className="text-[11px] text-gray-600">
          Private / internal hosts are rejected. Results cached 1 hour. JS libraries use the retire.js vulnerability database.
        </p>
      </form>

      {/* Batch results */}
      {mode === 'batch' && batch.isError && (
        <div className="card p-6 flex items-center gap-3 text-red-400">
          <AlertTriangle className="h-5 w-5 shrink-0" /><p className="text-sm">{getErrorMessage(batch.error)}</p>
        </div>
      )}
      {mode === 'batch' && batch.isPending && (
        <div className="card p-8 flex flex-col items-center gap-3 text-gray-500">
          <Loader2 className="h-6 w-6 animate-spin" /><p className="text-sm">Scanning {batchUrlCount} target(s)…</p>
        </div>
      )}
      {mode === 'batch' && batch.data && <BatchTable rows={batch.data} onOpen={openSingle} />}

      {/* Saved sessions history */}
      <SessionsHistory
        sessions={sessions.data ?? []}
        activeId={sessionId}
        onOpen={openSession}
        onDelete={(id) => delSession.mutate(id)}
      />

      {/* Single results (live lookup or an opened session) */}
      {mode === 'single' && !sessionId && lookup.isError && (
        <div className="card p-6 flex items-center gap-3 text-red-400">
          <AlertTriangle className="h-5 w-5 shrink-0" /><p className="text-sm">{getErrorMessage(lookup.error)}</p>
        </div>
      )}
      {mode === 'single' && !sessionId && lookup.isPending && (
        <div className="card p-8 flex flex-col items-center gap-3 text-gray-500">
          <Loader2 className="h-6 w-6 animate-spin" /><p className="text-sm">Fetching &amp; fingerprinting {url.trim()} …</p>
        </div>
      )}
      {mode === 'single' && sessionId && sessionView.isPending && (
        <div className="card p-8 flex flex-col items-center gap-3 text-gray-500">
          <Loader2 className="h-6 w-6 animate-spin" /><p className="text-sm">Loading saved session…</p>
        </div>
      )}
      {mode === 'single' && result && (
        <>
          {sessionId && (
            <div className="flex items-center gap-2 text-[11px] text-gray-500">
              <History className="h-3.5 w-3.5" /> Viewing a saved session.
              <button className="text-emerald-400 hover:text-emerald-300" onClick={() => { setSessionId(null); if (url.trim()) lookup.mutate(url.trim()) }}>Re-run now</button>
            </div>
          )}
          <Result result={result} />
        </>
      )}
    </div>
  )
}

const SESSION_RISK: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-emerald-400', '': 'text-gray-500',
}

function SessionsHistory({ sessions, activeId, onOpen, onDelete }: {
  sessions: TechStackSession[]; activeId: string | null
  onOpen: (s: TechStackSession) => void; onDelete: (id: string) => void
}) {
  if (sessions.length === 0) return null
  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-gray-800 text-xs text-gray-400">
        <History className="h-3.5 w-3.5 text-emerald-400" />
        <span className="font-medium">Saved sessions</span>
        <span className="text-gray-600">({sessions.length}) — click to reopen; runs are kept, not lost</span>
      </div>
      <div className="max-h-64 overflow-y-auto divide-y divide-gray-800/50">
        {sessions.map((s) => (
          <div key={s.id}
            className={`flex items-center gap-3 px-3 py-2 cursor-pointer hover:bg-gray-800/30 ${activeId === s.id ? 'bg-emerald-950/20' : ''}`}
            onClick={() => onOpen(s)}>
            <span className={`font-mono text-sm font-semibold tabular-nums w-8 text-center ${SESSION_RISK[s.risk_level] ?? 'text-gray-500'}`}>{s.risk_score}</span>
            <div className="min-w-0 flex-1">
              <div className="text-sm text-gray-200 truncate">{s.host || s.url}</div>
              <div className="text-[11px] text-gray-600 truncate">
                {s.tech_count} tech · {s.cve_total} CVE{s.kev > 0 ? ` · ${s.kev} KEV` : ''}{s.exploit > 0 ? ` · ${s.exploit} exploit` : ''}
                {s.active ? ' · active' : ''}{s.deep ? ' · deep' : ''} · {safeDistanceToNow(s.updated_at, { addSuffix: true })}
              </div>
            </div>
            <button className="text-gray-600 hover:text-red-400 shrink-0" title="Delete session"
              onClick={(e) => { e.stopPropagation(); onDelete(s.id) }}>
              <Trash2 className="h-3.5 w-3.5" />
            </button>
          </div>
        ))}
      </div>
    </div>
  )
}

const RISK_BADGE: Record<string, string> = {
  critical: 'text-red-400', high: 'text-orange-400', medium: 'text-yellow-400', low: 'text-emerald-400',
}

function BatchTable({ rows, onOpen }: { rows: TechBatchRow[]; onOpen: (u: string) => void }) {
  const sorted = [...rows].sort((a, b) => (b.risk_score || 0) - (a.risk_score || 0))
  return (
    <div className="card overflow-hidden">
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="bg-gray-900/60 border-b border-gray-800 text-gray-500">
            <tr className="text-left text-[11px] uppercase tracking-wider">
              <th className="px-3 py-2">Host</th>
              <th className="px-3 py-2 text-center">Risk</th>
              <th className="px-3 py-2 text-center">Tech</th>
              <th className="px-3 py-2 text-center">CVEs</th>
              <th className="px-3 py-2 text-center">Crit</th>
              <th className="px-3 py-2 text-center">KEV</th>
              <th className="px-3 py-2 text-center">Exploit</th>
              <th className="px-3 py-2 text-center">Exposed</th>
              <th className="px-3 py-2">Edge</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800/50">
            {sorted.map((r) => (
              <tr key={r.url} onClick={() => !r.error && onOpen(r.url)}
                className={`${r.error ? 'opacity-60' : 'cursor-pointer hover:bg-gray-800/30'}`}>
                <td className="px-3 py-2">
                  <div className="font-mono text-emerald-400 truncate max-w-[220px]">{r.host || r.url}</div>
                  {r.error
                    ? <div className="text-[11px] text-red-400/80 truncate max-w-[220px]">{r.error}</div>
                    : r.title && <div className="text-[11px] text-gray-500 truncate max-w-[220px]">{r.title}</div>}
                </td>
                <td className="px-3 py-2 text-center">
                  {r.error ? '—' : <span className={`font-mono font-semibold ${RISK_BADGE[r.risk_level || 'low']}`}>{r.risk_score}</span>}
                </td>
                <td className="px-3 py-2 text-center text-gray-300 font-mono">{r.error ? '' : r.tech_count}</td>
                <td className="px-3 py-2 text-center font-mono text-amber-400">{r.error ? '' : (r.cve_total || '')}</td>
                <td className="px-3 py-2 text-center font-mono text-red-400">{r.critical || ''}</td>
                <td className="px-3 py-2 text-center font-mono text-red-400">{r.kev || ''}</td>
                <td className="px-3 py-2 text-center font-mono text-red-400">{r.exploit || ''}</td>
                <td className="px-3 py-2 text-center font-mono text-orange-400">{r.exposures || ''}</td>
                <td className="px-3 py-2 text-[11px] text-sky-400/80 truncate max-w-[140px]">{(r.edge || []).join(', ')}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <p className="text-[11px] text-gray-600 px-3 py-2 border-t border-gray-800/50">Click a row to open its full report (cached).</p>
    </div>
  )
}

function Result({ result }: { result: TechStackResult }) {
  const versioned = result.technologies.filter((t) => t.version)
  const detected = result.technologies.filter((t) => !t.version)

  return (
    <div className="space-y-5">
      {/* Risk triage */}
      {result.risk && <RiskSummary risk={result.risk} />}

      {/* Target summary */}
      <div className="card p-4">
        <div className="flex items-start justify-between gap-4 flex-wrap">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              <a href={result.final_url} target="_blank" rel="noopener noreferrer"
                className="text-emerald-400 hover:text-emerald-300 font-medium inline-flex items-center gap-1.5 truncate">
                {result.host}
                <ExternalLink className="h-3.5 w-3.5 shrink-0" />
              </a>
              <span className="text-xs font-mono text-gray-500">HTTP {result.status_code}</span>
            </div>
            {result.title && <p className="text-sm text-gray-400 mt-1 truncate">{result.title}</p>}
            <div className="flex flex-wrap gap-x-4 gap-y-1 mt-2 text-xs text-gray-500">
              {result.server && <span>Server: <span className="text-gray-300 font-mono">{result.server}</span></span>}
              {result.powered_by && <span>Powered-By: <span className="text-gray-300 font-mono">{result.powered_by}</span></span>}
              {result.tls?.version && <span className="inline-flex items-center gap-1"><Lock className="h-3 w-3" />{result.tls.version}</span>}
            </div>
          </div>
          <StatTiles summary={result.cve_summary} techCount={result.technologies.length} versioned={versioned.length} />
        </div>
        {result.scope_note && (
          <div className="mt-3 flex items-start gap-2 text-xs text-yellow-500/90 bg-yellow-900/10 border border-yellow-900/30 rounded p-2">
            <Info className="h-3.5 w-3.5 mt-0.5 shrink-0" />
            {result.scope_note}
          </div>
        )}
        {result.edge_services && result.edge_services.length > 0 && (
          <div className="mt-3 pt-3 border-t border-gray-800/60">
            <div className="flex items-center gap-2 flex-wrap">
              <Cloud className="h-4 w-4 text-sky-400" />
              <span className="text-xs text-gray-400">Edge protection:</span>
              {result.edge_services.map((e) => (
                <span key={e.name} title={e.evidence}
                  className="inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs bg-sky-900/30 text-sky-300 border border-sky-800/40">
                  {e.name}
                  <span className="text-[10px] text-sky-500/80">{e.type}</span>
                </span>
              ))}
            </div>
            <p className="text-[11px] text-gray-600 mt-1.5">
              A WAF may block exploitation payloads; a CDN caches/masks the real origin — factor this into any testing.
            </p>
          </div>
        )}
      </div>

      {/* Exposed files / panels (deep scan) */}
      {result.exposures && result.exposures.length > 0 && (
        <ExposuresSection exposures={result.exposures} />
      )}
      {result.deep && (!result.exposures || result.exposures.length === 0) && (
        <div className="card p-3 flex items-center gap-2 text-xs text-emerald-400/90">
          <ShieldCheck className="h-4 w-4" /> Deep scan ran — no exposed sensitive files or panels found.
        </div>
      )}

      {/* Versioned tech + CVEs */}
      {versioned.length > 0 && (
        <div className="space-y-3">
          <SectionLabel icon={ShieldAlert} text={`Technologies with known versions (${versioned.length})`} />
          {versioned.map((t) => <TechCard key={t.name} tech={t} targetUrl={result.final_url} />)}
        </div>
      )}

      {/* Detected without version */}
      {detected.length > 0 && (
        <div className="card p-4">
          <SectionLabel icon={Boxes} text={`Also detected — version unknown (${detected.length})`} />
          <p className="text-[11px] text-gray-600 mb-2">No version disclosed → CVE matching skipped to avoid false positives.</p>
          <div className="flex flex-wrap gap-2">
            {detected.map((t) => (
              <span key={t.name} className="inline-flex items-center gap-1.5 px-2 py-1 rounded bg-gray-900 border border-gray-800 text-xs text-gray-300">
                {t.name}
                {t.categories && t.categories.length > 0 && (
                  <span className="text-gray-600">· {t.categories[0]}</span>
                )}
              </span>
            ))}
          </div>
        </div>
      )}

      {/* Security posture */}
      <SecurityPosture result={result} />

      {result.technologies.length === 0 && (
        <div className="card p-8 text-center text-gray-500 text-sm">
          No technologies could be fingerprinted for this target.
        </div>
      )}
    </div>
  )
}

const RISK_STYLES: Record<TechRisk['level'], { ring: string; text: string; label: string }> = {
  critical: { ring: 'border-red-700 bg-red-950/40',      text: 'text-red-400',    label: 'Critical' },
  high:     { ring: 'border-orange-700 bg-orange-950/30', text: 'text-orange-400', label: 'High' },
  medium:   { ring: 'border-yellow-700 bg-yellow-950/20', text: 'text-yellow-400', label: 'Medium' },
  low:      { ring: 'border-emerald-800 bg-emerald-950/20', text: 'text-emerald-400', label: 'Low' },
}

const ACTION_COLORS: Record<string, string> = {
  critical: 'text-red-400 border-red-800/50 bg-red-900/20',
  high:     'text-orange-400 border-orange-800/50 bg-orange-900/20',
  medium:   'text-yellow-400 border-yellow-800/50 bg-yellow-900/20',
  low:      'text-blue-400 border-blue-800/50 bg-blue-900/20',
  info:     'text-gray-400 border-gray-700 bg-gray-800/40',
}

function RiskSummary({ risk }: { risk: TechRisk }) {
  const s = RISK_STYLES[risk.level] ?? RISK_STYLES.low
  return (
    <div className={`card p-4 border ${s.ring}`}>
      <div className="flex items-start gap-4 flex-wrap">
        <div className="flex items-center gap-3">
          <Gauge className={`h-8 w-8 ${s.text}`} />
          <div>
            <div className="flex items-baseline gap-2">
              <span className={`text-3xl font-bold font-mono tabular-nums ${s.text}`}>{risk.score}</span>
              <span className="text-xs text-gray-500">/100</span>
              <span className={`text-sm font-semibold uppercase tracking-wide ${s.text}`}>{s.label} risk</span>
            </div>
            <p className="text-[11px] text-gray-500 mt-0.5">Heuristic triage score — CVEs (KEV/exploit weighted), exposed files, and posture.</p>
          </div>
        </div>
        {risk.actions && risk.actions.length > 0 && (
          <div className="flex-1 min-w-[260px]">
            <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5">Fix first</div>
            <ul className="space-y-1">
              {risk.actions.map((a, i) => (
                <li key={i} className="flex items-start gap-2 text-xs">
                  <span className={`shrink-0 px-1 py-0.5 rounded text-[9px] font-semibold uppercase border ${ACTION_COLORS[a.severity] ?? ACTION_COLORS.info}`}>
                    {a.severity}
                  </span>
                  <span className="text-gray-300">
                    {a.url
                      ? <a href={a.url} target="_blank" rel="noopener noreferrer" className="hover:text-emerald-300">{a.title}</a>
                      : a.title}
                    {a.detail && <span className="text-gray-500"> — {a.detail}</span>}
                  </span>
                </li>
              ))}
            </ul>
          </div>
        )}
      </div>
    </div>
  )
}

function StatTiles({ summary, techCount, versioned }: {
  summary: TechStackResult['cve_summary']; techCount: number; versioned: number
}) {
  const tile = (label: string, value: number | string, color: string) => (
    <div className="text-center px-3">
      <div className={`text-lg font-semibold font-mono tabular-nums ${color}`}>{value}</div>
      <div className="text-[10px] text-gray-500 uppercase tracking-wider">{label}</div>
    </div>
  )
  return (
    <div className="flex items-center divide-x divide-gray-800">
      {tile('Tech', techCount, 'text-gray-200')}
      {tile('Versioned', versioned, 'text-gray-200')}
      {tile('CVEs', summary.total, summary.total > 0 ? 'text-amber-400' : 'text-gray-500')}
      {tile('Critical', summary.critical, summary.critical > 0 ? 'text-red-400' : 'text-gray-500')}
      {tile('KEV', summary.kev, summary.kev > 0 ? 'text-red-400' : 'text-gray-500')}
      {tile('Exploit', summary.exploit, summary.exploit > 0 ? 'text-red-400' : 'text-gray-500')}
    </div>
  )
}

function TechCard({ tech, targetUrl }: { tech: DetectedTech; targetUrl: string }) {
  const cves = tech.top_cves ?? []
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between gap-3 flex-wrap">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="font-medium text-gray-100">{tech.name}</span>
          <span className="font-mono text-xs px-1.5 py-0.5 rounded bg-emerald-900/30 text-emerald-300 border border-emerald-800/40">
            v{tech.version}
          </span>
          {tech.categories?.slice(0, 2).map((c) => (
            <span key={c} className="text-[10px] text-gray-500 uppercase tracking-wide">{c}</span>
          ))}
          {tech.source === 'active-probe' && (
            <span className="text-[10px] text-amber-500/80" title="Version confirmed via active probe">probe</span>
          )}
          {tech.eol ? (
            <span className="inline-flex items-center gap-0.5 text-[10px] px-1 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-800/60"
              title={tech.latest_known ? `End-of-life — latest is ~${tech.latest_known}` : 'End-of-life — no security updates'}>
              <Clock className="h-2.5 w-2.5" /> EOL
            </span>
          ) : tech.outdated ? (
            <span className="inline-flex items-center gap-0.5 text-[10px] px-1 py-0.5 rounded bg-amber-900/30 text-amber-300 border border-amber-800/50"
              title={tech.latest_known ? `Outdated — latest is ~${tech.latest_known}` : 'Outdated'}>
              <Clock className="h-2.5 w-2.5" /> outdated{tech.latest_known ? ` · latest ~${tech.latest_known}` : ''}
            </span>
          ) : null}
        </div>
        <span className="text-xs text-gray-500">
          {tech.cve_count > 0
            ? <>{tech.cve_count} known{cves.length < tech.cve_count ? <> · showing top {cves.length}</> : ''}</>
            : 'No known CVEs found'}
        </span>
      </div>

      {cves.length > 0 && (
        <div className="mt-3 border-t border-gray-800/60 divide-y divide-gray-800/40">
          {cves.map((cve) => <CveRow key={cve.id} cve={cve} targetUrl={targetUrl} />)}
        </div>
      )}
    </div>
  )
}

// CveScanButton launches a targeted nuclei run of just this CVE's template against
// the analysed URL — confirming whether the target is actually exploitable rather
// than merely running a matching version.
function CveScanButton({ cve, targetUrl }: { cve: TechCVE; targetUrl: string }) {
  const scan = useMutation({
    mutationFn: () => vulnscanApi.createAdHocNuclei({ url: targetUrl, cve_ids: [cve.id], proxy_choice: 'direct' }),
    onSuccess: () => toast.success(`Nuclei ${cve.id} scan started — open the Vuln Scan tab for results`),
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  return (
    <button type="button" onClick={() => scan.mutate()} disabled={scan.isPending || scan.isSuccess}
      className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded border border-emerald-800/50 text-emerald-300 bg-emerald-900/20 hover:bg-emerald-900/40 disabled:opacity-50"
      title={`Run nuclei's ${cve.id} template against ${targetUrl} to verify exploitability`}>
      {scan.isPending ? <Loader2 className="h-2.5 w-2.5 animate-spin" /> : <Crosshair className="h-2.5 w-2.5" />}
      {scan.isSuccess ? 'scanning…' : 'Verify'}
    </button>
  )
}

function CveRow({ cve, targetUrl }: { cve: TechCVE; targetUrl: string }) {
  const epssPct = Math.round((cve.epss_percentile || 0) * 100)
  return (
    <div className="flex items-start gap-3 py-2">
      <div className="flex flex-col items-start gap-1 w-40 shrink-0">
        <a href={`https://nvd.nist.gov/vuln/detail/${cve.id}`} target="_blank" rel="noopener noreferrer"
          className="font-mono text-xs text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1">
          {cve.id}<ExternalLink className="h-3 w-3" />
        </a>
        <div className="flex items-center gap-1.5">
          <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
          {cve.is_kev && (
            <span className="inline-flex items-center gap-0.5 text-[10px] px-1 py-0.5 rounded bg-red-900/40 text-red-300 border border-red-800/60" title="CISA Known Exploited Vulnerability">
              <ShieldAlert className="h-2.5 w-2.5" />KEV
            </span>
          )}
        </div>
      </div>
      <div className="min-w-0 flex-1">
        <p className="text-xs text-gray-400 line-clamp-2">{cve.description || '—'}</p>
        <div className="flex items-center gap-3 mt-0.5 flex-wrap">
          {epssPct > 0 && (
            <span className="text-[10px] text-gray-600">EPSS {epssPct}th pct · {((cve.epss_score || 0) * 100).toFixed(1)}% (30d)</span>
          )}
          {cve.has_exploit && cve.top_poc_url && (
            <a href={cve.top_poc_url} target="_blank" rel="noopener noreferrer"
              className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-red-900/30 text-red-300 border border-red-800/50 hover:bg-red-900/50"
              title={`${cve.poc_count} public repo(s) — top: ${cve.top_poc_name}`}>
              <Github className="h-2.5 w-2.5" />
              PoC{cve.poc_count && cve.poc_count > 1 ? ` ×${cve.poc_count}` : ''}
            </a>
          )}
          <CveScanButton cve={cve} targetUrl={targetUrl} />
        </div>
      </div>
    </div>
  )
}

function SecurityPosture({ result }: { result: TechStackResult }) {
  const missing = result.missing_security_headers ?? []
  return (
    <div className="card p-4">
      <SectionLabel icon={ShieldCheck} text="Security posture" />
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-1">
        <div>
          <div className="text-xs text-gray-500 mb-1.5">HTTP security headers</div>
          <div className="flex flex-wrap gap-1.5">
            {result.security_headers.map((h) => (
              <span key={h.name}
                className={`text-[11px] px-1.5 py-0.5 rounded border ${
                  h.present
                    ? 'bg-emerald-900/20 text-emerald-400 border-emerald-800/40'
                    : 'bg-red-900/20 text-red-400/80 border-red-900/40'
                }`}
                title={h.value || (h.present ? 'present' : 'missing')}>
                {h.present ? '✓' : '✕'} {h.name}
              </span>
            ))}
          </div>
          {missing.length > 0 && (
            <p className="text-[11px] text-gray-600 mt-1.5">{missing.length} recommended header(s) missing.</p>
          )}
        </div>
        {result.tls && (
          <div>
            <div className="text-xs text-gray-500 mb-1.5">TLS certificate</div>
            <div className="text-xs text-gray-400 space-y-0.5 font-mono">
              {result.tls.version && <div>{result.tls.version}</div>}
              {result.tls.issuer && <div className="truncate">Issuer: {result.tls.issuer}</div>}
              {result.tls.not_after && (
                <div className={result.tls.expires_in_days < 14 ? 'text-red-400' : ''}>
                  Expires: {result.tls.not_after} ({result.tls.expires_in_days}d)
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* CORS + cookies */}
      {(result.cors || (result.cookies && result.cookies.length > 0)) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 mt-4 pt-3 border-t border-gray-800/50">
          {result.cors && (
            <div>
              <div className="text-xs text-gray-500 mb-1 flex items-center gap-1.5"><Globe className="h-3 w-3" /> CORS</div>
              <span className={`text-[11px] px-1.5 py-0.5 rounded border ${ACTION_COLORS[result.cors.severity] ?? ACTION_COLORS.info}`}>
                {result.cors.allow_origin}{result.cors.allow_credentials ? ' + credentials' : ''}
              </span>
              <p className="text-[11px] text-gray-500 mt-1">{result.cors.note}</p>
            </div>
          )}
          {result.cookies && result.cookies.length > 0 && (
            <div>
              <div className="text-xs text-gray-500 mb-1 flex items-center gap-1.5"><Cookie className="h-3 w-3" /> Cookies ({result.cookies.length})</div>
              <div className="space-y-1">
                {result.cookies.slice(0, 6).map((ck) => (
                  <div key={ck.name} className="flex items-center gap-2 text-[11px]">
                    <span className="font-mono text-gray-300 truncate max-w-[120px]">{ck.name}</span>
                    {ck.issues && ck.issues.length > 0 ? (
                      <span className="text-red-400/80">⚠ {ck.issues.join(', ')}</span>
                    ) : (
                      <span className="text-emerald-400/80">✓ secure</span>
                    )}
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

const EXPOSURE_COLORS: Record<ExposedPath['severity'], string> = {
  critical: 'bg-red-900/30 text-red-300 border-red-800/50',
  high:     'bg-orange-900/30 text-orange-300 border-orange-800/50',
  medium:   'bg-yellow-900/30 text-yellow-300 border-yellow-800/50',
  low:      'bg-blue-900/30 text-blue-300 border-blue-800/50',
  info:     'bg-gray-800 text-gray-400 border-gray-700',
}

function ExposuresSection({ exposures }: { exposures: ExposedPath[] }) {
  return (
    <div className="card p-4 border-red-900/40">
      <SectionLabel icon={FileWarning} text={`Exposed files & panels (${exposures.length})`} />
      <div className="space-y-2">
        {exposures.map((e) => (
          <div key={e.path} className="flex items-start gap-3 py-1.5 border-b border-gray-800/40 last:border-0">
            <span className={`shrink-0 px-1.5 py-0.5 rounded text-[10px] font-semibold uppercase border ${EXPOSURE_COLORS[e.severity]}`}>
              {e.severity}
            </span>
            <div className="min-w-0 flex-1">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-sm text-gray-200">{e.title}</span>
                <a href={e.url} target="_blank" rel="noopener noreferrer"
                  className="font-mono text-xs text-emerald-400/90 hover:text-emerald-300 inline-flex items-center gap-1">
                  {e.path}<ExternalLink className="h-3 w-3" />
                </a>
                <span className="text-[10px] font-mono text-gray-600">HTTP {e.status}</span>
              </div>
              {e.evidence && <p className="text-[11px] text-gray-500 font-mono mt-0.5 truncate">{e.evidence}</p>}
            </div>
          </div>
        ))}
      </div>
    </div>
  )
}

function SectionLabel({ icon: Icon, text }: { icon: React.ElementType; text: string }) {
  return (
    <div className="flex items-center gap-2 text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
      <Icon className="h-3.5 w-3.5 text-emerald-400" />
      {text}
    </div>
  )
}
