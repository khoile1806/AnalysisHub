import { useEffect, useMemo, useRef, useState } from 'react'
import { useParams, useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  ChevronLeft, Loader2, StopCircle, CheckCircle, XCircle, Clock,
  Fingerprint, ArrowRight, MinusCircle, Download, FileBarChart2,
  ListTree, AlertTriangle, ShieldCheck, ShieldPlus, Sparkles, ExternalLink,
  Network, Copy, Globe, AtSign, MapPin, Upload,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { formatDistanceToNow } from 'date-fns'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import {
  osintApi, CATEGORY_LABELS, COLLECTOR_LABELS, parseRelated,
  type OsintScan, type OsintCollector, type OsintFinding, type RelatedEntity, type OsintTargetType,
  type GeoPoint, type IdentityConfidence,
} from '@/api/osint'
import { analysisApi } from '@/api/analysis'
import OsintGraphView from '@/components/OsintGraphView'
import OsintCorrelations from '@/components/OsintCorrelations'
import { getErrorMessage, copyToClipboard } from '@/lib/utils'
import { TYPE_ICON } from './Osint'

// OsintAiTriage runs an AI summary of the scan's findings (defensive angle).
function OsintAiTriage({ scanId }: { scanId: string }) {
  const [providerId, setProviderId] = useState('')
  const [summary, setSummary] = useState('')
  const { data: providers = [] } = useQuery({ queryKey: ['ai-providers'], queryFn: analysisApi.listProviders })
  const active = providers.filter((p) => p.is_active)

  const mut = useMutation({
    mutationFn: () => osintApi.triage(scanId, providerId),
    onSuccess: (d) => { setSummary(d.summary); toast.success(`AI triage done (${d.tokens} tokens)`) },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <div className="card p-4 space-y-3">
      <div className="flex items-center justify-between gap-2 flex-wrap">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <Sparkles className="h-4 w-4 text-emerald-400" /> AI Triage
        </h3>
        <div className="flex items-center gap-2">
          {active.length === 0 ? (
            <a href="/ai-providers" className="text-xs text-yellow-400 underline">Configure AI provider</a>
          ) : (
            <select
              value={providerId}
              onChange={(e) => setProviderId(e.target.value)}
              className="text-xs bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
            >
              <option value="">Select provider…</option>
              {active.map((p) => <option key={p.id} value={p.id}>{p.name}</option>)}
            </select>
          )}
          <button
            className="btn-primary text-xs disabled:opacity-50"
            disabled={!providerId || mut.isPending}
            onClick={() => mut.mutate()}
          >
            {mut.isPending ? 'Analyzing…' : summary ? 'Re-run' : 'Run AI triage'}
          </button>
        </div>
      </div>
      {summary ? (
        <div className="prose prose-invert prose-sm max-w-none text-gray-300 prose-headings:text-emerald-400 prose-strong:text-gray-100">
          <ReactMarkdown remarkPlugins={[remarkGfm]}>{summary}</ReactMarkdown>
        </div>
      ) : (
        <p className="text-xs text-gray-500">Let AI summarize this footprint: what the entity is, malicious or not, related infrastructure, and recommended DFIR next steps.</p>
      )}
    </div>
  )
}

const SEVERITY_COLOR: Record<string, string> = {
  critical: 'text-red-400 bg-red-900/20 border-red-800/40',
  high:     'text-orange-400 bg-orange-900/20 border-orange-800/40',
  medium:   'text-yellow-400 bg-yellow-900/20 border-yellow-800/40',
  low:      'text-blue-400 bg-blue-900/20 border-blue-800/40',
  info:     'text-gray-400 bg-gray-800 border-slate-700',
}

// usePivot launches a fresh investigation against a discovered related entity.
function usePivot() {
  const navigate = useNavigate()
  return useMutation({
    mutationFn: (e: RelatedEntity) => osintApi.create({ target: e.value }),
    onSuccess: (scan) => {
      toast.success('Pivot investigation started')
      navigate(`/osint/${scan.id}`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })
}

// ---- SSE stream hook (mirrors useReconStream) -------------------------------

function useOsintStream(scanId: string) {
  const [lines, setLines] = useState<string[]>([])
  const [streaming, setStreaming] = useState(false)

  useEffect(() => {
    setLines([])
    const es = new EventSource(osintApi.streamUrl(scanId))
    setStreaming(true)

    es.onmessage = (e) => {
      if (e.data === '__DONE__') {
        es.close()
        setStreaming(false)
        return
      }
      setLines(prev => prev.length >= 2000 ? [...prev.slice(-1999), e.data] : [...prev, e.data])
    }
    es.onerror = () => {
      if (es.readyState === EventSource.CLOSED) setStreaming(false)
    }

    return () => { es.close(); setStreaming(false) }
  }, [scanId])

  return { lines, streaming }
}

function lineColor(l: string): string {
  if (l.startsWith('[+]')) return 'text-emerald-400'
  if (l.startsWith('[!]')) return 'text-red-400'
  if (l.startsWith('[*]')) return 'text-blue-400'
  return 'text-gray-400'
}

// ---- Target graph hero (SVG: target + radial collector spokes) ---------------

function TargetGraphHero({
  scan,
  totalFindings,
}: {
  scan: OsintScan
  totalFindings: number
}) {
  const collectors = scan.collectors ?? []
  const TypeIcon = TYPE_ICON[scan.target_type] ?? Fingerprint

  // Polar layout: place collectors evenly around the central target.
  // SVG viewBox is 500x260, target at (250,130), spokes radius 110.
  const cx = 250
  const cy = 130
  const radius = 105
  const n = collectors.length

  return (
    <div className="card relative overflow-hidden p-0">
      {/* Soft glow background */}
      <div className="absolute inset-0 pointer-events-none">
        <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 w-96 h-96 bg-emerald-500/8 rounded-full blur-3xl" />
      </div>

      <div className="relative flex flex-col lg:flex-row gap-4 p-4">
        {/* SVG graph */}
        <div className="relative shrink-0 mx-auto lg:mx-0">
          <svg viewBox="0 0 500 260" className="w-full max-w-[500px] h-[260px]">
            {/* Spokes */}
            {collectors.map((c, i) => {
              const angle = n === 0 ? 0 : (i * 2 * Math.PI) / n - Math.PI / 2
              const x = cx + Math.cos(angle) * radius
              const y = cy + Math.sin(angle) * radius
              const stroke =
                c.status === 'done'   ? '#ff6f1f' :
                c.status === 'running'? '#e6261a' :
                c.status === 'failed' ? '#7f1d1d' :
                c.status === 'skipped'? '#1f0303' : '#3a1a20'
              const dash = c.status === 'running' ? '4 3' : undefined
              return (
                <line
                  key={c.id}
                  x1={cx} y1={cy} x2={x} y2={y}
                  stroke={stroke}
                  strokeWidth={c.status === 'running' ? 1.5 : 1}
                  strokeDasharray={dash}
                  opacity={c.status === 'pending' || c.status === 'skipped' ? 0.4 : 1}
                />
              )
            })}

            {/* Collector nodes */}
            {collectors.map((c, i) => {
              const angle = n === 0 ? 0 : (i * 2 * Math.PI) / n - Math.PI / 2
              const x = cx + Math.cos(angle) * radius
              const y = cy + Math.sin(angle) * radius
              const fill =
                c.status === 'done'    ? '#ff6f1f' :
                c.status === 'running' ? '#e6261a' :
                c.status === 'failed'  ? '#7f1d1d' :
                c.status === 'skipped' ? '#3a1a20' : '#221014'
              const labelAngle = angle
              const labelX = cx + Math.cos(labelAngle) * (radius + 18)
              const labelY = cy + Math.sin(labelAngle) * (radius + 18)
              const anchor =
                Math.abs(Math.cos(labelAngle)) < 0.2 ? 'middle' :
                Math.cos(labelAngle) > 0 ? 'start' : 'end'
              return (
                <g key={c.id}>
                  <circle
                    cx={x} cy={y}
                    r={c.status === 'running' ? 7 : 5}
                    fill={fill}
                    opacity={c.status === 'pending' ? 0.4 : 1}
                  >
                    {c.status === 'running' && (
                      <animate attributeName="r" values="5;8;5" dur="1.4s" repeatCount="indefinite" />
                    )}
                  </circle>
                  <text
                    x={labelX} y={labelY}
                    fontSize="8"
                    fontFamily="JetBrains Mono, monospace"
                    fill={c.status === 'done' ? '#ffb673' : c.status === 'running' ? '#ff7a6e' : '#54262e'}
                    textAnchor={anchor as 'start' | 'middle' | 'end'}
                    dominantBaseline="middle"
                  >
                    {(COLLECTOR_LABELS[c.name] ?? c.name).toUpperCase()}
                    {c.status === 'done' && c.findings_count > 0 ? ` · ${c.findings_count}` : ''}
                  </text>
                </g>
              )
            })}

            {/* Central target node */}
            <circle cx={cx} cy={cy} r="32" fill="#16090c" stroke="#e6261a" strokeWidth="1.5" />
            <circle cx={cx} cy={cy} r="44" fill="none" stroke="#e6261a" strokeWidth="0.5" opacity="0.4" />
            <circle cx={cx} cy={cy} r="56" fill="none" stroke="#e6261a" strokeWidth="0.3" opacity="0.2" />
          </svg>

          {/* Target identity overlay — centred */}
          <div className="absolute top-1/2 left-1/2 -translate-x-1/2 -translate-y-1/2 flex flex-col items-center text-center pointer-events-none">
            <TypeIcon className="h-5 w-5 text-emerald-400 mb-0.5" />
            <span className="text-[8px] font-mono uppercase tracking-widest text-emerald-700">
              {scan.target_type}
            </span>
          </div>
        </div>

        {/* Stats column */}
        <div className="flex-1 min-w-0 flex flex-col justify-center gap-3">
          <div>
            <div className="text-[10px] font-mono uppercase tracking-widest text-emerald-700 mb-1">
              &gt; target acquired
            </div>
            <div className="text-xl sm:text-2xl font-mono text-emerald-300 break-all" title={scan.target}>
              {scan.target}
            </div>
            <div className="text-xs text-gray-500 mt-1">{scan.name}</div>
            <ExposureBadge score={scan.exposure_score} grade={scan.exposure_grade} />
          </div>

          <div className="grid grid-cols-3 gap-2 text-center">
            <div className="bg-deep-800 border border-emerald-700/30 rounded-sm p-2">
              <div className="text-lg font-bold font-mono text-emerald-300">{totalFindings}</div>
              <div className="text-[9px] font-mono uppercase tracking-widest text-gray-500">findings</div>
            </div>
            <div className="bg-deep-800 border border-amber-500/30 rounded-sm p-2">
              <div className="text-lg font-bold font-mono text-amber-400">
                {collectors.filter(c => c.status === 'done').length}/{collectors.length}
              </div>
              <div className="text-[9px] font-mono uppercase tracking-widest text-gray-500">collectors</div>
            </div>
            <div className="bg-deep-800 border border-slate-700 rounded-sm p-2">
              <div className="text-lg font-bold font-mono text-gray-300">
                {scan.status === 'running' ? (
                  <span className="text-emerald-400 animate-pulse-red">LIVE</span>
                ) : scan.status === 'done' ? (
                  <span className="text-amber-400">DONE</span>
                ) : (
                  scan.status.toUpperCase()
                )}
              </div>
              <div className="text-[9px] font-mono uppercase tracking-widest text-gray-500">state</div>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// CollectorTimeline — horizontal filmstrip of collector states.
function CollectorTimeline({ collectors }: { collectors: OsintCollector[] }) {
  if (collectors.length === 0) {
    return (
      <div className="card p-4 text-center text-xs font-mono text-emerald-700">
        &gt; awaiting collectors to register
      </div>
    )
  }
  return (
    <div className="card p-3">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-[10px] font-mono uppercase tracking-widest text-emerald-300">
          &gt; collector timeline
        </h3>
        <span className="text-[10px] font-mono text-gray-500">
          {collectors.length} sources
        </span>
      </div>
      <div className="relative flex gap-1 overflow-x-auto pb-1">
        {collectors.map((c) => {
          const icon =
            c.status === 'running' ? <Loader2 className="h-3 w-3 animate-spin" />
            : c.status === 'done'  ? <CheckCircle className="h-3 w-3" />
            : c.status === 'failed' ? <XCircle className="h-3 w-3" />
            : c.status === 'skipped' ? <MinusCircle className="h-3 w-3" />
            : <Clock className="h-3 w-3" />
          const cls =
            c.status === 'running' ? 'border-emerald-500 text-emerald-300 bg-emerald-900/30 animate-pulse-red'
            : c.status === 'done'  ? 'border-amber-500/40 text-amber-300 bg-amber-600/10'
            : c.status === 'failed' ? 'border-red-700 text-red-400 bg-red-900/20'
            : c.status === 'skipped' ? 'border-slate-800 text-gray-700'
            : 'border-slate-700 text-gray-500'
          return (
            <div
              key={c.id}
              className={`shrink-0 flex flex-col items-center gap-1 px-2.5 py-2 rounded-sm border min-w-[80px] ${cls}`}
              title={c.error || `${c.name} · ${c.status}`}
            >
              {icon}
              <span className="text-[9px] font-mono uppercase tracking-widest text-center">
                {COLLECTOR_LABELS[c.name] ?? c.name}
              </span>
              {c.status === 'done' && c.findings_count > 0 && (
                <span className="text-[10px] font-mono font-bold">{c.findings_count}</span>
              )}
            </div>
          )
        })}
      </div>
    </div>
  )
}

// ---- Live output ------------------------------------------------------------

function LiveOutput({ lines, streaming }: { lines: string[]; streaming: boolean }) {
  const ref = useRef<HTMLDivElement>(null)
  useEffect(() => {
    if (ref.current) ref.current.scrollTop = ref.current.scrollHeight
  }, [lines])
  if (lines.length === 0) return null
  return (
    <div className="card p-4">
      <div className="flex items-center justify-between mb-2">
        <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest">Live Output</h3>
        {streaming
          ? <span className="text-[10px] text-blue-400 font-mono animate-pulse">● live</span>
          : <span className="text-[10px] text-gray-600 font-mono">○ closed</span>}
      </div>
      <div ref={ref} className="font-mono text-xs bg-deep-950 rounded p-3 h-48 overflow-y-auto space-y-0.5">
        {lines.map((l, i) => <div key={i} className={lineColor(l)}>{l}</div>)}
      </div>
    </div>
  )
}

function OsintStreamPanel({ scanId }: { scanId: string }) {
  const { lines, streaming } = useOsintStream(scanId)
  return <LiveOutput lines={lines} streaming={streaming} />
}

// ---- Finding row + pivots ---------------------------------------------------

function FindingValue({ value }: { value: string }) {
  if (/^https?:\/\//.test(value)) {
    return (
      <a
        href={value}
        target="_blank"
        rel="noreferrer"
        className="text-xs font-mono text-blue-400 hover:underline break-all mt-0.5 block"
      >
        {value}
      </a>
    )
  }
  return <div className="text-xs font-mono text-gray-400 break-all mt-0.5">{value}</div>
}

function PivotButtons({ related, onPivot }: { related: RelatedEntity[]; onPivot: (e: RelatedEntity) => void }) {
  if (related.length === 0) return null
  return (
    <div className="flex flex-wrap gap-1.5 mt-1.5">
      {related.map((r, i) => (
        <button
          key={i}
          onClick={() => onPivot(r)}
          className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded
                     bg-emerald-900/20 text-emerald-300 border border-emerald-800/40
                     hover:bg-emerald-900/40 transition-colors"
          title={`Investigate ${r.value}`}
        >
          <ArrowRight className="h-3 w-3" />
          {r.type}: {r.value}
        </button>
      ))}
    </div>
  )
}

const EXPOSURE_COLOR: Record<string, string> = {
  critical: 'bg-red-900/40 text-red-300 border-red-700/50',
  high:     'bg-orange-900/40 text-orange-300 border-orange-700/50',
  elevated: 'bg-amber-900/30 text-amber-300 border-amber-700/50',
  low:      'bg-emerald-900/30 text-emerald-300 border-emerald-700/50',
  minimal:  'bg-gray-800 text-gray-400 border-gray-700',
}

// ExposureBadge shows the aggregate exposure score + grade for the investigation.
function ExposureBadge({ score, grade }: { score?: number; grade?: string }) {
  if (score == null || !grade) return null
  return (
    <div className={`mt-2 inline-flex items-center gap-2 px-2.5 py-1 rounded border text-xs font-mono ${EXPOSURE_COLOR[grade] ?? EXPOSURE_COLOR.minimal}`}
      title="Aggregate exposure: ransomware + dark-web + breach + stealer + threat-intel">
      <span className="uppercase tracking-wider">Exposure</span>
      <span className="font-bold">{score}/100</span>
      <span className="uppercase">{grade}</span>
    </div>
  )
}

const CONFIDENCE_COLOR: Record<string, string> = {
  verified:   'bg-emerald-900/40 text-emerald-300 border-emerald-700/50',
  likely:     'bg-amber-900/30 text-amber-300 border-amber-700/50',
  unverified: 'bg-gray-800 text-gray-400 border-gray-700',
}

// FindingData renders a finding's extra JSON payload as readable key/value rows,
// falling back to the raw string when it isn't an object.
function FindingData({ data }: { data?: string }) {
  if (!data) return null
  let parsed: unknown
  try { parsed = JSON.parse(data) } catch { /* not JSON */ }
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
    const entries = Object.entries(parsed as Record<string, unknown>)
      .filter(([, v]) => v !== '' && v != null)
    if (entries.length === 0) return null
    return (
      <div className="mt-1 flex flex-wrap gap-x-3 gap-y-0.5">
        {entries.map(([k, v]) => (
          <span key={k} className="text-[10px] font-mono text-gray-500">
            <span className="text-gray-600">{k}:</span> {String(v)}
          </span>
        ))}
      </div>
    )
  }
  return <div className="mt-1 text-[10px] font-mono text-gray-500 break-all">{data}</div>
}

// SourceLink shows a clickable link to where a trace was discovered.
function SourceLink({ url }: { url?: string }) {
  if (!url) return null
  return (
    <a
      href={url}
      target="_blank"
      rel="noreferrer"
      className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded
                 bg-blue-900/20 text-blue-300 border border-blue-800/40 hover:bg-blue-900/40 transition-colors"
      title="Open where this was discovered"
    >
      <ExternalLink className="h-3 w-3" /> source
    </a>
  )
}

function FindingRow({ f, onPivot }: { f: OsintFinding; onPivot: (e: RelatedEntity) => void }) {
  const sev = f.severity ?? 'info'
  const related = parseRelated(f.related_entities)
  const conf = f.confidence || undefined
  const sourceLabel = COLLECTOR_LABELS[f.source] ?? f.source
  // Avatar fingerprint findings: show the actual picture as a thumbnail rather
  // than the raw hash, so an analyst can eyeball the avatar being fingerprinted.
  const isAvatar = f.value?.startsWith('avatar_phash:')
  const avatarHash = isAvatar ? f.value.slice('avatar_phash:'.length) : ''
  return (
    <div className="flex items-start gap-3 py-2.5 px-3 border-b border-slate-800 last:border-0">
      <span className={`text-[10px] px-2 py-0.5 rounded font-mono uppercase shrink-0 mt-0.5 border ${SEVERITY_COLOR[sev] ?? SEVERITY_COLOR.info}`}>
        {sev}
      </span>
      {isAvatar && f.source_url && (
        <img src={f.source_url} alt="" referrerPolicy="no-referrer" loading="lazy"
          className="h-10 w-10 rounded object-cover bg-gray-900 border border-slate-700 shrink-0" />
      )}
      <div className="flex-1 min-w-0">
        <div className="flex items-center gap-2 flex-wrap">
          <span className="text-sm text-gray-200">{f.title}</span>
          {conf && (
            <span
              className={`text-[9px] px-1.5 py-0.5 rounded font-mono uppercase border ${CONFIDENCE_COLOR[conf] ?? CONFIDENCE_COLOR.unverified}`}
              title="Tool self-verification verdict (cross-checked against other collectors)"
            >
              {conf === 'verified' ? '✓ verified' : conf === 'likely' ? '~ likely' : '? unverified'}
            </span>
          )}
          {sourceLabel && (
            <span
              className="text-[9px] px-1.5 py-0.5 rounded font-mono bg-slate-800 text-gray-400 border border-slate-700"
              title="Collector that produced this finding"
            >
              {sourceLabel}
            </span>
          )}
          <SourceLink url={f.source_url} />
        </div>
        {isAvatar
          ? (
            <div className="mt-0.5 flex items-center gap-2">
              <span className="font-mono text-[11px] text-gray-500">fingerprint <span className="text-gray-400">{avatarHash}</span></span>
              {f.source_url && (
                <a href={`https://lens.google.com/uploadbyurl?url=${encodeURIComponent(f.source_url)}`}
                  target="_blank" rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-900/20 text-emerald-300 border border-emerald-800/40 hover:bg-emerald-900/40 transition-colors">
                  <ExternalLink className="h-3 w-3" /> Reverse search
                </a>
              )}
            </div>
          )
          : <FindingValue value={f.value} />}
        <FindingData data={f.data} />
        {f.verify_note && (
          <div className="mt-1 text-[11px] text-gray-500 italic">{f.verify_note}</div>
        )}
        <PivotButtons related={related} onPivot={onPivot} />
      </div>
    </div>
  )
}

// ---- Findings grouped by category -------------------------------------------

// groupByCategory groups findings, preserving the CATEGORY_LABELS order.
function groupByCategory(findings: OsintFinding[]) {
  const map: Record<string, OsintFinding[]> = {}
  for (const f of findings) {
    (map[f.category] ??= []).push(f)
  }
  const ordered = Object.keys(CATEGORY_LABELS).filter(k => map[k])
  const extra = Object.keys(map).filter(k => !(k in CATEGORY_LABELS))
  return [...ordered, ...extra].map(cat => ({ cat, items: map[cat] }))
}

function FindingsPanel({ scanId, isRunning }: { scanId: string; isRunning: boolean }) {
  const pivot = usePivot()

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['osint-findings', scanId],
    queryFn: () => osintApi.findings(scanId),
    refetchInterval: isRunning ? 4000 : false,
  })

  const grouped = useMemo(() => groupByCategory(findings), [findings])

  if (isLoading) {
    return <div className="flex justify-center py-8"><Loader2 className="h-5 w-5 animate-spin text-gray-600" /></div>
  }
  if (findings.length === 0) {
    return <p className="text-center text-gray-600 text-sm py-10">No findings yet</p>
  }

  return (
    <div className="space-y-4">
      {grouped.map(({ cat, items }) => (
        <div key={cat} className="card">
          <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800">
            <h3 className="text-sm font-semibold text-gray-200">{CATEGORY_LABELS[cat] ?? cat}</h3>
            <span className="text-[10px] font-mono text-gray-500">{items.length}</span>
          </div>
          <div>
            {items.map(f => (
              <FindingRow key={f.id} f={f} onPivot={(e) => pivot.mutate(e)} />
            ))}
          </div>
        </div>
      ))}
    </div>
  )
}

// ---- Related entities (IPs / Domains / Accounts) ----------------------------
// Rolls up every related entity surfaced anywhere in the scan's findings —
// IP A/AAAA records + the IP/domain/account pivots collectors attach as
// related_entities — into one panel with per-type views and bulk actions, so
// the analyst sees the target's whole resolved footprint at a glance.

const IPV4_G = /\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b/g
const IPV4_ONE = /^(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)$/
const DOMAIN_RE = /^(?=.{1,253}$)(?:[a-z0-9_](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$/i
function isIPv6(s: string) {
  return s.includes(':') && /^[0-9a-fA-F:]+$/.test(s) && (s.match(/:/g) || []).length >= 2
}
function isIP(s: string) { return IPV4_ONE.test(s) || isIPv6(s) }
function isPrivateIP(ip: string) {
  if (ip.includes(':')) { const l = ip.toLowerCase(); return l === '::1' || l.startsWith('fe80') || l.startsWith('fc') || l.startsWith('fd') }
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.')) return true
  const o = ip.split('.').map(Number)
  if (o[0] === 172 && o[1] >= 16 && o[1] <= 31) return true
  return false
}
// netblock24 returns the /24 (IPv4) the address sits in — a cheap, always-
// available proxy for "same infrastructure" when full ASN data isn't present.
function netblock24(ip: string): string { const o = ip.split('.'); return o.length === 4 ? `${o[0]}.${o[1]}.${o[2]}.0/24` : '' }
const SEV_RANK: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 }

type EntityKind = 'ip' | 'domain' | 'account'
interface RelatedEntityAgg {
  value: string
  kind: EntityKind
  etype: OsintTargetType // exact pivot/IOC type (ip | domain | email | username | name)
  sources: string[]
  sampleTitle: string
  severity: string
  count: number
  isV6?: boolean
  isPrivate?: boolean
  subnet?: string
}

// promotable indicator types accepted by the IOC store.
const PROMOTABLE: Record<string, boolean> = { ip: true, domain: true, email: true, hash: true }

function aggregateRelatedEntities(findings: OsintFinding[], target: string): Record<EntityKind, RelatedEntityAgg[]> {
  const map = new Map<string, RelatedEntityAgg>()
  const add = (raw: string, etype: OsintTargetType, source: string, title: string, sev?: string) => {
    const v = (raw || '').trim()
    if (!v || v === target) return
    const kind: EntityKind = etype === 'ip' ? 'ip' : etype === 'domain' ? 'domain' : 'account'
    const key = kind + '|' + v.toLowerCase()
    let r = map.get(key)
    if (!r) {
      r = {
        value: v, kind, etype, sources: [], sampleTitle: title, severity: sev || 'info', count: 0,
        ...(kind === 'ip' ? { isV6: v.includes(':'), isPrivate: isPrivateIP(v), subnet: netblock24(v) } : {}),
      }
      map.set(key, r)
    }
    r.count++
    if (source && !r.sources.includes(source)) r.sources.push(source)
    if ((SEV_RANK[sev || 'info'] ?? 0) > (SEV_RANK[r.severity] ?? 0)) r.severity = sev || 'info'
  }
  for (const f of findings) {
    for (const e of parseRelated(f.related_entities)) {
      if (e.type === 'ip' && isIP(e.value)) add(e.value, 'ip', f.source, f.title, f.severity)
      else if (e.type === 'domain' && DOMAIN_RE.test(e.value)) add(e.value, 'domain', f.source, f.title, f.severity)
      else if (e.type === 'email' || e.type === 'username' || e.type === 'name') add(e.value, e.type, f.source, f.title, f.severity)
    }
    // IPs frequently sit only in finding.value (DNS A records, "host -> ip" lines).
    const m = f.value?.match(IPV4_G)
    if (m) m.forEach(ip => isIP(ip) && add(ip, 'ip', f.source, f.title, f.severity))
    // NS / certificate domains live in value without a related entity.
    if ((f.category === 'dns' || f.category === 'certificate') && f.value && DOMAIN_RE.test(f.value.trim())) {
      add(f.value.trim(), 'domain', f.source, f.title, f.severity)
    }
  }
  const sortFn = (a: RelatedEntityAgg, b: RelatedEntityAgg) =>
    Number(!!a.isPrivate) - Number(!!b.isPrivate) ||
    (a.subnet && b.subnet ? a.subnet.localeCompare(b.subnet) : 0) ||
    (SEV_RANK[b.severity] ?? 0) - (SEV_RANK[a.severity] ?? 0) ||
    b.count - a.count
  const out: Record<EntityKind, RelatedEntityAgg[]> = { ip: [], domain: [], account: [] }
  for (const r of map.values()) out[r.kind].push(r)
  out.ip.sort(sortFn); out.domain.sort(sortFn); out.account.sort(sortFn)
  return out
}

function RelatedEntitiesPanel({ scanId, target, isRunning }: { scanId: string; target: string; isRunning: boolean }) {
  const navigate = useNavigate()
  const [view, setView] = useState<EntityKind>('ip')
  const [busy, setBusy] = useState<string | null>(null)
  const [bulkBusy, setBulkBusy] = useState(false)
  const [sel, setSel] = useState<Set<string>>(new Set())

  const { data: findings = [] } = useQuery({
    queryKey: ['osint-findings', scanId],
    queryFn: () => osintApi.findings(scanId),
    refetchInterval: isRunning ? 4000 : false,
  })
  const agg = useMemo(() => aggregateRelatedEntities(findings, target), [findings, target])
  const total = agg.ip.length + agg.domain.length + agg.account.length
  if (total === 0) return null

  // Default the view to the first non-empty bucket.
  const rows = agg[view].length ? agg[view] : (agg.ip.length ? agg.ip : agg.domain.length ? agg.domain : agg.account)
  const activeView: EntityKind = agg[view].length ? view : (agg.ip.length ? 'ip' : agg.domain.length ? 'domain' : 'account')

  const toggle = (v: string) => setSel(p => { const n = new Set(p); n.has(v) ? n.delete(v) : n.add(v); return n })
  const switchView = (v: EntityKind) => { setView(v); setSel(new Set()) }
  const copy = async (v: string, label: string) => { (await copyToClipboard(v)) ? toast.success(`${label} copied`) : toast.error('Copy failed') }

  const promoteOne = async (r: RelatedEntityAgg) => {
    setBusy(r.value)
    try {
      const { created } = await osintApi.promoteIOC(r.value, r.etype, `OSINT related ${r.etype} of ${target}`)
      toast.success(created ? `${r.value} added to IOC store` : `${r.value} already in IOC store`)
    } catch (err) { toast.error(getErrorMessage(err)) }
    finally { setBusy(null) }
  }

  const selectedRows = () => rows.filter(r => sel.has(r.value))
  const bulkPromote = async () => {
    const targets = selectedRows().filter(r => PROMOTABLE[r.etype])
    if (!targets.length) { toast.error('No promotable indicators selected'); return }
    setBulkBusy(true)
    try {
      const res = await Promise.allSettled(targets.map(r => osintApi.promoteIOC(r.value, r.etype, `OSINT related ${r.etype} of ${target}`)))
      const ok = res.filter(x => x.status === 'fulfilled').length
      toast.success(`Added ${ok}/${targets.length} indicator(s) to IOC store`)
    } finally { setBulkBusy(false) }
  }
  const bulkPivot = async () => {
    const targets = selectedRows().slice(0, 12) // cap to avoid runaway graph expansion
    if (!targets.length) return
    setBulkBusy(true)
    try {
      await Promise.allSettled(targets.map(r => osintApi.create({ target: r.value })))
      toast.success(`Started ${targets.length} pivot investigation(s) — see the graph`)
      setSel(new Set())
    } catch (err) { toast.error(getErrorMessage(err)) }
    finally { setBulkBusy(false) }
  }
  const copyAll = () => copy(rows.map(r => r.value).join('\n'), `${rows.length} ${activeView}(s)`)
  const allSelected = rows.length > 0 && rows.every(r => sel.has(r.value))
  const toggleAll = () => setSel(allSelected ? new Set() : new Set(rows.map(r => r.value)))

  const TABS: { k: EntityKind; label: string; icon: any; n: number }[] = [
    { k: 'ip', label: 'IPs', icon: Network, n: agg.ip.length },
    { k: 'domain', label: 'Domains', icon: Globe, n: agg.domain.length },
    { k: 'account', label: 'Accounts', icon: AtSign, n: agg.account.length },
  ]
  const colLabel = activeView === 'ip' ? 'IP address' : activeView === 'domain' ? 'Domain' : 'Account'

  return (
    <div className="card">
      <div className="flex items-center justify-between px-4 py-2.5 border-b border-slate-800 flex-wrap gap-2">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <Network className="h-4 w-4 text-emerald-400" /> Related Entities
        </h3>
        <div className="flex items-center gap-1">
          {TABS.filter(t => t.n > 0).map(t => {
            const Icon = t.icon
            return (
              <button key={t.k} onClick={() => switchView(t.k)}
                className={`flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium transition-colors ${activeView === t.k ? 'bg-emerald-600/20 text-emerald-300 border border-emerald-700/50' : 'text-gray-400 hover:text-gray-200 border border-transparent'}`}>
                <Icon className="h-3 w-3" /> {t.label} <span className="opacity-60">{t.n}</span>
              </button>
            )
          })}
          <button onClick={copyAll} className="ml-1 flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded bg-gray-800 border border-slate-700 text-gray-300 hover:text-emerald-300 hover:border-emerald-700/50 transition-colors">
            <Copy className="h-3 w-3" /> Copy all
          </button>
        </div>
      </div>
      <p className="px-4 pt-2 text-[11px] text-gray-500">
        Entities discovered while investigating <span className="font-mono text-gray-400">{target}</span> — resolved IPs, related domains/subdomains and linked accounts.
      </p>

      {sel.size > 0 && (
        <div className="flex flex-wrap items-center gap-2 px-4 py-2 bg-emerald-500/5 border-y border-emerald-500/15">
          <span className="text-[11px] text-emerald-300 font-medium">{sel.size} selected</span>
          <button onClick={bulkPivot} disabled={bulkBusy} className="flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded bg-emerald-900/30 text-emerald-300 border border-emerald-800/40 hover:bg-emerald-900/50 disabled:opacity-50">
            <ArrowRight className="h-3 w-3" /> Pivot selected{sel.size > 12 ? ' (first 12)' : ''}
          </button>
          <button onClick={bulkPromote} disabled={bulkBusy} className="flex items-center gap-1 text-[10px] font-mono px-2 py-1 rounded bg-blue-900/30 text-blue-300 border border-blue-800/40 hover:bg-blue-900/50 disabled:opacity-50">
            {bulkBusy ? <Loader2 className="h-3 w-3 animate-spin" /> : <ShieldPlus className="h-3 w-3" />} Add selected to IOC
          </button>
          <button onClick={() => setSel(new Set())} className="text-[10px] text-gray-500 hover:text-gray-300">Clear</button>
        </div>
      )}

      <div className="overflow-x-auto">
        <table className="w-full text-xs">
          <thead><tr className="border-b border-slate-800 text-gray-500">
            <th className="px-3 py-2 w-6"><input type="checkbox" checked={allSelected} onChange={toggleAll} className="accent-emerald-500" /></th>
            <th className="text-left font-medium px-2 py-2">{colLabel}</th>
            {activeView === 'ip' && <th className="text-left font-medium px-3 py-2">Netblock</th>}
            <th className="text-left font-medium px-3 py-2">Discovered by</th>
            <th className="text-left font-medium px-3 py-2">Hits</th>
            <th className="text-right font-medium px-4 py-2">Actions</th>
          </tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.value} className="border-b border-slate-800/60 last:border-0 hover:bg-slate-800/30">
                <td className="px-3 py-2"><input type="checkbox" checked={sel.has(r.value)} onChange={() => toggle(r.value)} className="accent-emerald-500" /></td>
                <td className="px-2 py-2">
                  <div className="flex items-center gap-2 flex-wrap">
                    <span className="font-mono text-gray-200 break-all">{r.value}</span>
                    {r.kind === 'ip' && <span className="text-[9px] font-mono uppercase text-gray-600">{r.isV6 ? 'IPv6' : 'IPv4'}</span>}
                    {r.kind === 'account' && <span className="text-[9px] font-mono uppercase text-gray-600">{r.etype}</span>}
                    {r.isPrivate && <span className="text-[9px] font-mono uppercase px-1.5 py-0.5 rounded bg-gray-800 text-gray-500 border border-slate-700">private</span>}
                    {(SEV_RANK[r.severity] ?? 0) >= 2 && <span className={`text-[9px] px-1.5 py-0.5 rounded font-mono uppercase border ${SEVERITY_COLOR[r.severity] ?? SEVERITY_COLOR.info}`}>{r.severity}</span>}
                  </div>
                  <div className="text-[10px] text-gray-600 truncate max-w-md mt-0.5">{r.sampleTitle}</div>
                </td>
                {activeView === 'ip' && <td className="px-3 py-2 font-mono text-gray-500">{r.subnet || '—'}</td>}
                <td className="px-3 py-2">
                  <div className="flex flex-wrap gap-1">
                    {r.sources.map(s => <span key={s} className="text-[9px] font-mono px-1.5 py-0.5 rounded bg-slate-800 text-gray-400 border border-slate-700">{COLLECTOR_LABELS[s] ?? s}</span>)}
                  </div>
                </td>
                <td className="px-3 py-2 font-mono text-gray-500">{r.count}</td>
                <td className="px-4 py-2">
                  <div className="flex items-center justify-end gap-1.5">
                    <button onClick={async () => { try { const s = await osintApi.create({ target: r.value }); toast.success('Pivot started'); navigate(`/osint/${s.id}`) } catch (e) { toast.error(getErrorMessage(e)) } }}
                      title={`Launch a fresh OSINT investigation on this ${r.etype}`}
                      className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-900/20 text-emerald-300 border border-emerald-800/40 hover:bg-emerald-900/40 transition-colors">
                      <ArrowRight className="h-3 w-3" /> Pivot
                    </button>
                    {PROMOTABLE[r.etype] && (
                      <button onClick={() => promoteOne(r)} disabled={busy === r.value} title="Add to the IOC store (ELK auto-hunt will search logs for it)"
                        className="flex items-center gap-1 text-[10px] font-mono px-2 py-0.5 rounded bg-blue-900/20 text-blue-300 border border-blue-800/40 hover:bg-blue-900/40 transition-colors disabled:opacity-50">
                        {busy === r.value ? <Loader2 className="h-3 w-3 animate-spin" /> : <ShieldPlus className="h-3 w-3" />} IOC
                      </button>
                    )}
                    <button onClick={() => copy(r.value, colLabel)} title="Copy" className="text-gray-600 hover:text-emerald-300"><Copy className="h-3.5 w-3.5" /></button>
                  </div>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ---- Geolocation ------------------------------------------------------------
// Surfaces the lat/lon the geoip collector buries in a finding's Data JSON as a
// readable location card with network ownership + an OpenStreetMap link (no map
// tiles embedded, so it stays safe in air-gapped DFIR environments).
const IDENTITY_GRADE: Record<string, { label: string; cls: string; bar: string }> = {
  strong:   { label: 'Strong',   cls: 'text-emerald-300 border-emerald-700/50', bar: 'bg-emerald-500' },
  moderate: { label: 'Moderate', cls: 'text-yellow-300 border-yellow-700/50',  bar: 'bg-yellow-500' },
  weak:     { label: 'Weak',     cls: 'text-orange-300 border-orange-700/50',  bar: 'bg-orange-500' },
  minimal:  { label: 'Minimal',  cls: 'text-gray-400 border-slate-700',         bar: 'bg-gray-600' },
}

// IdentityPanel shows how strongly the graph corroborates a single identity — a
// 0-100 score, grade, and the independent signals behind it. Self-hides when
// there are no identity signals (e.g. an infrastructure-only scan).
function IdentityPanel({ scanId, isRunning }: { scanId: string; isRunning: boolean }) {
  const { data } = useQuery({
    queryKey: ['osint-identity', scanId],
    queryFn: () => osintApi.identity(scanId),
    refetchInterval: isRunning ? 5000 : false,
  })
  if (!data || (data as IdentityConfidence).signals.length === 0) return null
  const g = IDENTITY_GRADE[data.grade] ?? IDENTITY_GRADE.minimal

  return (
    <div className="card">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <ShieldCheck className="h-4 w-4 text-emerald-400" /> Identity confidence
        </h3>
        <span className={`ml-auto text-[11px] font-mono px-1.5 py-0.5 rounded border ${g.cls}`}>{g.label} · {data.score}/100</span>
      </div>
      <div className="p-4 space-y-3">
        <div className="h-2 w-full rounded-full bg-gray-800 overflow-hidden">
          <div className={`h-full ${g.bar} transition-all`} style={{ width: `${data.score}%` }} />
        </div>
        <p className="text-xs text-gray-400">{data.summary}</p>
        <div className="space-y-1.5">
          {data.signals.map((s) => (
            <div key={s.key} className="flex items-center gap-2 text-xs">
              <ShieldPlus className="h-3.5 w-3.5 text-emerald-500 shrink-0" />
              <span className="text-gray-200">{s.label}</span>
              {s.detail && <span className="text-gray-500">— {s.detail}</span>}
              <span className="ml-auto text-[10px] font-mono text-gray-600">+{s.weight}</span>
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

// bboxDelta picks a map zoom window (degrees) for a precision level: a precise
// EXIF fix is shown tight; a country-level hint is shown wide.
function bboxDelta(precision?: string): number {
  switch (precision) {
    case 'exact': return 0.01
    case 'city': return 0.15
    case 'region': return 1.5
    default: return 6 // country / unknown
  }
}

// osmEmbedURL builds an embedded OpenStreetMap map (no JS library needed) with a
// marker at (lat,lon), zoomed by the precision of the best estimate.
function osmEmbedURL(lat: number, lon: number, precision?: string): string {
  const d = bboxDelta(precision)
  // OSM's embed endpoint expects raw commas in bbox/marker, so do not URL-encode.
  const bbox = `${lon - d},${lat - d},${lon + d},${lat + d}`
  return `https://www.openstreetmap.org/export/embed.html?bbox=${bbox}&layer=mapnik&marker=${lat},${lon}`
}

const GEO_SOURCE_LABEL: Record<string, string> = {
  exif: 'Photo EXIF GPS', geoip: 'IP geolocation', phone: 'Phone region',
  whois: 'WHOIS', profile: 'Profile',
}
const GEO_CONF_CLS: Record<string, string> = {
  high: 'text-emerald-300 bg-emerald-900/30 border-emerald-800/40',
  medium: 'text-yellow-300 bg-yellow-900/30 border-yellow-800/40',
  low: 'text-gray-400 bg-gray-800 border-slate-700',
}

function GeoPointRow({ p }: { p: GeoPoint }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-gray-900/40 p-3">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 text-sm text-gray-200 min-w-0">
          <MapPin className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="font-medium truncate">{p.place || `${p.lat.toFixed(4)}, ${p.lon.toFixed(4)}`}</span>
        </div>
        <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border shrink-0 ${GEO_CONF_CLS[p.confidence] ?? GEO_CONF_CLS.low}`}>
          {p.precision}/{p.confidence}
        </span>
      </div>
      <div className="mt-1 flex items-center gap-2 text-[11px] text-gray-500">
        <span className="font-mono">{p.lat.toFixed(5)}, {p.lon.toFixed(5)}</span>
        <span className="text-gray-600">·</span>
        <span>{GEO_SOURCE_LABEL[p.source] ?? p.source}</span>
        {p.target && <><span className="text-gray-600">·</span><span className="truncate">{p.target}</span></>}
      </div>
      <a href={`https://www.openstreetmap.org/?mlat=${p.lat}&mlon=${p.lon}#map=12/${p.lat}/${p.lon}`}
        target="_blank" rel="noopener noreferrer"
        className="mt-2 inline-flex items-center gap-1 text-[11px] font-mono px-2 py-1 rounded bg-emerald-900/20 text-emerald-300 border border-emerald-800/40 hover:bg-emerald-900/40 transition-colors">
        <ExternalLink className="h-3 w-3" /> Open map
      </a>
    </div>
  )
}

function PhotoGeoUpload({ scanId }: { scanId: string }) {
  const qc = useQueryClient()
  const fileRef = useRef<HTMLInputElement>(null)
  const mut = useMutation({
    mutationFn: (file: File) => osintApi.addScanPhotoGeo(scanId, file),
    onSuccess: (d) => {
      if (d.found) {
        toast.success('Photo GPS added to the map')
        qc.invalidateQueries({ queryKey: ['osint-location', scanId] })
        qc.invalidateQueries({ queryKey: ['osint-findings', scanId] })
      } else {
        toast(d.note || 'No EXIF GPS in this image', { icon: '🔍' })
      }
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })
  return (
    <>
      <input ref={fileRef} type="file" accept="image/*" className="hidden"
        onChange={(e) => { const f = e.target.files?.[0]; if (f) mut.mutate(f); e.target.value = '' }} />
      <button
        onClick={() => fileRef.current?.click()}
        disabled={mut.isPending}
        className="inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-gray-800 text-gray-300 border border-slate-700 hover:border-emerald-700 hover:text-emerald-300 transition-colors disabled:opacity-50"
        title="Extract a photo's EXIF GPS and pin it on the map"
      >
        {mut.isPending ? <Loader2 className="h-3 w-3 animate-spin" /> : <Upload className="h-3 w-3" />} Add photo
      </button>
    </>
  )
}

function GeolocationPanel({ scanId, isRunning }: { scanId: string; isRunning: boolean }) {
  const { data } = useQuery({
    queryKey: ['osint-location', scanId],
    queryFn: () => osintApi.location(scanId),
    refetchInterval: isRunning ? 5000 : false,
  })

  // No coordinates yet — still expose the EXIF photo uploader (it's the only way
  // to add an exact fix for person/handle targets that have no IP geolocation).
  if (!data || !data.found || !data.best) {
    return (
      <div className="card px-4 py-3 flex items-center gap-2">
        <MapPin className="h-4 w-4 text-gray-600" />
        <span className="text-xs text-gray-500">No location resolved yet. Have a photo of the target? Extract its GPS:</span>
        <span className="ml-auto"><PhotoGeoUpload scanId={scanId} /></span>
      </div>
    )
  }
  const best = data.best
  const others = data.points.filter((p) => !(p.lat === best.lat && p.lon === best.lon && p.source === best.source))

  return (
    <div className="card">
      <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
        <h3 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <MapPin className="h-4 w-4 text-emerald-400" /> Location
          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-emerald-900/30 text-emerald-300 border border-emerald-800/40">{data.count}</span>
        </h3>
        <PhotoGeoUpload scanId={scanId} />
        <span className="ml-auto text-[11px] text-gray-500">best estimate · {best.precision}/{best.confidence}</span>
      </div>

      {/* Embedded OpenStreetMap centered on the best estimate (no JS map lib). */}
      <div className="relative">
        <iframe
          title="target-location-map"
          className="w-full h-72 border-0 bg-gray-900"
          loading="lazy"
          referrerPolicy="no-referrer"
          src={osmEmbedURL(best.lat, best.lon, best.precision)}
        />
        <div className="absolute bottom-2 left-2 right-2 flex items-center gap-2 rounded bg-gray-950/80 backdrop-blur px-2.5 py-1.5 border border-slate-700">
          <MapPin className="h-4 w-4 text-emerald-400 shrink-0" />
          <span className="text-xs text-gray-200 font-medium truncate">{best.place || `${best.lat.toFixed(4)}, ${best.lon.toFixed(4)}`}</span>
          <span className="text-[10px] text-gray-500 font-mono">{GEO_SOURCE_LABEL[best.source] ?? best.source}</span>
          {data.maps_url && (
            <a href={data.maps_url} target="_blank" rel="noopener noreferrer"
              className="ml-auto inline-flex items-center gap-1 text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-900/30 text-emerald-300 border border-emerald-800/40 hover:bg-emerald-900/50 transition-colors shrink-0">
              <ExternalLink className="h-3 w-3" /> Google Maps
            </a>
          )}
        </div>
      </div>

      {others.length > 0 && (
        <div className="p-4">
          <p className="text-[11px] text-gray-500 mb-2">All located observations ({data.points.length}) — agreement across sources raises confidence:</p>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            {data.points.map((p, i) => <GeoPointRow key={i} p={p} />)}
          </div>
        </div>
      )}
    </div>
  )
}

// ---- Report tab -------------------------------------------------------------

function StatCard({ label, value, color }: { label: string; value: number; color: string }) {
  return (
    <div className="card p-4 text-center">
      <div className={`text-3xl font-bold font-mono ${color}`}>{value}</div>
      <div className="text-[10px] text-gray-500 uppercase tracking-wider mt-1">{label}</div>
    </div>
  )
}

function ReportTab({ scan, isRunning }: { scan: OsintScan; isRunning: boolean }) {
  const pivot = usePivot()

  const { data: findings = [], isLoading } = useQuery({
    queryKey: ['osint-findings', scan.id],
    queryFn: () => osintApi.findings(scan.id),
    refetchInterval: isRunning ? 4000 : false,
  })

  const stats = useMemo(() => {
    let high = 0, medium = 0, low = 0, pivots = 0, social = 0
    for (const f of findings) {
      const s = f.severity ?? 'info'
      if (s === 'high' || s === 'critical') high++
      else if (s === 'medium') medium++
      else if (s === 'low') low++
      pivots += parseRelated(f.related_entities).length
      if (f.category === 'social' && f.title.startsWith('Profile found')) social++
    }
    return { total: findings.length, high, medium, low, pivots, social }
  }, [findings])

  const highlights = useMemo(
    () => findings.filter(f => f.severity === 'critical' || f.severity === 'high' || f.severity === 'medium'),
    [findings],
  )
  const grouped = useMemo(() => groupByCategory(findings), [findings])

  const collectors = scan.collectors ?? []
  const cDone = collectors.filter(c => c.status === 'done').length
  const cSkipped = collectors.filter(c => c.status === 'skipped').length
  const cFailed = collectors.filter(c => c.status === 'failed').length

  if (isLoading) {
    return <div className="flex justify-center py-8"><Loader2 className="h-5 w-5 animate-spin text-gray-600" /></div>
  }

  return (
    <div className="space-y-6">
      {/* Report header + download */}
      <div className="card p-5 bg-gradient-to-br from-emerald-900/10 to-gray-900 border-emerald-900/30">
        <div className="flex flex-col sm:flex-row sm:items-start justify-between gap-4">
          <div className="flex items-start gap-3">
            <div className="p-2.5 bg-emerald-900/30 rounded-lg shrink-0">
              <FileBarChart2 className="h-5 w-5 text-emerald-400" />
            </div>
            <div>
              <h2 className="text-base font-bold text-gray-100">Investigation Report</h2>
              <p className="text-xs text-gray-500 mt-0.5">
                {scan.target} · <span className="uppercase">{scan.target_type}</span> ·
                {' '}created {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
              </p>
            </div>
          </div>
          <a
            href={osintApi.reportUrl(scan.id)}
            download
            className="btn-primary flex items-center gap-2 shrink-0"
            title="Download a self-contained HTML report"
          >
            <Download className="h-4 w-4" />
            Download HTML
          </a>
        </div>
      </div>

      {/* Stat grid */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard label="Total Findings"  value={stats.total}  color="text-emerald-400" />
        <StatCard label="High / Critical" value={stats.high}   color="text-red-400" />
        <StatCard label="Medium"          value={stats.medium} color="text-yellow-400" />
        <StatCard label="Low"             value={stats.low}    color="text-blue-400" />
        <StatCard label="Social Profiles" value={stats.social} color="text-cyan-400" />
        <StatCard label="Pivots Found"    value={stats.pivots} color="text-purple-400" />
      </div>

      {/* Collector coverage */}
      <div className="card p-4">
        <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-3">Data Source Coverage</h3>
        <div className="flex flex-wrap gap-4 text-sm">
          <span className="flex items-center gap-1.5 text-emerald-400">
            <CheckCircle className="h-4 w-4" /> {cDone} completed
          </span>
          <span className="flex items-center gap-1.5 text-gray-500">
            <MinusCircle className="h-4 w-4" /> {cSkipped} skipped
          </span>
          <span className="flex items-center gap-1.5 text-red-400">
            <XCircle className="h-4 w-4" /> {cFailed} failed
          </span>
        </div>
      </div>

      {/* Highlights */}
      <div className="card">
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
          <AlertTriangle className={`h-4 w-4 ${highlights.length > 0 ? 'text-orange-400' : 'text-gray-600'}`} />
          <h3 className="text-sm font-semibold text-gray-200">Highlights</h3>
          <span className="text-[10px] font-mono text-gray-500">{highlights.length}</span>
        </div>
        {highlights.length === 0 ? (
          <div className="flex items-center justify-center gap-2 py-8 text-sm text-gray-600">
            <ShieldCheck className="h-4 w-4 text-emerald-600" />
            No high or medium severity findings.
          </div>
        ) : (
          <div>
            {highlights.map(f => (
              <FindingRow key={f.id} f={f} onPivot={(e) => pivot.mutate(e)} />
            ))}
          </div>
        )}
      </div>

      {/* Category breakdown summary */}
      <div className="card p-4">
        <h3 className="text-xs font-mono text-gray-500 uppercase tracking-widest mb-3">Findings by Category</h3>
        {grouped.length === 0 ? (
          <p className="text-sm text-gray-600">No findings recorded.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            {grouped.map(({ cat, items }) => (
              <span
                key={cat}
                className="text-xs font-mono px-2.5 py-1 rounded-lg bg-gray-800 border border-slate-700 text-gray-300"
              >
                {CATEGORY_LABELS[cat] ?? cat}
                <span className="ml-1.5 text-emerald-400">{items.length}</span>
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ---- Page -------------------------------------------------------------------

export default function OsintDetailPage() {
  const { id } = useParams<{ id: string }>()
  const navigate = useNavigate()
  const qc = useQueryClient()
  const [tab, setTab] = useState<'findings' | 'report'>('findings')

  const { data: scan, isLoading } = useQuery({
    queryKey: ['osint-scan', id],
    queryFn: () => osintApi.get(id!),
    enabled: !!id,
    refetchInterval: (q) => {
      const s = q.state.data?.status
      return s === 'running' || s === 'pending' ? 3000 : false
    },
  })

  const stopMutation = useMutation({
    mutationFn: () => osintApi.stop(id!),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['osint-scan', id] })
      toast.success('Stop signal sent')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  // Promote the investigated target into the IOC store — the ELK auto-hunt then
  // searches the logs for it on its next run (the OSINT → defence loop).
  const promoteMutation = useMutation({
    mutationFn: () => osintApi.promoteIOC(scan!.target, scan!.target_type, `OSINT: ${scan!.name}`),
    onSuccess: (d) => toast.success(d.created
      ? 'Added to IOC store — ELK auto-hunt will pick it up'
      : 'Already in the IOC store'),
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  if (isLoading) {
    return <div className="flex justify-center py-20"><Loader2 className="h-6 w-6 animate-spin text-gray-600" /></div>
  }
  if (!scan) {
    return <p className="text-red-400 text-center py-20">Investigation not found</p>
  }

  const collectors = scan.collectors ?? []
  const isRunning = scan.status === 'running'

  const TABS = [
    { key: 'findings' as const, label: 'Findings', icon: ListTree },
    { key: 'report' as const,   label: 'Report',   icon: FileBarChart2 },
  ]

  return (
    <div className="space-y-4">
      {/* Top action bar */}
      <div className="flex items-center justify-between gap-3">
        <button
          onClick={() => navigate('/osint')}
          className="flex items-center gap-1.5 text-xs font-mono text-gray-500 hover:text-emerald-300 transition-colors"
        >
          <ChevronLeft className="h-4 w-4" /> back to targets
        </button>
        <div className="flex items-center gap-2">
          {['ip', 'domain', 'email', 'hash', 'wallet'].includes(scan.target_type) && (
            <button
              className="btn-secondary flex items-center gap-2"
              disabled={promoteMutation.isPending}
              onClick={() => promoteMutation.mutate()}
              title="Add this target to the IOC store so the ELK auto-hunt can search the logs for it"
            >
              <ShieldPlus className="h-4 w-4" /> Add to IOC store
            </button>
          )}
          {scan.status !== 'pending' && (
            <a
              href={osintApi.reportUrl(scan.id)}
              download
              className="btn-secondary flex items-center gap-2"
              title="Download a self-contained HTML report"
            >
              <Download className="h-4 w-4" />
              Report
            </a>
          )}
          {scan.status !== 'pending' && (
            <a
              href={osintApi.exportUrl(scan.id, 'stix')}
              download
              className="btn-secondary flex items-center gap-2"
              title="Export indicators as a STIX 2.1 bundle for MISP / OpenCTI / TIP ingestion"
            >
              <Download className="h-4 w-4" />
              STIX
            </a>
          )}
          {scan.status !== 'pending' && (
            <a
              href={osintApi.exportUrl(scan.id, 'csv')}
              download
              className="btn-secondary flex items-center gap-2"
              title="Export findings as CSV"
            >
              <Download className="h-4 w-4" />
              CSV
            </a>
          )}
          {scan.status !== 'pending' && (
            <a
              href={osintApi.graphExportUrl(scan.id)}
              download
              className="btn-secondary flex items-center gap-2"
              title="Export the investigation graph as GraphML for Maltego / Gephi / yEd / Cytoscape"
            >
              <Download className="h-4 w-4" />
              GraphML
            </a>
          )}
          {isRunning && (
            <button
              className="btn-danger flex items-center gap-2"
              disabled={stopMutation.isPending}
              onClick={() => stopMutation.mutate()}
            >
              <StopCircle className="h-4 w-4" /> Stop
            </button>
          )}
        </div>
      </div>

      {/* Target graph hero */}
      <TargetGraphHero
        scan={scan}
        totalFindings={collectors.reduce((sum, c) => sum + (c.findings_count ?? 0), 0)}
      />

      {/* Collector timeline */}
      <CollectorTimeline collectors={collectors} />

      {/* Identity confidence — how strongly the graph corroborates one identity */}
      <IdentityPanel scanId={scan.id} isRunning={isRunning} />

      {/* Related entities (IPs / domains / accounts) — self-hides when empty */}
      <RelatedEntitiesPanel scanId={scan.id} target={scan.target} isRunning={isRunning} />

      {/* Geolocation — self-hides when no geo coordinates were resolved */}
      <GeolocationPanel scanId={scan.id} isRunning={isRunning} />

      {/* Live output */}
      <OsintStreamPanel scanId={scan.id} />

      {/* Investigation graph (auto-pivot) — self-hides when no pivots */}
      <OsintGraphView scanId={scan.id} live={isRunning} />

      {/* Shared indicators (correlation / de-anon) — self-hides when no cross-links */}
      <OsintCorrelations scanId={scan.id} live={isRunning} />

      {/* AI triage (defensive summary) */}
      {!isRunning && scan.status !== 'pending' && <OsintAiTriage scanId={scan.id} />}

      {/* Tab bar */}
      <div className="flex gap-1 border-b border-slate-800 overflow-x-auto whitespace-nowrap">
        {TABS.map(t => {
          const Icon = t.icon
          return (
            <button
              key={t.key}
              onClick={() => setTab(t.key)}
              className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 transition-colors ${
                tab === t.key
                  ? 'border-emerald-500 text-emerald-400'
                  : 'border-transparent text-gray-500 hover:text-gray-300'
              }`}
            >
              <Icon className="h-4 w-4" />
              {t.label}
            </button>
          )
        })}
      </div>

      {/* Tab content */}
      {tab === 'findings'
        ? <FindingsPanel scanId={scan.id} isRunning={isRunning} />
        : <ReportTab scan={scan} isRunning={isRunning} />}
    </div>
  )
}
