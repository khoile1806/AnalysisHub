import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  ShieldAlert, Loader2, Play, Square, Trash2, ChevronRight, AlertTriangle,
  Radio, Server, Terminal, Download, Search, ExternalLink, ChevronDown, Code2, Copy, ArrowDownToLine,
} from 'lucide-react'

import {
  vulnscanApi, type VulnScan, type VulnFinding, SEVERITY_ORDER, SEVERITY_COLOR,
  priorityScore, priorityLabel,
} from '@/api/vulnscan'
import { useAuthStore } from '@/store/auth'
import { safeDistanceToNow } from '@/lib/utils'

const ALL_SEV = ['critical', 'high', 'medium', 'low', 'info']

function StatusDot({ status }: { status: string }) {
  const c =
    status === 'running' ? 'bg-emerald-400 animate-pulse'
    : status === 'done' ? 'bg-sky-400'
    : status === 'failed' ? 'bg-red-400'
    : status === 'stopped' ? 'bg-amber-400'
    : 'bg-slate-500'
  return <span className={`h-2 w-2 rounded-full ${c}`} />
}

// VulnScanPanel is rendered as a tab inside the OSINT list page AND, scoped to a
// single investigation (osintScanId), inside the OSINT detail page. It runs
// httpx+nuclei over assets discovered by OSINT.
export function VulnScanPanel({ osintScanId, osintTarget }: { osintScanId?: string; osintTarget?: string } = {}) {
  const qc = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'
  const [selected, setSelected] = useState<string | null>(null)
  const [scanModal, setScanModal] = useState(false)

  const { data: scans = [], isLoading } = useQuery({
    queryKey: osintScanId ? ['vulnscans', 'osint', osintScanId] : ['vulnscans'],
    queryFn: () => (osintScanId ? vulnscanApi.listForOsint(osintScanId) : vulnscanApi.list()),
    refetchInterval: (q) => {
      const data = q.state.data as VulnScan[] | undefined
      return data?.some((s) => s.status === 'running' || s.status === 'pending') ? 5000 : 0
    },
  })

  const refreshList = () => qc.invalidateQueries({ queryKey: osintScanId ? ['vulnscans', 'osint', osintScanId] : ['vulnscans'] })

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-lg border border-amber-600/30 bg-amber-500/5 p-3 text-xs text-amber-300">
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
        <div>
          <b>Active vulnerability scanning.</b> httpx + nuclei (and, on the aggressive profile,
          dalfox/wpscan/nmap) probe the selected assets directly. Only scan systems you are authorised
          to test. Traffic and DNS route through the configured egress proxy/Tor; private/internal
          addresses are filtered out automatically.
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-4">
        <div className="space-y-3">
          {isAdmin && (osintScanId ? (
            <button className="btn-primary w-full justify-center" onClick={() => setScanModal(true)}>
              <Play className="h-4 w-4" /> Scan related assets
            </button>
          ) : (
            <NewScanForm onCreated={(id) => { setSelected(id); refreshList() }} />
          ))}
          {scanModal && osintScanId && (
            <AssetScanModal
              osintScanId={osintScanId}
              targetLabel={osintTarget || 'investigation'}
              onClose={() => setScanModal(false)}
              onStarted={(id) => { setScanModal(false); setSelected(id); refreshList() }}
            />
          )}
          <div className="space-y-2">
            {isLoading ? (
              <div className="flex justify-center py-10 text-gray-600"><Loader2 className="h-5 w-5 animate-spin" /></div>
            ) : scans.length === 0 ? (
              <div className="card text-center py-10 text-sm text-gray-500">No scans yet</div>
            ) : (
              scans.map((s) => (
                <button
                  key={s.id}
                  onClick={() => setSelected(s.id)}
                  className={`card w-full text-left p-3 transition-colors ${selected === s.id ? 'border-emerald-500/50' : 'hover:border-slate-700'}`}
                >
                  <div className="flex items-center gap-2">
                    <StatusDot status={s.status} />
                    <span className="text-sm font-medium truncate flex-1">{s.name}</span>
                    <ChevronRight className="h-4 w-4 text-gray-600" />
                  </div>
                  <div className="mt-1.5 flex items-center gap-2 text-[11px] text-gray-500">
                    <span>{s.target_count} assets</span>
                    <span>·</span>
                    <span>{safeDistanceToNow(s.created_at)}</span>
                  </div>
                  <SummaryChips summary={s.summary} />
                </button>
              ))
            )}
          </div>
        </div>

        <div>
          {selected ? (
            <ScanDetail key={selected} scanId={selected} isAdmin={isAdmin} onDeleted={() => setSelected(null)} />
          ) : (
            <div className="card flex flex-col items-center justify-center py-24 text-center gap-3 text-gray-600">
              <ShieldAlert className="h-10 w-10" />
              <p className="text-sm text-gray-500">Select a scan to view findings, or start a new one.</p>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

function SummaryChips({ summary }: { summary?: string }) {
  const counts = useMemo<Record<string, number>>(() => {
    if (!summary) return {}
    try { return JSON.parse(summary) } catch { return {} }
  }, [summary])
  const keys = SEVERITY_ORDER.filter((k) => counts[k] > 0)
  if (keys.length === 0) return null
  return (
    <div className="mt-2 flex flex-wrap gap-1">
      {keys.map((k) => (
        <span key={k} className={`text-[10px] px-1.5 py-0.5 rounded border ${SEVERITY_COLOR[k] ?? SEVERITY_COLOR.unknown}`}>
          {k} {counts[k]}
        </span>
      ))}
    </div>
  )
}

const TRIAGE_STATUSES = ['open', 'confirmed', 'false_positive', 'fixed'] as const

// logLineClass colour-codes a live-output line by its prefix so an operator can
// scan the console at a glance: errors red, successes green, findings by severity.
function logLineClass(l: string): string {
  if (/^\[!\]/.test(l)) return 'text-red-400'
  if (/^\[\+\]/.test(l)) return 'text-emerald-400'
  if (/^\[(CRITICAL|KEV)/i.test(l)) return 'text-red-400 font-semibold'
  if (/^\[HIGH/i.test(l)) return 'text-orange-400'
  if (/^\[MEDIUM/i.test(l)) return 'text-amber-400'
  if (/^\[LOW/i.test(l)) return 'text-sky-400'
  if (/^\[ffuf\]/i.test(l)) return 'text-cyan-400'
  if (/^\[\*\]/.test(l)) return 'text-slate-400'
  return 'text-gray-300'
}

// TOOL_COLOR tints the per-tool badge so an analyst can see at a glance which
// engine produced a finding (nuclei vs dalfox/wpscan/nmap/httpx/tlsx).
const TOOL_COLOR: Record<string, string> = {
  nuclei: 'border-violet-500/30 text-violet-300',
  'nuclei-dast': 'border-fuchsia-500/30 text-fuchsia-300',
  ffuf: 'border-cyan-500/30 text-cyan-300',
  dalfox: 'border-pink-500/30 text-pink-300',
  wpscan: 'border-blue-500/30 text-blue-300',
  nmap: 'border-teal-500/30 text-teal-300',
  httpx: 'border-slate-600 text-gray-400',
  tlsx: 'border-cyan-500/30 text-cyan-300',
}

function parseRefs(reference?: string): string[] {
  if (!reference) return []
  try {
    const v = JSON.parse(reference)
    return Array.isArray(v) ? v.filter((x) => typeof x === 'string') : []
  } catch {
    return reference.startsWith('http') ? [reference] : []
  }
}

// FindingCard renders one vuln finding with a priority score, verification/KEV/
// EPSS badges, an expandable details pane (references, tags, raw tool output)
// and inline operator triage (status + note).
function FindingCard({ f, scanId }: { f: VulnFinding; scanId: string }) {
  const qc = useQueryClient()
  const [note, setNote] = useState(f.note ?? '')
  const [noteOpen, setNoteOpen] = useState(false)
  const [open, setOpen] = useState(false)
  const status = f.status ?? 'open'
  const prio = priorityLabel(priorityScore(f))
  const refs = useMemo(() => parseRefs(f.reference), [f.reference])
  const tags = useMemo(() => (f.tags ? f.tags.split(',').map((t) => t.trim()).filter(Boolean) : []), [f.tags])

  const update = useMutation({
    mutationFn: (body: { status?: string; note?: string }) => vulnscanApi.updateFinding(f.id, body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['vulnscan-findings', scanId] }),
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Update failed'),
  })

  const muted = status === 'false_positive' || status === 'fixed'
  const hasDetails = refs.length > 0 || tags.length > 0 || !!f.data || !!f.description
  return (
    <div className={`card p-3 ${muted ? 'opacity-60' : ''}`}>
      <div className="flex items-start gap-2 flex-wrap">
        <span className={`shrink-0 text-[10px] px-1.5 py-0.5 rounded border font-mono uppercase ${prio.cls}`} title="Triage priority = severity + KEV + EPSS + verified">
          P·{prio.label}
        </span>
        <span className={`text-sm font-medium flex-1 ${status === 'false_positive' ? 'line-through' : ''}`}>{f.name}</span>
        {f.confirmed && (
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-emerald-500/40 bg-emerald-500/15 text-emerald-300" title="Independently re-checked — the template matched again">
            ✓ verified
          </span>
        )}
        {f.is_kev && (
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-red-500/40 bg-red-500/15 text-red-300 font-semibold" title="CISA Known-Exploited — actively exploited in the wild">
            ⚠ KEV
          </span>
        )}
        {typeof f.epss_score === 'number' && f.epss_score > 0 && (
          <span className="text-[10px] px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-300" title="EPSS — exploitation probability (30 days)">
            EPSS {(f.epss_score * 100).toFixed(0)}%
          </span>
        )}
      </div>

      <div className="mt-1 flex items-center gap-2 flex-wrap text-[10px]">
        {f.tool && <span className={`px-1.5 py-0.5 rounded border font-mono ${TOOL_COLOR[f.tool] ?? 'border-slate-600 text-gray-400'}`}>{f.tool}</span>}
        {f.type && <span className="px-1.5 py-0.5 rounded border border-slate-700 text-gray-500 font-mono">{f.type}</span>}
        {f.cve_id && (
          <a href={`https://nvd.nist.gov/vuln/detail/${f.cve_id}`} target="_blank" rel="noreferrer" className="text-sky-400 font-mono hover:underline inline-flex items-center gap-0.5">
            {f.cve_id}<ExternalLink className="h-2.5 w-2.5" />
          </a>
        )}
        {f.template_id && !f.cve_id && <span className="text-gray-500 font-mono">{f.template_id}</span>}
      </div>

      <div className="mt-1 text-[11px] text-emerald-400/80 font-mono break-all">{f.matched_at || f.host}</div>
      {f.description && <div className={`mt-1 text-[11px] text-gray-500 ${open ? '' : 'line-clamp-2'}`}>{f.description}</div>}

      {open && (
        <div className="mt-2 space-y-2">
          {tags.length > 0 && (
            <div className="flex flex-wrap gap-1">
              {tags.map((t) => <span key={t} className="text-[9px] px-1.5 py-0.5 rounded bg-slate-800 text-gray-400 border border-slate-700 font-mono">{t}</span>)}
            </div>
          )}
          {refs.length > 0 && (
            <div className="space-y-0.5">
              {refs.map((r) => (
                <a key={r} href={r} target="_blank" rel="noreferrer" className="block text-[10px] text-sky-400 hover:underline truncate inline-flex items-center gap-1 max-w-full">
                  <ExternalLink className="h-2.5 w-2.5 shrink-0" /> <span className="truncate">{r}</span>
                </a>
              ))}
            </div>
          )}
          {f.data && (
            <pre className="text-[10px] bg-black/40 rounded p-2 overflow-auto max-h-40 text-gray-400 whitespace-pre-wrap break-all">{f.data}</pre>
          )}
        </div>
      )}

      <div className="mt-2 flex items-center gap-2 flex-wrap">
        <select
          className="input text-[11px] py-0.5 h-7"
          value={status}
          onChange={(e) => update.mutate({ status: e.target.value })}
          title="Triage status"
        >
          {TRIAGE_STATUSES.map((s) => <option key={s} value={s}>{s.replace('_', ' ')}</option>)}
        </select>
        <button className="text-[11px] text-gray-500 hover:text-gray-300" onClick={() => setNoteOpen((v) => !v)}>
          {f.note ? '📝 note' : '+ note'}
        </button>
        {hasDetails && (
          <button className="text-[11px] text-gray-500 hover:text-gray-300 inline-flex items-center gap-1 ml-auto" onClick={() => setOpen((v) => !v)}>
            {f.data ? <Code2 className="h-3 w-3" /> : <ChevronDown className={`h-3 w-3 transition-transform ${open ? 'rotate-180' : ''}`} />}
            {open ? 'less' : 'details'}
          </button>
        )}
      </div>
      {noteOpen && (
        <div className="mt-1.5 flex gap-2">
          <input className="input text-[11px] flex-1 h-7" value={note} onChange={(e) => setNote(e.target.value)} placeholder="Triage note…" />
          <button className="btn-secondary text-[11px] py-0.5" onClick={() => update.mutate({ note })}>Save</button>
        </div>
      )}
    </div>
  )
}

const SCOPE_BADGE: Record<string, { label: string; cls: string; title: string }> = {
  private: { label: 'private', cls: 'border-slate-600 text-gray-400', title: 'Resolves only to private/internal IPs — excluded' },
  mixed: { label: 'mixed', cls: 'border-red-500/40 text-red-400', title: 'Resolves to BOTH public and private IPs (DNS-rebinding risk) — excluded' },
  unresolved: { label: 'unresolved', cls: 'border-amber-500/30 text-amber-400', title: 'Does not resolve yet — scanner will try' },
  deferred: { label: 'via tor', cls: 'border-violet-500/30 text-violet-300', title: 'Anonymous mode — resolved through the proxy at scan time, no local DNS lookup' },
}

function ScopeBadge({ scope }: { scope: string }) {
  const b = SCOPE_BADGE[scope]
  if (!b) return null
  return (
    <span className={`shrink-0 text-[9px] px-1 py-0 rounded border ${b.cls}`} title={b.title}>{b.label}</span>
  )
}

// AssetScanModal previews the domains/subdomains/IPs discovered by an OSINT
// investigation and lets the operator review/deselect them before launching an
// active vuln scan over exactly the chosen subset.
export function AssetScanModal({ osintScanId, targetLabel, onClose, onStarted }: {
  osintScanId: string
  targetLabel: string
  onClose: () => void
  onStarted: (scanId: string) => void
}) {
  const [sel, setSel] = useState<Set<string>>(new Set())
  const [profile, setProfile] = useState<'quick' | 'full' | 'cve-only' | 'deep' | 'aggressive'>('quick')
  const [direct, setDirect] = useState(false)
  const [allowPrivate, setAllowPrivate] = useState(false)

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ['vuln-preview', osintScanId, allowPrivate],
    queryFn: () => vulnscanApi.previewAssets(osintScanId, allowPrivate),
  })
  // Default-select only in-scope assets; out-of-scope (private/mixed) are shown
  // but excluded — the backend would drop them anyway.
  useEffect(() => { setSel(new Set(assets.filter((a) => a.keep !== false).map((a) => a.value))) }, [assets])

  const byValue = useMemo(() => Object.fromEntries(assets.map((a) => [a.value, a])), [assets])
  const domains = useMemo(() => assets.filter((a) => a.type === 'domain').map((a) => a.value).sort(), [assets])
  const ips = useMemo(() => assets.filter((a) => a.type === 'ip').map((a) => a.value).sort(), [assets])
  const droppedCount = useMemo(() => assets.filter((a) => a.keep === false).length, [assets])

  const toggle = (v: string) => setSel((p) => { const n = new Set(p); n.has(v) ? n.delete(v) : n.add(v); return n })
  const toggleGroup = (vals: string[], on: boolean) =>
    setSel((p) => { const n = new Set(p); vals.forEach((v) => on ? n.add(v) : n.delete(v)); return n })

  const create = useMutation({
    mutationFn: () => vulnscanApi.create({
      name: `Vuln scan: ${targetLabel}`,
      source_scan_id: osintScanId,
      targets: Array.from(sel),
      profile,
      proxy_choice: direct ? 'direct' : 'tor',
      allow_private: allowPrivate,
    }),
    onSuccess: (s) => { toast.success('Scan started'); onStarted(s.id) },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed to start scan'),
  })

  const Group = ({ title, vals }: { title: string; vals: string[] }) => (
    <div className="space-y-1">
      <div className="flex items-center justify-between">
        <span className="text-[11px] uppercase tracking-wide text-gray-500">{title} ({vals.length})</span>
        {vals.length > 0 && (
          <div className="flex gap-2 text-[10px]">
            <button className="text-emerald-400" onClick={() => toggleGroup(vals, true)}>all</button>
            <button className="text-gray-500" onClick={() => toggleGroup(vals, false)}>none</button>
          </div>
        )}
      </div>
      <div className="max-h-48 overflow-auto space-y-0.5 rounded border border-slate-800 p-1.5">
        {vals.length === 0 ? <div className="text-[11px] text-gray-600 px-1 py-2">none discovered</div> :
          vals.map((v) => {
            const a = byValue[v]
            const dropped = a?.keep === false
            return (
              <label
                key={v}
                className={`flex items-center gap-2 px-1 py-0.5 rounded cursor-pointer ${dropped ? 'opacity-60' : 'hover:bg-slate-800/50'}`}
                title={a?.reason || ''}
              >
                <input type="checkbox" checked={sel.has(v)} onChange={() => toggle(v)} />
                <span className={`text-xs font-mono truncate ${dropped ? 'line-through text-gray-500' : ''}`}>{v}</span>
                {a?.scope && a.scope !== 'in' && <ScopeBadge scope={a.scope} />}
              </label>
            )
          })}
      </div>
    </div>
  )

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="card w-full max-w-2xl max-h-[85vh] overflow-auto p-4 space-y-3" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2">
          <ShieldAlert className="h-5 w-5 text-emerald-400" />
          <h3 className="text-sm font-semibold flex-1">Scan related assets — {targetLabel}</h3>
          <button className="text-gray-500 hover:text-gray-300 text-sm" onClick={onClose}>✕</button>
        </div>
        <p className="text-[11px] text-gray-500">
          Domains, subdomains and IPs discovered across this OSINT investigation. Review and deselect anything
          out of your authorised scope before scanning. Private/internal addresses are filtered server-side.
          {droppedCount > 0 && (
            <span className="text-amber-400"> {droppedCount} asset{droppedCount === 1 ? '' : 's'} excluded as out-of-scope (hover for the reason).</span>
          )}
          {assets.some((a) => a.scope === 'deferred') && (
            <span className="text-violet-300"> Anonymous mode is on — hostnames are resolved through Tor at scan time (no local DNS leak).</span>
          )}
        </p>

        {isLoading ? (
          <div className="flex justify-center py-10 text-gray-600"><Loader2 className="h-5 w-5 animate-spin" /></div>
        ) : assets.length === 0 ? (
          <div className="text-center py-8 text-sm text-gray-500">No public assets discovered in this investigation yet.</div>
        ) : (
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            <Group title="Domains & subdomains" vals={domains} />
            <Group title="IP addresses" vals={ips} />
          </div>
        )}

        <div className="flex flex-wrap items-center gap-3 pt-1 border-t border-slate-800">
          <div className="flex items-center gap-2">
            <span className="text-[11px] text-gray-500">Profile</span>
            <select className="input text-xs" value={profile} onChange={(e) => setProfile(e.target.value as any)}>
              <option value="quick">Quick</option>
              <option value="full">Full (no crawl)</option>
              <option value="cve-only">CVE only</option>
              <option value="deep">Deep (+ katana/gau crawl · XSS · DAST)</option>
              <option value="aggressive">Aggressive (Deep + nmap NSE + intrusive)</option>
            </select>
          </div>
          <label className="flex items-center gap-1.5 text-[11px] text-gray-400">
            <input type="checkbox" checked={direct} onChange={(e) => setDirect(e.target.checked)} /> Direct (no Tor)
          </label>
          <label
            className="flex items-center gap-1.5 text-[11px] text-amber-400"
            title="Allow scanning private/loopback/LAN targets (localhost, 10./192.168.). Authorized internal scans only — use with Direct egress."
          >
            <input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} /> Allow private/LAN
          </label>
          <button
            className="btn-primary ml-auto justify-center"
            disabled={create.isPending || sel.size === 0}
            onClick={() => create.mutate()}
          >
            {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
            Scan {sel.size} asset{sel.size === 1 ? '' : 's'}
          </button>
        </div>
      </div>
    </div>
  )
}

function NewScanForm({ onCreated }: { onCreated: (id: string) => void }) {
  const [open, setOpen] = useState(false)
  const [name, setName] = useState('')
  const [targets, setTargets] = useState('')
  const [sev, setSev] = useState<Set<string>>(new Set(['critical', 'high', 'medium', 'low']))
  const [profile, setProfile] = useState<'quick' | 'full' | 'cve-only' | 'deep' | 'aggressive'>('quick')
  const [tags, setTags] = useState('')
  const [direct, setDirect] = useState(false)
  const [allowPrivate, setAllowPrivate] = useState(false)

  const create = useMutation({
    mutationFn: () =>
      vulnscanApi.create({
        name: name.trim() || undefined,
        targets: targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean),
        severities: Array.from(sev).join(','),
        profile,
        tags: tags.trim() || undefined,
        proxy_choice: direct ? 'direct' : 'tor',
        allow_private: allowPrivate,
      }),
    onSuccess: (s) => { toast.success('Scan started'); setOpen(false); setTargets(''); setName(''); onCreated(s.id) },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed to start scan'),
  })

  if (!open) {
    return (
      <button className="btn-primary w-full justify-center" onClick={() => setOpen(true)}>
        <Play className="h-4 w-4" /> New vulnerability scan
      </button>
    )
  }
  return (
    <div className="card space-y-2.5 p-3">
      <input className="input w-full text-sm" placeholder="Scan name (optional)" value={name} onChange={(e) => setName(e.target.value)} />
      <textarea
        className="input w-full text-sm font-mono h-24"
        placeholder="Targets — one per line (domain / IP). e.g.&#10;example.com&#10;203.0.113.5"
        value={targets}
        onChange={(e) => setTargets(e.target.value)}
      />
      <div className="flex flex-wrap gap-1">
        {ALL_SEV.map((s) => (
          <button
            key={s}
            onClick={() => setSev((prev) => { const n = new Set(prev); n.has(s) ? n.delete(s) : n.add(s); return n })}
            className={`text-[11px] px-2 py-1 rounded border ${sev.has(s) ? SEVERITY_COLOR[s] : 'border-slate-700 text-gray-500'}`}
          >
            {s}
          </button>
        ))}
      </div>
      <div className="flex items-center gap-2">
        <label className="text-[11px] text-gray-500">Profile</label>
        <select className="input text-xs flex-1" value={profile} onChange={(e) => setProfile(e.target.value as any)}>
          <option value="quick">Quick (cve · exposure · misconfig)</option>
          <option value="full">Full — all templates + ports + wpscan (no crawl)</option>
          <option value="cve-only">CVE only</option>
          <option value="deep">Deep — Full + katana/gau crawl + XSS + DAST fuzzing</option>
          <option value="aggressive">Aggressive — Deep + nmap NSE + intrusive templates</option>
        </select>
      </div>
      <input className="input w-full text-sm" placeholder="Extra nuclei tags (optional, CSV)" value={tags} onChange={(e) => setTags(e.target.value)} />
      <label className="flex items-center gap-2 text-[11px] text-gray-400">
        <input type="checkbox" checked={direct} onChange={(e) => setDirect(e.target.checked)} />
        Egress direct (no Tor) — faster but reveals this host's IP
      </label>
      <label className="flex items-center gap-2 text-[11px] text-amber-400">
        <input type="checkbox" checked={allowPrivate} onChange={(e) => setAllowPrivate(e.target.checked)} />
        Allow private/LAN targets (localhost, 10./192.168.) — authorized internal scans; use with Direct
      </label>
      <div className="flex gap-2">
        <button className="btn-primary flex-1 justify-center" disabled={create.isPending || !targets.trim()} onClick={() => create.mutate()}>
          {create.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Start
        </button>
        <button className="btn-secondary" onClick={() => setOpen(false)}>Cancel</button>
      </div>
    </div>
  )
}

function ScanDetail({ scanId, isAdmin, onDeleted }: { scanId: string; isAdmin: boolean; onDeleted: () => void }) {
  const qc = useQueryClient()
  const [log, setLog] = useState<string[]>([])
  const [live, setLive] = useState(false)
  const [hideResolved, setHideResolved] = useState(true)
  const [search, setSearch] = useState('')
  const [toolFilter, setToolFilter] = useState('')
  const [confirmedOnly, setConfirmedOnly] = useState(false)
  const [autoScroll, setAutoScroll] = useState(true)
  const logEndRef = useRef<HTMLDivElement | null>(null)

  const { data: scan } = useQuery({
    queryKey: ['vulnscan', scanId],
    queryFn: () => vulnscanApi.get(scanId),
    refetchInterval: (q) => ((q.state.data as VulnScan | undefined)?.status === 'running' ? 4000 : 0),
  })
  const { data: findings = [] } = useQuery({
    queryKey: ['vulnscan-findings', scanId],
    queryFn: () => vulnscanApi.findings(scanId),
    refetchInterval: scan?.status === 'running' ? 6000 : 0,
  })

  // Live SSE log.
  useEffect(() => {
    setLog([])
    const es = new EventSource(vulnscanApi.streamUrl(scanId))
    es.onopen = () => setLive(true)
    es.onmessage = (ev) => {
      if (ev.data === '__DONE__') {
        es.close(); setLive(false)
        qc.invalidateQueries({ queryKey: ['vulnscan', scanId] })
        qc.invalidateQueries({ queryKey: ['vulnscan-findings', scanId] })
        qc.invalidateQueries({ queryKey: ['vulnscans'] })
        return
      }
      setLog((prev) => [...prev.slice(-2000), ev.data])
    }
    es.onerror = () => { setLive(false); es.close() }
    return () => es.close()
  }, [scanId, qc])

  useEffect(() => { if (autoScroll) logEndRef.current?.scrollIntoView({ block: 'end' }) }, [log, autoScroll])

  const stop = useMutation({
    mutationFn: () => vulnscanApi.stop(scanId),
    onSuccess: () => toast.success('Stop requested'),
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed'),
  })
  const remove = useMutation({
    mutationFn: () => vulnscanApi.remove(scanId),
    onSuccess: () => { toast.success('Deleted'); qc.invalidateQueries({ queryKey: ['vulnscans'] }); onDeleted() },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed'),
  })

  // Tools present in this scan's findings → powers the tool filter dropdown.
  const toolsPresent = useMemo(() => Array.from(new Set(findings.map((f) => f.tool))).sort(), [findings])

  const grouped = useMemo(() => {
    const q = search.trim().toLowerCase()
    const m: Record<string, VulnFinding[]> = {}
    const visible = findings.filter((f) => {
      const st = f.status ?? 'open'
      if (hideResolved && (st === 'false_positive' || st === 'fixed')) return false
      if (toolFilter && f.tool !== toolFilter) return false
      if (confirmedOnly && !f.confirmed && !f.is_kev) return false
      if (q && !(`${f.name} ${f.host} ${f.matched_at ?? ''} ${f.cve_id ?? ''} ${f.template_id ?? ''} ${f.tags ?? ''}`.toLowerCase().includes(q))) return false
      return true
    })
    for (const f of visible) (m[f.severity] ??= []).push(f)
    // Within a severity, surface by triage priority (KEV/EPSS/verified) first.
    for (const k of Object.keys(m)) m[k].sort((a, b) => priorityScore(b) - priorityScore(a))
    return m
  }, [findings, hideResolved, search, toolFilter, confirmedOnly])

  const visibleCount = useMemo(() => Object.values(grouped).reduce((n, arr) => n + arr.length, 0), [grouped])

  return (
    <div className="space-y-3">
      <div className="card p-3 flex items-center gap-3">
        <StatusDot status={scan?.status ?? 'pending'} />
        <div className="flex-1 min-w-0">
          <div className="text-sm font-semibold truncate">{scan?.name ?? '…'}</div>
          <div className="text-[11px] text-gray-500 flex items-center gap-2">
            <span>{scan?.status}</span>
            {scan?.proxy_mode && <><span>·</span><Radio className="h-3 w-3" /><span>{scan.proxy_mode}</span></>}
            <span>·</span><span>{scan?.target_count} assets</span>
          </div>
        </div>
        {isAdmin && scan?.status === 'running' && (
          <button className="btn-secondary text-xs" onClick={() => stop.mutate()}><Square className="h-3.5 w-3.5" /> Stop</button>
        )}
        {isAdmin && scan?.status !== 'running' && (
          <button className="btn-secondary text-xs text-red-400" onClick={() => remove.mutate()}><Trash2 className="h-3.5 w-3.5" /> Delete</button>
        )}
      </div>

      {scan?.tool_runs && scan.tool_runs.length > 0 && (
        <div className="flex flex-wrap gap-2">
          {scan.tool_runs.map((t) => {
            const dur = t.started_at && t.finished_at
              ? Math.max(0, Math.round((new Date(t.finished_at).getTime() - new Date(t.started_at).getTime()) / 1000))
              : null
            const toolCls =
              t.status === 'done' ? 'border-slate-700 text-gray-400'
              : t.status === 'running' ? 'border-emerald-600/40 text-emerald-300'
              : t.status === 'skipped' ? 'border-slate-800 text-gray-600'
              : t.status === 'failed' ? 'border-red-600/40 text-red-300'
              : 'border-slate-700 text-gray-400'
            return (
              <span key={t.id} className={`text-[11px] px-2 py-1 rounded border flex items-center gap-1.5 ${toolCls}`} title={t.error || ''}>
                <Server className="h-3 w-3" /> {t.name}: {t.status}{t.status === 'done' ? ` (${t.findings_count})` : ''}
                {dur !== null && <span className="text-gray-600">· {dur}s</span>}
                {t.error ? <span className="text-red-400 truncate max-w-[160px]">— {t.error}</span> : null}
              </span>
            )
          })}
        </div>
      )}

      {/* Live log */}
      <div className="card p-0 overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 text-xs text-gray-400">
          <Terminal className="h-3.5 w-3.5" /> Live output
          {live && <span className="text-emerald-400" title="streaming">●</span>}
          <span className="text-gray-600">{log.length} line{log.length === 1 ? '' : 's'}</span>
          <div className="ml-auto flex items-center gap-2">
            <button
              className={`inline-flex items-center gap-1 hover:text-gray-200 ${autoScroll ? 'text-emerald-400' : 'text-gray-500'}`}
              onClick={() => setAutoScroll((v) => !v)}
              title="Toggle auto-scroll"
            >
              <ArrowDownToLine className="h-3.5 w-3.5" /> auto
            </button>
            <button
              className="inline-flex items-center gap-1 hover:text-gray-200 text-gray-500"
              onClick={() => { navigator.clipboard?.writeText(log.join('\n')); toast.success('Log copied') }}
              title="Copy the whole log"
            >
              <Copy className="h-3.5 w-3.5" /> copy
            </button>
          </div>
        </div>
        <div className="bg-black/40 p-3 font-mono text-[11px] leading-relaxed max-h-[28rem] min-h-[10rem] overflow-auto resize-y">
          {log.length === 0 ? <span className="text-gray-600">No output{scan?.status === 'running' ? ' yet…' : ''}</span> :
            log.map((l, i) => <div key={i} className={`whitespace-pre-wrap break-all ${logLineClass(l)}`}>{l}</div>)}
          <div ref={logEndRef} />
        </div>
      </div>

      {/* Findings */}
      <div className="space-y-3">
        {findings.length > 0 && (
          <div className="flex items-center gap-2 flex-wrap">
            <div className="relative flex-1 min-w-[140px]">
              <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-600" />
              <input
                className="input text-[11px] h-7 w-full pl-7"
                placeholder="Search name / host / CVE / tag…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
            <select className="input text-[11px] h-7" value={toolFilter} onChange={(e) => setToolFilter(e.target.value)} title="Filter by tool">
              <option value="">all tools</option>
              {toolsPresent.map((t) => <option key={t} value={t}>{t}</option>)}
            </select>
            <label className="flex items-center gap-1 text-[11px] text-gray-500" title="Only KEV or independently-verified findings">
              <input type="checkbox" checked={confirmedOnly} onChange={(e) => setConfirmedOnly(e.target.checked)} /> verified/KEV
            </label>
            <label className="flex items-center gap-1 text-[11px] text-gray-500">
              <input type="checkbox" checked={hideResolved} onChange={(e) => setHideResolved(e.target.checked)} /> hide resolved
            </label>
            <a
              className="btn-secondary text-[11px] py-0.5 inline-flex items-center gap-1"
              href={vulnscanApi.exportUrl(scanId, { tool: toolFilter || undefined })}
              title="Export findings as CSV"
            >
              <Download className="h-3.5 w-3.5" /> CSV
            </a>
            <span className="text-[11px] text-gray-600 w-full sm:w-auto">{visibleCount}/{findings.length} shown</span>
          </div>
        )}
        {findings.length === 0 ? (
          <div className="card text-center py-8 text-sm text-gray-500">No findings yet</div>
        ) : (
          SEVERITY_ORDER.filter((s) => grouped[s]?.length).map((s) => (
            <div key={s} className="space-y-1.5">
              <div className={`inline-block text-[11px] px-2 py-0.5 rounded border ${SEVERITY_COLOR[s] ?? SEVERITY_COLOR.unknown}`}>
                {s.toUpperCase()} · {grouped[s].length}
              </div>
              {grouped[s].map((f) => <FindingCard key={f.id} f={f} scanId={scanId} />)}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
