import { useEffect, useMemo, useRef, useState } from 'react'
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import {
  ShieldAlert, Loader2, Play, Square, Trash2, ChevronRight, AlertTriangle,
  Radio, Server, Terminal,
} from 'lucide-react'

import {
  vulnscanApi, type VulnScan, type VulnFinding, SEVERITY_ORDER, SEVERITY_COLOR,
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

// VulnScanPanel is rendered as a tab inside the OSINT page (mirrors OobPanel /
// CanaryPanel). It runs httpx+nuclei over assets discovered by OSINT.
export function VulnScanPanel() {
  const qc = useQueryClient()
  const isAdmin = useAuthStore((s) => s.user?.role) === 'admin'
  const [selected, setSelected] = useState<string | null>(null)

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['vulnscans'],
    queryFn: () => vulnscanApi.list(),
    refetchInterval: (q) => {
      const data = q.state.data as VulnScan[] | undefined
      return data?.some((s) => s.status === 'running' || s.status === 'pending') ? 5000 : 0
    },
  })

  return (
    <div className="space-y-4">
      <div className="flex items-start gap-3 rounded-lg border border-amber-600/30 bg-amber-500/5 p-3 text-xs text-amber-300">
        <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
        <div>
          <b>Active vulnerability scanning.</b> httpx + nuclei probe the selected assets directly.
          Only scan systems you are authorised to test. Traffic is routed through the configured
          egress proxy/Tor; private/internal addresses are filtered out automatically.
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[340px_1fr] gap-4">
        <div className="space-y-3">
          {isAdmin && <NewScanForm onCreated={(id) => { setSelected(id); qc.invalidateQueries({ queryKey: ['vulnscans'] }) }} />}
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
  const [profile, setProfile] = useState<'quick' | 'full' | 'cve-only'>('quick')
  const [direct, setDirect] = useState(false)

  const { data: assets = [], isLoading } = useQuery({
    queryKey: ['vuln-preview', osintScanId],
    queryFn: () => vulnscanApi.previewAssets(osintScanId),
  })
  useEffect(() => { setSel(new Set(assets.map((a) => a.value))) }, [assets])

  const domains = useMemo(() => assets.filter((a) => a.type === 'domain').map((a) => a.value).sort(), [assets])
  const ips = useMemo(() => assets.filter((a) => a.type === 'ip').map((a) => a.value).sort(), [assets])

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
          vals.map((v) => (
            <label key={v} className="flex items-center gap-2 px-1 py-0.5 rounded hover:bg-slate-800/50 cursor-pointer">
              <input type="checkbox" checked={sel.has(v)} onChange={() => toggle(v)} />
              <span className="text-xs font-mono truncate">{v}</span>
            </label>
          ))}
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
              <option value="full">Full</option>
              <option value="cve-only">CVE only</option>
            </select>
          </div>
          <label className="flex items-center gap-1.5 text-[11px] text-gray-400">
            <input type="checkbox" checked={direct} onChange={(e) => setDirect(e.target.checked)} /> Direct (no Tor)
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
  const [profile, setProfile] = useState<'quick' | 'full' | 'cve-only'>('quick')
  const [tags, setTags] = useState('')
  const [direct, setDirect] = useState(false)

  const create = useMutation({
    mutationFn: () =>
      vulnscanApi.create({
        name: name.trim() || undefined,
        targets: targets.split(/[\s,]+/).map((t) => t.trim()).filter(Boolean),
        severities: Array.from(sev).join(','),
        profile,
        tags: tags.trim() || undefined,
        proxy_choice: direct ? 'direct' : 'tor',
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
          <option value="full">Full (all templates + port scan)</option>
          <option value="cve-only">CVE only</option>
        </select>
      </div>
      <input className="input w-full text-sm" placeholder="Extra nuclei tags (optional, CSV)" value={tags} onChange={(e) => setTags(e.target.value)} />
      <label className="flex items-center gap-2 text-[11px] text-gray-400">
        <input type="checkbox" checked={direct} onChange={(e) => setDirect(e.target.checked)} />
        Egress direct (no Tor) — faster but reveals this host's IP
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
      setLog((prev) => [...prev.slice(-500), ev.data])
    }
    es.onerror = () => { setLive(false); es.close() }
    return () => es.close()
  }, [scanId, qc])

  useEffect(() => { logEndRef.current?.scrollIntoView({ block: 'end' }) }, [log])

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

  const grouped = useMemo(() => {
    const m: Record<string, VulnFinding[]> = {}
    for (const f of findings) (m[f.severity] ??= []).push(f)
    // Within a severity, surface known-exploited (KEV) then higher-EPSS first.
    for (const k of Object.keys(m)) {
      m[k].sort((a, b) =>
        Number(b.is_kev ?? false) - Number(a.is_kev ?? false) ||
        (b.epss_score ?? 0) - (a.epss_score ?? 0))
    }
    return m
  }, [findings])

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
          {scan.tool_runs.map((t) => (
            <span key={t.id} className="text-[11px] px-2 py-1 rounded border border-slate-700 text-gray-400 flex items-center gap-1.5">
              <Server className="h-3 w-3" /> {t.name}: {t.status}{t.status === 'done' ? ` (${t.findings_count})` : ''}
              {t.error ? <span className="text-red-400">— {t.error}</span> : null}
            </span>
          ))}
        </div>
      )}

      {/* Live log */}
      <div className="card p-0 overflow-hidden">
        <div className="flex items-center gap-2 px-3 py-2 border-b border-slate-800 text-xs text-gray-400">
          <Terminal className="h-3.5 w-3.5" /> Live output {live && <span className="text-emerald-400">●</span>}
        </div>
        <div className="bg-black/40 p-3 font-mono text-[11px] leading-relaxed max-h-56 overflow-auto">
          {log.length === 0 ? <span className="text-gray-600">No output{scan?.status === 'running' ? ' yet…' : ''}</span> :
            log.map((l, i) => <div key={i} className="whitespace-pre-wrap text-gray-300">{l}</div>)}
          <div ref={logEndRef} />
        </div>
      </div>

      {/* Findings */}
      <div className="space-y-3">
        {findings.length === 0 ? (
          <div className="card text-center py-8 text-sm text-gray-500">No findings yet</div>
        ) : (
          SEVERITY_ORDER.filter((s) => grouped[s]?.length).map((s) => (
            <div key={s} className="space-y-1.5">
              <div className={`inline-block text-[11px] px-2 py-0.5 rounded border ${SEVERITY_COLOR[s] ?? SEVERITY_COLOR.unknown}`}>
                {s.toUpperCase()} · {grouped[s].length}
              </div>
              {grouped[s].map((f) => (
                <div key={f.id} className="card p-3">
                  <div className="flex items-start gap-2 flex-wrap">
                    <span className="text-sm font-medium flex-1">{f.name}</span>
                    {f.is_kev && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded border border-red-500/40 bg-red-500/15 text-red-300 font-semibold" title="Listed in CISA Known-Exploited Vulnerabilities — actively exploited in the wild">
                        ⚠ KEV
                      </span>
                    )}
                    {typeof f.epss_score === 'number' && f.epss_score > 0 && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded border border-amber-500/30 bg-amber-500/10 text-amber-300" title="EPSS — probability of exploitation in the next 30 days">
                        EPSS {(f.epss_score * 100).toFixed(0)}%
                      </span>
                    )}
                    {f.cve_id && <span className="text-[10px] text-sky-400 font-mono">{f.cve_id}</span>}
                    {f.template_id && !f.cve_id && <span className="text-[10px] text-gray-500 font-mono">{f.template_id}</span>}
                  </div>
                  <div className="mt-1 text-[11px] text-emerald-400/80 font-mono break-all">{f.matched_at || f.host}</div>
                  {f.description && <div className="mt-1 text-[11px] text-gray-500 line-clamp-2">{f.description}</div>}
                </div>
              ))}
            </div>
          ))
        )}
      </div>
    </div>
  )
}
