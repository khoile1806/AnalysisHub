import { useState, useMemo } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { ReactFlow, Background, Controls, MiniMap, MarkerType, type Node, type Edge } from '@xyflow/react'
import '@xyflow/react/dist/style.css'
import { ResponsiveContainer, AreaChart, Area, XAxis, YAxis, Tooltip, CartesianGrid } from 'recharts'
import {
  Upload, Loader2, Trash2, Network, ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle,
  Globe, Boxes, Radar, FileWarning, Loader, Brain, Sparkles, Activity, ArrowUpDown, Layers,
  Eye, Download, Bug, X, FileText, MessagesSquare, FileDown, Clock,
} from 'lucide-react'
import {
  networkApi, nsafeParse,
  type NetworkScan, type NetChainStep, type NetworkResult, type NetworkFinding, type NetVerdict,
  type NetDNS, type CarvedPreview,
} from '@/api/network'
import { analysisApi } from '@/api/analysis'
import AiMarkdown from '@/components/AiMarkdown'
import { getErrorMessage } from '@/lib/utils'

// impactCls colours a score-card signal row by its direction.
function impactCls(impact: string): string {
  if (impact === 'malicious') return 'border-red-500/50 text-red-300 bg-red-500/10'
  if (impact === 'suspicious') return 'border-amber-500/50 text-amber-300 bg-amber-500/10'
  if (impact === 'benign') return 'border-emerald-500/50 text-emerald-300 bg-emerald-500/10'
  return 'border-slate-700 text-gray-400'
}

function verdictMeta(v: string): { label: string; cls: string; Icon: typeof ShieldAlert } {
  switch (v) {
    case 'malicious': return { label: 'Malicious', cls: 'border-red-500/50 text-red-300 bg-red-500/10', Icon: ShieldAlert }
    case 'suspicious': return { label: 'Suspicious', cls: 'border-amber-500/50 text-amber-300 bg-amber-500/10', Icon: AlertTriangle }
    case 'benign': return { label: 'Benign', cls: 'border-emerald-500/50 text-emerald-300 bg-emerald-500/10', Icon: ShieldCheck }
    default: return { label: 'Unknown', cls: 'border-slate-600 text-gray-400 bg-slate-800/40', Icon: ShieldQuestion }
  }
}
const sevCls: Record<string, string> = {
  critical: 'border-red-500/50 text-red-300 bg-red-500/10',
  high: 'border-red-500/40 text-red-300 bg-red-500/5',
  medium: 'border-amber-500/40 text-amber-300 bg-amber-500/5',
  low: 'border-slate-600 text-gray-400',
  info: 'border-slate-700 text-gray-500',
}
const fmtBytes = (n: number) => n >= 1e6 ? (n / 1e6).toFixed(1) + 'M' : n >= 1e3 ? (n / 1e3).toFixed(1) + 'K' : String(n)
const fmtBytesFull = (n: number) => n >= 1e9 ? (n / 1e9).toFixed(2) + ' GB' : n >= 1e6 ? (n / 1e6).toFixed(2) + ' MB' : n >= 1e3 ? (n / 1e3).toFixed(1) + ' KB' : n + ' B'

// isPrivateIP classifies an address as internal (RFC1918 / loopback / link-local).
function isPrivateIP(ip: string): boolean {
  if (!ip) return false
  if (ip.startsWith('10.') || ip.startsWith('192.168.') || ip.startsWith('127.') || ip.startsWith('169.254.') ||
    ip === '::1' || ip.startsWith('fe80:') || ip.startsWith('fc') || ip.startsWith('fd')) return true
  if (ip.startsWith('172.')) { const o = parseInt(ip.split('.')[1] || '', 10); return o >= 16 && o <= 31 }
  return false
}
// parseTs parses a Suricata timestamp (…+0000) into epoch ms, or null.
function parseTs(s?: string): number | null {
  if (!s) return null
  const t = Date.parse(s.replace(/([+-]\d{2})(\d{2})$/, '$1:$2'))
  return isNaN(t) ? null : t
}
// ipDomainMap builds a reverse map (resolved IP → the domain that resolved to it).
function ipDomainMap(dns?: NetDNS[]): Record<string, string> {
  const m: Record<string, string> = {}
  for (const d of dns ?? []) for (const a of d.answers ?? []) if (!m[a]) m[a] = d.query
  return m
}
const fmtDuration = (sec: number) => sec <= 0 ? '—' : sec < 60 ? sec.toFixed(1) + 's' : sec < 3600 ? Math.floor(sec / 60) + 'm ' + Math.round(sec % 60) + 's' : (sec / 3600).toFixed(1) + 'h'
// ccFlag turns a 2-letter country code into its flag emoji (regional indicators).
function ccFlag(cc?: string): string {
  if (!cc || cc.length !== 2 || !/^[A-Za-z]{2}$/.test(cc)) return ''
  return String.fromCodePoint(...[...cc.toUpperCase()].map((c) => 0x1f1e6 + c.charCodeAt(0) - 65))
}
function geoLabel(g?: { asn: string; cc: string; org: string }): string {
  if (!g) return ''
  const parts = []
  if (g.cc) parts.push(`${ccFlag(g.cc)} ${g.cc}`)
  if (g.asn && g.asn !== '0') parts.push(`AS${g.asn}`)
  if (g.org) parts.push(g.org.length > 24 ? g.org.slice(0, 24) + '…' : g.org)
  return parts.join(' · ')
}

function Card({ title, icon: Icon, right, children }: { title: string; icon: typeof Network; right?: React.ReactNode; children: React.ReactNode }) {
  return (
    <div className="rounded-lg border border-slate-800 bg-gray-900/40">
      <div className="px-3 py-2 border-b border-slate-800 flex items-center gap-2">
        <Icon className="h-4 w-4 text-emerald-400" />
        <span className="text-sm font-semibold text-gray-200">{title}</span>
        {right && <span className="ml-auto">{right}</span>}
      </div>
      <div className="p-3 space-y-2">{children}</div>
    </div>
  )
}

const PROTO_COLORS = ['#34d399', '#60a5fa', '#f59e0b', '#a78bfa', '#f472b6', '#22d3ee', '#fb7185', '#94a3b8']
function LegendDot({ c, label }: { c: string; label: string }) {
  return <span className="flex items-center gap-1"><span className="h-2 w-2 rounded-full" style={{ background: c }} />{label}</span>
}

// StatsOverview shows the capture at a glance: metric tiles + protocol mix.
function StatsOverview({ result }: { result: NetworkResult }) {
  const s = result.stats || {}
  const dur = useMemo(() => {
    let mn = Infinity, mx = -Infinity
    for (const f of result.flows ?? []) {
      const a = parseTs(f.start); const b = parseTs(f.end) ?? a
      if (a != null) { mn = Math.min(mn, a); if (b != null) mx = Math.max(mx, b) }
    }
    return mx > mn ? (mx - mn) / 1000 : 0
  }, [result.flows])
  const proto = useMemo(() => {
    const m: Record<string, number> = {}
    for (const f of result.flows ?? []) { const k = (f.app || f.proto || 'other').toLowerCase(); m[k] = (m[k] || 0) + f.bytes }
    return Object.entries(m).map(([name, bytes]) => ({ name, bytes })).sort((a, b) => b.bytes - a.bytes).slice(0, 8)
  }, [result.flows])
  const totalProto = proto.reduce((a, b) => a + b.bytes, 0) || 1
  const tiles = [
    { label: 'Packets', v: (s.packets ?? 0).toLocaleString() },
    { label: 'Bytes', v: fmtBytesFull(s.bytes ?? 0) },
    { label: 'Flows', v: (s.flows ?? 0).toLocaleString() },
    { label: 'Duration', v: fmtDuration(dur) },
    { label: 'DNS', v: result.dns?.length ?? 0 },
    { label: 'TLS', v: result.tls?.length ?? 0 },
    { label: 'HTTP', v: result.http?.length ?? 0 },
    { label: 'Files', v: result.files?.length ?? 0 },
  ]
  return (
    <Card title="Capture overview" icon={Activity}>
      <div className="grid grid-cols-4 gap-2">
        {tiles.map((t) => (
          <div key={t.label} className="rounded-md bg-slate-800/40 border border-slate-800 p-2">
            <div className="text-[10px] text-gray-500">{t.label}</div>
            <div className="text-sm font-semibold text-gray-100">{t.v}</div>
          </div>
        ))}
      </div>
      {proto.length > 0 && (
        <div className="mt-3">
          <div className="text-[10px] text-gray-500 mb-1">Protocol distribution (by bytes)</div>
          <div className="flex h-3 rounded overflow-hidden border border-slate-800">
            {proto.map((p, i) => <div key={p.name} title={`${p.name} ${fmtBytesFull(p.bytes)}`} style={{ width: `${(p.bytes / totalProto) * 100}%`, background: PROTO_COLORS[i % PROTO_COLORS.length] }} />)}
          </div>
          <div className="flex flex-wrap gap-x-3 gap-y-0.5 mt-1">
            {proto.map((p, i) => <span key={p.name} className="text-[9px] text-gray-400 flex items-center gap-1"><span className="h-2 w-2 rounded-sm" style={{ background: PROTO_COLORS[i % PROTO_COLORS.length] }} />{p.name} {((p.bytes / totalProto) * 100).toFixed(0)}%</span>)}
          </div>
        </div>
      )}
    </Card>
  )
}

// TopTalkers ranks destination endpoints by bytes, split by direction.
function TopTalkers({ result }: { result: NetworkResult }) {
  const dom = useMemo(() => ipDomainMap(result.dns), [result.dns])
  const rows = useMemo(() => {
    const m: Record<string, { bytes: number; out: number; in: number; flows: number; ports: Set<string> }> = {}
    for (const f of result.flows ?? []) {
      if (!f.dst) continue
      const r = m[f.dst] || (m[f.dst] = { bytes: 0, out: 0, in: 0, flows: 0, ports: new Set() })
      r.bytes += f.bytes; r.out += f.to_server || 0; r.in += f.to_client || 0; r.flows++
      if (f.dport) r.ports.add(String(f.dport))
    }
    return Object.entries(m).map(([dst, r]) => ({ dst, ...r, ports: [...r.ports].slice(0, 6), internal: isPrivateIP(dst), domain: dom[dst], geo: result.geo?.[dst] }))
      .sort((a, b) => b.bytes - a.bytes).slice(0, 15)
  }, [result.flows, result.geo, dom])
  const hasGeo = rows.some((r) => r.geo)
  if (rows.length === 0) return null
  return (
    <Card title="Top talkers" icon={ArrowUpDown} right={<span className="text-[10px] text-gray-500">by bytes</span>}>
      <div className="overflow-x-auto"><table className="w-full text-[10px]">
        <thead><tr className="text-gray-500 text-left"><th className="pr-2">Destination</th>{hasGeo && <th className="pr-2">Geo / ASN</th>}<th className="pr-2">Bytes</th><th className="pr-2">↑ out</th><th className="pr-2">↓ in</th><th className="pr-2">Flows</th><th className="pr-2">Ports</th></tr></thead>
        <tbody>{rows.map((r, i) => (
          <tr key={i} className="border-t border-slate-800/50">
            <td className="pr-2"><span className={`font-mono ${r.internal ? 'text-sky-300' : 'text-gray-200'}`}>{r.dst}</span>{r.domain && <span className="text-emerald-500 ml-1 break-all">{r.domain}</span>}</td>
            {hasGeo && <td className="pr-2 text-gray-400">{geoLabel(r.geo) || '—'}</td>}
            <td className="pr-2 text-gray-300">{fmtBytesFull(r.bytes)}</td>
            <td className="pr-2 text-amber-300/80">{fmtBytes(r.out)}</td>
            <td className="pr-2 text-sky-300/80">{fmtBytes(r.in)}</td>
            <td className="pr-2 text-gray-400">{r.flows}</td>
            <td className="pr-2 font-mono text-gray-500">{r.ports.join(',')}</td>
          </tr>
        ))}</tbody>
      </table></div>
    </Card>
  )
}

// ZeekPanel surfaces the deep Zeek logs: notices, file provenance (which file
// went between which two hosts, over which protocol), TLS validation, and
// lateral-movement / auth events (SMB / Kerberos / NTLM / SSH).
function ZeekPanel({ result }: { result: NetworkResult }) {
  const z = result.zeek
  if (!z || (!z.notices?.length && !z.files?.length && !z.ssl?.some((s) => s.validation && s.validation !== 'ok') && !z.kerberos?.length && !z.ntlm?.length && !z.smb?.length && !z.ssh?.length)) return null
  const auth = [
    ...(z.kerberos ?? []).map((k) => ({ proto: 'Kerberos', who: k.client, extra: k.service, ok: k.success, src: k.src, dst: k.dst })),
    ...(z.ntlm ?? []).map((n) => ({ proto: 'NTLM', who: `${n.domain}\\${n.user}`, extra: n.host, ok: null as boolean | null, src: n.src, dst: n.dst })),
    ...(z.smb ?? []).map((s) => ({ proto: 'SMB', who: s.name || s.path, extra: s.action, ok: null as boolean | null, src: s.src, dst: s.dst })),
    ...(z.ssh ?? []).map((s) => ({ proto: 'SSH', who: s.client, extra: s.server, ok: s.success, src: s.src, dst: s.dst })),
  ].slice(0, 60)
  return (
    <Card title="Zeek deep analysis" icon={Radar} right={<span className="text-[10px] text-gray-500">protocol logs</span>}>
      {!!z.notices?.length && (
        <div>
          <div className="label text-[10px] mb-0.5">Notices ({z.notices.length})</div>
          <div className="space-y-0.5 max-h-40 overflow-y-auto">{z.notices.slice(0, 60).map((n, i) => (
            <div key={i} className="text-[10px] flex items-start gap-2"><span className="text-amber-300 font-mono shrink-0">{n.note}</span><span className="text-gray-400 break-all">{n.msg}</span></div>
          ))}</div>
        </div>
      )}
      {!!z.files?.length && (
        <div className="mt-2">
          <div className="label text-[10px] mb-0.5">File transfers — provenance ({z.files.length})</div>
          <div className="overflow-x-auto max-h-48 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2">From → To</th><th className="pr-2">Proto</th><th className="pr-2">MIME</th><th className="pr-2">Bytes</th><th className="pr-2">SHA256</th></tr></thead>
            <tbody>{z.files.slice(0, 150).map((f, i) => (
              <tr key={i} className="border-t border-slate-800/50">
                <td className="pr-2 font-mono text-gray-300">{f.tx || '?'} <span className="text-gray-600">→</span> {f.rx || '?'}</td>
                <td className="pr-2 text-gray-400">{f.source || '—'}</td>
                <td className="pr-2 text-gray-400 break-all">{f.mime || '—'}</td>
                <td className="pr-2 text-gray-400">{fmtBytesFull(f.bytes)}</td>
                <td className="pr-2 font-mono text-gray-600 break-all">{f.sha256 ? f.sha256.slice(0, 16) + '…' : '—'}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      )}
      {auth.length > 0 && (
        <div className="mt-2">
          <div className="label text-[10px] mb-0.5">Authentication / lateral movement ({auth.length})</div>
          <div className="overflow-x-auto max-h-40 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2">Proto</th><th className="pr-2">Identity</th><th className="pr-2">Target</th><th className="pr-2">Src → Dst</th></tr></thead>
            <tbody>{auth.map((a, i) => (
              <tr key={i} className="border-t border-slate-800/50">
                <td className="pr-2 text-violet-300">{a.proto}</td>
                <td className="pr-2 text-gray-300 break-all">{a.who}{a.ok === false && <span className="ml-1 text-red-400">✗</span>}{a.ok === true && <span className="ml-1 text-emerald-400">✓</span>}</td>
                <td className="pr-2 text-gray-400 break-all">{a.extra}</td>
                <td className="pr-2 font-mono text-gray-500">{a.src} → {a.dst}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </div>
      )}
    </Card>
  )
}

// TimelineCard shows traffic volume over the capture (area chart) plus a Gantt of
// when each conversation was active — bursts and beaconing become visible.
function TimelineCard({ result }: { result: NetworkResult }) {
  const tl = result.timeline
  if (!tl || !tl.buckets?.length) return null
  const data = tl.buckets.map((b) => ({ t: b.t, bytes: b.bytes, flows: b.flows }))
  const startMs = Date.parse(tl.start_ts.replace(' ', 'T') + 'Z')
  const totalMs = (tl.duration_sec || 1) * 1000
  const convs = (result.conversations ?? []).slice(0, 20)
  return (
    <Card title="Traffic timeline" icon={Clock} right={<span className="text-[10px] text-gray-500">{tl.start_ts} · {fmtDuration(tl.duration_sec)}</span>}>
      <div style={{ height: 170 }}>
        <ResponsiveContainer width="100%" height="100%">
          <AreaChart data={data} margin={{ top: 5, right: 8, bottom: 0, left: 0 }}>
            <CartesianGrid stroke="#1e293b" strokeDasharray="3 3" />
            <XAxis dataKey="t" tick={{ fontSize: 9, fill: '#64748b' }} tickFormatter={(v) => '+' + v + 's'} />
            <YAxis tick={{ fontSize: 9, fill: '#64748b' }} tickFormatter={(v) => fmtBytes(v)} width={46} />
            <Tooltip contentStyle={{ background: '#0b0f17', border: '1px solid #334155', fontSize: 11 }} labelFormatter={(v) => '+' + v + 's from start'} formatter={(v: any, n: any) => [n === 'bytes' ? fmtBytesFull(Number(v)) : v, n]} />
            <Area type="monotone" dataKey="bytes" stroke="#34d399" fill="#34d39933" />
          </AreaChart>
        </ResponsiveContainer>
      </div>
      {convs.length > 0 && !isNaN(startMs) && (
        <div className="mt-2">
          <div className="text-[10px] text-gray-500 mb-1">Conversation activity</div>
          <div className="space-y-0.5">
            {convs.map((c, i) => {
              const s = c.first_seen ? Date.parse(c.first_seen.replace(' ', 'T') + 'Z') : startMs
              const e = c.last_seen ? Date.parse(c.last_seen.replace(' ', 'T') + 'Z') : s
              const left = Math.min(99, Math.max(0, ((s - startMs) / totalMs) * 100))
              const width = Math.min(100 - left, Math.max(1.5, ((e - s) / totalMs) * 100))
              return (
                <div key={i} className="flex items-center gap-2 text-[9px]">
                  <span className="w-36 shrink-0 truncate font-mono text-gray-400" title={`${c.a} → ${c.b}`}>{c.a}→{c.b}</span>
                  <div className="flex-1 h-2 rounded bg-slate-800/70 relative">
                    <div className="absolute h-2 rounded bg-sky-500/70" style={{ left: left + '%', width: width + '%' }} title={`${c.first_seen || ''} → ${c.last_seen || ''}`} />
                  </div>
                </div>
              )
            })}
          </div>
        </div>
      )}
    </Card>
  )
}

// ConversationsCard shows the host-to-host aggregation: who initiated contact
// with whom, how many times, how much data, over what protocols, and when.
function ConversationsCard({ result }: { result: NetworkResult }) {
  const rows = result.conversations ?? []
  if (rows.length === 0) return null
  return (
    <Card title="Conversations" icon={MessagesSquare} right={<span className="text-[10px] text-gray-500">who talked to whom</span>}>
      <div className="overflow-x-auto max-h-64 overflow-y-auto"><table className="w-full text-[10px]">
        <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2 py-1">Initiator → Responder</th><th className="pr-2">Geo / ASN</th><th className="pr-2">Times</th><th className="pr-2">Bytes</th><th className="pr-2">Protocols</th><th className="pr-2">First → Last (UTC)</th></tr></thead>
        <tbody>{rows.slice(0, 40).map((c, i) => (
          <tr key={i} className="border-t border-slate-800/50">
            <td className="pr-2 font-mono whitespace-nowrap"><span className={c.a_internal ? 'text-sky-300' : 'text-gray-200'}>{c.a}</span> <span className="text-gray-600">→</span> <span className="text-gray-200">{c.b}</span></td>
            <td className="pr-2 text-gray-400">{geoLabel(result.geo?.[c.b]) || '—'}</td>
            <td className="pr-2 text-gray-400">{c.count}</td>
            <td className="pr-2 text-gray-300">{fmtBytesFull(c.bytes)}</td>
            <td className="pr-2 text-gray-400">{(c.protos ?? []).join(', ') || '—'}</td>
            <td className="pr-2 text-gray-500 whitespace-nowrap">{c.first_seen ? `${c.first_seen} → ${c.last_seen}` : '—'}</td>
          </tr>
        ))}</tbody>
      </table></div>
    </Card>
  )
}

// ProtocolTree renders the tshark protocol hierarchy (indented by level, bar by bytes).
function ProtocolTree({ result }: { result: NetworkResult }) {
  const rows = result.protocols ?? []
  if (rows.length === 0) return null
  const max = Math.max(1, ...rows.map((r) => r.bytes))
  return (
    <Card title="Protocol hierarchy" icon={Layers} right={<span className="text-[10px] text-gray-500">tshark</span>}>
      <div className="space-y-0.5">
        {rows.map((r, i) => (
          <div key={i} className="flex items-center gap-2 text-[10px]">
            <span className="text-gray-300 font-mono" style={{ paddingLeft: r.level * 12 }}>{r.name}</span>
            <span className="flex-1 h-1.5 rounded bg-slate-800 overflow-hidden"><span className="block h-full bg-emerald-500/60" style={{ width: `${(r.bytes / max) * 100}%` }} /></span>
            <span className="text-gray-500 w-16 text-right">{fmtBytesFull(r.bytes)}</span>
            <span className="text-gray-600 w-14 text-right">{r.frames.toLocaleString()} pkt</span>
          </div>
        ))}
      </div>
    </Card>
  )
}

// FlowGraph — a host-communication graph: internal vs external hosts, node size
// by traffic volume, malicious endpoints highlighted, directional arrows,
// click-to-inspect a host, and filters. Manual bipartite layout (internal on the
// left, external on the right sorted by bytes).
function FlowGraph({ result, findings }: { result: NetworkResult; findings: NetworkFinding[] }) {
  const [onlyMal, setOnlyMal] = useState(false)
  const [hideSmall, setHideSmall] = useState(false)
  const [sel, setSel] = useState<string | null>(null)
  const dom = useMemo(() => ipDomainMap(result.dns), [result.dns])
  const mal = useMemo(() => new Set(findings.filter((f) => f.indicator).map((f) => f.indicator as string)), [findings])

  const { nodes, edges, hidden } = useMemo(() => {
    const g = result.graph ?? { nodes: [], edges: [] }
    const bytesByNode: Record<string, number> = {}
    for (const e of g.edges) { bytesByNode[e.src] = (bytesByNode[e.src] || 0) + e.bytes; bytesByNode[e.dst] = (bytesByNode[e.dst] || 0) + e.bytes }
    let ids = g.nodes.map((n) => n.id)
    let edgeList = g.edges
    if (onlyMal) {
      edgeList = edgeList.filter((e) => mal.has(e.dst) || mal.has(e.src))
      const keep = new Set<string>(); edgeList.forEach((e) => { keep.add(e.src); keep.add(e.dst) })
      ids = ids.filter((id) => keep.has(id))
    }
    if (hideSmall) ids = ids.filter((id) => (bytesByNode[id] || 0) >= 1024 || mal.has(id))
    const total = ids.length
    ids = ids.slice(0, 140)
    const idset = new Set(ids)
    const internal = ids.filter(isPrivateIP)
    const external = ids.filter((id) => !isPrivateIP(id)).sort((a, b) => (bytesByNode[b] || 0) - (bytesByNode[a] || 0))
    const maxBytes = Math.max(1, ...ids.map((id) => bytesByNode[id] || 0))
    const nodeW = (id: string) => 118 + Math.round(70 * (Math.log10((bytesByNode[id] || 0) + 1) / Math.log10(maxBytes + 1)))
    const mkNode = (id: string, x: number, y: number): Node => {
      const internalNode = isPrivateIP(id); const bad = mal.has(id)
      const label = dom[id] && !internalNode ? `${id}\n${dom[id]}` : id
      return {
        id, position: { x, y }, data: { label },
        style: {
          fontSize: 9, padding: 6, borderRadius: 8, width: nodeW(id), textAlign: 'center' as const, whiteSpace: 'pre-line' as const,
          background: bad ? '#450a0a' : internalNode ? '#0c2a45' : '#111827',
          border: `${bad ? 2 : 1}px solid ${bad ? '#ef4444' : internalNode ? '#38bdf8' : '#334155'}`,
          color: bad ? '#fca5a5' : internalNode ? '#7dd3fc' : '#cbd5e1',
          boxShadow: sel === id ? '0 0 0 2px #34d399' : bad ? '0 0 8px rgba(239,68,68,.4)' : 'none',
        },
      }
    }
    const nodes: Node[] = []
    const gapY = 58
    const rightH = Math.min(external.length, 22) * 44
    const centerY = Math.max((internal.length) * gapY, rightH) / 2
    internal.forEach((id, i) => nodes.push(mkNode(id, 40, (i - (internal.length - 1) / 2) * gapY + centerY)))
    external.forEach((id, i) => { const col = Math.floor(i / 22), row = i % 22; nodes.push(mkNode(id, 400 + col * 240, row * 44)) })
    const edges: Edge[] = edgeList.filter((e) => idset.has(e.src) && idset.has(e.dst)).slice(0, 600).map((e, i) => {
      const bad = mal.has(e.dst) || mal.has(e.src)
      const w = 1 + Math.min(5, Math.log10(e.bytes + 1))
      return {
        id: `e${i}`, source: e.src, target: e.dst, animated: bad,
        label: idset.size <= 40 ? `${e.proto} ${fmtBytes(e.bytes)}` : undefined,
        markerEnd: { type: MarkerType.ArrowClosed, color: bad ? '#ef4444' : '#475569', width: 14, height: 14 },
        style: { stroke: bad ? '#ef4444' : '#475569', strokeWidth: bad ? Math.max(2, w) : w },
        labelStyle: { fontSize: 8, fill: '#94a3b8' }, labelBgStyle: { fill: '#0b0f17' },
      }
    })
    return { nodes, edges, hidden: total - ids.length }
  }, [result, mal, dom, onlyMal, hideSmall, sel])

  const selInfo = useMemo(() => {
    if (!sel) return null
    const g = result.graph ?? { nodes: [], edges: [] }
    const ports = new Set<string>(); let bytes = 0, flows = 0; const peers = new Set<string>()
    for (const e of g.edges) { if (e.src === sel || e.dst === sel) { bytes += e.bytes; flows += e.flows; e.ports.forEach((p) => ports.add(p)); peers.add(e.src === sel ? e.dst : e.src) } }
    return { bytes, flows, ports: [...ports].slice(0, 12), peers: peers.size, domain: dom[sel], internal: isPrivateIP(sel), geo: result.geo?.[sel], findings: findings.filter((f) => f.indicator === sel) }
  }, [sel, result, findings, dom])

  if ((result.graph?.nodes?.length ?? 0) === 0) return <p className="text-xs text-gray-500">No host flows to graph.</p>
  return (
    <div className="space-y-2">
      <div className="flex items-center gap-3 text-[11px] text-gray-400 flex-wrap">
        <label className="flex items-center gap-1 cursor-pointer"><input type="checkbox" checked={onlyMal} onChange={(e) => setOnlyMal(e.target.checked)} /> Only malicious paths</label>
        <label className="flex items-center gap-1 cursor-pointer"><input type="checkbox" checked={hideSmall} onChange={(e) => setHideSmall(e.target.checked)} /> Hide &lt;1KB hosts</label>
        <span className="ml-auto flex items-center gap-3"><LegendDot c="#38bdf8" label="internal" /><LegendDot c="#64748b" label="external" /><LegendDot c="#ef4444" label="malicious" /></span>
      </div>
      <div style={{ height: 520 }} className="relative rounded border border-slate-800 bg-[#0b0f17]">
        <ReactFlow nodes={nodes} edges={edges} fitView minZoom={0.05} proOptions={{ hideAttribution: true }} onNodeClick={(_, n) => setSel(n.id)} onPaneClick={() => setSel(null)}>
          <Background color="#1e293b" gap={20} />
          <MiniMap pannable zoomable style={{ background: '#0b0f17' }} nodeColor={(n) => (n.style?.background as string) ?? '#111827'} />
          <Controls />
        </ReactFlow>
        {selInfo && sel && (
          <div className="absolute top-2 right-2 w-64 rounded-lg border border-slate-700 bg-gray-900/95 p-3 text-[11px] shadow-xl">
            <div className="flex items-center gap-1.5 mb-1"><span className={`h-2 w-2 rounded-full ${selInfo.internal ? 'bg-sky-400' : selInfo.findings.length ? 'bg-red-500' : 'bg-slate-500'}`} /><b className="text-gray-100 break-all">{sel}</b></div>
            {selInfo.domain && <div className="text-emerald-400 break-all mb-1">{selInfo.domain}</div>}
            {selInfo.geo && <div className="text-gray-300 mb-1">{geoLabel(selInfo.geo)}</div>}
            <div className="grid grid-cols-2 gap-1 text-gray-400">
              <span>Role <b className="text-gray-200">{selInfo.internal ? 'internal' : 'external'}</b></span>
              <span>Peers <b className="text-gray-200">{selInfo.peers}</b></span>
              <span>Bytes <b className="text-gray-200">{fmtBytesFull(selInfo.bytes)}</b></span>
              <span>Flows <b className="text-gray-200">{selInfo.flows}</b></span>
            </div>
            {selInfo.ports.length > 0 && <div className="mt-1 text-gray-500">Ports: <span className="text-gray-300 font-mono">{selInfo.ports.join(', ')}</span></div>}
            {selInfo.findings.map((f, i) => <div key={i} className="mt-1 text-red-300">⚠ {f.title}</div>)}
          </div>
        )}
        {hidden > 0 && <div className="absolute bottom-2 left-2 text-[10px] text-gray-600">+{hidden} host(s) hidden</div>}
      </div>
    </div>
  )
}

function StepList({ steps }: { steps: NetChainStep[] }) {
  return (
    <div className="space-y-1">
      {steps.map((s) => (
        <div key={s.id} className="flex items-center gap-2 text-[11px]">
          {s.status === 'done' ? <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
            : s.status === 'running' ? <Loader className="h-3.5 w-3.5 text-sky-400 animate-spin" />
            : s.status === 'failed' ? <AlertTriangle className="h-3.5 w-3.5 text-red-400" />
            : <span className="h-3.5 w-3.5 rounded-full border border-slate-700 inline-block" />}
          <span className="text-gray-300">{s.label}</span>
          {s.detail && <span className="text-gray-600 truncate">— {s.detail}</span>}
        </div>
      ))}
    </div>
  )
}

// NetAICard runs a SEPARATE AI pass over the finished capture — its own verdict,
// kill-chain narrative, ATT&CK and transparent score card — beside the
// deterministic Suricata verdict. Mirrors the malware feature's AI opinion.
function NetAICard({ scan }: { scan: NetworkScan }) {
  const qc = useQueryClient()
  const [providerId, setProviderId] = useState('')
  const { data: providers } = useQuery({ queryKey: ['ai-providers'], queryFn: () => analysisApi.listProviders() })
  const run = useMutation({
    mutationFn: () => networkApi.aiAnalyze(scan.id, providerId || undefined),
    onSuccess: () => { toast.success('AI analysis started'); qc.invalidateQueries({ queryKey: ['network', scan.id] }) },
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const running = scan.network_ai_status === 'running' || run.isPending
  const v = scan.network_ai_status === 'done' ? nsafeParse<NetVerdict>(scan.network_ai) : null
  const vm = v ? verdictMeta(v.verdict) : null

  return (
    <Card title="AI analysis" icon={Brain} right={
      <span className="text-[10px] text-gray-500">{scan.network_ai_status === 'done' ? 'done' : running ? 'running' : 'on-demand'}</span>
    }>
      <div className="flex items-center gap-2 flex-wrap">
        <select className="input text-xs flex-1 min-w-[160px]" value={providerId} onChange={(e) => setProviderId(e.target.value)} disabled={running}>
          <option value="">Default AI provider</option>
          {(providers ?? []).map((p) => <option key={p.id} value={p.id}>{p.name} ({p.model})</option>)}
        </select>
        <button className="btn-primary text-xs inline-flex items-center gap-1.5 py-1.5" disabled={running || scan.status !== 'done'} onClick={() => run.mutate()}>
          {running ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Sparkles className="h-3.5 w-3.5" />}
          {v ? 'Re-run AI' : 'Run AI analysis'}
        </button>
      </div>

      {running && <p className="text-[11px] text-sky-400 flex items-center gap-1.5"><Loader className="h-3 w-3 animate-spin" /> The model is reasoning over the flows, alerts, DNS/TLS/HTTP and files…</p>}
      {scan.network_ai_status === 'failed' && <p className="text-[11px] text-red-400">AI analysis failed — try again or pick another provider.</p>}

      {v && vm && (
        <div className="space-y-2.5 pt-1">
          <div className="flex items-center gap-2 flex-wrap">
            <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium flex items-center gap-1 ${vm.cls}`}><vm.Icon className="h-3 w-3" />{vm.label}</span>
            <span className="text-[11px] text-gray-400">{v.confidence}% confidence · threat {v.threat_score}/100</span>
            {v.family && <span className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-gray-300 border border-slate-700">{v.family}</span>}
          </div>

          {v.behavior_summary && <AiMarkdown content={v.behavior_summary} />}

          {!!v.attck_techniques?.length && (
            <div className="flex flex-wrap gap-1">{v.attck_techniques.map((t) => <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-slate-800 text-sky-300 border border-slate-700 font-mono">{t}</span>)}</div>
          )}

          {!!v.key_indicators?.length && (
            <div>
              <div className="label text-[10px] mb-0.5">Key indicators</div>
              <ul className="text-[11px] text-gray-300 space-y-0.5 list-disc pl-4">{v.key_indicators.map((k, i) => <li key={i} className="break-all">{k}</li>)}</ul>
            </div>
          )}

          {!!v.independent_findings?.filter((k) => k.trim()).length && (
            <div className="rounded border border-violet-500/30 bg-violet-500/5 p-2">
              <div className="label text-[10px] mb-0.5 text-violet-300 flex items-center gap-1"><Sparkles className="h-3 w-3" /> AI independent findings (beyond Suricata)</div>
              <ul className="text-[11px] text-gray-300 space-y-0.5 list-disc pl-4">{v.independent_findings.filter((k) => k.trim()).map((k, i) => <li key={i} className="break-all">{k}</li>)}</ul>
            </div>
          )}

          {!!v.recommendations?.length && (
            <div>
              <div className="label text-[10px] mb-0.5">Recommended defender actions</div>
              <ul className="text-[11px] text-gray-300 space-y-0.5 list-disc pl-4">{v.recommendations.map((k, i) => <li key={i}>{k}</li>)}</ul>
            </div>
          )}

          {!!v.signals?.length && (
            <details className="mt-1">
              <summary className="cursor-pointer label text-[10px]">Why this verdict — signal breakdown ({v.signals.length})</summary>
              <div className="mt-1 space-y-1">
                {v.signals.map((sig, i) => (
                  <div key={i} className="flex items-start gap-2 text-[11px]">
                    <span className={`px-1.5 py-0.5 rounded border text-[9px] font-medium uppercase shrink-0 w-20 text-center ${impactCls(sig.impact)}`}>{sig.impact}</span>
                    <span className="text-gray-300 flex-1"><b className="text-gray-200">{sig.source}</b> — {sig.detail}</span>
                  </div>
                ))}
              </div>
              <p className="text-[10px] text-gray-600 mt-1.5">Deterministic signals (Suricata high-severity signatures, threat-intel C2) set the verdict floor; the AI reading cannot lower it.</p>
            </details>
          )}

          {v.signal_agreement && <p className="text-[10px] text-gray-500 italic">{v.signal_agreement}</p>}
        </div>
      )}

      {!v && !running && <p className="text-[11px] text-gray-600">Run an AI analyst pass over this capture for a plain-language kill-chain, ATT&CK mapping and a fused verdict — separate from the Suricata signatures above.</p>}
    </Card>
  )
}

// FilePreviewModal shows a carved file's type + hex dump + extracted strings.
function FilePreviewModal({ preview, onClose }: { preview: CarvedPreview; onClose: () => void }) {
  const [tab, setTab] = useState<'hex' | 'strings'>('hex')
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-3xl max-h-[85vh] flex flex-col rounded-lg border border-slate-700 bg-gray-900 shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-4 py-2.5 border-b border-slate-800">
          <FileWarning className="h-4 w-4 text-sky-400" />
          <span className="text-sm font-semibold text-gray-100 break-all">{preview.name}</span>
          <button className="ml-auto text-gray-500 hover:text-gray-300" onClick={onClose}><X className="h-4 w-4" /></button>
        </div>
        <div className="px-4 py-2 border-b border-slate-800 flex items-center gap-3 flex-wrap text-[11px] text-gray-400">
          <span className="px-1.5 py-0.5 rounded bg-slate-800 text-gray-200">{preview.type}</span>
          <span>{fmtBytesFull(preview.size)}{preview.truncated && <span className="text-amber-400"> (preview truncated)</span>}</span>
          <span className="font-mono text-gray-600 break-all">{preview.sha256.slice(0, 24)}…</span>
          <span className="ml-auto flex gap-1">
            <button className={`px-2 py-0.5 rounded text-[11px] ${tab === 'hex' ? 'bg-slate-700 text-gray-100' : 'text-gray-400'}`} onClick={() => setTab('hex')}>Hex</button>
            <button className={`px-2 py-0.5 rounded text-[11px] ${tab === 'strings' ? 'bg-slate-700 text-gray-100' : 'text-gray-400'}`} onClick={() => setTab('strings')}>Strings ({preview.strings.length})</button>
          </span>
        </div>
        <div className="flex-1 overflow-auto p-3">
          {tab === 'hex' ? (
            <pre className="text-[10px] leading-tight font-mono text-gray-400 whitespace-pre">{preview.hex || '(empty)'}</pre>
          ) : (
            <div className="text-[10px] font-mono text-gray-300 space-y-0.5">
              {preview.strings.length === 0 ? <span className="text-gray-600">No printable strings found.</span> : preview.strings.map((s, i) => <div key={i} className="break-all">{s}</div>)}
              {preview.strings.length >= preview.string_cap && <div className="text-gray-600">… (capped at {preview.string_cap})</div>}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// CarvedFileActions renders View / Download / Analyze for a carved file.
function CarvedFileActions({ scanId, sha, name }: { scanId: string; sha: string; name: string }) {
  const navigate = useNavigate()
  const [preview, setPreview] = useState<CarvedPreview | null>(null)
  const viewMut = useMutation({ mutationFn: () => networkApi.previewFile(scanId, sha), onSuccess: setPreview, onError: (e) => toast.error(getErrorMessage(e)) })
  const dlMut = useMutation({ mutationFn: () => networkApi.downloadFile(scanId, sha, name), onError: (e) => toast.error(getErrorMessage(e)) })
  const malMut = useMutation({
    mutationFn: () => networkApi.analyzeInMalware(scanId, sha),
    onSuccess: () => { toast.success('Sent to Malware Analysis'); navigate('/malware') },
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const busy = viewMut.isPending || dlMut.isPending || malMut.isPending
  return (
    <div className="flex items-center gap-1">
      <button title="View content (hex + strings)" disabled={busy} onClick={() => viewMut.mutate()} className="p-1 rounded hover:bg-slate-700 text-gray-400 hover:text-sky-300 disabled:opacity-40">
        {viewMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Eye className="h-3.5 w-3.5" />}
      </button>
      <button title="Download file" disabled={busy} onClick={() => dlMut.mutate()} className="p-1 rounded hover:bg-slate-700 text-gray-400 hover:text-emerald-300 disabled:opacity-40">
        {dlMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Download className="h-3.5 w-3.5" />}
      </button>
      <button title="Analyze in Malware Analysis" disabled={busy} onClick={() => malMut.mutate()} className="p-1 rounded hover:bg-slate-700 text-gray-400 hover:text-red-300 disabled:opacity-40">
        {malMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Bug className="h-3.5 w-3.5" />}
      </button>
      {preview && <FilePreviewModal preview={preview} onClose={() => setPreview(null)} />}
    </div>
  )
}

function Detail({ id }: { id: string }) {
  const qc = useQueryClient()
  const { data: scan } = useQuery({
    queryKey: ['network', id],
    queryFn: () => networkApi.get(id),
    refetchInterval: (q) => { const s = q.state.data as NetworkScan | undefined; return (s?.status === 'running' || s?.status === 'pending' || s?.network_ai_status === 'running') ? 2000 : false },
  })
  const del = useMutation({ mutationFn: () => networkApi.remove(id), onSuccess: () => { toast.success('Deleted'); qc.invalidateQueries({ queryKey: ['network-list'] }) } })
  if (!scan) return <div className="rounded-lg border border-slate-800 bg-gray-900/40 text-center py-10 text-sm text-gray-500">Loading…</div>

  const steps = nsafeParse<NetChainStep[]>(scan.steps) ?? []
  const result = nsafeParse<NetworkResult>(scan.result)
  const findings = nsafeParse<NetworkFinding[]>(scan.findings) ?? []
  const carvedShas = new Set(findings.filter((f) => f.category === 'carved').map((f) => (f.indicator || '').toLowerCase()))
  const vm = verdictMeta(scan.verdict)

  return (
    <div className="space-y-3">
      <div className={`rounded-lg border p-4 ring-1 ${vm.cls}`}>
        <div className="flex items-start gap-3">
          <vm.Icon className="h-8 w-8 shrink-0" />
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-lg font-bold">{vm.label}</span>
              <span className="text-xs opacity-80">· threat {scan.threat_score}/100</span>
            </div>
            <div className="text-sm text-gray-200/90 font-medium break-all mt-0.5">{scan.file_name}</div>
            <div className="text-[11px] text-gray-400 mt-0.5">{scan.summary}</div>
          </div>
          {scan.status === 'done' && <button className="btn-secondary text-[11px] py-1 px-2" title="Export HTML report (print → PDF)" onClick={() => networkApi.openReport(scan.id).catch((e) => toast.error(getErrorMessage(e)))}><FileDown className="h-3.5 w-3.5" /></button>}
          <button className="btn-secondary text-[11px] py-1 px-2" onClick={() => del.mutate()}><Trash2 className="h-3.5 w-3.5" /></button>
        </div>
        <div className="mt-3 flex gap-4 flex-wrap text-[11px] text-gray-400">
          <span>Flows <b className="text-gray-200">{scan.flow_count}</b></span>
          <span>Alerts <b className="text-gray-200">{scan.alert_count}</b></span>
          <span>C2/malicious <b className={scan.c2_count > 0 ? 'text-red-400' : 'text-gray-200'}>{scan.c2_count}</b></span>
          {result?.stats?.bytes ? <span>Bytes <b className="text-gray-200">{fmtBytes(result.stats.bytes)}</b></span> : null}
        </div>
      </div>

      {scan.auto_summary && (
        <Card title="Analyst summary" icon={FileText} right={<span className="text-[10px] px-1.5 py-0.5 rounded border border-slate-700 text-gray-400">{scan.auto_summary_kind === 'ai' ? 'AI-generated' : 'auto (no AI provider)'}</span>}>
          <AiMarkdown content={scan.auto_summary} />
        </Card>
      )}

      <Card title="Analysis pipeline" icon={Radar} right={<span className={`text-[10px] px-1.5 py-0.5 rounded border ${scan.status === 'done' ? 'border-emerald-500/40 text-emerald-400' : scan.status === 'failed' ? 'border-red-500/40 text-red-400' : 'border-sky-500/40 text-sky-400'}`}>{scan.status}</span>}>
        <StepList steps={steps} />
        {scan.error && <div className="text-[11px] text-red-400">{scan.error}</div>}
      </Card>

      {result && <StatsOverview result={result} />}
      {result && <TimelineCard result={result} />}
      {result && <ConversationsCard result={result} />}
      {result && <TopTalkers result={result} />}
      {result && <ProtocolTree result={result} />}
      {result && <ZeekPanel result={result} />}

      {findings.length > 0 && (
        <Card title="C2 / malicious traffic findings" icon={ShieldAlert} right={<span className="text-[10px] text-gray-500">{findings.length}</span>}>
          <div className="space-y-1">
            {[...findings].sort((a, b) => (['info', 'low', 'medium', 'high', 'critical'].indexOf(b.severity) - ['info', 'low', 'medium', 'high', 'critical'].indexOf(a.severity))).map((f, i) => (
              <div key={i} className="flex items-start gap-2 text-[11px]">
                <span className={`px-1.5 py-0.5 rounded border text-[9px] uppercase shrink-0 ${sevCls[f.severity] ?? sevCls.low}`}>{f.severity}</span>
                <span className="text-[9px] px-1 py-0.5 rounded bg-slate-800 text-gray-400 shrink-0">{f.category}</span>
                <span className="text-gray-200 flex-1">{f.title}<span className="text-gray-500"> — {f.detail}</span></span>
              </div>
            ))}
          </div>
        </Card>
      )}

      {findings.some((f) => f.category === 'carved') && (
        <div className="rounded-lg border border-sky-500/30 bg-sky-500/5 p-3 text-[11px] text-gray-300 flex items-start gap-2">
          <FileWarning className="h-4 w-4 text-sky-400 shrink-0 mt-0.5" />
          <span>
            <b>{findings.filter((f) => f.category === 'carved').length} file(s)</b> reconstructed from this capture were saved to the <b>Evidence Store</b>.
            Download them (admin-only, audited) from the Evidence page — match by sha256 shown in the findings above. You can then run a carved sample through Malware Analysis.
          </span>
        </div>
      )}

      <NetAICard scan={scan} />

      {result?.graph && result.graph.nodes.length > 0 && (
        <Card title="Network flow graph" icon={Network} right={<span className="text-[10px] text-gray-500">{result.graph.nodes.length} host(s)</span>}>
          <FlowGraph result={result} findings={findings} />
        </Card>
      )}

      {!!result?.dns?.length && (
        <Card title={`DNS queries (${result.dns.length})`} icon={Globe}>
          <div className="overflow-x-auto max-h-56 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2 py-1">Query</th><th className="pr-2">Type</th><th className="pr-2">Rcode</th><th className="pr-2">Answers</th></tr></thead>
            <tbody>{result.dns.slice(0, 300).map((d, i) => (
              <tr key={i} className="border-t border-slate-800/50">
                <td className="pr-2 text-gray-300 break-all">{d.query}</td>
                <td className="pr-2 text-gray-500">{d.type || '—'}</td>
                <td className="pr-2">{d.rcode ? <span className={d.rcode === 'NXDOMAIN' ? 'text-amber-400' : 'text-gray-500'}>{d.rcode}</span> : '—'}</td>
                <td className="pr-2 font-mono text-gray-500 break-all">{(d.answers ?? []).join(', ') || '—'}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </Card>
      )}
      {!!result?.tls?.length && (
        <Card title={`TLS / JA3 (${result.tls.length})`} icon={ShieldCheck}>
          <div className="overflow-x-auto max-h-56 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2 py-1">SNI</th><th className="pr-2">Ver</th><th className="pr-2">JA3</th><th className="pr-2">JA3S</th><th className="pr-2">Issuer</th><th className="pr-2">Dst</th></tr></thead>
            <tbody>{result.tls.slice(0, 200).map((t, i) => {
              const self = t.subject && t.subject === t.issuer
              return (
                <tr key={i} className="border-t border-slate-800/50">
                  <td className="pr-2 text-gray-300 break-all">{t.sni || '—'}{self && <span className="ml-1 text-[8px] px-1 rounded bg-amber-500/20 text-amber-300">self-signed</span>}</td>
                  <td className="pr-2 text-gray-500">{(t.version || '').replace('TLS ', '') || '—'}</td>
                  <td className="pr-2 font-mono text-gray-500">{t.ja3 ? t.ja3.slice(0, 12) + '…' : '—'}</td>
                  <td className="pr-2 font-mono text-gray-600">{t.ja3s ? t.ja3s.slice(0, 12) + '…' : '—'}</td>
                  <td className="pr-2 text-gray-500 break-all">{t.issuer ? t.issuer.replace(/^.*CN=/, '').slice(0, 28) : '—'}</td>
                  <td className="pr-2 font-mono text-gray-500">{t.dst}</td>
                </tr>
              )
            })}</tbody>
          </table></div>
        </Card>
      )}
      {!!result?.http?.length && (
        <Card title={`HTTP (${result.http.length})`} icon={Globe}>
          <div className="overflow-x-auto max-h-56 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2 py-1">Method</th><th className="pr-2">Host / URL</th><th className="pr-2">Status</th><th className="pr-2">User-Agent</th></tr></thead>
            <tbody>{result.http.slice(0, 200).map((h, i) => (
              <tr key={i} className="border-t border-slate-800/50">
                <td className="pr-2 text-gray-300">{h.method}</td>
                <td className="pr-2 text-gray-300 break-all">{h.host}{h.url}</td>
                <td className="pr-2 text-gray-500">{h.status || '—'}</td>
                <td className="pr-2 text-gray-600 break-all">{h.ua || '—'}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </Card>
      )}
      {!!result?.decrypted_http?.length && (
        <Card title={`Decrypted HTTPS requests (${result.decrypted_http.length})`} icon={ShieldCheck} right={<span className="text-[10px] px-1.5 py-0.5 rounded border border-violet-500/40 text-violet-300">TLS decrypted</span>}>
          <div className="overflow-x-auto max-h-56 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2 py-1">Method</th><th className="pr-2">Host / URL</th><th className="pr-2">Dst</th><th className="pr-2">User-Agent</th></tr></thead>
            <tbody>{result.decrypted_http.slice(0, 200).map((h, i) => (
              <tr key={i} className="border-t border-slate-800/50">
                <td className="pr-2 text-gray-300">{h.method}</td>
                <td className="pr-2 text-gray-200 break-all">{h.host}{h.url}</td>
                <td className="pr-2 font-mono text-gray-500">{h.dst}</td>
                <td className="pr-2 text-gray-600 break-all">{h.ua || '—'}</td>
              </tr>
            ))}</tbody>
          </table></div>
        </Card>
      )}
      {!!result?.files?.length && (
        <Card title={`Files transferred (${result.files.length})`} icon={FileWarning}>
          <div className="overflow-x-auto max-h-56 overflow-y-auto"><table className="w-full text-[10px]">
            <thead className="sticky top-0 bg-gray-900"><tr className="text-gray-500 text-left"><th className="pr-2 py-1">Filename</th><th className="pr-2">Type</th><th className="pr-2">Size</th><th className="pr-2">SHA256</th><th className="pr-2">Actions</th></tr></thead>
            <tbody>{result.files.slice(0, 150).map((f, i) => {
              const carved = carvedShas.has((f.sha256 || '').toLowerCase())
              return (
                <tr key={i} className="border-t border-slate-800/50">
                  <td className="pr-2 text-gray-300 break-all">
                    {f.filename || '(unnamed)'}
                    {carved && <span className="ml-1 text-[8px] px-1 rounded bg-sky-500/20 text-sky-300">carved</span>}
                    {f.decrypted && <span className="ml-1 text-[8px] px-1 rounded bg-violet-500/20 text-violet-300">decrypted</span>}
                    {!!f.yara?.length && <span className="ml-1 text-[8px] px-1 rounded bg-red-500/20 text-red-300" title={f.yara.join(', ')}>⚠ YARA: {f.yara.join(', ')}</span>}
                  </td>
                  <td className="pr-2 text-gray-500 break-all">{f.magic || '—'}</td>
                  <td className="pr-2 text-gray-400">{fmtBytesFull(f.size)}</td>
                  <td className="pr-2 font-mono text-gray-600 break-all">{f.sha256 ? f.sha256.slice(0, 20) + '…' : '—'}</td>
                  <td className="pr-2">{carved && f.sha256 ? <CarvedFileActions scanId={scan.id} sha={f.sha256} name={f.filename || f.sha256} /> : <span className="text-gray-700 text-[9px]">not carved</span>}</td>
                </tr>
              )
            })}</tbody>
          </table></div>
          <p className="text-[10px] text-gray-600 mt-1">Carved files: view content (hex/strings), download, or send to Malware Analysis. Only cleartext-protocol files can be reconstructed.</p>
        </Card>
      )}
    </div>
  )
}

export default function NetworkAnalysisPage() {
  const qc = useQueryClient()
  const [file, setFile] = useState<File | null>(null)
  const [keylog, setKeylog] = useState<File | null>(null)
  const [selected, setSelected] = useState<string | null>(null)
  const { data: cfg } = useQuery({ queryKey: ['network-config'], queryFn: () => networkApi.config() })
  const { data: scans = [] } = useQuery({
    queryKey: ['network-list'], queryFn: () => networkApi.list(),
    refetchInterval: (q) => ((q.state.data as NetworkScan[] | undefined)?.some((s) => s.status === 'running' || s.status === 'pending') ? 2500 : false),
  })
  const analyze = useMutation({
    mutationFn: () => networkApi.analyze(file!, undefined, keylog),
    onSuccess: (r) => { toast.success(r.decrypt ? 'PCAP analysis started (TLS decryption on)' : 'PCAP analysis started'); setFile(null); setKeylog(null); qc.invalidateQueries({ queryKey: ['network-list'] }); setSelected(r.scan_id) },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <div className="p-4 space-y-4">
      <div className="flex items-center gap-2 flex-wrap">
        <Network className="h-5 w-5 text-emerald-400" />
        <h1 className="text-lg font-semibold text-gray-100">Network Traffic Analysis</h1>
        <span className="text-[11px] text-gray-500">upload a .pcap → Suricata flows / DNS / TLS-JA3 / HTTP + ET-Open C2 detection + flow graph</span>
        <span className={`ml-auto text-[10px] px-1.5 py-0.5 rounded border ${cfg?.available ? 'border-emerald-500/40 text-emerald-400' : 'border-slate-700 text-gray-600'}`}>
          Suricata {cfg?.available ? `on (${cfg.rules} rules)` : 'off'}
        </span>
      </div>

      <div className="rounded-lg border border-slate-800 bg-gray-900/40 p-3 space-y-3">
        <label className="flex items-center gap-3 cursor-pointer rounded-lg border border-dashed border-gray-700 bg-gray-950/40 p-4 hover:border-emerald-700 transition-colors">
          <Upload className="h-5 w-5 text-gray-500" />
          <span className="text-sm text-gray-300 truncate">{file ? file.name : 'Choose a capture (.pcap / .pcapng / .cap)'}</span>
          <input type="file" accept=".pcap,.pcapng,.cap" className="hidden" onChange={(e) => setFile(e.target.files?.[0] ?? null)} />
        </label>
        <label className="flex items-center gap-3 cursor-pointer rounded-lg border border-dashed border-slate-800 bg-gray-950/40 px-4 py-2 hover:border-sky-800 transition-colors">
          <ShieldCheck className="h-4 w-4 text-gray-600" />
          <span className="text-[11px] text-gray-400 truncate">{keylog ? keylog.name : 'Optional: SSLKEYLOG file to decrypt TLS (HTTPS) and carve encrypted files'}</span>
          <input type="file" accept=".log,.txt,.keys,.keylog" className="hidden" onChange={(e) => setKeylog(e.target.files?.[0] ?? null)} />
          {keylog && <button className="ml-auto text-gray-500 hover:text-gray-300" onClick={(e) => { e.preventDefault(); setKeylog(null) }}><X className="h-3.5 w-3.5" /></button>}
        </label>
        <div className="flex items-center gap-2">
          <button className="btn-primary inline-flex items-center gap-2" disabled={!file || analyze.isPending || !cfg?.available} onClick={() => analyze.mutate()}>
            {analyze.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Network className="h-4 w-4" />} Analyse pcap
          </button>
          <p className="text-[10px] text-gray-600">Admin-only. Raw pcap → Evidence Store (audited). Provide an SSLKEYLOG to see inside encrypted TLS traffic.</p>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-4">
        <div className="space-y-2">
          {scans.length === 0 ? (
            <div className="rounded-lg border border-slate-800 bg-gray-900/40 text-center py-8 text-sm text-gray-500 flex flex-col items-center gap-2"><Boxes className="h-6 w-6" /> No captures analysed yet</div>
          ) : scans.map((s) => {
            const m = verdictMeta(s.verdict)
            const busy = s.status === 'running' || s.status === 'pending'
            return (
              <button key={s.id} onClick={() => setSelected(s.id)} className={`w-full text-left rounded-lg border p-2.5 transition-colors ${selected === s.id ? 'border-emerald-600 bg-emerald-500/5' : 'border-slate-800 bg-gray-900/40 hover:border-slate-700'}`}>
                <div className="flex items-center gap-2">
                  <span className={`px-1.5 py-0.5 rounded border text-[10px] font-medium ${m.cls} flex items-center gap-1`}><m.Icon className="h-3 w-3" />{m.label}</span>
                  <span className="text-sm text-gray-200 truncate flex-1">{s.file_name}</span>
                  {busy && <Loader2 className="h-3.5 w-3.5 animate-spin text-sky-400" />}
                </div>
                <div className="mt-1 flex items-center gap-2 text-[10px] text-gray-500">
                  <span>{s.flow_count} flows</span>
                  {s.c2_count > 0 && <span className="text-red-400">· {s.c2_count} C2</span>}
                </div>
              </button>
            )
          })}
        </div>
        <div>{selected ? <Detail id={selected} /> : <div className="rounded-lg border border-slate-800 bg-gray-900/40 text-center py-10 text-sm text-gray-500">Select a capture to view details</div>}</div>
      </div>
    </div>
  )
}
