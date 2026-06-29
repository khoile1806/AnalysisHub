import { useState, useEffect, useRef, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Radio, Plus, Trash2, Copy, RefreshCw, Globe, Server, Mail, Network,
  CheckCircle2, Wifi, WifiOff, ChevronRight, Webhook, Save, Zap, Settings2, Wand2,
  Terminal as TerminalIcon, Bell, BellOff, Download, Search,
  Pause, Play, Eye, EyeOff, Pencil, X, Eraser, Star, Crosshair, FileJson, FileDown, ListTree,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { oobApi, type OobClient, type OobPayload, type OobInteraction, type OobProtocol, type OobRule } from '@/api/oob'
import { decodeApi, type DecodeResult } from '@/api/decode'

const PROTO_META: Record<OobProtocol, { icon: typeof Globe; color: string; label: string }> = {
  dns:   { icon: Network, color: 'text-sky-400 bg-sky-500/10 border-sky-500/20',         label: 'DNS' },
  http:  { icon: Globe,   color: 'text-emerald-400 bg-emerald-500/10 border-emerald-500/20', label: 'HTTP' },
  https: { icon: Globe,   color: 'text-teal-400 bg-teal-500/10 border-teal-500/20',       label: 'HTTPS' },
  smtp:  { icon: Mail,    color: 'text-amber-400 bg-amber-500/10 border-amber-500/20',     label: 'SMTP' },
  ldap:  { icon: Server,  color: 'text-purple-400 bg-purple-500/10 border-purple-500/20', label: 'LDAP' },
  rmi:   { icon: Server,  color: 'text-fuchsia-400 bg-fuchsia-500/10 border-fuchsia-500/20', label: 'RMI' },
}

function copy(text: string, label = 'Copied') {
  navigator.clipboard.writeText(text).then(
    () => toast.success(label),
    () => toast.error('Copy failed'),
  )
}

function timeAgo(iso: string) {
  const s = Math.max(0, (Date.now() - new Date(iso).getTime()) / 1000)
  if (s < 60) return `${Math.floor(s)}s ago`
  if (s < 3600) return `${Math.floor(s / 60)}m ago`
  if (s < 86400) return `${Math.floor(s / 3600)}h ago`
  return `${Math.floor(s / 86400)}d ago`
}

// OobPanel is the "Catch (OOB)" sub-feature rendered as a tab inside the OSINT
// page (mirrors CanaryPanel / WatchlistPanel).
export function OobPanel() {
  const qc = useQueryClient()
  const [selectedId, setSelectedId] = useState<string | null>(null)
  const [payload, setPayload] = useState<OobPayload | null>(null)
  const [detail, setDetail] = useState<OobInteraction | null>(null)
  const [search, setSearch] = useState('')
  const [notifyOpen, setNotifyOpen] = useState(false)
  const [notifyDraft, setNotifyDraft] = useState('')
  const [paused, setPaused] = useState(false)
  const [connected, setConnected] = useState(false)
  const [pendingNew, setPendingNew] = useState(0)
  const [revealSecret, setRevealSecret] = useState(false)
  const [editingName, setEditingName] = useState(false)
  const [nameDraft, setNameDraft] = useState('')
  const [protoFilter, setProtoFilter] = useState('')
  const [starredOnly, setStarredOnly] = useState(false)
  const [noteDraft, setNoteDraft] = useState('')
  const [limit, setLimit] = useState(100)
  const searchRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const initedRef = useRef<string | null>(null)

  const { data: config } = useQuery({ queryKey: ['oob-config'], queryFn: oobApi.config, refetchInterval: 15_000 })
  const { data: clients = [] } = useQuery({ queryKey: ['oob-clients'], queryFn: oobApi.listClients, refetchInterval: 10_000 })

  const selected = clients.find(c => c.id === selectedId) ?? null

  const { data: interactionsResp, isError: interactionsError } = useQuery({
    queryKey: ['oob-interactions', selectedId, search, protoFilter, starredOnly, limit],
    queryFn: () => oobApi.interactions(selectedId!, {
      q: search || undefined,
      protocol: protoFilter || undefined,
      starred: starredOnly ? 'true' : undefined,
      limit,
    }),
    enabled: !!selectedId,
    // SSE drives instant updates; poll slowly as a reconciliation fallback when
    // connected, faster when not (e.g. hub unavailable).
    refetchInterval: connected ? 20_000 : 4_000,
  })
  const interactions = interactionsResp?.data ?? []

  // Debounce search input to avoid spamming the API while typing.
  const handleSearchChange = useCallback((val: string) => {
    if (searchRef.current) clearTimeout(searchRef.current)
    searchRef.current = setTimeout(() => setSearch(val), 300)
  }, [])
  useEffect(() => () => { if (searchRef.current) clearTimeout(searchRef.current) }, [])

  // Live updates via Server-Sent Events. On each new interaction we refresh the
  // list (respecting the active search) unless paused, in which case we just
  // count pending arrivals for a "+N new" badge.
  useEffect(() => {
    if (!selectedId) { setConnected(false); return }
    const es = new EventSource(oobApi.streamUrl(selectedId))
    es.onopen = () => setConnected(true)
    es.onerror = () => setConnected(false)
    es.addEventListener('interaction', () => {
      if (paused) setPendingNew(n => n + 1)
      else qc.invalidateQueries({ queryKey: ['oob-interactions', selectedId] })
    })
    return () => { es.close(); setConnected(false) }
  }, [selectedId, paused, qc])

  const resumeLive = () => {
    setPaused(false)
    setPendingNew(0)
    if (selectedId) qc.invalidateQueries({ queryKey: ['oob-interactions', selectedId] })
  }

  // Full detail of the selected session (carries the secret — stripped from the
  // list response) so we can build the curl read command.
  const { data: selectedDetail } = useQuery({
    queryKey: ['oob-client', selectedId],
    queryFn: () => oobApi.getClient(selectedId!),
    enabled: !!selectedId,
  })

  const register = useMutation({
    mutationFn: () => oobApi.register({}),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['oob-clients'] })
      setSelectedId(data.client.id)
      setPayload(data.payload)
      toast.success('New OOB session created')
    },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed to create session'),
  })

  const remove = useMutation({
    mutationFn: (id: string) => oobApi.deleteClient(id),
    onSuccess: (_d, id) => {
      qc.invalidateQueries({ queryKey: ['oob-clients'] })
      if (selectedId === id) { setSelectedId(null); setPayload(null) }
      toast.success('Session deleted')
    },
  })

  const genPayload = useMutation({
    mutationFn: (id: string) => oobApi.generatePayload(id),
    onSuccess: (p) => { setPayload(p); toast.success('New payload generated') },
  })

  // Webhook response editor (webhook.site-style custom response per session).
  const [respOpen, setRespOpen] = useState(false)
  const [rulesOpen, setRulesOpen] = useState(false)
  const [respDraft, setRespDraft] = useState({ status: 200, content_type: 'text/plain', body: '', headers: '' })
  // Initialise the response/notify/name drafts once the selected session's data
  // is available, re-running only when the selected id actually changes (so it
  // never clobbers the operator's in-progress edits or fails to init when the
  // record arrives after selection).
  useEffect(() => {
    if (selected && initedRef.current !== selected.id) {
      initedRef.current = selected.id
      setRespDraft({
        status: selected.resp_status,
        content_type: selected.resp_content_type,
        body: selected.resp_body ?? '',
        headers: headersToText(selected.resp_headers),
      })
      setNotifyDraft(selected.notify_url ?? '')
      setNameDraft(selected.name)
      setEditingName(false)
      setRevealSecret(false)
      setLimit(100)
    }
  }, [selected])

  const updateResp = useMutation({
    mutationFn: () => oobApi.updateResponse(selected!.id, {
      status: respDraft.status,
      content_type: respDraft.content_type,
      body: respDraft.body,
      headers: textToHeaders(respDraft.headers),
    }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['oob-clients'] }); toast.success('Response saved') },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed to save response'),
  })

  const updateNotify = useMutation({
    mutationFn: () => oobApi.updateNotify(selected!.id, notifyDraft.trim()),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['oob-clients'] }); toast.success('Notification URL saved'); setNotifyOpen(false) },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Failed to save notify URL'),
  })

  const renameClient = useMutation({
    mutationFn: () => oobApi.rename(selected!.id, { name: nameDraft.trim() }),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['oob-clients'] }); setEditingName(false); toast.success('Renamed') },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Rename failed'),
  })

  const clearInteractions = useMutation({
    mutationFn: () => oobApi.clearInteractions(selected!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['oob-interactions', selectedId] })
      qc.invalidateQueries({ queryKey: ['oob-clients'] })
      setPendingNew(0)
      toast.success('Interactions cleared')
    },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Clear failed'),
  })

  const deleteInteraction = useMutation({
    mutationFn: (iid: string) => oobApi.deleteInteraction(selected!.id, iid),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['oob-interactions', selectedId] })
      qc.invalidateQueries({ queryKey: ['oob-clients'] })
    },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Delete failed'),
  })

  const patchInteraction = useMutation({
    mutationFn: (v: { iid: string; body: { seen?: boolean; starred?: boolean; note?: string; tags?: string } }) =>
      oobApi.patchInteraction(selected!.id, v.iid, v.body),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['oob-interactions', selectedId] }),
  })

  const markAllSeen = useMutation({
    mutationFn: () => oobApi.markAllSeen(selected!.id),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['oob-interactions', selectedId] }),
  })

  const promoteIOC = useMutation({
    mutationFn: (iid: string) => oobApi.promoteIOC(selected!.id, iid),
    onSuccess: (d) => toast.success(`Added ${d.value} (${d.type}) to IOC store`),
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Promote failed'),
  })

  const unseenCount = interactions.filter(i => !i.seen).length

  const openDetail = (it: OobInteraction) => {
    setDetail(it)
    setNoteDraft(it.note ?? '')
    if (!it.seen) patchInteraction.mutate({ iid: it.id, body: { seen: true } })
  }

  // The webhook URL is stable per session (no DNS / no generate needed). Use the
  // freshly generated unique payload when present, else derive from the base.
  const webhookUrl = payload?.webhook
    ?? (config?.webhook_base && selected ? config.webhook_base + selected.correlation_id : '')
  // Advanced OAST (DNS/HTTP-host/SMTP) only works once OOB_DOMAIN is delegated.
  const oastReady = !!config?.running && !!config?.domain

  // CLI read — fetch captured callbacks from a terminal (no UI/JWT), gated by
  // the session secret. The read URL uses the correlation id as the token.
  const readUrl = config?.webhook_base && selected ? config.webhook_base + selected.correlation_id : ''
  const secret = selectedDetail?.secret ?? ''
  const curlJson = readUrl && secret ? `curl "${readUrl}?__read=1&secret=${secret}"` : ''
  const curlText = readUrl && secret ? `curl "${readUrl}?__read=1&secret=${secret}&format=text"` : ''
  // Masked variants for display (the real secret is only copied, not shown,
  // until the operator reveals it).
  const shownSecret = revealSecret ? secret : (secret ? secret.slice(0, 4) + '••••••••' : '')
  const curlJsonShown = readUrl && secret ? `curl "${readUrl}?__read=1&secret=${shownSecret}"` : ''
  const curlTextShown = readUrl && secret ? `curl "${readUrl}?__read=1&secret=${shownSecret}&format=text"` : ''

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-rose-500/20 to-orange-500/20 flex items-center justify-center border border-rose-500/30">
            <Radio className="h-5 w-5 text-rose-400" />
          </div>
          <div>
            <h2 className="text-base font-bold text-white tracking-tight leading-none">Catch — OOB Interaction Server</h2>
            <p className="text-xs text-gray-400 mt-1">Out-of-band DNS / HTTP / SMTP callbacks (Interactsh / Collaborator style)</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          {config && (
            <span className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border text-emerald-400 bg-emerald-500/10 border-emerald-500/20">
              <Webhook className="h-3.5 w-3.5" /> Webhook ready
            </span>
          )}
          {config && (
            <span className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium border ${
              oastReady ? 'text-sky-400 bg-sky-500/10 border-sky-500/20' : 'text-gray-400 bg-gray-500/10 border-gray-500/20'
            }`} title="Full DNS/SMTP OAST needs OOB_DOMAIN delegation">
              {oastReady ? <Wifi className="h-3.5 w-3.5" /> : <WifiOff className="h-3.5 w-3.5" />}
              {oastReady ? 'DNS/SMTP up' : 'DNS/SMTP off'}
            </span>
          )}
          <button
            onClick={() => register.mutate()}
            disabled={register.isPending}
            className="flex items-center gap-2 px-4 py-1.5 rounded-lg text-sm font-medium bg-rose-500/10 text-rose-300 hover:bg-rose-500/20 border border-rose-500/20 disabled:opacity-40"
          >
            <Plus className="h-4 w-4" /> New session
          </button>
        </div>
      </div>

      {/* Webhook-first explainer — webhook mode always works; DNS/SMTP is optional */}
      <div className="rounded-xl border border-emerald-500/20 bg-emerald-500/[0.06] p-4 flex gap-3">
        <Zap className="h-5 w-5 text-emerald-400 shrink-0 mt-0.5" />
        <div className="text-sm text-emerald-100/90 space-y-1">
          <p className="font-semibold text-emerald-300">Webhook mode is ready — no setup needed</p>
          <p>• Create a session, copy its <span className="text-emerald-300 font-medium">Webhook URL</span>, and fire it from your target (SSRF, blind RCE, webhook test). HTTP callbacks are captured instantly on this backend.</p>
          {!oastReady && (
            <p className="text-gray-400">• <span className="text-gray-300">Optional advanced OAST</span> (raw DNS / SMTP / hostname callbacks for blind XXE, JNDI, email injection) needs <code className="text-gray-300">OOB_DOMAIN</code> delegated + <code className="text-gray-300">OOB_ENABLED=true</code>.</p>
          )}
        </div>
      </div>

      {/* Server facts (advanced OAST) only when a zone is configured */}
      {config?.domain && (
        <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
          <Fact icon={Globe}  label="Zone"      value={config.domain} />
          <Fact icon={Server} label="Public IP" value={config.public_ip || '—'} />
          <Fact icon={Network} label="Listeners" value={config.listeners?.length ? config.listeners.join(', ') : '—'} />
          <Fact icon={config.running ? CheckCircle2 : WifiOff} label="Status" value={config.running ? 'Running' : 'Stopped'} />
        </div>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-[300px_1fr] gap-4 min-h-[560px]">
        {/* Sessions list */}
        <div className="rounded-xl border border-white/5 bg-[#121214] flex flex-col min-h-0">
          <div className="px-4 py-3 border-b border-white/5 text-xs font-semibold text-gray-300 uppercase tracking-wider flex items-center justify-between">
            Sessions <span className="text-gray-500">{clients.length}</span>
          </div>
          <div className="flex-1 overflow-y-auto p-2 space-y-1">
            {clients.length === 0 && <div className="text-center text-gray-500 text-sm py-10">No sessions yet</div>}
            {clients.map(c => (
              <SessionRow key={c.id} c={c} active={c.id === selectedId}
                onSelect={() => { setSelectedId(c.id); setPayload(null) }}
                onDelete={() => remove.mutate(c.id)} />
            ))}
          </div>
        </div>

        {/* Detail */}
        <div className="rounded-xl border border-white/5 bg-[#121214] flex flex-col min-h-0">
          {!selected ? (
            <div className="flex-1 flex items-center justify-center text-gray-500 text-sm">
              Select or create a session to get a payload
            </div>
          ) : (
            <div className="flex flex-col min-h-0">
              {/* Payload card */}
              <div className="p-4 border-b border-white/5 space-y-3">
                <div className="flex items-center justify-between">
                  {editingName ? (
                    <div className="flex items-center gap-1.5 flex-1 mr-2">
                      <input autoFocus value={nameDraft} onChange={e => setNameDraft(e.target.value)}
                        onKeyDown={e => { if (e.key === 'Enter') renameClient.mutate(); if (e.key === 'Escape') { setEditingName(false); setNameDraft(selected.name) } }}
                        className="flex-1 bg-black/40 border border-white/10 rounded px-2 py-0.5 text-sm text-gray-200" />
                      <button onClick={() => renameClient.mutate()} className="p-1 text-emerald-400 hover:text-emerald-300"><Save className="h-3.5 w-3.5" /></button>
                      <button onClick={() => { setEditingName(false); setNameDraft(selected.name) }} className="p-1 text-gray-500 hover:text-white"><X className="h-3.5 w-3.5" /></button>
                    </div>
                  ) : (
                    <div className="flex items-center gap-1.5 group/name">
                      <span className="text-sm font-semibold text-gray-200">{selected.name}</span>
                      <button onClick={() => { setNameDraft(selected.name); setEditingName(true) }} title="Rename" className="p-0.5 text-gray-600 hover:text-gray-300 opacity-0 group-hover/name:opacity-100"><Pencil className="h-3 w-3" /></button>
                    </div>
                  )}
                  <div className="flex items-center gap-1.5">
                    <button onClick={() => setRulesOpen(true)}
                      className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md bg-white/5 text-gray-300 hover:bg-white/10" title="Conditional response rules (match path/method → response)">
                      <ListTree className="h-3 w-3" /> Rules
                    </button>
                    <button onClick={() => setRespOpen(o => !o)}
                      className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md bg-white/5 text-gray-300 hover:bg-white/10" title="Default HTTP response the target receives">
                      <Settings2 className="h-3 w-3" /> Response
                    </button>
                    <button onClick={() => setNotifyOpen(o => !o)}
                      className={`flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md border hover:bg-white/10 ${selected.notify_url ? 'bg-amber-500/10 text-amber-300 border-amber-500/20' : 'bg-white/5 text-gray-300 border-transparent'}`}
                      title="Get notified (Slack/Discord/webhook) on every new interaction">
                      {selected.notify_url ? <Bell className="h-3 w-3" /> : <BellOff className="h-3 w-3" />} Notify
                    </button>
                    <button onClick={() => genPayload.mutate(selected.id)}
                      className="flex items-center gap-1.5 text-xs px-2.5 py-1 rounded-md bg-white/5 text-gray-300 hover:bg-white/10" title="Fresh unique payload (for per-callback attribution)">
                      <RefreshCw className="h-3 w-3" /> New payload
                    </button>
                  </div>
                </div>

                {/* Primary: instant webhook URL (no setup) */}
                <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/[0.05] p-2.5">
                  <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-emerald-400 mb-1.5">
                    <Webhook className="h-3 w-3" /> Webhook URL · works instantly
                  </div>
                  <div className="flex items-center gap-2">
                    <code className="flex-1 text-xs text-emerald-200 font-mono bg-black/40 rounded px-2 py-1.5 truncate" title={webhookUrl}>{webhookUrl || '—'}</code>
                    <button onClick={() => webhookUrl && copy(webhookUrl, 'Webhook URL copied')} className="p-1.5 text-emerald-400/80 hover:text-emerald-300 shrink-0">
                      <Copy className="h-4 w-4" />
                    </button>
                  </div>
                  <p className="text-[10px] text-gray-500 mt-1.5">Any HTTP method/path to this URL is captured below. e.g. <code className="text-gray-400">curl {webhookUrl || '<url>'}/test</code></p>
                </div>

                {/* CLI read — check captured callbacks from the terminal, no UI */}
                <div className="rounded-lg border border-white/10 bg-black/20 p-2.5">
                  <div className="flex items-center justify-between mb-1.5">
                    <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-gray-400">
                      <TerminalIcon className="h-3 w-3" /> Read results from terminal (no UI)
                    </div>
                    <button onClick={() => setRevealSecret(v => !v)} title={revealSecret ? 'Hide secret' : 'Reveal secret'}
                      className="flex items-center gap-1 text-[10px] text-gray-500 hover:text-gray-300">
                      {revealSecret ? <EyeOff className="h-3 w-3" /> : <Eye className="h-3 w-3" />}
                      {revealSecret ? 'hide' : 'reveal'}
                    </button>
                  </div>
                  <CmdRow label="JSON" cmd={curlJson} display={curlJsonShown} />
                  <CmdRow label="Table" cmd={curlText} display={curlTextShown} />
                  <p className="text-[10px] text-gray-500 mt-1.5">
                    Filters: <code className="text-gray-400">&amp;since=&lt;RFC3339&gt;</code> · <code className="text-gray-400">&amp;protocol=http|dns|smtp</code> · <code className="text-gray-400">&amp;limit=N</code>. Secret can also go in header <code className="text-gray-400">X-OOB-Secret</code>.
                  </p>
                </div>

                {/* Response editor (collapsible) */}
                {respOpen && (
                  <div className="rounded-lg border border-white/10 bg-black/20 p-2.5 space-y-2">
                    <div className="flex items-center gap-2">
                      <label className="text-[10px] text-gray-500 w-20 shrink-0">Status</label>
                      <input type="number" value={respDraft.status} min={100} max={599}
                        onChange={e => setRespDraft(d => ({ ...d, status: Number(e.target.value) }))}
                        className="w-20 bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200" />
                      <label className="text-[10px] text-gray-500 ml-2 shrink-0">Content-Type</label>
                      <input value={respDraft.content_type}
                        onChange={e => setRespDraft(d => ({ ...d, content_type: e.target.value }))}
                        className="flex-1 bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
                    </div>
                    <textarea value={respDraft.body} rows={2} placeholder="Response body (optional)"
                      onChange={e => setRespDraft(d => ({ ...d, body: e.target.value }))}
                      className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
                    <textarea value={respDraft.headers} rows={2} placeholder={'Extra headers, one per line\nLocation: https://example.com'}
                      onChange={e => setRespDraft(d => ({ ...d, headers: e.target.value }))}
                      className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
                    <div className="flex justify-end">
                      <button onClick={() => updateResp.mutate()} disabled={updateResp.isPending}
                        className="flex items-center gap-1.5 text-xs px-3 py-1 rounded-md bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 border border-emerald-500/20 disabled:opacity-40">
                        <Save className="h-3 w-3" /> Save response
                      </button>
                    </div>
                  </div>
                )}

                {/* Notification URL editor */}
                {notifyOpen && (
                  <div className="rounded-lg border border-amber-500/20 bg-amber-500/[0.05] p-2.5 space-y-2">
                    <div className="flex items-center gap-1.5 text-[10px] font-bold uppercase tracking-wider text-amber-400 mb-0.5">
                      <Bell className="h-3 w-3" /> Push notification on every callback
                    </div>
                    <p className="text-[10px] text-gray-400">Paste a Slack/Discord incoming webhook URL or any HTTP endpoint. A JSON POST is sent for every new interaction.</p>
                    <input
                      type="url"
                      value={notifyDraft}
                      onChange={e => setNotifyDraft(e.target.value)}
                      placeholder="https://hooks.slack.com/services/… or any POST URL"
                      className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono"
                    />
                    <div className="flex items-center justify-between">
                      <button onClick={() => { setNotifyDraft(''); updateNotify.mutate() }}
                        className="text-[10px] text-gray-500 hover:text-rose-400">Clear / disable</button>
                      <button onClick={() => updateNotify.mutate()} disabled={updateNotify.isPending}
                        className="flex items-center gap-1.5 text-xs px-3 py-1 rounded-md bg-amber-500/10 text-amber-300 hover:bg-amber-500/20 border border-amber-500/20 disabled:opacity-40">
                        <Save className="h-3 w-3" /> Save
                      </button>
                    </div>
                  </div>
                )}

                {/* Advanced OAST variants — only when a zone is delegated */}
                {payload && (payload.http || payload.dns) && (
                  <div className="space-y-1.5">
                    <div className="text-[10px] font-bold uppercase tracking-wider text-gray-500">Advanced OAST (needs domain)</div>
                    {payload.http && <PayloadRow label="HTTP" value={payload.http} />}
                    {payload.https && <PayloadRow label="HTTPS" value={payload.https} />}
                    {payload.dns && <PayloadRow label="DNS" value={payload.dns} />}
                    {payload.smtp && <PayloadRow label="SMTP" value={payload.smtp} />}
                    {payload.jndi_ldap && <PayloadRow label="JNDI" value={payload.jndi_ldap} />}
                    {payload.jndi_rmi && <PayloadRow label="RMI" value={payload.jndi_rmi} />}
                  </div>
                )}

                <p className="text-[11px] text-gray-500">
                  Correlation <code className="text-gray-400">{selected.correlation_id}</code> — any callback carrying this prefix is captured below.
                </p>
              </div>

              {/* Interactions header */}
              <div className="px-4 py-2.5 border-b border-white/5 flex items-center gap-2 flex-wrap">
                <span className="text-xs font-semibold text-gray-300 uppercase tracking-wider shrink-0">Interactions</span>
                <span className="text-[11px] text-gray-500 flex items-center gap-1 shrink-0" title={connected ? 'Live (SSE connected)' : 'Reconnecting — polling'}>
                  <span className={`w-1.5 h-1.5 rounded-full ${connected ? 'bg-emerald-500 animate-pulse' : 'bg-amber-500'}`} />
                  {connected ? 'live' : 'poll'} · {interactions.length}
                </span>
                {/* Pause / resume live updates */}
                <button onClick={() => (paused ? resumeLive() : setPaused(true))}
                  title={paused ? 'Resume live updates' : 'Pause live updates'}
                  className={`relative p-1.5 rounded-md shrink-0 ${paused ? 'text-amber-400 bg-amber-400/10' : 'text-gray-500 hover:text-gray-300 hover:bg-white/5'}`}>
                  {paused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
                  {paused && pendingNew > 0 && (
                    <span className="absolute -top-1 -right-1 min-w-[14px] h-[14px] px-0.5 rounded-full bg-rose-500 text-white text-[9px] font-bold flex items-center justify-center">{pendingNew > 99 ? '99+' : pendingNew}</span>
                  )}
                </button>
                {/* Search box */}
                <div className="flex-1 min-w-[140px] relative">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 h-3 w-3 text-gray-500 pointer-events-none" />
                  <input
                    type="text"
                    placeholder="Search IP, path, body…"
                    onChange={e => handleSearchChange(e.target.value)}
                    className="w-full pl-6 pr-6 py-1 rounded bg-black/30 border border-white/10 text-[11px] text-gray-300 placeholder-gray-600 focus:outline-none focus:border-white/20"
                  />
                </div>
                {/* Export CSV (authenticated blob download) */}
                <button
                  onClick={() => oobApi.downloadCsv(selected.id, selected.name, { q: search || undefined }).catch(() => toast.error('Export failed'))}
                  title="Export interactions as CSV"
                  className="p-1.5 text-gray-500 hover:text-emerald-400 hover:bg-emerald-400/10 rounded-md shrink-0"
                >
                  <Download className="h-3.5 w-3.5" />
                </button>
                {/* Clear all */}
                <button
                  onClick={() => { if (window.confirm('Delete ALL captured interactions for this session?')) clearInteractions.mutate() }}
                  disabled={interactions.length === 0}
                  title="Clear all interactions"
                  className="p-1.5 text-gray-500 hover:text-rose-400 hover:bg-rose-400/10 rounded-md shrink-0 disabled:opacity-30"
                >
                  <Eraser className="h-3.5 w-3.5" />
                </button>
              </div>
              {interactionsError && (
                <div className="px-4 py-1.5 text-[11px] text-rose-400 bg-rose-500/5 border-b border-rose-500/10">Failed to load interactions — retrying…</div>
              )}
              {/* Filter chips */}
              <div className="px-4 py-1.5 border-b border-white/5 flex items-center gap-1.5 flex-wrap text-[11px]">
                {(['', 'http', 'https', 'dns', 'smtp'] as const).map(p => (
                  <button key={p || 'all'} onClick={() => setProtoFilter(p)}
                    className={`px-2 py-0.5 rounded-full border ${protoFilter === p ? 'bg-white/10 text-white border-white/20' : 'text-gray-500 border-white/5 hover:text-gray-300'}`}>
                    {p ? p.toUpperCase() : 'All'}
                  </button>
                ))}
                <button onClick={() => setStarredOnly(s => !s)}
                  className={`px-2 py-0.5 rounded-full border flex items-center gap-1 ${starredOnly ? 'bg-amber-500/15 text-amber-300 border-amber-500/30' : 'text-gray-500 border-white/5 hover:text-gray-300'}`}>
                  <Star className="h-3 w-3" /> Starred
                </button>
                <div className="flex-1" />
                {unseenCount > 0 && (
                  <button onClick={() => markAllSeen.mutate()} className="px-2 py-0.5 rounded-full border border-emerald-500/20 text-emerald-300 bg-emerald-500/10 hover:bg-emerald-500/20">
                    Mark {unseenCount} seen
                  </button>
                )}
              </div>
              <div className="flex-1 overflow-y-auto">
                {interactions.length === 0 ? (
                  <div className="text-center text-gray-500 text-sm py-12">
                    Waiting for callbacks… fire the payload from your target.
                  </div>
                ) : (
                  <table className="w-full text-sm">
                    <tbody>
                      {interactions.map(it => {
                        const meta = PROTO_META[it.protocol] ?? PROTO_META.dns
                        const Icon = meta.icon
                        return (
                          <tr key={it.id} onClick={() => openDetail(it)}
                            className={`group border-b border-white/5 hover:bg-white/[0.03] cursor-pointer ${it.seen ? '' : 'bg-white/[0.015]'}`}>
                            <td className="pl-2 pr-1 py-2 w-7">
                              <div className="flex items-center gap-1">
                                <span className={`w-1.5 h-1.5 rounded-full shrink-0 ${it.seen ? 'bg-transparent' : 'bg-sky-400'}`} title={it.seen ? 'seen' : 'new'} />
                                <button onClick={(e) => { e.stopPropagation(); patchInteraction.mutate({ iid: it.id, body: { starred: !it.starred } }) }}
                                  title={it.starred ? 'Unstar' : 'Star'}
                                  className={it.starred ? 'text-amber-400' : 'text-gray-700 hover:text-gray-400 opacity-0 group-hover:opacity-100'}>
                                  <Star className={`h-3 w-3 ${it.starred ? 'fill-amber-400' : ''}`} />
                                </button>
                              </div>
                            </td>
                            <td className="px-1 py-2 w-16">
                              <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-bold border ${meta.color}`}>
                                <Icon className="h-3 w-3" /> {meta.label}
                              </span>
                            </td>
                            <td className="px-2 py-2 font-mono text-gray-300 text-xs truncate max-w-0">
                              {it.protocol === 'dns' && <span className="text-sky-400">{it.query_type} </span>}
                              {it.method && <span className="text-emerald-400">{it.method} </span>}
                              {it.full_host}{it.path && <span className="text-gray-500">{it.path}</span>}
                            </td>
                            <td className="px-2 py-2 text-gray-400 font-mono text-xs whitespace-nowrap">
                              {it.geo_country && <span className="text-gray-600 mr-1" title={`${it.geo_city ?? ''} ${it.geo_country}`}>{it.geo_country}</span>}
                              {it.remote_ip}
                              {it.is_proxy && <span className="ml-1 text-amber-500" title="proxy/VPN">⚑</span>}
                            </td>
                            <td className="px-3 py-2 text-gray-500 text-xs whitespace-nowrap" title={new Date(it.created_at).toLocaleString()}>{timeAgo(it.created_at)}</td>
                            <td className="px-2 py-2 text-gray-600">
                              <div className="flex items-center gap-0.5">
                                <button onClick={(e) => { e.stopPropagation(); deleteInteraction.mutate(it.id) }}
                                  title="Delete this interaction"
                                  className="p-0.5 text-gray-600 hover:text-rose-400 opacity-0 group-hover:opacity-100">
                                  <Trash2 className="h-3.5 w-3.5" />
                                </button>
                                <ChevronRight className="h-3.5 w-3.5" />
                              </div>
                            </td>
                          </tr>
                        )
                      })}
                    </tbody>
                  </table>
                )}
                {interactions.length >= limit && limit < 1000 && (
                  <div className="p-2 text-center">
                    <button onClick={() => setLimit(l => Math.min(l + 200, 1000))}
                      className="text-xs px-3 py-1 rounded-md bg-white/5 text-gray-400 hover:bg-white/10">
                      Load more
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>

      {/* Raw detail drawer */}
      {detail && (
        <div className="fixed inset-0 z-50 flex justify-end bg-black/50" onClick={() => setDetail(null)}>
          <div className="w-full max-w-2xl h-full bg-[#0d0d0f] border-l border-white/10 p-5 overflow-y-auto" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between mb-3">
              <h3 className="text-base font-semibold text-white">Interaction detail</h3>
              <button onClick={() => setDetail(null)} className="text-gray-400 hover:text-white text-sm">Close</button>
            </div>

            {/* Action toolbar */}
            <div className="flex items-center gap-1.5 mb-4 flex-wrap">
              <button onClick={() => { patchInteraction.mutate({ iid: detail!.id, body: { starred: !detail!.starred } }); setDetail({ ...detail!, starred: !detail!.starred }) }}
                className={`flex items-center gap-1 text-xs px-2 py-1 rounded-md border ${detail.starred ? 'text-amber-300 border-amber-500/30 bg-amber-500/10' : 'text-gray-400 border-white/10 hover:bg-white/5'}`}>
                <Star className={`h-3 w-3 ${detail.starred ? 'fill-amber-400' : ''}`} /> {detail.starred ? 'Starred' : 'Star'}
              </button>
              {detail.remote_ip && (
                <button onClick={() => promoteIOC.mutate(detail!.id)} title="Add source IP to IOC store"
                  className="flex items-center gap-1 text-xs px-2 py-1 rounded-md border text-rose-300 border-rose-500/20 bg-rose-500/10 hover:bg-rose-500/20">
                  <Crosshair className="h-3 w-3" /> Promote IOC
                </button>
              )}
              <button onClick={() => downloadInteraction(detail!)} title="Download as JSON"
                className="flex items-center gap-1 text-xs px-2 py-1 rounded-md border text-gray-400 border-white/10 hover:bg-white/5">
                <FileJson className="h-3 w-3" /> JSON
              </button>
              {(detail.protocol === 'http' || detail.protocol === 'https') && (
                <>
                  <button onClick={() => copy(toFetch(detail!, parseRaw(detail!.raw_request ?? '')), 'fetch() copied')}
                    className="flex items-center gap-1 text-xs px-2 py-1 rounded-md border text-gray-400 border-white/10 hover:bg-white/5">
                    <FileDown className="h-3 w-3" /> fetch
                  </button>
                  <button onClick={() => copy(toPowerShell(detail!, parseRaw(detail!.raw_request ?? '')), 'PowerShell copied')}
                    className="flex items-center gap-1 text-xs px-2 py-1 rounded-md border text-gray-400 border-white/10 hover:bg-white/5">
                    <TerminalIcon className="h-3 w-3" /> PowerShell
                  </button>
                </>
              )}
            </div>

            <div className="grid grid-cols-2 gap-3 text-sm mb-4">
              <Kv k="Protocol" v={detail.protocol.toUpperCase()} />
              <Kv k="Source IP" v={detail.remote_ip ?? '—'} />
              <Kv k="Host" v={detail.full_host} />
              <Kv k="When" v={new Date(detail.created_at).toLocaleString()} />
              {detail.query_type && <Kv k="Query type" v={detail.query_type} />}
              {detail.method && <Kv k="Method" v={detail.method} />}
              {detail.smtp_from && <Kv k="MAIL FROM" v={detail.smtp_from} />}
              {detail.smtp_to && <Kv k="RCPT TO" v={detail.smtp_to} />}
              {(detail.geo_country || detail.geo_city) && <Kv k="Location" v={[detail.geo_city, detail.geo_country].filter(Boolean).join(', ')} />}
              {detail.asn && <Kv k="ASN" v={detail.asn} />}
              {detail.isp && <Kv k="ISP" v={detail.isp} />}
              {detail.rdns && <Kv k="Reverse DNS" v={detail.rdns} />}
              {(detail.is_proxy || detail.is_hosting) && <Kv k="Network" v={[detail.is_proxy && 'proxy/VPN', detail.is_hosting && 'hosting/datacenter'].filter(Boolean).join(', ')} />}
            </div>

            {/* Note + tags */}
            <div className="mb-4 grid grid-cols-1 gap-2">
              <textarea value={noteDraft} rows={2} placeholder="Add a note (analyst triage)…"
                onChange={e => setNoteDraft(e.target.value)}
                onBlur={() => { if (noteDraft !== (detail!.note ?? '')) { patchInteraction.mutate({ iid: detail!.id, body: { note: noteDraft } }); setDetail({ ...detail!, note: noteDraft }) } }}
                className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200" />
            </div>

            {(() => {
              const parsed = parseRaw(detail.raw_request ?? '')
              const queryStr = (detail.path?.split('?')[1]) ?? ''
              const decodeSeed = parsed.body || decodeURIComponent(queryStr || '') || parsed.requestLine
              return (
                <>
                  {/* Parsed headers */}
                  {parsed.headers.length > 0 && (
                    <div className="mb-4">
                      <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                        Headers
                        {(detail.protocol === 'http' || detail.protocol === 'https') && (
                          <button onClick={() => copy(toCurl(detail!, parsed), 'curl copied')}
                            className="flex items-center gap-1 text-[11px] text-gray-400 hover:text-white normal-case font-normal">
                            <Copy className="h-3 w-3" /> Copy as curl
                          </button>
                        )}
                      </div>
                      <div className="rounded-lg border border-white/5 overflow-hidden">
                        {parsed.headers.map((h, i) => (
                          <div key={i} className="flex text-xs border-b border-white/5 last:border-0">
                            <span className="px-2 py-1 text-gray-400 font-mono w-40 shrink-0 truncate bg-black/20">{h.name}</span>
                            <span className="px-2 py-1 text-gray-200 font-mono break-all">{h.value}</span>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Body (JSON pretty-printed when applicable) */}
                  {parsed.body && (
                    <div className="mb-4">
                      <div className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-1.5 flex items-center justify-between">
                        Body
                        <button onClick={() => copy(parsed.body, 'Body copied')} className="flex items-center gap-1 text-[11px] text-gray-400 hover:text-white normal-case font-normal"><Copy className="h-3 w-3" /> copy</button>
                      </div>
                      <pre className="bg-black/60 rounded-lg p-3 text-xs text-gray-300 font-mono whitespace-pre-wrap break-all border border-white/5 max-h-64 overflow-y-auto">{prettyBody(parsed.body)}</pre>
                    </div>
                  )}

                  {/* Smart decode */}
                  <SmartDecodePanel initial={decodeSeed} />

                  {/* Raw */}
                  <div className="text-xs text-gray-400 mb-1 mt-4 flex items-center justify-between">
                    Raw request
                    <button onClick={() => copy(detail!.raw_request ?? '')} className="flex items-center gap-1 hover:text-white"><Copy className="h-3 w-3" /> copy</button>
                  </div>
                  <pre className="bg-black/60 rounded-lg p-3 text-xs text-gray-400 font-mono whitespace-pre-wrap break-all border border-white/5 max-h-40 overflow-y-auto">
                    {detail!.raw_request || '(empty)'}
                  </pre>
                </>
              )
            })()}
          </div>
        </div>
      )}

      {rulesOpen && selected && (
        <RulesModal clientId={selected.id} onClose={() => setRulesOpen(false)} />
      )}
    </div>
  )
}

// RulesModal manages a session's conditional response rules (match → response).
function RulesModal({ clientId, onClose }: { clientId: string; onClose: () => void }) {
  const qc = useQueryClient()
  const { data: rules = [] } = useQuery({ queryKey: ['oob-rules', clientId], queryFn: () => oobApi.listRules(clientId) })
  const blank = { name: '', match_method: '', match_path_prefix: '', match_path_sub: '', status: 200, content_type: 'text/plain', body: '', priority: 0 }
  const [draft, setDraft] = useState(blank)

  const create = useMutation({
    mutationFn: () => oobApi.createRule(clientId, draft),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['oob-rules', clientId] }); setDraft(blank); toast.success('Rule added') },
    onError: (e: any) => toast.error(e?.response?.data?.error ?? 'Add failed'),
  })
  const del = useMutation({
    mutationFn: (rid: string) => oobApi.deleteRule(clientId, rid),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['oob-rules', clientId] }),
  })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4" onClick={onClose}>
      <div className="w-full max-w-2xl max-h-[85vh] bg-[#0d0d0f] border border-white/10 rounded-xl p-5 overflow-y-auto" onClick={e => e.stopPropagation()}>
        <div className="flex items-center justify-between mb-1">
          <h3 className="text-base font-semibold text-white flex items-center gap-2"><ListTree className="h-4 w-4" /> Response rules</h3>
          <button onClick={onClose} className="text-gray-400 hover:text-white text-sm">Close</button>
        </div>
        <p className="text-[11px] text-gray-500 mb-3">First matching rule (lowest priority number) wins; if none match, the session default response is used.</p>

        {/* Existing rules */}
        <div className="space-y-1.5 mb-4">
          {rules.length === 0 && <div className="text-xs text-gray-600 py-2">No rules yet — the default response applies to every request.</div>}
          {rules.map(r => (
            <div key={r.id} className="flex items-center gap-2 text-xs rounded-lg border border-white/5 bg-black/20 px-2.5 py-1.5">
              <span className="text-gray-500 w-6 shrink-0">#{r.priority}</span>
              <span className="font-mono text-gray-300 truncate flex-1">
                {ruleCond(r)} <span className="text-gray-600">→</span> <span className="text-emerald-400">{r.status}</span> {r.content_type}
              </span>
              <button onClick={() => del.mutate(r.id)} className="p-1 text-gray-500 hover:text-rose-400 shrink-0"><Trash2 className="h-3.5 w-3.5" /></button>
            </div>
          ))}
        </div>

        {/* Add rule */}
        <div className="rounded-lg border border-white/10 bg-black/20 p-3 space-y-2">
          <div className="text-[10px] font-bold uppercase tracking-wider text-gray-400">Add rule</div>
          <div className="grid grid-cols-2 gap-2">
            <input placeholder="Name (optional)" value={draft.name} onChange={e => setDraft(d => ({ ...d, name: e.target.value }))} className="bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200" />
            <input type="number" placeholder="Priority" value={draft.priority} onChange={e => setDraft(d => ({ ...d, priority: Number(e.target.value) }))} className="bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200" />
            <input placeholder="Match method (e.g. POST)" value={draft.match_method} onChange={e => setDraft(d => ({ ...d, match_method: e.target.value }))} className="bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
            <input placeholder="Path prefix (e.g. /admin)" value={draft.match_path_prefix} onChange={e => setDraft(d => ({ ...d, match_path_prefix: e.target.value }))} className="bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
            <input placeholder="Path contains" value={draft.match_path_sub} onChange={e => setDraft(d => ({ ...d, match_path_sub: e.target.value }))} className="bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
            <div className="flex gap-2">
              <input type="number" placeholder="Status" value={draft.status} onChange={e => setDraft(d => ({ ...d, status: Number(e.target.value) }))} className="w-20 bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200" />
              <input placeholder="Content-Type" value={draft.content_type} onChange={e => setDraft(d => ({ ...d, content_type: e.target.value }))} className="flex-1 bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
            </div>
          </div>
          <textarea placeholder="Response body (optional)" value={draft.body} rows={2} onChange={e => setDraft(d => ({ ...d, body: e.target.value }))} className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono" />
          <div className="flex justify-end">
            <button onClick={() => create.mutate()} disabled={create.isPending} className="flex items-center gap-1.5 text-xs px-3 py-1 rounded-md bg-emerald-500/10 text-emerald-300 hover:bg-emerald-500/20 border border-emerald-500/20 disabled:opacity-40">
              <Plus className="h-3 w-3" /> Add rule
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

function ruleCond(r: OobRule): string {
  const parts: string[] = []
  if (r.match_method) parts.push(r.match_method)
  if (r.match_path_prefix) parts.push(`path^="${r.match_path_prefix}"`)
  if (r.match_path_sub) parts.push(`path~="${r.match_path_sub}"`)
  return parts.length ? parts.join(' & ') : 'any request'
}

// headersToText serialises a stored JSON header map into "Name: value" lines.
function headersToText(json: string): string {
  if (!json) return ''
  try {
    const m = JSON.parse(json) as Record<string, string>
    return Object.entries(m).map(([k, v]) => `${k}: ${v}`).join('\n')
  } catch { return '' }
}

// textToHeaders parses "Name: value" lines back into a header map.
function textToHeaders(text: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const line of text.split('\n')) {
    const c = line.indexOf(':')
    if (c > 0) {
      const k = line.slice(0, c).trim()
      const v = line.slice(c + 1).trim()
      if (k) out[k] = v
    }
  }
  return out
}

// parseRaw splits a captured raw HTTP dump into request line, headers and body.
function parseRaw(raw: string): { requestLine: string; headers: { name: string; value: string }[]; body: string } {
  const idx = raw.indexOf('\r\n\r\n')
  const head = idx >= 0 ? raw.slice(0, idx) : raw
  const body = idx >= 0 ? raw.slice(idx + 4) : ''
  const lines = head.split('\r\n')
  const headers = lines.slice(1).map(l => {
    const c = l.indexOf(':')
    return c > 0 ? { name: l.slice(0, c).trim(), value: l.slice(c + 1).trim() } : null
  }).filter(Boolean) as { name: string; value: string }[]
  return { requestLine: lines[0] ?? '', headers, body }
}

// downloadInteraction saves one captured interaction as a JSON file.
function downloadInteraction(it: OobInteraction) {
  const blob = new Blob([JSON.stringify(it, null, 2)], { type: 'application/json' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = `oob-${it.id}.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}

function reqHeaders(parsed: ReturnType<typeof parseRaw>) {
  return parsed.headers.filter(h => !['host', 'content-length'].includes(h.name.toLowerCase()))
}

// toFetch reconstructs an equivalent browser fetch() call.
function toFetch(it: OobInteraction, parsed: ReturnType<typeof parseRaw>): string {
  const scheme = it.protocol === 'https' ? 'https' : 'http'
  const url = `${scheme}://${it.full_host}${it.path ?? ''}`
  const headers: Record<string, string> = {}
  for (const h of reqHeaders(parsed)) headers[h.name] = h.value
  const opts: Record<string, unknown> = { method: it.method ?? 'GET', headers }
  if (parsed.body) opts.body = parsed.body
  return `fetch(${JSON.stringify(url)}, ${JSON.stringify(opts, null, 2)})`
}

// toPowerShell reconstructs an equivalent Invoke-WebRequest command.
function toPowerShell(it: OobInteraction, parsed: ReturnType<typeof parseRaw>): string {
  const scheme = it.protocol === 'https' ? 'https' : 'http'
  const url = `${scheme}://${it.full_host}${it.path ?? ''}`
  const hdr = reqHeaders(parsed).map(h => `  '${h.name}' = '${h.value.replace(/'/g, "''")}'`).join('\n')
  let s = `$headers = @{\n${hdr}\n}\nInvoke-WebRequest -Uri '${url}' -Method ${it.method ?? 'GET'} -Headers $headers`
  if (parsed.body) s += ` -Body '${parsed.body.replace(/'/g, "''")}'`
  return s
}

// prettyBody pretty-prints a JSON body, leaving anything else untouched.
function prettyBody(body: string): string {
  const t = body.trim()
  if ((t.startsWith('{') && t.endsWith('}')) || (t.startsWith('[') && t.endsWith(']'))) {
    try { return JSON.stringify(JSON.parse(t), null, 2) } catch { /* not JSON */ }
  }
  return body
}

// toCurl reconstructs an equivalent curl command for an HTTP interaction.
function toCurl(it: OobInteraction, parsed: ReturnType<typeof parseRaw>): string {
  const scheme = it.protocol === 'https' ? 'https' : 'http'
  let s = `curl -X ${it.method ?? 'GET'} '${scheme}://${it.full_host}${it.path ?? ''}'`
  for (const h of parsed.headers) {
    if (['host', 'content-length'].includes(h.name.toLowerCase())) continue
    s += ` \\\n  -H '${h.name}: ${h.value.replace(/'/g, "'\\''")}'`
  }
  if (parsed.body) s += ` \\\n  --data-raw '${parsed.body.replace(/'/g, "'\\''")}'`
  return s
}

const CODEC_COLOR: Record<string, string> = {
  url: 'text-sky-400', base64: 'text-emerald-400', base32: 'text-emerald-400',
  hex: 'text-amber-400', html: 'text-purple-400', unicode: 'text-pink-400',
  gzip: 'text-orange-400', zlib: 'text-orange-400', jwt: 'text-rose-400',
}

// SmartDecodePanel auto-detects and recursively decodes the seed value, showing
// every layer. Editable so the operator can paste any captured string.
function SmartDecodePanel({ initial }: { initial: string }) {
  const [input, setInput] = useState(initial)
  const [result, setResult] = useState<DecodeResult | null>(null)
  const [loading, setLoading] = useState(false)

  const run = async (val: string) => {
    if (!val.trim()) { setResult(null); return }
    setLoading(true)
    try { setResult(await decodeApi.analyze(val)) }
    catch { toast.error('Decode failed') }
    finally { setLoading(false) }
  }

  useEffect(() => { setInput(initial); run(initial) }, [initial]) // eslint-disable-line react-hooks/exhaustive-deps

  return (
    <div className="mb-4 rounded-lg border border-indigo-500/20 bg-indigo-500/[0.04] p-3">
      <div className="flex items-center justify-between mb-2">
        <div className="flex items-center gap-1.5 text-xs font-semibold text-indigo-300">
          <Wand2 className="h-3.5 w-3.5" /> Smart decode
        </div>
        <button onClick={() => run(input)} disabled={loading}
          className="flex items-center gap-1.5 text-[11px] px-2 py-0.5 rounded bg-indigo-500/15 text-indigo-300 hover:bg-indigo-500/25 disabled:opacity-40">
          <RefreshCw className={`h-3 w-3 ${loading ? 'animate-spin' : ''}`} /> Decode
        </button>
      </div>
      <textarea value={input} onChange={e => setInput(e.target.value)} rows={2}
        placeholder="Paste any encoded string (URL, Base64, Hex, JWT, gzip…)"
        className="w-full bg-black/40 border border-white/10 rounded px-2 py-1 text-xs text-gray-200 font-mono mb-2" />
      {result && result.layers === 0 && (
        <p className="text-[11px] text-gray-500">No known encoding detected — value is already plain.</p>
      )}
      {result && result.layers > 0 && (
        <div className="space-y-1.5">
          {result.steps.map((s, i) => (
            <div key={i} className="rounded border border-white/5 bg-black/30">
              <div className="flex items-center gap-2 px-2 py-1 border-b border-white/5">
                <span className="text-[10px] text-gray-500">#{i + 1}</span>
                <span className={`text-[10px] font-bold uppercase ${CODEC_COLOR[s.codec] ?? 'text-gray-300'}`}>{s.label}</span>
                {s.binary && <span className="text-[10px] text-amber-400">binary</span>}
                {s.note && <span className="text-[10px] text-gray-500">· {s.note}</span>}
                <button onClick={() => copy(s.output, 'Layer copied')} className="ml-auto text-gray-500 hover:text-white"><Copy className="h-3 w-3" /></button>
              </div>
              <pre className="px-2 py-1 text-[11px] text-gray-200 font-mono whitespace-pre-wrap break-all max-h-32 overflow-y-auto">{s.output}</pre>
            </div>
          ))}
          <div className="text-[11px] text-emerald-400 flex items-center gap-1.5 pt-1">
            <CheckCircle2 className="h-3.5 w-3.5" /> Fully decoded in {result.layers} layer{result.layers > 1 ? 's' : ''}
          </div>
        </div>
      )}
    </div>
  )
}

function Fact({ icon: Icon, label, value }: { icon: typeof Globe; label: string; value: string }) {
  return (
    <div className="rounded-xl border border-white/5 bg-[#121214] p-3">
      <div className="flex items-center gap-1.5 text-[10px] uppercase tracking-wider text-gray-500 mb-1">
        <Icon className="h-3 w-3" /> {label}
      </div>
      <div className="text-sm text-gray-200 font-mono truncate" title={value}>{value}</div>
    </div>
  )
}

function SessionRow({ c, active, onSelect, onDelete }: { c: OobClient; active: boolean; onSelect: () => void; onDelete: () => void }) {
  return (
    <div onClick={onSelect}
      className={`group flex items-center justify-between gap-2 p-2.5 rounded-lg cursor-pointer border ${
        active ? 'bg-rose-500/10 border-rose-500/20' : 'border-transparent hover:bg-white/5'
      }`}>
      <div className="min-w-0">
        <div className="text-sm font-medium text-gray-200 truncate">{c.name}</div>
        <div className="text-[11px] text-gray-500 flex items-center gap-2">
          <span>{c.interaction_count} hits</span>
          {c.last_seen_at && <span>· {timeAgo(c.last_seen_at)}</span>}
        </div>
      </div>
      <button onClick={(e) => { e.stopPropagation(); onDelete() }}
        className="p-1.5 text-gray-500 hover:text-rose-400 hover:bg-rose-400/10 rounded-md opacity-0 group-hover:opacity-100 shrink-0">
        <Trash2 className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

function CmdRow({ label, cmd, display }: { label: string; cmd: string; display?: string }) {
  const shown = display ?? cmd
  return (
    <div className="flex items-center gap-2 mb-1 last:mb-0">
      <span className="text-[10px] font-bold text-gray-500 w-10 shrink-0">{label}</span>
      <code className="flex-1 text-[11px] text-gray-300 font-mono bg-black/40 rounded px-2 py-1 truncate" title={shown}>{shown || '— select a session —'}</code>
      <button onClick={() => cmd && copy(cmd, 'Command copied')} disabled={!cmd} className="p-1 text-gray-500 hover:text-white shrink-0 disabled:opacity-30">
        <Copy className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}


function PayloadRow({ label, value }: { label: string; value: string }) {
  return (
    <div className="flex items-center gap-2">
      <span className="text-[10px] font-bold text-gray-500 w-12 shrink-0">{label}</span>
      <code className="flex-1 text-xs text-gray-300 font-mono bg-black/40 rounded px-2 py-1 truncate" title={value}>{value}</code>
      <button onClick={() => copy(value, `${label} payload copied`)} className="p-1 text-gray-500 hover:text-white shrink-0">
        <Copy className="h-3.5 w-3.5" />
      </button>
    </div>
  )
}

function Kv({ k, v }: { k: string; v: string }) {
  return (
    <div>
      <div className="text-[10px] uppercase tracking-wider text-gray-500">{k}</div>
      <div className="text-gray-200 font-mono break-all">{v}</div>
    </div>
  )
}
