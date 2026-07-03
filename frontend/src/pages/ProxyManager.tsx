import { useCallback, useEffect, useRef, useState } from 'react'
import {
  Plus, Trash2, Power, Activity, RefreshCw, Radio, Globe,
  CheckCircle2, XCircle, Pencil, X, Eraser, ArrowRightLeft,
} from 'lucide-react'
import {
  proxyApi, type ProxyProfile, type ProxyFlow, type ProxyFlowStats, type ProxyProfilePayload,
} from '@/api/proxy'

const emptyForm: ProxyProfilePayload = { name: '', url: '', no_proxy: '', fallback_direct: false }

function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0
  let v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}

function statusColor(s: number): string {
  if (s === 0) return 'text-gray-400'
  if (s >= 500) return 'text-red-400'
  if (s >= 400) return 'text-amber-400'
  return 'text-emerald-400'
}

export default function ProxyManager() {
  const [profiles, setProfiles] = useState<ProxyProfile[]>([])
  const [flows, setFlows] = useState<ProxyFlow[]>([])
  const [stats, setStats] = useState<ProxyFlowStats | null>(null)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [form, setForm] = useState<ProxyProfilePayload>(emptyForm)

  const [history, setHistory] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [hostFilter, setHostFilter] = useState('')
  const timer = useRef<number | null>(null)

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text })
    window.setTimeout(() => setMsg(null), 4000)
  }

  const loadProfiles = useCallback(async () => {
    try { setProfiles(await proxyApi.list()) } catch { /* ignore */ }
  }, [])

  const loadFlows = useCallback(async () => {
    try {
      const [f, s] = await Promise.all([
        proxyApi.flows({ limit: 200, history, host: hostFilter || undefined }),
        proxyApi.flowStats(),
      ])
      setFlows(f)
      setStats(s)
    } catch { /* ignore */ }
  }, [history, hostFilter])

  useEffect(() => { loadProfiles(); loadFlows() }, [loadProfiles, loadFlows])

  useEffect(() => {
    if (timer.current) { window.clearInterval(timer.current); timer.current = null }
    if (autoRefresh && !history) {
      timer.current = window.setInterval(loadFlows, 3000)
    }
    return () => { if (timer.current) window.clearInterval(timer.current) }
  }, [autoRefresh, history, loadFlows])

  const submitForm = async () => {
    if (!form.name.trim() || !form.url.trim()) { flash('err', 'Name and URL are required'); return }
    try {
      if (editId != null) { await proxyApi.update(editId, form); flash('ok', 'Proxy updated') }
      else { await proxyApi.create(form); flash('ok', 'Proxy added') }
      setShowForm(false); setEditId(null); setForm(emptyForm)
      loadProfiles()
    } catch (e: unknown) { flash('err', errText(e)) }
  }

  const onEdit = (p: ProxyProfile) => {
    setEditId(p.id)
    setForm({ name: p.name, url: p.url, no_proxy: p.no_proxy, fallback_direct: p.fallback_direct })
    setShowForm(true)
  }

  const act = async (fn: () => Promise<unknown>, ok: string) => {
    try { await fn(); flash('ok', ok); loadProfiles() } catch (e: unknown) { flash('err', errText(e)) }
  }

  const activeProfile = profiles.find(p => p.is_active)

  return (
    <div className="p-6 space-y-6 text-gray-200">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <ArrowRightLeft className="w-6 h-6 text-indigo-400" /> Proxy Manager
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Manage the egress proxy pool, switch the active proxy at runtime, and watch the outbound flow log.
          </p>
        </div>
        <div className="text-sm">
          {activeProfile
            ? <span className="px-3 py-1 rounded-full bg-indigo-500/20 text-indigo-300">Active: {activeProfile.name}</span>
            : <span className="px-3 py-1 rounded-full bg-gray-700 text-gray-300">Direct (no proxy)</span>}
        </div>
      </div>

      {msg && (
        <div className={`rounded-md px-4 py-2 text-sm ${msg.kind === 'ok' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}`}>
          {msg.text}
        </div>
      )}

      {/* Proxy pool */}
      <section className="bg-gray-800/50 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <h2 className="font-medium flex items-center gap-2"><Globe className="w-4 h-4" /> Proxy pool</h2>
          <div className="flex gap-2">
            <button onClick={() => act(() => proxyApi.deactivate(), 'Switched to direct')}
              className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600">Use direct</button>
            <button onClick={() => { setEditId(null); setForm(emptyForm); setShowForm(true) }}
              className="text-xs px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500 flex items-center gap-1">
              <Plus className="w-3.5 h-3.5" /> Add proxy
            </button>
          </div>
        </div>

        {showForm && (
          <div className="px-4 py-3 border-b border-gray-700 bg-gray-900/40 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{editId != null ? 'Edit proxy' : 'New proxy'}</span>
              <button onClick={() => { setShowForm(false); setEditId(null) }} className="text-gray-400 hover:text-gray-200"><X className="w-4 h-4" /></button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                placeholder="Name (e.g. Tor local, DC residential)"
                className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <input value={form.url} onChange={e => setForm({ ...form, url: e.target.value })}
                placeholder="socks5://127.0.0.1:9050 or http(s)://user:pass@host:port"
                className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <input value={form.no_proxy} onChange={e => setForm({ ...form, no_proxy: e.target.value })}
                placeholder="no_proxy (comma-separated, optional)"
                className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={!!form.fallback_direct}
                  onChange={e => setForm({ ...form, fallback_direct: e.target.checked })} />
                Fall back to direct if this proxy is down
              </label>
            </div>
            <div className="flex justify-end gap-2">
              <button onClick={() => { setShowForm(false); setEditId(null) }} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600">Cancel</button>
              <button onClick={submitForm} className="text-xs px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500">{editId != null ? 'Save' : 'Add'}</button>
            </div>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-gray-400 text-xs uppercase">
              <tr className="border-b border-gray-700">
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">URL</th>
                <th className="text-left px-4 py-2">Health</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {profiles.length === 0 && (
                <tr><td colSpan={4} className="px-4 py-6 text-center text-gray-500">No proxies yet. Add one to route egress traffic through it.</td></tr>
              )}
              {profiles.map(p => (
                <tr key={p.id} className={`border-b border-gray-800 ${p.is_active ? 'bg-indigo-500/5' : ''}`}>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      {p.is_active && <Power className="w-3.5 h-3.5 text-indigo-400" />}
                      <span className="font-medium">{p.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-400">{p.url}</td>
                  <td className="px-4 py-2">
                    {p.last_check
                      ? (p.healthy
                        ? <span className="flex items-center gap-1 text-emerald-400"><CheckCircle2 className="w-3.5 h-3.5" />{p.latency_ms}ms</span>
                        : <span className="flex items-center gap-1 text-red-400" title={p.last_error}><XCircle className="w-3.5 h-3.5" />down</span>)
                      : <span className="text-gray-500">not checked</span>}
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex items-center justify-end gap-1">
                      {!p.is_active && (
                        <button onClick={() => act(() => proxyApi.activate(p.id), `Switched to ${p.name}`)}
                          title="Switch to this proxy" className="p-1.5 rounded hover:bg-gray-700 text-indigo-300"><Power className="w-4 h-4" /></button>
                      )}
                      <button onClick={() => act(() => proxyApi.check(p.id), 'Health checked')}
                        title="Health check" className="p-1.5 rounded hover:bg-gray-700 text-sky-300"><Activity className="w-4 h-4" /></button>
                      <button onClick={() => onEdit(p)} title="Edit" className="p-1.5 rounded hover:bg-gray-700 text-gray-300"><Pencil className="w-4 h-4" /></button>
                      <button onClick={() => act(() => proxyApi.remove(p.id), 'Proxy deleted')}
                        title="Delete" className="p-1.5 rounded hover:bg-gray-700 text-red-300"><Trash2 className="w-4 h-4" /></button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Flow log */}
      <section className="bg-gray-800/50 rounded-lg border border-gray-700">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-gray-700">
          <h2 className="font-medium flex items-center gap-2"><Radio className="w-4 h-4" /> Egress flow log</h2>
          <div className="flex flex-wrap items-center gap-2">
            <input value={hostFilter} onChange={e => setHostFilter(e.target.value)} placeholder="filter host…"
              className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1 text-xs" />
            <button onClick={() => setHistory(h => !h)}
              className={`text-xs px-3 py-1.5 rounded-md ${history ? 'bg-indigo-600' : 'bg-gray-700 hover:bg-gray-600'}`}>
              {history ? 'History (DB)' : 'Live'}
            </button>
            {!history && (
              <button onClick={() => setAutoRefresh(a => !a)}
                className={`text-xs px-3 py-1.5 rounded-md flex items-center gap-1 ${autoRefresh ? 'bg-emerald-600' : 'bg-gray-700 hover:bg-gray-600'}`}>
                <RefreshCw className={`w-3.5 h-3.5 ${autoRefresh ? 'animate-spin-slow' : ''}`} /> Auto
              </button>
            )}
            <button onClick={loadFlows} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600">Refresh</button>
            <button onClick={() => act(() => proxyApi.clearFlows(), 'Flows cleared')}
              className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600 flex items-center gap-1"><Eraser className="w-3.5 h-3.5" /> Clear</button>
          </div>
        </div>

        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-4 gap-px bg-gray-700 text-sm">
            <Stat label="Requests (live)" value={String(stats.count)} />
            <Stat label="Downloaded" value={fmtBytes(stats.bytes_in)} />
            <Stat label="Uploaded" value={fmtBytes(stats.bytes_out)} />
            <Stat label="Errors" value={String(stats.errors)} accent={stats.errors > 0 ? 'text-amber-400' : undefined} />
          </div>
        )}

        <div className="overflow-x-auto max-h-[520px]">
          <table className="w-full text-xs">
            <thead className="text-gray-400 uppercase sticky top-0 bg-gray-800">
              <tr className="border-b border-gray-700">
                <th className="text-left px-3 py-2">Time</th>
                <th className="text-left px-3 py-2">Proxy</th>
                <th className="text-left px-3 py-2">Method</th>
                <th className="text-left px-3 py-2">Host</th>
                <th className="text-right px-3 py-2">Status</th>
                <th className="text-right px-3 py-2">Out</th>
                <th className="text-right px-3 py-2">In</th>
                <th className="text-right px-3 py-2">ms</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 && (
                <tr><td colSpan={8} className="px-3 py-6 text-center text-gray-500">No flows recorded yet.</td></tr>
              )}
              {flows.map(f => (
                <tr key={f.id} className="border-b border-gray-800 hover:bg-gray-800/50" title={f.error || f.url}>
                  <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">{new Date(f.created_at).toLocaleTimeString()}</td>
                  <td className="px-3 py-1.5">
                    <span className={`px-1.5 py-0.5 rounded ${f.via_proxy ? 'bg-indigo-500/20 text-indigo-300' : 'bg-gray-700 text-gray-300'}`}>{f.proxy_label}</span>
                  </td>
                  <td className="px-3 py-1.5 font-mono">{f.method}</td>
                  <td className="px-3 py-1.5 font-mono text-gray-300 truncate max-w-[280px]">{f.host}</td>
                  <td className={`px-3 py-1.5 text-right font-mono ${statusColor(f.status)}`}>{f.error ? 'ERR' : (f.status || '—')}</td>
                  <td className="px-3 py-1.5 text-right text-gray-400">{fmtBytes(f.bytes_out)}</td>
                  <td className="px-3 py-1.5 text-right text-gray-400">{fmtBytes(f.bytes_in)}</td>
                  <td className="px-3 py-1.5 text-right text-gray-400">{f.duration_ms}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}

function Stat({ label, value, accent }: { label: string; value: string; accent?: string }) {
  return (
    <div className="bg-gray-800 px-4 py-3">
      <div className="text-xs text-gray-400">{label}</div>
      <div className={`text-lg font-semibold ${accent || 'text-gray-100'}`}>{value}</div>
    </div>
  )
}

function errText(e: unknown): string {
  const anyE = e as { response?: { data?: { error?: string } }; message?: string }
  return anyE?.response?.data?.error || anyE?.message || 'Request failed'
}
