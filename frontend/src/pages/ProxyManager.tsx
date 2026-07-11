import { Fragment, useCallback, useEffect, useRef, useState } from 'react'
import {
  Plus, Trash2, Power, Activity, RefreshCw, Radio, Globe, CheckCircle2, XCircle,
  Pencil, X, Eraser, ArrowRightLeft, Fingerprint, ShieldAlert, ShieldCheck, Download, BarChart3,
  Zap, Layers, Upload, FlaskConical,
} from 'lucide-react'
import {
  proxyApi, type ProxyProfile, type ProxyFlow, type ProxyFlowStats,
  type ProxyProfilePayload, type ProxyPoolMode, type ProxyAnalytics, type ProxyLane,
  type ProxyHealthHistory,
} from '@/api/proxy'
import { getErrorMessage } from '@/lib/utils'

const emptyForm: ProxyProfilePayload = { name: '', url: '', no_proxy: '', fallback_direct: false, lane: 'default', quota_bytes: 0, quota_hard_stop: false }

const LANES: ProxyLane[] = ['default', 'osint', 'vulnscan']
const LANE_STYLE: Record<ProxyLane, string> = {
  default: 'bg-gray-700 text-gray-300',
  osint: 'bg-sky-500/20 text-sky-300',
  vulnscan: 'bg-fuchsia-500/20 text-fuchsia-300',
}

function fmtBytes(n: number): string {
  if (!n) return '0 B'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let i = 0, v = n
  while (v >= 1024 && i < units.length - 1) { v /= 1024; i++ }
  return `${v.toFixed(v < 10 && i > 0 ? 1 : 0)} ${units[i]}`
}

function statusColor(s: number): string {
  if (s === 0) return 'text-gray-400'
  if (s >= 500) return 'text-red-400'
  if (s >= 400) return 'text-amber-400'
  return 'text-emerald-400'
}

function errText(e: unknown): string {
  return getErrorMessage(e)
}

export default function ProxyManager() {
  const [profiles, setProfiles] = useState<ProxyProfile[]>([])
  const [flows, setFlows] = useState<ProxyFlow[]>([])
  const [stats, setStats] = useState<ProxyFlowStats | null>(null)
  const [mode, setMode] = useState<ProxyPoolMode | null>(null)
  const [analytics, setAnalytics] = useState<ProxyAnalytics | null>(null)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)

  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [form, setForm] = useState<ProxyProfilePayload>(emptyForm)

  const [history, setHistory] = useState(false)
  const [autoRefresh, setAutoRefresh] = useState(true)
  const [leakedOnly, setLeakedOnly] = useState(false)
  const [hostFilter, setHostFilter] = useState('')
  const [busyId, setBusyId] = useState<number | null>(null)
  const [showBulk, setShowBulk] = useState(false)
  const [bulkText, setBulkText] = useState('')
  const [bulkLane, setBulkLane] = useState<ProxyLane>('default')
  const [historyFor, setHistoryFor] = useState<number | null>(null)
  const [history24, setHistory24] = useState<ProxyHealthHistory | null>(null)
  const timer = useRef<number | null>(null)

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text }); window.setTimeout(() => setMsg(null), 4000)
  }

  const loadProfiles = useCallback(async () => {
    try { setProfiles(await proxyApi.list()) } catch { /* ignore */ }
  }, [])
  const loadMode = useCallback(async () => {
    try { setMode(await proxyApi.getMode()) } catch { /* ignore */ }
  }, [])
  const loadAnalytics = useCallback(async () => {
    try { setAnalytics(await proxyApi.analytics(24)) } catch { /* ignore */ }
  }, [])
  const loadFlows = useCallback(async () => {
    try {
      const [f, s] = await Promise.all([
        proxyApi.flows({ limit: 200, history, host: hostFilter || undefined, leaked: leakedOnly }),
        proxyApi.flowStats(),
      ])
      setFlows(f); setStats(s)
    } catch { /* ignore */ }
  }, [history, hostFilter, leakedOnly])

  useEffect(() => { loadProfiles(); loadMode(); loadAnalytics() }, [loadProfiles, loadMode, loadAnalytics])
  useEffect(() => { loadFlows() }, [loadFlows])
  useEffect(() => {
    if (timer.current) { window.clearInterval(timer.current); timer.current = null }
    if (autoRefresh && !history) timer.current = window.setInterval(loadFlows, 3000)
    return () => { if (timer.current) window.clearInterval(timer.current) }
  }, [autoRefresh, history, loadFlows])

  const submitForm = async () => {
    if (!form.name.trim() || !form.url.trim()) { flash('err', 'Name and URL are required'); return }
    try {
      if (editId != null) { await proxyApi.update(editId, form); flash('ok', 'Proxy updated') }
      else { await proxyApi.create(form); flash('ok', 'Proxy added') }
      setShowForm(false); setEditId(null); setForm(emptyForm); loadProfiles()
    } catch (e) { flash('err', errText(e)) }
  }

  const onEdit = (p: ProxyProfile) => {
    setEditId(p.id)
    setForm({ name: p.name, url: p.url, no_proxy: p.no_proxy, fallback_direct: p.fallback_direct, lane: p.lane, quota_bytes: p.quota_bytes, quota_hard_stop: p.quota_hard_stop })
    setShowForm(true)
  }

  const toggleKillSwitch = async () => {
    if (!mode) return
    try { setMode(await proxyApi.setMode({ kill_switch: !mode.kill_switch })); flash('ok', `Kill-switch ${!mode.kill_switch ? 'armed' : 'disarmed'}`) }
    catch (e) { flash('err', errText(e)) }
  }

  const doCheckAll = async () => {
    try { setProfiles(await proxyApi.checkAll()); flash('ok', 'All proxies checked') }
    catch (e) { flash('err', errText(e)) }
  }

  const doBulk = async () => {
    if (!bulkText.trim()) { flash('err', 'Paste at least one proxy URL'); return }
    try {
      const r = await proxyApi.bulkCreate(bulkText, bulkLane)
      flash(r.errors.length ? 'err' : 'ok', `Imported ${r.created} proxy(ies)${r.errors.length ? `, ${r.errors.length} skipped` : ''}`)
      setBulkText(''); setShowBulk(false); loadProfiles()
    } catch (e) { flash('err', errText(e)) }
  }

  const doHistory = async (id: number) => {
    if (historyFor === id) { setHistoryFor(null); setHistory24(null); return }
    try {
      const h = await proxyApi.healthHistory(id, 24)
      setHistory24(h); setHistoryFor(id)
    } catch (e) { flash('err', errText(e)) }
  }

  const doLeakTest = async (id: number) => {
    setBusyId(id)
    try {
      const r = await proxyApi.leakTest(id)
      if (r.error) flash('err', `Leak test: ${r.error}`)
      else flash(r.consistent ? 'ok' : 'err', r.consistent
        ? `Exit consistent: ${r.exit_ip} (${Object.keys(r.exit_ips).length} services agree)`
        : `INCONSISTENT exit IPs: ${Object.entries(r.exit_ips).map(([s, ip]) => `${s}=${ip}`).join(', ')}`)
    } catch (e) { flash('err', errText(e)) }
    finally { setBusyId(null) }
  }

  const act = async (fn: () => Promise<unknown>, ok: string, id?: number) => {
    if (id != null) setBusyId(id)
    try { await fn(); flash('ok', ok); loadProfiles() }
    catch (e) { flash('err', errText(e)) }
    finally { setBusyId(null) }
  }

  const changeMode = async (m: string, interval?: number) => {
    try { setMode(await proxyApi.setMode({ mode: m, interval_sec: interval })); flash('ok', `Mode: ${m}`) }
    catch (e) { flash('err', errText(e)) }
  }

  const doExport = async () => {
    try {
      const blob = await proxyApi.exportCsv({ host: hostFilter || undefined, leaked: leakedOnly })
      const url = URL.createObjectURL(blob)
      const a = document.createElement('a')
      a.href = url; a.download = 'proxy-flows.csv'; a.click()
      URL.revokeObjectURL(url)
    } catch (e) { flash('err', errText(e)) }
  }

  const activeProfile = profiles.find(p => p.is_active)
  const coverage = stats ? Math.round(stats.coverage_pct) : 100

  return (
    <div className="p-6 space-y-6 text-gray-200">
      {/* Header */}
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h1 className="text-2xl font-semibold flex items-center gap-2">
            <ArrowRightLeft className="w-6 h-6 text-indigo-400" /> Proxy Manager
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Egress proxy pool, runtime switch, exit-identity, and the outbound flow log with anonymity coverage.
          </p>
        </div>
        <div className="flex items-center gap-2 text-sm">
          {mode && (
            <button onClick={toggleKillSwitch} title="Fail-closed: block all egress when no healthy proxy is available"
              className={`px-3 py-1 rounded-full flex items-center gap-1 ${mode.kill_switch ? 'bg-red-500/25 text-red-300' : 'bg-gray-700 text-gray-400 hover:bg-gray-600'}`}>
              <Zap className="w-3.5 h-3.5" /> Kill-switch {mode.kill_switch ? 'ON' : 'OFF'}
            </button>
          )}
          {activeProfile
            ? <span className="px-3 py-1 rounded-full bg-indigo-500/20 text-indigo-300">Active: {activeProfile.name}{activeProfile.is_tor ? ' · Tor' : ''}</span>
            : <span className="px-3 py-1 rounded-full bg-gray-700 text-gray-300">Direct (no proxy)</span>}
        </div>
      </div>

      {msg && (
        <div className={`rounded-md px-4 py-2 text-sm ${msg.kind === 'ok' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}`}>{msg.text}</div>
      )}

      {/* Anonymity leak banner */}
      {stats && stats.leaked > 0 && (
        <div className="rounded-md px-4 py-3 bg-red-500/15 border border-red-500/40 text-red-200 flex items-center gap-2">
          <ShieldAlert className="w-5 h-5 shrink-0" />
          <span><strong>{stats.leaked}</strong> request(s) went <strong>DIRECT while a proxy was active</strong> — potential identity leak. Use the “Leaked only” filter below to inspect.</span>
        </div>
      )}

      {/* Coverage bar */}
      {stats && (
        <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-4">
          <div className="flex items-center justify-between text-sm mb-2">
            <span className="flex items-center gap-2 font-medium">
              {coverage >= 100 ? <ShieldCheck className="w-4 h-4 text-emerald-400" /> : <ShieldAlert className="w-4 h-4 text-amber-400" />}
              Anonymity coverage (live)
            </span>
            <span className={coverage >= 100 ? 'text-emerald-400' : coverage >= 80 ? 'text-amber-400' : 'text-red-400'}>{coverage}% via proxy</span>
          </div>
          <div className="h-2 rounded-full bg-gray-700 overflow-hidden">
            <div className={`h-full ${coverage >= 100 ? 'bg-emerald-500' : coverage >= 80 ? 'bg-amber-500' : 'bg-red-500'}`} style={{ width: `${coverage}%` }} />
          </div>
          <div className="text-xs text-gray-400 mt-2">{stats.proxied} via proxy · {stats.direct} direct · {stats.leaked} leaked</div>
        </div>
      )}

      {/* Proxy pool */}
      <section className="bg-gray-800/50 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700 flex-wrap gap-2">
          <h2 className="font-medium flex items-center gap-2"><Globe className="w-4 h-4" /> Proxy pool</h2>
          <div className="flex items-center gap-2 flex-wrap">
            {mode && (
              <div className="flex items-center gap-1 text-xs">
                <span className="text-gray-400">Mode:</span>
                {(['manual', 'failover', 'rotate'] as const).map(m => (
                  <button key={m} onClick={() => changeMode(m, mode.interval_sec)}
                    className={`px-2 py-1 rounded ${mode.mode === m ? 'bg-indigo-600' : 'bg-gray-700 hover:bg-gray-600'}`}>{m}</button>
                ))}
                {mode.mode === 'rotate' && (
                  <input type="number" min={30} defaultValue={mode.interval_sec} title="rotate interval (sec)"
                    onBlur={e => changeMode('rotate', Number(e.target.value))}
                    className="w-16 bg-gray-900 border border-gray-700 rounded px-1 py-0.5" />
                )}
              </div>
            )}
            <button onClick={() => act(() => proxyApi.deactivate(), 'Switched to direct')} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600">Use direct</button>
            <button onClick={doCheckAll} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600 flex items-center gap-1"><Activity className="w-3.5 h-3.5" /> Test all</button>
            <button onClick={() => setShowBulk(v => !v)} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600 flex items-center gap-1"><Upload className="w-3.5 h-3.5" /> Bulk</button>
            <button onClick={() => { setEditId(null); setForm(emptyForm); setShowForm(true) }} className="text-xs px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500 flex items-center gap-1"><Plus className="w-3.5 h-3.5" /> Add proxy</button>
          </div>
        </div>

        {showBulk && (
          <div className="px-4 py-3 border-b border-gray-700 bg-gray-900/40 space-y-2">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium flex items-center gap-1"><Upload className="w-4 h-4" /> Bulk import</span>
              <button onClick={() => setShowBulk(false)} className="text-gray-400 hover:text-gray-200"><X className="w-4 h-4" /></button>
            </div>
            <textarea value={bulkText} onChange={e => setBulkText(e.target.value)} rows={4}
              placeholder={'One per line — "name url" or just url\nsocks5://127.0.0.1:9050\nres1 http://user:pass@host:8080'}
              className="w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm font-mono" />
            <div className="flex items-center justify-end gap-2">
              <label className="text-xs text-gray-400 flex items-center gap-1">Lane:
                <select value={bulkLane} onChange={e => setBulkLane(e.target.value as ProxyLane)} className="bg-gray-900 border border-gray-700 rounded px-2 py-1">
                  {LANES.map(l => <option key={l} value={l}>{l}</option>)}
                </select>
              </label>
              <button onClick={doBulk} className="text-xs px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500">Import</button>
            </div>
          </div>
        )}

        {showForm && (
          <div className="px-4 py-3 border-b border-gray-700 bg-gray-900/40 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{editId != null ? 'Edit proxy' : 'New proxy'}</span>
              <button onClick={() => { setShowForm(false); setEditId(null) }} className="text-gray-400 hover:text-gray-200"><X className="w-4 h-4" /></button>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} placeholder="Name (e.g. Tor local, DC residential)" className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <input value={form.url} onChange={e => setForm({ ...form, url: e.target.value })} placeholder="socks5://127.0.0.1:9050 or http(s)://user:pass@host:port" className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <input value={form.no_proxy} onChange={e => setForm({ ...form, no_proxy: e.target.value })} placeholder="no_proxy (comma-separated, optional)" className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <span className="text-gray-400 flex items-center gap-1"><Layers className="w-3.5 h-3.5" /> Lane</span>
                <select value={form.lane ?? 'default'} onChange={e => setForm({ ...form, lane: e.target.value as ProxyLane })}
                  className="flex-1 bg-gray-900 border border-gray-700 rounded-md px-2 py-2">
                  {LANES.map(l => <option key={l} value={l}>{l}</option>)}
                </select>
              </label>
              <input type="number" min={0} value={form.quota_bytes ? Math.round((form.quota_bytes) / (1024 * 1024)) : 0}
                onChange={e => setForm({ ...form, quota_bytes: Math.max(0, Number(e.target.value)) * 1024 * 1024 })}
                placeholder="quota MB (0 = unlimited)" title="Data quota in MB (0 = unlimited)"
                className="bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm" />
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={!!form.quota_hard_stop} onChange={e => setForm({ ...form, quota_hard_stop: e.target.checked })} />
                Hard-stop: auto-deactivate when quota reached
              </label>
              <label className="flex items-center gap-2 text-sm text-gray-300">
                <input type="checkbox" checked={!!form.fallback_direct} onChange={e => setForm({ ...form, fallback_direct: e.target.checked })} />
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
                <th className="text-left px-4 py-2">Lane</th>
                <th className="text-left px-4 py-2">URL</th>
                <th className="text-left px-4 py-2">Exit identity</th>
                <th className="text-left px-4 py-2">Health</th>
                <th className="text-left px-4 py-2">Usage</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {profiles.length === 0 && (
                <tr><td colSpan={7} className="px-4 py-6 text-center text-gray-500">No proxies yet. Add one to route egress traffic through it.</td></tr>
              )}
              {profiles.map(p => (
                <Fragment key={p.id}>
                <tr className={`border-b border-gray-800 ${p.is_active ? 'bg-indigo-500/5' : ''}`}>
                  <td className="px-4 py-2">
                    <div className="flex items-center gap-2">
                      {p.is_active && <Power className="w-3.5 h-3.5 text-indigo-400" />}
                      <span className="font-medium">{p.name}</span>
                    </div>
                  </td>
                  <td className="px-4 py-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded ${LANE_STYLE[p.lane] ?? LANE_STYLE.default}`}>{p.lane}</span>
                  </td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-400">{p.url}</td>
                  <td className="px-4 py-2 text-xs">
                    {p.exit_checked_at
                      ? <div className="flex flex-col">
                          <span className="font-mono text-gray-200 flex items-center gap-1">
                            {p.exit_ip || '—'}
                            {p.is_tor && <span className="px-1 rounded bg-purple-500/25 text-purple-300">Tor</span>}
                            {p.identity_drift && <span className="px-1 rounded bg-amber-500/25 text-amber-300" title={`was ${p.exit_ip_prev}`}>drift</span>}
                          </span>
                          <span className="text-gray-500">{[p.exit_country, p.exit_org].filter(Boolean).join(' · ')}</span>
                        </div>
                      : <span className="text-gray-500">unknown</span>}
                  </td>
                  <td className="px-4 py-2">
                    {p.last_check
                      ? (p.healthy
                        ? <span className="flex items-center gap-1 text-emerald-400"><CheckCircle2 className="w-3.5 h-3.5" />{p.latency_ms}ms</span>
                        : <span className="flex items-center gap-1 text-red-400" title={p.last_error}><XCircle className="w-3.5 h-3.5" />down</span>)
                      : <span className="text-gray-500">not checked</span>}
                  </td>
                  <td className="px-4 py-2 text-xs">
                    {p.quota_bytes > 0
                      ? <span className={p.over_quota ? 'text-red-400' : 'text-gray-400'}>{fmtBytes(p.quota_used_bytes)} / {fmtBytes(p.quota_bytes)}</span>
                      : <span className="text-gray-500">{fmtBytes(p.quota_used_bytes)}</span>}
                  </td>
                  <td className="px-4 py-2">
                    <div className="flex items-center justify-end gap-1">
                      {!p.is_active && <button onClick={() => act(() => proxyApi.activate(p.id), `Switched to ${p.name}`, p.id)} title="Switch to this proxy" className="p-1.5 rounded hover:bg-gray-700 text-indigo-300"><Power className="w-4 h-4" /></button>}
                      <button onClick={() => act(() => proxyApi.check(p.id), 'Health checked', p.id)} title="Health check" className="p-1.5 rounded hover:bg-gray-700 text-sky-300"><Activity className="w-4 h-4" /></button>
                      <button onClick={() => act(() => proxyApi.identity(p.id), 'Exit identity checked', p.id)} title="Check exit IP / Tor" className={`p-1.5 rounded hover:bg-gray-700 text-fuchsia-300 ${busyId === p.id ? 'animate-pulse' : ''}`}><Fingerprint className="w-4 h-4" /></button>
                      <button onClick={() => doLeakTest(p.id)} title="Exit-consistency leak test" className="p-1.5 rounded hover:bg-gray-700 text-amber-300"><FlaskConical className="w-4 h-4" /></button>
                      <button onClick={() => doHistory(p.id)} title="Health history (24h uptime)" className="p-1.5 rounded hover:bg-gray-700 text-emerald-300"><BarChart3 className="w-4 h-4" /></button>
                      <button onClick={() => onEdit(p)} title="Edit" className="p-1.5 rounded hover:bg-gray-700 text-gray-300"><Pencil className="w-4 h-4" /></button>
                      <button onClick={() => act(() => proxyApi.remove(p.id), 'Proxy deleted', p.id)} title="Delete" className="p-1.5 rounded hover:bg-gray-700 text-red-300"><Trash2 className="w-4 h-4" /></button>
                    </div>
                  </td>
                </tr>
                {historyFor === p.id && history24 && (
                  <tr className="border-b border-gray-800 bg-gray-900/40">
                    <td colSpan={7} className="px-4 py-3">
                      {history24.count === 0
                        ? <span className="text-xs text-gray-500">No health samples yet for this proxy.</span>
                        : <div className="flex items-center gap-4">
                            <div>
                              <div className="text-[10px] uppercase text-gray-500">Uptime 24h</div>
                              <div className={`text-lg font-semibold ${history24.uptime_pct >= 99 ? 'text-emerald-400' : history24.uptime_pct >= 90 ? 'text-amber-400' : 'text-red-400'}`}>{Math.round(history24.uptime_pct)}%</div>
                              <div className="text-[10px] text-gray-500">{history24.count} samples</div>
                            </div>
                            <div className="flex-1">
                              <div className="text-[10px] uppercase text-gray-500 mb-1">Latency (ms)</div>
                              <Sparkline samples={history24.samples} />
                            </div>
                          </div>}
                    </td>
                  </tr>
                )}
                </Fragment>
              ))}
            </tbody>
          </table>
        </div>
      </section>

      {/* Analytics (last 24h from history) */}
      {analytics && (analytics.total > 0) && (
        <section className="bg-gray-800/50 rounded-lg border border-gray-700 p-4">
          <div className="flex items-center justify-between mb-3">
            <h2 className="font-medium flex items-center gap-2"><BarChart3 className="w-4 h-4" /> Analytics (last {analytics.since_hours}h)</h2>
            <button onClick={loadAnalytics} className="text-xs px-2 py-1 rounded bg-gray-700 hover:bg-gray-600">Refresh</button>
          </div>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-sm">
            <div>
              <div className="text-xs text-gray-400 mb-1">Top hosts</div>
              <div className="space-y-1">
                {analytics.top_hosts.slice(0, 10).map(h => (
                  <div key={h.host} className="flex justify-between font-mono text-xs">
                    <span className="text-gray-300 truncate max-w-[220px]">{h.host}</span>
                    <span className="text-gray-500">{h.count} · {fmtBytes(h.bytes)}</span>
                  </div>
                ))}
              </div>
            </div>
            <div>
              <div className="text-xs text-gray-400 mb-1">Per proxy</div>
              <div className="space-y-1">
                {analytics.per_proxy.map(p => (
                  <div key={p.proxy_label} className="flex justify-between text-xs">
                    <span className="text-gray-300">{p.proxy_label}</span>
                    <span className="text-gray-500">{p.count} req · {p.errors} err · p50 {Math.round(p.p50_ms)}ms · p95 {Math.round(p.p95_ms)}ms · {fmtBytes(p.bytes_in + p.bytes_out)}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </section>
      )}

      {/* Flow log */}
      <section className="bg-gray-800/50 rounded-lg border border-gray-700">
        <div className="flex flex-wrap items-center justify-between gap-2 px-4 py-3 border-b border-gray-700">
          <h2 className="font-medium flex items-center gap-2"><Radio className="w-4 h-4" /> Egress flow log</h2>
          <div className="flex flex-wrap items-center gap-2">
            <input value={hostFilter} onChange={e => setHostFilter(e.target.value)} placeholder="filter host…" className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1 text-xs" />
            <button onClick={() => setLeakedOnly(v => !v)} className={`text-xs px-3 py-1.5 rounded-md flex items-center gap-1 ${leakedOnly ? 'bg-red-600' : 'bg-gray-700 hover:bg-gray-600'}`}><ShieldAlert className="w-3.5 h-3.5" /> Leaked only</button>
            <button onClick={() => setHistory(h => !h)} className={`text-xs px-3 py-1.5 rounded-md ${history ? 'bg-indigo-600' : 'bg-gray-700 hover:bg-gray-600'}`}>{history ? 'History (DB)' : 'Live'}</button>
            {!history && <button onClick={() => setAutoRefresh(a => !a)} className={`text-xs px-3 py-1.5 rounded-md flex items-center gap-1 ${autoRefresh ? 'bg-emerald-600' : 'bg-gray-700 hover:bg-gray-600'}`}><RefreshCw className="w-3.5 h-3.5" /> Auto</button>}
            <button onClick={loadFlows} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600">Refresh</button>
            <button onClick={doExport} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600 flex items-center gap-1"><Download className="w-3.5 h-3.5" /> CSV</button>
            <button onClick={() => act(() => proxyApi.clearFlows(), 'Flows cleared')} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600 flex items-center gap-1"><Eraser className="w-3.5 h-3.5" /> Clear</button>
          </div>
        </div>

        {stats && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-px bg-gray-700 text-sm">
            <Stat label="Requests" value={String(stats.count)} />
            <Stat label="Downloaded" value={fmtBytes(stats.bytes_in)} />
            <Stat label="Uploaded" value={fmtBytes(stats.bytes_out)} />
            <Stat label="Errors" value={String(stats.errors)} accent={stats.errors > 0 ? 'text-amber-400' : undefined} />
            <Stat label="Leaked" value={String(stats.leaked)} accent={stats.leaked > 0 ? 'text-red-400' : undefined} />
          </div>
        )}

        <div className="overflow-x-auto max-h-[520px]">
          <table className="w-full text-xs">
            <thead className="text-gray-400 uppercase sticky top-0 bg-gray-800">
              <tr className="border-b border-gray-700">
                <th className="text-left px-3 py-2">Time</th>
                <th className="text-left px-3 py-2">Proxy</th>
                <th className="text-left px-3 py-2">Source</th>
                <th className="text-left px-3 py-2">Method</th>
                <th className="text-left px-3 py-2">Host</th>
                <th className="text-left px-3 py-2">TLS</th>
                <th className="text-right px-3 py-2">Status</th>
                <th className="text-right px-3 py-2">Out</th>
                <th className="text-right px-3 py-2">In</th>
                <th className="text-right px-3 py-2">ms</th>
              </tr>
            </thead>
            <tbody>
              {flows.length === 0 && (
                <tr><td colSpan={10} className="px-3 py-6 text-center text-gray-500">No flows recorded yet.</td></tr>
              )}
              {flows.map(f => (
                <tr key={f.id} className={`border-b border-gray-800 hover:bg-gray-800/50 ${f.leaked ? 'bg-red-500/10' : ''}`}
                  title={`${f.url}${f.error ? '\n' + f.error : ''}\nDNS ${f.dns_ms}ms · connect ${f.connect_ms}ms · TLS ${f.tls_ms}ms · TTFB ${f.ttfb_ms}ms${f.content_type ? '\n' + f.content_type : ''}`}>
                  <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">{new Date(f.created_at).toLocaleTimeString()}</td>
                  <td className="px-3 py-1.5">
                    <span className={`px-1.5 py-0.5 rounded ${f.leaked ? 'bg-red-500/25 text-red-300' : f.via_proxy ? 'bg-indigo-500/20 text-indigo-300' : 'bg-gray-700 text-gray-300'}`}>
                      {f.leaked ? 'LEAK' : f.proxy_label}
                    </span>
                  </td>
                  <td className="px-3 py-1.5 text-gray-400">{f.source}</td>
                  <td className="px-3 py-1.5 font-mono">{f.method}</td>
                  <td className="px-3 py-1.5 font-mono text-gray-300 truncate max-w-[260px]">{f.scheme === 'http' ? <span className="text-amber-400">http</span> : ''} {f.host}</td>
                  <td className="px-3 py-1.5 text-gray-500">{f.tls_version || (f.scheme === 'http' ? 'none' : '')}</td>
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

// Sparkline draws latency (ms) over the sampled window as a small polyline, with
// down samples marked red so an outage shows at a glance.
function Sparkline({ samples }: { samples: ProxyHealthHistory['samples'] }) {
  const w = 320, h = 40, pad = 2
  if (samples.length === 0) return null
  const lats = samples.map(s => (s.healthy ? s.latency_ms : 0))
  const max = Math.max(1, ...lats)
  const step = samples.length > 1 ? (w - pad * 2) / (samples.length - 1) : 0
  const y = (v: number) => h - pad - (v / max) * (h - pad * 2)
  const points = samples.map((s, i) => `${pad + i * step},${y(s.healthy ? s.latency_ms : 0)}`).join(' ')
  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none" className="block">
      <polyline points={points} fill="none" stroke="#6366f1" strokeWidth={1.5} vectorEffect="non-scaling-stroke" />
      {samples.map((s, i) => !s.healthy && (
        <circle key={i} cx={pad + i * step} cy={h - pad} r={1.8} fill="#f87171" />
      ))}
    </svg>
  )
}
