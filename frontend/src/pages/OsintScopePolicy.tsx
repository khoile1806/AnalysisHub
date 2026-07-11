import { useCallback, useEffect, useState } from 'react'
import {
  ShieldCheck, Plus, Trash2, Pencil, X, Save, GripVertical, AlertTriangle,
} from 'lucide-react'
import {
  osintPolicyApi, type OsintScopeRule, type OsintScopeSettings, type OsintScopeRulePayload, type ScopeMode,
} from '@/api/osint'
import { useAuthStore } from '@/store/auth'
import { getErrorMessage } from '@/lib/utils'

// OSINT Scope Policy — admin console for the rules that decide, per situation,
// whether an OSINT scan may run its active (target-touching) collectors. The
// decision is evaluated live at scan launch; this page defines it.

const TARGET_TYPES = ['any', 'domain', 'ip', 'email', 'username', 'phone', 'hash', 'wallet', 'name', 'social_profile']
const SCOPES = ['any', 'internal', 'external']
const EGRESS = ['any', 'anonymized', 'direct']
const ACTIONS: { value: ScopeMode; label: string }[] = [
  { value: 'all', label: 'All collectors' },
  { value: 'passive_only', label: 'Passive only' },
  { value: 'block', label: 'Block' },
]

const emptyRule: OsintScopeRulePayload = {
  priority: 100, name: '', enabled: true,
  match_target_type: 'any', match_scope: 'any', match_egress: 'any',
  action: 'all', require_proxy: false,
}

const ACTION_STYLE: Record<ScopeMode, string> = {
  all: 'text-emerald-400',
  passive_only: 'text-amber-400',
  block: 'text-red-400',
}

function errText(e: unknown): string {
  return getErrorMessage(e)
}

export function ScopePolicyPanel() {
  const isAdmin = useAuthStore(s => s.user?.role === 'admin')
  const [rules, setRules] = useState<OsintScopeRule[]>([])
  const [settings, setSettings] = useState<OsintScopeSettings | null>(null)
  const [msg, setMsg] = useState<{ kind: 'ok' | 'err'; text: string } | null>(null)
  const [showForm, setShowForm] = useState(false)
  const [editId, setEditId] = useState<number | null>(null)
  const [form, setForm] = useState<OsintScopeRulePayload>(emptyRule)
  const [domains, setDomains] = useState('')

  const flash = (kind: 'ok' | 'err', text: string) => {
    setMsg({ kind, text }); window.setTimeout(() => setMsg(null), 4000)
  }

  const load = useCallback(async () => {
    try {
      const [r, s] = await Promise.all([osintPolicyApi.listRules(), osintPolicyApi.getSettings()])
      setRules(r); setSettings(s); setDomains(s.internal_domains || '')
    } catch (e) { flash('err', errText(e)) }
  }, [])

  useEffect(() => { load() }, [load])

  const saveSettings = async (patch: Partial<Pick<OsintScopeSettings, 'enforce' | 'allow_override' | 'internal_domains'>>) => {
    try {
      const s = await osintPolicyApi.updateSettings(patch)
      setSettings(s); setDomains(s.internal_domains || ''); flash('ok', 'Settings saved')
    } catch (e) { flash('err', errText(e)) }
  }

  const submitForm = async () => {
    if (!form.name.trim()) { flash('err', 'Name is required'); return }
    try {
      if (editId != null) { await osintPolicyApi.updateRule(editId, form); flash('ok', 'Rule updated') }
      else { await osintPolicyApi.createRule(form); flash('ok', 'Rule added') }
      setShowForm(false); setEditId(null); setForm(emptyRule); load()
    } catch (e) { flash('err', errText(e)) }
  }

  const onEdit = (r: OsintScopeRule) => {
    setEditId(r.id)
    setForm({
      priority: r.priority, name: r.name, enabled: r.enabled,
      match_target_type: r.match_target_type, match_scope: r.match_scope, match_egress: r.match_egress,
      action: r.action, require_proxy: r.require_proxy,
    })
    setShowForm(true)
  }

  const onDelete = async (id: number) => {
    try { await osintPolicyApi.deleteRule(id); flash('ok', 'Rule deleted'); load() }
    catch (e) { flash('err', errText(e)) }
  }

  const toggleEnabled = async (r: OsintScopeRule) => {
    try {
      await osintPolicyApi.updateRule(r.id, {
        priority: r.priority, name: r.name, enabled: !r.enabled,
        match_target_type: r.match_target_type, match_scope: r.match_scope, match_egress: r.match_egress,
        action: r.action, require_proxy: r.require_proxy,
      })
      load()
    } catch (e) { flash('err', errText(e)) }
  }

  return (
    <div className="space-y-6 text-gray-200">
      <div className="flex items-center justify-between flex-wrap gap-2">
        <div>
          <h2 className="text-lg font-semibold flex items-center gap-2">
            <ShieldCheck className="w-5 h-5 text-indigo-400" /> Scope Policy
          </h2>
          <p className="text-sm text-gray-400 mt-1">
            Rules deciding, per situation, whether an OSINT scan may run its active (target-touching) collectors — evaluated live at every scan launch.
          </p>
        </div>
      </div>

      {!isAdmin && (
        <div className="rounded-md px-4 py-2 text-sm bg-amber-500/15 text-amber-300 flex items-center gap-2">
          <AlertTriangle className="w-4 h-4" /> Read-only: only an administrator can change the scope policy.
        </div>
      )}
      {msg && (
        <div className={`rounded-md px-4 py-2 text-sm ${msg.kind === 'ok' ? 'bg-emerald-500/15 text-emerald-300' : 'bg-red-500/15 text-red-300'}`}>{msg.text}</div>
      )}

      {/* Master settings */}
      {settings && (
        <section className="bg-gray-800/50 rounded-lg border border-gray-700 p-4 space-y-3">
          <h2 className="font-medium">Master settings</h2>
          <div className="flex flex-wrap gap-6 text-sm">
            <label className="flex items-center gap-2">
              <input type="checkbox" disabled={!isAdmin} checked={settings.enforce}
                onChange={e => saveSettings({ enforce: e.target.checked })} />
              Enforce policy <span className="text-gray-500">(off = every collector runs)</span>
            </label>
            <label className="flex items-center gap-2">
              <input type="checkbox" disabled={!isAdmin} checked={settings.allow_override}
                onChange={e => saveSettings({ allow_override: e.target.checked })} />
              Allow operator override at launch <span className="text-gray-500">(tighten only)</span>
            </label>
          </div>
          <div>
            <label className="text-xs text-gray-400">Internal domain suffixes (one per line / comma-separated) — matched targets are treated as <em>internal</em> scope without any DNS lookup.</label>
            <textarea value={domains} disabled={!isAdmin}
              onChange={e => setDomains(e.target.value)}
              onBlur={() => isAdmin && domains !== (settings.internal_domains || '') && saveSettings({ internal_domains: domains })}
              rows={3} placeholder="corp&#10;local&#10;mycompany.com"
              className="mt-1 w-full bg-gray-900 border border-gray-700 rounded-md px-3 py-2 text-sm font-mono" />
          </div>
        </section>
      )}

      {/* Rules */}
      <section className="bg-gray-800/50 rounded-lg border border-gray-700">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-700">
          <h2 className="font-medium">Rules <span className="text-xs text-gray-500">(lowest priority evaluated first; first match wins)</span></h2>
          {isAdmin && (
            <button onClick={() => { setEditId(null); setForm(emptyRule); setShowForm(true) }}
              className="text-xs px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500 flex items-center gap-1"><Plus className="w-3.5 h-3.5" /> Add rule</button>
          )}
        </div>

        {showForm && isAdmin && (
          <div className="px-4 py-3 border-b border-gray-700 bg-gray-900/40 space-y-3">
            <div className="flex items-center justify-between">
              <span className="text-sm font-medium">{editId != null ? 'Edit rule' : 'New rule'}</span>
              <button onClick={() => { setShowForm(false); setEditId(null) }} className="text-gray-400 hover:text-gray-200"><X className="w-4 h-4" /></button>
            </div>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
              <label className="flex flex-col gap-1">Name
                <input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })}
                  className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1.5" placeholder="e.g. External + anonymized" />
              </label>
              <label className="flex flex-col gap-1">Priority
                <input type="number" value={form.priority} onChange={e => setForm({ ...form, priority: Number(e.target.value) })}
                  className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1.5" />
              </label>
              <label className="flex flex-col gap-1">Target type
                <select value={form.match_target_type} onChange={e => setForm({ ...form, match_target_type: e.target.value })}
                  className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1.5">
                  {TARGET_TYPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="flex flex-col gap-1">Scope
                <select value={form.match_scope} onChange={e => setForm({ ...form, match_scope: e.target.value })}
                  className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1.5">
                  {SCOPES.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="flex flex-col gap-1">Egress
                <select value={form.match_egress} onChange={e => setForm({ ...form, match_egress: e.target.value })}
                  className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1.5">
                  {EGRESS.map(t => <option key={t} value={t}>{t}</option>)}
                </select>
              </label>
              <label className="flex flex-col gap-1">Action
                <select value={form.action} onChange={e => setForm({ ...form, action: e.target.value as ScopeMode })}
                  className="bg-gray-900 border border-gray-700 rounded-md px-2 py-1.5">
                  {ACTIONS.map(a => <option key={a.value} value={a.value}>{a.label}</option>)}
                </select>
              </label>
              <label className="flex items-center gap-2 mt-5">
                <input type="checkbox" checked={form.require_proxy} onChange={e => setForm({ ...form, require_proxy: e.target.checked })} />
                Require proxy
              </label>
              <label className="flex items-center gap-2 mt-5">
                <input type="checkbox" checked={form.enabled} onChange={e => setForm({ ...form, enabled: e.target.checked })} />
                Enabled
              </label>
            </div>
            <p className="text-[11px] text-gray-500">
              “Require proxy” downgrades an <em>All</em> action to <em>Passive only</em> whenever egress is direct — active collectors run only once traffic is anonymized.
            </p>
            <div className="flex justify-end gap-2">
              <button onClick={() => { setShowForm(false); setEditId(null) }} className="text-xs px-3 py-1.5 rounded-md bg-gray-700 hover:bg-gray-600">Cancel</button>
              <button onClick={submitForm} className="text-xs px-3 py-1.5 rounded-md bg-indigo-600 hover:bg-indigo-500 flex items-center gap-1"><Save className="w-3.5 h-3.5" /> {editId != null ? 'Save' : 'Add'}</button>
            </div>
          </div>
        )}

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead className="text-gray-400 text-xs uppercase">
              <tr className="border-b border-gray-700">
                <th className="text-left px-4 py-2">#</th>
                <th className="text-left px-4 py-2">Name</th>
                <th className="text-left px-4 py-2">When target type</th>
                <th className="text-left px-4 py-2">Scope</th>
                <th className="text-left px-4 py-2">Egress</th>
                <th className="text-left px-4 py-2">Action</th>
                <th className="text-left px-4 py-2">Proxy</th>
                <th className="text-right px-4 py-2">Actions</th>
              </tr>
            </thead>
            <tbody>
              {rules.length === 0 && (
                <tr><td colSpan={8} className="px-4 py-6 text-center text-gray-500">No rules — every scan runs all collectors.</td></tr>
              )}
              {rules.map(r => (
                <tr key={r.id} className={`border-b border-gray-800 ${!r.enabled ? 'opacity-45' : ''}`}>
                  <td className="px-4 py-2 text-gray-500 font-mono flex items-center gap-1"><GripVertical className="w-3 h-3" />{r.priority}</td>
                  <td className="px-4 py-2 font-medium">{r.name}</td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-400">{r.match_target_type}</td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-400">{r.match_scope}</td>
                  <td className="px-4 py-2 font-mono text-xs text-gray-400">{r.match_egress}</td>
                  <td className={`px-4 py-2 font-mono text-xs font-semibold ${ACTION_STYLE[r.action]}`}>{r.action}</td>
                  <td className="px-4 py-2 text-xs text-gray-400">{r.require_proxy ? 'required' : '—'}</td>
                  <td className="px-4 py-2">
                    <div className="flex items-center justify-end gap-1">
                      {isAdmin ? (
                        <>
                          <button onClick={() => toggleEnabled(r)} title={r.enabled ? 'Disable' : 'Enable'}
                            className="text-[10px] px-1.5 py-0.5 rounded border border-slate-700 hover:bg-gray-700">{r.enabled ? 'on' : 'off'}</button>
                          <button onClick={() => onEdit(r)} title="Edit" className="p-1.5 rounded hover:bg-gray-700 text-gray-300"><Pencil className="w-4 h-4" /></button>
                          <button onClick={() => onDelete(r.id)} title="Delete" className="p-1.5 rounded hover:bg-gray-700 text-red-300"><Trash2 className="w-4 h-4" /></button>
                        </>
                      ) : <span className="text-[10px] text-gray-600">{r.enabled ? 'enabled' : 'disabled'}</span>}
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </section>
    </div>
  )
}
