import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import toast from 'react-hot-toast'
import { Boxes, Play, Clock, Trash2, Tag, Loader2, RefreshCw, Plus } from 'lucide-react'
import { agentsApi, type Agent } from '@/api/agents'
import {
  fleetApi, FLEET_COLLECTIONS,
  type FleetCollection, type ScheduledCollection,
} from '@/api/fleet'
import { getErrorMessage, safeFormat } from '@/lib/utils'

function parseTags(json?: string): string[] {
  if (!json) return []
  try { const a = JSON.parse(json); return Array.isArray(a) ? a : [] } catch { return [] }
}

const RESULT_CLS: Record<string, string> = {
  done: 'text-emerald-300', pending: 'text-blue-300', error: 'text-red-300',
  offline: 'text-gray-500', timeout: 'text-yellow-300',
}

export default function FleetPage() {
  const qc = useQueryClient()
  const { data: agents = [] } = useQuery({ queryKey: ['agents'], queryFn: agentsApi.list, refetchInterval: 10000 })
  const { data: groups } = useQuery({ queryKey: ['fleet-groups'], queryFn: fleetApi.groups })
  const { data: results = [] } = useQuery({ queryKey: ['fleet-results'], queryFn: () => fleetApi.results(), refetchInterval: 5000 })
  const { data: schedules = [] } = useQuery({ queryKey: ['fleet-schedules'], queryFn: fleetApi.listSchedules })

  // Bulk collect
  const [collection, setCollection] = useState<FleetCollection>('processes')
  const [scopeGroup, setScopeGroup] = useState('')
  const [scopeTag, setScopeTag] = useState('')
  const bulkMut = useMutation({
    mutationFn: () => fleetApi.bulkCollect({ collection, group: scopeGroup || undefined, tag: scopeTag || undefined }),
    onSuccess: (d) => {
      const ok = d.dispatched.filter((x) => x.status === 'dispatched').length
      toast.success(`Dispatched ${collection} to ${ok}/${d.dispatched.length} agent(s)`)
      qc.invalidateQueries({ queryKey: ['fleet-results'] })
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <div className="space-y-6">
      <div>
        <h1 className="flex items-center gap-2 text-xl font-bold text-gray-100"><Boxes className="h-5 w-5 text-emerald-400" /> Fleet</h1>
        <p className="text-sm text-gray-500 mt-0.5">Group endpoints, run a collection across many at once, and schedule recurring collections.</p>
      </div>

      {/* Bulk collect */}
      <div className="card p-4 space-y-3">
        <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2"><Play className="h-4 w-4 text-emerald-400" /> Bulk collection</h3>
        <div className="flex flex-wrap items-end gap-2">
          <label className="text-xs text-gray-400">Collection
            <select className="input mt-1 block" value={collection} onChange={(e) => setCollection(e.target.value as FleetCollection)}>
              {FLEET_COLLECTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
            </select>
          </label>
          <label className="text-xs text-gray-400">Group
            <select className="input mt-1 block" value={scopeGroup} onChange={(e) => setScopeGroup(e.target.value)}>
              <option value="">— any —</option>
              {(groups?.groups ?? []).map((g) => <option key={g.name} value={g.name}>{g.name} ({g.count})</option>)}
            </select>
          </label>
          <label className="text-xs text-gray-400">Tag
            <select className="input mt-1 block" value={scopeTag} onChange={(e) => setScopeTag(e.target.value)}>
              <option value="">— any —</option>
              {(groups?.tags ?? []).map((t) => <option key={t.name} value={t.name}>{t.name} ({t.count})</option>)}
            </select>
          </label>
          <button className="btn-primary flex items-center gap-2" disabled={bulkMut.isPending || (!scopeGroup && !scopeTag)}
            onClick={() => bulkMut.mutate()} title={!scopeGroup && !scopeTag ? 'Pick a group or tag to target' : ''}>
            {bulkMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Collect
          </button>
        </div>
        <p className="text-[11px] text-gray-600">Dispatches to ONLINE agents in scope. Results appear below as each agent reports back.</p>
      </div>

      {/* Agents + group/tag */}
      <div className="card p-0">
        <div className="px-4 py-2.5 border-b border-slate-800 text-sm font-semibold text-gray-200 flex items-center gap-2"><Tag className="h-4 w-4 text-emerald-400" /> Endpoints ({agents.length})</div>
        <div className="tbl-wrap overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-[11px] uppercase text-gray-500 border-b border-slate-800">
              <th className="px-4 py-2">Name</th><th className="px-4 py-2">Status</th><th className="px-4 py-2">Group</th><th className="px-4 py-2">Tags</th><th className="px-4 py-2"></th>
            </tr></thead>
            <tbody>
              {agents.map((a) => <AgentRow key={a.id} agent={a} onSaved={() => { qc.invalidateQueries({ queryKey: ['agents'] }); qc.invalidateQueries({ queryKey: ['fleet-groups'] }) }} />)}
              {agents.length === 0 && <tr><td colSpan={5} className="px-4 py-6 text-center text-gray-500 text-xs">No agents enrolled.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>

      {/* Scheduled collections */}
      <ScheduleSection schedules={schedules} groups={groups?.groups ?? []} tags={groups?.tags ?? []}
        onChanged={() => qc.invalidateQueries({ queryKey: ['fleet-schedules'] })} />

      {/* Results */}
      <div className="card p-0">
        <div className="px-4 py-2.5 border-b border-slate-800 text-sm font-semibold text-gray-200 flex items-center gap-2">
          <RefreshCw className="h-4 w-4 text-emerald-400" /> Recent collection results ({results.length})
        </div>
        <div className="tbl-wrap overflow-x-auto">
          <table className="w-full text-sm">
            <thead><tr className="text-left text-[11px] uppercase text-gray-500 border-b border-slate-800">
              <th className="px-4 py-2">Agent</th><th className="px-4 py-2">Collection</th><th className="px-4 py-2">Status</th><th className="px-4 py-2">Started</th>
            </tr></thead>
            <tbody>
              {results.map((r) => (
                <tr key={r.id} className="border-b border-slate-800/50">
                  <td className="px-4 py-2">{r.agent_name}</td>
                  <td className="px-4 py-2 font-mono text-xs">{r.collection}</td>
                  <td className={`px-4 py-2 text-xs font-mono ${RESULT_CLS[r.status] ?? 'text-gray-400'}`}>{r.status}{r.error ? ` — ${r.error}` : ''}</td>
                  <td className="px-4 py-2 text-xs text-gray-500">{safeFormat(r.started_at, 'MM-dd HH:mm:ss')}</td>
                </tr>
              ))}
              {results.length === 0 && <tr><td colSpan={4} className="px-4 py-6 text-center text-gray-500 text-xs">No collection results yet.</td></tr>}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

function AgentRow({ agent, onSaved }: { agent: Agent; onSaved: () => void }) {
  const [editing, setEditing] = useState(false)
  const [group, setGroup] = useState(agent.group_name ?? '')
  const [tags, setTags] = useState(parseTags(agent.tags).join(', '))
  const mut = useMutation({
    mutationFn: () => fleetApi.setTags(agent.id, {
      group_name: group.trim(),
      tags: tags.split(',').map((t) => t.trim()).filter(Boolean),
    }),
    onSuccess: () => { toast.success('Saved'); setEditing(false); onSaved() },
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  return (
    <tr className="border-b border-slate-800/50">
      <td className="px-4 py-2">{agent.name}</td>
      <td className="px-4 py-2"><span className={`text-[10px] px-1.5 py-0.5 rounded ${agent.status === 'online' ? 'bg-emerald-900/40 text-emerald-300' : 'bg-gray-800 text-gray-500'}`}>{agent.status}</span></td>
      {editing ? (
        <>
          <td className="px-4 py-2"><input className="input text-xs py-1" value={group} onChange={(e) => setGroup(e.target.value)} placeholder="group" /></td>
          <td className="px-4 py-2"><input className="input text-xs py-1" value={tags} onChange={(e) => setTags(e.target.value)} placeholder="tag1, tag2" /></td>
          <td className="px-4 py-2 whitespace-nowrap">
            <button className="btn-primary text-xs px-2 py-1" disabled={mut.isPending} onClick={() => mut.mutate()}>Save</button>
            <button className="btn-secondary text-xs px-2 py-1 ml-1" onClick={() => setEditing(false)}>Cancel</button>
          </td>
        </>
      ) : (
        <>
          <td className="px-4 py-2 text-gray-300">{agent.group_name || <span className="text-gray-600">—</span>}</td>
          <td className="px-4 py-2">{parseTags(agent.tags).map((t) => <span key={t} className="text-[10px] px-1.5 py-0.5 rounded bg-gray-800 text-gray-400 mr-1">{t}</span>) || '—'}</td>
          <td className="px-4 py-2"><button className="btn-secondary text-xs px-2 py-1" onClick={() => setEditing(true)}>Edit</button></td>
        </>
      )}
    </tr>
  )
}

function ScheduleSection({ schedules, groups, tags, onChanged }: {
  schedules: ScheduledCollection[]
  groups: { name: string; count: number }[]
  tags: { name: string; count: number }[]
  onChanged: () => void
}) {
  const [name, setName] = useState('')
  const [collection, setCollection] = useState<FleetCollection>('autoruns')
  const [group, setGroup] = useState('')
  const [tag, setTag] = useState('')
  const [interval, setInterval] = useState(1440)

  const createMut = useMutation({
    mutationFn: () => fleetApi.createSchedule({ name: name.trim(), collection, group: group || undefined, tag: tag || undefined, interval_minutes: interval }),
    onSuccess: () => { toast.success('Schedule created'); setName(''); onChanged() },
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const toggleMut = useMutation({
    mutationFn: (s: ScheduledCollection) => fleetApi.updateSchedule(s.id, { enabled: !s.enabled }),
    onSuccess: onChanged, onError: (e) => toast.error(getErrorMessage(e)),
  })
  const delMut = useMutation({
    mutationFn: (id: string) => fleetApi.deleteSchedule(id),
    onSuccess: () => { toast.success('Schedule deleted'); onChanged() }, onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <div className="card p-4 space-y-3">
      <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2"><Clock className="h-4 w-4 text-emerald-400" /> Scheduled collections</h3>
      <div className="flex flex-wrap items-end gap-2">
        <input className="input text-sm" placeholder="Schedule name" value={name} onChange={(e) => setName(e.target.value)} />
        <select className="input text-sm" value={collection} onChange={(e) => setCollection(e.target.value as FleetCollection)}>
          {FLEET_COLLECTIONS.map((c) => <option key={c} value={c}>{c}</option>)}
        </select>
        <select className="input text-sm" value={group} onChange={(e) => setGroup(e.target.value)}>
          <option value="">group: any</option>{groups.map((g) => <option key={g.name} value={g.name}>{g.name}</option>)}
        </select>
        <select className="input text-sm" value={tag} onChange={(e) => setTag(e.target.value)}>
          <option value="">tag: any</option>{tags.map((t) => <option key={t.name} value={t.name}>{t.name}</option>)}
        </select>
        <label className="text-xs text-gray-400">Every (min)
          <input type="number" min={5} className="input text-sm mt-1 block w-24" value={interval} onChange={(e) => setInterval(Number(e.target.value))} />
        </label>
        <button className="btn-primary flex items-center gap-1.5" disabled={!name.trim() || (!group && !tag) || createMut.isPending} onClick={() => createMut.mutate()}>
          <Plus className="h-4 w-4" /> Add
        </button>
      </div>
      {schedules.length > 0 && (
        <div className="space-y-1.5">
          {schedules.map((s) => (
            <div key={s.id} className="flex items-center gap-2 rounded border border-slate-700 bg-gray-900/40 px-3 py-2 text-sm">
              <span className="font-medium text-gray-200">{s.name}</span>
              <span className="text-[11px] font-mono text-gray-500">{s.collection} · every {s.interval_minutes}m · {s.group || s.tag || 'all'}</span>
              {s.next_run && <span className="text-[10px] text-gray-600">next {safeFormat(s.next_run, 'MM-dd HH:mm')}</span>}
              <button className={`ml-auto text-[10px] px-2 py-0.5 rounded border ${s.enabled ? 'border-emerald-700 text-emerald-300' : 'border-slate-700 text-gray-500'}`} onClick={() => toggleMut.mutate(s)}>
                {s.enabled ? 'enabled' : 'paused'}
              </button>
              <button className="text-gray-500 hover:text-red-400" onClick={() => delMut.mutate(s.id)}><Trash2 className="h-3.5 w-3.5" /></button>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
