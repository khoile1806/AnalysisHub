import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { openctiApi, OpenCTIConfig, OpenCTIConfigPayload, ManualIOCPayload } from '@/api/opencti'
import {
  elkApi,
  ELKConfig,
  ELKConfigPayload,
  ELKHit,
  AutoHuntProgress,
  AutoHuntDoneEvent,
  FileIOCParseResponse,
} from '@/api/elk'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'
import {
  Database, RefreshCw, ShieldAlert, FileText, Globe, Server, Search,
  AlertTriangle, Plus, X, Zap, Code2, PieChart as PieChartIcon, Activity,
  Upload, Pencil, Trash2, CheckCircle2, Link2, Rocket, FileSearch,
} from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  AreaChart, Area
} from 'recharts'

type TabType = 'hunt' | 'iocs' | 'connections'

// ---------------------------------------------------------------------------
// Page shell — ELK Hunt is now the primary tab.
// ---------------------------------------------------------------------------
export default function ELKHuntingPage() {
  const [activeTab, setActiveTab] = useState<TabType>('hunt')

  const tabs: { id: TabType; label: string; icon: React.ComponentType<{ className?: string }>; accent?: string }[] = [
    { id: 'hunt',        label: 'ELK Hunt',       icon: Search,   accent: 'emerald' },
    { id: 'iocs',        label: 'IOC Database',   icon: Database },
    { id: 'connections', label: 'Connections',    icon: Link2 },
  ]

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-100 flex items-center gap-2">
            <Search className="h-6 w-6 text-emerald-500" />
            ELK Threat Hunting
          </h1>
          <p className="text-gray-400 mt-1">
            Hunt indicators across Elasticsearch — from the IOC database, from an uploaded IOC file, or with a manual query.
          </p>
        </div>
        <div className="flex flex-wrap bg-gray-900 rounded-lg p-1 border border-gray-800 self-start">
          {tabs.map((t) => {
            const Ic = t.icon
            const active = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
                  active
                    ? t.accent === 'emerald'
                      ? 'bg-emerald-900/50 text-emerald-400'
                      : 'bg-gray-800 text-white'
                    : 'text-gray-400 hover:text-gray-200'
                }`}
              >
                <Ic className="h-4 w-4" />
                {t.label}
              </button>
            )
          })}
        </div>
      </div>

      {activeTab === 'hunt'        && <HuntTab />}
      {activeTab === 'iocs'        && <IOCsTab />}
      {activeTab === 'connections' && <ConnectionsTab />}
    </div>
  )
}

// ---------------------------------------------------------------------------
// CONNECTIONS TAB — multi-profile manager for ELK + OpenCTI
// ---------------------------------------------------------------------------
function ConnectionsTab() {
  const [sub, setSub] = useState<'elk' | 'opencti'>('elk')
  return (
    <div className="space-y-4">
      <div className="flex bg-gray-900 rounded-lg p-1 border border-gray-800 w-fit">
        <button
          onClick={() => setSub('elk')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium transition ${
            sub === 'elk' ? 'bg-emerald-900/50 text-emerald-400' : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <Server className="h-4 w-4" /> Elasticsearch
        </button>
        <button
          onClick={() => setSub('opencti')}
          className={`flex items-center gap-2 px-3 py-1.5 rounded text-sm font-medium transition ${
            sub === 'opencti' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-gray-200'
          }`}
        >
          <ShieldAlert className="h-4 w-4" /> OpenCTI
        </button>
      </div>
      {sub === 'elk' ? <ELKProfilesList /> : <OpenCTIProfilesList />}
    </div>
  )
}

// ---- Shared profile-card shell ----
function ProfileCard({
  title, url, username, hasAuth, isActive, onActivate, onEdit, onDelete,
}: {
  title: string; url: string; username: string; hasAuth: boolean; isActive: boolean
  onActivate: () => void; onEdit: () => void; onDelete: () => void
}) {
  return (
    <div className={`relative p-4 rounded-xl border ${isActive ? 'border-emerald-500/40 bg-emerald-500/5' : 'border-gray-800 bg-gray-900/40'}`}>
      {isActive && (
        <span className="absolute top-2 right-2 inline-flex items-center gap-1 text-[10px] font-semibold text-emerald-400 bg-emerald-500/15 px-2 py-0.5 rounded-full border border-emerald-500/30 uppercase tracking-wider">
          <CheckCircle2 className="h-3 w-3" /> Active
        </span>
      )}
      <div className="flex items-start justify-between gap-2 mb-2 pr-16">
        <h3 className="text-sm font-medium text-gray-200 truncate">{title}</h3>
      </div>
      <div className="text-xs text-gray-400 space-y-0.5 font-mono break-all">
        <div><span className="text-gray-500">url:</span> {url || <span className="text-gray-600 italic">—</span>}</div>
        {username && <div><span className="text-gray-500">user:</span> {username}</div>}
        <div className={hasAuth ? 'text-emerald-400/80' : 'text-amber-400/80'}>
          <span className="text-gray-500">auth:</span> {hasAuth ? 'configured' : 'missing'}
        </div>
      </div>
      <div className="flex items-center gap-2 mt-4">
        {!isActive && (
          <button
            onClick={onActivate}
            className="px-2.5 py-1 text-xs bg-emerald-600/20 hover:bg-emerald-600/40 text-emerald-300 border border-emerald-700/40 rounded flex items-center gap-1"
          >
            <CheckCircle2 className="h-3 w-3" /> Use
          </button>
        )}
        <button
          onClick={onEdit}
          className="px-2.5 py-1 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded flex items-center gap-1"
        >
          <Pencil className="h-3 w-3" /> Edit
        </button>
        <button
          onClick={onDelete}
          className="px-2.5 py-1 text-xs bg-red-600/15 hover:bg-red-600/30 text-red-300 border border-red-700/40 rounded flex items-center gap-1 ml-auto"
        >
          <Trash2 className="h-3 w-3" /> Delete
        </button>
      </div>
    </div>
  )
}

// ---- ELK profile list + modal ----
function ELKProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<ELKConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['elk-configs'],
    queryFn: () => elkApi.listConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => elkApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['elk-configs'] })
      qc.invalidateQueries({ queryKey: ['elk-config'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to activate'),
  })

  const del = useMutation({
    mutationFn: (id: number) => elkApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['elk-configs'] })
      qc.invalidateQueries({ queryKey: ['elk-config'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to delete'),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
          {profiles.length} ELK profile{profiles.length === 1 ? '' : 's'} saved. The active one is used for every hunt.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded"
        >
          <Plus className="h-4 w-4" /> Add ELK Profile
        </button>
      </div>

      {isLoading ? (
        <div className="text-gray-500 text-sm">Loading…</div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-gray-800 rounded">
          <Server className="h-8 w-8 text-gray-700 mx-auto mb-2" />
          <p className="text-gray-500 text-sm">No ELK profiles yet. Add one to start hunting.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              title={p.name}
              url={p.url}
              username={p.username}
              hasAuth={p.has_auth}
              isActive={p.is_active}
              onActivate={() => activate.mutate(p.id)}
              onEdit={() => setEditing(p)}
              onDelete={() => {
                if (confirm(`Delete profile "${p.name}"?`)) del.mutate(p.id)
              }}
            />
          ))}
        </div>
      )}

      {creating && <ELKProfileModal onClose={() => setCreating(false)} />}
      {editing && <ELKProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function ELKProfileModal({ profile, onClose }: { profile?: ELKConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: ELKConfigPayload) =>
      isEdit ? elkApi.updateConfig(profile!.id, payload) : elkApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['elk-configs'] })
      qc.invalidateQueries({ queryKey: ['elk-config'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to save'),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: ELKConfigPayload = {
      name: (fd.get('name') as string).trim(),
      description: fd.get('description') as string,
      url: fd.get('url') as string,
      username: fd.get('username') as string,
    }
    const password = fd.get('password') as string
    const api_key = fd.get('api_key') as string
    if (password) payload.password = password
    if (api_key) payload.api_key = api_key
    mutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-lg w-full shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="text-lg font-medium text-gray-100">
            {isEdit ? `Edit "${profile!.name}"` : 'New ELK Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200"><X className="h-5 w-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Profile Name *</label>
              <input
                name="name"
                required
                defaultValue={profile?.name}
                placeholder="e.g. DFIR Lab"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Description</label>
              <input
                name="description"
                defaultValue={profile?.description}
                placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">Elasticsearch URL *</label>
            <input
              name="url" type="url" required
              defaultValue={profile?.url}
              placeholder="https://elastic.example.com:9200"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Username (Basic Auth)</label>
              <input
                name="username"
                defaultValue={profile?.username}
                placeholder="elastic"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Password</label>
              <input
                name="password" type="password"
                placeholder={profile?.has_auth ? '•••••••• (leave blank to keep)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">OR API Key (base64-encoded)</label>
            <input
              name="api_key" type="password"
              placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank to keep)' : 'enter API key'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
            />
            <p className="text-[11px] text-gray-500 mt-1">Use either Basic Auth or API Key. Leave secret fields blank when editing to keep the stored value.</p>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded disabled:opacity-50"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- OpenCTI profile list + modal ----
function OpenCTIProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<OpenCTIConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['opencti-configs'],
    queryFn: () => openctiApi.listConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => openctiApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['opencti-configs'] })
      qc.invalidateQueries({ queryKey: ['opencti-config'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to activate'),
  })

  const del = useMutation({
    mutationFn: (id: number) => openctiApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['opencti-configs'] })
      qc.invalidateQueries({ queryKey: ['opencti-config'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to delete'),
  })

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <p className="text-sm text-gray-400">
          {profiles.length} OpenCTI profile{profiles.length === 1 ? '' : 's'} saved. The active one is used when syncing IOCs.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-1.5 px-3 py-1.5 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded"
        >
          <Plus className="h-4 w-4" /> Add OpenCTI Profile
        </button>
      </div>

      {isLoading ? (
        <div className="text-gray-500 text-sm">Loading…</div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-12 border border-dashed border-gray-800 rounded">
          <ShieldAlert className="h-8 w-8 text-gray-700 mx-auto mb-2" />
          <p className="text-gray-500 text-sm">No OpenCTI profiles. Add one to sync IOCs.</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-3">
          {profiles.map((p) => (
            <ProfileCard
              key={p.id}
              title={p.name}
              url={p.url}
              username={p.username}
              hasAuth={p.has_auth}
              isActive={p.is_active}
              onActivate={() => activate.mutate(p.id)}
              onEdit={() => setEditing(p)}
              onDelete={() => {
                if (confirm(`Delete profile "${p.name}"?`)) del.mutate(p.id)
              }}
            />
          ))}
        </div>
      )}

      {creating && <OpenCTIProfileModal onClose={() => setCreating(false)} />}
      {editing && <OpenCTIProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function OpenCTIProfileModal({ profile, onClose }: { profile?: OpenCTIConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: OpenCTIConfigPayload) =>
      isEdit ? openctiApi.updateConfig(profile!.id, payload) : openctiApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['opencti-configs'] })
      qc.invalidateQueries({ queryKey: ['opencti-config'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to save'),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: OpenCTIConfigPayload = {
      name: (fd.get('name') as string).trim(),
      description: fd.get('description') as string,
      url: fd.get('url') as string,
      username: fd.get('username') as string,
    }
    const password = fd.get('password') as string
    const token = fd.get('token') as string
    if (password) payload.password = password
    if (token) payload.token = token
    mutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-lg w-full shadow-2xl overflow-hidden">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800">
          <h2 className="text-lg font-medium text-gray-100">
            {isEdit ? `Edit "${profile!.name}"` : 'New OpenCTI Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200"><X className="h-5 w-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Profile Name *</label>
              <input
                name="name" required
                defaultValue={profile?.name}
                placeholder="e.g. OpenCTI Prod"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Description</label>
              <input
                name="description"
                defaultValue={profile?.description}
                placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">OpenCTI URL *</label>
            <input
              name="url" type="url" required
              defaultValue={profile?.url}
              placeholder="https://opencti.example.com"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div>
            <label className="block text-xs text-gray-400 mb-1">API Token (Bearer) — recommended</label>
            <input
              name="token" type="password"
              placeholder={profile?.has_auth ? '•••••••• (leave blank to keep)' : 'enter API token'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-gray-400 mb-1">Username (optional)</label>
              <input
                name="username"
                defaultValue={profile?.username}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
            <div>
              <label className="block text-xs text-gray-400 mb-1">Password (optional)</label>
              <input
                name="password" type="password"
                placeholder={profile?.has_auth ? '•••••••• (leave blank to keep)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500"
              />
            </div>
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-gray-400 hover:text-gray-200">Cancel</button>
            <button
              type="submit"
              disabled={mutation.isPending}
              className="px-4 py-2 text-sm bg-emerald-600 hover:bg-emerald-500 text-white rounded disabled:opacity-50"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// IOC DATABASE TAB
// ---------------------------------------------------------------------------
function IOCsTab() {
  const qc = useQueryClient()
  const [isModalOpen, setIsModalOpen] = useState(false)

  const { data: iocs, isLoading } = useQuery({
    queryKey: ['iocs'],
    queryFn: openctiApi.listIOCs,
  })

  const syncMutation = useMutation({
    mutationFn: openctiApi.sync,
    onSuccess: (data) => {
      toast.success(data.message)
      qc.invalidateQueries({ queryKey: ['iocs'] })
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Sync failed'),
  })

  const getIconForType = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ipv4-addr':
      case 'ipv6-addr':   return <Server className="h-4 w-4 text-blue-400" />
      case 'domain-name':
      case 'url':         return <Globe className="h-4 w-4 text-purple-400" />
      case 'file':
      case 'file-hash':   return <FileText className="h-4 w-4 text-orange-400" />
      default:            return <ShieldAlert className="h-4 w-4 text-gray-400" />
    }
  }

  const iocTypeData = useMemo(() => {
    if (!iocs) return []
    const counts: Record<string, number> = {}
    iocs.forEach((ioc: any) => { counts[ioc.type] = (counts[ioc.type] || 0) + 1 })
    const COLORS = ['#3b82f6', '#a855f7', '#f97316', '#10b981', '#ef4444', '#06b6d4']
    return Object.entries(counts).map(([name, value], idx) => ({ name, value, color: COLORS[idx % COLORS.length] }))
  }, [iocs])

  const iocSourceData = useMemo(() => {
    if (!iocs) return []
    const counts: Record<string, number> = { 'OpenCTI': 0, 'Manual': 0 }
    iocs.forEach((ioc: any) => {
      const src = ioc.source === 'Manual' ? 'Manual' : 'OpenCTI'
      counts[src] = (counts[src] || 0) + 1
    })
    return [
      { name: 'OpenCTI', value: counts['OpenCTI'], fill: '#10b981' },
      { name: 'Manual',  value: counts['Manual'],  fill: '#6366f1' },
    ].filter(item => item.value > 0)
  }, [iocs])

  const iocTimelineData = useMemo(() => {
    if (!iocs) return []
    const counts: Record<string, number> = {}
    iocs.forEach((ioc: any) => {
      if (!ioc.created_at) return
      const date = new Date(ioc.created_at).toISOString().split('T')[0]
      counts[date] = (counts[date] || 0) + 1
    })
    return Object.entries(counts)
      .map(([date, count]) => ({ date, count }))
      .sort((a, b) => a.date.localeCompare(b.date))
      .slice(-14)
  }, [iocs])

  return (
    <div className="space-y-6">
      {iocs && iocs.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          <div className="card p-5 bg-gray-900/40 border border-gray-800/60">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <PieChartIcon className="h-4 w-4 text-purple-400" /> IOC Distribution
            </h3>
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie data={iocTypeData} cx="50%" cy="50%" innerRadius={50} outerRadius={75} paddingAngle={5} dataKey="value">
                    {iocTypeData.map((entry, index) => <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0)" />)}
                  </Pie>
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} itemStyle={{ color: '#f1f5f9', fontSize: '12px' }} />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="card p-5 bg-gray-900/40 border border-gray-800/60">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <Database className="h-4 w-4 text-emerald-400" /> Source Breakdown
            </h3>
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={iocSourceData} layout="vertical" margin={{ top: 10, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={true} vertical={false} />
                  <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip cursor={{ fill: '#1e293b', opacity: 0.4 }} contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={24} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>
          <div className="card p-5 bg-gray-900/40 border border-gray-800/60">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" /> Sync Timeline
            </h3>
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <AreaChart data={iocTimelineData} margin={{ top: 10, right: 10, left: -25, bottom: 0 }}>
                  <defs>
                    <linearGradient id="colorTimeline" x1="0" y1="0" x2="0" y2="1">
                      <stop offset="5%" stopColor="#3b82f6" stopOpacity={0.8}/>
                      <stop offset="95%" stopColor="#8b5cf6" stopOpacity={0}/>
                    </linearGradient>
                  </defs>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                  <XAxis dataKey="date" stroke="#64748b" fontSize={9} tickLine={false} axisLine={false} tickFormatter={(val) => val.substring(5)} />
                  <YAxis stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }} labelStyle={{ color: '#94a3b8' }} />
                  <Area type="monotone" dataKey="count" stroke="#3b82f6" strokeWidth={2} fillOpacity={1} fill="url(#colorTimeline)" />
                </AreaChart>
              </ResponsiveContainer>
            </div>
          </div>
        </div>
      )}

      <div className="flex justify-between items-center bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div>
          <h2 className="text-lg font-medium text-gray-200">Synchronized & Manual IOCs</h2>
          <p className="text-sm text-gray-500">{iocs?.length || 0} items retrieved from OpenCTI or added manually</p>
        </div>
        <div className="flex gap-2">
          <button
            onClick={() => setIsModalOpen(true)}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg font-medium"
          >
            <Plus className="h-4 w-4" /> Add Manual IOC
          </button>
          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200 px-4 py-2 rounded-lg font-medium disabled:opacity-50 border border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            {syncMutation.isPending ? 'Syncing…' : 'Sync OpenCTI'}
          </button>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col" style={{ height: 'calc(100vh - 250px)' }}>
        <div className="overflow-auto flex-1">
          <table className="w-full text-left text-sm text-gray-400 relative">
            <thead className="bg-gray-950/90 text-gray-500 uppercase text-xs sticky top-0 z-10 backdrop-blur-sm">
              <tr>
                <th className="px-6 py-3 font-medium">Type</th>
                <th className="px-6 py-3 font-medium">Value</th>
                <th className="px-6 py-3 font-medium">Description</th>
                <th className="px-6 py-3 font-medium">Date Synced</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {isLoading ? (
                <tr><td colSpan={4} className="px-6 py-8 text-center text-gray-500">Loading IOCs...</td></tr>
              ) : !iocs || iocs.length === 0 ? (
                <tr><td colSpan={4} className="px-6 py-8 text-center text-gray-500">No IOCs found. Click "Sync OpenCTI" to fetch data.</td></tr>
              ) : (
                iocs.map((ioc: any) => (
                  <tr key={ioc.id} className="hover:bg-gray-800/50 transition-colors">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        {getIconForType(ioc.type)}
                        <span className="font-medium text-gray-300">{ioc.type}</span>
                        {ioc.source === 'Manual' && (
                          <span className="ml-2 px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">MANUAL</span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-3 font-mono text-emerald-400 break-all">{ioc.value}</td>
                    <td className="px-6 py-3 max-w-xs truncate" title={ioc.description}>{ioc.description || <span className="text-gray-600 italic">No description</span>}</td>
                    <td className="px-6 py-3 whitespace-nowrap">{new Date(ioc.created_at).toLocaleDateString()}</td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {isModalOpen && <AddManualIOCModal onClose={() => setIsModalOpen(false)} />}
    </div>
  )
}

function AddManualIOCModal({ onClose }: { onClose: () => void }) {
  const qc = useQueryClient()
  const addMutation = useMutation({
    mutationFn: openctiApi.addManualIOC,
    onSuccess: (data) => {
      toast.success(data.message)
      qc.invalidateQueries({ queryKey: ['iocs'] })
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to add manual IOC'),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: ManualIOCPayload = {
      type: fd.get('type') as string,
      value: fd.get('value') as string,
    }
    const description = fd.get('description') as string
    if (description) payload.description = description
    addMutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-md w-full shadow-2xl overflow-hidden">
        <div className="flex justify-between items-center px-6 py-4 border-b border-gray-800">
          <h2 className="text-lg font-medium text-gray-100 flex items-center gap-2">
            <Plus className="h-5 w-5 text-emerald-500" /> Add Manual IOC
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200"><X className="h-5 w-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">IOC Type</label>
            <select name="type" required className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500">
              <option value="IPv4-Addr">IPv4 Address</option>
              <option value="Domain-Name">Domain Name</option>
              <option value="File-Hash">File Hash (MD5, SHA256...)</option>
              <option value="URL">URL</option>
              <option value="Email-Address">Email Address</option>
              <option value="Mac-Addr">MAC Address</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Value / Pattern</label>
            <input name="value" type="text" required placeholder="e.g. 192.168.1.1 or malicious.com" className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 font-mono" />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description (Optional)</label>
            <textarea name="description" rows={3} className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 resize-none" />
          </div>
          <div className="pt-4 flex justify-end gap-3">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm font-medium text-gray-400 hover:text-gray-200">Cancel</button>
            <button type="submit" disabled={addMutation.isPending} className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium disabled:opacity-50">
              {addMutation.isPending ? 'Adding...' : 'Add IOC'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---------------------------------------------------------------------------
// HUNT TAB — Auto / File IOC / Manual
// ---------------------------------------------------------------------------
type ManualMode = 'lucene' | 'dsl'

interface HuntState {
  running: boolean
  hits: ELKHit[]
  progress?: AutoHuntProgress
  done?: AutoHuntDoneEvent
  batchErrors: { batch: number; bucket: string; error: string }[]
}

const initialHunt: HuntState = { running: false, hits: [], batchErrors: [] }

function HuntTab() {
  const token = useAuthStore((s) => s.token)
  const esRef = useRef<EventSource | null>(null)

  const [manualMode, setManualMode] = useState<ManualMode>('lucene')
  const [luceneQuery, setLuceneQuery] = useState('')
  const [dslText, setDslText] = useState(JSON.stringify({
    query: { match_all: {} },
    size: 50,
    sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'boolean' } }],
  }, null, 2))

  const [auto, setAuto] = useState<HuntState>(initialHunt)
  const [fileHunt, setFileHunt] = useState<HuntState>(initialHunt)
  const [parsedFile, setParsedFile] = useState<FileIOCParseResponse | null>(null)
  const [parsedFileName, setParsedFileName] = useState<string>('')

  useEffect(() => {
    return () => {
      esRef.current?.close()
      esRef.current = null
    }
  }, [])

  const manualMutation = useMutation({
    mutationFn: elkApi.manualHunt,
    onSuccess: (data) => toast.success(`Manual hunt completed in ${data.took}ms`),
    onError: (err: any) => toast.error(err.response?.data?.error || 'Hunt failed'),
  })

  const stopAnyStream = () => {
    esRef.current?.close()
    esRef.current = null
  }

  const startAutoHunt = () => {
    if (!token) { toast.error('Not authenticated'); return }
    if (auto.running || fileHunt.running) { toast.error('A hunt is already running'); return }
    stopAnyStream()
    setAuto({ ...initialHunt, running: true })
    esRef.current = elkApi.streamAutoHunt(token, {
      onProgress: (p) => setAuto((s) => ({ ...s, progress: p })),
      onHits:     (h) => setAuto((s) => ({ ...s, hits: [...s.hits, ...h.hits] })),
      onError:    (e) => setAuto((s) => ({ ...s, batchErrors: [...s.batchErrors, { batch: e.batch, bucket: e.bucket, error: e.error }] })),
      onDone:     (d) => {
        setAuto((s) => ({ ...s, running: false, done: d }))
        toast.success(`Auto hunt done — ${d.total_hits} hits across ${d.total_iocs} IOCs`)
      },
      onTransportError: () => {
        setAuto((s) => ({ ...s, running: false }))
        toast.error('Stream closed unexpectedly')
      },
    })
  }

  const stopAutoHunt = () => {
    stopAnyStream()
    setAuto((s) => ({ ...s, running: false }))
  }

  const runManual = () => {
    if (manualMode === 'lucene') {
      if (!luceneQuery.trim()) { toast.error('Enter a Lucene query string'); return }
      manualMutation.mutate({ mode: 'lucene', query: luceneQuery })
      return
    }
    let parsed: Record<string, any>
    try { parsed = JSON.parse(dslText) }
    catch (e: any) { toast.error(`Invalid JSON: ${e.message}`); return }
    if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) { toast.error('DSL body must be a JSON object'); return }
    manualMutation.mutate({ mode: 'dsl', body: parsed })
  }

  // --- File IOC handlers ---
  const parseMutation = useMutation({
    mutationFn: (file: File) => elkApi.parseIOCFile(file),
    onSuccess: (data) => {
      setParsedFile(data)
      toast.success(`Parsed ${data.iocs.length} IOC(s) from ${data.total_lines} line(s)`)
    },
    onError: (err: any) => {
      setParsedFile(null)
      toast.error(err.response?.data?.error || 'Failed to parse file')
    },
  })

  const onFilePicked = (file: File | null) => {
    if (!file) return
    setParsedFileName(file.name)
    setFileHunt(initialHunt)
    parseMutation.mutate(file)
  }

  const startFileHunt = () => {
    if (!token) { toast.error('Not authenticated'); return }
    if (!parsedFile || parsedFile.iocs.length === 0) { toast.error('Parse a file first'); return }
    if (auto.running || fileHunt.running) { toast.error('A hunt is already running'); return }
    stopAnyStream()
    setFileHunt({ ...initialHunt, running: true })
    esRef.current = elkApi.streamFileHunt(token, parsedFile.iocs, {
      onProgress: (p) => setFileHunt((s) => ({ ...s, progress: p })),
      onHits:     (h) => setFileHunt((s) => ({ ...s, hits: [...s.hits, ...h.hits] })),
      onError:    (e) => setFileHunt((s) => ({ ...s, batchErrors: [...s.batchErrors, { batch: e.batch, bucket: e.bucket, error: e.error }] })),
      onDone:     (d) => {
        setFileHunt((s) => ({ ...s, running: false, done: d }))
        toast.success(`File hunt done — ${d.total_hits} hits across ${d.total_iocs} IOCs`)
      },
      onTransportError: () => {
        setFileHunt((s) => ({ ...s, running: false }))
        toast.error('Stream closed unexpectedly')
      },
    })
  }

  const stopFileHunt = () => {
    stopAnyStream()
    setFileHunt((s) => ({ ...s, running: false }))
  }

  const manualHits = manualMutation.data?.hits.hits ?? []
  const manualTotal = manualMutation.data?.hits.total
  const showManual = manualMutation.data !== undefined
  const showAuto = auto.running || auto.hits.length > 0 || auto.done !== undefined
  const showFile = fileHunt.running || fileHunt.hits.length > 0 || fileHunt.done !== undefined

  return (
    <div className="space-y-4">
      {/* Auto Hunt panel — IOCs from DB */}
      <div className="flex flex-col gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-medium text-gray-200 flex items-center gap-2">
              <Zap className="h-5 w-5 text-emerald-500" /> Auto Hunt (IOC database)
            </h2>
            <p className="text-sm text-gray-500">
              Streams across every IOC stored in the database (synced from OpenCTI + manual entries).
            </p>
          </div>
          {auto.running ? (
            <button onClick={stopAutoHunt} className="flex items-center gap-2 bg-red-600/80 hover:bg-red-500 text-white px-5 py-2 rounded-lg font-medium">
              <X className="h-4 w-4" /> Stop
            </button>
          ) : (
            <button onClick={startAutoHunt} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg font-medium whitespace-nowrap">
              <Search className="h-4 w-4" /> Start Auto Hunt
            </button>
          )}
        </div>
        {(auto.running || auto.progress) && <ProgressBlock state={auto} />}
      </div>

      {/* File IOC Hunt panel */}
      <div className="flex flex-col gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-medium text-gray-200 flex items-center gap-2">
              <FileSearch className="h-5 w-5 text-emerald-500" /> Hunt from IOC File
            </h2>
            <p className="text-sm text-gray-500">
              Upload a <code className="text-emerald-400">.txt</code> file — one IOC per line. The server auto-detects
              IP, hash, domain, URL, email & MAC, then runs an ephemeral hunt (nothing is saved to the IOC DB).
            </p>
          </div>
          <label className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200 px-4 py-2 rounded-lg font-medium cursor-pointer border border-gray-700">
            <Upload className="h-4 w-4" />
            <span>{parseMutation.isPending ? 'Parsing…' : 'Choose .txt'}</span>
            <input
              type="file"
              accept=".txt,.csv,.ioc,text/plain"
              hidden
              onChange={(e) => onFilePicked(e.target.files?.[0] ?? null)}
            />
          </label>
        </div>

        {parsedFile && (
          <div className="border-t border-gray-800 pt-4 space-y-3">
            <div className="flex flex-wrap items-center justify-between gap-2">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-xs text-gray-400 font-mono">{parsedFileName}</span>
                <span className="text-xs text-gray-500">·</span>
                <span className="text-xs text-gray-400">{parsedFile.iocs.length} parsed</span>
                <span className="text-xs text-gray-500">·</span>
                <span className="text-xs text-gray-400">{parsedFile.skipped.length} skipped</span>
                <span className="text-xs text-gray-500">·</span>
                <span className="text-xs text-gray-400">{parsedFile.total_lines} total lines</span>
              </div>
              <div className="flex items-center gap-2">
                <button
                  onClick={() => { setParsedFile(null); setParsedFileName(''); setFileHunt(initialHunt) }}
                  className="px-3 py-1.5 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded"
                >
                  Clear
                </button>
                {fileHunt.running ? (
                  <button onClick={stopFileHunt} className="flex items-center gap-2 bg-red-600/80 hover:bg-red-500 text-white px-4 py-1.5 rounded text-sm">
                    <X className="h-3.5 w-3.5" /> Stop
                  </button>
                ) : (
                  <button
                    onClick={startFileHunt}
                    disabled={parsedFile.iocs.length === 0}
                    className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-1.5 rounded text-sm disabled:opacity-40"
                  >
                    <Rocket className="h-3.5 w-3.5" /> Auto Search This File
                  </button>
                )}
              </div>
            </div>

            {/* Counts by type */}
            {Object.keys(parsedFile.counts).length > 0 && (
              <div className="flex flex-wrap gap-2">
                {Object.entries(parsedFile.counts).map(([type, count]) => (
                  <span key={type} className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full text-xs bg-gray-800 text-gray-300 border border-gray-700">
                    {type}: <span className="text-emerald-400 font-medium">{count}</span>
                  </span>
                ))}
              </div>
            )}

            {/* Parsed IOC preview */}
            <details className="text-xs text-gray-400" open={parsedFile.iocs.length <= 50}>
              <summary className="cursor-pointer text-gray-300 hover:text-gray-100">
                Preview parsed IOCs ({parsedFile.iocs.length})
              </summary>
              <div className="mt-2 max-h-60 overflow-auto bg-gray-950/60 rounded border border-gray-800">
                <table className="w-full text-xs font-mono">
                  <thead className="bg-gray-900/60 text-gray-500 sticky top-0">
                    <tr>
                      <th className="text-left px-3 py-1.5 font-normal">Line</th>
                      <th className="text-left px-3 py-1.5 font-normal">Type</th>
                      <th className="text-left px-3 py-1.5 font-normal">Value</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-gray-800/50">
                    {parsedFile.iocs.slice(0, 500).map((ioc, i) => (
                      <tr key={i}>
                        <td className="px-3 py-1 text-gray-500">{ioc.line_no}</td>
                        <td className="px-3 py-1 text-purple-400">{ioc.type}</td>
                        <td className="px-3 py-1 text-emerald-400 break-all">{ioc.value}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
                {parsedFile.iocs.length > 500 && (
                  <div className="px-3 py-2 text-gray-500 italic">…{parsedFile.iocs.length - 500} more (still included in the hunt)</div>
                )}
              </div>
            </details>

            {parsedFile.skipped.length > 0 && (
              <details className="text-xs text-amber-400/80">
                <summary className="cursor-pointer">Skipped lines ({parsedFile.skipped.length})</summary>
                <ul className="mt-2 space-y-1 font-mono max-h-40 overflow-auto bg-gray-950/40 rounded border border-gray-800 p-2">
                  {parsedFile.skipped.slice(0, 200).map((s, i) => (
                    <li key={i}><span className="text-gray-500">L{s.line_no}:</span> {s.line} <span className="text-gray-600">— {s.reason}</span></li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}

        {(fileHunt.running || fileHunt.progress) && <ProgressBlock state={fileHunt} />}
      </div>

      {/* Manual Search panel */}
      <div className="flex flex-col gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-medium text-gray-200 flex items-center gap-2">
              <Code2 className="h-5 w-5 text-emerald-500" /> Manual Search
            </h2>
            <p className="text-sm text-gray-500">Lucene query string or raw Elasticsearch DSL body.</p>
          </div>
          <div className="flex bg-gray-950 rounded-lg p-1 border border-gray-800 self-start">
            <button onClick={() => setManualMode('lucene')} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${manualMode === 'lucene' ? 'bg-gray-800 text-emerald-400' : 'text-gray-500 hover:text-gray-300'}`}>Lucene</button>
            <button onClick={() => setManualMode('dsl')} className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${manualMode === 'dsl' ? 'bg-gray-800 text-emerald-400' : 'text-gray-500 hover:text-gray-300'}`}>Raw DSL (JSON)</button>
          </div>
        </div>
        {manualMode === 'lucene' ? (
          <input
            type="text" value={luceneQuery} onChange={(e) => setLuceneQuery(e.target.value)}
            placeholder='e.g. source.ip:"192.168.1.1" OR url.domain:"malicious.com"'
            className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 font-mono text-sm"
          />
        ) : (
          <textarea
            value={dslText} onChange={(e) => setDslText(e.target.value)} rows={10} spellCheck={false}
            className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 font-mono text-xs resize-y"
          />
        )}
        <div className="flex justify-end">
          <button onClick={runManual} disabled={manualMutation.isPending} className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg font-medium disabled:opacity-50">
            <Search className={`h-4 w-4 ${manualMutation.isPending ? 'animate-pulse' : ''}`} />
            {manualMutation.isPending ? 'Searching...' : 'Run Search'}
          </button>
        </div>
      </div>

      {/* Results area */}
      {!showAuto && !showManual && !showFile && !manualMutation.isPending && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <Search className="h-12 w-12 text-gray-700 mb-4" />
          <h3 className="text-lg font-medium text-gray-300">Ready to Hunt</h3>
          <p className="text-gray-500 max-w-sm mt-2">
            Hunt across IOCs in the database, upload a file of indicators, or run a manual query.
          </p>
        </div>
      )}

      {showFile && (
        <ResultsPanel
          title="File IOC Hunt Results"
          hits={fileHunt.hits}
          totalLabel={fileHunt.done
            ? `${fileHunt.done.total_hits} hits across ${fileHunt.done.total_iocs} IOCs (${fileHunt.done.total_batches} batches)`
            : `${fileHunt.hits.length} hits so far`}
          tookMs={fileHunt.done?.took_ms}
        />
      )}
      {showAuto && (
        <ResultsPanel
          title="Auto Hunt Results"
          hits={auto.hits}
          totalLabel={auto.done
            ? `${auto.done.total_hits} unique hits across ${auto.done.total_iocs} IOCs (${auto.done.total_batches} batches)`
            : `${auto.hits.length} hits so far`}
          tookMs={auto.done?.took_ms}
        />
      )}
      {showManual && (
        <ResultsPanel
          title="Manual Search Results"
          hits={manualHits}
          totalLabel={manualTotal ? `${manualTotal.value}${manualTotal.relation === 'gte' ? '+' : ''} matches` : ''}
          tookMs={manualMutation.data?.took}
        />
      )}
    </div>
  )
}

function ProgressBlock({ state }: { state: HuntState }) {
  return (
    <div className="border-t border-gray-800 pt-3 space-y-2 text-sm">
      <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-xs text-gray-400">
        <span>batch: <span className="text-emerald-400">{state.progress?.batch ?? 0} / {state.progress?.total_batches ?? '?'}</span></span>
        <span>bucket: <span className="text-emerald-400">{state.progress?.bucket ?? '—'}</span></span>
        <span>hits so far: <span className="text-emerald-400">{state.progress?.total_hits ?? state.hits.length}</span></span>
        {state.done && <span>took: <span className="text-emerald-400">{state.done.took_ms}ms</span></span>}
      </div>
      <div className="h-1.5 w-full bg-gray-800 rounded overflow-hidden">
        <div
          className="h-full bg-emerald-500 transition-all"
          style={{ width: `${state.progress && state.progress.total_batches > 0 ? Math.min(100, (state.progress.batch / state.progress.total_batches) * 100) : 0}%` }}
        />
      </div>
      {state.batchErrors.length > 0 && (
        <details className="text-xs text-amber-400/80">
          <summary className="cursor-pointer">{state.batchErrors.length} batch error(s)</summary>
          <ul className="mt-1 space-y-1 font-mono">
            {state.batchErrors.map((e, i) => (<li key={i}>batch {e.batch} [{e.bucket}]: {e.error}</li>))}
          </ul>
        </details>
      )}
    </div>
  )
}

function ResultsPanel({ title, hits, totalLabel, tookMs }: { title: string; hits: ELKHit[]; totalLabel: string; tookMs?: number }) {
  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col" style={{ height: 'calc(100vh - 250px)' }}>
      <div className="p-4 bg-gray-950/50 border-b border-gray-800 flex justify-between items-center">
        <div className="flex items-center gap-2">
          {hits.length > 0 ? <AlertTriangle className="h-5 w-5 text-red-500" /> : <ShieldAlert className="h-5 w-5 text-emerald-500" />}
          <span className="font-medium text-gray-200">{title}</span>
          <span className="text-xs text-gray-500">— {totalLabel}</span>
        </div>
        {tookMs !== undefined && <span className="text-xs text-gray-500 font-mono">took: {tookMs}ms</span>}
      </div>
      <div className="overflow-auto flex-1 p-4 bg-gray-950/20">
        {hits.length === 0 ? (
          <div className="h-full flex items-center justify-center text-emerald-500/80 italic">No matches yet.</div>
        ) : (
          <div className="space-y-4">
            {hits.map((hit, idx) => (
              <div key={`${hit._index}-${hit._id}-${idx}`} className="bg-gray-900 border border-red-900/30 rounded-lg p-4 shadow-sm relative overflow-hidden group">
                <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500/50 group-hover:bg-red-500 transition-colors"></div>
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs font-mono bg-gray-800 text-gray-400 px-2 py-1 rounded">{hit._index}</span>
                  <span className="text-xs text-gray-500 font-mono">Score: {hit._score?.toFixed(2) ?? '—'}</span>
                </div>
                <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-all bg-gray-950 p-3 rounded border border-gray-800 overflow-x-auto">{JSON.stringify(hit._source, null, 2)}</pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
