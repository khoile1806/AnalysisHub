import { useEffect, useRef, useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { openctiApi, OpenCTIConfig, OpenCTIConfigPayload } from '@/api/opencti'
import {
  elkApi,
  ELKConfig,
  ELKConfigPayload,
  ELKHit,
  AutoHuntProgress,
  AutoHuntDoneEvent,
  FileIOCParseResponse,
} from '@/api/elk'
import { splunkApi, SplunkConfig } from '@/api/splunk'
import { qradarApi, QRadarConfig } from '@/api/qradar'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'
import {
  ShieldAlert, Server, Search,
  Plus, X, Zap, Code2,
  Upload, Pencil, Trash2, CheckCircle2, Rocket, FileSearch, Layers
} from 'lucide-react'
import { JsonViewer } from '@/components/JsonViewer'

type TabType = 'hunt' | 'connections'

// ---------------------------------------------------------------------------
// Page shell 
// ---------------------------------------------------------------------------
export default function ELKHuntingPage() {
  const [activeTab, setActiveTab] = useState<TabType>('hunt')

  const tabs: { id: TabType; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: 'hunt',        label: 'Threat Hunt',   icon: Search },
    { id: 'connections', label: 'Integrations',  icon: Layers },
  ]

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-100 flex items-center gap-2">
            <Search className="h-6 w-6 text-emerald-500" />
            SIEM Threat Hunting
          </h1>
          <p className="text-gray-400 mt-1">
            Hunt indicators across Elasticsearch — from the IOC database, from an uploaded IOC file, or with a manual query.
          </p>
        </div>
        <div className="flex bg-gray-900/60 p-1 border border-gray-800/60 rounded-lg backdrop-blur-sm self-start shadow-sm">
          {tabs.map((t) => {
            const Ic = t.icon
            const active = activeTab === t.id
            return (
              <button
                key={t.id}
                onClick={() => setActiveTab(t.id)}
                className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all duration-200 ${
                  active
                    ? 'bg-gray-800 text-emerald-400 shadow-sm'
                    : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
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
      {activeTab === 'connections' && <ConnectionsTab />}
    </div>
  )
}

// ---------------------------------------------------------------------------
// CONNECTIONS TAB — multi-profile manager for ELK + OpenCTI
// ---------------------------------------------------------------------------
function ConnectionsTab() {
  const [sub, setSub] = useState<'elk' | 'splunk' | 'qradar' | 'opencti'>('elk')
  return (
    <div className="space-y-4">
      <div className="flex bg-gray-900/60 p-1 border border-gray-800/60 rounded-lg w-fit backdrop-blur-sm shadow-sm">
        <button
          onClick={() => setSub('elk')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'elk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <Server className="h-4 w-4" /> ELK
        </button>
        <button
          onClick={() => setSub('splunk')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'splunk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <Server className="h-4 w-4" /> Splunk
        </button>
        <button
          onClick={() => setSub('qradar')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'qradar' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <Server className="h-4 w-4" /> QRadar
        </button>
        <button
          onClick={() => setSub('opencti')}
          className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-all ${
            sub === 'opencti' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-400 hover:text-gray-200 hover:bg-gray-800/50'
          }`}
        >
          <ShieldAlert className="h-4 w-4" /> OpenCTI
        </button>
      </div>
      {sub === 'elk' ? <ELKProfilesList /> : sub === 'splunk' ? <SplunkProfilesList /> : sub === 'qradar' ? <QRadarProfilesList /> : <OpenCTIProfilesList />}
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
    <div className={`relative p-5 rounded-2xl border backdrop-blur-sm transition-all duration-300 ${isActive ? 'border-emerald-500/40 bg-emerald-950/10 shadow-[0_0_15px_rgba(16,185,129,0.1)]' : 'border-gray-800/60 bg-gray-900/40 hover:bg-gray-900/60 hover:border-gray-700'}`}>
      {isActive && (
        <span className="absolute top-3 right-3 inline-flex items-center gap-1 text-[10px] font-bold text-emerald-400 bg-emerald-500/10 px-2.5 py-1 rounded-full border border-emerald-500/20 uppercase tracking-wider shadow-[0_0_10px_rgba(16,185,129,0.2)]">
          <CheckCircle2 className="h-3 w-3" /> Active
        </span>
      )}
      <div className="flex items-start justify-between gap-2 mb-3 pr-16">
        <h3 className="text-base font-semibold text-gray-100 truncate">{title}</h3>
      </div>
      <div className="text-xs text-gray-400 space-y-1 font-mono break-all bg-gray-950/50 p-3 rounded-lg border border-gray-800/40">
        <div className="flex gap-2"><span className="text-gray-600 shrink-0 w-10">url:</span> <span className="text-gray-300">{url || <span className="text-gray-600 italic">—</span>}</span></div>
        {username && <div className="flex gap-2"><span className="text-gray-600 shrink-0 w-10">user:</span> <span className="text-gray-300">{username}</span></div>}
        <div className={`flex gap-2 ${hasAuth ? 'text-emerald-400/90' : 'text-amber-400/90'}`}>
          <span className="text-gray-600 shrink-0 w-10">auth:</span> <span>{hasAuth ? 'configured' : 'missing'}</span>
        </div>
      </div>
      <div className="flex items-center gap-2 mt-4">
        {!isActive && (
          <button
            onClick={onActivate}
            className="px-3 py-1.5 text-xs font-medium bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-400 border border-emerald-500/20 hover:border-emerald-500/40 rounded-lg flex items-center gap-1.5 transition-all"
          >
            <CheckCircle2 className="h-3.5 w-3.5" /> Use
          </button>
        )}
        <button
          onClick={onEdit}
          className="px-3 py-1.5 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-300 border border-gray-700 rounded-lg flex items-center gap-1.5 transition-all"
        >
          <Pencil className="h-3.5 w-3.5" /> Edit
        </button>
        <button
          onClick={onDelete}
          className="px-3 py-1.5 text-xs font-medium bg-red-500/10 hover:bg-red-500/20 text-red-400 border border-red-500/20 hover:border-red-500/40 rounded-lg flex items-center gap-1.5 ml-auto transition-all"
        >
          <Trash2 className="h-3.5 w-3.5" /> Delete
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
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} ELK profile{profiles.length === 1 ? '' : 's'} saved. The active one is used for every hunt.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add ELK Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <Server className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No ELK profiles yet</p>
          <p className="text-gray-500 text-sm mt-1">Add one to start hunting across Elasticsearch</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Server className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New ELK Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. DFIR Lab"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">Elasticsearch URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://elastic.example.com:9200"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (Basic Auth)</label>
              <input
                name="username" defaultValue={profile?.username} placeholder="elastic"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OR API Key (base64-encoded)</label>
            <input
              name="api_key" type="password" placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank)' : 'enter API key'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
            <p className="text-[11px] text-gray-500 font-medium">Use either Basic Auth or API Key. Leave blank when editing to keep stored value.</p>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- Splunk profile list + modal ----
function SplunkProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<SplunkConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['splunk-configs'],
    queryFn: () => splunkApi.getConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => splunkApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['splunk-configs'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to activate'),
  })

  const del = useMutation({
    mutationFn: (id: number) => splunkApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['splunk-configs'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to delete'),
  })

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} Splunk profile{profiles.length === 1 ? '' : 's'} saved.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add Splunk Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <Server className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No Splunk profiles yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
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

      {creating && <SplunkProfileModal onClose={() => setCreating(false)} />}
      {editing && <SplunkProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function SplunkProfileModal({ profile, onClose }: { profile?: SplunkConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: any) =>
      isEdit ? splunkApi.updateConfig(profile!.id, payload) : splunkApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['splunk-configs'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to save'),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: any = {
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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Server className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New Splunk Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. Splunk Core"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">Splunk URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://splunk.example.com:8089"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (Basic Auth)</label>
              <input
                name="username" defaultValue={profile?.username} placeholder="admin"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OR API Key (Bearer token)</label>
            <input
              name="api_key" type="password" placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank)' : 'enter API key'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
            <p className="text-[11px] text-gray-500 font-medium">Use either Basic Auth or API Key. Leave blank when editing to keep stored value.</p>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
            >
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save Changes' : 'Create Profile'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ---- QRadar profile list + modal ----
function QRadarProfilesList() {
  const qc = useQueryClient()
  const [editing, setEditing] = useState<QRadarConfig | null>(null)
  const [creating, setCreating] = useState(false)

  const { data: profiles = [], isLoading } = useQuery({
    queryKey: ['qradar-configs'],
    queryFn: () => qradarApi.getConfigs(),
  })

  const activate = useMutation({
    mutationFn: (id: number) => qradarApi.activateConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qradar-configs'] })
      toast.success('Profile activated')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to activate'),
  })

  const del = useMutation({
    mutationFn: (id: number) => qradarApi.deleteConfig(id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qradar-configs'] })
      toast.success('Profile deleted')
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to delete'),
  })

  return (
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} QRadar profile{profiles.length === 1 ? '' : 's'} saved.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add QRadar Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <Server className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No QRadar profiles yet</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 lg:grid-cols-2 xl:grid-cols-3 gap-4">
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

      {creating && <QRadarProfileModal onClose={() => setCreating(false)} />}
      {editing && <QRadarProfileModal profile={editing} onClose={() => setEditing(null)} />}
    </div>
  )
}

function QRadarProfileModal({ profile, onClose }: { profile?: QRadarConfig; onClose: () => void }) {
  const qc = useQueryClient()
  const isEdit = !!profile

  const mutation = useMutation({
    mutationFn: (payload: any) =>
      isEdit ? qradarApi.updateConfig(profile!.id, payload) : qradarApi.createConfig(payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['qradar-configs'] })
      toast.success(isEdit ? 'Profile updated' : 'Profile created')
      onClose()
    },
    onError: (err: any) => toast.error(err.response?.data?.error || 'Failed to save'),
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const fd = new FormData(e.currentTarget)
    const payload: any = {
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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <Server className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New QRadar Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. QRadar Core"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">QRadar URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://qradar.example.com"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (Basic Auth)</label>
              <input
                name="username" defaultValue={profile?.username} placeholder="admin"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OR SEC Token (SEC header)</label>
            <input
              name="api_key" type="password" placeholder={profile?.has_auth && !profile?.username ? '•••••••• (leave blank)' : 'enter SEC token'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
            <p className="text-[11px] text-gray-500 font-medium">Use either Basic Auth or SEC Token. Leave blank when editing to keep stored value.</p>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
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
    <div className="space-y-4 animate-in fade-in slide-in-from-bottom-2 duration-500">
      <div className="flex items-center justify-between bg-gray-900/30 p-4 rounded-xl border border-gray-800/40">
        <p className="text-sm text-gray-400 font-medium">
          {profiles.length} OpenCTI profile{profiles.length === 1 ? '' : 's'} saved. The active one is used when syncing IOCs.
        </p>
        <button
          onClick={() => setCreating(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
        >
          <Plus className="h-4 w-4" /> Add OpenCTI Profile
        </button>
      </div>

      {isLoading ? (
        <div className="flex items-center justify-center py-12 text-gray-500 text-sm">
          <div className="h-6 w-6 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
        </div>
      ) : profiles.length === 0 ? (
        <div className="text-center py-16 border border-dashed border-gray-800 rounded-2xl bg-gray-900/20 backdrop-blur-sm">
          <ShieldAlert className="h-12 w-12 text-gray-700/50 mx-auto mb-4" />
          <p className="text-gray-400 text-base font-medium">No OpenCTI profiles</p>
          <p className="text-gray-500 text-sm mt-1">Add one to sync IOCs</p>
        </div>
      ) : (
        <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
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
    <div className="fixed inset-0 bg-black/80 backdrop-blur-sm flex items-center justify-center z-50 p-4 animate-in fade-in duration-200">
      <div className="bg-gray-900 border border-gray-800 rounded-2xl max-w-lg w-full shadow-2xl overflow-hidden scale-in-95 animate-in duration-200">
        <div className="flex items-center justify-between px-6 py-4 border-b border-gray-800 bg-gray-950/50">
          <h2 className="text-lg font-semibold text-gray-100 flex items-center gap-2">
            <ShieldAlert className="h-5 w-5 text-emerald-500" />
            {isEdit ? `Edit "${profile!.name}"` : 'New OpenCTI Profile'}
          </h2>
          <button onClick={onClose} className="text-gray-500 hover:text-gray-300 transition-colors bg-gray-800 hover:bg-gray-700 rounded-full p-1"><X className="h-4 w-4" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-5">
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Profile Name *</label>
              <input
                name="name" required defaultValue={profile?.name} placeholder="e.g. OpenCTI Prod"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Description</label>
              <input
                name="description" defaultValue={profile?.description} placeholder="optional"
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner"
              />
            </div>
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">OpenCTI URL *</label>
            <input
              name="url" type="url" required defaultValue={profile?.url} placeholder="https://opencti.example.com"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="space-y-1.5">
            <label className="block text-xs font-medium text-gray-400">API Token (Bearer) — recommended</label>
            <input
              name="token" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter API token'}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
            />
          </div>
          <div className="grid grid-cols-2 gap-5">
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Username (optional)</label>
              <input
                name="username" defaultValue={profile?.username}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
            <div className="space-y-1.5">
              <label className="block text-xs font-medium text-gray-400">Password (optional)</label>
              <input
                name="password" type="password" placeholder={profile?.has_auth ? '•••••••• (leave blank)' : 'enter password'}
                className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-200 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 transition-all shadow-inner font-mono"
              />
            </div>
          </div>
          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <button type="button" onClick={onClose} className="px-5 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 bg-gray-800 hover:bg-gray-700 rounded-lg transition-colors">Cancel</button>
            <button
              type="submit" disabled={mutation.isPending}
              className="px-5 py-2 text-sm font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50 shadow-[0_0_15px_rgba(16,185,129,0.2)] transition-all"
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
// HUNT TAB — Auto / File IOC / Manual
// ---------------------------------------------------------------------------
type ManualMode = 'lucene' | 'dsl'
type HuntMode = 'auto' | 'file' | 'manual'

interface HuntState {
  running: boolean
  hits: ELKHit[]
  progress?: AutoHuntProgress
  done?: AutoHuntDoneEvent
  batchErrors: { batch: number; bucket: string; error: string }[]
}

const initialHunt: HuntState = { running: false, hits: [], batchErrors: [] }

function HuntTab() {
  const [targetSiem, setTargetSiem] = useState<'elk' | 'splunk' | 'qradar'>('elk')
  const [targetIndices, setTargetIndices] = useState<string>('*')
  const [timeRange, setTimeRange] = useState<string>('') // empty = All Time
  const token = useAuthStore((s) => s.token)
  const esRef = useRef<EventSource | null>(null)

  const [mode, setMode] = useState<HuntMode>('auto')

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

  const { data: availableIndices } = useQuery({
    queryKey: ['siem-indices', targetSiem],
    queryFn: () => targetSiem === 'splunk' ? splunkApi.getIndices() : targetSiem === 'elk' ? elkApi.getIndices() : Promise.resolve([]),
    retry: false,
    enabled: targetSiem !== 'qradar'
  })

  const manualMutation = useMutation({
    mutationFn: (payload: any) => {
      if (targetSiem === 'splunk') return splunkApi.manualHunt(payload)
      if (targetSiem === 'qradar') return qradarApi.manualHunt(payload)
      return elkApi.manualHunt(payload)
    },
    onSuccess: (data) => toast.success(`Manual hunt completed in ${data.took || 0}ms`),
    onError: (err: any) => toast.error(err.response?.data?.error || 'Hunt failed'),
  })

  const stopAnyStream = () => {
    esRef.current?.close()
    esRef.current = null
  }

  // Pick the streaming client for the selected SIEM. ELK/Splunk/QRadar all share
  // the same SSE event contract (progress/hits/error/done), so the handlers below
  // are identical regardless of target.
  const siemStreamApi = targetSiem === 'splunk' ? splunkApi : targetSiem === 'qradar' ? qradarApi : elkApi

  const startAutoHunt = () => {
    if (!token) { toast.error('Not authenticated'); return }
    if (auto.running || fileHunt.running) { toast.error('A hunt is already running'); return }
    stopAnyStream()
    setAuto({ ...initialHunt, running: true })
    esRef.current = siemStreamApi.streamAutoHunt(token, targetIndices, timeRange, {
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
      if (!luceneQuery.trim()) { toast.error(`Enter a ${targetSiem === 'splunk' ? 'SPL' : targetSiem === 'qradar' ? 'AQL' : 'Lucene'} query string`); return }
      manualMutation.mutate({ mode: 'lucene', query: luceneQuery, indices: targetIndices, timeRange })
      return
    }
    let parsed: Record<string, any>
    try { parsed = JSON.parse(dslText) }
    catch (e: any) { toast.error(`Invalid JSON: ${e.message}`); return }
    if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) { toast.error('DSL body must be a JSON object'); return }
    manualMutation.mutate({ mode: 'dsl', body: parsed, indices: targetIndices, timeRange })
  }

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
    esRef.current = siemStreamApi.streamFileHunt(token, parsedFile.iocs, targetIndices, timeRange, {
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

  const activeHits = mode === 'auto' ? auto.hits : mode === 'file' ? fileHunt.hits : manualHits
  const activeTitle = mode === 'auto' ? "Auto Hunt Results" : mode === 'file' ? "File Hunt Results" : "Manual Hunt Results"
  const activeRunning = mode === 'auto' ? auto.running : mode === 'file' ? fileHunt.running : manualMutation.isPending
  
  let activeTotalLabel = ""
  let activeTookMs: number | undefined = undefined
  if (mode === 'auto') {
    activeTotalLabel = auto.done ? `${auto.done.total_hits} unique hits across ${auto.done.total_iocs} IOCs` : `${auto.hits.length} hits so far`
    activeTookMs = auto.done?.took_ms
  } else if (mode === 'file') {
    activeTotalLabel = fileHunt.done ? `${fileHunt.done.total_hits} hits across ${fileHunt.done.total_iocs} IOCs` : `${fileHunt.hits.length} hits so far`
    activeTookMs = fileHunt.done?.took_ms
  } else if (mode === 'manual') {
    activeTotalLabel = manualTotal ? `${manualTotal.value}${manualTotal.relation === 'gte' ? '+' : ''} matches` : ''
    activeTookMs = manualMutation.data?.took
  }

  const hasData = (mode === 'auto' && showAuto) || (mode === 'file' && showFile) || (mode === 'manual' && showManual)

  return (
    <div className="flex flex-col xl:flex-row gap-6 animate-in fade-in duration-500">
      {/* LEFT PANEL: CONFIG */}
      <div className="w-full xl:w-1/3 flex flex-col gap-5">
        {/* Target SIEM Selector */}
        <div className="bg-gray-900/60 p-4 border border-gray-800/60 rounded-xl flex items-center justify-between backdrop-blur-sm shadow-sm">
          <div className="flex flex-col">
            <span className="text-sm font-bold text-gray-200">Target SIEM</span>
            <span className="text-xs text-gray-500">Select analysis engine</span>
          </div>
          <div className="flex bg-gray-950 rounded-lg p-1 border border-gray-800">
            <button onClick={() => setTargetSiem('elk')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${targetSiem === 'elk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>ELK</button>
            <button onClick={() => setTargetSiem('splunk')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${targetSiem === 'splunk' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>Splunk</button>
            <button onClick={() => setTargetSiem('qradar')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${targetSiem === 'qradar' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>QRadar</button>
          </div>
        </div>
        {/* Mode Selector */}
        <div className="bg-gray-900/60 p-1.5 border border-gray-800/60 rounded-xl flex gap-1.5 backdrop-blur-sm shadow-sm">
          <button onClick={() => setMode('auto')} className={`flex-1 flex flex-col items-center justify-center gap-2 py-4 rounded-lg text-sm font-semibold transition-all duration-200 ${mode === 'auto' ? 'bg-gray-800 border-emerald-500/40 shadow-md text-emerald-400' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}`}>
            <Zap className="h-5 w-5" /> Auto DB
          </button>
          <button onClick={() => setMode('file')} className={`flex-1 flex flex-col items-center justify-center gap-2 py-4 rounded-lg text-sm font-semibold transition-all duration-200 ${mode === 'file' ? 'bg-gray-800 border-emerald-500/40 shadow-md text-emerald-400' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}`}>
            <FileSearch className="h-5 w-5" /> File IOC
          </button>
          <button onClick={() => setMode('manual')} className={`flex-1 flex flex-col items-center justify-center gap-2 py-4 rounded-lg text-sm font-semibold transition-all duration-200 ${mode === 'manual' ? 'bg-gray-800 border-emerald-500/40 shadow-md text-emerald-400' : 'text-gray-500 hover:text-gray-300 hover:bg-gray-800/50'}`}>
            <Code2 className="h-5 w-5" /> Manual
          </button>
        </div>

        {/* Filter Bar */}
        <div className="bg-gray-900/60 p-4 border border-gray-800/60 rounded-xl backdrop-blur-sm shadow-sm space-y-4">
          {targetSiem !== 'qradar' && (<div className="space-y-1.5">
            <label className="text-xs font-semibold text-gray-400 flex items-center gap-2">
              Index Pattern
            </label>
            <select 
              value={targetIndices}
              onChange={e => setTargetIndices(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-emerald-500/50 appearance-none"
            >
              <option value="*">All Indices (*)</option>
              {availableIndices?.map(idx => (
                <option key={idx} value={idx}>{idx}</option>
              ))}
            </select>
          </div>)}
          <div className="space-y-1.5">
            <label className="text-xs font-semibold text-gray-400 flex items-center gap-2">
              Time Range
            </label>
            <select 
              value={timeRange}
              onChange={e => setTimeRange(e.target.value)}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-3 py-2 text-sm text-gray-300 focus:outline-none focus:border-emerald-500/50 appearance-none"
            >
              <option value="">All Time</option>
              <option value="now-1h">Last 1 Hour</option>
              <option value="now-24h">Last 24 Hours</option>
              <option value="now-7d">Last 7 Days</option>
              <option value="now-30d">Last 30 Days</option>
              <option value="now-90d">Last 90 Days</option>
            </select>
          </div>
        </div>

        {/* Config Container */}
        <div className="bg-gray-900/60 border border-gray-800/60 rounded-xl p-6 shadow-sm backdrop-blur-sm flex-1 flex flex-col">
          {mode === 'auto' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-left-2 duration-300">
              <div className="space-y-2">
                <h3 className="text-lg font-semibold text-gray-200 flex items-center gap-2"><Zap className="h-5 w-5 text-emerald-500" /> Auto Hunt (IOC DB)</h3>
                <p className="text-sm text-gray-400 leading-relaxed">Streams across every IOC stored in the database (synced from OpenCTI + manual entries). This is an intensive process.</p>
              </div>
              <div className="pt-2">
                {auto.running ? (
                  <button onClick={stopAutoHunt} className="w-full flex items-center justify-center gap-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 px-5 py-3 rounded-xl font-semibold transition-all shadow-[0_0_15px_rgba(239,68,68,0.15)]">
                    <X className="h-5 w-5" /> Stop Hunt
                  </button>
                ) : (
                  <button onClick={startAutoHunt} className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] px-5 py-3 rounded-xl font-semibold transition-all">
                    <Search className="h-5 w-5" /> Start Auto Hunt
                  </button>
                )}
              </div>
              {(auto.running || auto.progress) && <ProgressBlock state={auto} />}
            </div>
          )}

          {mode === 'file' && (
            <div className="space-y-6 animate-in fade-in slide-in-from-left-2 duration-300">
              <div className="space-y-2">
                <h3 className="text-lg font-semibold text-gray-200 flex items-center gap-2"><FileSearch className="h-5 w-5 text-emerald-500" /> File IOC Hunt</h3>
                <p className="text-sm text-gray-400 leading-relaxed">Upload a <code className="text-emerald-400/90 bg-emerald-500/10 px-1.5 py-0.5 rounded font-mono text-xs border border-emerald-500/20">.txt</code> file — one indicator per line. The server auto-detects types and runs an ephemeral hunt.</p>
              </div>
              
              <label className="flex flex-col items-center justify-center border-2 border-dashed border-gray-700/60 hover:border-emerald-500/50 bg-gray-950/40 hover:bg-emerald-950/10 rounded-xl p-8 cursor-pointer transition-all mt-2 group">
                <Upload className="h-8 w-8 text-gray-500 group-hover:text-emerald-400 mb-3 transition-colors" />
                <span className="text-sm font-semibold text-gray-300 group-hover:text-gray-200">{parseMutation.isPending ? 'Parsing...' : 'Choose .txt file'}</span>
                <span className="text-xs text-gray-600 mt-1.5">Drag and drop or click</span>
                <input type="file" accept=".txt,.csv,.ioc,text/plain" hidden onChange={(e) => onFilePicked(e.target.files?.[0] ?? null)} />
              </label>

              {parsedFile && (
                <div className="pt-2 space-y-4">
                  <div className="flex items-center justify-between bg-gray-950/50 p-3 rounded-lg border border-gray-800/60">
                    <div className="flex flex-col">
                      <span className="text-sm text-emerald-400 font-semibold truncate max-w-[180px]">{parsedFileName}</span>
                      <div className="flex gap-2 text-[10px] font-bold tracking-wider text-gray-500 uppercase mt-1">
                        <span>{parsedFile.iocs.length} PARSED</span>
                        <span>•</span>
                        <span>{parsedFile.skipped.length} SKIPPED</span>
                      </div>
                    </div>
                    <button onClick={() => { setParsedFile(null); setParsedFileName(''); setFileHunt(initialHunt) }} className="p-2 text-gray-500 hover:text-red-400 hover:bg-red-500/10 rounded-md transition-colors"><Trash2 className="h-4 w-4" /></button>
                  </div>

                  <div className="pt-2">
                    {fileHunt.running ? (
                      <button onClick={stopFileHunt} className="w-full flex items-center justify-center gap-2 bg-red-600/20 hover:bg-red-600/40 text-red-400 border border-red-500/30 px-5 py-3 rounded-xl font-semibold transition-all shadow-[0_0_15px_rgba(239,68,68,0.15)]">
                        <X className="h-5 w-5" /> Stop Hunt
                      </button>
                    ) : (
                      <button onClick={startFileHunt} disabled={parsedFile.iocs.length === 0} className="w-full flex items-center justify-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] px-5 py-3 rounded-xl font-semibold disabled:opacity-50 transition-all">
                        <Rocket className="h-5 w-5" /> Search Indicators
                      </button>
                    )}
                  </div>
                </div>
              )}
              {(fileHunt.running || fileHunt.progress) && <ProgressBlock state={fileHunt} />}
            </div>
          )}

          {mode === 'manual' && (
            <div className="space-y-4 flex flex-col h-full animate-in fade-in slide-in-from-left-2 duration-300">
              <div className="flex items-center justify-between mb-2">
                <h3 className="text-lg font-semibold text-gray-200 flex items-center gap-2"><Code2 className="h-5 w-5 text-emerald-500" /> Manual Search</h3>
                <div className="flex bg-gray-950/80 rounded-lg p-1 border border-gray-800/60 shadow-inner">
                  <button onClick={() => setManualMode('lucene')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${manualMode === 'lucene' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>
                    {targetSiem === 'splunk' ? 'SPL' : targetSiem === 'qradar' ? 'AQL' : 'Lucene'}
                  </button>
                  <button onClick={() => setManualMode('dsl')} className={`px-4 py-1.5 rounded-md text-xs font-semibold transition-all ${manualMode === 'dsl' ? 'bg-gray-800 text-emerald-400 shadow-sm' : 'text-gray-500 hover:text-gray-300'}`}>DSL JSON</button>
                </div>
              </div>
              
              <div className="flex-1 min-h-[250px]">
                {manualMode === 'lucene' ? (
                  <textarea
                    value={luceneQuery} onChange={(e) => setLuceneQuery(e.target.value)}
                    placeholder={targetSiem === 'splunk' ? 'search index=* "192.168.1.1"' : targetSiem === 'qradar' ? 'SELECT * FROM events WHERE UTF8(payload) ILIKE \'%192.168.1.1%\'' : 'e.g. source.ip:"192.168.1.1" OR url.domain:"malicious.com"'}
                    className="w-full h-full bg-gray-950/80 border border-gray-800/60 rounded-xl px-5 py-4 text-emerald-400 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 font-mono text-sm resize-none shadow-inner transition-all placeholder:text-gray-700"
                  />
                ) : (
                  <textarea
                    value={dslText} onChange={(e) => setDslText(e.target.value)} spellCheck={false}
                    className="w-full h-full bg-gray-950/80 border border-gray-800/60 rounded-xl px-5 py-4 text-blue-400 focus:outline-none focus:border-emerald-500/50 focus:ring-1 focus:ring-emerald-500/50 font-mono text-xs resize-none leading-relaxed shadow-inner transition-all"
                  />
                )}
              </div>
              <button onClick={runManual} disabled={manualMutation.isPending} className="w-full flex items-center justify-center gap-2 mt-4 bg-emerald-600 hover:bg-emerald-500 text-white shadow-[0_0_15px_rgba(16,185,129,0.3)] px-5 py-3 rounded-xl font-semibold disabled:opacity-50 transition-all">
                <Search className={`h-5 w-5 ${manualMutation.isPending ? 'animate-pulse' : ''}`} />
                {manualMutation.isPending ? 'Searching...' : 'Run Search'}
              </button>
            </div>
          )}
        </div>
      </div>

      {/* RIGHT PANEL: RESULTS */}
      <div className="w-full xl:w-2/3 h-[calc(100vh-140px)]">
        {!hasData && !activeRunning ? (
          <div className="h-full bg-gray-900/40 border border-gray-800/60 rounded-2xl p-12 text-center flex flex-col items-center justify-center backdrop-blur-sm shadow-sm relative overflow-hidden group">
            <div className="absolute inset-0 bg-emerald-500/5 blur-3xl rounded-full scale-0 group-hover:scale-150 transition-transform duration-1000 ease-out pointer-events-none"></div>
            <Search className="h-16 w-16 text-gray-700/40 mb-6 group-hover:text-emerald-500/30 transition-colors" />
            <h3 className="text-xl font-semibold text-gray-200">Ready to Hunt</h3>
            <p className="text-gray-500 text-sm max-w-sm mt-3 leading-relaxed">
              Select your hunt mode on the left and run a search to analyze matching Elasticsearch logs here.
            </p>
          </div>
        ) : (
          <ResultsPanel
            title={activeTitle}
            hits={activeHits}
            totalLabel={activeTotalLabel}
            tookMs={activeTookMs}
            isLoading={activeRunning}
          />
        )}
      </div>
    </div>
  )
}

function ProgressBlock({ state }: { state: HuntState }) {
  return (
    <div className="pt-4 space-y-4 text-sm border-t border-gray-800/60 mt-6">
      <div className="flex flex-wrap gap-3 font-mono text-[11px] font-semibold tracking-wider text-gray-400">
        <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-gray-800">BATCH: <span className="text-emerald-400">{state.progress?.batch ?? 0}</span> / {state.progress?.total_batches ?? '?'}</div>
        <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-gray-800 truncate max-w-[200px]">BUCKET: <span className="text-emerald-400">{state.progress?.bucket ?? '—'}</span></div>
        <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-red-900/30 shadow-[0_0_10px_rgba(239,68,68,0.1)]">HITS: <span className="text-red-400 font-bold">{state.progress?.total_hits ?? state.hits.length}</span></div>
        {state.done && <div className="bg-gray-950/80 px-3 py-1.5 rounded-md border border-gray-800">TOOK: <span className="text-emerald-400">{state.done.took_ms}ms</span></div>}
      </div>
      <div className="h-2 w-full bg-gray-950 rounded-full overflow-hidden border border-gray-800/60 shadow-inner">
        <div
          className="h-full bg-emerald-500 transition-all duration-300 relative shadow-[0_0_10px_rgba(16,185,129,0.8)]"
          style={{ width: `${state.progress && state.progress.total_batches > 0 ? Math.min(100, (state.progress.batch / state.progress.total_batches) * 100) : 0}%` }}
        >
          <div className="absolute inset-0 bg-white/20 animate-pulse"></div>
        </div>
      </div>
      {state.batchErrors.length > 0 && (
        <details className="text-xs text-amber-400/90 bg-amber-950/30 border border-amber-900/40 rounded-lg p-3 backdrop-blur-sm">
          <summary className="cursor-pointer font-semibold outline-none">{state.batchErrors.length} batch error(s)</summary>
          <ul className="mt-3 space-y-1.5 font-mono max-h-32 overflow-auto custom-scrollbar opacity-80">
            {state.batchErrors.map((e, i) => (<li key={i}>batch {e.batch} [{e.bucket}]: {e.error}</li>))}
          </ul>
        </details>
      )}
    </div>
  )
}

function ResultsPanel({ title, hits, totalLabel, tookMs, isLoading }: { title: string; hits: ELKHit[]; totalLabel: string; tookMs?: number; isLoading: boolean }) {
  return (
    <div className="bg-gray-900/60 border border-gray-800/60 rounded-2xl flex flex-col h-full shadow-sm backdrop-blur-sm overflow-hidden animate-in fade-in duration-300">
      <div className="p-5 bg-gray-950/40 border-b border-gray-800/60 flex flex-wrap justify-between items-center gap-4 shrink-0">
        <div className="flex items-center gap-3">
          <div className="relative">
            <ShieldAlert className={`h-6 w-6 ${hits.length > 0 ? 'text-red-500 drop-shadow-[0_0_8px_rgba(239,68,68,0.5)]' : 'text-emerald-500'}`} />
            {isLoading && <span className="absolute -top-1 -right-1 h-2.5 w-2.5 rounded-full bg-emerald-400 animate-ping" />}
          </div>
          <span className="text-lg font-semibold text-gray-100">{title}</span>
          <span className="text-[11px] text-gray-400 font-bold tracking-wider px-3 py-1 rounded-md bg-gray-900/80 border border-gray-700/50 shadow-inner">{totalLabel || '0 matches'}</span>
        </div>
        {tookMs !== undefined && <span className="text-[11px] tracking-wider text-gray-500 font-bold bg-gray-950 px-3 py-1 rounded-md border border-gray-800">TOOK: <span className="text-emerald-400">{tookMs}MS</span></span>}
      </div>
      
      <div className="overflow-auto flex-1 p-5 bg-gray-950/20 custom-scrollbar relative">
        {hits.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-gray-500">
            {isLoading ? (
               <div className="flex flex-col items-center gap-3">
                 <div className="h-8 w-8 border-2 border-emerald-500/20 border-t-emerald-500 rounded-full animate-spin"></div>
                 <span className="text-sm font-medium animate-pulse">Searching through logs...</span>
               </div>
            ) : (
              <span className="italic">No matches found.</span>
            )}
          </div>
        ) : (
          <div className="space-y-6">
            {hits.map((hit, idx) => (
              <div key={`${hit._index}-${hit._id}-${idx}`} className="bg-gray-900/80 border border-gray-800 hover:border-red-500/40 transition-colors rounded-xl p-0 shadow-sm relative overflow-hidden group">
                {/* Red side indicator */}
                <div className="absolute left-0 top-0 bottom-0 w-1.5 bg-gradient-to-b from-red-500 to-red-600/50 opacity-70 group-hover:opacity-100 transition-opacity"></div>
                
                <div className="flex flex-wrap justify-between items-center gap-3 p-3.5 bg-gray-950/60 border-b border-gray-800/60 ml-1.5">
                  <div className="flex items-center gap-3">
                    <span className="text-[10px] font-bold tracking-wider text-gray-500 uppercase">Index</span>
                    <span className="text-xs font-mono bg-gray-900 text-emerald-400 px-2.5 py-1 rounded border border-gray-800">{hit._index}</span>
                  </div>
                  <span className="text-[10px] uppercase tracking-wider text-gray-500 font-bold bg-gray-900 px-2.5 py-1 rounded border border-gray-800">Score: {hit._score?.toFixed(2) ?? '—'}</span>
                </div>
                
                <div className="p-4 ml-1.5 bg-[#0d1117] overflow-x-auto custom-scrollbar">
                  <JsonViewer data={hit._source} className="!bg-transparent !p-0 !border-none !text-[13px] leading-relaxed" />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
