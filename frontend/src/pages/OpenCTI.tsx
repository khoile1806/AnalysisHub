import { useEffect, useRef, useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { openctiApi, OpenCTIConfigPayload, ManualIOCPayload } from '@/api/opencti'
import {
  elkApi,
  ELKConfigPayload,
  ELKHit,
  AutoHuntProgress,
  AutoHuntDoneEvent,
} from '@/api/elk'
import { useAuthStore } from '@/store/auth'
import toast from 'react-hot-toast'
import { Database, Settings, RefreshCw, ShieldAlert, FileText, Globe, Server, Search, AlertTriangle, Plus, X, Zap, Code2, PieChart as PieChartIcon, Activity } from 'lucide-react'
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  AreaChart, Area
} from 'recharts'

type TabType = 'iocs' | 'hunt' | 'config-opencti' | 'config-elk'

export default function OpenCTIPage() {
  const [activeTab, setActiveTab] = useState<TabType>('iocs')

  return (
    <div className="space-y-6">
      <div className="flex flex-col gap-4 lg:flex-row lg:items-center lg:justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight text-gray-100 flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-emerald-500" />
            Threat Hunting (OpenCTI + ELK)
          </h1>
          <p className="text-gray-400 mt-1">
            Synchronize Indicators of Compromise and hunt them across your Elasticsearch logs.
          </p>
        </div>
        <div className="flex flex-wrap bg-gray-900 rounded-lg p-1 border border-gray-800 self-start">
          <button
            onClick={() => setActiveTab('iocs')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'iocs' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Database className="h-4 w-4" />
            IOC Database
          </button>
          <button
            onClick={() => setActiveTab('hunt')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'hunt' ? 'bg-emerald-900/50 text-emerald-400' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Search className="h-4 w-4" />
            ELK Hunt
          </button>
          <button
            onClick={() => setActiveTab('config-opencti')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'config-opencti' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Settings className="h-4 w-4" />
            OpenCTI Config
          </button>
          <button
            onClick={() => setActiveTab('config-elk')}
            className={`flex items-center gap-2 px-4 py-2 rounded-md text-sm font-medium transition-colors ${
              activeTab === 'config-elk' ? 'bg-gray-800 text-white' : 'text-gray-400 hover:text-gray-200'
            }`}
          >
            <Settings className="h-4 w-4" />
            ELK Config
          </button>
        </div>
      </div>

      {activeTab === 'config-opencti' && <OpenCTIConfigTab />}
      {activeTab === 'config-elk' && <ELKConfigTab />}
      {activeTab === 'iocs' && <IOCsTab />}
      {activeTab === 'hunt' && <HuntTab />}
    </div>
  )
}

function OpenCTIConfigTab() {
  const queryClient = useQueryClient()
  const { data: config, isLoading } = useQuery({
    queryKey: ['opencti-config'],
    queryFn: openctiApi.getConfig,
  })

  const mutation = useMutation({
    mutationFn: openctiApi.saveConfig,
    onSuccess: () => {
      toast.success('OpenCTI configuration saved')
      queryClient.invalidateQueries({ queryKey: ['opencti-config'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to save configuration')
    },
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const payload: OpenCTIConfigPayload = {
      url: formData.get('url') as string,
      username: formData.get('username') as string,
    }
    const password = formData.get('password') as string
    if (password) payload.password = password
    
    const token = formData.get('token') as string
    if (token) payload.token = token

    mutation.mutate(payload)
  }

  if (isLoading) return <div className="text-gray-500">Loading configuration...</div>

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-2xl">
      <div className="px-6 py-5 border-b border-gray-800">
        <h2 className="text-lg font-medium text-gray-200">OpenCTI Connection</h2>
        <p className="text-sm text-gray-500 mt-1">Configure your OpenCTI instance details to sync IOCs.</p>
      </div>
      <form onSubmit={handleSubmit} className="p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">OpenCTI URL</label>
          <input
            name="url"
            type="url"
            required
            defaultValue={config?.url}
            placeholder="https://opencti.example.com"
            className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          />
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Username (Optional)</label>
            <input
              name="username"
              type="text"
              defaultValue={config?.username}
              placeholder="admin@opencti.io"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
            <input
              name="password"
              type="password"
              placeholder={config?.has_auth ? "•••••••• (Saved)" : "Enter password"}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
            />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">API Token (Bearer)</label>
          <input
            name="token"
            type="password"
            placeholder={config?.has_auth ? "•••••••• (Saved Token)" : "Enter API Token (Recommended)"}
            className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          />
        </div>

        <div className="pt-4 flex justify-end">
          <button
            type="submit"
            disabled={mutation.isPending}
            className="bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg font-medium transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </form>
    </div>
  )
}

function ELKConfigTab() {
  const queryClient = useQueryClient()
  const { data: config, isLoading } = useQuery({
    queryKey: ['elk-config'],
    queryFn: elkApi.getConfig,
  })

  const mutation = useMutation({
    mutationFn: elkApi.saveConfig,
    onSuccess: () => {
      toast.success('ELK configuration saved')
      queryClient.invalidateQueries({ queryKey: ['elk-config'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to save configuration')
    },
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const payload: ELKConfigPayload = {
      url: formData.get('url') as string,
      username: formData.get('username') as string,
    }
    const password = formData.get('password') as string
    if (password) payload.password = password
    
    const api_key = formData.get('api_key') as string
    if (api_key) payload.api_key = api_key

    mutation.mutate(payload)
  }

  if (isLoading) return <div className="text-gray-500">Loading configuration...</div>

  return (
    <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-2xl">
      <div className="px-6 py-5 border-b border-gray-800">
        <h2 className="text-lg font-medium text-gray-200">Elasticsearch Connection</h2>
        <p className="text-sm text-gray-500 mt-1">Configure your ELK instance details to perform Threat Hunts.</p>
      </div>
      <form onSubmit={handleSubmit} className="p-6 space-y-5">
        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">Elasticsearch URL</label>
          <input
            name="url"
            type="url"
            required
            defaultValue={config?.url}
            placeholder="https://elastic.example.com:9200"
            className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          />
        </div>
        
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Username (Basic Auth)</label>
            <input
              name="username"
              type="text"
              defaultValue={config?.username}
              placeholder="elastic"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
            />
          </div>
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Password</label>
            <input
              name="password"
              type="password"
              placeholder={config?.has_auth && config.username ? "•••••••• (Saved)" : "Enter password"}
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
            />
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-300 mb-1">OR API Key (Base64 Encoded)</label>
          <input
            name="api_key"
            type="password"
            placeholder={config?.has_auth && !config.username ? "•••••••• (Saved API Key)" : "Enter API Key"}
            className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500"
          />
          <p className="text-xs text-gray-500 mt-2">
            Use either Basic Auth (Username + Password) OR an API Key.
          </p>
        </div>

        <div className="pt-4 flex justify-end">
          <button
            type="submit"
            disabled={mutation.isPending}
            className="bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg font-medium transition-colors disabled:opacity-50"
          >
            {mutation.isPending ? 'Saving...' : 'Save Configuration'}
          </button>
        </div>
      </form>
    </div>
  )
}

function IOCsTab() {
  const queryClient = useQueryClient()
  const [isModalOpen, setIsModalOpen] = useState(false)
  
  const { data: iocs, isLoading } = useQuery({
    queryKey: ['iocs'],
    queryFn: openctiApi.listIOCs,
  })

  const syncMutation = useMutation({
    mutationFn: openctiApi.sync,
    onSuccess: (data) => {
      toast.success(data.message)
      queryClient.invalidateQueries({ queryKey: ['iocs'] })
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Sync failed')
    },
  })

  const getIconForType = (type: string) => {
    switch (type.toLowerCase()) {
      case 'ipv4-addr':
      case 'ipv6-addr':
        return <Server className="h-4 w-4 text-blue-400" />
      case 'domain-name':
      case 'url':
        return <Globe className="h-4 w-4 text-purple-400" />
      case 'file':
        return <FileText className="h-4 w-4 text-orange-400" />
      default:
        return <ShieldAlert className="h-4 w-4 text-gray-400" />
    }
  }

  // Dashboard Data Calculations
  const iocTypeData = useMemo(() => {
    if (!iocs) return []
    const counts: Record<string, number> = {}
    iocs.forEach((ioc: any) => {
      counts[ioc.type] = (counts[ioc.type] || 0) + 1
    })
    const COLORS = ['#3b82f6', '#a855f7', '#f97316', '#10b981', '#ef4444']
    return Object.entries(counts).map(([name, value], idx) => ({
      name,
      value,
      color: COLORS[idx % COLORS.length]
    }))
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
      { name: 'Manual', value: counts['Manual'], fill: '#6366f1' }
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
      .slice(-14) // Last 14 days
  }, [iocs])

  return (
    <div className="space-y-6">
      {/* Threat Intelligence Dashboard */}
      {iocs && iocs.length > 0 && (
        <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
          {/* IOC Distribution by Type */}
          <div className="card p-5 bg-gray-900/40 backdrop-blur-md border border-gray-800/60 shadow-[0_8px_30px_rgb(0,0,0,0.12)]">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <PieChartIcon className="h-4 w-4 text-purple-400" />
              IOC Distribution
            </h3>
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <PieChart>
                  <Pie
                    data={iocTypeData}
                    cx="50%"
                    cy="50%"
                    innerRadius={50}
                    outerRadius={75}
                    paddingAngle={5}
                    dataKey="value"
                  >
                    {iocTypeData.map((entry, index) => (
                      <Cell key={`cell-${index}`} fill={entry.color} stroke="rgba(0,0,0,0)" />
                    ))}
                  </Pie>
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                    itemStyle={{ color: '#f1f5f9', fontSize: '12px' }}
                  />
                  <Legend verticalAlign="bottom" height={36} iconType="circle" wrapperStyle={{ fontSize: '11px', color: '#94a3b8' }} />
                </PieChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Threat Source Breakdown */}
          <div className="card p-5 bg-gray-900/40 backdrop-blur-md border border-gray-800/60 shadow-[0_8px_30px_rgb(0,0,0,0.12)]">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <Database className="h-4 w-4 text-emerald-400" />
              Source Breakdown
            </h3>
            <div className="h-[200px] w-full">
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={iocSourceData} layout="vertical" margin={{ top: 10, right: 30, left: 20, bottom: 5 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={true} vertical={false} />
                  <XAxis type="number" stroke="#64748b" fontSize={10} tickLine={false} axisLine={false} />
                  <YAxis dataKey="name" type="category" stroke="#94a3b8" fontSize={11} tickLine={false} axisLine={false} />
                  <Tooltip 
                    cursor={{ fill: '#1e293b', opacity: 0.4 }}
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                  />
                  <Bar dataKey="value" radius={[0, 4, 4, 0]} barSize={24} />
                </BarChart>
              </ResponsiveContainer>
            </div>
          </div>

          {/* Intelligence Sync Timeline */}
          <div className="card p-5 bg-gray-900/40 backdrop-blur-md border border-gray-800/60 shadow-[0_8px_30px_rgb(0,0,0,0.12)]">
            <h3 className="text-xs font-bold text-gray-400 uppercase tracking-widest mb-4 flex items-center gap-2">
              <Activity className="h-4 w-4 text-blue-400" />
              Sync Timeline
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
                  <Tooltip 
                    contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                    labelStyle={{ color: '#94a3b8' }}
                  />
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
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg font-medium transition-colors"
          >
            <Plus className="h-4 w-4" />
            Add Manual IOC
          </button>
          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            className="flex items-center gap-2 bg-gray-800 hover:bg-gray-700 text-gray-200 px-4 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 border border-gray-700"
          >
            <RefreshCw className={`h-4 w-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            {syncMutation.isPending ? 'Syncing...' : 'Sync OpenCTI'}
          </button>
        </div>
      </div>

      <div className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col" style={{ height: 'calc(100vh - 250px)' }}>
        <div className="overflow-auto flex-1">
          <table className="w-full text-left text-sm text-gray-400 relative">
            <thead className="bg-gray-950/90 text-gray-500 uppercase text-xs sticky top-0 z-10 backdrop-blur-sm shadow-sm">
              <tr>
                <th className="px-6 py-3 font-medium">Type</th>
                <th className="px-6 py-3 font-medium">Value</th>
                <th className="px-6 py-3 font-medium">Description</th>
                <th className="px-6 py-3 font-medium">Date Synced</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800">
              {isLoading ? (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-gray-500">
                    Loading IOCs...
                  </td>
                </tr>
              ) : !iocs || iocs.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-6 py-8 text-center text-gray-500">
                    No IOCs found. Click "Sync Now" to fetch data from OpenCTI.
                  </td>
                </tr>
              ) : (
                iocs.map((ioc: any) => (
                  <tr key={ioc.id} className="hover:bg-gray-800/50 transition-colors">
                    <td className="px-6 py-3">
                      <div className="flex items-center gap-2">
                        {getIconForType(ioc.type)}
                        <span className="font-medium text-gray-300">{ioc.type}</span>
                        {ioc.source === 'Manual' && (
                          <span className="ml-2 px-1.5 py-0.5 rounded-full text-[10px] font-medium bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                            MANUAL
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-6 py-3 font-mono text-emerald-400 break-all">{ioc.value}</td>
                    <td className="px-6 py-3 max-w-xs truncate" title={ioc.description}>
                      {ioc.description || <span className="text-gray-600 italic">No description</span>}
                    </td>
                    <td className="px-6 py-3 whitespace-nowrap">
                      {new Date(ioc.created_at).toLocaleDateString()}
                    </td>
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
  const queryClient = useQueryClient()
  
  const addMutation = useMutation({
    mutationFn: openctiApi.addManualIOC,
    onSuccess: (data) => {
      toast.success(data.message)
      queryClient.invalidateQueries({ queryKey: ['iocs'] })
      onClose()
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Failed to add manual IOC')
    },
  })

  const handleSubmit = (e: React.FormEvent<HTMLFormElement>) => {
    e.preventDefault()
    const formData = new FormData(e.currentTarget)
    const payload: ManualIOCPayload = {
      type: formData.get('type') as string,
      value: formData.get('value') as string,
    }
    const description = formData.get('description') as string
    if (description) payload.description = description

    addMutation.mutate(payload)
  }

  return (
    <div className="fixed inset-0 bg-black/60 backdrop-blur-sm flex items-center justify-center z-50 p-4">
      <div className="bg-gray-900 border border-gray-800 rounded-xl max-w-md w-full shadow-2xl overflow-hidden animate-in fade-in zoom-in-95 duration-200">
        <div className="flex justify-between items-center px-6 py-4 border-b border-gray-800">
          <h2 className="text-lg font-medium text-gray-100 flex items-center gap-2">
            <Plus className="h-5 w-5 text-emerald-500" />
            Add Manual IOC
          </h2>
          <button onClick={onClose} className="text-gray-400 hover:text-gray-200 transition-colors">
            <X className="h-5 w-5" />
          </button>
        </div>

        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">IOC Type</label>
            <select
              name="type"
              required
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 appearance-none"
            >
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
            <input
              name="value"
              type="text"
              required
              placeholder="e.g. 192.168.1.1 or malicious.com"
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 font-mono"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Description (Optional)</label>
            <textarea
              name="description"
              rows={3}
              placeholder="Added manually for investigation..."
              className="w-full bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 resize-none"
            />
          </div>

          <div className="pt-4 flex justify-end gap-3">
            <button
              type="button"
              onClick={onClose}
              className="px-4 py-2 text-sm font-medium text-gray-400 hover:text-gray-200 transition-colors"
            >
              Cancel
            </button>
            <button
              type="submit"
              disabled={addMutation.isPending}
              className="bg-emerald-600 hover:bg-emerald-500 text-white px-4 py-2 rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
            >
              {addMutation.isPending ? 'Adding...' : 'Add IOC'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

type ManualMode = 'lucene' | 'dsl'

interface AutoState {
  running: boolean
  hits: ELKHit[]
  progress?: AutoHuntProgress
  done?: AutoHuntDoneEvent
  batchErrors: { batch: number; bucket: string; error: string }[]
}

function HuntTab() {
  const token = useAuthStore((s) => s.token)
  const esRef = useRef<EventSource | null>(null)

  const [manualMode, setManualMode] = useState<ManualMode>('lucene')
  const [luceneQuery, setLuceneQuery] = useState('')
  const [dslText, setDslText] = useState(
    JSON.stringify(
      {
        query: { match_all: {} },
        size: 50,
        sort: [{ '@timestamp': { order: 'desc', unmapped_type: 'boolean' } }],
      },
      null,
      2,
    ),
  )

  const [auto, setAuto] = useState<AutoState>({
    running: false,
    hits: [],
    batchErrors: [],
  })

  // Close any open SSE stream when the tab unmounts so we don't leak the
  // connection while the hunt is still running upstream.
  useEffect(() => {
    return () => {
      esRef.current?.close()
      esRef.current = null
    }
  }, [])

  const manualMutation = useMutation({
    mutationFn: elkApi.manualHunt,
    onSuccess: (data) => {
      toast.success(`Manual hunt completed in ${data.took}ms`)
    },
    onError: (err: any) => {
      toast.error(err.response?.data?.error || 'Hunt failed')
    },
  })

  const startAutoHunt = () => {
    if (!token) {
      toast.error('Not authenticated')
      return
    }
    if (auto.running) return

    esRef.current?.close()
    setAuto({ running: true, hits: [], progress: undefined, done: undefined, batchErrors: [] })

    esRef.current = elkApi.streamAutoHunt(token, {
      onProgress: (p) => setAuto((s) => ({ ...s, progress: p })),
      onHits: (h) => setAuto((s) => ({ ...s, hits: [...s.hits, ...h.hits] })),
      onError: (e) =>
        setAuto((s) => ({
          ...s,
          batchErrors: [...s.batchErrors, { batch: e.batch, bucket: e.bucket, error: e.error }],
        })),
      onDone: (d) => {
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
    esRef.current?.close()
    esRef.current = null
    setAuto((s) => ({ ...s, running: false }))
  }

  const runManual = () => {
    if (manualMode === 'lucene') {
      if (!luceneQuery.trim()) {
        toast.error('Enter a Lucene query string')
        return
      }
      manualMutation.mutate({ mode: 'lucene', query: luceneQuery })
      return
    }
    let parsed: Record<string, any>
    try {
      parsed = JSON.parse(dslText)
    } catch (e: any) {
      toast.error(`Invalid JSON: ${e.message}`)
      return
    }
    if (typeof parsed !== 'object' || Array.isArray(parsed) || parsed === null) {
      toast.error('DSL body must be a JSON object')
      return
    }
    manualMutation.mutate({ mode: 'dsl', body: parsed })
  }

  const manualHits = manualMutation.data?.hits.hits ?? []
  const manualTotal = manualMutation.data?.hits.total
  const showManual = manualMutation.data !== undefined
  const showAuto = auto.running || auto.hits.length > 0 || auto.done !== undefined

  return (
    <div className="space-y-4">
      {/* Auto Hunt panel */}
      <div className="flex flex-col gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-medium text-gray-200 flex items-center gap-2">
              <Zap className="h-5 w-5 text-emerald-500" />
              Auto Hunt (all IOCs)
            </h2>
            <p className="text-sm text-gray-500">
              Streams across <span className="text-gray-300">every IOC</span> in the database in batches.
              Safe for large IOC sets — runs slower instead of overloading the cluster.
            </p>
          </div>
          {auto.running ? (
            <button
              onClick={stopAutoHunt}
              className="flex items-center gap-2 bg-red-600/80 hover:bg-red-500 text-white px-5 py-2 rounded-lg font-medium transition-colors"
            >
              <X className="h-4 w-4" />
              Stop
            </button>
          ) : (
            <button
              onClick={startAutoHunt}
              className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg font-medium transition-colors whitespace-nowrap"
            >
              <Search className="h-4 w-4" />
              Start Auto Hunt
            </button>
          )}
        </div>

        {(auto.running || auto.progress) && (
          <div className="border-t border-gray-800 pt-3 space-y-2 text-sm">
            <div className="flex flex-wrap gap-x-6 gap-y-1 font-mono text-xs text-gray-400">
              <span>
                batch:{' '}
                <span className="text-emerald-400">
                  {auto.progress?.batch ?? 0} / {auto.progress?.total_batches ?? '?'}
                </span>
              </span>
              <span>
                bucket: <span className="text-emerald-400">{auto.progress?.bucket ?? '—'}</span>
              </span>
              <span>
                hits so far: <span className="text-emerald-400">{auto.progress?.total_hits ?? auto.hits.length}</span>
              </span>
              {auto.done && <span>took: <span className="text-emerald-400">{auto.done.took_ms}ms</span></span>}
            </div>
            <div className="h-1.5 w-full bg-gray-800 rounded overflow-hidden">
              <div
                className="h-full bg-emerald-500 transition-all"
                style={{
                  width: `${
                    auto.progress && auto.progress.total_batches > 0
                      ? Math.min(100, (auto.progress.batch / auto.progress.total_batches) * 100)
                      : 0
                  }%`,
                }}
              />
            </div>
            {auto.batchErrors.length > 0 && (
              <details className="text-xs text-amber-400/80">
                <summary className="cursor-pointer">{auto.batchErrors.length} batch error(s)</summary>
                <ul className="mt-1 space-y-1 font-mono">
                  {auto.batchErrors.map((e, i) => (
                    <li key={i}>
                      batch {e.batch} [{e.bucket}]: {e.error}
                    </li>
                  ))}
                </ul>
              </details>
            )}
          </div>
        )}
      </div>

      {/* Manual Search panel */}
      <div className="flex flex-col gap-4 bg-gray-900 border border-gray-800 rounded-xl p-4">
        <div className="flex justify-between items-center">
          <div>
            <h2 className="text-lg font-medium text-gray-200 flex items-center gap-2">
              <Code2 className="h-5 w-5 text-emerald-500" />
              Manual Search
            </h2>
            <p className="text-sm text-gray-500">
              Run any Elasticsearch query — Lucene string or full DSL body.
            </p>
          </div>
          <div className="flex bg-gray-950 rounded-lg p-1 border border-gray-800 self-start">
            <button
              onClick={() => setManualMode('lucene')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                manualMode === 'lucene' ? 'bg-gray-800 text-emerald-400' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              Lucene
            </button>
            <button
              onClick={() => setManualMode('dsl')}
              className={`px-3 py-1.5 rounded text-xs font-medium transition-colors ${
                manualMode === 'dsl' ? 'bg-gray-800 text-emerald-400' : 'text-gray-500 hover:text-gray-300'
              }`}
            >
              Raw DSL (JSON)
            </button>
          </div>
        </div>

        {manualMode === 'lucene' ? (
          <input
            type="text"
            value={luceneQuery}
            onChange={(e) => setLuceneQuery(e.target.value)}
            placeholder='e.g. source.ip:"192.168.1.1" OR url.domain:"malicious.com"'
            className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 font-mono text-sm"
          />
        ) : (
          <textarea
            value={dslText}
            onChange={(e) => setDslText(e.target.value)}
            rows={10}
            spellCheck={false}
            className="bg-gray-950 border border-gray-800 rounded-lg px-4 py-2 text-gray-200 focus:outline-none focus:border-emerald-500 focus:ring-1 focus:ring-emerald-500 font-mono text-xs resize-y"
          />
        )}

        <div className="flex justify-end">
          <button
            onClick={runManual}
            disabled={manualMutation.isPending}
            className="flex items-center gap-2 bg-emerald-600 hover:bg-emerald-500 text-white px-5 py-2 rounded-lg font-medium transition-colors disabled:opacity-50 whitespace-nowrap"
          >
            <Search className={`h-4 w-4 ${manualMutation.isPending ? 'animate-pulse' : ''}`} />
            {manualMutation.isPending ? 'Searching...' : 'Run Search'}
          </button>
        </div>
      </div>

      {/* Results area */}
      {!showAuto && !showManual && !manualMutation.isPending && (
        <div className="bg-gray-900 border border-gray-800 rounded-xl p-12 text-center flex flex-col items-center justify-center">
          <Search className="h-12 w-12 text-gray-700 mb-4" />
          <h3 className="text-lg font-medium text-gray-300">Ready to Hunt</h3>
          <p className="text-gray-500 max-w-sm mt-2">
            Start an auto hunt across all IOCs, or run a manual Lucene / DSL query.
          </p>
        </div>
      )}

      {showAuto && (
        <ResultsPanel
          title="Auto Hunt Results"
          hits={auto.hits}
          totalLabel={
            auto.done
              ? `${auto.done.total_hits} unique hits across ${auto.done.total_iocs} IOCs (${auto.done.total_batches} batches)`
              : `${auto.hits.length} hits so far`
          }
          tookMs={auto.done?.took_ms}
        />
      )}

      {showManual && (
        <ResultsPanel
          title="Manual Search Results"
          hits={manualHits}
          totalLabel={
            manualTotal
              ? `${manualTotal.value}${manualTotal.relation === 'gte' ? '+' : ''} matches`
              : ''
          }
          tookMs={manualMutation.data?.took}
        />
      )}
    </div>
  )
}

function ResultsPanel({
  title,
  hits,
  totalLabel,
  tookMs,
}: {
  title: string
  hits: ELKHit[]
  totalLabel: string
  tookMs?: number
}) {
  return (
    <div
      className="bg-gray-900 border border-gray-800 rounded-xl overflow-hidden flex flex-col"
      style={{ height: 'calc(100vh - 250px)' }}
    >
      <div className="p-4 bg-gray-950/50 border-b border-gray-800 flex justify-between items-center">
        <div className="flex items-center gap-2">
          {hits.length > 0 ? (
            <AlertTriangle className="h-5 w-5 text-red-500" />
          ) : (
            <ShieldAlert className="h-5 w-5 text-emerald-500" />
          )}
          <span className="font-medium text-gray-200">{title}</span>
          <span className="text-xs text-gray-500">— {totalLabel}</span>
        </div>
        {tookMs !== undefined && (
          <span className="text-xs text-gray-500 font-mono">took: {tookMs}ms</span>
        )}
      </div>

      <div className="overflow-auto flex-1 p-4 bg-gray-950/20">
        {hits.length === 0 ? (
          <div className="h-full flex items-center justify-center text-emerald-500/80 italic">
            No matches yet.
          </div>
        ) : (
          <div className="space-y-4">
            {hits.map((hit, idx) => (
              <div
                key={`${hit._index}-${hit._id}-${idx}`}
                className="bg-gray-900 border border-red-900/30 rounded-lg p-4 shadow-sm relative overflow-hidden group"
              >
                <div className="absolute left-0 top-0 bottom-0 w-1 bg-red-500/50 group-hover:bg-red-500 transition-colors"></div>
                <div className="flex justify-between items-start mb-2">
                  <span className="text-xs font-mono bg-gray-800 text-gray-400 px-2 py-1 rounded">
                    {hit._index}
                  </span>
                  <span className="text-xs text-gray-500 font-mono">
                    Score: {hit._score?.toFixed(2) ?? '—'}
                  </span>
                </div>
                <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-all bg-gray-950 p-3 rounded border border-gray-800 overflow-x-auto">
                  {JSON.stringify(hit._source, null, 2)}
                </pre>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
