import { useState, useEffect, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Search, Bug, Trash2, Plus, ExternalLink, Loader2, BarChart3, List, Zap, ShieldAlert,
  Newspaper, Shield, Building, Eye, Star, Globe, Target,
  type LucideIcon,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import CVENewsTab from '@/components/CVENewsTab'
import {
  PieChart, Pie, Cell, ResponsiveContainer,
  BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, Legend,
  ScatterChart, Scatter, ZAxis,
  AreaChart, Area
} from 'recharts'
import { newsApi, type NewsArticle, type NewsCategory } from '@/api/news'
import { cveCollectionApi, CollectedCVE } from '@/api/cve_collection'
import { cveApi } from '@/api/cve'
import { SeverityBadge } from '@/components/StatusBadge'
import { getErrorMessage } from '@/lib/utils'
import { useAuthStore } from '@/store/auth'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
} from '@/components/ui/dialog'

const SEVERITY_COLORS = {
  critical: '#ef4444', // red-500
  high: '#f97316',     // orange-500
  medium: '#eab308',   // yellow-500
  low: '#22c55e',      // green-500
  none: '#64748b'      // slate-500
}

type TabType =
  | 'list'
  | 'analytics'
  | 'news-general'
  | 'news-threat-intel'
  | 'news-gov-alerts'
  | 'news-darkweb'
  | 'news-high-quality'
  | 'news-world-news'
  | 'news-vn-target'

const TABS: { id: TabType; label: string; icon: LucideIcon }[] = [
  { id: 'analytics', label: 'Analytics', icon: BarChart3 },
  { id: 'list', label: 'CVE alert', icon: List },
  { id: 'news-vn-target', label: 'VN Target', icon: Target },
  { id: 'news-world-news', label: 'World News', icon: Globe },
  { id: 'news-high-quality', label: 'High Quality', icon: Star },
  { id: 'news-gov-alerts', label: 'Gov Alerts', icon: Building },
  { id: 'news-threat-intel', label: 'Threat Intel', icon: Shield },
  { id: 'news-darkweb', label: 'Dark Web', icon: Eye },
  { id: 'news-general', label: 'General News', icon: Newspaper },
]

function newsCategoryOf(tab: TabType): NewsCategory | null {
  if (!tab.startsWith('news-')) return null
  return tab.replace('news-', '') as NewsCategory
}

export default function CVECollectionPage() {
  const [activeTab, setActiveTab] = useState<TabType>('analytics')
  const [searchQuery, setSearchQuery] = useState('')
  const [isAddOpen, setIsAddOpen] = useState(false)
  const queryClient = useQueryClient()


  const { data: cves = [], isLoading, isError, error } = useQuery({
    queryKey: ['cve-collection'],
    queryFn: cveCollectionApi.getAll,
  })

  // Real-time updates via SSE
  useEffect(() => {
    const token = useAuthStore.getState().token ?? ''
    const base = import.meta.env.VITE_API_URL || window.location.origin
    const url = `${base}/api/v1/cve-collection/stream?token=${encodeURIComponent(token)}`

    const eventSource = new EventSource(url)

    eventSource.addEventListener('update', () => {
      queryClient.invalidateQueries({ queryKey: ['cve-collection'] })
    })

    eventSource.onerror = (err) => {
      console.error('CVE SSE Error:', err)
      eventSource.close()
    }

    return () => {
      eventSource.close()
    }
  }, [queryClient])

  const deleteMutation = useMutation({
    mutationFn: cveCollectionApi.delete,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cve-collection'] })
    },
  })

  const filteredCves = useMemo(() => {
    return cves.filter(
      (c) =>
        c.id.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        c.tags?.some((t) => t.toLowerCase().includes(searchQuery.toLowerCase()))
    )
  }, [cves, searchQuery])

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 flex items-center gap-2">
            <Bug className="h-5 w-5 text-emerald-400" />
            Threat Intelligence
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            List of specially tracked, internally stored CVEs.
          </p>
        </div>
        <div className="flex items-center gap-3 flex-wrap">
          <div className="flex bg-gray-900/80 p-1 rounded-lg border border-gray-800 flex-wrap">
            {TABS.map((tab) => {
              const Icon = tab.icon
              const isActive = activeTab === tab.id

              return (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`relative flex items-center gap-2 px-3 py-1.5 text-xs font-medium rounded-md transition-all ${
                    isActive
                      ? 'bg-gray-800 text-emerald-400 shadow-sm'
                      : 'text-gray-400 hover:text-gray-200'
                  }`}
                >
                  <Icon className="h-3.5 w-3.5" />
                  {tab.label}
                </button>
              )
            })}
          </div>
          {!activeTab.startsWith('news-') && (
            <button className="btn-primary" onClick={() => setIsAddOpen(true)}>
              <Plus className="h-4 w-4" />
              Add CVE
            </button>
          )}
        </div>
      </div>

      {activeTab === 'list' && (
        <>
          {/* Filter */}
          <div className="card p-4">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
              <input
                className="input pl-9 text-sm"
                placeholder="Search CVE ID, description, tags..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
              />
            </div>
          </div>

          {/* Results */}
          <div className="card overflow-hidden">
            {isLoading && (
              <div className="p-6 space-y-3">
                {Array.from({ length: 3 }).map((_, i) => (
                  <div key={i} className="skeleton h-16 w-full rounded" />
                ))}
              </div>
            )}

            {isError && (
              <div className="p-6 text-red-400 text-sm">
                Failed to load CVE collection: {getErrorMessage(error)}
              </div>
            )}

            {filteredCves.length === 0 && !isLoading && !isError && (
              <div className="p-12 text-center text-gray-500">
                No CVEs in the collection.
              </div>
            )}

            {filteredCves.length > 0 && (
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead className="bg-gray-900/50 border-b border-gray-800">
                    <tr>
                      <th className="table-header text-left px-4 py-3 w-44">CVE ID</th>
                      <th className="table-header text-left px-4 py-3 w-36">Severity</th>
                      <th className="table-header text-left px-4 py-3 w-32">Risk (EPSS)</th>
                      <th className="table-header text-left px-4 py-3">Details</th>
                      <th className="table-header text-left px-4 py-3 w-32">Added</th>
                      <th className="table-header px-4 py-3 w-16"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredCves.map((cve) => (
                      <tr key={cve.id} className="border-b border-gray-800/50 hover:bg-gray-800/30">
                        <td className="px-4 py-3 font-mono text-emerald-400 font-semibold">{cve.id}</td>
                        <td className="px-4 py-3">
                          <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
                          {cve.is_kev && (
                            <div className="mt-1">
                              <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold bg-red-900/60 text-red-400 border border-red-800 animate-pulse">
                                <ShieldAlert className="h-3 w-3" />
                                EXPLOITED
                              </span>
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          {cve.epss_score ? (
                            <div className="space-y-1">
                              <div className="flex items-center gap-2">
                                <Zap className={`h-3 w-3 ${cve.epss_score > 0.1 ? 'text-amber-400' : 'text-gray-500'}`} />
                                <span className="text-sm font-mono text-gray-300">
                                  {(cve.epss_score * 100).toFixed(2)}%
                                </span>
                              </div>
                              <div className="w-20 h-1 bg-gray-800 rounded-full overflow-hidden">
                                <div 
                                  className={`h-full ${cve.epss_score > 0.3 ? 'bg-red-500' : cve.epss_score > 0.1 ? 'bg-amber-500' : 'bg-emerald-500'}`}
                                  style={{ width: `${Math.min(cve.epss_score * 100, 100)}%` }}
                                />
                              </div>
                            </div>
                          ) : (
                            <span className="text-gray-600 text-xs">N/A</span>
                          )}
                        </td>
                        <td className="px-4 py-3">
                          <p className="line-clamp-2 text-sm text-gray-300">{cve.description}</p>
                          <div className="mt-2 flex flex-wrap gap-2 items-center">
                            {cve.source && (
                              <span className="text-[10px] px-1.5 py-0 bg-gray-800 text-gray-400 rounded border border-gray-700 uppercase">
                                {cve.source}
                              </span>
                            )}
                            {cve.poc_links && cve.poc_links.length > 0 && (
                              cve.poc_links.map((link, idx) => (
                                <a
                                  key={idx}
                                  href={link}
                                  target="_blank"
                                  rel="noopener noreferrer"
                                  className="inline-flex items-center gap-1 text-[11px] bg-gray-900 border border-gray-700 rounded px-2 py-0.5 text-emerald-400 hover:text-emerald-300"
                                >
                                  PoC
                                  <ExternalLink className="h-3 w-3" />
                                </a>
                              ))
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3 text-xs text-gray-500">
                          {cve.added_at ? formatDistanceToNow(new Date(cve.added_at), { addSuffix: true }) : ''}
                        </td>
                        <td className="px-4 py-3 text-right">
                          <button
                            onClick={(e) => {
                              e.stopPropagation()
                              if (confirm(`Remove ${cve.id} from collection?`)) {
                                deleteMutation.mutate(cve.id)
                              }
                            }}
                            className="text-gray-500 hover:text-red-400 transition-colors"
                            title="Delete"
                          >
                            <Trash2 className="h-4 w-4" />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </div>
        </>
      )}

      {activeTab === 'analytics' && (
        <div className="space-y-6">
          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
              Threat Intelligence Overview
            </h2>
            <CVEAnalytics cves={cves} />
          </section>
          <section className="space-y-3">
            <h2 className="text-sm font-semibold text-gray-300 uppercase tracking-wide">
              News Aggregation
            </h2>
            <NewsAnalytics />
          </section>
        </div>
      )}

      {newsCategoryOf(activeTab) && (
        <CVENewsTab category={newsCategoryOf(activeTab) as NewsCategory} />
      )}

      <AddCveDialog open={isAddOpen} onClose={() => setIsAddOpen(false)} />
    </div>
  )
}

function CVEAnalytics({ cves }: { cves: CollectedCVE[] }) {
  const severityData = useMemo(() => {
    const counts: Record<string, number> = { critical: 0, high: 0, medium: 0, low: 0, none: 0 }
    cves.forEach(c => {
      const s = c.severity.toLowerCase()
      if (counts[s] !== undefined) counts[s]++
    })
    return Object.entries(counts)
      .filter(([_, count]) => count > 0)
      .map(([name, value]) => ({ name: name.toUpperCase(), value, color: SEVERITY_COLORS[name as keyof typeof SEVERITY_COLORS] }))
  }, [cves])

  const exploitData = useMemo(() => {
    return [
      { name: 'Total CVEs', count: cves.length },
      { name: 'Has PoC', count: cves.filter(c => c.poc_links && c.poc_links.length > 0).length },
      { name: 'CISA KEV', count: cves.filter(c => c.is_kev).length },
    ]
  }, [cves])

  const scatterData = useMemo(() => {
    return cves
      .filter(c => c.cvss_score > 0 && c.epss_score !== undefined)
      .map(c => ({
        id: c.id,
        cvss: c.cvss_score,
        epss: (c.epss_score || 0) * 100,
        severity: c.severity
      }))
  }, [cves])

  const sourceData = useMemo(() => {
    const sources: Record<string, number> = {}
    cves.forEach(c => {
      const s = c.source || 'Unknown'
      sources[s] = (sources[s] || 0) + 1
    })
    return Object.entries(sources).map(([name, value]) => ({ name, value }))
  }, [cves])

  if (cves.length === 0) {
    return (
      <div className="card p-12 text-center text-gray-500">
        <BarChart3 className="h-8 w-8 mx-auto mb-3 opacity-20" />
        <p>Not enough data for analysis.</p>
      </div>
    )
  }

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
      {/* Severity Pie Chart */}
      <div className="card p-4 h-72 flex flex-col">
        <h3 className="text-sm font-medium text-gray-300">Severity Distribution</h3>
        <div className="flex-1 mt-2 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <PieChart>
              <Pie
                data={severityData}
                cx="50%"
                cy="50%"
                innerRadius={60}
                outerRadius={80}
                paddingAngle={5}
                dataKey="value"
              >
                {severityData.map((entry, index) => (
                  <Cell key={`cell-${index}`} fill={entry.color} />
                ))}
              </Pie>
              <Tooltip 
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                itemStyle={{ color: '#f1f5f9' }}
              />
              <Legend verticalAlign="bottom" height={36}/>
            </PieChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Exploit Status Bar Chart */}
      <div className="card p-4 h-72 flex flex-col">
        <h3 className="text-sm font-medium text-gray-300">Exploitation Status</h3>
        <div className="flex-1 mt-2 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={exploitData}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
              <XAxis dataKey="name" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip 
                cursor={{ fill: '#1e293b', opacity: 0.4 }}
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
              />
              <Bar dataKey="count" fill="#10b981" radius={[4, 4, 0, 0]} barSize={40} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* EPSS vs CVSS Scatter Chart */}
      <div className="card p-4 h-80 flex flex-col lg:col-span-2">
        <h3 className="text-sm font-medium text-gray-300">EPSS (%) vs CVSS Score</h3>
        <div className="flex-1 mt-2 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <ScatterChart margin={{ top: 20, right: 20, bottom: 20, left: 20 }}>
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" />
              <XAxis type="number" dataKey="cvss" name="CVSS" unit="" stroke="#64748b" fontSize={12} domain={[0, 10]} />
              <YAxis type="number" dataKey="epss" name="EPSS" unit="%" stroke="#64748b" fontSize={12} />
              <ZAxis type="category" dataKey="id" name="CVE" />
              <Tooltip 
                cursor={{ strokeDasharray: '3 3' }}
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
              />
              <Scatter name="CVEs" data={scatterData} fill="#3b82f6" />
            </ScatterChart>
          </ResponsiveContainer>
        </div>
      </div>

      {/* Source Distribution Bar Chart */}
      <div className="card p-4 h-80 flex flex-col">
        <h3 className="text-sm font-medium text-gray-300">Data Sources</h3>
        <div className="flex-1 mt-2 min-h-0">
          <ResponsiveContainer width="100%" height="100%">
            <BarChart data={sourceData} layout="vertical">
              <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
              <XAxis type="number" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <YAxis dataKey="name" type="category" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} />
              <Tooltip 
                cursor={{ fill: '#1e293b', opacity: 0.4 }}
                contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
              />
              <Bar dataKey="value" fill="#8b5cf6" radius={[0, 4, 4, 0]} barSize={20} />
            </BarChart>
          </ResponsiveContainer>
        </div>
      </div>
    </div>
  )
}

const NEWS_CATEGORY_META: { slug: NewsCategory; label: string; color: string }[] = [
  { slug: 'vn-target',    label: 'VN Target',    color: '#ef4444' },
  { slug: 'general',      label: 'General',      color: '#10b981' },
  { slug: 'threat-intel', label: 'Threat Intel', color: '#3b82f6' },
  { slug: 'gov-alerts',   label: 'Gov Alerts',   color: '#f97316' },
  { slug: 'darkweb',      label: 'Dark Web',     color: '#a855f7' },
  { slug: 'high-quality', label: 'High Quality', color: '#facc15' },
  { slug: 'world-news',   label: 'World News',   color: '#8b5cf6' },
]

function NewsAnalytics() {
  const { data: articles = [], isLoading } = useQuery({
    queryKey: ['news', 'all'],
    queryFn: () => newsApi.list(),
  })

  const categoryData = useMemo(() => {
    const counts: Record<string, number> = {}
    NEWS_CATEGORY_META.forEach((c) => { counts[c.slug] = 0 })
    articles.forEach((a) => {
      if (counts[a.category] !== undefined) counts[a.category]++
    })
    return NEWS_CATEGORY_META.map((c) => ({
      name: c.label,
      slug: c.slug,
      value: counts[c.slug],
      color: c.color,
    }))
  }, [articles])

  const topSourcesData = useMemo(() => {
    const counts: Record<string, number> = {}
    articles.forEach((a) => {
      counts[a.source] = (counts[a.source] || 0) + 1
    })
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10)
  }, [articles])

  const dailyData = useMemo(() => buildDailySeries(articles, 14), [articles])

  const tagData = useMemo(() => {
    const counts: Record<string, number> = {}
    articles.forEach((a) => {
      a.tags?.forEach((t) => {
        const k = t.trim().toLowerCase()
        if (!k || k.length > 30) return
        counts[k] = (counts[k] || 0) + 1
      })
    })
    return Object.entries(counts)
      .map(([name, value]) => ({ name, value }))
      .sort((a, b) => b.value - a.value)
      .slice(0, 10)
  }, [articles])

  if (isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {Array.from({ length: 4 }).map((_, i) => (
          <div key={i} className="skeleton h-[290px] w-full rounded" />
        ))}
      </div>
    )
  }

  if (articles.length === 0) {
    return (
      <div className="card p-12 text-center text-gray-500">
        <Newspaper className="h-8 w-8 mx-auto mb-3 opacity-20" />
        <p>No articles yet. The worker is collecting data, please check back in a few minutes.</p>
      </div>
    )
  }

  return (
    <div className="space-y-4">
      {/* Top row */}
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <div className="card p-4 h-80 flex flex-col md:col-span-1">
          <h3 className="text-sm font-medium text-gray-300">Articles by Category</h3>
          <div className="flex-1 mt-2 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={categoryData}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="name" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  cursor={{ fill: '#1e293b', opacity: 0.4 }}
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                />
                <Bar dataKey="value" radius={[4, 4, 0, 0]} barSize={36}>
                  {categoryData.map((entry, idx) => (
                    <Cell key={idx} fill={entry.color} />
                  ))}
                </Bar>
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        {/* Articles per Day (14d) */}
        <div className="card p-4 h-80 flex flex-col md:col-span-2">
          <h3 className="text-sm font-medium text-gray-300">Article Volume (14 days)</h3>
          <div className="flex-1 mt-2 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <AreaChart data={dailyData} margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                <defs>
                  <linearGradient id="newsArea" x1="0" y1="0" x2="0" y2="1">
                    <stop offset="0%" stopColor="#10b981" stopOpacity={0.4} />
                    <stop offset="100%" stopColor="#10b981" stopOpacity={0} />
                  </linearGradient>
                </defs>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" vertical={false} />
                <XAxis dataKey="day" stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <YAxis stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <Tooltip
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                  itemStyle={{ color: '#f1f5f9' }}
                />
                <Area
                  type="monotone"
                  dataKey="count"
                  stroke="#10b981"
                  strokeWidth={2}
                  fill="url(#newsArea)"
                />
              </AreaChart>
            </ResponsiveContainer>
          </div>
        </div>
      </div>

      {/* Bottom row */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="card p-4 h-80 flex flex-col">
          <h3 className="text-sm font-medium text-gray-300">Top 10 Sources (by article count)</h3>
          <div className="flex-1 mt-2 min-h-0">
            <ResponsiveContainer width="100%" height="100%">
              <BarChart data={topSourcesData} layout="vertical" margin={{ left: 10, right: 10 }}>
                <CartesianGrid strokeDasharray="3 3" stroke="#1e293b" horizontal={false} />
                <XAxis type="number" stroke="#64748b" fontSize={12} tickLine={false} axisLine={false} allowDecimals={false} />
                <YAxis dataKey="name" type="category" width={140} stroke="#64748b" fontSize={11} tickLine={false} axisLine={false} />
                <Tooltip
                  cursor={{ fill: '#1e293b', opacity: 0.4 }}
                  contentStyle={{ backgroundColor: '#0f172a', border: '1px solid #1e293b', borderRadius: '8px' }}
                />
                <Bar dataKey="value" fill="#06b6d4" radius={[0, 4, 4, 0]} barSize={16} />
              </BarChart>
            </ResponsiveContainer>
          </div>
        </div>

        <div className="card p-4 h-80 flex flex-col">
          <h3 className="text-sm font-medium text-gray-300">Popular Tags</h3>
          <div className="flex-1 mt-2 min-h-0">
            {tagData.length > 0 ? (
              <ResponsiveContainer width="100%" height="100%">
                <BarChart data={tagData} layout="vertical" margin={{ top: 10, right: 10, left: 0, bottom: 0 }}>
                  <CartesianGrid strokeDasharray="3 3" stroke="#1f2937" horizontal={true} vertical={false} />
                  <XAxis type="number" hide />
                  <YAxis dataKey="name" type="category" width={80} tick={{ fontSize: 10, fill: '#9ca3af' }} axisLine={false} tickLine={false} />
                  <Tooltip contentStyle={{ backgroundColor: '#111827', borderColor: '#374151' }} itemStyle={{ color: '#e5e7eb' }} />
                  <Bar dataKey="value" fill="#3b82f6" radius={[0, 4, 4, 0]} barSize={20} />
                </BarChart>
              </ResponsiveContainer>
            ) : (
              <div className="h-full flex items-center justify-center text-xs text-gray-600">
                No tags in collected data yet.
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}

function buildDailySeries(articles: NewsArticle[], days: number): { day: string; count: number }[] {
  const buckets: Record<string, number> = {}
  const today = new Date()
  today.setHours(0, 0, 0, 0)

  for (let i = days - 1; i >= 0; i--) {
    const d = new Date(today)
    d.setDate(d.getDate() - i)
    buckets[isoDay(d)] = 0
  }

  articles.forEach((a) => {
    if (!a.published) return
    const d = new Date(a.published)
    if (isNaN(d.getTime())) return
    const key = isoDay(d)
    if (key in buckets) buckets[key]++
  })

  return Object.entries(buckets).map(([day, count]) => ({
    day: day.slice(5),
    count,
  }))
}

function isoDay(d: Date): string {
  const y = d.getFullYear()
  const m = String(d.getMonth() + 1).padStart(2, '0')
  const day = String(d.getDate()).padStart(2, '0')
  return `${y}-${m}-${day}`
}

function AddCveDialog({ open, onClose }: { open: boolean; onClose: () => void }) {
  const [cveId, setCveId] = useState('')
  const [isFetching, setIsFetching] = useState(false)
  const [fetchError, setFetchError] = useState('')

  const queryClient = useQueryClient()
  const addMutation = useMutation({
    mutationFn: cveCollectionApi.add,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['cve-collection'] })
      onClose()
      setCveId('')
    },
  })

  const handleFetchAndSave = async () => {
    const id = cveId.trim().toUpperCase()
    if (!id) return

    setIsFetching(true)
    setFetchError('')

    try {
      // Fetch details from NVD
      const detail = await cveApi.get(id)
      
      // Fetch PoCs from GitHub
      let pocLinks: string[] = []
      try {
        const pocs = await cveApi.getPocs(id)
        pocLinks = pocs.map(p => p.html_url)
      } catch (err) {
        // ignore poc fetch error
      }

      // Save to collection
      await addMutation.mutateAsync({
        id: detail.id,
        description: detail.description,
        severity: detail.severity,
        cvss_score: detail.cvss_score,
        published_date: detail.published_date,
        poc_links: pocLinks,
        tags: [],
      })
      
    } catch (err) {
      setFetchError(getErrorMessage(err) || 'CVE information not found')
    } finally {
      setIsFetching(false)
    }
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && onClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Add new CVE</DialogTitle>
          <DialogDescription>
            Enter CVE ID (e.g., CVE-2023-1234), the system will automatically query NVD and GitHub for information.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div>
            <label className="label">CVE ID</label>
            <input
              autoFocus
              className="input uppercase"
              placeholder="CVE-YYYY-NNNN"
              value={cveId}
              onChange={(e) => setCveId(e.target.value)}
              onKeyDown={(e) => {
                if (e.key === 'Enter') handleFetchAndSave()
              }}
            />
          </div>

          {fetchError && <p className="text-sm text-red-400">{fetchError}</p>}
          {addMutation.isError && <p className="text-sm text-red-400">{getErrorMessage(addMutation.error)}</p>}

          <div className="flex justify-end gap-3 pt-4">
            <button type="button" className="btn-secondary" onClick={onClose} disabled={isFetching || addMutation.isPending}>
              Cancel
            </button>
            <button
              type="submit"
              className="btn-primary"
              onClick={handleFetchAndSave}
              disabled={!cveId.trim() || isFetching || addMutation.isPending}
            >
              {(isFetching || addMutation.isPending) ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Processing....
                </>
              ) : (
                'Add to collection'
              )}
            </button>
          </div>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}
