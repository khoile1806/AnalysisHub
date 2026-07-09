import { useMemo, useState, type FormEvent, type KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, Bug, AlertTriangle, ShieldAlert, FilterX, SlidersHorizontal, ArrowUpDown, Plus, X } from 'lucide-react'
import { cveApi, type CveSummary, type Severity } from '@/api/cve'
import { SeverityBadge } from '@/components/StatusBadge'
import { getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import { CveDetailDialog } from '@/components/CveDetailDialog'
import { useUiStore } from '@/store/uiStore'

const SEVERITY_OPTIONS: Severity[] = ['critical', 'high', 'medium', 'low', 'none']

const DEFAULT_FILTERS = {
  severities: new Set<Severity>(),
  onlyKev: false,
  cvssMin: 0,
  epssPercentileMin: 0,
}

export default function CVEPage() {
  const {
    cveInput: input,
    cveVersionInput: versionInput,
    cveQuery: query,
    cveVersion: version,
    cveSelectedId: selectedId,
    cveFilters: filters,
    setCveState
  } = useUiStore()

  const setInput = (val: string) => setCveState({ cveInput: val })
  const setVersionInput = (val: string) => setCveState({ cveVersionInput: val })
  const setQuery = (val: string) => setCveState({ cveQuery: val })
  const setVersion = (val: string) => setCveState({ cveVersion: val })
  const setSelectedId = (val: string | null) => setCveState({ cveSelectedId: val })
  const setFilters = (val: any) => setCveState({ cveFilters: typeof val === 'function' ? val(filters) : val })

  const search = useQuery({
    queryKey: ['cve', 'search', query, version],
    queryFn: () => cveApi.search(query, version || undefined, 100),
    enabled: query.length > 0,
    staleTime: 60_000,
    // The backend already fails fast (≈12s budget) and caches; retrying only
    // doubles the wait before the user sees an error on a throttled/empty query.
    retry: false,
  })

  const [sortBy, setSortBy] = useState<'risk' | 'cvss' | 'epss' | 'newest'>('risk')
  // Version input is hidden until requested (or when one is already set).
  const [showVersion, setShowVersion] = useState(!!versionInput)

  const filtered = useMemo<CveSummary[]>(() => {
    if (!search.data) return []
    return search.data.filter((cve) => {
      if (filters.severities.size > 0 && !filters.severities.has(cve.severity)) return false
      if (filters.onlyKev && !cve.is_kev) return false
      if (filters.cvssMin > 0 && (cve.cvss_score || 0) < filters.cvssMin) return false
      if (filters.epssPercentileMin > 0 && (cve.epss_percentile || 0) * 100 < filters.epssPercentileMin) return false
      return true
    })
  }, [search.data, filters])

  // Sorted view. "Risk" (default) is exploitation-priority: KEV first, then EPSS
  // percentile, then CVSS — the most actionable ordering for triage.
  const sorted = useMemo<CveSummary[]>(() => {
    const arr = [...filtered]
    arr.sort((a, b) => {
      switch (sortBy) {
        case 'cvss': return (b.cvss_score || 0) - (a.cvss_score || 0)
        case 'epss': return (b.epss_percentile || 0) - (a.epss_percentile || 0)
        case 'newest': return new Date(b.published_date || 0).getTime() - new Date(a.published_date || 0).getTime()
        default:
          if (a.is_kev !== b.is_kev) return a.is_kev ? -1 : 1
          if ((b.epss_percentile || 0) !== (a.epss_percentile || 0)) return (b.epss_percentile || 0) - (a.epss_percentile || 0)
          return (b.cvss_score || 0) - (a.cvss_score || 0)
      }
    })
    return arr
  }, [filtered, sortBy])

  // Triage counts over the full (unfiltered) result set.
  const stats = useMemo(() => {
    const d = search.data ?? []
    let critical = 0, high = 0, kev = 0, hot = 0
    for (const c of d) {
      if (c.severity === 'critical') critical++
      else if (c.severity === 'high') high++
      if (c.is_kev) kev++
      if ((c.epss_percentile || 0) >= 0.9) hot++
    }
    return { total: d.length, critical, high, kev, hot }
  }, [search.data])

  const filtersActive =
    filters.severities.size > 0 ||
    filters.onlyKev ||
    filters.cvssMin > 0 ||
    filters.epssPercentileMin > 0

  const toggleSeverity = (s: Severity) => {
    setFilters((prev: any) => {
      const next = new Set(prev.severities)
      if (next.has(s)) next.delete(s)
      else next.add(s)
      return { ...prev, severities: next }
    })
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    const trimmed = input.trim()
    if (trimmed) {
      setQuery(trimmed)
      setVersion(versionInput.trim())
    }
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') handleSubmit(e)
  }

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 flex items-center gap-2">
            <Bug className="h-5 w-5 text-emerald-400" />
            Vulnerability Search
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Search for vulnerability data and exploitation PoCs from NVD, WPScan, and GitHub.
          </p>
        </div>
      </div>

      {/* Search bar */}
      <form onSubmit={handleSubmit} className="card p-4">
        <div className="flex flex-col sm:flex-row sm:items-end gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center justify-between gap-2 mb-1">
              <span className="label mb-0">Product / Keyword</span>
              {!showVersion && (
                <button
                  type="button"
                  onClick={() => setShowVersion(true)}
                  className="text-[11px] text-gray-500 hover:text-emerald-400 inline-flex items-center gap-1"
                >
                  <Plus className="h-3 w-3" /> Add version
                </button>
              )}
            </div>
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
              <input
                id="cve-q"
                className="input pl-9"
                placeholder='e.g. "CVE-2021-44228, CWE-79, jquery"'
                value={input}
                onChange={(e) => setInput(e.target.value)}
                onKeyDown={handleKeyDown}
                maxLength={200}
              />
            </div>
          </div>

          {showVersion && (
            <div className="sm:w-[180px]">
              <label htmlFor="cve-v" className="label">Version</label>
              <div className="relative">
                <input
                  id="cve-v"
                  className="input pr-8"
                  placeholder="e.g. 1.6.2"
                  value={versionInput}
                  onChange={(e) => setVersionInput(e.target.value)}
                  onKeyDown={handleKeyDown}
                  maxLength={32}
                  autoFocus
                />
                <button
                  type="button"
                  onClick={() => { setShowVersion(false); setVersionInput('') }}
                  className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                  title="Remove version filter"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </div>
            </div>
          )}

          <button type="submit" className="btn-primary sm:w-auto justify-center" disabled={!input.trim()}>
            <Search className="h-4 w-4" />
            Search
          </button>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          Tip: You can search multiple vulnerabilities at once using commas (max 5 keywords). Directly supports formats like <span className="font-mono text-gray-400">CVE-YYYY-NNNN</span>, <span className="font-mono text-gray-400">CWE-NNN</span>, or <span className="font-mono text-gray-400">mal-xxx</span>.
          WPScan is only triggered when the query contains <span className="font-mono text-gray-400">wordpress</span>, <span className="font-mono text-gray-400">wp-&lt;slug&gt;</span> or <span className="font-mono text-gray-400">wp:&lt;slug&gt;</span>.
        </p>
      </form>

      {/* Pre-result states (full width) */}
      {!query && (
        <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
          <Search className="h-8 w-8 mb-3 opacity-40" />
          <p className="text-sm">Enter a product, keyword, or CVE/CWE id to start searching.</p>
        </div>
      )}
      {query && search.isLoading && (
        <div className="card p-6 space-y-3">
          {Array.from({ length: 6 }).map((_, i) => <div key={i} className="skeleton h-12 w-full rounded" />)}
        </div>
      )}
      {query && search.isError && (
        <div className="card flex flex-col items-center justify-center py-16 text-red-400">
          <AlertTriangle className="h-8 w-8 mb-3" />
          <p className="text-sm">{getErrorMessage(search.error)}</p>
        </div>
      )}
      {query && search.isSuccess && search.data.length === 0 && (
        <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
          <Bug className="h-8 w-8 mb-3 opacity-40" />
          <p className="text-sm">No CVEs found for "{query}{version ? ` ${version}` : ''}".</p>
        </div>
      )}

      {/* Results: sticky filter sidebar + list */}
      {query && search.isSuccess && search.data.length > 0 && (
        <div className="grid grid-cols-1 lg:grid-cols-[248px_1fr] gap-5 items-start">
          {/* Filters sidebar */}
          <aside className="card p-4 space-y-4 lg:sticky lg:top-4">
            <div className="flex items-center justify-between">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider inline-flex items-center gap-1.5">
                <SlidersHorizontal className="h-3.5 w-3.5" /> Filters
              </span>
              {filtersActive && (
                <button type="button" onClick={() => setFilters(DEFAULT_FILTERS)}
                  className="inline-flex items-center gap-1 text-[11px] text-gray-500 hover:text-gray-300">
                  <FilterX className="h-3 w-3" /> Clear
                </button>
              )}
            </div>

            <div>
              <div className="label mb-1.5">Severity</div>
              <div className="flex gap-1.5 flex-wrap">
                {SEVERITY_OPTIONS.map((s) => {
                  const active = filters.severities.has(s)
                  const colorMap: Record<Severity, string> = {
                    critical: active ? 'bg-red-900/40 text-red-300 border-red-800' : '',
                    high: active ? 'bg-orange-900/40 text-orange-300 border-orange-800' : '',
                    medium: active ? 'bg-yellow-900/40 text-yellow-300 border-yellow-800' : '',
                    low: active ? 'bg-emerald-900/30 text-emerald-300 border-emerald-800' : '',
                    none: active ? 'bg-gray-700/40 text-gray-300 border-gray-700' : '',
                  }
                  return (
                    <button key={s} type="button" onClick={() => toggleSeverity(s)}
                      className={`px-2.5 py-1 rounded text-xs border capitalize transition-colors ${active ? colorMap[s] : 'bg-gray-900 text-gray-400 border-gray-800 hover:border-gray-700'}`}>
                      {s}
                    </button>
                  )
                })}
              </div>
            </div>

            <div>
              <label htmlFor="cvss-min" className="label">
                CVSS ≥ <span className="font-mono text-gray-300">{filters.cvssMin.toFixed(1)}</span>
              </label>
              <input id="cvss-min" type="range" min={0} max={10} step={0.5} value={filters.cvssMin}
                onChange={(e) => setFilters((p: any) => ({ ...p, cvssMin: parseFloat(e.target.value) }))}
                className="w-full accent-emerald-500" />
            </div>

            <div>
              <label htmlFor="epss-min" className="label">
                EPSS pct ≥ <span className="font-mono text-gray-300">{filters.epssPercentileMin}%</span>
              </label>
              <input id="epss-min" type="range" min={0} max={100} step={5} value={filters.epssPercentileMin}
                onChange={(e) => setFilters((p: any) => ({ ...p, epssPercentileMin: parseInt(e.target.value, 10) }))}
                className="w-full accent-emerald-500" />
            </div>

            <label className="inline-flex items-center gap-2 text-sm text-gray-300 cursor-pointer select-none">
              <input type="checkbox" checked={filters.onlyKev}
                onChange={(e) => setFilters((p: any) => ({ ...p, onlyKev: e.target.checked }))}
                className="accent-red-500" />
              <ShieldAlert className="h-3.5 w-3.5 text-red-400" /> Only CISA KEV
            </label>
          </aside>

          {/* Results column */}
          <div className="space-y-3 min-w-0">
            {/* Summary + sort bar */}
            <div className="card p-3 flex items-center justify-between gap-3 flex-wrap">
              <div className="flex items-center gap-3 flex-wrap text-xs">
                <span className="text-gray-400">
                  <span className="text-emerald-400 font-mono">{sorted.length}</span>
                  <span className="text-gray-600"> / {stats.total}</span> CVE
                </span>
                <span className="w-px h-3 bg-gray-800" />
                <CveStat label="Critical" value={stats.critical} color="text-red-400" />
                <CveStat label="High" value={stats.high} color="text-orange-400" />
                <CveStat label="KEV" value={stats.kev} color="text-red-400" kev />
                <CveStat label="Hot EPSS" value={stats.hot} color="text-amber-400" />
              </div>
              <div className="flex items-center gap-1.5 shrink-0">
                <ArrowUpDown className="h-3.5 w-3.5 text-gray-500" />
                <select value={sortBy} onChange={(e) => setSortBy(e.target.value as any)}
                  className="input text-xs py-1 w-auto">
                  <option value="risk">Risk (KEV · EPSS · CVSS)</option>
                  <option value="cvss">CVSS score</option>
                  <option value="epss">EPSS percentile</option>
                  <option value="newest">Newest</option>
                </select>
              </div>
            </div>

            {sorted.length === 0 ? (
              <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
                <FilterX className="h-8 w-8 mb-3 opacity-40" />
                <p className="text-sm">Filters excluded all results — loosen the conditions.</p>
              </div>
            ) : (
              <div className="card overflow-hidden">
                <div className="max-h-[calc(100vh-18rem)] overflow-y-auto">
                  <table className="w-full">
                    <thead className="bg-gray-900 border-b border-gray-800 sticky top-0 z-10">
                      <tr>
                        <th className="table-header text-left px-4 py-3 w-44">CVE ID</th>
                        <th className="table-header text-left px-4 py-3 w-32">Severity</th>
                        <th className="table-header text-left px-4 py-3 w-40">Risk (EPSS)</th>
                        <th className="table-header text-left px-4 py-3 w-32">Published</th>
                        <th className="table-header text-left px-4 py-3">Description</th>
                      </tr>
                    </thead>
                    <tbody>
                      {sorted.map((cve) => (
                        <CveRow key={cve.id} cve={cve} onClick={() => setSelectedId(cve.id)} />
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      <CveDetailDialog
        id={selectedId}
        onClose={() => setSelectedId(null)}
      />
    </div>
  )
}

function CveStat({ label, value, color, kev }: { label: string; value: number; color: string; kev?: boolean }) {
  return (
    <span className="inline-flex items-center gap-1 text-gray-500">
      {kev && <ShieldAlert className="h-3 w-3 text-red-400/80" />}
      <span className={value > 0 ? `${color} font-mono font-semibold` : 'text-gray-600 font-mono'}>{value}</span>
      {label}
    </span>
  )
}

interface CveRowProps {
  cve: CveSummary
  onClick: () => void
}

function CveRow({ cve, onClick }: CveRowProps) {
  return (
    <tr
      onClick={onClick}
      className="border-b border-gray-800/50 hover:bg-gray-800/30 cursor-pointer transition-colors"
    >
      <td className="px-4 py-3 table-cell font-mono text-emerald-400">{cve.id}</td>
      <td className="px-4 py-3">
        <SeverityBadge severity={cve.severity} score={cve.cvss_score} />
      </td>
      <td className="px-4 py-3">
        <RiskCell
          epssScore={cve.epss_score}
          percentile={cve.epss_percentile}
          isKev={cve.is_kev}
        />
      </td>
      <td className="px-4 py-3 table-cell text-gray-400 text-xs">
        {cve.published_date
          ? safeDistanceToNow(cve.published_date, { addSuffix: true })
          : '—'}
      </td>
      <td className="px-4 py-3 table-cell">
        <p className="line-clamp-2 text-gray-300">{cve.description || '—'}</p>
        {cve.affected_products.length > 0 && (
          <p className="text-xs text-gray-500 mt-1 truncate">
            {cve.affected_products.slice(0, 3).join(' · ')}
            {cve.affected_products.length > 3 && ` · +${cve.affected_products.length - 3}`}
          </p>
        )}
      </td>
    </tr>
  )
}

interface RiskCellProps {
  epssScore: number
  percentile: number
  isKev: boolean
}

// EPSS percentile is the most actionable single number for "real-world
// exploitation likelihood". The bar's color thresholds match common SOC
// triage cutoffs (>=95th = critical priority, >=80th = high, >=50th = watch).
function RiskCell({ epssScore, percentile, isKev }: RiskCellProps) {
  const pct = Math.round((percentile || 0) * 100)
  const probPct = ((epssScore || 0) * 100).toFixed(1)

  let barColor = 'bg-gray-600'
  if (pct >= 95) barColor = 'bg-red-500'
  else if (pct >= 80) barColor = 'bg-orange-500'
  else if (pct >= 50) barColor = 'bg-yellow-500'
  else if (pct > 0) barColor = 'bg-emerald-500'

  return (
    <div className="flex flex-col gap-1">
      {isKev && (
        <span
          className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-semibold bg-red-900/40 text-red-300 border border-red-800/60 w-fit"
          title="Listed in CISA Known Exploited Vulnerabilities catalog"
        >
          <ShieldAlert className="h-3 w-3" />
          KEV
        </span>
      )}
      <div className="flex items-center gap-2">
        <div className="h-1.5 w-16 bg-gray-800 rounded-full overflow-hidden">
          <div className={`h-full ${barColor}`} style={{ width: `${pct}%` }} />
        </div>
        <span className="text-xs text-gray-300 font-mono tabular-nums">{pct}%</span>
      </div>
      <span className="text-[10px] text-gray-500">EPSS {probPct}%</span>
    </div>
  )
}

