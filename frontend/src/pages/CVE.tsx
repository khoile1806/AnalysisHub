import { useMemo, type FormEvent, type KeyboardEvent } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Search, ExternalLink, Star, Bug, AlertTriangle, GitBranch, ShieldAlert, FilterX } from 'lucide-react'
import { cveApi, type CveSummary, type Severity } from '@/api/cve'
import { SeverityBadge } from '@/components/StatusBadge'
import { getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
} from '@/components/ui/dialog'
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
    queryFn: () => cveApi.search(query, version || undefined, 500),
    enabled: query.length > 0,
    staleTime: 60_000,
  })

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
        <div className="grid grid-cols-1 md:grid-cols-[1fr_220px_auto] gap-3">
          <div>
            <label htmlFor="cve-q" className="label">Product / Keyword</label>
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
          <div>
            <label htmlFor="cve-v" className="label">
              Version <span className="text-gray-500 font-normal">(optional)</span>
            </label>
            <input
              id="cve-v"
              className="input"
              placeholder="e.g. 1.6.2"
              value={versionInput}
              onChange={(e) => setVersionInput(e.target.value)}
              onKeyDown={handleKeyDown}
              maxLength={32}
            />
          </div>
          <div className="flex md:items-end">
            <button type="submit" className="btn-primary w-full md:w-auto" disabled={!input.trim()}>
              <Search className="h-4 w-4" />
              Search
            </button>
          </div>
        </div>
        <p className="text-xs text-gray-500 mt-2">
          Tip: You can search multiple vulnerabilities at once using commas (max 5 keywords). Directly supports formats like <span className="font-mono text-gray-400">CVE-YYYY-NNNN</span>, <span className="font-mono text-gray-400">CWE-NNN</span>, or <span className="font-mono text-gray-400">mal-xxx</span>.
          WPScan is only triggered when the query contains <span className="font-mono text-gray-400">wordpress</span>, <span className="font-mono text-gray-400">wp-&lt;slug&gt;</span> or <span className="font-mono text-gray-400">wp:&lt;slug&gt;</span>.
        </p>
      </form>

      {/* Filters — only meaningful once we have data */}
      {query && search.isSuccess && search.data.length > 0 && (
        <div className="card p-4 space-y-3">
          <div className="flex items-center justify-between gap-3 flex-wrap">
            <div className="flex items-center gap-3 flex-wrap">
              <span className="text-xs font-semibold text-gray-400 uppercase tracking-wider">
                Filter
              </span>
              <span className="text-xs text-gray-500">
                Showing <span className="text-emerald-400 font-mono">{filtered.length}</span>
                {' / '}
                <span className="font-mono">{search.data.length}</span> CVE
              </span>
            </div>
            {filtersActive && (
              <button
                type="button"
                onClick={() => setFilters(DEFAULT_FILTERS)}
                className="inline-flex items-center gap-1.5 text-xs text-gray-400 hover:text-gray-200"
              >
                <FilterX className="h-3.5 w-3.5" />
                Clear filters
              </button>
            )}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-[1fr_auto_auto_auto] gap-4 items-end">
            {/* Severity chips */}
            <div>
              <div className="label">Severity</div>
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
                    <button
                      key={s}
                      type="button"
                      onClick={() => toggleSeverity(s)}
                      className={`px-2.5 py-1 rounded text-xs border capitalize transition-colors ${
                        active
                          ? colorMap[s]
                          : 'bg-gray-900 text-gray-400 border-gray-800 hover:border-gray-700'
                      }`}
                    >
                      {s}
                    </button>
                  )
                })}
              </div>
            </div>

            {/* CVSS min */}
            <div>
              <label htmlFor="cvss-min" className="label">
                CVSS ≥ <span className="font-mono text-gray-300">{filters.cvssMin.toFixed(1)}</span>
              </label>
              <input
                id="cvss-min"
                type="range"
                min={0}
                max={10}
                step={0.5}
                value={filters.cvssMin}
                onChange={(e) =>
                  setFilters((p: any) => ({ ...p, cvssMin: parseFloat(e.target.value) }))
                }
                className="w-40 accent-emerald-500"
              />
            </div>

            {/* EPSS percentile min */}
            <div>
              <label htmlFor="epss-min" className="label">
                EPSS pct ≥ <span className="font-mono text-gray-300">{filters.epssPercentileMin}%</span>
              </label>
              <input
                id="epss-min"
                type="range"
                min={0}
                max={100}
                step={5}
                value={filters.epssPercentileMin}
                onChange={(e) =>
                  setFilters((p: any) => ({ ...p, epssPercentileMin: parseInt(e.target.value, 10) }))
                }
                className="w-40 accent-emerald-500"
              />
            </div>

            {/* KEV toggle */}
            <label className="inline-flex items-center gap-2 text-sm text-gray-300 cursor-pointer select-none whitespace-nowrap pb-1">
              <input
                type="checkbox"
                checked={filters.onlyKev}
                onChange={(e) => setFilters((p: any) => ({ ...p, onlyKev: e.target.checked }))}
                className="accent-red-500"
              />
              <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
              Only CISA KEV
            </label>
          </div>
        </div>
      )}

      {/* Results */}
      <div className="card overflow-hidden">
        {!query && (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500">
            <Search className="h-8 w-8 mb-3 opacity-40" />
            <p className="text-sm">Enter keywords to start searching CVEs.</p>
          </div>
        )}

        {query && search.isLoading && (
          <div className="p-6 space-y-3">
            {Array.from({ length: 6 }).map((_, i) => (
              <div key={i} className="skeleton h-12 w-full rounded" />
            ))}
          </div>
        )}

        {query && search.isError && (
          <div className="flex flex-col items-center justify-center py-16 text-red-400">
            <AlertTriangle className="h-8 w-8 mb-3" />
            <p className="text-sm">{getErrorMessage(search.error)}</p>
          </div>
        )}

        {query && search.isSuccess && search.data.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500">
            <p className="text-sm">
              No CVEs found for "{query}{version ? ` ${version}` : ''}".
            </p>
          </div>
        )}

        {query && search.isSuccess && search.data.length > 0 && filtered.length === 0 && (
          <div className="flex flex-col items-center justify-center py-16 text-gray-500">
            <FilterX className="h-8 w-8 mb-3 opacity-40" />
            <p className="text-sm">Current filters excluded all results — try loosening the conditions.</p>
          </div>
        )}

        {query && search.isSuccess && filtered.length > 0 && (
          <div className="max-h-[calc(100vh-22rem)] overflow-y-auto">
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
                {filtered.map((cve) => (
                  <CveRow key={cve.id} cve={cve} onClick={() => setSelectedId(cve.id)} />
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>

      <CveDetailDialog
        id={selectedId}
        onClose={() => setSelectedId(null)}
      />
    </div>
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

interface CveDetailDialogProps {
  id: string | null
  onClose: () => void
}

function CveDetailDialog({ id, onClose }: CveDetailDialogProps) {
  const detail = useQuery({
    queryKey: ['cve', 'detail', id],
    queryFn: () => cveApi.get(id!),
    enabled: !!id,
    staleTime: 5 * 60_000,
  })
  const pocs = useQuery({
    queryKey: ['cve', 'pocs', id],
    queryFn: () => cveApi.getPocs(id!),
    enabled: !!id,
    staleTime: 60_000,
  })
  const relatedIocs = useQuery({
    queryKey: ['cve', 'iocs', id],
    queryFn: () => cveApi.getRelatedIOCs(id!),
    enabled: !!id,
    staleTime: 60_000,
  })

  return (
    <Dialog open={!!id} onOpenChange={(open) => !open && onClose()}>
      <DialogContent className="max-w-3xl">
        <DialogHeader>
          <DialogTitle className="font-mono text-emerald-400 text-base">{id}</DialogTitle>
          <DialogDescription>
            {detail.data && (
              <span className="flex items-center gap-2 mt-1">
                <SeverityBadge severity={detail.data.severity} score={detail.data.cvss_score} />
                {detail.data.published_date && (
                  <span className="text-xs text-gray-500">
                    Published {new Date(detail.data.published_date).toLocaleDateString()}
                  </span>
                )}
              </span>
            )}
          </DialogDescription>
        </DialogHeader>

        <DialogBody className="space-y-5">
          {detail.isLoading && (
            <div className="space-y-2">
              <div className="skeleton h-4 w-full rounded" />
              <div className="skeleton h-4 w-5/6 rounded" />
              <div className="skeleton h-4 w-4/6 rounded" />
            </div>
          )}

          {detail.isError && (
            <p className="text-sm text-red-400">{getErrorMessage(detail.error)}</p>
          )}

          {detail.data && (
            <>
              {/* Exploitation risk */}
              <RiskSection
                cvss={detail.data.cvss_score}
                severity={detail.data.severity}
                epssScore={detail.data.epss_score}
                percentile={detail.data.epss_percentile}
                isKev={detail.data.is_kev}
              />

              {/* Description */}
              <section>
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                  Description
                </h3>
                <p className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed">
                  {detail.data.description || '—'}
                </p>
              </section>

              {/* Affected configurations */}
              {detail.data.configurations.length > 0 && (
                <section>
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                    Affected configurations ({detail.data.configurations.length})
                  </h3>
                  <div className="bg-gray-950 border border-gray-800 rounded-lg p-3 max-h-40 overflow-y-auto">
                    <ul className="space-y-1 font-mono text-xs text-gray-400">
                      {detail.data.configurations.slice(0, 50).map((cpe) => (
                        <li key={cpe} className="break-all">{cpe}</li>
                      ))}
                      {detail.data.configurations.length > 50 && (
                        <li className="text-gray-600 italic">
                          + {detail.data.configurations.length - 50} more...
                        </li>
                      )}
                    </ul>
                  </div>
                </section>
              )}

              {/* Related IOCs Section */}
              <section>
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                  <ShieldAlert className="h-3.5 w-3.5 text-blue-400" />
                  Related IOCs (Indicators of Compromise)
                </h3>
                
                {relatedIocs.isLoading && (
                  <div className="skeleton h-12 w-full rounded" />
                )}
                
                {relatedIocs.data && relatedIocs.data.length === 0 && (
                  <p className="text-xs text-gray-500 italic px-1">No indicators linked to this CVE found in the local database.</p>
                )}
                
                {relatedIocs.data && relatedIocs.data.length > 0 && (
                  <div className="bg-gray-900/50 border border-gray-800 rounded-lg overflow-hidden">
                    <table className="w-full text-xs">
                      <thead className="bg-gray-950">
                        <tr>
                          <th className="px-3 py-2 text-left text-gray-500 font-semibold uppercase tracking-wider">Type</th>
                          <th className="px-3 py-2 text-left text-gray-500 font-semibold uppercase tracking-wider">Indicator Value</th>
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-gray-800">
                        {relatedIocs.data.map(ioc => (
                          <tr key={ioc.id} className="hover:bg-gray-800/30 transition-colors">
                            <td className="px-3 py-2">
                              <span className="px-1.5 py-0.5 bg-gray-800 text-gray-400 rounded text-[10px] font-mono uppercase border border-gray-700">
                                {ioc.type}
                              </span>
                            </td>
                            <td className="px-3 py-2 font-mono text-gray-300 break-all">{ioc.value}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </section>

              {/* References */}
              {detail.data.references.length > 0 && (
                <section>
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                    References ({detail.data.references.length})
                  </h3>
                  <ul className="space-y-1.5">
                    {detail.data.references.map((ref) => (
                      <li key={ref.url} className="text-sm">
                        <a
                          href={ref.url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="inline-flex items-start gap-1.5 text-emerald-400 hover:text-emerald-300 break-all"
                        >
                          <ExternalLink className="h-3.5 w-3.5 mt-0.5 shrink-0" />
                          <span>{ref.url}</span>
                        </a>
                        {ref.tags && ref.tags.length > 0 && (
                          <span className="ml-5 text-[10px] text-gray-500 uppercase tracking-wider">
                            {ref.tags.join(' · ')}
                          </span>
                        )}
                      </li>
                    ))}
                  </ul>
                </section>
              )}
            </>
          )}

          {/* PoCs */}
          <section>
            <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-2">
              <GitBranch className="h-3.5 w-3.5" />
              Public PoC repositories
            </h3>

            {pocs.isLoading && (
              <div className="space-y-2">
                <div className="skeleton h-10 w-full rounded" />
                <div className="skeleton h-10 w-full rounded" />
              </div>
            )}

            {pocs.isError && (
              <p className="text-sm text-red-400">{getErrorMessage(pocs.error)}</p>
            )}

            {pocs.data && pocs.data.length === 0 && (
              <p className="text-sm text-gray-500">No public PoCs found on GitHub.</p>
            )}

            {pocs.data && pocs.data.length > 0 && (
              <ul className="space-y-2">
                {pocs.data.map((poc) => (
                  <li
                    key={poc.html_url}
                    className="bg-gray-950 border border-gray-800 rounded-lg p-3 hover:border-emerald-800/50 transition-colors"
                  >
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <a
                          href={poc.html_url}
                          target="_blank"
                          rel="noopener noreferrer"
                          className="text-sm font-medium text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1.5"
                        >
                          {poc.owner}/{poc.name}
                          <ExternalLink className="h-3 w-3" />
                        </a>
                        {poc.description && (
                          <p className="text-xs text-gray-400 mt-1 line-clamp-2">{poc.description}</p>
                        )}
                      </div>
                      <span className="inline-flex items-center gap-1 text-xs text-yellow-500 shrink-0">
                        <Star className="h-3 w-3 fill-current" />
                        {poc.stars.toLocaleString()}
                      </span>
                    </div>
                  </li>
                ))}
              </ul>
            )}
          </section>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}

interface RiskSectionProps {
  cvss: number
  severity: string
  epssScore: number
  percentile: number
  isKev: boolean
}

// RiskSection summarises three orthogonal risk signals:
//   - CVSS:  theoretical impact severity (what's the damage potential?)
//   - EPSS:  predicted likelihood of exploitation in the next 30 days
//   - KEV:   confirmed exploitation observed in the wild (CISA catalog)
// SOC triage typically escalates when EPSS percentile is high OR KEV is set,
// regardless of CVSS — that's why the percentile is rendered most prominently.
function RiskSection({ cvss, severity, epssScore, percentile, isKev }: RiskSectionProps) {
  const pct = Math.round((percentile || 0) * 100)
  const probPct = ((epssScore || 0) * 100).toFixed(2)

  let pctColor = 'text-gray-300'
  let interpretation = 'Low predicted exploitation likelihood.'
  if (pct >= 95) {
    pctColor = 'text-red-400'
    interpretation = 'Very high — top 5% most likely to be exploited.'
  } else if (pct >= 80) {
    pctColor = 'text-orange-400'
    interpretation = 'High — significantly above average exploitation risk.'
  } else if (pct >= 50) {
    pctColor = 'text-yellow-400'
    interpretation = 'Moderate — worth monitoring.'
  } else if (pct > 0) {
    pctColor = 'text-emerald-400'
  }

  return (
    <section className="rounded-lg border border-gray-800 bg-gray-950/40 p-4">
      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-3 flex items-center gap-2">
        <ShieldAlert className="h-3.5 w-3.5 text-emerald-400" />
        Exploitation risk
      </h3>

      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">CVSS</div>
          <div className="text-lg font-semibold text-gray-100 font-mono tabular-nums">
            {cvss ? cvss.toFixed(1) : '—'}
          </div>
          <div className="text-[11px] text-gray-500 mt-0.5 capitalize">
            {severity || 'unknown'} impact
          </div>
        </div>

        <div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">EPSS Score</div>
          <div className="text-lg font-semibold text-gray-100 font-mono tabular-nums">
            {probPct}%
          </div>
          <div className="text-[11px] text-gray-500 mt-0.5">
            Probability of exploit (30d)
          </div>
        </div>

        <div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Percentile</div>
          <div className={`text-lg font-semibold font-mono tabular-nums ${pctColor}`}>
            {pct}%
          </div>
          <div className="text-[11px] text-gray-500 mt-0.5">
            Higher than {pct}% of all CVEs
          </div>
        </div>
      </div>

      <div className="mt-3 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={
            pct >= 95
              ? 'h-full bg-red-500'
              : pct >= 80
              ? 'h-full bg-orange-500'
              : pct >= 50
              ? 'h-full bg-yellow-500'
              : pct > 0
              ? 'h-full bg-emerald-500'
              : 'h-full bg-gray-600'
          }
          style={{ width: `${pct}%` }}
        />
      </div>
      <p className="text-[11px] text-gray-500 mt-2">{interpretation}</p>

      {isKev && (
        <div className="mt-3 pt-3 border-t border-red-900/40 flex items-start gap-2">
          <ShieldAlert className="h-4 w-4 mt-0.5 shrink-0 text-red-400" />
          <div>
            <div className="text-xs font-semibold text-red-300">
              Actively exploited in the wild
            </div>
            <div className="text-[11px] text-gray-400 mt-0.5">
              Listed in CISA Known Exploited Vulnerabilities (KEV) catalog —
              patching is the highest priority regardless of CVSS/EPSS.
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
