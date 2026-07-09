import { useQuery } from '@tanstack/react-query'
import { ExternalLink, Star, GitBranch, ShieldAlert } from 'lucide-react'
import { cveApi } from '@/api/cve'
import { SeverityBadge } from '@/components/StatusBadge'
import { getErrorMessage } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
} from '@/components/ui/dialog'

interface CveDetailDialogProps {
  id: string | null
  onClose: () => void
}

// CveDetailDialog shows the full NVD record for a CVE — exploitation risk
// (CVSS/EPSS/KEV), description, affected configurations, related local IOCs,
// references, and public GitHub PoCs. Shared by the Vulnerability Search page and
// the OSINT Tech-Stack tool so a CVE opens the same detail view everywhere.
export function CveDetailDialog({ id, onClose }: CveDetailDialogProps) {
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
          <DialogTitle className="font-mono text-emerald-400 text-base flex items-center gap-2">
            {id}
            {id && (
              <a href={`https://nvd.nist.gov/vuln/detail/${id}`} target="_blank" rel="noopener noreferrer"
                className="text-gray-500 hover:text-emerald-300" title="Open on NVD">
                <ExternalLink className="h-3.5 w-3.5" />
              </a>
            )}
          </DialogTitle>
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
              <RiskSection
                cvss={detail.data.cvss_score}
                severity={detail.data.severity}
                epssScore={detail.data.epss_score}
                percentile={detail.data.epss_percentile}
                isKev={detail.data.is_kev}
              />

              <section>
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                  Description
                </h3>
                <p className="text-sm text-gray-300 whitespace-pre-wrap leading-relaxed">
                  {detail.data.description || '—'}
                </p>
              </section>

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

              <section>
                <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2 flex items-center gap-2">
                  <ShieldAlert className="h-3.5 w-3.5 text-blue-400" />
                  Related IOCs (Indicators of Compromise)
                </h3>

                {relatedIocs.isLoading && <div className="skeleton h-12 w-full rounded" />}

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
                        {relatedIocs.data.map((ioc) => (
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

              {detail.data.references.length > 0 && (
                <section>
                  <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                    References ({detail.data.references.length})
                  </h3>
                  <ul className="space-y-1.5">
                    {detail.data.references.map((ref) => (
                      <li key={ref.url} className="text-sm">
                        <a href={ref.url} target="_blank" rel="noopener noreferrer"
                          className="inline-flex items-start gap-1.5 text-emerald-400 hover:text-emerald-300 break-all">
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

            {pocs.isError && <p className="text-sm text-red-400">{getErrorMessage(pocs.error)}</p>}

            {pocs.data && pocs.data.length === 0 && (
              <p className="text-sm text-gray-500">No public PoCs found on GitHub.</p>
            )}

            {pocs.data && pocs.data.length > 0 && (
              <ul className="space-y-2">
                {pocs.data.map((poc) => (
                  <li key={poc.html_url}
                    className="bg-gray-950 border border-gray-800 rounded-lg p-3 hover:border-emerald-800/50 transition-colors">
                    <div className="flex items-start justify-between gap-3">
                      <div className="flex-1 min-w-0">
                        <a href={poc.html_url} target="_blank" rel="noopener noreferrer"
                          className="text-sm font-medium text-emerald-400 hover:text-emerald-300 inline-flex items-center gap-1.5">
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

// RiskSection summarises three orthogonal risk signals: CVSS (impact), EPSS
// (predicted exploitation likelihood), KEV (confirmed in-the-wild exploitation).
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
          <div className="text-lg font-semibold text-gray-100 font-mono tabular-nums">{cvss ? cvss.toFixed(1) : '—'}</div>
          <div className="text-[11px] text-gray-500 mt-0.5 capitalize">{severity || 'unknown'} impact</div>
        </div>
        <div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">EPSS Score</div>
          <div className="text-lg font-semibold text-gray-100 font-mono tabular-nums">{probPct}%</div>
          <div className="text-[11px] text-gray-500 mt-0.5">Probability of exploit (30d)</div>
        </div>
        <div>
          <div className="text-[10px] text-gray-500 uppercase tracking-wider mb-1">Percentile</div>
          <div className={`text-lg font-semibold font-mono tabular-nums ${pctColor}`}>{pct}%</div>
          <div className="text-[11px] text-gray-500 mt-0.5">Higher than {pct}% of all CVEs</div>
        </div>
      </div>

      <div className="mt-3 h-1.5 bg-gray-800 rounded-full overflow-hidden">
        <div
          className={
            pct >= 95 ? 'h-full bg-red-500'
            : pct >= 80 ? 'h-full bg-orange-500'
            : pct >= 50 ? 'h-full bg-yellow-500'
            : pct > 0 ? 'h-full bg-emerald-500'
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
            <div className="text-xs font-semibold text-red-300">Actively exploited in the wild</div>
            <div className="text-[11px] text-gray-400 mt-0.5">
              Listed in CISA Known Exploited Vulnerabilities (KEV) catalog — patching is the highest priority regardless of CVSS/EPSS.
            </div>
          </div>
        </div>
      )}
    </section>
  )
}
