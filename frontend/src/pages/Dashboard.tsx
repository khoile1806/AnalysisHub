import { useMemo } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Link } from 'react-router-dom'
import {
  Server, ClipboardList, ShieldAlert, Bug, ArrowRight, ArrowUpRight, Briefcase,
} from 'lucide-react'
import { safeDistanceToNow } from '@/lib/utils'
import { agentsApi } from '@/api/agents'
import { jobsApi } from '@/api/jobs'
import { cveCollectionApi } from '@/api/cve_collection'
import { openctiApi } from '@/api/opencti'
import { casesApi } from '@/api/cases'
import { elkResultsApi } from '@/api/analysis'
import { JobStatusBadge } from '@/components/StatusBadge'

interface StatCardProps {
  label: string; value: number | string; sub?: string
  icon: React.ElementType; color: string; loading: boolean
}

function StatCard({ label, value, sub, icon: Icon, color, loading }: StatCardProps) {
  return (
    <div className="card p-5 flex items-start justify-between">
      <div className="flex-1 min-w-0">
        <p className="text-sm text-gray-400 mb-1 truncate">{label}</p>
        {loading ? <div className="skeleton h-8 w-16 rounded" /> : (
          <div className="flex items-baseline gap-2">
            <p className="text-2xl font-bold text-gray-100">{value}</p>
            {sub && <span className="text-[10px] text-gray-500 font-medium truncate">{sub}</span>}
          </div>
        )}
      </div>
      <div className={`flex h-10 w-10 items-center justify-center rounded-lg shrink-0 ${color}`}>
        <Icon className="h-5 w-5" />
      </div>
    </div>
  )
}

// ── Main page ───────────────────────────────────────────────────────────────
// DFIR overview: live tallies + recent activity across the platform. Incident-
// specific views live on the Case Manager (per-case scoped data); standard
// response procedures live on the Playbooks page.
export default function DashboardPage() {
  const agentsQ = useQuery({ queryKey: ['agents'], queryFn: () => agentsApi.list(), refetchInterval: 20_000 })
  const jobsQ   = useQuery({ queryKey: ['jobs'],   queryFn: () => jobsApi.list(),   refetchInterval: 20_000 })
  const cvesQ   = useQuery({ queryKey: ['cve-coll'], queryFn: () => cveCollectionApi.getAll() })
  const iocsQ   = useQuery({ queryKey: ['iocs', 'dashboard'], queryFn: () => openctiApi.listIOCs({ limit: 6 }) })
  const casesQ  = useQuery({ queryKey: ['cases'],  queryFn: () => casesApi.list() })
  const elkQ    = useQuery({ queryKey: ['elk-hunt-results'], queryFn: elkResultsApi.list })

  const agents = agentsQ.data ?? []
  const jobs   = jobsQ.data   ?? []
  const cves   = cvesQ.data   ?? []
  const iocs   = iocsQ.data?.data ?? []
  const iocTotal = iocsQ.data?.total ?? 0
  const cases  = casesQ.data  ?? []
  const elkResults = elkQ.data ?? []

  const onlineAgents = useMemo(() => agents.filter((a) => a.status === 'online'), [agents])
  const kevCves      = useMemo(() => cves.filter((c) => c.is_kev), [cves])
  const openCases    = useMemo(() => cases.filter((c) => c.status === 'open'), [cases])
  const recentJobs   = jobs.slice(0, 6)

  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100">DFIR Overview</h1>
        <p className="text-sm text-gray-500 mt-1">Forensic &amp; Hunting platform · live tally.</p>
      </div>

      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-3">
        <Link to="/agents"><StatCard label="Agents · online" value={onlineAgents.length}
          sub={`/ ${agents.length} total`} icon={Server}
          color="bg-emerald-500/10 text-emerald-400 border border-emerald-500/30" loading={agentsQ.isLoading} /></Link>
        <Link to="/jobs"><StatCard label="Jobs" value={jobs.length} icon={ClipboardList}
          color="bg-blue-500/10 text-blue-400 border border-blue-500/30" loading={jobsQ.isLoading} /></Link>
        <Link to="/cve-collection"><StatCard label="CVEs · KEV" value={kevCves.length}
          sub={`/ ${cves.length} collected`} icon={Bug}
          color="bg-amber-500/10 text-amber-400 border border-amber-500/30" loading={cvesQ.isLoading} /></Link>
        <Link to="/ioc-store"><StatCard label="IOCs" value={iocTotal} icon={ShieldAlert}
          color="bg-purple-500/10 text-purple-400 border border-purple-500/30" loading={iocsQ.isLoading} /></Link>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        <section className="card p-4">
          <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
            <span>Recent jobs</span>
            <Link to="/jobs" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
          </h2>
          {recentJobs.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No jobs yet</div> : (
            <ul className="space-y-2">
              {recentJobs.map((j) => (
                <li key={j.id}>
                  <Link to={`/jobs/${j.id}`} className="flex items-center justify-between text-xs p-2 rounded hover:bg-gray-800/60">
                    <span className="truncate text-gray-300">{j.tool?.name ?? j.id.slice(0, 8)}</span>
                    <div className="flex items-center gap-3 shrink-0">
                      <JobStatusBadge status={j.status} />
                      <span className="text-[10px] text-gray-500">{j.created_at && safeDistanceToNow(j.created_at, { addSuffix: true })}</span>
                    </div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4">
          <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
            <span>KEV CVEs</span>
            <Link to="/cve-collection" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
          </h2>
          {kevCves.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No KEV-flagged CVEs</div> : (
            <ul className="space-y-2">
              {kevCves.slice(0, 6).map((c) => (
                <li key={c.id} className="text-xs p-2 rounded hover:bg-gray-800/60">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-gray-200">{c.id}</span>
                    <span className="text-[10px] text-amber-400">KEV</span>
                  </div>
                  {c.description && <div className="text-gray-500 text-[11px] mt-0.5 line-clamp-1">{c.description}</div>}
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4">
          <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
            <span>Recent IOCs</span>
            <Link to="/opencti" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
          </h2>
          {iocs.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No IOCs</div> : (
            <ul className="space-y-2">
              {iocs.slice(0, 6).map((ioc: any) => (
                <li key={ioc.id} className="text-xs p-2 rounded hover:bg-gray-800/60 flex items-center justify-between">
                  <span className="font-mono text-gray-300 truncate">{ioc.value}</span>
                  <span className="text-[10px] text-purple-400 shrink-0 ml-2">{ioc.type}</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4">
          <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
            <span>ELK hunt results</span>
            <Link to="/opencti" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
          </h2>
          {elkResults.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No hunt results</div> : (
            <ul className="space-y-2">
              {elkResults.slice(0, 6).map((r) => (
                <li key={r.id} className="text-xs p-2 rounded hover:bg-gray-800/60 flex items-center justify-between">
                  <span className="text-gray-300 truncate">{r.title}</span>
                  <span className="text-[10px] text-sky-400 shrink-0 ml-2">{r.total_hits} hits</span>
                </li>
              ))}
            </ul>
          )}
        </section>

        <section className="card p-4">
          <h2 className="flex items-center justify-between text-sm font-semibold text-gray-200 mb-3">
            <span>Open cases</span>
            <Link to="/cases" className="text-xs text-gray-500 hover:text-emerald-400 flex items-center gap-1">all <ArrowRight className="h-3 w-3" /></Link>
          </h2>
          {openCases.length === 0 ? <div className="text-xs text-gray-500 py-6 text-center">No open cases</div> : (
            <ul className="space-y-2">
              {openCases.slice(0, 6).map((cs) => (
                <li key={cs.id}>
                  <Link to={`/cases/${cs.id}`} className="flex items-center justify-between text-xs p-2 rounded hover:bg-gray-800/60">
                    <span className="truncate text-gray-300 flex items-center gap-1.5"><Briefcase className="h-3 w-3 text-gray-500" />{cs.name}</span>
                    <ArrowUpRight className="h-3 w-3 text-gray-600 shrink-0" />
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </section>
      </div>
    </div>
  )
}
