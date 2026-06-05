import { useState } from 'react'
import { useParams, Link } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { casesApi } from '@/api/cases'
import { Briefcase, Activity, Server, ChevronRight, User, Wrench, ClipboardList, Lock, Unlock } from 'lucide-react'
import { AgentStatusBadge, JobStatusBadge } from '@/components/StatusBadge'
import toast from 'react-hot-toast'
import { getErrorMessage, safeFormat } from '@/lib/utils'

export default function CaseDetailPage() {
  const { id } = useParams<{ id: string }>()
  const qc = useQueryClient()
  const [tab, setTab] = useState<'timeline' | 'jobs'>('timeline')

  const { data, isLoading } = useQuery({
    queryKey: ['case-summary', id],
    queryFn: () => casesApi.getSummary(id!),
    enabled: !!id,
    refetchInterval: 3000,
  })

  const toggleStatusMutation = useMutation({
    mutationFn: (newStatus: 'open' | 'closed') =>
      casesApi.update(id!, { status: newStatus }),
    onSuccess: (updated) => {
      qc.invalidateQueries({ queryKey: ['case-summary', id] })
      qc.invalidateQueries({ queryKey: ['cases'] })
      toast.success(`Case ${updated.status === 'open' ? 'reopened' : 'closed'}`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  if (isLoading) {
    return <div className="p-10 text-center"><div className="skeleton h-8 w-64 mx-auto rounded mb-4" /><div className="skeleton h-32 w-full max-w-4xl mx-auto rounded" /></div>
  }

  if (!data) return <div className="p-10 text-center text-red-400">Case not found</div>

  const { case: caseObj, agents, deployments, jobs, checklist_runs } = data

  // Aggregate all activities into a single timeline
  const activities: any[] = []
  if (deployments) {
    deployments.forEach((d: any) => activities.push({ ...d, _type: 'deployment', _time: new Date(d.created_at).getTime() }))
  }
  if (jobs) {
    jobs.forEach((j: any) => activities.push({ ...j, _type: 'job', _time: new Date(j.created_at).getTime() }))
  }
  if (checklist_runs) {
    checklist_runs.forEach((r: any) => activities.push({ ...r, _type: 'checklist', _time: new Date(r.created_at).getTime() }))
  }
  activities.sort((a, b) => b._time - a._time)

  const isOpen = caseObj.status === 'open'

  return (
    <div className="space-y-6 max-w-6xl mx-auto">
      {/* Header */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <div className="flex items-center gap-2 text-xs text-gray-500 mb-2">
            <Link to="/cases" className="hover:text-emerald-400 flex items-center gap-1">
              <Briefcase className="h-3.5 w-3.5" /> Cases
            </Link>
            <ChevronRight className="h-3 w-3" />
            <span className="text-gray-300 font-mono">{caseObj.id.split('-')[0]}</span>
          </div>
          <h1 className="text-2xl font-bold text-gray-100">{caseObj.name}</h1>
          <p className="text-sm text-gray-400 mt-1">{caseObj.description || 'No description'}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <span className={`text-xs uppercase font-bold px-3 py-1 rounded-full ${isOpen ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-300'}`}>
            {caseObj.status}
          </span>
          <button
            onClick={() => toggleStatusMutation.mutate(isOpen ? 'closed' : 'open')}
            disabled={toggleStatusMutation.isPending}
            className={`flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded border transition disabled:opacity-50 ${
              isOpen
                ? 'bg-gray-800 hover:bg-gray-700 text-gray-300 border-gray-700 hover:text-red-400 hover:border-red-500/40'
                : 'bg-emerald-900/30 hover:bg-emerald-900/50 text-emerald-400 border-emerald-500/30'
            }`}
            title={isOpen ? 'Close this case' : 'Reopen this case'}
          >
            {isOpen ? <Lock className="h-3 w-3" /> : <Unlock className="h-3 w-3" />}
            {isOpen ? 'Close Case' : 'Reopen'}
          </button>
        </div>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-3 gap-6">

        {/* Agents List */}
        <div className="col-span-1 space-y-4">
          <h3 className="font-semibold text-gray-200 flex items-center gap-2">
            <Server className="h-4 w-4 text-emerald-400" />
            Associated Agents
          </h3>
          <div className="card divide-y divide-gray-800/60">
            {agents && agents.length > 0 ? (
              agents.map((a: any) => (
                <div key={a.id} className="p-4 flex items-center justify-between">
                  <div>
                    <Link to={`/agents/${a.id}`} className="font-medium text-sm text-gray-200 hover:text-emerald-400">
                      {a.name}
                    </Link>
                    <div className="text-xs text-gray-500 font-mono">{a.ip_address}</div>
                  </div>
                  <AgentStatusBadge status={a.status} />
                </div>
              ))
            ) : (
              <div className="p-6 text-center text-sm text-gray-500">No agents linked to this case.</div>
            )}
          </div>
        </div>

        {/* Main Content Area */}
        <div className="col-span-1 md:col-span-2 space-y-4">
          <div className="flex items-center gap-1 border-b border-gray-800">
            {[
              { key: 'timeline', label: 'Activity Timeline', icon: Activity },
              { key: 'jobs', label: 'Hunting Results', icon: ClipboardList },
            ].map((t) => (
              <button
                key={t.key}
                onClick={() => setTab(t.key as 'timeline' | 'jobs')}
                className={`px-4 py-2 text-sm font-medium transition flex items-center gap-2 border-b-2 -mb-px ${
                  tab === t.key
                    ? 'border-emerald-500 text-emerald-400'
                    : 'border-transparent text-gray-400 hover:text-gray-200'
                }`}
              >
                <t.icon className="h-4 w-4" />
                {t.label}
              </button>
            ))}
          </div>

          {tab === 'timeline' && (
            <div className="card p-5">
              <div className="space-y-6 relative before:absolute before:inset-0 before:ml-5 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-gray-800 before:to-transparent">
                {activities.length > 0 ? (
                  activities.map((act) => (
                    <div key={act.id} className="relative flex items-center justify-between md:justify-normal md:odd:flex-row-reverse group is-active">
                      <div className="flex items-center justify-center w-10 h-10 rounded-full border border-gray-800 bg-gray-900 shadow shrink-0 md:order-1 md:group-odd:-translate-x-1/2 md:group-even:translate-x-1/2 text-emerald-400 relative z-10">
                        {act._type === 'deployment' ? <Activity className="h-4 w-4" /> : act._type === 'job' ? <Wrench className="h-4 w-4" /> : <ClipboardList className="h-4 w-4" />}
                      </div>
                      <div className="w-[calc(100%-4rem)] md:w-[calc(50%-2.5rem)] card p-4 group-odd:text-right group-odd:items-end flex flex-col hover:border-emerald-500/30 transition-colors">
                        <div className="flex items-center gap-2 text-[10px] text-gray-500 font-mono mb-1">
                          <span>{safeFormat(act.created_at, 'MMM dd, HH:mm:ss')}</span>
                        </div>
                        <h4 className="font-semibold text-sm text-gray-200 mb-1">
                          {act._type === 'deployment' ? `Deployed ${act.scenario?.name || 'Scenario'}` : act._type === 'job' ? (
                            <Link to={`/jobs/${act.id}`} className="hover:text-emerald-400 flex items-center gap-1 group-odd:justify-end transition-colors">
                              Executed {act.tool?.name || 'Tool'} <ChevronRight className="h-3 w-3" />
                            </Link>
                          ) : `Ran Evidence Checklist`}
                        </h4>
                        {act._type === 'job' && act.status && (
                          <div className="mt-1 mb-1">
                            <JobStatusBadge status={act.status} />
                          </div>
                        )}
                        <div className="text-xs text-gray-400 flex items-center gap-1.5 mt-1">
                          <Server className="h-3 w-3" /> {act.agent?.name || agents?.find((a: any) => a.id === act.agent_id)?.name || 'Agent'}
                        </div>
                        <div className="text-[10px] text-emerald-400/80 flex items-center gap-1.5 mt-2 bg-emerald-950/30 px-2 py-1 rounded inline-flex">
                          <User className="h-3 w-3" />
                          {act.created_by_user?.name || act.created_by_user?.email || act.analyst || 'System'}
                        </div>
                      </div>
                    </div>
                  ))
                ) : (
                  <div className="text-center text-sm text-gray-500 py-8 relative z-10">No activities recorded yet.</div>
                )}
              </div>
            </div>
          )}

          {tab === 'jobs' && (
            <div className="space-y-4">
              {jobs && jobs.length > 0 ? (
                <div className="card overflow-hidden">
                  <table className="w-full text-sm">
                    <thead className="bg-gray-900/60 border-b border-gray-800 text-xs text-gray-500 uppercase tracking-wider">
                      <tr>
                        <th className="text-left py-3 px-4 font-medium">Job Tool</th>
                        <th className="text-left py-3 px-4 font-medium">Agent</th>
                        <th className="text-left py-3 px-4 font-medium">Status</th>
                        <th className="text-left py-3 px-4 font-medium">Time</th>
                        <th className="text-right py-3 px-4 font-medium">Action</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-gray-800">
                      {jobs.map((j: any) => (
                        <tr key={j.id} className="hover:bg-gray-900/30 transition-colors">
                          <td className="py-3 px-4 font-medium text-gray-200">{j.tool?.name || 'Unknown Tool'}</td>
                          <td className="py-3 px-4 text-gray-400 text-xs">
                            <div className="flex items-center gap-1.5">
                              <Server className="h-3.5 w-3.5" />
                              {j.agent?.name || agents?.find((a: any) => a.id === j.agent_id)?.name || 'Agent'}
                            </div>
                          </td>
                          <td className="py-3 px-4"><JobStatusBadge status={j.status} /></td>
                          <td className="py-3 px-4 text-xs text-gray-500 font-mono">
                            {safeFormat(j.created_at, 'MMM dd, HH:mm')}
                          </td>
                          <td className="py-3 px-4 text-right">
                            <Link
                              to={`/jobs/${j.id}`}
                              className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-gray-800 hover:bg-gray-700 text-gray-200 rounded transition border border-gray-700"
                            >
                              <Wrench className="h-3.5 w-3.5" /> View Result
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              ) : (
                <div className="card p-10 text-center flex flex-col items-center justify-center">
                  <Wrench className="h-10 w-10 text-gray-700 mb-3" />
                  <p className="text-gray-400 font-medium">No hunting jobs found</p>
                  <p className="text-xs text-gray-500 mt-1">Deploy a scenario from the Hunting page and link it to this case.</p>
                </div>
              )}
            </div>
          )}
        </div>

      </div>
    </div>
  )
}
