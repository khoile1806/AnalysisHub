import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { ShieldOff, AlertTriangle, Radar, Server, Grid3x3, Loader2, Info } from 'lucide-react'
import {
  coverageApi,
  type ChannelVerdict, type HostCoverageStatus,
  type CoverageChannel, type CoverageHost,
} from '@/api/coverage'
import { getErrorMessage, safeFormat } from '@/lib/utils'

// Detection Coverage answers what a rule count hides: how many of the loaded
// rules can actually fire, given the telemetry the endpoints really produce.
// Every "0" on this page is qualified — an unmeasured host is `unknown`, never
// a measured zero, because the two lead to opposite decisions.

const VERDICT_CLS: Record<ChannelVerdict, string> = {
  covered: 'text-emerald-300 bg-emerald-900/30 border-emerald-700/50',
  partial: 'text-amber-300 bg-amber-900/30 border-amber-700/50',
  missing: 'text-red-300 bg-red-900/30 border-red-700/50',
  unknown: 'text-gray-400 bg-gray-800/60 border-gray-700',
}

const HOST_CLS: Record<HostCoverageStatus, string> = {
  covered: 'text-emerald-300 bg-emerald-900/30 border-emerald-700/50',
  partial: 'text-amber-300 bg-amber-900/30 border-amber-700/50',
  blind: 'text-red-300 bg-red-900/30 border-red-700/50',
  unknown: 'text-gray-400 bg-gray-800/60 border-gray-700',
}

const DAY_OPTIONS = [1, 7, 14, 30, 90]

function Badge({ label, cls }: { label: string; cls: string }) {
  return (
    <span className={`inline-block rounded border px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wide ${cls}`}>
      {label}
    </span>
  )
}

function Stat({ label, value, hint, tone = 'text-gray-200' }: {
  label: string; value: string; hint?: string; tone?: string
}) {
  return (
    <div className="rounded-lg border border-slate-800 bg-gray-900/40 px-3 py-2">
      <div className="text-[10px] uppercase tracking-widest text-gray-500">{label}</div>
      <div className={`mt-0.5 font-mono text-lg ${tone}`}>{value}</div>
      {hint && <div className="text-[10px] text-gray-600 mt-0.5">{hint}</div>}
    </div>
  )
}

// Channel counts are per host, so the sum only means something next to the
// number of hosts that reported on that channel at all.
function channelHostSplit(ch: CoverageChannel): string {
  if (ch.hosts_reporting === 0) return 'never queried'
  const parts = [`${ch.hosts_with_events} with events`]
  if (ch.hosts_silent > 0) parts.push(`${ch.hosts_silent} silent`)
  if (ch.hosts_failed > 0) parts.push(`${ch.hosts_failed} failed`)
  return `${parts.join(' · ')} of ${ch.hosts_reporting}`
}

function hostCoverageLabel(h: CoverageHost): string {
  return h.measured ? `${h.coverage_percent.toFixed(1)}%` : '—'
}

// embedded = rendered inside the Fleet page's "Detection coverage" tab (the big
// page title is dropped since the Fleet header already frames it).
export default function DetectionCoveragePage({ embedded = false }: { embedded?: boolean }) {
  const [days, setDays] = useState(7)
  const { data, isLoading, isError, error } = useQuery({
    queryKey: ['detection-coverage', days],
    queryFn: () => coverageApi.detection(days),
  })

  return (
    <div className="space-y-6">
      <div className="flex flex-wrap items-center justify-between gap-3">
        {!embedded && (
          <div>
            <h1 className="flex items-center gap-2 text-xl font-bold text-gray-100">
              <Radar className="h-5 w-5 text-emerald-400" /> Detection Coverage
            </h1>
            <p className="text-sm text-gray-500 mt-0.5">
              Which loaded detection rules can actually fire, measured against the log channels the
              endpoints really produce — not against the rule count.
            </p>
          </div>
        )}
        <label className={`text-xs text-gray-400 ${embedded ? 'ml-auto' : ''}`}>Evidence window
          <select className="input mt-1 block" value={days} onChange={(e) => setDays(Number(e.target.value))}>
            {DAY_OPTIONS.map((d) => <option key={d} value={d}>Last {d} day{d > 1 ? 's' : ''}</option>)}
          </select>
        </label>
      </div>

      {isLoading && (
        <div className="card p-6 flex items-center gap-2 text-sm text-gray-400">
          <Loader2 className="h-4 w-4 animate-spin text-emerald-400" /> Reading fleet sweep evidence…
        </div>
      )}

      {isError && (
        <div className="card p-6 text-sm text-red-300 border-red-900/50">
          Failed to load coverage: {getErrorMessage(error)}
        </div>
      )}

      {data && (
        <>
          {/* Headline — the number the page exists for. */}
          <div className={`card p-4 ${data.no_data ? 'border-amber-800/60' : data.headline.rules_at_risk > 0 ? 'border-red-900/60' : 'border-emerald-900/50'}`}>
            {data.no_data ? (
              <div className="flex items-start gap-3">
                <AlertTriangle className="h-6 w-6 text-amber-400 shrink-0 mt-0.5" />
                <div>
                  <div className="text-lg font-semibold text-amber-300">Coverage has never been measured</div>
                  <p className="text-sm text-gray-400 mt-1">
                    No fleet Sigma sweep produced results in this window, so nothing below is evidence of
                    telemetry — it is the absence of evidence. Run a sweep from the <b className="text-gray-300">Endpoints &amp; sweep</b> tab, then come back.
                  </p>
                </div>
              </div>
            ) : (
              <div className="flex items-start gap-3">
                <ShieldOff className={`h-6 w-6 shrink-0 mt-0.5 ${data.headline.rules_at_risk > 0 ? 'text-red-400' : 'text-emerald-400'}`} />
                <div>
                  <div className={`text-2xl font-bold ${data.headline.rules_at_risk > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                    {data.headline.rules_at_risk.toLocaleString()} rule{data.headline.rules_at_risk === 1 ? '' : 's'} cannot fire on any host
                  </div>
                  <p className="text-sm text-gray-400 mt-1">
                    {data.headline.channels_missing} of {data.ruleset.channels_required} required log channel(s) produced
                    no events anywhere in the fleet. Rules that depend on them have never evaluated a single event.
                  </p>
                </div>
              </div>
            )}

            <div className="mt-4 grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-2">
              <Stat label="Rules loaded" value={data.ruleset.rules_loaded.toLocaleString()}
                hint={`${data.ruleset.rules_unsupported.toLocaleString()} unsupported · ${data.ruleset.files_unreadable} unreadable file(s)`} />
              <Stat label="Reachable" value={data.headline.rules_reachable.toLocaleString()}
                tone="text-emerald-300" hint="on channels at least one host supplies" />
              <Stat label="At risk" value={data.headline.rules_at_risk.toLocaleString()}
                tone={data.headline.rules_at_risk > 0 ? 'text-red-400' : 'text-gray-400'} hint="on channels no host supplies" />
              <Stat label="Unmeasured" value={data.headline.rules_unmeasured.toLocaleString()}
                tone="text-gray-300" hint="on channels no sweep has touched" />
              <Stat label="Hosts" value={`${data.headline.hosts_swept}/${data.headline.hosts_total}`}
                tone={data.headline.hosts_never_swept > 0 ? 'text-amber-300' : 'text-gray-200'}
                hint={`${data.headline.hosts_never_swept} never swept · ${data.headline.hosts_blind} blind`} />
            </div>

            <p className="mt-3 text-[11px] text-gray-500 font-mono">Measured from: {data.measured_from}</p>
          </div>

          {/* Caveats — never buried. */}
          {data.notes.length > 0 && (
            <div className="card p-4 space-y-1.5">
              <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
                <Info className="h-4 w-4 text-blue-400" /> What these numbers do and do not say
              </h3>
              <ul className="space-y-1">
                {data.notes.map((n, i) => (
                  <li key={i} className="text-xs text-gray-400 pl-4 -indent-2">· {n}</li>
                ))}
              </ul>
            </div>
          )}

          {/* Per-channel */}
          <div className="card p-0">
            <div className="px-4 py-2.5 border-b border-slate-800 text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Grid3x3 className="h-4 w-4 text-emerald-400" /> Log channels the ruleset needs ({data.channels.length})
            </div>
            <div className="tbl-wrap overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-[11px] uppercase text-gray-500 border-b border-slate-800">
                  <th className="px-4 py-2">Channel</th>
                  <th className="px-4 py-2">Rules</th>
                  <th className="px-4 py-2">Verdict</th>
                  <th className="px-4 py-2">Hosts</th>
                  <th className="px-4 py-2">Events</th>
                  <th className="px-4 py-2">Why</th>
                </tr></thead>
                <tbody>
                  {data.channels.map((ch) => (
                    <tr key={ch.log_name} className="border-b border-slate-800/50 align-top">
                      <td className="px-4 py-2 font-mono text-xs text-gray-200">
                        {ch.log_name}
                        {ch.event_ids && ch.event_ids.length > 0 && (
                          <div className="text-[10px] text-gray-600 mt-0.5">
                            IDs {ch.event_ids.slice(0, 8).join(', ')}{ch.event_ids.length > 8 ? '…' : ''}
                          </div>
                        )}
                        {!ch.in_ruleset && <div className="text-[10px] text-gray-600 mt-0.5">not in the current ruleset</div>}
                      </td>
                      <td className={`px-4 py-2 font-mono ${ch.verdict === 'missing' && ch.in_ruleset ? 'text-red-400' : 'text-gray-300'}`}>
                        {ch.rules.toLocaleString()}
                      </td>
                      <td className="px-4 py-2"><Badge label={ch.verdict} cls={VERDICT_CLS[ch.verdict]} /></td>
                      <td className="px-4 py-2 text-xs text-gray-400">{channelHostSplit(ch)}</td>
                      <td className="px-4 py-2 font-mono text-xs text-gray-500">{ch.events.toLocaleString()}</td>
                      <td className="px-4 py-2 text-xs text-gray-500 max-w-md">
                        {ch.sample_error || ch.note || (ch.verdict === 'unknown' ? 'no sweep has queried this channel' : '—')}
                      </td>
                    </tr>
                  ))}
                  {data.channels.length === 0 && (
                    <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500 text-xs">
                      The loaded ruleset declares no log channels — nothing could be collected for it.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* Per-host */}
          <div className="card p-0">
            <div className="px-4 py-2.5 border-b border-slate-800 text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Server className="h-4 w-4 text-emerald-400" /> Endpoints ({data.hosts.length})
            </div>
            <div className="tbl-wrap overflow-x-auto">
              <table className="w-full text-sm">
                <thead><tr className="text-left text-[11px] uppercase text-gray-500 border-b border-slate-800">
                  <th className="px-4 py-2">Host</th>
                  <th className="px-4 py-2">Status</th>
                  <th className="px-4 py-2">Coverage</th>
                  <th className="px-4 py-2">Working channels</th>
                  <th className="px-4 py-2">Failed / silent</th>
                  <th className="px-4 py-2">Last swept</th>
                </tr></thead>
                <tbody>
                  {data.hosts.map((h) => (
                    <tr key={h.agent_id} className="border-b border-slate-800/50 align-top">
                      <td className="px-4 py-2">
                        <div className="text-gray-200">{h.agent_name}</div>
                        <div className="text-[10px] text-gray-600 font-mono">{[h.os, h.agent_status].filter(Boolean).join(' · ') || '—'}</div>
                      </td>
                      <td className="px-4 py-2"><Badge label={h.status} cls={HOST_CLS[h.status]} /></td>
                      <td className="px-4 py-2">
                        <div className={`font-mono ${!h.measured ? 'text-gray-500' : h.coverage_percent >= 90 ? 'text-emerald-300' : h.coverage_percent > 0 ? 'text-amber-300' : 'text-red-400'}`}>
                          {hostCoverageLabel(h)}
                        </div>
                        {h.measured && (
                          <div className="text-[10px] text-gray-600 font-mono">
                            {h.rules_reachable.toLocaleString()} reachable · {h.rules_blocked.toLocaleString()} blocked
                          </div>
                        )}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-400 max-w-xs">
                        {h.channels_ok.length > 0
                          ? <span className="font-mono">{h.channels_ok.join(', ')}</span>
                          : <span className="text-gray-600">—</span>}
                      </td>
                      <td className="px-4 py-2 text-xs max-w-xs">
                        {h.channels_failed.length > 0 && <div className="font-mono text-red-300">{h.channels_failed.join(', ')}</div>}
                        {h.channels_silent.length > 0 && <div className="font-mono text-gray-500">{h.channels_silent.join(', ')} (silent)</div>}
                        {h.channels_failed.length === 0 && h.channels_silent.length === 0 && <span className="text-gray-600">—</span>}
                        {h.note && <div className="text-[10px] text-amber-400/80 mt-0.5">{h.note}</div>}
                      </td>
                      <td className="px-4 py-2 text-xs text-gray-500 whitespace-nowrap">
                        {h.last_swept ? safeFormat(h.last_swept, 'MM-dd HH:mm') : 'never'}
                        {h.sweep_status && <div className="text-[10px] text-gray-600 font-mono">{h.sweep_status}</div>}
                      </td>
                    </tr>
                  ))}
                  {data.hosts.length === 0 && (
                    <tr><td colSpan={6} className="px-4 py-6 text-center text-gray-500 text-xs">
                      No agents are enrolled, so there is no estate to measure coverage against.
                    </td></tr>
                  )}
                </tbody>
              </table>
            </div>
          </div>

          {/* ATT&CK */}
          <div className="card p-4 space-y-2">
            <h3 className="text-sm font-semibold text-gray-200 flex items-center gap-2">
              <Grid3x3 className="h-4 w-4 text-purple-400" /> ATT&amp;CK techniques observed ({data.attack.techniques_observed.length})
            </h3>
            <p className="text-xs text-gray-500">{data.attack.note}</p>
            {data.attack.tactics_observed.length > 0 && (
              <div className="text-xs text-gray-400">
                Tactics seen: <span className="text-gray-300">{data.attack.tactics_observed.join(' · ')}</span>
              </div>
            )}
            {data.attack.techniques_observed.length > 0 ? (
              <div className="flex flex-wrap gap-1.5 pt-1">
                {data.attack.techniques_observed.map((t) => (
                  <span key={t.technique}
                    className="rounded border border-purple-700/50 bg-purple-900/20 px-2 py-1 font-mono text-[11px] text-purple-300"
                    title={`${t.rules} rule(s) fired on ${t.hosts} host(s)`}>
                    {t.technique}
                    <span className="text-purple-500/80"> · {t.hosts}h/{t.rules}r</span>
                  </span>
                ))}
              </div>
            ) : (
              <p className="text-xs text-gray-500">
                No rule fired during the sweeps in this window, so no technique is confirmed exercised.
                That is not the same as the ruleset covering nothing — it is the absence of a detection.
              </p>
            )}
          </div>
        </>
      )}
    </div>
  )
}
