import { ExternalLink, Loader2 } from 'lucide-react'
import { useQuery } from '@tanstack/react-query'
import { logsearchApi } from '@/api/logsearch'
import { useKeepalive } from '@/hooks/useKeepalive'

// KibanaView embeds the bundled Kibana (served same-origin under /kbn) so it can
// be used inside AnalysisHub like a normal ELK stack — Discover to view logs,
// plus detection rules, alerting, dashboards and visualizations. For full screen
// real estate it can also be opened in its own tab.
//
// ELK is idle-auto-stopped to free RAM; opening this page heartbeats a keepalive
// that auto-starts it. We wait for Kibana to report running before loading the
// iframe so the user doesn't see nginx's "connection refused".
export default function KibanaView() {
  useKeepalive('elk')
  const { data: elk } = useQuery({
    queryKey: ['elk-status-kbn'],
    queryFn: logsearchApi.elkStatus,
    refetchInterval: (q) => (q.state.data?.kibana?.running ? false : 3000),
  })
  // When docker control is off we can't know/trigger state — just show the iframe.
  const controlOff = elk && !elk.control_enabled
  const kibanaUp = !!elk?.kibana?.running || controlOff
  const manualOff = elk?.auto_shutdown?.manual_off

  return (
    <div className="flex-1 flex flex-col min-h-0 -m-4 sm:-m-6">
      <div className="flex items-center gap-3 px-4 py-2 border-b border-gray-800 bg-gray-900/50 shrink-0">
        <h1 className="text-sm font-semibold text-gray-200">Kibana</h1>
        <span className="text-xs text-gray-500">view logs · build detection rules · dashboards</span>
        <a href="/kbn/" target="_blank" rel="noreferrer" className="ml-auto flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300">
          Open full screen <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>
      {kibanaUp ? (
        <iframe src="/kbn/" title="Kibana" className="flex-1 w-full border-0 bg-white" />
      ) : (
        <div className="flex-1 flex flex-col items-center justify-center gap-3 text-gray-400">
          {manualOff ? (
            <p className="text-sm">ELK has been stopped by an admin. Start it from the Log Ingest tab to use Kibana.</p>
          ) : (
            <>
              <Loader2 className="h-6 w-6 animate-spin text-emerald-400" />
              <p className="text-sm">Starting Elasticsearch + Kibana… this takes ~30–60s the first time.</p>
              <p className="text-[11px] text-gray-600">ELK is auto-stopped when idle to save RAM and auto-starts on demand.</p>
            </>
          )}
        </div>
      )}
    </div>
  )
}
