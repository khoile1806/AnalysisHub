import { ExternalLink } from 'lucide-react'

// KibanaView embeds the bundled Kibana (served same-origin under /kbn) so it can
// be used inside AnalysisHub like a normal ELK stack — Discover to view logs,
// plus detection rules, alerting, dashboards and visualizations. For full screen
// real estate it can also be opened in its own tab.
export default function KibanaView() {
  return (
    <div className="flex-1 flex flex-col min-h-0 -m-4 sm:-m-6">
      <div className="flex items-center gap-3 px-4 py-2 border-b border-gray-800 bg-gray-900/50 shrink-0">
        <h1 className="text-sm font-semibold text-gray-200">Kibana</h1>
        <span className="text-xs text-gray-500">view logs · build detection rules · dashboards</span>
        <a
          href="/kbn/"
          target="_blank"
          rel="noreferrer"
          className="ml-auto flex items-center gap-1 text-xs text-emerald-400 hover:text-emerald-300"
        >
          Open full screen <ExternalLink className="h-3.5 w-3.5" />
        </a>
      </div>
      <iframe src="/kbn/" title="Kibana" className="flex-1 w-full border-0 bg-white" />
    </div>
  )
}
