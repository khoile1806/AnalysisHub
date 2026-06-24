import { useState } from 'react'
import { Search, Activity, AlertTriangle, FileText } from 'lucide-react'
import { agentsApi, type Agent } from '@/api/agents'
import toast from 'react-hot-toast'
import {
  Select, SelectContent, SelectItem, SelectTrigger,
  SelectValue,
} from '@/components/ui/select'
import { huntingApi, type SigmaAlert } from '@/api/hunting'

export function EvtxViewer({ agent }: { agent: Agent }) {
  const [logName, setLogName] = useState('Security')
  const [eventId, setEventId] = useState('4624')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  
  const [scanningSigma, setScanningSigma] = useState(false)
  const [sigmaAlerts, setSigmaAlerts] = useState<SigmaAlert[]>([])

  const handleParse = async () => {
    if (!eventId) {
      toast.error('Please enter an Event ID')
      return
    }

    if (agent.status !== 'online') {
      toast.error('Agent is offline')
      return
    }

    setLoading(true)
    setError(null)
    setResult(null)

    try {
      const data = await agentsApi.parseEvtx(agent.id, logName, eventId)
      let parsed = data
      if (typeof data === 'string') {
        try {
          parsed = JSON.parse(data)
        } catch (e) {
          parsed = { message: data }
        }
      }
      setResult(parsed)
      toast.success('EVTX log parsed successfully')
    } catch (err: any) {
      const msg = err.response?.data?.error || err.message || 'Failed to parse EVTX'
      setError(msg)
      toast.error(msg)
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className="flex flex-col h-full min-h-[600px] gap-4">
      {/* Header & Controls */}
      <div className="flex flex-col gap-3 p-4 bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm shrink-0">
        <div className="flex flex-col md:flex-row items-start md:items-center justify-between gap-4">
          <div className="flex items-center gap-3">
            <div className="p-3 bg-purple-500/10 rounded-lg border border-purple-500/20">
              <Activity className="h-6 w-6 text-purple-500" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-100">EVTX Viewer (Edge)</h1>
              <p className="text-xs text-gray-400">Query Windows Event Logs directly on {agent.name} using Native API</p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-end gap-3 w-full pt-2 border-t border-gray-800/50">
          {/* Log Name Input */}
          <div className="flex flex-col gap-1.5 w-40">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Log Name</label>
            <Select value={logName} onValueChange={setLogName}>
              <SelectTrigger className="bg-gray-950/50 border-gray-800 h-9 font-mono text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="Security">Security</SelectItem>
                <SelectItem value="System">System</SelectItem>
                <SelectItem value="Application">Application</SelectItem>
                <SelectItem value="Setup">Setup</SelectItem>
                <SelectItem value="Windows PowerShell">PowerShell</SelectItem>
                <SelectItem value="Microsoft-Windows-Sysmon/Operational">Sysmon</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Event ID Input */}
          <div className="flex flex-col gap-1.5 flex-1 min-w-[200px]">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Event ID</label>
            <div className="relative">
              <input 
                type="text" 
                value={eventId}
                onChange={(e) => setEventId(e.target.value)}
                placeholder="e.g. 4624 (Logon), 4688 (Process)"
                className="input h-9 w-full font-mono text-xs bg-gray-950/50"
                onKeyDown={(e) => e.key === 'Enter' && handleParse()}
              />
            </div>
          </div>

          {/* Start Button */}
          <div className="flex flex-col gap-1.5 ml-auto md:ml-0">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Actions</label>
            <div className="flex items-center gap-2">
              <button 
                onClick={handleParse}
                disabled={loading || agent.status !== 'online'}
                className="btn-primary h-9 whitespace-nowrap px-6 bg-purple-600 hover:bg-purple-700 ring-purple-500"
              >
                {loading ? (
                  <span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                {loading ? 'Querying...' : 'Search EVTX'}
              </button>
              
              {result && Array.isArray(result) && result.length > 0 && (
                <button 
                  onClick={async () => {
                    setScanningSigma(true)
                    try {
                      const alerts = await huntingApi.scanSigma(result)
                      setSigmaAlerts(alerts)
                      if (alerts.length > 0) {
                        toast.error(`Found ${alerts.length} Sigma alerts!`)
                      } else {
                        toast.success('No Sigma alerts found.')
                      }
                    } catch (err: any) {
                      toast.error('Sigma scan failed: ' + err.message)
                    } finally {
                      setScanningSigma(false)
                    }
                  }}
                  disabled={scanningSigma}
                  className="btn-primary h-9 whitespace-nowrap px-6 bg-red-600 hover:bg-red-700 ring-red-500"
                >
                  {scanningSigma ? 'Scanning...' : 'Scan with Sigma'}
                </button>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Result View */}
      <div className="flex-1 bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900/50 shrink-0">
          <div className="flex items-center gap-2">
            <FileText className="h-4 w-4 text-gray-400" />
            <h3 className="text-sm font-medium text-gray-200">Event Results (Max 100)</h3>
          </div>
        </div>

        <div className="flex-1 p-4 overflow-y-auto">
          {loading ? (
             <div className="h-full flex items-center justify-center text-gray-500 flex-col gap-3">
               <span className="h-8 w-8 rounded-full border-2 border-purple-500/30 border-t-purple-500 animate-spin" />
               <p className="text-sm">Querying {logName} log for Event ID {eventId} on target...</p>
             </div>
          ) : error ? (
            <div className="rounded-lg border border-red-900/50 bg-red-950/20 p-4 flex items-start gap-3">
               <AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
               <div>
                 <h4 className="text-sm font-medium text-red-200">Error reading EVTX</h4>
                 <p className="text-xs text-red-300/80 mt-1">{error}</p>
               </div>
            </div>
          ) : !result ? (
             <div className="h-full flex items-center justify-center text-gray-500">
               <p className="text-sm">Enter an Event ID and click "Search EVTX" to view events.</p>
             </div>
          ) : Array.isArray(result) && result.length === 0 ? (
             <div className="h-full flex items-center justify-center text-gray-500">
               <p className="text-sm">No events found matching ID {eventId} in {logName}.</p>
             </div>
          ) : (
             <div className="flex flex-col gap-2">
               {sigmaAlerts.length > 0 && (
                 <div className="mb-4 rounded-lg border border-red-900/50 bg-red-950/20 p-4">
                   <h4 className="text-sm font-bold text-red-500 mb-2 flex items-center gap-2">
                     <AlertTriangle className="h-4 w-4" />
                     Sigma Alerts Detected ({sigmaAlerts.length})
                   </h4>
                   <div className="flex flex-col gap-2">
                     {sigmaAlerts.map((alert, i) => (
                       <div key={i} className="text-xs bg-black/40 p-3 rounded border border-red-900/30">
                         <span className="font-bold text-red-400">[{alert.rule_level?.toUpperCase() || 'HIGH'}]</span> {alert.rule_title}
                         <p className="text-gray-400 mt-1">{alert.rule_description}</p>
                       </div>
                     ))}
                   </div>
                 </div>
               )}
               {Array.isArray(result) ? result.map((evt: any, i: number) => (
                 <div key={i} className="text-xs font-mono bg-black/40 p-3 rounded-lg border border-gray-800/50 flex flex-col gap-1.5">
                   <div className="flex items-center gap-3 text-gray-500 mb-1">
                     <span className="text-purple-400 font-bold">Event ID: {evt.Id}</span>
                     <span>{evt.TimeCreated}</span>
                     <span className={`px-1.5 py-0.5 rounded text-[10px] uppercase ${
                       evt.LevelDisplayName === 'Information' ? 'bg-blue-500/10 text-blue-400' :
                       evt.LevelDisplayName === 'Warning' ? 'bg-yellow-500/10 text-yellow-400' :
                       evt.LevelDisplayName === 'Error' ? 'bg-red-500/10 text-red-400' :
                       'bg-gray-800 text-gray-400'
                     }`}>
                       {evt.LevelDisplayName || 'Unknown'}
                     </span>
                   </div>
                   <div className="text-gray-300 whitespace-pre-wrap pl-1 border-l-2 border-gray-800">
                     {evt.Message}
                   </div>
                 </div>
               )) : (
                 <pre className="text-xs text-gray-300 font-mono whitespace-pre-wrap">{JSON.stringify(result, null, 2)}</pre>
               )}
             </div>
          )}
        </div>
      </div>
    </div>
  )
}
