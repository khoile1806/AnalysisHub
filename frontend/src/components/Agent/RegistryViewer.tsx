import { useState } from 'react'
import { Search, Database, AlertTriangle, GitBranch } from 'lucide-react'
import { agentsApi, type Agent } from '@/api/agents'
import toast from 'react-hot-toast'
import TraceOriginModal from '@/components/Agent/TraceOriginModal'
import {
  Select, SelectContent, SelectItem, SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

// exeFromValue extracts the executable a registry value points to (e.g. a Run-key
// command) so Trace origin can reconstruct WHERE that binary came from. Returns
// the basename only when the value clearly references an executable, else "".
function exeFromValue(v: unknown): string {
  const s = typeof v === 'string' ? v : ''
  if (!s) return ''
  const m = s.match(/"([^"]+)"/)
  const first = m ? m[1] : s.split(/\s+/)[0]
  if (!/\.(exe|dll|bat|cmd|ps1|scr|com)$/i.test(first)) return ''
  return first.split(/[\\/]/).pop() || ''
}

export function RegistryViewer({ agent }: { agent: Agent }) {
  const [root, setRoot] = useState('HKLM')
  const [path, setPath] = useState('SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run')
  const [loading, setLoading] = useState(false)
  const [result, setResult] = useState<any>(null)
  const [error, setError] = useState<string | null>(null)
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)

  const handleParse = async () => {
    if (!path) {
      toast.error('Please enter a registry path')
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
      const data = await agentsApi.parseRegistry(agent.id, root, path)
      // The API returns the raw JSON string from the agent, so we need to parse it if it's a string
      let parsed = data
      if (typeof data === 'string') {
        try {
          parsed = JSON.parse(data)
        } catch (e) {
          // If it's not valid JSON (e.g., "[+] Registry parsing complete." message)
          parsed = { message: data }
        }
      }
      setResult(parsed)
      toast.success('Registry key parsed successfully')
    } catch (err: any) {
      const msg = err.response?.data?.error || err.message || 'Failed to parse registry'
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
            <div className="p-3 bg-blue-500/10 rounded-lg border border-blue-500/20">
              <Database className="h-6 w-6 text-blue-500" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-gray-100">Registry Parser (Edge)</h1>
              <p className="text-xs text-gray-400">Directly read Windows Registry on {agent.name} without memory dumping</p>
            </div>
          </div>
        </div>

        <div className="flex flex-wrap items-end gap-3 w-full pt-2 border-t border-gray-800/50">
          {/* Root Input */}
          <div className="flex flex-col gap-1.5 w-32">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Root Key</label>
            <Select value={root} onValueChange={setRoot}>
              <SelectTrigger className="bg-gray-950/50 border-gray-800 h-9 font-mono text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="HKLM">HKLM</SelectItem>
                <SelectItem value="HKCU">HKCU</SelectItem>
                <SelectItem value="HKCR">HKCR</SelectItem>
                <SelectItem value="HKU">HKU</SelectItem>
                <SelectItem value="HKCC">HKCC</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {/* Path Input */}
          <div className="flex flex-col gap-1.5 flex-1 min-w-[300px]">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold ml-1">Subkey Path</label>
            <div className="relative">
              <input 
                type="text" 
                value={path}
                onChange={(e) => setPath(e.target.value)}
                placeholder="e.g. SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
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
                className="btn-primary h-9 whitespace-nowrap px-6"
              >
                {loading ? (
                  <span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" />
                ) : (
                  <Search className="h-4 w-4" />
                )}
                {loading ? 'Reading...' : 'Read Key'}
              </button>
            </div>
          </div>
        </div>
      </div>

      {/* Result View */}
      <div className="flex-1 bg-gray-900/50 rounded-xl border border-gray-800 backdrop-blur-sm overflow-hidden flex flex-col">
        <div className="flex items-center justify-between px-4 py-3 border-b border-gray-800 bg-gray-900/50 shrink-0">
          <div className="flex items-center gap-2">
            <Database className="h-4 w-4 text-gray-400" />
            <h3 className="text-sm font-medium text-gray-200">Values</h3>
          </div>
        </div>

        <div className="flex-1 p-4 overflow-y-auto">
          {loading ? (
             <div className="h-full flex items-center justify-center text-gray-500 flex-col gap-3">
               <span className="h-8 w-8 rounded-full border-2 border-blue-500/30 border-t-blue-500 animate-spin" />
               <p className="text-sm">Querying registry on target...</p>
             </div>
          ) : error ? (
            <div className="rounded-lg border border-red-900/50 bg-red-950/20 p-4 flex items-start gap-3">
               <AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" />
               <div>
                 <h4 className="text-sm font-medium text-red-200">Error reading registry</h4>
                 <p className="text-xs text-red-300/80 mt-1">{error}</p>
               </div>
            </div>
          ) : !result ? (
             <div className="h-full flex items-center justify-center text-gray-500">
               <p className="text-sm">Enter a path and click "Read Key" to view registry values.</p>
             </div>
          ) : Array.isArray(result?.values) ? (
             <div className="space-y-2">
               {result.key_path && <div className="text-[11px] font-mono text-gray-500 break-all">{result.key_path}</div>}
               <div className="overflow-auto rounded-lg border border-gray-800">
                 <table className="w-full text-xs">
                   <thead className="sticky top-0 bg-gray-900 z-10">
                     <tr className="border-b border-gray-800">
                       <th className="px-3 py-2 text-left text-gray-500 font-medium">Name</th>
                       <th className="px-3 py-2 text-left text-gray-500 font-medium">Type</th>
                       <th className="px-3 py-2 text-left text-gray-500 font-medium">Value</th>
                       <th className="px-2 py-2 w-10"></th>
                     </tr>
                   </thead>
                   <tbody>
                     {result.values.map((v: any, i: number) => {
                       const exe = exeFromValue(v.value)
                       return (
                         <tr key={i} className="group border-b border-gray-900 hover:bg-white/5">
                           <td className="px-3 py-1.5 font-mono text-gray-300 whitespace-nowrap">{v.name || '(Default)'}</td>
                           <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{v.type || '—'}</td>
                           <td className="px-3 py-1.5 font-mono text-gray-400 break-all">{v.error ? <span className="text-red-400">{v.error}</span> : String(v.value ?? '')}</td>
                           <td className="px-2 py-1.5 text-right">
                             {exe && agent.status === 'online' && (
                               <button onClick={() => setTraceTarget({ target: exe, pid: 0 })} title={`Trace origin of ${exe}`}
                                 className="text-gray-500 hover:text-emerald-400 opacity-0 group-hover:opacity-100 transition-opacity">
                                 <GitBranch className="h-3.5 w-3.5" />
                               </button>
                             )}
                           </td>
                         </tr>
                       )
                     })}
                   </tbody>
                 </table>
               </div>
             </div>
          ) : (
             <div className="bg-gray-950 rounded border border-gray-800 p-4 overflow-auto">
               <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap break-all">
                 {JSON.stringify(result, null, 2)}
               </pre>
             </div>
          )}
        </div>
      </div>
      {traceTarget && <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />}
    </div>
  )
}
