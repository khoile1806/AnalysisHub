import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, Terminal as TerminalIcon, Cpu, RefreshCw, Server, MemoryStick, Database, PanelLeftClose, PanelLeftOpen, Power, PlayCircle, StopCircle, Loader2 } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuthStore } from '@/store/auth'
import { useUiStore } from '@/store/uiStore'
import { logsearchApi } from '@/api/logsearch'
import { useKeepalive } from '@/hooks/useKeepalive'
import { getErrorMessage } from '@/lib/utils'

interface DumpFile {
  name: string
  size: number
}

function formatBytes(bytes: number) {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB', 'TB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i]
}

export default function SandboxAnalysis() {
  const token = useAuthStore(s => s.token)
  const queryClient = useQueryClient()
  useKeepalive('sandbox') // keep the sandbox alive / auto-start while this page is open
  const [isUploading, setIsUploading] = useState(false)
  const [uploadProgress, setUploadProgress] = useState(0) // 0–100, upload %
  const [terminalUrl, setTerminalUrl] = useState<string>('')
  const [isDragging, setIsDragging] = useState(false)
  
  // State to toggle sidebar and make console bigger
  const isSidebarOpen = useUiStore(s => s.memorySidebarOpen)
  const setIsSidebarOpen = useUiStore(s => s.setMemorySidebarOpen)

  // Sandbox container power toggle (frees its RAM when idle, like the ELK toggle)
  const { data: sbx } = useQuery({
    queryKey: ['sandbox-status'],
    queryFn: logsearchApi.sandboxStatus,
    refetchInterval: 5000,
  })
  const sbxPowerMut = useMutation({
    mutationFn: (verb: 'start' | 'stop') => logsearchApi.sandboxPower(verb),
    onSuccess: (_d, verb) => {
      toast.success(verb === 'start' ? 'Starting sandbox…' : 'Stopping sandbox…')
      queryClient.invalidateQueries({ queryKey: ['sandbox-status'] })
    },
    onError: (e: any) => toast.error(getErrorMessage(e)),
  })
  const sbxRunning = !!sbx?.sandbox?.running

  // The ttyd terminal is no longer exposed on a host port — the backend
  // reverse-proxies it behind an admin JWT. Browsers can't attach an
  // Authorization header to an <iframe>, so we first ask the backend to drop a
  // short-lived, path-scoped HttpOnly cookie (the "grant"), then load the
  // same-origin proxy path; the cookie authenticates the iframe + its WebSocket.
  useEffect(() => {
    if (!token) return
    let cancelled = false
    fetch('/api/v1/sandbox/grant', {
      method: 'POST',
      headers: { Authorization: `Bearer ${token}` },
    })
      .then(res => {
        if (!res.ok) throw new Error('grant failed')
        if (!cancelled) setTerminalUrl('/api/v1/sandbox/terminal/')
      })
      .catch(() => {
        if (!cancelled) toast.error('Không khởi tạo được terminal (cần quyền admin)')
      })
    return () => { cancelled = true }
  }, [token])

  const { data: dumps = [], isLoading, refetch } = useQuery<DumpFile[]>({
    queryKey: ['memory-dumps'],
    queryFn: async () => {
      const res = await fetch('/api/v1/memory/dumps', {
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!res.ok) throw new Error('Failed to fetch memory dumps')
      const data = await res.json()
      return data.dumps || []
    }
  })

  const deleteDump = useMutation({
    mutationFn: async (filename: string) => {
      const res = await fetch(`/api/v1/memory/dumps/${encodeURIComponent(filename)}`, {
        method: 'DELETE',
        headers: { Authorization: `Bearer ${token}` }
      })
      if (!res.ok) throw new Error('Failed to delete')
    },
    onSuccess: () => {
      toast.success('Dump deleted')
      queryClient.invalidateQueries({ queryKey: ['memory-dumps'] })
    },
    onError: (err: Error) => toast.error(`Delete failed: ${err.message}`)
  })

  // Chunked upload: RAM dumps are routinely multi-GB, but an upstream proxy
  // (Cloudflare) caps a single request body at 100 MB. Splitting the file into
  // sub-cap chunks lets each request pass, and the backend reassembles them.
  const CHUNK_SIZE = 50 * 1024 * 1024 // 50 MB — safely under the 100 MB cap

  const uploadChunk = (
    blob: Blob,
    fields: { uploadId: string; filename: string; offset: number; totalSize: number; final: boolean },
    onChunkProgress: (loaded: number) => void,
  ) =>
    new Promise<void>((resolve, reject) => {
      const fd = new FormData()
      fd.append('upload_id', fields.uploadId)
      fd.append('filename', fields.filename)
      fd.append('offset', String(fields.offset))
      fd.append('total_size', String(fields.totalSize))
      fd.append('final', fields.final ? '1' : '0')
      fd.append('file', blob)

      const xhr = new XMLHttpRequest()
      xhr.open('POST', '/api/v1/memory/upload-chunk')
      xhr.setRequestHeader('Authorization', `Bearer ${token}`)
      xhr.timeout = 0
      xhr.upload.onprogress = (e) => { if (e.lengthComputable) onChunkProgress(e.loaded) }
      xhr.onload = () => {
        if (xhr.status >= 200 && xhr.status < 300) { resolve(); return }
        let msg = ''
        try { msg = JSON.parse(xhr.responseText)?.error } catch { /* not JSON */ }
        if (!msg) {
          const snippet = (xhr.responseText || '').replace(/<[^>]*>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 120)
          msg = `HTTP ${xhr.status || '???'}${snippet ? ` — ${snippet}` : ''}`
        }
        reject(new Error(msg))
      }
      xhr.onerror = () => reject(new Error('Network error / connection interrupted during upload'))
      xhr.ontimeout = () => reject(new Error('Upload timed out'))
      xhr.onabort = () => reject(new Error('Upload aborted'))
      xhr.send(fd)
    })

  const handleFile = async (file: File) => {
    setIsUploading(true)
    setUploadProgress(0)

    const uploadId =
      (typeof crypto !== 'undefined' && crypto.randomUUID)
        ? crypto.randomUUID()
        : `${Date.now()}-${Math.random().toString(16).slice(2)}`
    const total = file.size
    const chunkCount = Math.max(1, Math.ceil(total / CHUNK_SIZE))

    try {
      for (let i = 0; i < chunkCount; i++) {
        const start = i * CHUNK_SIZE
        const end = Math.min(start + CHUNK_SIZE, total)
        const blob = file.slice(start, end)
        await uploadChunk(
          blob,
          { uploadId, filename: file.name, offset: start, totalSize: total, final: i === chunkCount - 1 },
          (loaded) => setUploadProgress(Math.round(((start + loaded) / Math.max(1, total)) * 100)),
        )
      }
      setUploadProgress(100)
      toast.success('Memory dump uploaded successfully')
      queryClient.invalidateQueries({ queryKey: ['memory-dumps'] })
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally {
      setIsUploading(false)
      setUploadProgress(0)
    }
  }

  const onDragOver = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(true)
  }

  const onDragLeave = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
  }

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault()
    setIsDragging(false)
    const file = e.dataTransfer.files?.[0]
    if (file) handleFile(file)
  }

  return (
    <div className="flex-1 flex flex-col bg-[#09090b] overflow-hidden rounded-xl border border-white/5 shadow-2xl">
      
      {/* Top Header - Slimmer to save space */}
      <div className="h-16 shrink-0 border-b border-white/5 bg-[#121214] flex items-center justify-between px-4 z-20 shadow-sm">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-gradient-to-br from-indigo-500/20 to-purple-500/20 flex items-center justify-center border border-indigo-500/30 shadow-[0_0_10px_rgba(99,102,241,0.15)]">
            <Cpu className="h-5 w-5 text-indigo-400" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white tracking-tight leading-none">Sandbox Analysis</h1>
            <p className="text-xs text-gray-400 mt-1">Kali Linux Sandbox Environment</p>
          </div>
        </div>
        
        <div className="ml-auto flex items-center gap-2">
          {/* Sandbox power toggle */}
          {sbx?.control_enabled ? (
            <div className="flex items-center gap-2 mr-1">
              <span className="flex items-center gap-1.5 text-xs text-gray-400" title={
                sbx?.auto_shutdown?.enabled
                  ? (sbx.auto_shutdown.manual_off ? 'auto-shutdown paused (stopped by admin)'
                     : sbxRunning && sbx.auto_shutdown.stops_in_sec != null
                       ? `auto-stops in ${Math.floor(sbx.auto_shutdown.stops_in_sec / 60)}m ${sbx.auto_shutdown.stops_in_sec % 60}s (idle)`
                       : 'auto-starts on demand, stops when idle')
                  : undefined
              }>
                <Power className={`h-3.5 w-3.5 ${sbxRunning ? 'text-emerald-400' : 'text-gray-500'}`} />
                {sbxRunning ? 'running' : 'stopped'}
                {sbx?.auto_shutdown?.enabled && sbxRunning && sbx.auto_shutdown.stops_in_sec != null && !sbx.auto_shutdown.manual_off && (
                  <span className="text-[10px] text-gray-600">· ⏻ {Math.max(0, Math.floor(sbx.auto_shutdown.stops_in_sec / 60))}m</span>
                )}
              </span>
              <button
                disabled={sbxRunning || sbxPowerMut.isPending}
                onClick={() => sbxPowerMut.mutate('start')}
                className="px-2.5 py-1.5 rounded-lg text-xs bg-emerald-600 hover:bg-emerald-500 text-white disabled:opacity-40 flex items-center gap-1.5"
              >
                {sbxPowerMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <PlayCircle className="h-3.5 w-3.5" />} Start
              </button>
              <button
                disabled={!sbxRunning || sbxPowerMut.isPending}
                onClick={() => sbxPowerMut.mutate('stop')}
                className="px-2.5 py-1.5 rounded-lg text-xs bg-white/5 hover:bg-white/10 text-gray-300 border border-white/10 disabled:opacity-40 flex items-center gap-1.5"
              >
                <StopCircle className="h-3.5 w-3.5" /> Stop
              </button>
            </div>
          ) : (
            <span className="text-[11px] text-gray-500 mr-1" title={sbx?.hint}>power toggle off</span>
          )}

        {/* Toggle Sidebar Button */}
        <button
          onClick={() => setIsSidebarOpen(!isSidebarOpen)}
          className={`flex items-center gap-2 px-4 py-2 rounded-lg font-medium text-sm transition-all ${
            isSidebarOpen 
              ? 'bg-white/5 text-gray-300 hover:bg-white/10' 
              : 'bg-indigo-500/10 text-indigo-400 hover:bg-indigo-500/20 border border-indigo-500/20'
          }`}
        >
          {isSidebarOpen ? <PanelLeftClose className="w-4 h-4" /> : <PanelLeftOpen className="w-4 h-4" />}
          {isSidebarOpen ? 'Hide Files' : 'Manage Sandbox Files'}
        </button>
        </div>
      </div>

      {/* Main Content Area */}
      <div className="flex-1 flex overflow-hidden min-h-0 relative">
        
        {/* Left Sidebar (Collapsible) */}
        <div 
          className={`flex-shrink-0 flex flex-col border-r border-white/5 bg-[#121214] z-10 transition-all duration-300 ease-in-out ${
            isSidebarOpen ? 'w-80 xl:w-96 translate-x-0' : 'w-0 -translate-x-full overflow-hidden border-r-0'
          }`}
        >
          {isSidebarOpen && (
            <div className="flex flex-col h-full w-80 xl:w-96">
              {/* Upload Card */}
              <div className="p-4 border-b border-white/5 relative overflow-hidden shrink-0">
                <div className="absolute -top-10 -right-10 w-32 h-32 bg-indigo-500/10 blur-3xl rounded-full pointer-events-none"></div>
                <h2 className="text-sm font-semibold text-gray-200 mb-3 flex items-center gap-2">
                  <Database className="w-3.5 h-3.5 text-indigo-400" />
                  Sandbox Files
                </h2>
                
                <label
                  className={`relative flex flex-col items-center justify-center py-6 px-4 border-2 border-dashed rounded-xl cursor-pointer transition-all duration-200 ${
                    isDragging 
                      ? 'border-indigo-500 bg-indigo-500/10 scale-[1.02]' 
                      : 'border-white/10 hover:border-indigo-500/50 hover:bg-white/[0.02]'
                  }`}
                  onDragOver={onDragOver}
                  onDragLeave={onDragLeave}
                  onDrop={onDrop}
                >
                  <input
                    type="file"
                    className="hidden"
                    onChange={(e) => {
                      const file = e.target.files?.[0]
                      if (file) handleFile(file)
                      e.target.value = ''
                    }}
                    disabled={isUploading}
                    accept=".raw,.mem,.vmem,.bin,.dmp"
                  />
                  
                  {isUploading ? (
                    <div className="w-full px-4 flex flex-col items-center">
                      <RefreshCw className="h-6 w-6 text-indigo-400 animate-spin mb-2" />
                      <p className="text-sm font-medium text-indigo-300 mb-2">
                        Uploading… {uploadProgress}%
                      </p>
                      <div className="w-full h-2 bg-white/10 rounded-full overflow-hidden">
                        <div
                          className="h-full bg-indigo-500 transition-all duration-150"
                          style={{ width: `${uploadProgress}%` }}
                        />
                      </div>
                    </div>
                  ) : (
                    <>
                      <div className="p-2.5 bg-indigo-500/10 rounded-full mb-2 shadow-[0_0_10px_rgba(99,102,241,0.2)]">
                        <Upload className="h-5 w-5 text-indigo-400" />
                      </div>
                      <p className="text-sm font-medium text-gray-300 text-center">Drop dump here</p>
                    </>
                  )}
                </label>
              </div>

              {/* Dumps List Card */}
              <div className="flex-1 flex flex-col min-h-0">
                <div className="px-4 py-3 border-b border-white/5 flex items-center justify-between bg-[#151518] shrink-0">
                  <h2 className="text-xs font-medium text-gray-400 uppercase tracking-wider">Available Files</h2>
                  <button 
                    onClick={() => refetch()} 
                    className="p-1 text-gray-500 hover:text-white hover:bg-white/10 rounded-md transition-colors"
                    title="Refresh List"
                  >
                    <RefreshCw className="h-3.5 w-3.5" />
                  </button>
                </div>
                
                <div className="flex-1 overflow-y-auto p-2 space-y-1">
                  {isLoading ? (
                    <div className="flex items-center justify-center h-20 text-gray-500 text-sm">Loading...</div>
                  ) : dumps.length === 0 ? (
                    <div className="flex flex-col items-center justify-center h-32 text-gray-500 text-sm gap-2">
                      <MemoryStick className="h-6 w-6 opacity-40" />
                      <span>No dumps available</span>
                    </div>
                  ) : (
                    dumps.map(d => (
                      <div key={d.name} className="group flex items-center justify-between p-2.5 rounded-lg hover:bg-white/5 transition-colors border border-transparent hover:border-white/5">
                        <div className="min-w-0 flex-1 flex items-center gap-3">
                          <div className="p-1.5 bg-gray-800/50 rounded-md text-gray-400 group-hover:text-indigo-400 transition-colors">
                            <Server className="h-3.5 w-3.5" />
                          </div>
                          <div className="min-w-0">
                            <p className="text-sm font-medium text-gray-200 truncate pr-2" title={d.name}>{d.name}</p>
                            <p className="text-[11px] text-gray-500">{formatBytes(d.size)}</p>
                          </div>
                        </div>
                        <button
                          onClick={() => deleteDump.mutate(d.name)}
                          className="p-1.5 text-gray-500 hover:text-rose-400 hover:bg-rose-400/10 rounded-md opacity-0 group-hover:opacity-100 transition-all shrink-0"
                          title="Delete Dump"
                        >
                          <Trash2 className="h-3.5 w-3.5" />
                        </button>
                      </div>
                    ))
                  )}
                </div>
              </div>
            </div>
          )}
        </div>

        {/* Right Area (Terminal) - Expands to full width when sidebar is closed */}
        <div className="flex-1 flex flex-col bg-black relative">
          
          {/* Terminal Header */}
          <div className="h-10 bg-[#121214] border-b border-white/5 flex items-center px-4 justify-between shrink-0">
            <div className="flex items-center gap-4">
              <div className="flex items-center gap-2">
                <TerminalIcon className="h-4 w-4 text-emerald-400" />
                <span className="text-sm font-mono text-gray-300 tracking-wider">root@kali:~#</span>
              </div>
            </div>
            
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5">
                <div className="w-2.5 h-2.5 rounded-full bg-emerald-500/80 shadow-[0_0_8px_rgba(16,185,129,0.5)]"></div>
                <span className="text-[10px] uppercase font-bold tracking-widest text-emerald-400/80 mr-2">Online</span>
              </div>
              <span className="px-2 py-0.5 rounded bg-indigo-500/10 border border-indigo-500/20 text-indigo-300 text-[10px] uppercase font-mono font-bold tracking-wider">
                vol2
              </span>
              <span className="px-2 py-0.5 rounded bg-purple-500/10 border border-purple-500/20 text-purple-300 text-[10px] uppercase font-mono font-bold tracking-wider">
                vol3
              </span>
            </div>
          </div>
          
          {/* Terminal Body */}
          <div className="flex-1 bg-black relative">
             <iframe
              src={terminalUrl}
              className="absolute inset-0 w-full h-full border-none"
              title="Volatility Terminal"
              allow="clipboard-read; clipboard-write"
            />
          </div>
        </div>

      </div>
    </div>
  )
}
