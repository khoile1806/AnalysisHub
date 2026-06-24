import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Upload, Trash2, Terminal as TerminalIcon, Cpu, RefreshCw, FileWarning } from 'lucide-react'
import toast from 'react-hot-toast'
import { useAuthStore } from '@/store/auth'

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

export default function MemoryAnalysis() {
  const token = useAuthStore(s => s.token)
  const queryClient = useQueryClient()
  const [isUploading, setIsUploading] = useState(false)
  const [terminalUrl, setTerminalUrl] = useState<string>('')

  // Initialize terminal URL to point to the ttyd server
  useState(() => {
    const protocol = window.location.protocol
    const hostname = window.location.hostname
    setTerminalUrl(`${protocol}//${hostname}:7681`)
  })

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

  const handleFileUpload = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    if (!file) return

    setIsUploading(true)
    const formData = new FormData()
    formData.append('file', file)

    try {
      const res = await fetch('/api/v1/memory/upload', {
        method: 'POST',
        headers: { Authorization: `Bearer ${token}` },
        body: formData
      })
      if (!res.ok) {
        const errorData = await res.json().catch(() => null)
        throw new Error(errorData?.error || 'Upload failed')
      }
      toast.success('Memory dump uploaded successfully')
      queryClient.invalidateQueries({ queryKey: ['memory-dumps'] })
    } catch (err: any) {
      toast.error(err.message || 'Upload failed')
    } finally {
      setIsUploading(false)
      if (e.target) e.target.value = ''
    }
  }

  return (
    <div className="p-6 h-full flex flex-col gap-6">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-purple-500/20 flex items-center justify-center border border-purple-500/30">
            <Cpu className="h-5 w-5 text-purple-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white tracking-tight">Memory Analysis</h1>
            <p className="text-sm text-gray-400">Interactive Volatility 2 & 3 Sandbox</p>
          </div>
        </div>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-4 gap-6 flex-1 min-h-0">
        {/* Left Column: File Management */}
        <div className="col-span-1 flex flex-col gap-4 overflow-y-auto pr-2">
          <div className="bg-[#1C1C1E] border border-gray-800 rounded-xl p-4 flex flex-col gap-4">
            <h2 className="text-lg font-semibold text-gray-200">Upload Dump</h2>
            <div className="relative border-2 border-dashed border-gray-700 rounded-lg p-6 hover:border-purple-500/50 transition-colors bg-[#151515] text-center">
              <input
                type="file"
                className="absolute inset-0 w-full h-full opacity-0 cursor-pointer"
                onChange={handleFileUpload}
                disabled={isUploading}
                accept=".raw,.mem,.vmem,.bin"
              />
              <div className="flex flex-col items-center justify-center gap-2 pointer-events-none">
                {isUploading ? (
                  <RefreshCw className="h-8 w-8 text-purple-500 animate-spin" />
                ) : (
                  <Upload className="h-8 w-8 text-gray-500" />
                )}
                <span className="text-sm text-gray-400 font-medium">
                  {isUploading ? 'Uploading...' : 'Drag & Drop or Click to Upload'}
                </span>
              </div>
            </div>
          </div>

          <div className="bg-[#1C1C1E] border border-gray-800 rounded-xl p-4 flex flex-col gap-4 flex-1">
            <div className="flex items-center justify-between">
              <h2 className="text-lg font-semibold text-gray-200">Sandbox Dumps</h2>
              <button onClick={() => refetch()} className="p-1.5 hover:bg-white/5 rounded-md text-gray-400 hover:text-white transition-colors">
                <RefreshCw className="h-4 w-4" />
              </button>
            </div>
            
            <div className="flex-1 overflow-y-auto flex flex-col gap-2">
              {isLoading ? (
                <div className="text-center py-4 text-gray-500">Loading...</div>
              ) : dumps.length === 0 ? (
                <div className="text-center py-8 flex flex-col items-center gap-2 text-gray-500 border border-dashed border-gray-800 rounded-lg">
                  <FileWarning className="h-8 w-8 opacity-50" />
                  <p className="text-sm">No memory dumps uploaded</p>
                </div>
              ) : (
                dumps.map(d => (
                  <div key={d.name} className="flex items-center justify-between p-3 rounded-lg bg-[#252528] border border-gray-700 hover:border-gray-600 group">
                    <div className="min-w-0 flex-1">
                      <p className="text-sm font-medium text-gray-200 truncate">{d.name}</p>
                      <p className="text-xs text-gray-500">{formatBytes(d.size)}</p>
                    </div>
                    <button
                      onClick={() => deleteDump.mutate(d.name)}
                      className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-red-400/10 rounded-md opacity-0 group-hover:opacity-100 transition-all"
                      title="Delete Dump"
                    >
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </div>
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right Column: Web Terminal */}
        <div className="col-span-1 lg:col-span-3 bg-[#1C1C1E] border border-gray-800 rounded-xl flex flex-col overflow-hidden">
          <div className="flex items-center gap-2 bg-[#252528] px-4 py-2 border-b border-gray-800">
            <TerminalIcon className="h-4 w-4 text-purple-400" />
            <span className="text-sm font-medium text-gray-200">Volatility Interactive Console</span>
            <div className="ml-auto text-xs text-gray-500 flex items-center gap-2">
              <span className="px-2 py-0.5 rounded bg-gray-800 border border-gray-700">vol2</span>
              <span className="px-2 py-0.5 rounded bg-gray-800 border border-gray-700">vol3</span>
            </div>
          </div>
          <div className="flex-1 relative bg-black">
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
