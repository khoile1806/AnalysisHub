import { useState, useEffect, type FormEvent, type ChangeEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Search, Download, Trash2, Wrench, Upload, Pencil } from 'lucide-react'
import toast from 'react-hot-toast'
import {
  toolsApi,
  type Tool,
  type ToolCategory,
  type ToolPlatform,
  TOOL_CATEGORIES,
  TOOL_PLATFORMS,
} from '@/api/tools'
import { CategoryBadge, PlatformBadge } from '@/components/StatusBadge'
import { formatBytes, getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogBody,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

// ---- Upload modal ----
interface UploadModalProps {
  open: boolean
  onClose: () => void
}

function UploadModal({ open, onClose }: UploadModalProps) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [category, setCategory] = useState<ToolCategory>('other')
  const [platform, setPlatform] = useState<ToolPlatform>('windows')
  const [version, setVersion] = useState('')
  const [description, setDescription] = useState('')
  const [args, setArgs] = useState('')
  const [executablePath, setExecutablePath] = useState('')
  const [file, setFile] = useState<File | null>(null)
  // Result-collection spec
  const [collectResult, setCollectResult] = useState(false)
  const [outputGlobs, setOutputGlobs] = useState('')
  const [outputScope, setOutputScope] = useState('both')
  const [resultProcessor, setResultProcessor] = useState('auto')
  const [aiDefault, setAiDefault] = useState(true)
  const [autoAnalyze, setAutoAnalyze] = useState(false)
  const [maxResultMB, setMaxResultMB] = useState('200')

  const isZip = file?.name.toLowerCase().endsWith('.zip') ?? false

  const reset = () => {
    setName(''); setCategory('other'); setPlatform('windows')
    setVersion(''); setDescription(''); setArgs(''); setExecutablePath(''); setFile(null)
    setCollectResult(false); setOutputGlobs(''); setOutputScope('both')
    setResultProcessor('auto'); setAiDefault(true); setAutoAnalyze(false); setMaxResultMB('200')
  }

  const uploadMutation = useMutation({
    mutationFn: (fd: FormData) => toolsApi.upload(fd),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tools'] })
      toast.success('Tool uploaded successfully')
      reset()
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!file) { toast.error('Please select a file'); return }
    const fd = new FormData()
    fd.append('name', name)
    fd.append('category', category)
    fd.append('platform', platform)
    fd.append('version', version)
    fd.append('description', description)
    fd.append('args', args)
    fd.append('executable_path', executablePath)
    fd.append('collect_result', String(collectResult))
    fd.append('output_globs', outputGlobs)
    fd.append('output_scope', outputScope)
    fd.append('result_processor', resultProcessor)
    fd.append('ai_default', String(aiDefault))
    fd.append('auto_analyze', String(autoAnalyze))
    fd.append('max_result_mb', maxResultMB || '0')
    fd.append('file', file)
    uploadMutation.mutate(fd)
  }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) { reset(); onClose() } }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Upload Tool</DialogTitle>
          <DialogDescription>Add a forensic tool to the library</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="sm:col-span-2">
                <label className="label">Tool Name *</label>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. Volatility3" required />
              </div>
              <div>
                <label className="label">Category</label>
                <Select value={category} onValueChange={(v) => setCategory(v as ToolCategory)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {TOOL_CATEGORIES.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="label">Platform</label>
                <Select value={platform} onValueChange={(v) => setPlatform(v as ToolPlatform)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {TOOL_PLATFORMS.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="label">Version</label>
                <input className="input" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.0.0" />
              </div>
              <div>
                <label className="label">Default Args</label>
                <input className="input font-mono text-xs" value={args} onChange={(e) => setArgs(e.target.value)} placeholder="-f {evidence} --profile Win10x64" />
              </div>
              <div className="sm:col-span-2">
                <label className="label">Description</label>
                <textarea
                  className="input resize-none"
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                  placeholder="Brief description of this tool's purpose"
                />
              </div>
              <div className="sm:col-span-2">
                <label className="label">Tool File * <span className="text-gray-500 font-normal">(binary or .zip)</span></label>
                <label className="flex flex-col items-center justify-center w-full h-24 border-2 border-dashed border-gray-700 rounded-lg cursor-pointer bg-gray-800/50 hover:bg-gray-800 transition-colors">
                  <div className="flex flex-col items-center gap-1">
                    <Upload className="h-5 w-5 text-gray-500" />
                    <span className="text-xs text-gray-400">
                      {file ? (
                        <span className="text-emerald-400 font-mono">{file.name} ({formatBytes(file.size)})</span>
                      ) : (
                        'Click to select or drag & drop'
                      )}
                    </span>
                  </div>
                  <input
                    type="file"
                    className="hidden"
                    onChange={(e: ChangeEvent<HTMLInputElement>) => setFile(e.target.files?.[0] ?? null)}
                  />
                </label>
              </div>
              {isZip && (
                <div className="sm:col-span-2">
                  <label className="label">
                    Executable Path
                    <span className="text-gray-500 font-normal ml-1">(relative path inside zip to the file to run)</span>
                  </label>
                  <input
                    className="input font-mono text-xs"
                    value={executablePath}
                    onChange={(e) => setExecutablePath(e.target.value)}
                    placeholder="e.g. bin/DumpIt.exe"
                  />
                  <p className="text-[11px] text-gray-500 mt-1">
                    Leave empty to extract only (no auto-execution)
                  </p>
                </div>
              )}

              <div className="sm:col-span-2 rounded-lg border border-gray-700 bg-gray-800/40 p-3 space-y-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={collectResult} onChange={(e) => setCollectResult(e.target.checked)} />
                  <span className="text-sm font-medium text-gray-200">Auto-collect result files after run</span>
                </label>
                {collectResult && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="sm:col-span-2">
                      <label className="label">Output patterns <span className="text-gray-500 font-normal">(comma-separated globs)</span></label>
                      <input className="input font-mono text-xs" value={outputGlobs} onChange={(e) => setOutputGlobs(e.target.value)} placeholder="*.txt, *.csv, report/*.html" />
                      <p className="text-[11px] text-gray-500 mt-1">
                        Tip: point the tool's output flag at <code className="text-emerald-400">{'{{OUTDIR}}'}</code> in Default Args to collect everything it writes.
                      </p>
                    </div>
                    <div>
                      <label className="label">Scope</label>
                      <select className="input" value={outputScope} onChange={(e) => setOutputScope(e.target.value)}>
                        <option value="both">both</option>
                        <option value="tooldir">tool dir (glob)</option>
                        <option value="outdir">{'{{OUTDIR}}'} only</option>
                      </select>
                    </div>
                    <div>
                      <label className="label">Processor</label>
                      <select className="input" value={resultProcessor} onChange={(e) => setResultProcessor(e.target.value)}>
                        {['auto', 'text', 'csv', 'json', 'loki', 'redline', 'kape', 'none'].map((p) => <option key={p} value={p}>{p}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Max size / file (MB)</label>
                      <input className="input" type="number" min={0} value={maxResultMB} onChange={(e) => setMaxResultMB(e.target.value)} />
                    </div>
                    <div className="flex items-end">
                      <label className="flex items-center gap-2 cursor-pointer pb-2">
                        <input type="checkbox" checked={aiDefault} onChange={(e) => setAiDefault(e.target.checked)} />
                        <span className="text-sm text-gray-300">Send to AI by default</span>
                      </label>
                    </div>
                    <div className="sm:col-span-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" checked={autoAnalyze} onChange={(e) => setAutoAnalyze(e.target.checked)} disabled={!aiDefault} />
                        <span className="text-sm text-gray-300">Auto-analyze on finish <span className="text-gray-500 font-normal">(run AI findings → timeline automatically when the job completes)</span></span>
                      </label>
                      <p className="text-[11px] text-gray-500 mt-1">Requires an AI provider + the agent linked to a case. Uses tokens per run — leave off for manual control.</p>
                    </div>
                  </div>
                )}
              </div>

            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={() => { reset(); onClose() }}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={uploadMutation.isPending}>
              {uploadMutation.isPending ? (
                <><span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> Uploading…</>
              ) : (
                <><Upload className="h-4 w-4" /> Upload Tool</>
              )}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Edit modal ----
interface EditModalProps {
  tool: Tool | null
  onClose: () => void
}

function EditModal({ tool, onClose }: EditModalProps) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [category, setCategory] = useState<ToolCategory>('other')
  const [platform, setPlatform] = useState<ToolPlatform>('windows')
  const [version, setVersion] = useState('')
  const [description, setDescription] = useState('')
  const [args, setArgs] = useState('')
  const [executablePath, setExecutablePath] = useState('')
  const [collectResult, setCollectResult] = useState(false)
  const [outputGlobs, setOutputGlobs] = useState('')
  const [outputScope, setOutputScope] = useState('both')
  const [resultProcessor, setResultProcessor] = useState('auto')
  const [aiDefault, setAiDefault] = useState(true)
  const [autoAnalyze, setAutoAnalyze] = useState(false)
  const [maxResultMB, setMaxResultMB] = useState('200')

  const isZip = tool?.file_name.toLowerCase().endsWith('.zip') ?? false

  useEffect(() => {
    if (tool) {
      setName(tool.name)
      setCategory(tool.category)
      setPlatform(tool.platform)
      setVersion(tool.version ?? '')
      setDescription(tool.description ?? '')
      setArgs(tool.args ?? '')
      setExecutablePath(tool.executable_path ?? '')
      setCollectResult(tool.collect_result ?? false)
      setOutputGlobs(tool.output_globs ?? '')
      setOutputScope(tool.output_scope || 'both')
      setResultProcessor(tool.result_processor || 'auto')
      setAiDefault(tool.ai_default ?? true)
      setAutoAnalyze(tool.auto_analyze ?? false)
      setMaxResultMB(String(tool.max_result_mb ?? 200))
    }
  }, [tool])

  const updateMutation = useMutation({
    mutationFn: (payload: Parameters<typeof toolsApi.update>[1]) =>
      toolsApi.update(tool!.id, payload),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tools'] })
      toast.success('Tool updated')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!tool) return
    updateMutation.mutate({
      name, category, platform, version, description, args,
      executable_path: executablePath,
      collect_result: collectResult,
      output_globs: outputGlobs,
      output_scope: outputScope,
      result_processor: resultProcessor,
      ai_default: aiDefault,
      auto_analyze: autoAnalyze,
      max_result_mb: Number(maxResultMB) || 0,
    })
  }

  return (
    <Dialog open={!!tool} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Edit Tool</DialogTitle>
          <DialogDescription>Update metadata. Binary file cannot be replaced here — delete and re-upload to swap files.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
              <div className="sm:col-span-2">
                <label className="label">Tool Name *</label>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} required />
              </div>
              <div>
                <label className="label">Category</label>
                <Select value={category} onValueChange={(v) => setCategory(v as ToolCategory)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {TOOL_CATEGORIES.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="label">Platform</label>
                <Select value={platform} onValueChange={(v) => setPlatform(v as ToolPlatform)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {TOOL_PLATFORMS.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
                  </SelectContent>
                </Select>
              </div>
              <div>
                <label className="label">Version</label>
                <input className="input" value={version} onChange={(e) => setVersion(e.target.value)} placeholder="1.0.0" />
              </div>
              <div>
                <label className="label">Default Args</label>
                <input className="input font-mono text-xs" value={args} onChange={(e) => setArgs(e.target.value)} placeholder="-f {evidence}" />
              </div>
              <div className="sm:col-span-2">
                <label className="label">Description</label>
                <textarea
                  className="input resize-none"
                  rows={2}
                  value={description}
                  onChange={(e) => setDescription(e.target.value)}
                />
              </div>
              <div className="sm:col-span-2">
                <label className="label">File <span className="text-gray-500 font-normal">(read-only)</span></label>
                <div className="input bg-gray-900/60 text-gray-400 font-mono text-xs cursor-not-allowed">
                  {tool?.file_name} ({tool ? formatBytes(tool.file_size) : ''})
                </div>
              </div>
              {isZip && (
                <div className="sm:col-span-2">
                  <label className="label">
                    Executable Path
                    <span className="text-gray-500 font-normal ml-1">(relative path inside zip to the file to run)</span>
                  </label>
                  <input
                    className="input font-mono text-xs"
                    value={executablePath}
                    onChange={(e) => setExecutablePath(e.target.value)}
                    placeholder="e.g. bin/DumpIt.exe"
                  />
                  <p className="text-[11px] text-gray-500 mt-1">
                    Leave empty to extract only (no auto-execution)
                  </p>
                </div>
              )}

              <div className="sm:col-span-2 rounded-lg border border-gray-700 bg-gray-800/40 p-3 space-y-3">
                <label className="flex items-center gap-2 cursor-pointer">
                  <input type="checkbox" checked={collectResult} onChange={(e) => setCollectResult(e.target.checked)} />
                  <span className="text-sm font-medium text-gray-200">Auto-collect result files after run</span>
                </label>
                {collectResult && (
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div className="sm:col-span-2">
                      <label className="label">Output patterns <span className="text-gray-500 font-normal">(comma-separated globs)</span></label>
                      <input className="input font-mono text-xs" value={outputGlobs} onChange={(e) => setOutputGlobs(e.target.value)} placeholder="*.txt, *.csv, report/*.html" />
                    </div>
                    <div>
                      <label className="label">Scope</label>
                      <select className="input" value={outputScope} onChange={(e) => setOutputScope(e.target.value)}>
                        <option value="both">both</option>
                        <option value="tooldir">tool dir (glob)</option>
                        <option value="outdir">{'{{OUTDIR}}'} only</option>
                      </select>
                    </div>
                    <div>
                      <label className="label">Processor</label>
                      <select className="input" value={resultProcessor} onChange={(e) => setResultProcessor(e.target.value)}>
                        {['auto', 'text', 'csv', 'json', 'loki', 'redline', 'kape', 'none'].map((p) => <option key={p} value={p}>{p}</option>)}
                      </select>
                    </div>
                    <div>
                      <label className="label">Max size / file (MB)</label>
                      <input className="input" type="number" min={0} value={maxResultMB} onChange={(e) => setMaxResultMB(e.target.value)} />
                    </div>
                    <div className="flex items-end">
                      <label className="flex items-center gap-2 cursor-pointer pb-2">
                        <input type="checkbox" checked={aiDefault} onChange={(e) => setAiDefault(e.target.checked)} />
                        <span className="text-sm text-gray-300">Send to AI by default</span>
                      </label>
                    </div>
                    <div className="sm:col-span-2">
                      <label className="flex items-center gap-2 cursor-pointer">
                        <input type="checkbox" checked={autoAnalyze} onChange={(e) => setAutoAnalyze(e.target.checked)} disabled={!aiDefault} />
                        <span className="text-sm text-gray-300">Auto-analyze on finish <span className="text-gray-500 font-normal">(run AI findings → timeline automatically when the job completes)</span></span>
                      </label>
                      <p className="text-[11px] text-gray-500 mt-1">Requires an AI provider + the agent linked to a case. Uses tokens per run — leave off for manual control.</p>
                    </div>
                  </div>
                )}
              </div>
            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={updateMutation.isPending}>
              {updateMutation.isPending ? 'Saving…' : 'Save Changes'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- Delete confirmation ----
interface DeleteModalProps {
  tool: Tool | null
  onClose: () => void
}

function DeleteModal({ tool, onClose }: DeleteModalProps) {
  const qc = useQueryClient()
  const deleteMutation = useMutation({
    mutationFn: () => toolsApi.delete(tool!.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['tools'] })
      toast.success('Tool deleted')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  return (
    <Dialog open={!!tool} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-sm">
        <DialogHeader>
          <DialogTitle>Delete Tool</DialogTitle>
          <DialogDescription>This action cannot be undone.</DialogDescription>
        </DialogHeader>
        <DialogBody>
          <p className="text-sm text-gray-300">
            Are you sure you want to delete <span className="font-semibold text-white">{tool?.name}</span>?
            This will remove the tool and its binary from the server.
          </p>
        </DialogBody>
        <DialogFooter>
          <button className="btn-secondary" onClick={onClose}>Cancel</button>
          <button
            className="btn-danger"
            onClick={() => deleteMutation.mutate()}
            disabled={deleteMutation.isPending}
          >
            {deleteMutation.isPending ? 'Deleting…' : 'Delete Tool'}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- Main Page ----
export default function ToolsPage() {
  const [uploadOpen, setUploadOpen] = useState(false)
  const [editTarget, setEditTarget] = useState<Tool | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<Tool | null>(null)
  const [search, setSearch] = useState('')
  const [filterCategory, setFilterCategory] = useState<string>('all')
  const [filterPlatform, setFilterPlatform] = useState<string>('all')

  const { data: tools = [], isLoading } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list(),
  })

  const filtered = tools.filter((t) => {
    const matchSearch =
      search === '' ||
      t.name.toLowerCase().includes(search.toLowerCase()) ||
      t.description.toLowerCase().includes(search.toLowerCase())
    const matchCat = filterCategory === 'all' || t.category === filterCategory
    const matchPlat = filterPlatform === 'all' || t.platform === filterPlatform
    return matchSearch && matchCat && matchPlat
  })

  return (
    <div className="space-y-5">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Tool Library</h1>
          <p className="text-sm text-gray-400 mt-0.5">{tools.length} tool{tools.length !== 1 ? 's' : ''} available</p>
        </div>
        <button className="btn-primary w-full sm:w-auto justify-center" onClick={() => setUploadOpen(true)}>
          <Plus className="h-4 w-4" /> Upload Tool
        </button>
      </div>

      {/* Filter bar */}
      <div className="flex flex-col sm:flex-row flex-wrap items-stretch sm:items-center gap-3">
        <div className="relative flex-1 min-w-[200px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
          <input
            type="search"
            className="input pl-9"
            placeholder="Search tools…"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
          />
        </div>
        <Select value={filterCategory} onValueChange={setFilterCategory}>
          <SelectTrigger className="w-40"><SelectValue placeholder="Category" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Categories</SelectItem>
            {TOOL_CATEGORIES.map((c) => <SelectItem key={c} value={c}>{c}</SelectItem>)}
          </SelectContent>
        </Select>
        <Select value={filterPlatform} onValueChange={setFilterPlatform}>
          <SelectTrigger className="w-36"><SelectValue placeholder="Platform" /></SelectTrigger>
          <SelectContent>
            <SelectItem value="all">All Platforms</SelectItem>
            {TOOL_PLATFORMS.map((p) => <SelectItem key={p} value={p}>{p}</SelectItem>)}
          </SelectContent>
        </Select>
      </div>

      {/* Table */}
      <div className="card overflow-hidden">
        <div className="overflow-x-auto">
          {isLoading ? (
            <div className="p-6 space-y-3">
              {[...Array(6)].map((_, i) => <div key={i} className="skeleton h-12 w-full rounded" />)}
            </div>
          ) : filtered.length === 0 ? (
            <div className="flex flex-col items-center justify-center py-16 text-gray-500">
              <Wrench className="h-10 w-10 mb-3 opacity-30" />
              <p className="text-sm">{tools.length === 0 ? 'No tools uploaded yet' : 'No tools match your filters'}</p>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-gray-800">
                  <th className="table-header text-left px-5 py-3">Name</th>
                  <th className="table-header text-left px-5 py-3 hidden sm:table-cell">Category</th>
                  <th className="table-header text-left px-5 py-3 hidden md:table-cell">Platform</th>
                  <th className="table-header text-left px-5 py-3 hidden lg:table-cell">Version</th>
                  <th className="table-header text-left px-5 py-3 hidden lg:table-cell">Size</th>
                  <th className="table-header text-left px-5 py-3 hidden xl:table-cell">Default Args</th>
                  <th className="table-header text-left px-5 py-3 hidden md:table-cell">Uploaded</th>
                  <th className="table-header text-right px-5 py-3">Actions</th>
                </tr>
              </thead>
              <tbody>
                {filtered.map((tool) => (
                  <tr key={tool.id} className="border-b border-gray-800/60 hover:bg-gray-800/30 transition-colors">
                    <td className="px-5 py-3">
                      <div className="font-medium text-gray-200 text-sm">{tool.name}</div>
                      {tool.description && (
                        <div className="text-xs text-gray-500 mt-0.5 max-w-xs truncate">{tool.description}</div>
                      )}
                    </td>
                    <td className="px-5 py-3 hidden sm:table-cell">
                      <CategoryBadge category={tool.category} />
                    </td>
                    <td className="px-5 py-3 hidden md:table-cell">
                      <PlatformBadge platform={tool.platform} />
                    </td>
                    <td className="px-5 py-3 hidden lg:table-cell text-sm text-gray-400 font-mono">{tool.version || '—'}</td>
                    <td className="px-5 py-3 hidden lg:table-cell text-sm text-gray-400">{formatBytes(tool.file_size)}</td>
                    <td className="px-5 py-3 hidden xl:table-cell">
                      {tool.args ? (
                        <code className="text-xs text-amber-400 bg-amber-900/20 px-1.5 py-0.5 rounded font-mono max-w-[200px] block truncate">
                          {tool.args}
                        </code>
                      ) : (
                        <span className="text-gray-600 text-xs">—</span>
                      )}
                    </td>
                    <td className="px-5 py-3 hidden md:table-cell text-xs text-gray-500">
                      {safeDistanceToNow(tool.created_at, { addSuffix: true })}
                    </td>
                    <td className="px-5 py-3">
                      <div className="flex items-center justify-end gap-2">
                        <a
                          href={toolsApi.downloadUrl(tool.id)}
                          download={tool.file_name}
                          className="p-1.5 text-gray-400 hover:text-emerald-400 hover:bg-emerald-900/20 rounded transition-colors"
                          title="Download"
                        >
                          <Download className="h-4 w-4" />
                        </a>
                        <button
                          onClick={() => setEditTarget(tool)}
                          className="p-1.5 text-gray-400 hover:text-amber-400 hover:bg-amber-900/20 rounded transition-colors"
                          title="Edit"
                        >
                          <Pencil className="h-4 w-4" />
                        </button>
                        <button
                          onClick={() => setDeleteTarget(tool)}
                          className="p-1.5 text-gray-400 hover:text-red-400 hover:bg-red-900/20 rounded transition-colors"
                          title="Delete"
                        >
                          <Trash2 className="h-4 w-4" />
                        </button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      </div>

      <UploadModal open={uploadOpen} onClose={() => setUploadOpen(false)} />
      <EditModal tool={editTarget} onClose={() => setEditTarget(null)} />
      <DeleteModal tool={deleteTarget} onClose={() => setDeleteTarget(null)} />
    </div>
  )
}
