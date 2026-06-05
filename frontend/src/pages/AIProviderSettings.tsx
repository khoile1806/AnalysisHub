import { useState, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, Trash2, Pencil, Zap, Eye, EyeOff } from 'lucide-react'
import toast from 'react-hot-toast'
import { analysisApi, type AIProvider, type CreateProviderData } from '@/api/analysis'
import { getErrorMessage } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
  DialogFooter,
} from '@/components/ui/dialog'
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from '@/components/ui/select'

const PROVIDER_PRESETS: Record<string, { label: string; baseURL: string; type: 'openai' | 'anthropic' | 'google'; examples: string[] }> = {
  groq:       { label: 'Groq',        type: 'openai',    baseURL: 'https://api.groq.com/openai/v1',                 examples: ['llama-3.3-70b-versatile', 'mixtral-8x7b-32768'] },
  openrouter: { label: 'OpenRouter',  type: 'openai',    baseURL: 'https://openrouter.ai/api/v1',                   examples: ['meta-llama/llama-3.3-70b-instruct:free', 'mistralai/mistral-7b-instruct:free'] },
  together:   { label: 'Together AI', type: 'openai',    baseURL: 'https://api.together.xyz/v1',                    examples: ['meta-llama/Llama-3.3-70B-Instruct-Turbo'] },
  mistral:    { label: 'Mistral AI',  type: 'openai',    baseURL: 'https://api.mistral.ai/v1',                      examples: ['mistral-small-latest', 'open-mistral-7b'] },
  cerebras:   { label: 'Cerebras',    type: 'openai',    baseURL: 'https://api.cerebras.ai/v1',                     examples: ['llama3.1-70b', 'llama3.1-8b'] },
  sambanova:  { label: 'SambaNova',   type: 'openai',    baseURL: 'https://api.sambanova.ai/v1',                    examples: ['Meta-Llama-3.1-405B-Instruct', 'Meta-Llama-3.1-70B-Instruct'] },
  anthropic:  { label: 'Anthropic',   type: 'anthropic', baseURL: '',                                               examples: ['claude-sonnet-4-6', 'claude-haiku-4-5-20251001'] },
  google:     { label: 'Google Gemini', type: 'google',  baseURL: '',                                               examples: ['gemini-2.0-flash', 'gemini-1.5-flash'] },
  openai:     { label: 'OpenAI',      type: 'openai',    baseURL: 'https://api.openai.com/v1',                      examples: ['gpt-4o-mini', 'gpt-4o'] },
  custom:     { label: 'Custom',      type: 'openai',    baseURL: '',                                               examples: [] },
}

function ProviderFormModal({
  open, onClose, provider,
}: {
  open: boolean
  onClose: () => void
  provider?: AIProvider | null
}) {
  const qc = useQueryClient()
  const isEdit = !!provider

  const [preset, setPreset] = useState('custom')
  const [name, setName] = useState(provider?.name ?? '')
  const [provType, setProvType] = useState<'openai' | 'anthropic' | 'google'>(provider?.provider_type ?? 'openai')
  const [baseURL, setBaseURL] = useState(provider?.base_url ?? '')
  const [apiKey, setApiKey] = useState('')
  const [model, setModel] = useState(provider?.model ?? '')
  const [maxTokens, setMaxTokens] = useState(provider?.max_tokens ?? 0)
  const [showKey, setShowKey] = useState(false)
  const [testing, setTesting] = useState(false)

  const handlePreset = (p: string) => {
    setPreset(p)
    const def = PROVIDER_PRESETS[p]
    if (!def) return
    if (!name) setName(def.label)
    setProvType(def.type)
    setBaseURL(def.baseURL)
    if (def.examples.length > 0 && !model) setModel(def.examples[0])
  }

  const mutation = useMutation({
    mutationFn: (d: CreateProviderData) =>
      isEdit ? analysisApi.updateProvider(provider!.id, d) : analysisApi.createProvider(d),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai-providers'] })
      toast.success(isEdit ? 'Provider updated' : 'Provider added')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) { toast.error('Name is required'); return }
    const d: CreateProviderData = { name: name.trim(), provider_type: provType, base_url: baseURL, model, max_tokens: maxTokens }
    if (apiKey) d.api_key = apiKey
    mutation.mutate(d)
  }

  const handleTest = async () => {
    if (!isEdit) { toast.error('Save the provider first, then test'); return }
    setTesting(true)
    try {
      const res = await analysisApi.testProvider(provider!.id)
      if (res.success) toast.success('Connection successful!')
      else toast.error(res.error ?? 'Connection failed')
    } catch (e) {
      toast.error(getErrorMessage(e))
    } finally {
      setTesting(false)
    }
  }

  const selectedPreset = PROVIDER_PRESETS[preset]

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>{isEdit ? 'Edit Provider' : 'Add AI Provider'}</DialogTitle>
          <DialogDescription>Configure an AI API endpoint for forensic analysis.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            {!isEdit && (
              <div>
                <label className="label">Quick preset</label>
                <Select value={preset} onValueChange={handlePreset}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    {Object.entries(PROVIDER_PRESETS).map(([k, v]) => (
                      <SelectItem key={k} value={k}>{v.label}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
              </div>
            )}

            <div className="grid grid-cols-2 gap-3">
              <div>
                <label className="label">Display Name *</label>
                <input className="input" value={name} onChange={(e) => setName(e.target.value)} placeholder="e.g. My Groq Key" required />
              </div>
              <div>
                <label className="label">Type</label>
                <Select value={provType} onValueChange={(v) => setProvType(v as typeof provType)}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="openai">OpenAI-compatible</SelectItem>
                    <SelectItem value="anthropic">Anthropic</SelectItem>
                    <SelectItem value="google">Google Gemini</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>

            {provType === 'openai' && (
              <div>
                <label className="label">Base URL</label>
                <input className="input font-mono text-xs" value={baseURL} onChange={(e) => setBaseURL(e.target.value)} placeholder="https://api.groq.com/openai/v1" />
              </div>
            )}

            <div>
              <label className="label">Model</label>
              <input className="input font-mono text-xs" value={model} onChange={(e) => setModel(e.target.value)} placeholder="e.g. llama-3.3-70b-versatile" />
              {selectedPreset?.examples.length > 0 && (
                <div className="flex flex-wrap gap-1 mt-1">
                  {selectedPreset.examples.map((ex) => (
                    <button key={ex} type="button" onClick={() => setModel(ex)}
                      className="text-[10px] px-1.5 py-0.5 bg-gray-800 hover:bg-gray-700 text-gray-400 rounded font-mono">
                      {ex}
                    </button>
                  ))}
                </div>
              )}
            </div>

            <div>
              <label className="label">API Key {isEdit && provider?.has_key && <span className="text-gray-500">(leave blank to keep existing)</span>}</label>
              <div className="relative">
                <input
                  className="input pr-10 font-mono text-xs"
                  type={showKey ? 'text' : 'password'}
                  value={apiKey}
                  onChange={(e) => setApiKey(e.target.value)}
                  placeholder={isEdit && provider?.has_key ? '••••••••••••••' : 'sk-...'}
                />
                <button type="button" className="absolute right-3 top-1/2 -translate-y-1/2 text-gray-500 hover:text-gray-300"
                  onClick={() => setShowKey(!showKey)}>
                  {showKey ? <EyeOff className="h-4 w-4" /> : <Eye className="h-4 w-4" />}
                </button>
              </div>
            </div>

            <div>
              <label className="label">Max Tokens <span className="text-gray-500">(0 = provider default)</span></label>
              <input className="input" type="number" min="0" value={maxTokens} onChange={(e) => setMaxTokens(Number(e.target.value))} />
            </div>
          </DialogBody>
          <DialogFooter>
            <div className="flex items-center gap-2 flex-1">
              {isEdit && (
                <button type="button" onClick={handleTest} disabled={testing}
                  className="flex items-center gap-1.5 px-3 py-1.5 text-xs bg-gray-800 hover:bg-gray-700 text-gray-300 rounded border border-gray-700 disabled:opacity-50">
                  <Zap className="h-3.5 w-3.5" />
                  {testing ? 'Testing…' : 'Test'}
                </button>
              )}
            </div>
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={mutation.isPending}>
              {mutation.isPending ? 'Saving…' : isEdit ? 'Save' : 'Add Provider'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function AIProviderSettingsPage() {
  const qc = useQueryClient()
  const [addOpen, setAddOpen] = useState(false)
  const [editProvider, setEditProvider] = useState<AIProvider | null>(null)

  const { data: providers = [], isLoading } = useQuery({
    queryKey: ['ai-providers'],
    queryFn: analysisApi.listProviders,
  })

  const deleteMutation = useMutation({
    mutationFn: analysisApi.deleteProvider,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['ai-providers'] })
      toast.success('Provider removed')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const testMutation = useMutation({
    mutationFn: analysisApi.testProvider,
    onSuccess: (res) => {
      if (res.success) toast.success('Connection successful!')
      else toast.error(res.error ?? 'Connection failed')
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const TYPE_LABELS: Record<string, string> = {
    openai: 'OpenAI-compatible',
    anthropic: 'Anthropic',
    google: 'Google Gemini',
  }

  return (
    <div className="space-y-5 max-w-3xl">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">AI Providers</h1>
          <p className="text-sm text-gray-400 mt-0.5">Manage API keys for AI analysis. Keys are encrypted at rest.</p>
        </div>
        <button className="btn-primary" onClick={() => setAddOpen(true)}>
          <Plus className="h-4 w-4" /> Add Provider
        </button>
      </div>

      {isLoading ? (
        <div className="space-y-2">{[...Array(2)].map((_, i) => <div key={i} className="skeleton h-16 rounded-lg" />)}</div>
      ) : providers.length === 0 ? (
        <div className="card p-10 text-center text-gray-500">
          <p className="text-sm">No providers configured yet.</p>
          <p className="text-xs mt-1">Add a Groq or Google Gemini key to start analyzing forensic results with AI.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {providers.map((p) => (
            <div key={p.id} className="card p-4 flex items-center justify-between gap-4">
              <div className="flex items-center gap-3 min-w-0">
                <div className={`h-2 w-2 rounded-full shrink-0 ${p.is_active ? 'bg-emerald-400' : 'bg-gray-600'}`} />
                <div className="min-w-0">
                  <div className="text-sm font-medium text-gray-200 truncate">{p.name}</div>
                  <div className="text-xs text-gray-500 font-mono truncate">
                    {TYPE_LABELS[p.provider_type] ?? p.provider_type}
                    {p.model && <> · {p.model}</>}
                    {p.has_key ? <> · <span className="text-emerald-500/70">key set</span></> : <> · <span className="text-yellow-500/70">no key</span></>}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-1 shrink-0">
                <button
                  onClick={() => testMutation.mutate(p.id)}
                  disabled={testMutation.isPending}
                  className="p-1.5 text-gray-500 hover:text-blue-400 hover:bg-gray-800 rounded transition"
                  title="Test connection"
                >
                  {testMutation.isPending && testMutation.variables === p.id
                    ? <Zap className="h-4 w-4 animate-pulse" />
                    : <Zap className="h-4 w-4" />}
                </button>
                <button onClick={() => setEditProvider(p)} className="p-1.5 text-gray-500 hover:text-emerald-400 hover:bg-gray-800 rounded transition" title="Edit">
                  <Pencil className="h-4 w-4" />
                </button>
                <button
                  onClick={() => { if (confirm(`Remove "${p.name}"?`)) deleteMutation.mutate(p.id) }}
                  className="p-1.5 text-gray-500 hover:text-red-400 hover:bg-gray-800 rounded transition"
                  title="Delete"
                >
                  <Trash2 className="h-4 w-4" />
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <ProviderFormModal open={addOpen} onClose={() => setAddOpen(false)} />
      <ProviderFormModal open={!!editProvider} onClose={() => setEditProvider(null)} provider={editProvider} />
    </div>
  )
}
