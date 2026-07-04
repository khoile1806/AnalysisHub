import { useState, useEffect, useRef, type FormEvent } from 'react'
import { useNavigate, useSearchParams } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Loader2, CheckCircle, XCircle, Clock, StopCircle,
  ChevronRight, Fingerprint, Globe, Server, Mail, Phone, Search, AtSign, Hash, Wallet, User, RadioTower,
  Image as ImageIcon, Upload, ScanSearch, Link2, Wrench, FileText, ExternalLink, Radio, ShieldAlert, ShieldCheck,
} from 'lucide-react'
import { WatchlistPanel } from './OsintWatchlist'
import { CanaryPanel } from './CanaryTokens'
import { OobPanel } from './Oob'
import { VulnScanPanel } from './VulnScan'
import { ScopePolicyPanel } from './OsintScopePolicy'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import {
  osintApi, COLLECTOR_LABELS,
  type OsintScan, type OsintTargetType, type DetectResult, type ImageExtraction,
  type EmailCandidate, type DocMetaResult, type ScopeMode,
} from '@/api/osint'
import { analysisApi } from '@/api/analysis'
import { casesApi } from '@/api/cases'
import { getErrorMessage } from '@/lib/utils'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
  DialogDescription, DialogFooter, DialogBody,
} from '@/components/ui/dialog'

// Operator override choices offered on the launch form — only options STRICTER
// than the policy's own decision, so an override can never widen the scan.
function OVERRIDE_OPTIONS(mode: ScopeMode): { val: '' | ScopeMode; label: string }[] {
  const opts: { val: '' | ScopeMode; label: string }[] = [{ val: '', label: 'Policy default' }]
  if (mode === 'all') opts.push({ val: 'passive_only', label: 'Passive only' })
  opts.push({ val: 'block', label: 'Block' })
  return opts
}

// Visual style per scope-policy decision shown on the launch form.
const SCOPE_STYLE: Record<ScopeMode, { label: string; box: string; icon: string; text: string }> = {
  all:          { label: 'Full recon',   box: 'border-emerald-900/50 bg-emerald-950/20', icon: 'text-emerald-400', text: 'text-emerald-300' },
  passive_only: { label: 'Passive only',  box: 'border-amber-900/50 bg-amber-950/20',    icon: 'text-amber-400',   text: 'text-amber-300' },
  block:        { label: 'Blocked',       box: 'border-red-900/50 bg-red-950/20',        icon: 'text-red-400',     text: 'text-red-300' },
}

const STATUS_BADGE: Record<OsintScan['status'], { label: string; cls: string }> = {
  pending: { label: 'Pending', cls: 'bg-gray-700 text-gray-300' },
  running: { label: 'Running', cls: 'bg-blue-900/40 text-blue-300 animate-pulse' },
  done:    { label: 'Done',    cls: 'bg-emerald-900/40 text-emerald-400' },
  stopped: { label: 'Stopped', cls: 'bg-yellow-900/40 text-yellow-400' },
  failed:  { label: 'Failed',  cls: 'bg-red-900/40 text-red-400' },
}

export const TYPE_ICON: Record<OsintTargetType, React.ElementType> = {
  ip:       Server,
  domain:   Globe,
  email:    Mail,
  phone:    Phone,
  username: AtSign,
  hash:     Hash,
  wallet:   Wallet,
  name:     User,
  social_profile: Link2,
}

export const TYPE_LABEL: Record<OsintTargetType, string> = {
  ip: 'IP address',
  domain: 'Domain',
  email: 'Email address',
  phone: 'Phone number',
  username: 'Username / handle',
  hash: 'File hash',
  wallet: 'Crypto wallet',
  name: 'Person name',
  social_profile: 'Social profile link',
}

// Clickable examples so the operator immediately understands what can be pasted.
const TARGET_EXAMPLES: { label: string; value: string }[] = [
  { label: 'Domain', value: 'example.com' },
  { label: 'IP', value: '8.8.8.8' },
  { label: 'Email', value: 'john.doe@example.com' },
  { label: 'Username', value: 'johndoe' },
  { label: 'Profile link', value: 'https://twitter.com/johndoe' },
  { label: 'Phone', value: '+14155552671' },
]

function StatusIcon({ status }: { status: OsintScan['status'] }) {
  if (status === 'running') return <Loader2 className="h-4 w-4 animate-spin text-blue-400" />
  if (status === 'done')    return <CheckCircle className="h-4 w-4 text-emerald-400" />
  if (status === 'failed')  return <XCircle className="h-4 w-4 text-red-400" />
  if (status === 'stopped') return <StopCircle className="h-4 w-4 text-yellow-400" />
  return <Clock className="h-4 w-4 text-gray-500" />
}

// ---- New Investigation Modal -----------------------------------------------

function NewScanModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [target, setTarget] = useState('')
  const [name, setName] = useState('')
  const [autoPivot, setAutoPivot] = useState(false)
  const [depth, setDepth] = useState(2)
  const [caseId, setCaseId] = useState('')
  const [detected, setDetected] = useState<DetectResult | null>(null)
  const [detectError, setDetectError] = useState('')
  const [scopeOverride, setScopeOverride] = useState<'' | ScopeMode>('')

  // Cases to optionally file the investigation under (only open ones offered).
  const { data: cases = [] } = useQuery({
    queryKey: ['cases'],
    queryFn: casesApi.list,
    enabled: open,
  })

  const reset = () => {
    setTarget(''); setName(''); setAutoPivot(false); setDepth(2); setCaseId(''); setDetected(null); setDetectError(''); setScopeOverride('')
  }

  const mutation = useMutation({
    mutationFn: osintApi.create,
    onSuccess: (scan) => {
      qc.invalidateQueries({ queryKey: ['osint-scans'] })
      toast.success('Investigation started')
      reset()
      onClose()
      navigate(`/osint/${scan.id}`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const [detecting, setDetecting] = useState(false)
  const detectSeq = useRef(0)

  // Live (debounced) type detection as the user types — previews the detected
  // type + which collectors will run, so the input is no longer a blind text box.
  useEffect(() => {
    const t = target.trim()
    setDetected(null); setDetectError(''); setScopeOverride('')
    if (!t) { setDetecting(false); return }
    setDetecting(true)
    const seq = ++detectSeq.current
    const timer = setTimeout(async () => {
      try {
        const res = await osintApi.detect(t)
        if (seq === detectSeq.current) setDetected(res)
      } catch (err) {
        if (seq === detectSeq.current) setDetectError(getErrorMessage(err))
      } finally {
        if (seq === detectSeq.current) setDetecting(false)
      }
    }, 450)
    return () => clearTimeout(timer)
  }, [target])

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!target.trim()) { toast.error('Target is required'); return }
    mutation.mutate({
      target: target.trim(),
      name: name.trim() || undefined,
      auto_pivot: autoPivot,
      max_depth: autoPivot ? depth : undefined,
      case_id: caseId || undefined,
      scope_override: scopeOverride || undefined,
    })
  }

  const handleClose = () => {
    if (mutation.isPending) return
    reset()
    onClose()
  }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>New OSINT Investigation</DialogTitle>
          <DialogDescription>
            Enter an IP, domain, email, phone, username, full name, or a social-media profile link — the type is detected automatically.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div>
              <label className="label">Target</label>
              <div className="relative">
                <ScanSearch className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
                <input
                  className="input w-full font-mono pl-9 pr-9"
                  placeholder="domain · IP · email · phone · username · profile link · name · hash · wallet"
                  value={target}
                  onChange={e => setTarget(e.target.value)}
                  disabled={mutation.isPending}
                  autoFocus
                />
                {detecting && <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 animate-spin" />}
                {!detecting && detected && (() => {
                  const Icon = TYPE_ICON[detected.target_type as OsintTargetType] ?? Fingerprint
                  return <Icon className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 text-emerald-400" />
                })()}
              </div>

              {/* Example chips — always visible so the box is self-explanatory;
                  click to fill the field with a sample of each supported type. */}
              <div className="mt-2 flex flex-wrap items-center gap-1.5">
                <span className="text-[10px] text-gray-600 mr-0.5">Examples:</span>
                {TARGET_EXAMPLES.map(ex => (
                  <button
                    key={ex.value} type="button"
                    title={ex.value}
                    onClick={() => setTarget(ex.value)}
                    className="text-[10px] font-mono px-2 py-0.5 rounded-full border border-slate-700 text-gray-400 hover:border-emerald-700 hover:text-emerald-300 transition-colors"
                  >
                    {ex.label}
                  </button>
                ))}
              </div>

              {detected && (() => {
                const policy = detected.policy ?? null
                const blockedByPolicy = new Set(policy?.blocked_collectors ?? [])
                const noKey = new Set(detected.skipped_no_key ?? [])
                const willRun = detected.collectors.filter(c => !noKey.has(c) && !blockedByPolicy.has(c))
                return (
                <div className="mt-2 rounded-lg border border-emerald-900/40 bg-emerald-950/20 p-2.5 space-y-1.5">
                  <div className="flex items-center gap-2">
                    {(() => {
                      const Icon = TYPE_ICON[detected.target_type as OsintTargetType] ?? Fingerprint
                      return <Icon className="h-4 w-4 text-emerald-400 shrink-0" />
                    })()}
                    <span className="text-xs font-semibold text-emerald-300">
                      {TYPE_LABEL[detected.target_type as OsintTargetType] ?? detected.target_type.replace(/_/g, ' ')}
                    </span>
                    <span className="ml-auto text-[10px] font-mono text-gray-500">
                      {willRun.length} collectors
                    </span>
                  </div>
                  <div className="flex flex-wrap gap-1">
                    {willRun.map(c => (
                      <span key={c} className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-gray-800/70 text-gray-300 border border-slate-700">
                        {COLLECTOR_LABELS[c] ?? c}
                      </span>
                    ))}
                  </div>
                  {(detected.skipped_no_key?.length ?? 0) > 0 && (
                    <p className="text-[10px] text-amber-500/80">
                      Skipped (no API key): {detected.skipped_no_key!.map(c => COLLECTOR_LABELS[c] ?? c).join(' · ')}
                    </p>
                  )}

                  {/* Admin scope-policy decision: whether active (target-touching)
                      collectors may run for this target. */}
                  {policy && policy.enforced && (
                    <div className={`mt-1 rounded-md border p-2 ${SCOPE_STYLE[policy.mode].box}`}>
                      <div className="flex items-center gap-1.5">
                        <ShieldAlert className={`h-3.5 w-3.5 shrink-0 ${SCOPE_STYLE[policy.mode].icon}`} />
                        <span className={`text-[11px] font-semibold ${SCOPE_STYLE[policy.mode].text}`}>
                          Scope policy: {SCOPE_STYLE[policy.mode].label}
                        </span>
                        <span className="ml-auto text-[9px] uppercase tracking-wide font-mono text-gray-500">
                          {policy.scope} · {policy.anonymized ? 'via proxy' : 'direct'}
                        </span>
                      </div>
                      <p className="mt-1 text-[10px] text-gray-400">{policy.reason}</p>
                      {policy.matched_rule && (
                        <p className="text-[9px] text-gray-600">rule: {policy.matched_rule}</p>
                      )}
                      {blockedByPolicy.size > 0 && (
                        <p className="mt-1 text-[10px] text-amber-500/80">
                          Blocked by policy: {[...blockedByPolicy].map(c => COLLECTOR_LABELS[c] ?? c).join(' · ')}
                        </p>
                      )}
                      {detected.allow_override && policy.mode !== 'block' && (
                        <div className="mt-1.5 flex items-center gap-1.5">
                          <span className="text-[10px] text-gray-500">Tighten:</span>
                          {OVERRIDE_OPTIONS(policy.mode).map(opt => (
                            <button
                              key={opt.val || 'default'} type="button"
                              onClick={() => setScopeOverride(opt.val)}
                              className={`text-[10px] px-1.5 py-0.5 rounded border transition-colors ${
                                scopeOverride === opt.val
                                  ? 'bg-indigo-600 border-indigo-500 text-white'
                                  : 'border-slate-700 text-gray-400 hover:text-gray-200'
                              }`}
                            >{opt.label}</button>
                          ))}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                )
              })()}
              {detectError && (
                <p className="mt-2 text-xs text-red-400">{detectError}</p>
              )}
            </div>
            <div>
              <label className="label">Name (optional)</label>
              <input
                className="input w-full"
                placeholder="defaults to the target"
                value={name}
                onChange={e => setName(e.target.value)}
                disabled={mutation.isPending}
              />
            </div>
            <div>
              <label className="label">Case (optional)</label>
              <select
                className="input w-full"
                value={caseId}
                onChange={e => setCaseId(e.target.value)}
                disabled={mutation.isPending}
              >
                <option value="">— not filed under a case —</option>
                {cases.map(cs => (
                  <option key={cs.id} value={cs.id}>{cs.name}</option>
                ))}
              </select>
              <p className="mt-1 text-xs text-gray-500">
                Files this investigation (and every auto-pivot child) under a case so the whole graph stays grouped.
              </p>
            </div>
            <div className="rounded-lg border border-gray-700 bg-gray-900/40 p-3 space-y-2">
              <label className="flex items-center gap-2 cursor-pointer">
                <input
                  type="checkbox"
                  className="accent-emerald-500"
                  checked={autoPivot}
                  onChange={e => setAutoPivot(e.target.checked)}
                  disabled={mutation.isPending}
                />
                <span className="text-sm text-gray-200">Auto-pivot (recursive trace)</span>
              </label>
              <p className="text-xs text-gray-500">
                Automatically investigate every related entity discovered (related domains, IPs, accounts…) to build an investigation graph.
              </p>
              {autoPivot && (
                <div className="flex items-center gap-2 text-xs text-gray-400">
                  <span>Max depth:</span>
                  <select
                    value={depth}
                    onChange={e => setDepth(Number(e.target.value))}
                    className="bg-gray-800 border border-gray-700 rounded px-2 py-1 text-gray-200"
                    disabled={mutation.isPending}
                  >
                    <option value={1}>1</option>
                    <option value={2}>2</option>
                    <option value={3}>3</option>
                    <option value={4}>4</option>
                  </select>
                  <span className="text-gray-600">(higher = wider, slower)</span>
                </div>
              )}
            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={handleClose} disabled={mutation.isPending}>
              Cancel
            </button>
            <button type="submit" className="btn-primary" disabled={mutation.isPending}>
              {mutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Start Investigation'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

// ---- OCR → Pivot Modal (extract IOCs from an image) ------------------------

function ImageExtractModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const [file, setFile] = useState<File | null>(null)
  const [providerId, setProviderId] = useState('')
  const [result, setResult] = useState<ImageExtraction | null>(null)
  const [started, setStarted] = useState<Record<string, boolean>>({})

  // Vision extraction needs an Anthropic (Claude) provider; only those are offered.
  const { data: providers = [] } = useQuery({
    queryKey: ['ai-providers'],
    queryFn: analysisApi.listProviders,
    enabled: open,
  })
  const claude = providers.filter(p => p.is_active && p.provider_type === 'anthropic')

  const reset = () => { setFile(null); setProviderId(''); setResult(null); setStarted({}) }

  const extractMut = useMutation({
    mutationFn: () => osintApi.extractImage(file!, providerId),
    onSuccess: (d) => {
      setResult(d)
      if (d.candidates.length === 0) toast('No scannable indicators found in the image', { icon: '🔍' })
      else toast.success(`${d.candidates.length} indicator(s) extracted`)
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const scanMut = useMutation({
    mutationFn: (target: string) => osintApi.create({ target }),
    onSuccess: (scan) => { toast.success('Investigation started'); onClose(); reset(); navigate(`/osint/${scan.id}`) },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleClose = () => { if (extractMut.isPending) return; reset(); onClose() }

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>Extract indicators from an image</DialogTitle>
          <DialogDescription>
            OCR a ransom note, phishing screenshot or chat capture with a Claude vision model, then launch a footprinting scan against any wallet, email, domain, IP or hash it contains.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div>
            <label className="label">Image</label>
            <label className="flex items-center gap-3 cursor-pointer rounded-lg border border-dashed border-gray-700 bg-gray-900/40 p-4 hover:border-emerald-700 transition-colors">
              <Upload className="h-5 w-5 text-gray-500" />
              <span className="text-sm text-gray-300 truncate">
                {file ? file.name : 'Choose a PNG, JPEG, GIF or WebP (≤ 5 MB)'}
              </span>
              <input
                type="file"
                accept="image/png,image/jpeg,image/gif,image/webp"
                className="hidden"
                onChange={(e) => { setFile(e.target.files?.[0] ?? null); setResult(null) }}
                disabled={extractMut.isPending}
              />
            </label>
          </div>
          <div>
            <label className="label">Claude vision provider</label>
            {claude.length === 0 ? (
              <a href="/ai-providers" className="text-xs text-yellow-400 underline">Configure an Anthropic (Claude) AI provider</a>
            ) : (
              <select
                className="input w-full"
                value={providerId}
                onChange={(e) => setProviderId(e.target.value)}
                disabled={extractMut.isPending}
              >
                <option value="">Select provider…</option>
                {claude.map(p => <option key={p.id} value={p.id}>{p.name}</option>)}
              </select>
            )}
          </div>

          {result && (
            <div className="space-y-3">
              <div>
                <p className="label">Extracted indicators</p>
                {result.candidates.length === 0 ? (
                  <p className="text-xs text-gray-500">No scannable indicators detected.</p>
                ) : (
                  <div className="space-y-1.5">
                    {result.candidates.map((cand) => {
                      const Icon = TYPE_ICON[cand.type] ?? Fingerprint
                      return (
                        <div key={cand.value} className="flex items-center gap-2 rounded border border-slate-700 bg-gray-900/40 px-3 py-2">
                          <Icon className="h-3.5 w-3.5 text-gray-500 shrink-0" />
                          <span className="font-mono text-xs text-emerald-400 truncate flex-1">{cand.value}</span>
                          <span className="text-[10px] font-mono text-gray-600 uppercase">{cand.type}</span>
                          <button
                            className="btn-primary text-xs px-2 py-1 disabled:opacity-50"
                            disabled={scanMut.isPending || started[cand.value]}
                            onClick={() => { setStarted(s => ({ ...s, [cand.value]: true })); scanMut.mutate(cand.value) }}
                          >
                            <Search className="h-3 w-3" /> Scan
                          </button>
                        </div>
                      )
                    })}
                  </div>
                )}
              </div>
              {result.ocr_text && (
                <details className="text-xs">
                  <summary className="cursor-pointer text-gray-500 hover:text-gray-300">OCR transcript</summary>
                  <pre className="mt-2 whitespace-pre-wrap break-words rounded bg-gray-900/60 p-3 text-gray-400 max-h-48 overflow-auto">{result.ocr_text}</pre>
                </details>
              )}
            </div>
          )}
        </DialogBody>
        <DialogFooter>
          <button type="button" className="btn-secondary" onClick={handleClose} disabled={extractMut.isPending}>
            Close
          </button>
          <button
            type="button"
            className="btn-primary flex items-center gap-2"
            disabled={!file || !providerId || extractMut.isPending}
            onClick={() => extractMut.mutate()}
          >
            {extractMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ScanSearch className="h-4 w-4" />}
            {extractMut.isPending ? 'Extracting…' : 'Extract'}
          </button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- OSINT Tools Modal (email finder · doc metadata · reverse image) --------

type ToolTab = 'email' | 'doc' | 'image'

const EMAIL_STATUS_CLS: Record<string, string> = {
  deliverable: 'text-emerald-300 bg-emerald-900/30 border-emerald-800/40',
  catch_all:   'text-yellow-300 bg-yellow-900/30 border-yellow-800/40',
  rejected:    'text-gray-500 bg-gray-800 border-slate-700',
  unverified:  'text-gray-400 bg-gray-800 border-slate-700',
}

function ToolsModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const navigate = useNavigate()
  const [tab, setTab] = useState<ToolTab>('email')

  // Email finder
  const [emName, setEmName] = useState('')
  const [emDomain, setEmDomain] = useState('')
  const [emResult, setEmResult] = useState<EmailCandidate[] | null>(null)
  const emailMut = useMutation({
    mutationFn: () => osintApi.emailPermute(emName.trim(), emDomain.trim()),
    onSuccess: (d) => { setEmResult(d.candidates); toast.success(`${d.candidates.length} candidate(s)`) },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  // Document metadata
  const [docFile, setDocFile] = useState<File | null>(null)
  const [docResult, setDocResult] = useState<DocMetaResult | null>(null)
  const docMut = useMutation({
    mutationFn: () => osintApi.extractDocMeta(docFile!),
    onSuccess: (d) => { setDocResult(d); d.metadata.found ? toast.success('Metadata extracted') : toast('No author metadata found', { icon: '🔍' }) },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  // Reverse image (URL or upload)
  const [imgURL, setImgURL] = useState('')
  const [imgFile, setImgFile] = useState<File | null>(null)
  const [imgResult, setImgResult] = useState<import('@/api/osint').ReverseImageResult | null>(null)
  const imgMut = useMutation({
    mutationFn: () => imgFile ? osintApi.reverseImageUpload(imgFile) : osintApi.reverseImage(imgURL.trim()),
    onSuccess: (d) => setImgResult(d),
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const scanMut = useMutation({
    mutationFn: (target: string) => osintApi.create({ target }),
    onSuccess: (scan) => { toast.success('Investigation started'); onClose(); navigate(`/osint/${scan.id}`) },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const reset = () => {
    setEmName(''); setEmDomain(''); setEmResult(null)
    setDocFile(null); setDocResult(null); setImgURL(''); setImgFile(null); setImgResult(null)
  }
  const handleClose = () => { reset(); onClose() }

  const busy = emailMut.isPending || docMut.isPending || imgMut.isPending

  return (
    <Dialog open={open} onOpenChange={(o) => !o && handleClose()}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle>OSINT Tools</DialogTitle>
          <DialogDescription>Standalone lookups: find a work e-mail, read a document's author metadata, or reverse-search an image.</DialogDescription>
        </DialogHeader>

        <div className="flex gap-1 border-b border-slate-800 px-1">
          {([['email', 'Email Finder', Mail], ['doc', 'Doc Metadata', FileText], ['image', 'Reverse Image', ImageIcon]] as const).map(([k, label, Icon]) => (
            <button key={k} onClick={() => setTab(k)}
              className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium border-b-2 -mb-px transition-colors ${
                tab === k ? 'border-emerald-500 text-emerald-400' : 'border-transparent text-gray-500 hover:text-gray-300'}`}>
              <Icon className="h-3.5 w-3.5" /> {label}
            </button>
          ))}
        </div>

        <DialogBody className="space-y-4">
          {tab === 'email' && (
            <>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="label">Full name</label>
                  <input className="input w-full" placeholder="John Doe" value={emName} onChange={e => setEmName(e.target.value)} />
                </div>
                <div>
                  <label className="label">Company domain</label>
                  <input className="input w-full font-mono" placeholder="acme.com" value={emDomain} onChange={e => setEmDomain(e.target.value)} />
                </div>
              </div>
              <button className="btn-primary w-full flex items-center justify-center gap-2"
                disabled={!emName.trim() || !emDomain.trim() || emailMut.isPending}
                onClick={() => { setEmResult(null); emailMut.mutate() }}>
                {emailMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
                {emailMut.isPending ? 'Validating mailboxes…' : 'Find e-mail'}
              </button>
              {emResult && (
                <div className="space-y-1.5">
                  {emResult.map((c) => (
                    <div key={c.email} className="flex items-center gap-2 rounded border border-slate-700 bg-gray-900/40 px-3 py-2">
                      <span className="font-mono text-xs text-gray-200 truncate flex-1">{c.email}</span>
                      <span className="text-[10px] text-gray-600 font-mono">{c.pattern}</span>
                      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${EMAIL_STATUS_CLS[c.status] ?? EMAIL_STATUS_CLS.unverified}`}>{c.status}</span>
                      <button className="btn-secondary text-xs px-2 py-1" disabled={scanMut.isPending} onClick={() => scanMut.mutate(c.email)}>
                        <Search className="h-3 w-3" /> Scan
                      </button>
                    </div>
                  ))}
                  <p className="text-[10px] text-gray-600">SMTP probing needs port 25 outbound; blocked networks return “unverified”.</p>
                </div>
              )}
            </>
          )}

          {tab === 'doc' && (
            <>
              <label className="flex items-center gap-3 cursor-pointer rounded-lg border border-dashed border-gray-700 bg-gray-900/40 p-4 hover:border-emerald-700 transition-colors">
                <Upload className="h-5 w-5 text-gray-500" />
                <span className="text-sm text-gray-300 truncate">{docFile ? docFile.name : 'Choose a DOCX, XLSX, PPTX or PDF (≤ 30 MB)'}</span>
                <input type="file" accept=".docx,.xlsx,.pptx,.pdf" className="hidden"
                  onChange={(e) => { setDocFile(e.target.files?.[0] ?? null); setDocResult(null) }} />
              </label>
              <button className="btn-primary w-full flex items-center justify-center gap-2"
                disabled={!docFile || docMut.isPending} onClick={() => docMut.mutate()}>
                {docMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <FileText className="h-4 w-4" />}
                {docMut.isPending ? 'Reading…' : 'Extract metadata'}
              </button>
              {docResult && (
                <div className="space-y-2">
                  <div className="rounded border border-slate-700 bg-gray-900/40 p-3 text-xs space-y-1">
                    {([['Format', docResult.metadata.format], ['Author', docResult.metadata.creator], ['Last modified by', docResult.metadata.last_modified_by],
                       ['Company', docResult.metadata.company], ['Application', docResult.metadata.application], ['Title', docResult.metadata.title],
                       ['Created', docResult.metadata.created], ['Modified', docResult.metadata.modified]] as const)
                      .filter(([, v]) => v).map(([k, v]) => (
                        <div key={k} className="flex gap-2"><span className="text-gray-600 w-28 shrink-0">{k}</span><span className="text-gray-200 break-all">{v}</span></div>
                      ))}
                    {!docResult.metadata.found && <p className="text-gray-500">No author metadata (it may have been stripped).</p>}
                  </div>
                  {docResult.candidates.length > 0 && (
                    <div className="space-y-1.5">
                      <p className="label">Author candidates</p>
                      {docResult.candidates.map((cand) => (
                        <div key={cand.value} className="flex items-center gap-2 rounded border border-slate-700 bg-gray-900/40 px-3 py-2">
                          <span className="font-mono text-xs text-emerald-400 truncate flex-1">{cand.value}</span>
                          <span className="text-[10px] text-gray-600 uppercase">{cand.type}</span>
                          <button className="btn-secondary text-xs px-2 py-1" disabled={scanMut.isPending} onClick={() => scanMut.mutate(cand.value)}>
                            <Search className="h-3 w-3" /> Scan
                          </button>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </>
          )}

          {tab === 'image' && (
            <>
              <div>
                <label className="label">Public image URL</label>
                <input className="input w-full font-mono" placeholder="https://example.com/avatar.jpg"
                  value={imgURL} onChange={e => { setImgURL(e.target.value); setImgFile(null) }} disabled={!!imgFile} />
              </div>
              <div className="flex items-center gap-2 text-[10px] text-gray-600"><span className="flex-1 h-px bg-slate-800" />OR upload a local image<span className="flex-1 h-px bg-slate-800" /></div>
              <label className="flex items-center gap-3 cursor-pointer rounded-lg border border-dashed border-gray-700 bg-gray-900/40 p-3 hover:border-emerald-700 transition-colors">
                <Upload className="h-4 w-4 text-gray-500" />
                <span className="text-xs text-gray-300 truncate">{imgFile ? imgFile.name : 'Choose an image (fingerprint + face-search engines)'}</span>
                <input type="file" accept="image/*" className="hidden"
                  onChange={(e) => { setImgFile(e.target.files?.[0] ?? null); setImgURL(''); setImgResult(null) }} />
              </label>
              <button className="btn-primary w-full flex items-center justify-center gap-2"
                disabled={(!imgURL.trim() && !imgFile) || imgMut.isPending} onClick={() => { setImgResult(null); imgMut.mutate() }}>
                {imgMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <ImageIcon className="h-4 w-4" />}
                {imgFile ? 'Fingerprint + face-search links' : 'Build reverse-search links'}
              </button>
              {imgResult && (
                <div className="space-y-1.5">
                  {imgResult.fingerprint && (
                    <p className="text-[11px] text-gray-400">Fingerprint: <span className="font-mono text-emerald-400">{imgResult.fingerprint}</span></p>
                  )}
                  {[...(imgResult.engines ?? []), ...(imgResult.face_engines ?? [])].map((e) => (
                    <a key={e.name} href={e.url} target="_blank" rel="noopener noreferrer"
                      className="flex items-center gap-2 rounded border border-slate-700 bg-gray-900/40 px-3 py-2 hover:border-emerald-700 transition-colors">
                      <ExternalLink className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                      <span className="text-xs text-gray-200">{e.name}</span>
                    </a>
                  ))}
                  {imgResult.note && <p className="text-[10px] text-gray-600">{imgResult.note}</p>}
                </div>
              )}
            </>
          )}
        </DialogBody>
        <DialogFooter>
          <button type="button" className="btn-secondary" onClick={handleClose} disabled={busy}>Close</button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  )
}

// ---- Page -------------------------------------------------------------------

function TabButton({ active, onClick, icon: Icon, label }: {
  active: boolean; onClick: () => void; icon: React.ElementType; label: string
}) {
  return (
    <button
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 text-sm font-medium border-b-2 -mb-px transition-colors ${
        active
          ? 'border-emerald-500 text-emerald-400'
          : 'border-transparent text-gray-500 hover:text-gray-300'
      }`}
    >
      <Icon className="h-4 w-4" /> {label}
    </button>
  )
}

type OsintTab = 'investigations' | 'watchlist' | 'canary' | 'oob' | 'vulnscan' | 'scope'

export default function OsintPage() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [searchParams] = useSearchParams()
  const initialTab = (searchParams.get('tab') as OsintTab) || 'investigations'
  const [tab, setTab] = useState<OsintTab>(initialTab)
  const [newOpen, setNewOpen] = useState(false)
  const [imageOpen, setImageOpen] = useState(false)
  const [toolsOpen, setToolsOpen] = useState(false)
  const [deleting, setDeleting] = useState<string | null>(null)

  const { data: scans = [], isLoading } = useQuery({
    queryKey: ['osint-scans'],
    queryFn: osintApi.list,
    refetchInterval: 5000,
  })

  const deleteMutation = useMutation({
    mutationFn: osintApi.delete,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['osint-scans'] })
      toast.success('Investigation deleted')
      setDeleting(null)
    },
    onError: (err) => { toast.error(getErrorMessage(err)); setDeleting(null) },
  })

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-bold text-gray-100">OSINT</h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Passive entity intelligence + continuous monitoring — traces an IP, domain, email, phone or name left across the internet.
          </p>
        </div>
        {tab === 'investigations' && (
          <div className="flex items-center gap-2">
            <button className="btn-secondary flex items-center gap-2" onClick={() => setToolsOpen(true)} title="Email finder · document metadata · reverse image search">
              <Wrench className="h-4 w-4" /> Tools
            </button>
            <button className="btn-secondary flex items-center gap-2" onClick={() => setImageOpen(true)} title="Extract IOCs from an image (ransom note, screenshot) via OCR">
              <ImageIcon className="h-4 w-4" /> From Image
            </button>
            <button className="btn-primary flex items-center gap-2" onClick={() => setNewOpen(true)}>
              <Plus className="h-4 w-4" /> New Investigation
            </button>
          </div>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-800">
        <TabButton active={tab === 'investigations'} onClick={() => setTab('investigations')} icon={Fingerprint} label="Investigations" />
        <TabButton active={tab === 'watchlist'} onClick={() => setTab('watchlist')} icon={RadioTower} label="Watchlist" />
        <TabButton active={tab === 'canary'} onClick={() => setTab('canary')} icon={Link2} label="Canary Tokens" />
        <TabButton active={tab === 'oob'} onClick={() => setTab('oob')} icon={Radio} label="Catch (OOB)" />
        <TabButton active={tab === 'vulnscan'} onClick={() => setTab('vulnscan')} icon={ShieldAlert} label="Vuln Scan" />
        <TabButton active={tab === 'scope'} onClick={() => setTab('scope')} icon={ShieldCheck} label="Scope Policy" />
      </div>

      {tab === 'scope' ? (
        <ScopePolicyPanel />
      ) : tab === 'vulnscan' ? (
        <VulnScanPanel />
      ) : tab === 'oob' ? (
        <OobPanel />
      ) : tab === 'canary' ? (
        <CanaryPanel />
      ) : tab === 'watchlist' ? (
        <WatchlistPanel />
      ) : (
      <>
      {/* List */}
      {isLoading ? (
        <div className="flex items-center justify-center py-20 text-gray-600">
          <Loader2 className="h-6 w-6 animate-spin" />
        </div>
      ) : scans.length === 0 ? (
        <div className="card flex flex-col items-center justify-center py-20 text-center gap-3">
          <Fingerprint className="h-10 w-10 text-gray-700" />
          <p className="text-gray-500 text-sm">No investigations yet</p>
          <button className="btn-primary" onClick={() => setNewOpen(true)}>
            <Search className="h-4 w-4" /> Start your first investigation
          </button>
        </div>
      ) : (
        <div className="space-y-2">
          {scans.map(scan => {
            const badge = STATUS_BADGE[scan.status]
            const Icon = TYPE_ICON[scan.target_type] ?? Fingerprint
            return (
              <div
                key={scan.id}
                className="card flex items-center gap-4 cursor-pointer hover:border-slate-700 transition-colors p-4"
                onClick={() => navigate(`/osint/${scan.id}`)}
              >
                <StatusIcon status={scan.status} />
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2">
                    <span className="font-medium text-gray-100 truncate">{scan.name}</span>
                    <span className={`text-[10px] px-2 py-0.5 rounded-full font-mono uppercase ${badge.cls}`}>
                      {badge.label}
                    </span>
                  </div>
                  <div className="flex items-center gap-2 mt-0.5">
                    <Icon className="h-3.5 w-3.5 text-gray-600" />
                    <span className="font-mono text-xs text-emerald-400">{scan.target}</span>
                    <span className="text-[10px] font-mono text-gray-600 uppercase">{scan.target_type}</span>
                  </div>
                </div>
                <div className="text-xs text-gray-600 shrink-0">
                  {formatDistanceToNow(new Date(scan.created_at), { addSuffix: true })}
                </div>
                <button
                  className="btn-danger p-1.5 opacity-60 hover:opacity-100"
                  onClick={e => { e.stopPropagation(); setDeleting(scan.id) }}
                >
                  <Trash2 className="h-3.5 w-3.5" />
                </button>
                <ChevronRight className="h-4 w-4 text-gray-600" />
              </div>
            )
          })}
        </div>
      )}

      <NewScanModal open={newOpen} onClose={() => setNewOpen(false)} />
      <ImageExtractModal open={imageOpen} onClose={() => setImageOpen(false)} />
      <ToolsModal open={toolsOpen} onClose={() => setToolsOpen(false)} />

      <Dialog open={!!deleting} onOpenChange={o => !o && setDeleting(null)}>
        <DialogContent className="max-w-sm">
          <DialogHeader>
            <DialogTitle>Delete investigation?</DialogTitle>
            <DialogDescription>This permanently removes the investigation and all findings.</DialogDescription>
          </DialogHeader>
          <DialogFooter>
            <button className="btn-secondary" onClick={() => setDeleting(null)}>Cancel</button>
            <button
              className="btn-danger"
              disabled={deleteMutation.isPending}
              onClick={() => deleting && deleteMutation.mutate(deleting)}
            >
              {deleteMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : 'Delete'}
            </button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
      </>
      )}
    </div>
  )
}
