import { useState, type FormEvent } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Loader2, CheckCircle, XCircle, Clock, StopCircle,
  ChevronRight, Fingerprint, Globe, Server, Mail, Phone, Search, AtSign, Hash, Wallet, User, RadioTower,
} from 'lucide-react'
import { WatchlistPanel } from './OsintWatchlist'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import {
  osintApi, COLLECTOR_LABELS,
  type OsintScan, type OsintTargetType, type DetectResult,
} from '@/api/osint'
import { casesApi } from '@/api/cases'
import { getErrorMessage } from '@/lib/utils'
import {
  Dialog, DialogContent, DialogHeader, DialogTitle,
  DialogDescription, DialogFooter, DialogBody,
} from '@/components/ui/dialog'

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
}

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

  // Cases to optionally file the investigation under (only open ones offered).
  const { data: cases = [] } = useQuery({
    queryKey: ['cases'],
    queryFn: casesApi.list,
    enabled: open,
  })

  const reset = () => {
    setTarget(''); setName(''); setAutoPivot(false); setDepth(2); setCaseId(''); setDetected(null); setDetectError('')
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

  // Detect the target type as the user finishes typing, to preview collectors.
  const runDetect = async () => {
    const t = target.trim()
    setDetected(null); setDetectError('')
    if (!t) return
    try {
      setDetected(await osintApi.detect(t))
    } catch (err) {
      setDetectError(getErrorMessage(err))
    }
  }

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!target.trim()) { toast.error('Target is required'); return }
    mutation.mutate({
      target: target.trim(),
      name: name.trim() || undefined,
      auto_pivot: autoPivot,
      max_depth: autoPivot ? depth : undefined,
      case_id: caseId || undefined,
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
            Enter an IP, domain, email, phone, username, or full name — the type is detected automatically.
          </DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div>
              <label className="label">Target</label>
              <input
                className="input w-full font-mono"
                placeholder="domain · IP · email · phone · username · full name · hash · wallet"
                value={target}
                onChange={e => setTarget(e.target.value)}
                onBlur={runDetect}
                disabled={mutation.isPending}
                autoFocus
              />
              {detected && (
                <div className="mt-2 text-xs space-y-1">
                  <p className="text-emerald-400 font-mono">
                    Detected type: <span className="uppercase font-bold">{detected.target_type}</span>
                  </p>
                  <p className="text-gray-500">
                    Collectors: {detected.collectors
                      .filter(c => !(detected.skipped_no_key ?? []).includes(c))
                      .map(c => COLLECTOR_LABELS[c] ?? c).join(' · ')}
                  </p>
                  {(detected.skipped_no_key?.length ?? 0) > 0 && (
                    <p className="text-amber-500/80">
                      Skipped (no API key): {detected.skipped_no_key!.map(c => COLLECTOR_LABELS[c] ?? c).join(' · ')}
                    </p>
                  )}
                </div>
              )}
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

type OsintTab = 'investigations' | 'watchlist'

export default function OsintPage() {
  const qc = useQueryClient()
  const navigate = useNavigate()
  const [tab, setTab] = useState<OsintTab>('investigations')
  const [newOpen, setNewOpen] = useState(false)
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
          <button className="btn-primary flex items-center gap-2" onClick={() => setNewOpen(true)}>
            <Plus className="h-4 w-4" /> New Investigation
          </button>
        )}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 border-b border-slate-800">
        <TabButton active={tab === 'investigations'} onClick={() => setTab('investigations')} icon={Fingerprint} label="Investigations" />
        <TabButton active={tab === 'watchlist'} onClick={() => setTab('watchlist')} icon={RadioTower} label="Watchlist" />
      </div>

      {tab === 'watchlist' ? (
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
