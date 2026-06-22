import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Loader2, Play, Pause, RadioTower, Bell, ChevronDown, ChevronRight, Eye,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { osintApi, type OsintWatch, type OsintWatchAlert } from '@/api/osint'
import { getErrorMessage } from '@/lib/utils'

const INTERVALS = [
  { v: 60, label: 'Hourly' },
  { v: 360, label: 'Every 6h' },
  { v: 720, label: 'Every 12h' },
  { v: 1440, label: 'Daily' },
  { v: 10080, label: 'Weekly' },
]

const SEV_COLOR: Record<string, string> = {
  critical: 'text-red-400',
  high: 'text-orange-400',
  medium: 'text-amber-400',
}

function CreateWatch() {
  const qc = useQueryClient()
  const [target, setTarget] = useState('')
  const [interval, setInterval] = useState(1440)
  const [autoPivot, setAutoPivot] = useState(false)

  const m = useMutation({
    mutationFn: osintApi.createWatch,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['osint-watches'] })
      toast.success('Watch created — baseline scan started')
      setTarget('')
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <div className="card p-4 flex flex-col sm:flex-row sm:items-end gap-3">
      <div className="flex-1">
        <label className="label">Target to monitor</label>
        <input
          className="input w-full font-mono"
          placeholder="domain · IP · email · username · full name"
          value={target}
          onChange={e => setTarget(e.target.value)}
        />
      </div>
      <div>
        <label className="label">Interval</label>
        <select className="input" value={interval} onChange={e => setInterval(Number(e.target.value))}>
          {INTERVALS.map(i => <option key={i.v} value={i.v}>{i.label}</option>)}
        </select>
      </div>
      <label className="flex items-center gap-2 text-sm text-gray-300 pb-2 cursor-pointer">
        <input type="checkbox" className="accent-emerald-500" checked={autoPivot} onChange={e => setAutoPivot(e.target.checked)} />
        Auto-pivot
      </label>
      <button
        className="btn-primary flex items-center gap-2"
        disabled={m.isPending || !target.trim()}
        onClick={() => m.mutate({ target: target.trim(), interval_minutes: interval, auto_pivot: autoPivot })}
      >
        {m.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add Watch
      </button>
    </div>
  )
}

function AlertList({ watchId }: { watchId: string }) {
  const navigate = useNavigate()
  const { data: alerts = [], isLoading } = useQuery({
    queryKey: ['osint-watch-alerts', watchId],
    queryFn: () => osintApi.watchAlerts(watchId),
  })
  if (isLoading) return <div className="p-3 text-gray-600"><Loader2 className="h-4 w-4 animate-spin" /></div>
  if (alerts.length === 0) return <div className="p-3 text-xs text-gray-500">No new-trace alerts yet.</div>
  return (
    <div className="divide-y divide-slate-800">
      {alerts.map((a: OsintWatchAlert) => (
        <button
          key={a.id}
          onClick={() => navigate(`/osint/${a.scan_id}`)}
          className="w-full text-left flex items-start gap-3 p-2.5 hover:bg-slate-900/40"
        >
          <span className={`text-[10px] font-mono uppercase mt-0.5 ${SEV_COLOR[a.severity] ?? 'text-gray-500'}`}>{a.severity}</span>
          <div className="min-w-0">
            <div className="text-sm text-gray-200">{a.title}</div>
            <div className="font-mono text-xs text-emerald-400 break-all">{a.value}</div>
            <div className="text-[10px] text-gray-600">{a.source} · {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}</div>
          </div>
        </button>
      ))}
    </div>
  )
}

function WatchRow({ w }: { w: OsintWatch }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)
  const refresh = () => qc.invalidateQueries({ queryKey: ['osint-watches'] })

  const toggle = useMutation({
    mutationFn: () => osintApi.updateWatch(w.id, { enabled: !w.enabled }),
    onSuccess: refresh,
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const run = useMutation({
    mutationFn: () => osintApi.runWatch(w.id),
    onSuccess: () => toast.success('Re-scan started'),
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const del = useMutation({
    mutationFn: () => osintApi.deleteWatch(w.id),
    onSuccess: () => { toast.success('Watch deleted'); refresh() },
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const seen = useMutation({
    mutationFn: () => osintApi.markAlertsSeen(w.id),
    onSuccess: refresh,
  })

  return (
    <div className="card overflow-hidden">
      <div className="flex items-center gap-3 p-4">
        <button onClick={() => { setOpen(o => !o); if (!open && w.alert_count > 0) seen.mutate() }} className="text-gray-500">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <RadioTower className={`h-4 w-4 ${w.enabled ? 'text-emerald-400' : 'text-gray-600'}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-100 truncate">{w.name}</span>
            <span className="text-[10px] font-mono text-gray-600 uppercase">{w.target_type}</span>
            {w.alert_count > 0 && (
              <span className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded-full bg-red-900/40 text-red-300">
                <Bell className="h-3 w-3" /> {w.alert_count} new
              </span>
            )}
          </div>
          <div className="font-mono text-xs text-emerald-400 truncate">{w.target}</div>
          <div className="text-[10px] text-gray-600">
            every {w.interval_minutes}m · {w.last_run_at ? `last ${formatDistanceToNow(new Date(w.last_run_at), { addSuffix: true })}` : 'pending first run'}
          </div>
        </div>
        <button className="btn-secondary p-1.5" title="Run now" onClick={() => run.mutate()} disabled={run.isPending}>
          <Eye className="h-3.5 w-3.5" />
        </button>
        <button className="btn-secondary p-1.5" title={w.enabled ? 'Pause' : 'Resume'} onClick={() => toggle.mutate()} disabled={toggle.isPending}>
          {w.enabled ? <Pause className="h-3.5 w-3.5" /> : <Play className="h-3.5 w-3.5" />}
        </button>
        <button className="btn-danger p-1.5 opacity-60 hover:opacity-100" title="Delete" onClick={() => del.mutate()} disabled={del.isPending}>
          <Trash2 className="h-3.5 w-3.5" />
        </button>
      </div>
      {open && <div className="border-t border-slate-800"><AlertList watchId={w.id} /></div>}
    </div>
  )
}

// WatchlistPanel is the body of the watchlist (create form + watch list), with
// no top-level page header — designed to live inside the OSINT page's
// "Watchlist" tab so OSINT stays a single section.
export function WatchlistPanel() {
  const { data: watches = [], isLoading } = useQuery({
    queryKey: ['osint-watches'],
    queryFn: osintApi.watches,
    refetchInterval: 15000,
  })

  return (
    <div className="space-y-4">
      <p className="text-sm text-gray-500">
        Continuous monitoring — re-scans on a schedule and alerts you when a NEW trace appears (new subdomain, leaked credential, ransomware listing, malicious verdict…).
      </p>

      <CreateWatch />

      {isLoading ? (
        <div className="flex justify-center py-16 text-gray-600"><Loader2 className="h-6 w-6 animate-spin" /></div>
      ) : watches.length === 0 ? (
        <div className="card flex flex-col items-center justify-center py-16 text-center gap-3">
          <RadioTower className="h-9 w-9 text-gray-700" />
          <p className="text-gray-500 text-sm">No watches yet — add a target above to monitor it continuously.</p>
        </div>
      ) : (
        <div className="space-y-2">
          {watches.map(w => <WatchRow key={w.id} w={w} />)}
        </div>
      )}
    </div>
  )
}
