import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  Plus, Trash2, Loader2, Copy, Check, Link2, ChevronDown, ChevronRight,
  Power, PowerOff, Globe, Monitor, Smartphone, Bot, AlertTriangle, Eraser,
  MapPin, Crosshair, ScanSearch, Users, Image as ImageIcon, FileText, Download,
  BellRing, ShieldAlert,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import toast from 'react-hot-toast'
import { canaryApi, type CanaryToken, type CanaryHit, type CanaryKind, type CanaryAlert } from '@/api/canary'
import { casesApi } from '@/api/cases'
import { getErrorMessage } from '@/lib/utils'

// severityChip maps an auto-scored severity to a colour-coded badge class.
function severityChip(sev?: string): string {
  switch (sev) {
    case 'critical': return 'bg-red-500/20 text-red-300'
    case 'high': return 'bg-orange-500/20 text-orange-300'
    case 'medium': return 'bg-amber-500/15 text-amber-300'
    default: return 'bg-gray-700/50 text-gray-400'
  }
}

function CopyButton({ value }: { value: string }) {
  const [copied, setCopied] = useState(false)
  return (
    <button
      onClick={() => {
        navigator.clipboard.writeText(value)
        setCopied(true)
        toast.success('Link copied')
        setTimeout(() => setCopied(false), 1500)
      }}
      className="inline-flex items-center gap-1 rounded-md border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200 hover:bg-gray-700 transition"
      title="Copy link"
    >
      {copied ? <Check className="h-3.5 w-3.5 text-emerald-400" /> : <Copy className="h-3.5 w-3.5" />}
      {copied ? 'Copied' : 'Copy'}
    </button>
  )
}

function CreateToken() {
  const qc = useQueryClient()
  const [kind, setKind] = useState<CanaryKind>('link')
  const [tab, setTab] = useState<'single' | 'bulk'>('single')
  const [name, setName] = useState('')
  const [targetUrl, setTargetUrl] = useState('')
  const [slug, setSlug] = useState('')
  const [baseUrl, setBaseUrl] = useState('')
  const [description, setDescription] = useState('')
  const [caseId, setCaseId] = useState('')
  const [file, setFile] = useState<File | null>(null)
  // Bulk mode: one redirect URL per line, plus an optional shared label prefix.
  const [bulkTargets, setBulkTargets] = useState('')
  const [namePrefix, setNamePrefix] = useState('')
  // Collection is opt-in: default 'stealth' (transparent 302, no interstitial).
  // 'gps' = details + precise GPS prompt.
  const [mode, setMode] = useState<'stealth' | 'gps'>('stealth')

  const { data: cases = [] } = useQuery({ queryKey: ['cases'], queryFn: casesApi.list })

  const isFileKind = kind === 'image' || kind === 'document'

  const resetShared = () => {
    setBaseUrl('')
    setDescription('')
    setCaseId('')
    setMode('stealth')
    setFile(null)
  }

  const create = useMutation({
    mutationFn: () =>
      canaryApi.create({
        name: name.trim(),
        kind, // 'link' or 'image' (blank pixel — no upload)
        target_url: kind === 'link' ? targetUrl.trim() : undefined,
        slug: slug.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
        case_id: caseId || undefined,
        description: description.trim() || undefined,
        collect_details: kind === 'link' && mode === 'gps',
        request_location: kind === 'link' && mode === 'gps',
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
      setName('')
      setTargetUrl('')
      setSlug('')
      resetShared()
      toast.success('Canary token created')
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const createFile = useMutation({
    mutationFn: () =>
      canaryApi.createFile({
        kind: kind as 'image' | 'document',
        name: name.trim(),
        file: file!,
        slug: slug.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
        case_id: caseId || undefined,
        description: description.trim() || undefined,
      }),
    onSuccess: (tok) => {
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
      setName('')
      setSlug('')
      resetShared()
      toast.success(
        kind === 'document'
          ? 'Document token created — download the beacon-rigged file from the list below'
          : 'Image token created',
      )
      void tok
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const bulkLines = bulkTargets
    .split('\n')
    .map((l) => l.trim())
    .filter(Boolean)

  const createBulk = useMutation({
    mutationFn: () =>
      canaryApi.createBulk({
        targets: bulkLines,
        name_prefix: namePrefix.trim() || undefined,
        base_url: baseUrl.trim() || undefined,
        description: description.trim() || undefined,
        collect_details: mode === 'gps',
        request_location: mode === 'gps',
      }),
    onSuccess: (res) => {
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
      setBulkTargets('')
      setNamePrefix('')
      resetShared()
      const okMsg = `${res.created.length} link(s) created`
      if (res.errors.length > 0) {
        toast.success(`${okMsg}, ${res.errors.length} line(s) skipped`)
      } else {
        toast.success(okMsg)
      }
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  // Blank-pixel image tokens go through the JSON create; image/document with an
  // uploaded file go through the multipart upload endpoint.
  const useUpload = isFileKind && !!file
  const canSubmit = (() => {
    if (isFileKind) {
      if (!name.trim()) return false
      if (kind === 'document') return !!file // a document token needs a real .docx
      return true // image: file optional (blank pixel)
    }
    return tab === 'single' ? !!(name.trim() && targetUrl.trim()) : bulkLines.length > 0
  })()
  const pending = create.isPending || createBulk.isPending || createFile.isPending
  const submit = () => {
    if (useUpload) return createFile.mutate()
    if (isFileKind) return create.mutate() // blank-pixel image
    return tab === 'single' ? create.mutate() : createBulk.mutate()
  }

  const kindTabs: { v: CanaryKind; label: string; icon: typeof Link2 }[] = [
    { v: 'link', label: 'Redirect link', icon: Link2 },
    { v: 'image', label: 'Image (web-bug)', icon: ImageIcon },
    { v: 'document', label: 'Document (.docx)', icon: FileText },
  ]

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/50 p-4 space-y-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <h2 className="flex items-center gap-2 text-sm font-medium text-gray-200">
          <Plus className="h-4 w-4 text-emerald-400" /> New canary token
        </h2>
        {kind === 'link' && (
          <div className="flex rounded-lg border border-gray-700 p-0.5 text-xs">
            <button
              onClick={() => setTab('single')}
              className={`rounded-md px-3 py-1 transition ${tab === 'single' ? 'bg-emerald-600 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              Single
            </button>
            <button
              onClick={() => setTab('bulk')}
              className={`rounded-md px-3 py-1 transition ${tab === 'bulk' ? 'bg-emerald-600 text-white' : 'text-gray-400 hover:text-gray-200'}`}
            >
              Bulk
            </button>
          </div>
        )}
      </div>

      {/* Token type selector */}
      <div className="flex flex-wrap gap-2">
        {kindTabs.map((k) => {
          const Icon = k.icon
          const on = kind === k.v
          return (
            <button
              key={k.v}
              onClick={() => { setKind(k.v); if (k.v !== 'link') setTab('single') }}
              className={`inline-flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-xs transition ${
                on ? 'border-emerald-600/60 bg-emerald-500/10 text-emerald-200' : 'border-gray-700 text-gray-400 hover:border-gray-600'
              }`}
            >
              <Icon className="h-3.5 w-3.5" /> {k.label}
            </button>
          )
        })}
      </div>

      {kind === 'image' && (
        <p className="text-[11px] text-gray-500">
          Image web-bug: embed the image URL in an e-mail / document / web page. Every time the image
          is <b>viewed</b> (no click needed) the visitor's IP + device is recorded. Upload a real image
          so it renders correctly, or leave it blank to use a 1×1 transparent pixel.
        </p>
      )}
      {kind === 'document' && (
        <p className="text-[11px] text-gray-500">
          Document token: upload a real <b>.docx</b> file. The system embeds a remote beacon image and
          returns a file that opens normally; when the target <b>opens it in Word</b> it triggers.
          Download the rigged file from the list below.
        </p>
      )}

      {tab === 'bulk' && kind === 'link' && (
        <div className="space-y-3">
          <div>
            <textarea
              value={bulkTargets}
              onChange={(e) => setBulkTargets(e.target.value)}
              rows={5}
              placeholder={'One target URL per line, e.g.:\nhttps://vnexpress.net/bai-1.html\ngoogle.com\nhttps://example.com/x'}
              className="w-full rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 font-mono text-xs text-gray-100 placeholder-gray-600 focus:border-emerald-500 focus:outline-none"
            />
            <div className="mt-1 text-[11px] text-gray-500">
              {bulkLines.length} target → {bulkLines.length} link(s) (one random slug each). Max 200.
            </div>
          </div>
          <div className="grid gap-3 sm:grid-cols-2">
            <input
              value={namePrefix}
              onChange={(e) => setNamePrefix(e.target.value)}
              placeholder="Label prefix (optional — blank = use target host)"
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
            />
            <input
              value={baseUrl}
              onChange={(e) => setBaseUrl(e.target.value)}
              placeholder="Link domain (optional — hides real host)"
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
            />
          </div>
        </div>
      )}

      {tab === 'single' && (
        <div className="grid gap-3 sm:grid-cols-2">
          <input
            value={name}
            onChange={(e) => setName(e.target.value)}
            placeholder="Label (e.g. leaked-creds-bait)"
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          {kind === 'link' ? (
            <input
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="Redirect target (https://example.com)"
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
            />
          ) : (
            <input
              type="file"
              accept={kind === 'image' ? 'image/*' : '.docx'}
              onChange={(e) => setFile(e.target.files?.[0] ?? null)}
              className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-1.5 text-sm text-gray-300 file:mr-3 file:rounded-md file:border-0 file:bg-emerald-600 file:px-3 file:py-1 file:text-xs file:text-white hover:file:bg-emerald-500 focus:border-emerald-500 focus:outline-none"
            />
          )}
          <input
            value={slug}
            onChange={(e) => setSlug(e.target.value)}
            placeholder="Custom slug (optional — random if blank)"
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          <input
            value={baseUrl}
            onChange={(e) => setBaseUrl(e.target.value)}
            placeholder="Link domain (optional — hides real host, e.g. https://promo-event.io)"
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          <input
            value={description}
            onChange={(e) => setDescription(e.target.value)}
            placeholder="Notes (optional)"
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 placeholder-gray-500 focus:border-emerald-500 focus:outline-none"
          />
          <select
            value={caseId}
            onChange={(e) => setCaseId(e.target.value)}
            className="rounded-lg border border-gray-700 bg-gray-950 px-3 py-2 text-sm text-gray-100 focus:border-emerald-500 focus:outline-none"
          >
            <option value="">Attach to Case (optional)</option>
            {cases.map((cs) => (
              <option key={cs.id} value={cs.id}>
                {cs.name}
              </option>
            ))}
          </select>
        </div>
      )}
      {kind === 'link' && (
      <div className="space-y-2">
        <span className="text-xs font-medium uppercase tracking-wide text-gray-500">Collection mode</span>
        <label
          className={`flex cursor-pointer items-start gap-2 rounded-lg border p-2.5 text-xs transition ${
            mode === 'stealth' ? 'border-emerald-600/60 bg-emerald-500/5' : 'border-gray-700 hover:border-gray-600'
          }`}
        >
          <input
            type="radio"
            name="canary-mode"
            checked={mode === 'stealth'}
            onChange={() => setMode('stealth')}
            className="mt-0.5 accent-emerald-500"
          />
          <span className="text-gray-300">
            <span className="text-gray-100">Stealth (default)</span> — straight redirect, records only IP +
            User-Agent + approximate GeoIP. No interstitial page, no popup.
          </span>
        </label>
        <label
          className={`flex cursor-pointer items-start gap-2 rounded-lg border p-2.5 text-xs transition ${
            mode === 'gps' ? 'border-amber-500/60 bg-amber-500/5' : 'border-gray-700 hover:border-gray-600'
          }`}
        >
          <input
            type="radio"
            name="canary-mode"
            checked={mode === 'gps'}
            onChange={() => setMode('gps')}
            className="mt-0.5 accent-amber-500"
          />
          <span className="text-gray-300">
            <span className="text-gray-100">Details + GPS</span> — a brief loading page collects device
            data (screen, timezone, CPU/RAM, GPU, battery, network) and requests{' '}
            <span className="text-amber-400">precise GPS coordinates (the visitor sees a permission popup)</span>.
            The link must run over HTTPS to obtain GPS.
          </span>
        </label>
      </div>
      )}
      <button
        disabled={!canSubmit || pending}
        onClick={submit}
        className="inline-flex items-center gap-2 rounded-lg bg-emerald-600 px-4 py-2 text-sm font-medium text-white hover:bg-emerald-500 disabled:cursor-not-allowed disabled:opacity-50 transition"
      >
        {pending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Link2 className="h-4 w-4" />}
        {isFileKind
          ? kind === 'document' ? 'Create document token' : 'Create image token'
          : tab === 'bulk' ? `Create ${bulkLines.length || ''} link(s)` : 'Create link'}
      </button>
    </div>
  )
}

function DeviceIcon({ type }: { type?: string }) {
  if (type === 'bot') return <Bot className="h-3.5 w-3.5 text-amber-400" />
  if (type === 'mobile' || type === 'tablet') return <Smartphone className="h-3.5 w-3.5 text-sky-400" />
  return <Monitor className="h-3.5 w-3.5 text-gray-400" />
}

// KV renders a labelled value, skipping empty ones.
function KV({ label, value }: { label: string; value?: string | number | null }) {
  if (value === undefined || value === null || value === '' || value === 0) return null
  return (
    <div className="flex gap-2">
      <span className="w-28 flex-shrink-0 text-gray-500">{label}</span>
      <span className="break-all text-gray-300">{value}</span>
    </div>
  )
}

// HitRow is one visit: a summary table row + an expandable detail panel holding
// the rich client-side fingerprint (precise GPS, screen, hardware, GPU, …).
function HitRow({ h, tokenId }: { h: CanaryHit; tokenId: string }) {
  const [open, setOpen] = useState(false)
  const navigate = useNavigate()
  const hasGPS = typeof h.geo_lat === 'number' && typeof h.geo_lon === 'number'
  const hasDetails =
    hasGPS || !!h.timezone || !!h.platform || !!h.gpu_renderer || !!h.screen_w || !!h.client_data

  const scan = useMutation({
    mutationFn: () => canaryApi.scanHit(tokenId, h.id),
    onSuccess: (scanId) => {
      toast.success('OSINT scan started')
      navigate(`/osint/${scanId}`)
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <>
      <tr
        className="cursor-pointer text-gray-300 hover:bg-gray-900/50"
        onClick={() => hasDetails && setOpen((o) => !o)}
      >
        <td className="px-2 py-2 text-gray-600">
          {hasDetails ? (
            open ? <ChevronDown className="h-3.5 w-3.5" /> : <ChevronRight className="h-3.5 w-3.5" />
          ) : null}
        </td>
        <td className="whitespace-nowrap px-3 py-2 text-gray-400" title={h.created_at}>
          {formatDistanceToNow(new Date(h.created_at), { addSuffix: true })}
        </td>
        <td className="px-3 py-2">
          <div className="flex items-center gap-1.5">
            <span className="font-mono text-emerald-300">{h.ip || '—'}</span>
            {h.ip && (
              <button
                onClick={(e) => {
                  e.stopPropagation()
                  scan.mutate()
                }}
                disabled={scan.isPending}
                title="Pivot IP → OSINT scan"
                className="text-gray-500 hover:text-emerald-300 disabled:opacity-50"
              >
                {scan.isPending ? (
                  <Loader2 className="h-3.5 w-3.5 animate-spin" />
                ) : (
                  <ScanSearch className="h-3.5 w-3.5" />
                )}
              </button>
            )}
          </div>
        </td>
        <td className="px-3 py-2">
          {hasGPS ? (
            <div className="flex items-center gap-1 text-emerald-300">
              <Crosshair className="h-3.5 w-3.5" />
              <span className="font-mono">
                {h.geo_lat!.toFixed(5)}, {h.geo_lon!.toFixed(5)}
              </span>
            </div>
          ) : (
            <div className="flex items-center gap-1">
              {(h.city || h.country) && <Globe className="h-3.5 w-3.5 text-gray-500" />}
              <span>{[h.city, h.country].filter(Boolean).join(', ') || '—'}</span>
            </div>
          )}
          {h.isp && <div className="text-[11px] text-gray-500">{h.isp}{h.asn ? ` · ${h.asn}` : ''}</div>}
          {(h.proxy || h.hosting || h.mobile || h.severity) && (
            <div className="mt-0.5 flex flex-wrap items-center gap-1">
              {h.severity && h.severity !== 'low' && (
                <span className={`inline-flex items-center gap-0.5 rounded px-1.5 text-[10px] ${severityChip(h.severity)}`} title={h.risk_flags || ''}>
                  <ShieldAlert className="h-2.5 w-2.5" /> {h.severity}
                </span>
              )}
              {h.proxy && <span className="rounded bg-red-500/15 px-1.5 text-[10px] text-red-300">VPN/Proxy</span>}
              {h.hosting && <span className="rounded bg-orange-500/15 px-1.5 text-[10px] text-orange-300">Datacenter</span>}
              {h.mobile && <span className="rounded bg-sky-500/15 px-1.5 text-[10px] text-sky-300">Mobile</span>}
              {h.risk_flags?.includes('KNOWN IOC') && (
                <span className="rounded bg-red-600/25 px-1.5 text-[10px] text-red-200">KNOWN IOC</span>
              )}
            </div>
          )}
        </td>
        <td className="px-3 py-2">
          <div className="flex items-center gap-1">
            <DeviceIcon type={h.device_type} />
            <span>{[h.browser, h.os].filter(Boolean).join(' / ') || h.device_type || '—'}</span>
            {h.is_bot && (
              <span className="rounded bg-amber-500/15 px-1.5 text-[10px] text-amber-300" title="Automated (preview/scanner), not a human click">
                bot
              </span>
            )}
          </div>
          {h.user_agent && (
            <div className="max-w-[260px] truncate text-[11px] text-gray-600" title={h.user_agent}>
              {h.user_agent}
            </div>
          )}
        </td>
        <td className="max-w-[180px] truncate px-3 py-2 text-gray-400" title={h.referer || ''}>
          {h.referer || '—'}
        </td>
      </tr>
      {open && hasDetails && (
        <tr className="bg-gray-950/60">
          <td></td>
          <td colSpan={5} className="px-3 py-3">
            <div className="grid gap-x-6 gap-y-1 sm:grid-cols-2">
              {hasGPS && (
                <div className="sm:col-span-2 mb-1 flex items-center gap-2">
                  <a
                    href={`https://www.google.com/maps?q=${h.geo_lat},${h.geo_lon}`}
                    target="_blank"
                    rel="noreferrer"
                    className="inline-flex items-center gap-1 rounded-md border border-emerald-700/50 bg-emerald-500/10 px-2 py-1 text-xs text-emerald-300 hover:bg-emerald-500/20"
                  >
                    <MapPin className="h-3.5 w-3.5" /> Open in Google Maps
                  </a>
                  {typeof h.geo_accuracy === 'number' && (
                    <span className="text-xs text-gray-500">± {Math.round(h.geo_accuracy)} m</span>
                  )}
                </div>
              )}
              {h.geo_error && <KV label="GPS" value={`denied/failed: ${h.geo_error}`} />}
              <KV label="Timezone" value={h.timezone} />
              <KV label="Languages" value={h.languages} />
              <KV label="Platform" value={h.platform} />
              <KV
                label="Screen"
                value={h.screen_w ? `${h.screen_w}×${h.screen_h}${h.pixel_ratio ? ` @${h.pixel_ratio}x` : ''}` : undefined}
              />
              <KV label="Viewport" value={h.viewport_w ? `${h.viewport_w}×${h.viewport_h}` : undefined} />
              <KV label="CPU cores" value={h.cpu_cores} />
              <KV label="Device memory" value={h.device_memory ? `${h.device_memory} GB` : undefined} />
              <KV label="GPU" value={h.gpu_renderer} />
              <KV label="GPU vendor" value={h.gpu_vendor} />
              <KV label="Connection" value={h.conn_type} />
              <KV
                label="Battery"
                value={typeof h.battery_level === 'number' ? `${Math.round(h.battery_level * 100)}%` : undefined}
              />
              <KV label="Accept-Language" value={h.accept_language} />
              <KV label="Forwarded-For" value={h.forwarded_for} />
            </div>
            {h.client_data && (
              <details className="mt-2">
                <summary className="cursor-pointer text-xs text-gray-500 hover:text-gray-300">
                  Raw client data (JSON)
                </summary>
                <pre className="mt-1 max-h-60 overflow-auto rounded bg-black/40 p-2 text-[11px] text-gray-400">
                  {(() => {
                    try {
                      return JSON.stringify(JSON.parse(h.client_data), null, 2)
                    } catch {
                      return h.client_data
                    }
                  })()}
                </pre>
              </details>
            )}
          </td>
        </tr>
      )}
    </>
  )
}

function HitsLog({ tokenId }: { tokenId: string }) {
  const qc = useQueryClient()
  const [hideBots, setHideBots] = useState(true)
  const { data: hits, isLoading } = useQuery({
    queryKey: ['canary-hits', tokenId],
    queryFn: () => canaryApi.hits(tokenId),
    refetchInterval: 15_000, // near-live updates while the panel is open
  })

  const clear = useMutation({
    mutationFn: () => canaryApi.clearHits(tokenId),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['canary-hits', tokenId] })
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
      toast.success('Hit log cleared')
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  if (isLoading) {
    return (
      <div className="flex items-center gap-2 px-4 py-4 text-sm text-gray-500">
        <Loader2 className="h-4 w-4 animate-spin" /> Loading hits…
      </div>
    )
  }
  if (!hits || hits.length === 0) {
    return <div className="px-4 py-4 text-sm text-gray-500">No clicks recorded yet.</div>
  }

  const botCount = hits.filter((h: CanaryHit) => h.is_bot).length
  const humanCount = hits.length - botCount
  const shown = hideBots ? hits.filter((h: CanaryHit) => !h.is_bot) : hits

  return (
    <div className="space-y-2 px-4 py-3">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="text-xs font-medium uppercase tracking-wide text-gray-500">
          {humanCount} human click{humanCount === 1 ? '' : 's'}
          {botCount > 0 && <span className="ml-1 text-gray-600">· {botCount} bot/preview</span>}
        </span>
        <div className="flex items-center gap-2">
          {botCount > 0 && (
            <label className="flex items-center gap-1 text-xs text-gray-400">
              <input
                type="checkbox"
                checked={hideBots}
                onChange={(e) => setHideBots(e.target.checked)}
                className="accent-emerald-500"
              />
              Hide bots/previews
            </label>
          )}
          <button
            onClick={() => {
              if (confirm('Clear the entire hit log for this link?')) clear.mutate()
            }}
            className="inline-flex items-center gap-1 rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 transition"
          >
            <Eraser className="h-3.5 w-3.5" /> Clear log
          </button>
        </div>
      </div>
      <div className="overflow-x-auto rounded-lg border border-gray-800">
        <table className="w-full text-left text-xs">
          <thead className="bg-gray-900 text-gray-400">
            <tr>
              <th className="w-6 px-2 py-2"></th>
              <th className="px-3 py-2 font-medium">When</th>
              <th className="px-3 py-2 font-medium">IP</th>
              <th className="px-3 py-2 font-medium">Location</th>
              <th className="px-3 py-2 font-medium">Client</th>
              <th className="px-3 py-2 font-medium">Referer</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-gray-800">
            {shown.map((h: CanaryHit) => (
              <HitRow key={h.id} h={h} tokenId={tokenId} />
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function TokenRow({ token }: { token: CanaryToken }) {
  const qc = useQueryClient()
  const [open, setOpen] = useState(false)

  const toggle = useMutation({
    mutationFn: () => canaryApi.update(token.id, { active: !token.active }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
      toast.success(token.active ? 'Link disabled' : 'Link enabled')
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const remove = useMutation({
    mutationFn: () => canaryApi.remove(token.id),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
      toast.success('Link deleted')
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <div className="rounded-xl border border-gray-800 bg-gray-900/40">
      <div className="flex flex-wrap items-center gap-3 p-4">
        <button onClick={() => setOpen((o) => !o)} className="text-gray-500 hover:text-gray-300">
          {open ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-center gap-2">
            <span className="font-medium text-gray-100">{token.name}</span>
            <span
              className="inline-flex items-center gap-1 rounded-full bg-cyan-500/15 px-2 py-0.5 text-[11px] text-cyan-300"
              title={`Token kind: ${token.kind}`}
            >
              {token.kind === 'image' ? <ImageIcon className="h-3 w-3" /> : token.kind === 'document' ? <FileText className="h-3 w-3" /> : <Link2 className="h-3 w-3" />}
              {token.kind}
            </span>
            <span
              className={`rounded-full px-2 py-0.5 text-[11px] ${
                token.active ? 'bg-emerald-500/15 text-emerald-300' : 'bg-gray-700/50 text-gray-400'
              }`}
            >
              {token.active ? 'active' : 'disabled'}
            </span>
            {token.kind === 'link' && (
              <span
                className={`rounded-full px-2 py-0.5 text-[11px] ${
                  token.request_location
                    ? 'bg-amber-500/15 text-amber-300'
                    : token.collect_details
                      ? 'bg-violet-500/15 text-violet-300'
                      : 'bg-gray-700/50 text-gray-400'
                }`}
                title={
                  token.request_location
                    ? 'Collects device details + prompts for precise GPS'
                    : token.collect_details
                      ? 'Collects device details via JS interstitial'
                      : 'Transparent 302 — only IP + User-Agent'
                }
              >
                {token.request_location ? 'details + GPS' : token.collect_details ? 'details' : 'stealth'}
              </span>
            )}
            {token.alert_count > 0 && (
              <span className="inline-flex items-center gap-1 rounded-full bg-red-500/20 px-2 py-0.5 text-[11px] text-red-300" title="Unseen alerts">
                <BellRing className="h-3 w-3" /> {token.alert_count}
              </span>
            )}
            <span className="rounded-full bg-sky-500/15 px-2 py-0.5 text-[11px] text-sky-300">
              {token.hit_count} hit{token.hit_count === 1 ? '' : 's'}
            </span>
            {token.unique_visitors > 0 && (
              <span
                className="inline-flex items-center gap-1 rounded-full bg-indigo-500/15 px-2 py-0.5 text-[11px] text-indigo-300"
                title="Unique human visitors"
              >
                <Users className="h-3 w-3" /> {token.unique_visitors}
              </span>
            )}
            {token.case_id && (
              <span className="rounded-full bg-gray-700/50 px-2 py-0.5 text-[11px] text-gray-300" title="Attached to a Case">
                case
              </span>
            )}
          </div>
          <div className="mt-1 flex flex-wrap items-center gap-2">
            <code className="truncate rounded bg-gray-950 px-2 py-1 text-xs text-emerald-300">{token.link}</code>
            <CopyButton value={token.link} />
            {token.kind === 'image' && (
              <CopyButton value={`<img src="${token.link}" width="1" height="1" alt="">`} />
            )}
            {token.download_url && (
              <button
                onClick={() => canaryApi.downloadFile(token.id, token.file_name || (token.kind === 'document' ? 'bait.docx' : 'bait.png'))}
                className="inline-flex items-center gap-1 rounded-md border border-gray-700 bg-gray-800 px-2 py-1 text-xs text-gray-200 hover:bg-gray-700 transition"
                title={token.kind === 'document' ? 'Download the beacon-rigged .docx' : 'Download image'}
              >
                <Download className="h-3.5 w-3.5" /> {token.kind === 'document' ? 'Download .docx' : 'Download'}
              </button>
            )}
          </div>
          <div className="mt-1 truncate text-xs text-gray-500">
            {token.kind === 'link'
              ? <>→ {token.target_url}</>
              : token.kind === 'image'
                ? <span className="text-gray-600">{token.file_name ? `image · ${token.file_name}` : 'image · 1×1 pixel'}</span>
                : <span className="text-gray-600">document · {token.file_name || 'bait.docx'}</span>}
            {token.last_hit_at && (
              <span className="ml-2 text-gray-600">
                last hit {formatDistanceToNow(new Date(token.last_hit_at), { addSuffix: true })}
              </span>
            )}
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => toggle.mutate()}
            disabled={toggle.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 transition"
            title={token.active ? 'Disable' : 'Enable'}
          >
            {token.active ? <PowerOff className="h-3.5 w-3.5" /> : <Power className="h-3.5 w-3.5 text-emerald-400" />}
          </button>
          <button
            onClick={() => {
              if (confirm(`Delete "${token.name}" and all its recorded hits?`)) remove.mutate()
            }}
            disabled={remove.isPending}
            className="inline-flex items-center gap-1 rounded-md border border-gray-700 px-2 py-1 text-xs text-red-400 hover:bg-red-500/10 transition"
            title="Delete"
          >
            <Trash2 className="h-3.5 w-3.5" />
          </button>
        </div>
      </div>
      {open && (
        <div className="border-t border-gray-800">
          <HitsLog tokenId={token.id} />
        </div>
      )}
    </div>
  )
}

// AlertsBanner shows recent unseen alerts from human hits (badge + feed) and
// lets the operator acknowledge them. Polls so a fired token surfaces quickly.
function AlertsBanner() {
  const qc = useQueryClient()
  const { data: alerts = [] } = useQuery({
    queryKey: ['canary-alerts'],
    queryFn: () => canaryApi.alerts(true),
    refetchInterval: 15_000,
  })

  const seenAll = useMutation({
    mutationFn: () => canaryApi.markAlertsSeen({ all: true }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['canary-alerts'] })
      qc.invalidateQueries({ queryKey: ['canary-tokens'] })
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  if (alerts.length === 0) return null

  return (
    <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-3">
      <div className="mb-2 flex items-center justify-between">
        <span className="inline-flex items-center gap-2 text-sm font-medium text-red-200">
          <BellRing className="h-4 w-4" /> {alerts.length} unseen alert{alerts.length === 1 ? '' : 's'}
        </span>
        <button
          onClick={() => seenAll.mutate()}
          disabled={seenAll.isPending}
          className="rounded-md border border-gray-700 px-2 py-1 text-xs text-gray-300 hover:bg-gray-800 transition"
        >
          Mark all as seen
        </button>
      </div>
      <div className="max-h-48 space-y-1 overflow-y-auto">
        {alerts.slice(0, 12).map((a: CanaryAlert) => (
          <div key={a.id} className="flex items-center gap-2 text-xs">
            <span className={`rounded px-1.5 py-0.5 ${severityChip(a.severity)}`}>{a.severity}</span>
            <span className="font-medium text-gray-200">{a.title}</span>
            <span className="truncate text-gray-400">{a.summary}</span>
            <span className="ml-auto whitespace-nowrap text-gray-600">
              {formatDistanceToNow(new Date(a.created_at), { addSuffix: true })}
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// CanaryPanel is the OSINT "Canary Tokens" tab — tracking / honeytoken links.
// Rendered inside the OSINT page (which supplies the section header), so it has
// no page-level chrome of its own, mirroring WatchlistPanel.
export function CanaryPanel() {
  const { data: tokens, isLoading } = useQuery({
    queryKey: ['canary-tokens'],
    queryFn: () => canaryApi.list(),
  })

  return (
    <div className="space-y-5">
      <AlertsBanner />
      <p className="text-sm text-gray-500">
        Tracking / honeytoken links — a visitor who opens the link is recorded (IP, User-Agent,
        GeoIP) and then transparently redirected to a harmless page you choose.
      </p>

      <div className="flex items-start gap-2 rounded-lg border border-amber-500/30 bg-amber-500/10 p-3 text-xs text-amber-200">
        <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0" />
        <span>
          These links capture personal data (IP address, device). Use them only within an
          authorised investigation and point them at a benign destination.
        </span>
      </div>

      <CreateToken />

      {isLoading ? (
        <div className="flex items-center gap-2 p-6 text-sm text-gray-500">
          <Loader2 className="h-4 w-4 animate-spin" /> Loading links…
        </div>
      ) : !tokens || tokens.length === 0 ? (
        <div className="rounded-xl border border-dashed border-gray-800 p-8 text-center text-sm text-gray-500">
          No canary links yet. Create one above.
        </div>
      ) : (
        <div className="space-y-3">
          {tokens.map((t: CanaryToken) => (
            <TokenRow key={t.id} token={t} />
          ))}
        </div>
      )}
    </div>
  )
}
