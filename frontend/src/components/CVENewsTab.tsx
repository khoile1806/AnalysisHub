import { useEffect, useMemo, useState } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import {
  ExternalLink, Search, Rss, AlertCircle,
  ShieldAlert, Copy, Download, CheckCircle2,
} from 'lucide-react'
import { formatDistanceToNow } from 'date-fns'
import { newsApi, type NewsArticle, type NewsCategory } from '@/api/news'
import { useAuthStore } from '@/store/auth'
import { getErrorMessage } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogBody,
} from '@/components/ui/dialog'

const TOR_DOWNLOAD_URL = 'https://www.torproject.org/download/'

interface CVENewsTabProps {
  category: NewsCategory
}

type LangFilter = 'all' | 'vi' | 'en'

const LANG_SUBTABS: { id: LangFilter; label: string }[] = [
  { id: 'all', label: 'All' },
  { id: 'vi', label: 'Vietnamese' },
  { id: 'en', label: 'English' },
]

export default function CVENewsTab({ category }: CVENewsTabProps) {
  const [searchQuery, setSearchQuery] = useState('')
  const [langFilter, setLangFilter] = useState<LangFilter>('all')
  const [torPrompt, setTorPrompt] = useState<NewsArticle | null>(null)
  const [dangerPrompt, setDangerPrompt] = useState<NewsArticle | null>(null)
  const queryClient = useQueryClient()
  const isDarkweb = category === 'darkweb'
  const isVNTarget = category === 'vn-target'
  const isWorldNews = category === 'world-news'

  const { data: articles = [], isLoading, isError, error } = useQuery({
    queryKey: ['news', category],
    queryFn: () => newsApi.list(category),
  })

  // Realtime: SSE worker pushes one "update" event per feed that produced
  // new articles, carrying the affected category slug. We invalidate only
  // the matching tab's query so other tabs don't refetch needlessly.
  useEffect(() => {
    const token = useAuthStore.getState().token ?? ''
    const base = import.meta.env.VITE_API_URL || window.location.origin
    const url = `${base}/api/v1/news/stream?token=${encodeURIComponent(token)}`

    const es = new EventSource(url)

    es.addEventListener('update', (e) => {
      try {
        const payload = JSON.parse((e as MessageEvent).data ?? '{}') as { category?: string }
        if (!payload.category || payload.category === category) {
          queryClient.invalidateQueries({ queryKey: ['news', category] })
        }
      } catch {
        queryClient.invalidateQueries({ queryKey: ['news', category] })
      }
    })

    es.onerror = () => {
      es.close()
    }

    return () => {
      es.close()
    }
  }, [category, queryClient])

  const counts = useMemo(() => {
    let vi = 0
    let en = 0
    for (const a of articles) {
      if (a.language === 'vi') vi++
      else if (a.language === 'en') en++
    }
    return { all: articles.length, vi, en }
  }, [articles])

  const filtered = useMemo(() => {
    const q = searchQuery.trim().toLowerCase()
    let out = articles
    if (isWorldNews && langFilter !== 'all') {
      out = out.filter((a) => a.language === langFilter)
    }
    if (q) {
      out = out.filter(
        (a) =>
          a.title.toLowerCase().includes(q) ||
          a.description.toLowerCase().includes(q) ||
          a.source.toLowerCase().includes(q) ||
          a.tags?.some((t) => t.toLowerCase().includes(q)),
      )
    }
    return out
  }, [articles, searchQuery, isWorldNews, langFilter])

  return (
    <div className="space-y-5">
      {isWorldNews && (
        <div className="flex items-center gap-2 flex-wrap">
          {LANG_SUBTABS.map((s) => {
            const count = counts[s.id]
            const isActive = langFilter === s.id
            return (
              <button
                key={s.id}
                onClick={() => setLangFilter(s.id)}
                className={`px-3 py-1.5 text-xs font-medium rounded-md border transition-all ${
                  isActive
                    ? 'bg-emerald-900/40 border-emerald-700 text-emerald-300'
                    : 'bg-gray-900/60 border-gray-800 text-gray-400 hover:text-gray-200 hover:border-gray-700'
                }`}
              >
                {s.label}
                <span className="ml-1.5 text-[10px] opacity-70">({count})</span>
              </button>
            )
          })}
        </div>
      )}

      <div className="card p-4">
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500 pointer-events-none" />
          <input
            className="input pl-9"
            placeholder="Search by title, source, description..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
          />
        </div>
      </div>

      {isLoading && (
        <div className="grid gap-3">
          {Array.from({ length: 4 }).map((_, i) => (
            <div key={i} className="skeleton h-24 w-full rounded" />
          ))}
        </div>
      )}

      {isError && (
        <div className="card p-6 text-red-400 text-sm flex items-start gap-2">
          <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <span>Failed to load news: {getErrorMessage(error)}</span>
        </div>
      )}

      {!isLoading && !isError && filtered.length === 0 && (
        <div className="card p-12 text-center text-gray-500">
          <Rss className="h-8 w-8 mx-auto mb-2 text-gray-700" />
          {articles.length === 0
            ? 'No articles yet. The worker is collecting data, please check back in a few minutes.'
            : 'No results match the search keyword.'}
        </div>
      )}

      {isDarkweb && (
        <div className="card border-amber-700/50 bg-amber-950/20 p-3 text-xs text-amber-300 flex items-start gap-2">
          <ShieldAlert className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <div>
            Links in this tab can only be opened via <strong>Tor Browser</strong>.
            The system will block clicks and display instructions — it will not automatically open
            in the current browser.
          </div>
        </div>
      )}

      {isVNTarget && (
        <div className="card border-red-700/50 bg-red-950/20 p-3 text-xs text-red-300 flex items-start gap-2">
          <AlertCircle className="h-4 w-4 mt-0.5 flex-shrink-0" />
          <div>
            This tab contains links to potential threats targeting Vietnam. Clicks on <strong>all links</strong> are blocked to prevent accidental infection. Please copy the URL and investigate in a safe sandbox environment.
          </div>
        </div>
      )}

      {filtered.length > 0 && (
        <div className="grid gap-3">
          {filtered.map((a) => {
            let interceptFn: (() => void) | undefined = undefined
            if (isDarkweb) {
              interceptFn = () => setTorPrompt(a)
            } else if (isVNTarget) {
              interceptFn = () => setDangerPrompt(a)
            }

            return (
              <ArticleCard
                key={a.id}
                article={a}
                onIntercept={interceptFn}
                isDanger={isVNTarget}
              />
            )
          })}
        </div>
      )}

      <TorLinkPrompt article={torPrompt} onClose={() => setTorPrompt(null)} />
      <DangerLinkPrompt article={dangerPrompt} onClose={() => setDangerPrompt(null)} />
    </div>
  )
}

function ArticleCard({
  article,
  onIntercept,
  isDanger,
}: {
  article: NewsArticle
  onIntercept?: () => void
  isDanger?: boolean
}) {
  const published = article.published ? safeFormatDate(article.published) : ''

  const handleClick = (e: React.MouseEvent<HTMLAnchorElement>) => {
    if (onIntercept) {
      e.preventDefault()
      e.stopPropagation()
      onIntercept()
    }
  }

  return (
    <a
      href={article.link}
      target="_blank"
      rel="noopener noreferrer"
      onClick={handleClick}
      onAuxClick={onIntercept ? (e) => { e.preventDefault(); onIntercept() } : undefined}
      onContextMenu={onIntercept ? (e) => e.preventDefault() : undefined}
      className={`card p-4 hover:border-emerald-700/50 transition-colors block group ${isDanger ? 'border-red-900/30 bg-red-950/10 hover:border-red-700/50' : ''}`}
    >
      <div className="flex gap-4">
        {article.image_url && (
          <img
            src={article.image_url}
            alt=""
            loading="lazy"
            className="h-20 w-32 flex-shrink-0 object-cover rounded border border-gray-800"
            onError={(e) => {
              ;(e.currentTarget as HTMLImageElement).style.display = 'none'
            }}
          />
        )}
        <div className="flex-1 min-w-0">
          <div className="flex items-start justify-between gap-2">
            <h3 className="text-sm font-medium text-gray-100 group-hover:text-emerald-400 line-clamp-2">
              {article.title}
            </h3>
            <ExternalLink className="h-3.5 w-3.5 text-gray-600 group-hover:text-emerald-400 flex-shrink-0 mt-1" />
          </div>
          {article.description && (
            <p className="mt-1.5 text-xs text-gray-400 line-clamp-2">{article.description}</p>
          )}
          <div className="mt-2 flex flex-wrap items-center gap-2 text-[11px]">
            <span className="px-1.5 py-0.5 bg-gray-800 text-gray-300 rounded border border-gray-700">
              {article.source}
            </span>
            {article.author && (
              <span className="text-gray-500">by {article.author}</span>
            )}
            {published && <span className="text-gray-500">{published}</span>}
            {article.tags && article.tags.slice(0, 3).map((t) => (
              <span
                key={t}
                className="px-1.5 py-0.5 text-emerald-400/80 bg-emerald-900/20 border border-emerald-900/50 rounded"
              >
                {t}
              </span>
            ))}
          </div>
        </div>
      </div>
    </a>
  )
}

function TorLinkPrompt({
  article,
  onClose,
}: {
  article: NewsArticle | null
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)

  // Reset "copied" feedback whenever we open a fresh dialog.
  useEffect(() => {
    if (!article) return
    setCopied(false)
  }, [article])

  if (!article) return null

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(article.link)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback for non-secure contexts: do nothing, user can select manually
    }
  }

  const handleDownloadTor = () => {
    window.open(TOR_DOWNLOAD_URL, '_blank', 'noopener,noreferrer')
  }

  return (
    <Dialog open={!!article} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-amber-400">
            <ShieldAlert className="h-5 w-5" />
            Dark Web Link — Requires Tor Browser
          </DialogTitle>
          <DialogDescription>
            For security and anonymity, the system will <strong>not automatically open</strong> Dark Web links
            in the current browser. Copy the URL and open it in Tor Browser,
            or download Tor Browser if you don't have it.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div>
            <label className="label mb-1">Title</label>
            <p className="text-sm text-gray-200">{article.title}</p>
          </div>

          <div>
            <label className="label mb-1">URL</label>
            <div className="flex items-center gap-2 bg-gray-950 border border-gray-800 rounded-md px-3 py-2">
              <code className="flex-1 text-xs text-emerald-400 font-mono break-all">
                {article.link}
              </code>
              <button
                onClick={handleCopy}
                className="btn-secondary flex-shrink-0 !px-2 !py-1"
                title="Copy URL"
              >
                {copied ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-[11px]">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span className="text-[11px]">Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="text-xs text-gray-400 bg-gray-950/60 border border-gray-800 rounded-md p-3 space-y-1.5">
            <div className="font-semibold text-gray-300">Instructions:</div>
            <ol className="list-decimal list-inside space-y-0.5">
              <li>Copy the URL above.</li>
              <li>Open Tor Browser on your machine.</li>
              <li>Paste the URL into the address bar and press Enter.</li>
            </ol>
            <p className="text-[11px] text-gray-500 pt-1">
              Note: Web browsers cannot automatically detect if Tor Browser is installed,
              so the system cannot launch it for you. If you don't have Tor, use the button below.
            </p>
          </div>

          <div className="flex justify-between items-center pt-2">
            <button className="btn-secondary" onClick={onClose}>
              Close
            </button>
            <button className="btn-primary" onClick={handleDownloadTor}>
              <Download className="h-4 w-4" />
              Download Tor Browser
            </button>
          </div>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}

function safeFormatDate(iso: string): string {
  const d = new Date(iso)
  if (isNaN(d.getTime())) return iso
  return formatDistanceToNow(d, { addSuffix: true })
}

function DangerLinkPrompt({
  article,
  onClose,
}: {
  article: NewsArticle | null
  onClose: () => void
}) {
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!article) return
    setCopied(false)
  }, [article])

  if (!article) return null

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(article.link)
      setCopied(true)
      window.setTimeout(() => setCopied(false), 2000)
    } catch {
      // Fallback
    }
  }

  return (
    <Dialog open={!!article} onOpenChange={(o) => !o && onClose()}>
      <DialogContent>
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2 text-red-400">
            <AlertCircle className="h-5 w-5" />
            High Risk Link Blocked
          </DialogTitle>
          <DialogDescription>
            The system has blocked automatic navigation to this link for your safety.
          </DialogDescription>
        </DialogHeader>
        <DialogBody className="space-y-4">
          <div>
            <label className="label mb-1">Title</label>
            <p className="text-sm text-gray-200">{article.title}</p>
          </div>

          <div>
            <label className="label mb-1">URL</label>
            <div className="flex items-center gap-2 bg-gray-950 border border-gray-800 rounded-md px-3 py-2">
              <code className="flex-1 text-xs text-red-400 font-mono break-all">
                {article.link}
              </code>
              <button
                onClick={handleCopy}
                className="btn-secondary flex-shrink-0 !px-2 !py-1"
                title="Copy URL"
              >
                {copied ? (
                  <>
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    <span className="text-[11px]">Copied</span>
                  </>
                ) : (
                  <>
                    <Copy className="h-3.5 w-3.5" />
                    <span className="text-[11px]">Copy</span>
                  </>
                )}
              </button>
            </div>
          </div>

          <div className="text-xs text-gray-400 bg-gray-950/60 border border-red-900/30 rounded-md p-3 space-y-1.5">
            <div className="font-semibold text-red-400">Security Warning:</div>
            <p>
              Please investigate this URL only within an isolated Sandbox or Virtual Machine.
              Do not open this link on your host machine unless you know what you are doing.
            </p>
          </div>

          <div className="flex justify-end pt-2">
            <button className="btn-secondary" onClick={onClose}>
              Close
            </button>
          </div>
        </DialogBody>
      </DialogContent>
    </Dialog>
  )
}

