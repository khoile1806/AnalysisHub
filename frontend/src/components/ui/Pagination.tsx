import { ChevronLeft, ChevronRight } from 'lucide-react'

interface PaginationProps {
  page: number // 1-based
  pageSize: number
  totalItems: number
  onPageChange: (page: number) => void
  className?: string
}

// Pagination is a small, presentational page-stepper. It renders nothing when
// everything fits on a single page, so dropping it into a list is always safe.
export default function Pagination({ page, pageSize, totalItems, onPageChange, className = '' }: PaginationProps) {
  const totalPages = Math.max(1, Math.ceil(totalItems / pageSize))
  if (totalPages <= 1) return null

  const clamped = Math.min(Math.max(1, page), totalPages)
  const from = (clamped - 1) * pageSize + 1
  const to = Math.min(clamped * pageSize, totalItems)

  const go = (p: number) => onPageChange(Math.min(Math.max(1, p), totalPages))

  // Compact window of page numbers around the current page.
  const windowSize = 5
  let start = Math.max(1, clamped - Math.floor(windowSize / 2))
  const end = Math.min(totalPages, start + windowSize - 1)
  start = Math.max(1, end - windowSize + 1)
  const pages: number[] = []
  for (let p = start; p <= end; p++) pages.push(p)

  return (
    <div className={`flex items-center justify-between gap-3 px-5 py-3 border-t border-gray-800 ${className}`}>
      <span className="text-xs text-gray-500">
        Showing <span className="text-gray-300">{from}</span>–<span className="text-gray-300">{to}</span> of{' '}
        <span className="text-gray-300">{totalItems}</span>
      </span>
      <div className="flex items-center gap-1">
        <button
          onClick={() => go(clamped - 1)}
          disabled={clamped <= 1}
          className="inline-flex items-center justify-center h-7 w-7 rounded-md border border-gray-800 text-gray-400 hover:text-gray-100 hover:border-gray-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          aria-label="Previous page"
        >
          <ChevronLeft className="h-4 w-4" />
        </button>
        {start > 1 && <span className="px-1 text-xs text-gray-600">…</span>}
        {pages.map((p) => (
          <button
            key={p}
            onClick={() => go(p)}
            className={`h-7 min-w-7 px-2 rounded-md text-xs font-medium border transition-colors ${
              p === clamped
                ? 'bg-emerald-500/10 text-emerald-400 border-emerald-500/30'
                : 'text-gray-400 border-gray-800 hover:text-gray-100 hover:border-gray-600'
            }`}
          >
            {p}
          </button>
        ))}
        {end < totalPages && <span className="px-1 text-xs text-gray-600">…</span>}
        <button
          onClick={() => go(clamped + 1)}
          disabled={clamped >= totalPages}
          className="inline-flex items-center justify-center h-7 w-7 rounded-md border border-gray-800 text-gray-400 hover:text-gray-100 hover:border-gray-600 disabled:opacity-40 disabled:cursor-not-allowed transition-colors"
          aria-label="Next page"
        >
          <ChevronRight className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}
