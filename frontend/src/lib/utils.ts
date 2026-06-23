import { type ClassValue, clsx } from 'clsx'
import { twMerge } from 'tailwind-merge'
import { formatDistanceToNow, format } from 'date-fns'

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

export function formatBytes(bytes: number): string {
  if (bytes === 0) return '0 B'
  const k = 1024
  const sizes = ['B', 'KB', 'MB', 'GB']
  const i = Math.floor(Math.log(bytes) / Math.log(k))
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(1))} ${sizes[i]}`
}

export function formatDuration(startedAt: string, finishedAt: string | null): string {
  if (!startedAt) return '—'
  const start = new Date(startedAt).getTime()
  const end = finishedAt ? new Date(finishedAt).getTime() : Date.now()
  const diffMs = end - start
  if (diffMs < 0) return '—'
  const diffSec = Math.floor(diffMs / 1000)
  if (diffSec < 60) return `${diffSec}s`
  const diffMin = Math.floor(diffSec / 60)
  const remSec = diffSec % 60
  if (diffMin < 60) return `${diffMin}m ${remSec}s`
  const diffHr = Math.floor(diffMin / 60)
  const remMin = diffMin % 60
  return `${diffHr}h ${remMin}m`
}

export function getErrorMessage(error: unknown): string {
  if (error instanceof Error) return error.message
  if (typeof error === 'object' && error !== null) {
    const axiosError = error as { response?: { data?: { message?: string; error?: string } }; message?: string }
    return (
      axiosError.response?.data?.message ??
      axiosError.response?.data?.error ??
      axiosError.message ??
      'An unknown error occurred'
    )
  }
  return String(error)
}
// ──────────────────────────────────────────────────────────────────────────────
// Safe date helpers — prevent RangeError / "Invalid time value" crashes
// Use these instead of new Date(x) when x could be null/undefined/invalid.
// ──────────────────────────────────────────────────────────────────────────────

function safeDate(val: string | number | Date | null | undefined): Date | null {
  if (val == null || val === '') return null
  const d = new Date(val)
  return isNaN(d.getTime()) ? null : d
}

export function safeDistanceToNow(
  val: string | number | Date | null | undefined,
  opts?: { addSuffix?: boolean; includeSeconds?: boolean }
): string {
  const d = safeDate(val)
  if (!d) return '—'
  try { return formatDistanceToNow(d, opts) }
  catch { return '—' }
}

export function safeFormat(
  val: string | number | Date | null | undefined,
  fmt: string
): string {
  const d = safeDate(val)
  if (!d) return '—'
  try { return format(d, fmt) }
  catch { return '—' }
}

export async function copyToClipboard(text: string): Promise<boolean> {
  // Use modern API if available
  if (navigator.clipboard) {
    try {
      await navigator.clipboard.writeText(text)
      return true
    } catch (err) {
      console.warn('Clipboard API failed, falling back to execCommand', err)
    }
  }

  // Fallback for non-secure contexts (HTTP) or older browsers
  try {
    const textArea = document.createElement('textarea')
    textArea.value = text
    
    // Ensure textarea is not visible but part of document
    textArea.style.position = 'fixed'
    textArea.style.left = '-9999px'
    textArea.style.top = '0'
    textArea.style.opacity = '0'
    
    document.body.appendChild(textArea)
    textArea.select()
    
    const success = document.execCommand('copy')
    document.body.removeChild(textArea)
    return success
  } catch (err) {
    console.error('Fallback copy failed:', err)
    return false
  }
}
