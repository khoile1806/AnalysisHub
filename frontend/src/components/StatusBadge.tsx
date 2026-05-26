import type { AgentStatus } from '@/api/agents'
import type { JobStatus } from '@/api/jobs'
import type { Severity } from '@/api/cve'

interface AgentStatusBadgeProps {
  status: AgentStatus
}

interface JobStatusBadgeProps {
  status: JobStatus
}

export function AgentStatusBadge({ status }: AgentStatusBadgeProps) {
  if (status === 'online') {
    return (
      <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-900/40 text-emerald-400 border border-emerald-800/50">
        <span className="relative flex h-2 w-2">
          <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
        </span>
        Online
      </span>
    )
  }

  return (
    <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-800 text-gray-400 border border-gray-700">
      <span className="relative inline-flex rounded-full h-2 w-2 bg-gray-500" />
      Offline
    </span>
  )
}

export function JobStatusBadge({ status }: JobStatusBadgeProps) {
  switch (status) {
    case 'pending':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-yellow-900/40 text-yellow-400 border border-yellow-800/50">
          <span className="relative inline-flex rounded-full h-2 w-2 bg-yellow-500" />
          Pending
        </span>
      )
    case 'ready':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-amber-900/40 text-amber-400 border border-amber-800/50">
          <span className="relative inline-flex rounded-full h-2 w-2 bg-amber-500" />
          Ready
        </span>
      )
    case 'running':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-blue-900/40 text-blue-400 border border-blue-800/50">
          <span className="relative flex h-2 w-2">
            <span className="animate-spin absolute inline-flex h-full w-full rounded-full border-2 border-blue-400 border-t-transparent" />
          </span>
          Running
        </span>
      )
    case 'done':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-emerald-900/40 text-emerald-400 border border-emerald-800/50">
          <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
          Done
        </span>
      )
    case 'failed':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-red-900/40 text-red-400 border border-red-800/50">
          <span className="relative inline-flex rounded-full h-2 w-2 bg-red-500" />
          Failed
        </span>
      )
    case 'stopped':
      return (
        <span className="inline-flex items-center gap-1.5 px-2.5 py-0.5 rounded-full text-xs font-medium bg-gray-800 text-gray-300 border border-gray-700">
          <span className="relative inline-flex rounded-full h-2 w-2 bg-gray-500" />
          Stopped
        </span>
      )
    default:
      return null
  }
}

interface CategoryBadgeProps {
  category: string
}

const CATEGORY_COLORS: Record<string, string> = {
  Memory:  'bg-purple-900/40 text-purple-400 border-purple-800/50',
  Triage:  'bg-orange-900/40 text-orange-400 border-orange-800/50',
  Process: 'bg-blue-900/40 text-blue-400 border-blue-800/50',
  Network: 'bg-cyan-900/40 text-cyan-400 border-cyan-800/50',
  Disk:    'bg-amber-900/40 text-amber-400 border-amber-800/50',
  Log:     'bg-teal-900/40 text-teal-400 border-teal-800/50',
  Other:   'bg-gray-800 text-gray-400 border-gray-700',
}

export function CategoryBadge({ category }: CategoryBadgeProps) {
  const colorClass = CATEGORY_COLORS[category] ?? CATEGORY_COLORS.Other
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colorClass}`}>
      {category}
    </span>
  )
}

interface PlatformBadgeProps {
  platform: string
}

const PLATFORM_COLORS: Record<string, string> = {
  Windows: 'bg-sky-900/40 text-sky-400 border-sky-800/50',
  Linux:   'bg-yellow-900/40 text-yellow-400 border-yellow-800/50',
  Both:    'bg-violet-900/40 text-violet-400 border-violet-800/50',
}

export function PlatformBadge({ platform }: PlatformBadgeProps) {
  const colorClass = PLATFORM_COLORS[platform] ?? PLATFORM_COLORS.Both
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${colorClass}`}>
      {platform}
    </span>
  )
}

const SEVERITY_COLORS: Record<Severity, string> = {
  critical: 'bg-red-900/40 text-red-400 border-red-800/50',
  high:     'bg-orange-900/40 text-orange-400 border-orange-800/50',
  medium:   'bg-yellow-900/40 text-yellow-400 border-yellow-800/50',
  low:      'bg-blue-900/40 text-blue-400 border-blue-800/50',
  none:     'bg-gray-800 text-gray-400 border-gray-700',
}

interface SeverityBadgeProps {
  severity: Severity
  score?: number
}

export function SeverityBadge({ severity, score }: SeverityBadgeProps) {
  const colorClass = SEVERITY_COLORS[severity] ?? SEVERITY_COLORS.none
  return (
    <span className={`inline-flex items-center gap-1.5 px-2 py-0.5 rounded text-xs font-medium border ${colorClass}`}>
      {severity.toUpperCase()}
      {typeof score === 'number' && score > 0 && (
        <span className="font-mono opacity-80">{score.toFixed(1)}</span>
      )}
    </span>
  )
}
