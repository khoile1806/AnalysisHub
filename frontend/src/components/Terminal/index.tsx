import { useEffect, useRef } from 'react'

interface TerminalOutputProps {
  lines: string[]
  isRunning: boolean
  className?: string
}

export default function TerminalOutput({ lines, isRunning, className = '' }: TerminalOutputProps) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // Auto-scroll to bottom when new lines arrive
  useEffect(() => {
    if (bottomRef.current) {
      bottomRef.current.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines])

  return (
    <div
      ref={containerRef}
      className={`
        flex flex-col bg-gray-950 border border-gray-800 rounded-lg overflow-hidden
        font-mono text-sm leading-relaxed
        ${className}
      `}
    >
      {/* Terminal title bar */}
      <div className="flex items-center gap-2 px-4 py-2 bg-gray-900 border-b border-gray-800">
        <span className="h-3 w-3 rounded-full bg-red-500/70" />
        <span className="h-3 w-3 rounded-full bg-yellow-500/70" />
        <span className="h-3 w-3 rounded-full bg-emerald-500/70" />
        <span className="ml-2 text-xs text-gray-500 font-mono">output</span>
        {isRunning && (
          <span className="ml-auto flex items-center gap-1.5 text-xs text-emerald-400">
            <span className="relative flex h-2 w-2">
              <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75" />
              <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500" />
            </span>
            LIVE
          </span>
        )}
      </div>

      {/* Output area */}
      <div className="flex-1 p-4 overflow-y-auto min-h-[200px]">
        {lines.length === 0 ? (
          <span className="text-gray-600 font-mono text-xs">
            {isRunning ? 'Waiting for output...' : 'No output yet.'}
          </span>
        ) : (
          lines.map((line, i) => (
            <div key={i} className="flex">
              <span className="select-none text-gray-600 mr-4 text-xs w-8 text-right shrink-0 pt-0.5">
                {i + 1}
              </span>
              <span
                className="text-forensic-500 break-all whitespace-pre-wrap flex-1"
                style={{ color: getLineColor(line) }}
              >
                {line || '\u00A0'}
              </span>
            </div>
          ))
        )}

        {/* Blinking cursor when running */}
        {isRunning && (
          <div className="flex mt-0.5">
            <span className="select-none text-gray-600 mr-4 text-xs w-8 text-right shrink-0" />
            <span className="text-forensic-500">
              <span className="animate-blink inline-block w-2 h-4 bg-forensic-500 align-middle" />
            </span>
          </div>
        )}

        <div ref={bottomRef} />
      </div>
    </div>
  )
}

// Color-code common log line patterns
function getLineColor(line: string): string {
  const lower = line.toLowerCase()
  if (lower.includes('error') || lower.includes('fail') || lower.includes('fatal')) {
    return '#f87171' // red-400
  }
  if (lower.includes('warn') || lower.includes('warning')) {
    return '#fbbf24' // amber-400
  }
  if (lower.includes('success') || lower.includes('done') || lower.includes('complete')) {
    return '#34d399' // emerald-400
  }
  if (line.startsWith('[') || line.startsWith('=')) {
    return '#60a5fa' // blue-400
  }
  return '#00ff41' // forensic green
}
