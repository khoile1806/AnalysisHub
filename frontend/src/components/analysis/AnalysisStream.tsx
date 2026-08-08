import { useEffect, useRef, useState } from 'react'
import { Copy, Check, FileText, Loader2 } from 'lucide-react'
import AiMarkdown, { AI_FONT } from '@/components/AiMarkdown'

interface Props {
  content: string
  isStreaming?: boolean
  placeholder?: string
}

export default function AnalysisStream({ content, isStreaming, placeholder }: Props) {
  const bottomRef = useRef<HTMLDivElement>(null)
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!isStreaming && content) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [isStreaming, content])

  const handleCopy = async () => {
    await navigator.clipboard.writeText(content)
    setCopied(true)
    setTimeout(() => setCopied(false), 2000)
  }

  const wordCount = content ? content.split(/\s+/).filter(Boolean).length : 0


  return (
    <div className="rounded-xl border border-gray-700/60 bg-[#0d111a] overflow-hidden flex flex-col min-h-[300px] max-h-[680px] shadow-xl shadow-black/30">

      {/* Header */}
      <div className="flex items-center justify-between px-4 py-3 bg-[#111827]/80 border-b border-gray-700/60 shrink-0">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-1.5">
            <span className="h-5 w-5 rounded-md bg-violet-500/20 border border-violet-500/30 flex items-center justify-center">
              <FileText className="h-2.5 w-2.5 text-violet-400" />
            </span>
            <span className="text-xs font-semibold text-gray-300 tracking-wide">Forensic Analysis Report</span>
          </div>
          {isStreaming && (
            <span className="flex items-center gap-1 text-[10px] text-violet-300/60 italic">
              Analyzing — results will appear when complete…
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          {content && !isStreaming && (
            <span className="text-[10px] text-gray-600 font-mono">{wordCount.toLocaleString()} words</span>
          )}
          {content && !isStreaming && (
            <button
              onClick={handleCopy}
              className="flex items-center gap-1.5 text-[11px] text-gray-500 hover:text-gray-200 transition px-2 py-1 rounded hover:bg-gray-700/50"
            >
              {copied
                ? <><Check className="h-3.5 w-3.5 text-emerald-400" /><span className="text-emerald-400">Copied</span></>
                : <><Copy className="h-3.5 w-3.5" />Copy</>
              }
            </button>
          )}
        </div>
      </div>

      {/* Content */}
      <div className="flex-1 overflow-y-auto px-5 py-4 custom-scrollbar"
        style={{ fontFamily: AI_FONT }}>

        {/* While streaming: show placeholder, not content */}
        {isStreaming ? (
          <div className="flex flex-col items-center justify-center h-full min-h-[220px] gap-4">
            <div className="flex items-center gap-3">
              <Loader2 className="h-5 w-5 text-violet-400 animate-spin" />
              <span className="text-sm text-gray-500">AI is analyzing the data…</span>
            </div>
            <p className="text-xs text-gray-700 text-center max-w-xs">
              The full results will appear here once analysis completes.
              <br/>Track progress in the <span className="text-violet-500">Live Activity</span> panel above.
            </p>
          </div>
        ) : content ? (
          <AiMarkdown content={content} />
        ) : (
          <div className="flex flex-col items-center justify-center h-full min-h-[220px] gap-3">
            <div className="h-10 w-10 rounded-xl bg-gray-800/60 border border-gray-700/60 flex items-center justify-center">
              <FileText className="h-5 w-5 text-gray-600" />
            </div>
            <p className="text-sm text-gray-600">
              {placeholder ?? 'The analysis report will appear here…'}
            </p>
          </div>
        )}
        <div ref={bottomRef} />
      </div>

      {/* Footer — only when done and has content */}
      {content && !isStreaming && (
        <div className="px-5 py-2 border-t border-gray-700/40 bg-[#0a0e18]/60 shrink-0 flex items-center gap-4">
          <span className="text-[10px] text-gray-600 font-mono flex items-center gap-1">
            <span className="h-1.5 w-1.5 rounded-full bg-emerald-500" />
            Analysis complete
          </span>
          <span className="text-[10px] text-gray-700">·</span>
          <span className="text-[10px] text-gray-600">Scroll up to view the full report</span>
        </div>
      )}
    </div>
  )
}
