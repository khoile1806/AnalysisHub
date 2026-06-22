import { useEffect, useRef, useState } from 'react'
import { Copy, Check, FileText, AlertTriangle, Shield, Search, Lightbulb, BookOpen, Loader2 } from 'lucide-react'
import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { Components } from 'react-markdown'

interface Props {
  content: string
  isStreaming?: boolean
  placeholder?: string
}

// Map section headings to visual themes
const SECTION_THEMES: Record<string, { color: string; bg: string; border: string; icon: typeof FileText }> = {
  'tóm tắt':      { color: 'text-sky-300',    bg: 'bg-sky-900/20',    border: 'border-sky-500/50',    icon: BookOpen },
  'tổng quan':    { color: 'text-sky-300',    bg: 'bg-sky-900/20',    border: 'border-sky-500/50',    icon: BookOpen },
  'phát hiện':    { color: 'text-rose-300',   bg: 'bg-rose-900/20',   border: 'border-rose-500/50',   icon: AlertTriangle },
  'findings':     { color: 'text-rose-300',   bg: 'bg-rose-900/20',   border: 'border-rose-500/50',   icon: AlertTriangle },
  'phân tích':    { color: 'text-violet-300', bg: 'bg-violet-900/20', border: 'border-violet-500/50', icon: Search },
  'indicators':   { color: 'text-amber-300',  bg: 'bg-amber-900/20',  border: 'border-amber-500/50',  icon: Shield },
  'ioc':          { color: 'text-amber-300',  bg: 'bg-amber-900/20',  border: 'border-amber-500/50',  icon: Shield },
  'đề xuất':      { color: 'text-emerald-300',bg: 'bg-emerald-900/20',border: 'border-emerald-500/50',icon: Lightbulb },
  'hành động':    { color: 'text-emerald-300',bg: 'bg-emerald-900/20',border: 'border-emerald-500/50',icon: Lightbulb },
  'kết luận':     { color: 'text-blue-300',   bg: 'bg-blue-900/20',   border: 'border-blue-500/50',   icon: FileText },
}

function getSectionTheme(text: string) {
  const lower = text.toLowerCase()
  for (const [key, theme] of Object.entries(SECTION_THEMES)) {
    if (lower.includes(key)) return theme
  }
  return { color: 'text-gray-200', bg: 'bg-gray-800/30', border: 'border-gray-600/50', icon: FileText }
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

  const components: Components = {
    h2: ({ children }) => {
      const text = String(children)
      const theme = getSectionTheme(text)
      const Icon = theme.icon
      return (
        <div className={`flex items-center gap-2.5 mt-7 mb-3 pb-2.5 border-b ${theme.border}`}>
          <span className={`flex items-center justify-center h-7 w-7 rounded-md ${theme.bg} border ${theme.border} shrink-0`}>
            <Icon className={`h-3.5 w-3.5 ${theme.color}`} />
          </span>
          <h2 className={`text-base font-bold ${theme.color} tracking-tight`}>{children}</h2>
        </div>
      )
    },
    h3: ({ children }) => (
      <h3 className="text-sm font-semibold text-gray-200 mt-4 mb-1.5 flex items-center gap-1.5">
        <span className="w-1 h-3.5 rounded-full bg-gray-500 inline-block" />
        {children}
      </h3>
    ),
    p: ({ children }) => (
      <p className="text-[13.5px] text-gray-300 leading-[1.75] mb-3">{children}</p>
    ),
    ul: ({ children }) => <ul className="mb-3 space-y-1.5 ml-1">{children}</ul>,
    ol: ({ children }) => (
      <ol className="mb-3 space-y-1.5 ml-1 list-decimal list-inside marker:text-gray-500">{children}</ol>
    ),
    li: ({ children }) => (
      <li className="flex items-start gap-2 text-[13.5px] text-gray-300 leading-[1.7]">
        <span className="mt-[7px] h-1.5 w-1.5 rounded-full bg-gray-500 shrink-0" />
        <span className="flex-1">{children}</span>
      </li>
    ),
    strong: ({ children }) => {
      const text = String(children)
      if (/critical/i.test(text)) return <strong className="font-semibold text-red-400">{children}</strong>
      if (/high/i.test(text))     return <strong className="font-semibold text-orange-400">{children}</strong>
      if (/medium/i.test(text))   return <strong className="font-semibold text-yellow-400">{children}</strong>
      if (/low|info/i.test(text)) return <strong className="font-semibold text-emerald-400">{children}</strong>
      return <strong className="font-semibold text-white">{children}</strong>
    },
    em: ({ children }) => (
      <em className="not-italic text-[12px] bg-gray-800/60 px-1.5 py-0.5 rounded text-gray-400">{children}</em>
    ),
    code: ({ children, className }) => {
      const isBlock = className?.startsWith('language-')
      if (isBlock) return <code className="block text-[12px] text-emerald-300 font-mono leading-relaxed">{children}</code>
      return <code className="text-[12px] text-amber-300 bg-gray-800/80 border border-gray-700/60 px-1.5 py-0.5 rounded font-mono">{children}</code>
    },
    pre: ({ children }) => (
      <pre className="my-3 rounded-lg bg-[#0d1117] border border-gray-700/60 p-3 overflow-x-auto text-[12px] font-mono leading-relaxed">{children}</pre>
    ),
    blockquote: ({ children }) => (
      <blockquote className="my-3 pl-3 border-l-2 border-amber-500/60 bg-amber-900/10 rounded-r-lg pr-3 py-2">
        <div className="text-[13px] text-amber-200/80 leading-relaxed">{children}</div>
      </blockquote>
    ),
    hr: () => <hr className="my-5 border-0 border-t border-gray-700/60" />,
    table: ({ children }) => (
      <div className="my-3 overflow-x-auto rounded-lg border border-gray-700/60">
        <table className="w-full text-[12.5px]">{children}</table>
      </div>
    ),
    thead: ({ children }) => <thead className="bg-gray-800/60 border-b border-gray-700/60">{children}</thead>,
    tbody: ({ children }) => <tbody className="divide-y divide-gray-800/60">{children}</tbody>,
    tr: ({ children }) => <tr className="hover:bg-gray-800/30 transition-colors">{children}</tr>,
    th: ({ children }) => <th className="text-left px-3 py-2 text-[11px] font-semibold text-gray-400 uppercase tracking-wider">{children}</th>,
    td: ({ children }) => <td className="px-3 py-2 text-gray-300">{children}</td>,
    a: ({ href, children }) => (
      <a href={href} target="_blank" rel="noopener noreferrer"
        className="text-sky-400 hover:text-sky-300 underline underline-offset-2 decoration-sky-600/50">{children}</a>
    ),
  }

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
        style={{ fontFamily: "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif" }}>

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
          <div>
            <ReactMarkdown components={components} remarkPlugins={[remarkGfm]}>
              {content}
            </ReactMarkdown>
          </div>
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
