import ReactMarkdown from 'react-markdown'
import remarkGfm from 'remark-gfm'
import type { Components } from 'react-markdown'
import { FileText, AlertTriangle, Shield, Search, Lightbulb, BookOpen } from 'lucide-react'

// AiMarkdown — the ONE canonical renderer for AI-generated text across the whole
// app (OSINT triage, malware verdicts/RE, analysis streams, …). It fixes the AI
// font and typography in a single place so every feature reads identically:
// section headings become titled/iconed dividers, severity words are colour-coded,
// lists get bullets, tables/code/links are styled. Pass the raw markdown string.

// AI_FONT is the single font stack used for ALL AI output in the project.
export const AI_FONT = "'Inter', 'Segoe UI', system-ui, -apple-system, sans-serif"

const SECTION_THEMES: Record<string, { color: string; bg: string; border: string; icon: typeof FileText }> = {
  'tóm tắt':    { color: 'text-sky-300',     bg: 'bg-sky-900/20',     border: 'border-sky-500/50',     icon: BookOpen },
  'tổng quan':  { color: 'text-sky-300',     bg: 'bg-sky-900/20',     border: 'border-sky-500/50',     icon: BookOpen },
  'summary':    { color: 'text-sky-300',     bg: 'bg-sky-900/20',     border: 'border-sky-500/50',     icon: BookOpen },
  'overview':   { color: 'text-sky-300',     bg: 'bg-sky-900/20',     border: 'border-sky-500/50',     icon: BookOpen },
  'rủi ro':     { color: 'text-rose-300',    bg: 'bg-rose-900/20',    border: 'border-rose-500/50',    icon: AlertTriangle },
  'phát hiện':  { color: 'text-rose-300',    bg: 'bg-rose-900/20',    border: 'border-rose-500/50',    icon: AlertTriangle },
  'findings':   { color: 'text-rose-300',    bg: 'bg-rose-900/20',    border: 'border-rose-500/50',    icon: AlertTriangle },
  'risk':       { color: 'text-rose-300',    bg: 'bg-rose-900/20',    border: 'border-rose-500/50',    icon: AlertTriangle },
  'phân tích':  { color: 'text-violet-300',  bg: 'bg-violet-900/20',  border: 'border-violet-500/50',  icon: Search },
  'hạ tầng':    { color: 'text-violet-300',  bg: 'bg-violet-900/20',  border: 'border-violet-500/50',  icon: Search },
  'pivot':      { color: 'text-violet-300',  bg: 'bg-violet-900/20',  border: 'border-violet-500/50',  icon: Search },
  'indicators': { color: 'text-amber-300',   bg: 'bg-amber-900/20',   border: 'border-amber-500/50',   icon: Shield },
  'ioc':        { color: 'text-amber-300',   bg: 'bg-amber-900/20',   border: 'border-amber-500/50',   icon: Shield },
  'đề xuất':    { color: 'text-emerald-300', bg: 'bg-emerald-900/20', border: 'border-emerald-500/50', icon: Lightbulb },
  'hành động':  { color: 'text-emerald-300', bg: 'bg-emerald-900/20', border: 'border-emerald-500/50', icon: Lightbulb },
  'recommend':  { color: 'text-emerald-300', bg: 'bg-emerald-900/20', border: 'border-emerald-500/50', icon: Lightbulb },
  'kết luận':   { color: 'text-blue-300',    bg: 'bg-blue-900/20',    border: 'border-blue-500/50',    icon: FileText },
}

function getSectionTheme(text: string) {
  const lower = text.toLowerCase()
  for (const [key, theme] of Object.entries(SECTION_THEMES)) {
    if (lower.includes(key)) return theme
  }
  return { color: 'text-gray-200', bg: 'bg-gray-800/30', border: 'border-gray-600/50', icon: FileText }
}

// A titled/iconed section divider, shared by h1/h2/h3 so any heading level reads well.
function sectionHeading(children: React.ReactNode) {
  const theme = getSectionTheme(String(children))
  const Icon = theme.icon
  return (
    <div className={`flex items-center gap-2.5 mt-6 mb-3 pb-2 border-b ${theme.border} first:mt-0`}>
      <span className={`flex items-center justify-center h-7 w-7 rounded-md ${theme.bg} border ${theme.border} shrink-0`}>
        <Icon className={`h-3.5 w-3.5 ${theme.color}`} />
      </span>
      <span className={`text-[15px] font-bold ${theme.color} tracking-tight`}>{children}</span>
    </div>
  )
}

const components: Components = {
  h1: ({ children }) => sectionHeading(children),
  h2: ({ children }) => sectionHeading(children),
  h3: ({ children }) => (
    <h3 className="text-[13.5px] font-semibold text-gray-200 mt-4 mb-1.5 flex items-center gap-1.5">
      <span className="w-1 h-3.5 rounded-full bg-gray-500 inline-block" />
      {children}
    </h3>
  ),
  p: ({ children }) => <p className="text-[13.5px] text-gray-300 leading-[1.75] mb-3">{children}</p>,
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
    if (/\bhigh\b/i.test(text)) return <strong className="font-semibold text-orange-400">{children}</strong>
    if (/medium/i.test(text)) return <strong className="font-semibold text-yellow-400">{children}</strong>
    if (/\blow\b|\binfo\b/i.test(text)) return <strong className="font-semibold text-emerald-400">{children}</strong>
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
  td: ({ children }) => <td className="px-3 py-2 text-gray-300 align-top">{children}</td>,
  a: ({ href, children }) => (
    <a href={href} target="_blank" rel="noopener noreferrer"
      className="text-sky-400 hover:text-sky-300 underline underline-offset-2 decoration-sky-600/50">{children}</a>
  ),
}

export default function AiMarkdown({ content, className = '' }: { content: string; className?: string }) {
  return (
    <div className={`ai-markdown ${className}`} style={{ fontFamily: AI_FONT }}>
      <ReactMarkdown components={components} remarkPlugins={[remarkGfm]}>{content}</ReactMarkdown>
    </div>
  )
}
