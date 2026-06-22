import { useState } from 'react'
import { Link } from 'react-router-dom'
import {
  BookOpen, TerminalSquare, ShieldAlert, Briefcase, ChevronRight,
  Target, Crosshair, Server, Lock, Download, HardDrive, Cpu, Scan, FileText, Activity, Search, ExternalLink, Play, CheckSquare
} from 'lucide-react'
import { PLAYBOOKS, type Playbook } from '@/data/playbooks'

const ICONS: Record<string, any> = {
  TerminalSquare, ShieldAlert, Briefcase, Target, Crosshair, Server,
  Lock, Download, HardDrive, Cpu, Scan, FileText, Activity, Search
}

const COLORS: Record<string, { bg: string; border: string; text: string }> = {
  rose: { bg: 'bg-rose-500/10', border: 'border-rose-500/30', text: 'text-rose-400' },
  emerald: { bg: 'bg-emerald-500/10', border: 'border-emerald-500/30', text: 'text-emerald-400' },
  blue: { bg: 'bg-blue-500/10', border: 'border-blue-500/30', text: 'text-blue-400' }
}

export default function PlaybooksPage() {
  const [selectedPlaybook, setSelectedPlaybook] = useState<Playbook | null>(null)

  if (selectedPlaybook) {
    const Icon = ICONS[selectedPlaybook.icon] || BookOpen
    const col = COLORS[selectedPlaybook.color] || COLORS.blue

    return (
      <div className="space-y-6">
        {/* Breadcrumb */}
        <button
          onClick={() => setSelectedPlaybook(null)}
          className="text-sm text-gray-500 hover:text-gray-300 flex items-center gap-1 transition"
        >
          <ChevronRight className="h-4 w-4 rotate-180" /> Back to Playbooks
        </button>

        {/* Header */}
        <div className={`p-6 md:p-8 rounded-xl border ${col.border} bg-gray-900/40 relative overflow-hidden`}>
          <div className={`absolute top-0 right-0 w-64 h-64 ${col.bg} blur-3xl opacity-20 pointer-events-none rounded-full transform translate-x-1/3 -translate-y-1/3`} />
          <div className="relative z-10 flex flex-col md:flex-row md:items-start justify-between gap-6">
            <div>
              <div className="flex items-center gap-3 mb-3">
                <span className={`inline-flex items-center justify-center w-12 h-12 rounded-xl ${col.bg} border ${col.border}`}>
                  <Icon className={`h-6 w-6 ${col.text}`} />
                </span>
                <h1 className="text-3xl font-bold text-gray-100">{selectedPlaybook.title}</h1>
              </div>
              <p className="text-gray-400 text-sm max-w-2xl leading-relaxed mb-4">
                {selectedPlaybook.description}
              </p>
              <div className="flex flex-wrap gap-2 text-xs">
                <span className={`px-2.5 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300`}>
                  Type: <span className="font-semibold text-gray-200">{selectedPlaybook.type}</span>
                </span>
                <span className={`px-2.5 py-1 rounded bg-gray-800 border border-gray-700 text-gray-300`}>
                  MITRE: <span className="font-mono text-gray-200">{selectedPlaybook.mitre}</span>
                </span>
                {selectedPlaybook.platforms.map(p => (
                  <span key={p} className={`px-2.5 py-1 rounded bg-gray-800 border border-gray-700 text-gray-400`}>
                    {p}
                  </span>
                ))}
              </div>
            </div>
            
            <div className="shrink-0 flex flex-col gap-3">
              <Link
                to={`/collection-checklist?playbook=${selectedPlaybook.id}`}
                className={`inline-flex items-center justify-center gap-2 px-6 py-3 rounded-lg text-sm font-semibold transition shadow-lg 
                  bg-${selectedPlaybook.color}-600 hover:bg-${selectedPlaybook.color}-500 text-white shadow-${selectedPlaybook.color}-500/20`}
                style={{ backgroundColor: selectedPlaybook.color === 'rose' ? '#e11d48' : selectedPlaybook.color === 'emerald' ? '#059669' : '#2563eb' }}
              >
                <Play className="h-4 w-4" />
                Run Playbook Checklist
              </Link>
              <p className="text-[11px] text-gray-500 text-center max-w-[200px]">
                Open the automated evidence-collection interface for this scenario
              </p>
            </div>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* Main timeline */}
          <div className="lg:col-span-2 space-y-6">
            <h2 className="text-lg font-bold text-gray-200 border-b border-gray-800 pb-2">Execution Flow</h2>
            <div className="relative pl-6 space-y-8 before:absolute before:inset-0 before:ml-8 before:-translate-x-px md:before:mx-auto md:before:translate-x-0 before:h-full before:w-0.5 before:bg-gradient-to-b before:from-transparent before:via-gray-800 before:to-transparent">
              {selectedPlaybook.steps.map((step, idx) => {
                const StepIcon = step.icon ? ICONS[step.icon] : CheckSquare
                return (
                  <div key={idx} className="relative flex items-start gap-6">
                    <div className={`shrink-0 z-10 flex items-center justify-center w-10 h-10 rounded-full bg-gray-900 border ${col.border} shadow-lg shadow-black/50`}>
                      {StepIcon ? <StepIcon className={`h-4 w-4 ${col.text}`} /> : <span className={`text-sm font-bold ${col.text}`}>{idx + 1}</span>}
                    </div>
                    <div className="flex-1 bg-gray-900/40 border border-gray-800 rounded-xl p-5 hover:bg-gray-900/60 transition group">
                      <h3 className="text-base font-bold text-gray-200 mb-2 group-hover:text-white transition">{step.title}</h3>
                      <div className="text-sm text-gray-400 leading-relaxed">
                        {step.content.split('\n').map((line, i) => (
                          <p key={i} className={i > 0 ? 'mt-2' : ''} dangerouslySetInnerHTML={{ __html: line.replace(/\*\*(.*?)\*\*/g, '<strong class="text-gray-200">$1</strong>') }} />
                        ))}
                      </div>
                    </div>
                  </div>
                )
              })}
            </div>
          </div>

          {/* Sidebar (Goals & References) */}
          <div className="space-y-6">
            <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
              <h2 className="text-sm font-bold text-gray-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                <Target className="h-4 w-4 text-gray-500" /> Objectives
              </h2>
              <ul className="space-y-3">
                {selectedPlaybook.goals.map((goal, idx) => (
                  <li key={idx} className="flex items-start gap-2 text-sm text-gray-400">
                    <div className={`mt-1.5 w-1.5 h-1.5 rounded-full ${col.bg} border ${col.border} shrink-0`} />
                    <span className="leading-snug">{goal}</span>
                  </li>
                ))}
              </ul>
            </div>

            {selectedPlaybook.references && selectedPlaybook.references.length > 0 && (
              <div className="bg-gray-900/40 border border-gray-800 rounded-xl p-5">
                <h2 className="text-sm font-bold text-gray-200 uppercase tracking-wider mb-4 flex items-center gap-2">
                  <BookOpen className="h-4 w-4 text-gray-500" /> References & Frameworks
                </h2>
                <div className="space-y-3">
                  {selectedPlaybook.references.map((ref, idx) => (
                    <a
                      key={idx}
                      href={ref.url}
                      target="_blank"
                      rel="noreferrer"
                      className="block group"
                    >
                      <div className="flex items-start justify-between gap-2 p-3 rounded bg-gray-900/50 border border-gray-800 hover:border-gray-700 transition">
                        <span className="text-sm text-gray-300 group-hover:text-blue-400 transition">{ref.title}</span>
                        <ExternalLink className="h-3.5 w-3.5 text-gray-600 group-hover:text-blue-400 shrink-0 mt-0.5" />
                      </div>
                    </a>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    )
  }

  // Grid view
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
          <BookOpen className="h-6 w-6 text-emerald-400" />
          Playbooks Library
        </h1>
        <p className="text-sm text-gray-500 mt-1">
          Interactive DFIR workflows and automated checklists for incident response.
        </p>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-5">
        {PLAYBOOKS.map((playbook) => {
          const Icon = ICONS[playbook.icon] || BookOpen
          const col = COLORS[playbook.color] || COLORS.blue
          return (
            <div
              key={playbook.id}
              onClick={() => setSelectedPlaybook(playbook)}
              className={`group cursor-pointer p-6 rounded-xl border ${col.border} bg-gray-900/30 hover:bg-gray-900/60 transition shadow-lg overflow-hidden relative`}
            >
              <div className={`absolute top-0 right-0 w-32 h-32 ${col.bg} blur-2xl opacity-0 group-hover:opacity-40 transition-opacity pointer-events-none rounded-full transform translate-x-1/2 -translate-y-1/2`} />
              
              <div className="flex items-start justify-between mb-4">
                <span className={`inline-flex items-center justify-center w-12 h-12 rounded-lg ${col.bg} border ${col.border}`}>
                  <Icon className={`h-6 w-6 ${col.text}`} />
                </span>
                <span className="text-[10px] uppercase font-bold tracking-wider text-gray-500 px-2 py-1 rounded bg-gray-800">
                  {playbook.type}
                </span>
              </div>
              
              <h3 className="text-lg font-bold text-gray-200 mb-2 group-hover:text-white transition">{playbook.title}</h3>
              <p className="text-sm text-gray-500 line-clamp-3 mb-4 leading-relaxed min-h-[4rem]">
                {playbook.description}
              </p>
              
              <div className="flex items-center justify-between text-xs border-t border-gray-800 pt-4">
                <span className="text-gray-400 flex items-center gap-1.5">
                  <Target className="h-3.5 w-3.5" /> {playbook.steps.length} steps
                </span>
                <span className={`flex items-center gap-1 ${col.text} font-medium group-hover:underline`}>
                  Open <ChevronRight className="h-3 w-3" />
                </span>
              </div>
            </div>
          )
        })}
      </div>
    </div>
  )
}
