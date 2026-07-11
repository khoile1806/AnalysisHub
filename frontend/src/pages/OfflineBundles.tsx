import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Package,
  Download,
  Monitor,
  Terminal,
  Globe,
  Info,
  CheckSquare,
  Square,
  FileText,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { toolsApi } from '@/api/tools'
import { casesApi } from '@/api/cases'
import { generateOfflineBundle, type BundleReference } from '@/api/offline_bundles'
import { PLAYBOOK_CHECKLISTS } from '@/data/playbookChecklists'
import { COMPLIANCE_SECTIONS } from '@/data/complianceChecklist'
import { PLAYBOOKS } from '@/data/playbooks'

// All embeddable checklists, normalised to one shape: the IR playbook checklists
// plus the compliance audit (sourced from COMPLIANCE_SECTIONS, not the empty
// PLAYBOOK_CHECKLISTS['compliance']). Both share items:{win,linux}.
type GuideItem = { label: string; commands: string[]; purpose?: string; priority?: string }
type GuideSection = { phase: string; label: string; items: { win: GuideItem[]; linux: GuideItem[] } }
const CHECKLIST_SOURCES: Record<string, { label: string; sections: GuideSection[] }> = (() => {
  const src: Record<string, { label: string; sections: GuideSection[] }> = {}
  Object.keys(PLAYBOOK_CHECKLISTS).forEach((k) => {
    if (k === 'compliance') return
    src[k] = { label: PLAYBOOKS.find((p) => p.id === k)?.title || k, sections: PLAYBOOK_CHECKLISTS[k] as unknown as GuideSection[] }
  })
  src['compliance'] = { label: 'Compliance & Security Audit', sections: COMPLIANCE_SECTIONS as unknown as GuideSection[] }
  return src
})()
import { CategoryBadge, PlatformBadge } from '@/components/StatusBadge'
import { formatBytes, getErrorMessage } from '@/lib/utils'

type Platform = 'windows' | 'linux' | 'both'

const PLATFORM_OPTIONS: { value: Platform; label: string; icon: React.ReactNode; desc: string }[] = [
  {
    value: 'windows',
    label: 'Windows',
    icon: <Monitor className="w-4 h-4" />,
    desc: 'ZIP: agent-offline.exe + run.bat',
  },
  {
    value: 'linux',
    label: 'Linux',
    icon: <Terminal className="w-4 h-4" />,
    desc: 'ZIP: agent-offline-linux + run.sh',
  },
  {
    value: 'both',
    label: 'Both',
    icon: <Globe className="w-4 h-4" />,
    desc: 'ZIP with Windows + Linux binaries',
  },
]

export default function OfflineBundles() {
  const [bundleName, setBundleName] = useState('')
  const [platform, setPlatform] = useState<Platform>('windows')
  const [selectedIDs, setSelectedIDs] = useState<Set<string>>(new Set())
  const [generating, setGenerating] = useState(false)
  const [search, setSearch] = useState('')
  const [customYaraName, setCustomYaraName] = useState<string>('')
  const [customYaraContent, setCustomYaraContent] = useState<string>('')
  const [caseId, setCaseId] = useState('')
  const [selectedChecklists, setSelectedChecklists] = useState<Set<string>>(new Set())
  const [selectedPlaybooks, setSelectedPlaybooks] = useState<Set<string>>(new Set())

  // Options for the embeddable hunting guide (frontend-static data).
  const checklistOptions = Object.entries(CHECKLIST_SOURCES).map(([id, v]) => ({
    id,
    label: v.label,
  }))

  const { data: tools = [], isLoading } = useQuery({
    queryKey: ['tools'],
    queryFn: () => toolsApi.list(),
  })
  const { data: cases = [] } = useQuery({
    queryKey: ['cases'],
    queryFn: () => casesApi.list(),
  })

  const filtered = tools.filter((t) => {
    if (!search) return true
    const q = search.toLowerCase()
    return t.name.toLowerCase().includes(q) || t.category.toLowerCase().includes(q)
  })

  const toggleTool = (id: string) => {
    setSelectedIDs((prev) => {
      const next = new Set(prev)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  const toggleAll = () => {
    if (selectedIDs.size === filtered.length) {
      setSelectedIDs(new Set())
    } else {
      setSelectedIDs(new Set(filtered.map((t) => t.id)))
    }
  }

  const handleGenerate = async () => {
    if (!bundleName.trim()) {
      toast.error('Please enter a bundle name')
      return
    }
    if (selectedIDs.size === 0) {
      toast.error('Select at least one tool')
      return
    }

    setGenerating(true)
    const tid = toast.loading('Generating bundle…')
    try {
      const selectedCase = cases.find((c) => c.id === caseId)

      // Build the embedded hunting guide from the selected checklists + playbooks.
      let reference: BundleReference | undefined
      if (selectedChecklists.size > 0 || selectedPlaybooks.size > 0) {
        reference = {
          checklists: Array.from(selectedChecklists).map((key) => ({
            id: key,
            name: CHECKLIST_SOURCES[key]?.label || key,
            sections: (CHECKLIST_SOURCES[key]?.sections || []).map((s) => ({
              phase: s.phase,
              label: s.label,
              items: [
                ...s.items.win.map((it) => ({ label: it.label, commands: it.commands, purpose: it.purpose, priority: it.priority, platform: 'windows' })),
                ...s.items.linux.map((it) => ({ label: it.label, commands: it.commands, purpose: it.purpose, priority: it.priority, platform: 'linux' })),
              ],
            })),
          })),
          playbooks: Array.from(selectedPlaybooks).map((id) => {
            const p = PLAYBOOKS.find((x) => x.id === id)!
            return { id: p.id, title: p.title, description: p.description, goals: p.goals, steps: p.steps, references: p.references }
          }),
        }
      }

      await generateOfflineBundle({
        name: bundleName.trim(),
        tool_ids: Array.from(selectedIDs),
        platform,
        case_id: caseId || undefined,
        case_name: selectedCase?.name || undefined,
        custom_yara_rule: customYaraContent || undefined,
        reference,
      })
      toast.success('Bundle downloaded!', { id: tid })
    } catch (err) {
      toast.error(getErrorMessage(err), { id: tid })
    } finally {
      setGenerating(false)
    }
  }

  return (
    <div className="flex flex-col h-full">
      {/* Page header */}
      <div className="flex items-center gap-3 px-6 py-4 border-b border-border flex-shrink-0">
        <Package className="w-5 h-5 text-purple-400" />
        <div>
          <h1 className="text-lg font-bold text-foreground">Offline Bundles</h1>
          <p className="text-xs text-muted-foreground">
            Bundle selected tools into a self-contained package for offline hunting
          </p>
        </div>
      </div>

      <div className="flex flex-1 overflow-hidden">
        {/* Left: tool selector */}
        <div className="flex flex-col w-[55%] border-r border-border overflow-hidden">
          <div className="flex items-center gap-3 px-4 py-3 border-b border-border">
            <input
              type="text"
              placeholder="Search tools…"
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="flex-1 bg-gray-800 border border-gray-700 text-gray-100 rounded px-3 py-1.5 text-sm outline-none focus:border-emerald-500/50"
            />
            <button
              onClick={toggleAll}
              className="flex items-center gap-1.5 text-xs text-muted-foreground hover:text-foreground transition-colors px-2 py-1"
            >
              {selectedIDs.size === filtered.length && filtered.length > 0 ? (
                <CheckSquare className="w-4 h-4" />
              ) : (
                <Square className="w-4 h-4" />
              )}
              {selectedIDs.size === filtered.length && filtered.length > 0 ? 'Deselect all' : 'Select all'}
            </button>
            <span className="text-xs text-muted-foreground">
              {selectedIDs.size} selected
            </span>
          </div>

          <div className="flex-1 overflow-y-auto px-4 py-2">
            {isLoading ? (
              <div className="flex items-center justify-center h-32 text-muted-foreground text-sm">
                Loading tools…
              </div>
            ) : filtered.length === 0 ? (
              <div className="flex flex-col items-center justify-center h-32 text-muted-foreground text-sm gap-2">
                <Package className="w-8 h-8 opacity-30" />
                <span>No tools found</span>
              </div>
            ) : (
              <div className="space-y-1.5">
                {filtered.map((tool) => {
                  const selected = selectedIDs.has(tool.id)
                  return (
                    <div
                      key={tool.id}
                      onClick={() => toggleTool(tool.id)}
                      className={`flex items-center gap-3 p-3 rounded-lg border cursor-pointer transition-colors ${
                        selected
                          ? 'border-purple-500/50 bg-purple-500/5'
                          : 'border-border hover:border-border/70 bg-card'
                      }`}
                    >
                      <div className={`w-4 h-4 rounded border flex items-center justify-center flex-shrink-0 transition-colors ${
                        selected ? 'bg-purple-500 border-purple-500' : 'border-muted-foreground/40'
                      }`}>
                        {selected && (
                          <svg className="w-3 h-3 text-white" fill="none" viewBox="0 0 24 24" stroke="currentColor" strokeWidth={3}>
                            <path strokeLinecap="round" strokeLinejoin="round" d="M5 13l4 4L19 7" />
                          </svg>
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2">
                          <span className="font-medium text-sm text-foreground truncate">{tool.name}</span>
                          <span className="text-xs text-muted-foreground">{tool.version}</span>
                        </div>
                        {tool.description && (
                          <p className="text-xs text-muted-foreground mt-0.5 truncate">{tool.description}</p>
                        )}
                      </div>
                      <div className="flex items-center gap-1.5 flex-shrink-0">
                        <CategoryBadge category={tool.category} />
                        <PlatformBadge platform={tool.platform} />
                        {tool.file_size > 0 && (
                          <span className="text-xs text-muted-foreground">{formatBytes(tool.file_size)}</span>
                        )}
                      </div>
                    </div>
                  )
                })}
              </div>
            )}
          </div>
        </div>

        {/* Right: bundle config */}
        <div className="flex flex-col w-[45%] overflow-y-auto">
          <div className="flex-1 px-6 py-5 space-y-6">
            {/* Bundle name */}
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-2">Bundle Name</label>
              <input
                type="text"
                placeholder="e.g. WebServer Hunting — Incident #42"
                value={bundleName}
                onChange={(e) => setBundleName(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 text-gray-100 rounded-lg px-3 py-2 text-sm outline-none focus:border-purple-500/50 transition-colors"
              />
            </div>

            {/* Case linkage — so the returned report auto-correlates back */}
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-2">Link to Case <span className="text-gray-500 font-normal">(optional)</span></label>
              <select
                value={caseId}
                onChange={(e) => setCaseId(e.target.value)}
                className="w-full bg-gray-800 border border-gray-700 text-gray-100 rounded-lg px-3 py-2 text-sm outline-none focus:border-purple-500/50 transition-colors"
              >
                <option value="">— No case —</option>
                {cases.map((c) => (
                  <option key={c.id} value={c.id}>{c.name}</option>
                ))}
              </select>
              <p className="text-[11px] text-gray-500 mt-1">The case is baked into the bundle so the returned report routes back to it.</p>
            </div>

            {/* Hunting guide: embed checklists + reference playbooks */}
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-2">Hunting Guide <span className="text-gray-500 font-normal">(optional)</span></label>
              <p className="text-[11px] text-gray-500 mb-2">Embed checklists & playbooks so the responder can follow them on the target — viewable in the agent's <b>Guide</b> tab.</p>
              {checklistOptions.length > 0 && (
                <div className="mb-2">
                  <div className="text-[11px] font-semibold text-gray-400 mb-1">Checklists (Evidence & Compliance)</div>
                  <div className="max-h-28 overflow-y-auto rounded-lg border border-gray-700 bg-gray-800/60 p-2 space-y-1">
                    {checklistOptions.map((o) => (
                      <label key={o.id} className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer hover:text-white">
                        <input type="checkbox" checked={selectedChecklists.has(o.id)}
                          onChange={() => setSelectedChecklists((prev) => { const n = new Set(prev); n.has(o.id) ? n.delete(o.id) : n.add(o.id); return n })} />
                        {o.label}
                      </label>
                    ))}
                  </div>
                </div>
              )}
              <div>
                <div className="text-[11px] font-semibold text-gray-400 mb-1">Reference Playbooks</div>
                <div className="max-h-28 overflow-y-auto rounded-lg border border-gray-700 bg-gray-800/60 p-2 space-y-1">
                  {PLAYBOOKS.map((p) => (
                    <label key={p.id} className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer hover:text-white">
                      <input type="checkbox" checked={selectedPlaybooks.has(p.id)}
                        onChange={() => setSelectedPlaybooks((prev) => { const n = new Set(prev); n.has(p.id) ? n.delete(p.id) : n.add(p.id); return n })} />
                      {p.title}
                    </label>
                  ))}
                </div>
              </div>
            </div>

            {/* Platform */}
            <div>
              <label className="block text-sm font-semibold text-foreground mb-2">Target Platform</label>
              <div className="grid grid-cols-3 gap-2">
                {PLATFORM_OPTIONS.map((opt) => (
                  <button
                    key={opt.value}
                    onClick={() => setPlatform(opt.value)}
                    className={`flex flex-col items-center gap-1.5 p-3 rounded-lg border text-sm transition-colors ${
                      platform === opt.value
                        ? 'border-purple-500/60 bg-purple-500/10 text-purple-300'
                        : 'border-border bg-card text-muted-foreground hover:border-border/70'
                    }`}
                  >
                    {opt.icon}
                    <span className="font-medium">{opt.label}</span>
                    <span className="text-xs text-center leading-tight opacity-70">{opt.desc}</span>
                  </button>
                ))}
              </div>
            </div>

            {/* Custom YARA Rule */}
            <div>
              <label className="block text-sm font-semibold text-gray-200 mb-2">Custom YARA Rule (Optional)</label>
              <div className="flex items-center gap-2">
                <input 
                  type="file" 
                  accept=".yar,.yara"
                  className="hidden"
                  id="offline-yara-upload"
                  disabled={generating}
                  onChange={(e) => {
                    const file = e.target.files?.[0]
                    if (!file) return
                    setCustomYaraName(file.name)
                    const reader = new FileReader()
                    reader.onload = (ev) => {
                      setCustomYaraContent(ev.target?.result as string)
                    }
                    reader.readAsText(file)
                  }}
                />
                <label 
                  htmlFor="offline-yara-upload"
                  className={`btn-secondary py-1.5 px-3 text-xs cursor-pointer ${generating ? 'opacity-50 pointer-events-none' : ''}`}
                >
                  Choose .yar File
                </label>
                {customYaraName ? (
                  <div className="flex items-center gap-2 bg-purple-500/10 text-purple-400 px-2 py-1 rounded text-xs border border-purple-500/20 flex-1">
                    <FileText className="w-3 h-3" />
                    <span className="truncate flex-1">{customYaraName}</span>
                    <button 
                      onClick={() => {
                        setCustomYaraName('')
                        setCustomYaraContent('')
                      }}
                      className="ml-2 text-purple-400 hover:text-purple-300"
                      disabled={generating}
                    >
                      &times;
                    </button>
                  </div>
                ) : (
                  <span className="text-xs text-gray-500 flex-1">Scans alongside built-in rules</span>
                )}
              </div>
            </div>

            {/* Summary */}
            <div className="bg-gray-800/50 rounded-lg border border-gray-700 p-4 space-y-3">
              <h3 className="text-sm font-semibold text-gray-200">Bundle Contents</h3>
              <div className="space-y-1.5 text-xs text-gray-400">
                {platform === 'windows' || platform === 'both' ? (
                  <div className="flex items-center gap-2">
                    <Monitor className="w-3.5 h-3.5 text-blue-400" />
                    <span>agent-offline.exe + run.bat (Windows)</span>
                  </div>
                ) : null}
                {platform === 'linux' || platform === 'both' ? (
                  <div className="flex items-center gap-2">
                    <Terminal className="w-3.5 h-3.5 text-green-400" />
                    <span>agent-offline-linux + run.sh (Linux)</span>
                  </div>
                ) : null}
                <div className="flex items-center gap-2">
                  <Package className="w-3.5 h-3.5 text-purple-400" />
                  <span>{selectedIDs.size} tool(s) selected</span>
                </div>
                <div className="flex items-center gap-2">
                  <Download className="w-3.5 h-3.5 text-yellow-400" />
                  <span>bundle.json manifest + README.txt</span>
                </div>
              </div>
            </div>

            {/* Info box */}
            <div className="flex gap-2.5 bg-blue-500/5 border border-blue-500/20 rounded-lg p-3">
              <Info className="w-4 h-4 text-blue-400 flex-shrink-0 mt-0.5" />
              <div className="text-xs text-blue-300/80 leading-relaxed space-y-1">
                <p><strong>Completely offline.</strong> No internet connection needed on the target machine.</p>
                <p>Windows: double-click <code className="bg-blue-900/30 px-1 rounded">run.bat</code> to launch UI in browser.</p>
                <p>Linux headless (SSH): use <code className="bg-blue-900/30 px-1 rounded">--cli</code> flag for interactive terminal.</p>
                <p>Results saved as <code className="bg-blue-900/30 px-1 rounded">report-&lt;host&gt;-&lt;date&gt;.html</code> + <code className="bg-blue-900/30 px-1 rounded">.json</code></p>
              </div>
            </div>
          </div>

          {/* Generate button */}
          <div className="px-6 py-4 border-t border-border flex-shrink-0">
            <button
              onClick={handleGenerate}
              disabled={generating || selectedIDs.size === 0 || !bundleName.trim()}
              className="w-full flex items-center justify-center gap-2 bg-purple-600 hover:bg-purple-500 disabled:opacity-40 disabled:cursor-not-allowed text-white font-semibold py-2.5 rounded-lg transition-colors text-sm"
            >
              {generating ? (
                <>
                  <svg className="w-4 h-4 animate-spin" viewBox="0 0 24 24" fill="none">
                    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" />
                    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8v8H4z" />
                  </svg>
                  Generating…
                </>
              ) : (
                <>
                  <Download className="w-4 h-4" />
                  Generate &amp; Download Bundle
                </>
              )}
            </button>
            {selectedIDs.size === 0 && (
              <p className="text-xs text-muted-foreground text-center mt-2">
                Select tools from the left panel
              </p>
            )}
          </div>
        </div>
      </div>
    </div>
  )
}
