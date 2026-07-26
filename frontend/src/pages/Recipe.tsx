import { useEffect, useMemo, useRef, useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Wand2, Binary, Plus, X, ArrowUp, ArrowDown, Copy, Download, Search,
  Play, Trash2, Loader2, AlertTriangle, Sparkles,
} from 'lucide-react'
import toast from 'react-hot-toast'
import {
  forgeApi,
  type ForgeArg, type ForgeOp, type ForgeResult, type ForgeRecipeStep,
} from '@/api/forge'
import { copyToClipboard, getErrorMessage, formatBytes } from '@/lib/utils'

// Decoder / Recipe — a CyberChef-style transform workbench. Pick operations
// from the palette, stack them into an ordered recipe, and the backend runs
// them left-to-right on the input. Everything re-runs live (debounced) as the
// input, ops, args, or order change.

const MAGIC_OP = 'Magic (auto-detect)'
const DEBOUNCE_MS = 350

// A recipe step carries its own uid so the same op can appear twice and React
// keys / reorders stay stable regardless of position.
interface RecipeStep {
  uid: string
  op: string
  args: Record<string, string>
}

let uidSeq = 0
function nextUid(): string {
  uidSeq += 1
  return `s${uidSeq}_${Date.now().toString(36)}`
}

function seedArgs(op?: ForgeOp): Record<string, string> {
  const out: Record<string, string> = {}
  for (const a of op?.args ?? []) {
    out[a.key] = a.default ?? (a.type === 'bool' ? 'false' : '')
  }
  return out
}

export default function RecipePage() {
  const [input, setInput] = useState('')
  const [recipe, setRecipe] = useState<RecipeStep[]>([])
  const [search, setSearch] = useState('')
  const [result, setResult] = useState<ForgeResult | null>(null)
  const [runError, setRunError] = useState<string | null>(null)
  const [running, setRunning] = useState(false)

  const { data: ops, isLoading: opsLoading, isError: opsError, error: opsErr } = useQuery({
    queryKey: ['forge-operations'],
    queryFn: forgeApi.operations,
    staleTime: 5 * 60_000,
  })

  const opsByName = useMemo(() => {
    const m = new Map<string, ForgeOp>()
    for (const o of ops ?? []) m.set(o.name, o)
    return m
  }, [ops])

  // Group the palette by category, filtered by the search box (name + desc).
  const grouped = useMemo(() => {
    const q = search.trim().toLowerCase()
    const groups = new Map<string, ForgeOp[]>()
    for (const o of ops ?? []) {
      if (q && !o.name.toLowerCase().includes(q) && !o.description.toLowerCase().includes(q)) continue
      const arr = groups.get(o.category) ?? []
      arr.push(o)
      groups.set(o.category, arr)
    }
    return Array.from(groups.entries())
  }, [ops, search])

  // Guards against a slow earlier run clobbering a newer one's output.
  const runSeq = useRef(0)

  const runRecipe = async (inp: string, steps: RecipeStep[]) => {
    if (!inp && steps.length === 0) {
      setResult(null)
      setRunError(null)
      return
    }
    const payload: ForgeRecipeStep[] = steps.map((s) => ({ op: s.op, args: s.args }))
    const seq = ++runSeq.current
    setRunning(true)
    try {
      const res = await forgeApi.run(inp, payload)
      if (seq !== runSeq.current) return // a newer run superseded this one
      setResult(res.result ?? null)
      setRunError(res.success ? null : (res.error ?? 'Recipe failed'))
    } catch (e) {
      if (seq !== runSeq.current) return
      setRunError(getErrorMessage(e))
    } finally {
      if (seq === runSeq.current) setRunning(false)
    }
  }

  // Live run: re-run whenever input or recipe (ops/args/order) changes, debounced.
  const recipeKey = JSON.stringify(recipe.map((s) => ({ op: s.op, args: s.args })))
  useEffect(() => {
    const t = setTimeout(() => { void runRecipe(input, recipe) }, DEBOUNCE_MS)
    return () => clearTimeout(t)
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [input, recipeKey])

  const appendOp = (name: string) => {
    setRecipe((prev) => [...prev, { uid: nextUid(), op: name, args: seedArgs(opsByName.get(name)) }])
  }

  const removeStep = (uid: string) => setRecipe((prev) => prev.filter((s) => s.uid !== uid))

  const moveStep = (idx: number, dir: -1 | 1) => {
    setRecipe((prev) => {
      const to = idx + dir
      if (to < 0 || to >= prev.length) return prev
      const next = [...prev]
      ;[next[idx], next[to]] = [next[to], next[idx]]
      return next
    })
  }

  const setStepArg = (uid: string, key: string, value: string) => {
    setRecipe((prev) => prev.map((s) => (s.uid === uid ? { ...s, args: { ...s.args, [key]: value } } : s)))
  }

  const clearRecipe = () => setRecipe([])

  const runMagic = () => {
    // The one-click "just decode whatever this is". Append Magic and let the
    // live-run effect fire; also kick an immediate run for responsiveness.
    const next: RecipeStep[] = [...recipe, { uid: nextUid(), op: MAGIC_OP, args: seedArgs(opsByName.get(MAGIC_OP)) }]
    setRecipe(next)
    void runRecipe(input, next)
  }

  const handleCopy = async () => {
    if (!result) return
    const ok = await copyToClipboard(result.output)
    ok ? toast.success('Output copied') : toast.error('Copy failed')
  }

  const handleDownload = () => {
    if (!result) return
    const blob = new Blob([result.output], { type: 'text/plain;charset=utf-8' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = 'forge-output.txt'
    document.body.appendChild(a)
    a.click()
    document.body.removeChild(a)
    URL.revokeObjectURL(url)
  }

  // Map a step's error (if any) back to its recipe row by position.
  const stepErrors = result?.steps ?? []
  const failingIdx = stepErrors.findIndex((s) => s.error)

  return (
    <div className="space-y-4">
      {/* Header */}
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div>
          <h1 className="flex items-center gap-2 text-xl font-bold text-gray-100">
            <Wand2 className="h-5 w-5 text-emerald-400" /> Decoder / Recipe
          </h1>
          <p className="text-sm text-gray-500 mt-0.5">
            Stack encode / decode / crypto / hashing operations into an ordered recipe and run them
            live against your input — a CyberChef-style transform workbench.
          </p>
        </div>
        <div className="flex items-center gap-2">
          <button className="btn-secondary" onClick={runMagic} title="Append Magic (auto-detect) and run">
            <Sparkles className="h-4 w-4 text-emerald-400" /> Magic
          </button>
          <button className="btn-primary" onClick={() => void runRecipe(input, recipe)} disabled={running}>
            {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />} Run
          </button>
        </div>
      </div>

      {/* Three-area workbench: palette | recipe | io. Stacks on narrow screens. */}
      <div className="grid grid-cols-1 lg:grid-cols-12 gap-4">
        {/* Operations palette */}
        <div className="lg:col-span-3 card p-0 flex flex-col max-h-[80vh]">
          <div className="p-3 border-b border-gray-800">
            <div className="text-sm font-semibold text-gray-200 mb-2">Operations</div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input
                className="input pl-8"
                placeholder="Search operations…"
                value={search}
                onChange={(e) => setSearch(e.target.value)}
              />
            </div>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-4">
            {opsLoading && (
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <Loader2 className="h-4 w-4 animate-spin text-emerald-400" /> Loading operations…
              </div>
            )}
            {opsError && (
              <div className="text-sm text-red-300">Failed to load operations: {getErrorMessage(opsErr)}</div>
            )}
            {!opsLoading && !opsError && grouped.length === 0 && (
              <div className="text-sm text-gray-500">No operations match “{search}”.</div>
            )}
            {grouped.map(([category, list]) => (
              <div key={category}>
                <h3 className="text-[10px] font-bold text-gray-500 uppercase tracking-widest mb-1.5">{category}</h3>
                <div className="flex flex-wrap gap-1.5">
                  {list.map((o) => (
                    <button
                      key={o.name}
                      onClick={() => appendOp(o.name)}
                      onDoubleClick={() => appendOp(o.name)}
                      title={o.description}
                      className="group inline-flex items-center gap-1 rounded border border-gray-700 bg-gray-800/60 px-2 py-1 text-[11px] text-gray-300 hover:border-emerald-600/60 hover:bg-emerald-900/20 hover:text-emerald-300 transition-colors"
                    >
                      <Plus className="h-3 w-3 text-gray-500 group-hover:text-emerald-400" />
                      {o.name}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Recipe */}
        <div className="lg:col-span-4 card p-0 flex flex-col max-h-[80vh]">
          <div className="p-3 border-b border-gray-800 flex items-center justify-between">
            <div className="text-sm font-semibold text-gray-200">
              Recipe {recipe.length > 0 && <span className="text-gray-500 font-normal">· {recipe.length}</span>}
            </div>
            <button
              className="inline-flex items-center gap-1 text-[11px] text-gray-400 hover:text-red-400 disabled:opacity-40"
              onClick={clearRecipe}
              disabled={recipe.length === 0}
            >
              <Trash2 className="h-3.5 w-3.5" /> Clear recipe
            </button>
          </div>
          <div className="flex-1 overflow-y-auto custom-scrollbar p-3 space-y-2">
            {recipe.length === 0 && (
              <div className="flex flex-col items-center justify-center h-full text-center py-10 text-gray-500">
                <Binary className="h-8 w-8 mb-2 text-gray-700" />
                <p className="text-sm">Add operations from the palette to build a recipe.</p>
              </div>
            )}
            {recipe.map((step, idx) => {
              const def = opsByName.get(step.op)
              const err = stepErrors[idx]?.error
              return (
                <div
                  key={step.uid}
                  className={`rounded-lg border bg-gray-800/40 ${err ? 'border-red-700/60' : 'border-gray-700'}`}
                >
                  <div className="flex items-center gap-2 px-2.5 py-1.5 border-b border-gray-700/60">
                    <span className="text-[10px] text-gray-500 font-mono w-5 shrink-0">{idx + 1}</span>
                    <span className="text-xs font-medium text-gray-200 truncate flex-1" title={def?.description}>
                      {step.op}
                    </span>
                    <button
                      className="p-1 text-gray-500 hover:text-emerald-400 disabled:opacity-30"
                      onClick={() => moveStep(idx, -1)}
                      disabled={idx === 0}
                      title="Move up"
                    >
                      <ArrowUp className="h-3.5 w-3.5" />
                    </button>
                    <button
                      className="p-1 text-gray-500 hover:text-emerald-400 disabled:opacity-30"
                      onClick={() => moveStep(idx, 1)}
                      disabled={idx === recipe.length - 1}
                      title="Move down"
                    >
                      <ArrowDown className="h-3.5 w-3.5" />
                    </button>
                    <button
                      className="p-1 text-gray-500 hover:text-red-400"
                      onClick={() => removeStep(step.uid)}
                      title="Remove"
                    >
                      <X className="h-3.5 w-3.5" />
                    </button>
                  </div>
                  {def?.args && def.args.length > 0 && (
                    <div className="p-2.5 space-y-2">
                      {def.args.map((arg) => (
                        <ArgInput
                          key={arg.key}
                          arg={arg}
                          value={step.args[arg.key] ?? ''}
                          onChange={(v) => setStepArg(step.uid, arg.key, v)}
                        />
                      ))}
                    </div>
                  )}
                  {err && (
                    <div className="px-2.5 py-1.5 text-[11px] text-red-300 border-t border-red-700/40 bg-red-900/20">
                      {err}
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        </div>

        {/* Input / Output */}
        <div className="lg:col-span-5 flex flex-col gap-4">
          {/* Input */}
          <div className="card p-3">
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm font-semibold text-gray-200">Input</div>
              <span className="text-[11px] text-gray-500 font-mono">{new Blob([input]).size} bytes</span>
            </div>
            <textarea
              className="input font-mono min-h-[140px] resize-y"
              placeholder="Paste a string to transform (Base64, hex, JWT, gzip, ciphertext…)"
              value={input}
              onChange={(e) => setInput(e.target.value)}
              spellCheck={false}
            />
          </div>

          {/* Output */}
          <div className="card p-3 flex-1 flex flex-col">
            <div className="flex items-center justify-between mb-2 gap-2">
              <div className="flex items-center gap-2 min-w-0">
                <div className="text-sm font-semibold text-gray-200">Output</div>
                {running && <Loader2 className="h-3.5 w-3.5 animate-spin text-emerald-400" />}
                {result?.binary && (
                  <span className="rounded border border-amber-700/50 bg-amber-900/30 px-1.5 py-0.5 text-[10px] font-mono uppercase tracking-wide text-amber-300">
                    Binary
                  </span>
                )}
              </div>
              <div className="flex items-center gap-2 shrink-0">
                {result && (
                  <span className="text-[11px] text-gray-500 font-mono">
                    {result.bytes.toLocaleString()} B · {formatBytes(result.bytes)}
                  </span>
                )}
                <button className="p-1.5 text-gray-400 hover:text-emerald-400 disabled:opacity-30" onClick={handleCopy} disabled={!result} title="Copy output">
                  <Copy className="h-4 w-4" />
                </button>
                <button className="p-1.5 text-gray-400 hover:text-emerald-400 disabled:opacity-30" onClick={handleDownload} disabled={!result} title="Download as .txt">
                  <Download className="h-4 w-4" />
                </button>
              </div>
            </div>

            {runError && (
              <div className="mb-2 flex items-start gap-2 rounded-lg border border-red-700/50 bg-red-900/20 px-3 py-2 text-xs text-red-300">
                <AlertTriangle className="h-4 w-4 shrink-0 mt-0.5" />
                <span>
                  {failingIdx >= 0
                    ? <>Step {failingIdx + 1} (<span className="font-mono">{recipe[failingIdx]?.op ?? stepErrors[failingIdx]?.op}</span>): {runError}</>
                    : runError}
                </span>
              </div>
            )}

            <pre className="flex-1 min-h-[160px] overflow-auto rounded-lg border border-gray-800 bg-gray-950/60 p-3 text-[12px] text-gray-200 font-mono whitespace-pre-wrap break-all">
              {result?.output ?? (
                <span className="text-gray-600">
                  {input || recipe.length ? 'Running…' : 'Output appears here as you build the recipe.'}
                </span>
              )}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}

// ArgInput renders one operation argument by type. Values are always kept as
// strings (the API expects Record<string,string>); bool round-trips 'true'/'false'.
function ArgInput({ arg, value, onChange }: {
  arg: ForgeArg
  value: string
  onChange: (v: string) => void
}) {
  if (arg.type === 'bool') {
    return (
      <label className="flex items-center gap-2 text-xs text-gray-300 cursor-pointer">
        <input
          type="checkbox"
          checked={value === 'true'}
          onChange={(e) => onChange(e.target.checked ? 'true' : 'false')}
          className="h-3.5 w-3.5 rounded border-gray-600 bg-gray-800 text-emerald-500 focus:ring-emerald-500"
        />
        {arg.label}
        {arg.help && <span className="text-[10px] text-gray-600">— {arg.help}</span>}
      </label>
    )
  }

  return (
    <div>
      <label className="block text-[10px] uppercase tracking-wider text-gray-500 mb-0.5">{arg.label}</label>
      {arg.type === 'select' ? (
        <select className="input py-1 text-xs" value={value} onChange={(e) => onChange(e.target.value)}>
          {(arg.options ?? []).map((opt) => (
            <option key={opt} value={opt}>{opt}</option>
          ))}
        </select>
      ) : (
        <input
          className="input py-1 text-xs font-mono"
          type={arg.type === 'int' ? 'number' : 'text'}
          value={value}
          onChange={(e) => onChange(e.target.value)}
          spellCheck={false}
        />
      )}
      {arg.help && <p className="text-[10px] text-gray-600 mt-0.5">{arg.help}</p>}
    </div>
  )
}
