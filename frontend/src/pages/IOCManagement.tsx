import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient, keepPreviousData } from '@tanstack/react-query'
import {
  ShieldAlert, Plus, Trash2, Search, Upload, FileUp, RefreshCw, X, Database, Loader2, Layers,
  ChevronLeft, ChevronRight,
} from 'lucide-react'
import toast from 'react-hot-toast'
import { openctiApi, type IOC } from '@/api/opencti'
import { getErrorMessage, safeFormat } from '@/lib/utils'

const PAGE_SIZE = 100

const TYPE_OPTIONS = ['IPv4-Addr', 'IPv6-Addr', 'Domain-Name', 'URL', 'File-Hash', 'Email-Address', 'Mac-Addr']

const TYPE_BADGE: Record<string, string> = {
  'IPv4-Addr': 'text-cyan-300 border-cyan-700/50 bg-cyan-900/20',
  'IPv6-Addr': 'text-cyan-300 border-cyan-700/50 bg-cyan-900/20',
  'Domain-Name': 'text-blue-300 border-blue-700/50 bg-blue-900/20',
  'URL': 'text-indigo-300 border-indigo-700/50 bg-indigo-900/20',
  'File-Hash': 'text-purple-300 border-purple-700/50 bg-purple-900/20',
  'Email-Address': 'text-amber-300 border-amber-700/50 bg-amber-900/20',
  'Mac-Addr': 'text-emerald-300 border-emerald-700/50 bg-emerald-900/20',
}

export default function IOCManagement() {
  const qc = useQueryClient()

  const [searchInput, setSearchInput] = useState('')
  const [search, setSearch] = useState('')
  const [typeFilter, setTypeFilter] = useState('')
  const [sourceFilter, setSourceFilter] = useState('')
  const [page, setPage] = useState(0)
  const [adding, setAdding] = useState(false)
  const [bulkOpen, setBulkOpen] = useState(false)

  // Debounce the search box so each keystroke doesn't hit the (large) store.
  useEffect(() => {
    const t = setTimeout(() => { setSearch(searchInput); setPage(0) }, 350)
    return () => clearTimeout(t)
  }, [searchInput])

  const offset = page * PAGE_SIZE
  const { data: pageData, isLoading, isFetching } = useQuery({
    queryKey: ['iocs', search, typeFilter, sourceFilter, offset],
    queryFn: () => openctiApi.listIOCs({ search, type: typeFilter, source: sourceFilter, limit: PAGE_SIZE, offset }),
    placeholderData: keepPreviousData,
  })
  const { data: facets } = useQuery({ queryKey: ['ioc-facets'], queryFn: openctiApi.iocFacets })

  const iocs = pageData?.data ?? []
  const total = pageData?.total ?? 0
  const totalPages = Math.max(1, Math.ceil(total / PAGE_SIZE))

  const invalidate = () => {
    qc.invalidateQueries({ queryKey: ['iocs'] })
    qc.invalidateQueries({ queryKey: ['ioc-facets'] })
  }

  const deleteMut = useMutation({
    mutationFn: (id: number) => openctiApi.deleteIOC(id),
    onSuccess: () => { invalidate(); toast.success('IOC deleted') },
    onError: (e) => toast.error(getErrorMessage(e)),
  })
  const syncMut = useMutation({
    mutationFn: () => openctiApi.sync(),
    onSuccess: (r) => { invalidate(); toast.success(`OpenCTI sync — ${r.added} new IOC(s)`) },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const typeOpts = facets?.types ?? []
  const sourceOpts = facets?.sources ?? []

  return (
    <div className="space-y-5 w-full">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-gray-100 flex items-center gap-2">
            <Database className="h-6 w-6 text-emerald-400" /> IOC Store
          </h1>
          <p className="text-sm text-gray-500 mt-1">
            Kho chỉ dấu xâm phạm tập trung. Thêm/xóa, import hàng loạt từ nhiều nguồn, dùng cho IOC Sweep / đối chiếu scan. (Phân trang server-side — chịu được kho rất lớn.)
          </p>
        </div>
        <div className="flex items-center gap-2 flex-wrap">
          <button onClick={() => syncMut.mutate()} disabled={syncMut.isPending}
            className="btn-secondary text-sm flex items-center gap-1.5 disabled:opacity-50">
            <RefreshCw className={`h-4 w-4 ${syncMut.isPending ? 'animate-spin' : ''}`} /> Sync OpenCTI
          </button>
          <button onClick={() => setBulkOpen(true)} className="btn-secondary text-sm flex items-center gap-1.5">
            <Layers className="h-4 w-4" /> Bulk import
          </button>
          <button onClick={() => setAdding(true)} className="btn-primary text-sm flex items-center gap-1.5">
            <Plus className="h-4 w-4" /> Add IOC
          </button>
        </div>
      </div>

      {/* Stats (from facets — no row load) */}
      <div className="flex flex-wrap items-center gap-2 text-xs">
        <span className="px-2.5 py-1 rounded-full border border-gray-700 bg-gray-800 text-gray-300">{(facets?.total ?? 0).toLocaleString()} total</span>
        {typeOpts.map((t) => (
          <span key={t.value} className={`px-2.5 py-1 rounded-full border ${TYPE_BADGE[t.value] ?? 'border-gray-700 text-gray-400'}`}>{t.count.toLocaleString()} {t.value}</span>
        ))}
      </div>

      {/* Filters */}
      <div className="flex items-center gap-2 flex-wrap">
        <div className="relative flex-1 min-w-[220px]">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-gray-500" />
          <input value={searchInput} onChange={(e) => setSearchInput(e.target.value)} placeholder="Search value / description…"
            className="input pl-9 w-full" />
          {isFetching && <Loader2 className="absolute right-3 top-1/2 -translate-y-1/2 h-4 w-4 animate-spin text-gray-600" />}
        </div>
        <select className="input max-w-[200px]" value={typeFilter} onChange={(e) => { setTypeFilter(e.target.value); setPage(0) }}>
          <option value="">All types</option>
          {typeOpts.map((t) => <option key={t.value} value={t.value}>{t.value} ({t.count})</option>)}
        </select>
        <select className="input max-w-[200px]" value={sourceFilter} onChange={(e) => { setSourceFilter(e.target.value); setPage(0) }}>
          <option value="">All sources</option>
          {sourceOpts.map((s) => <option key={s.value} value={s.value}>{s.value} ({s.count})</option>)}
        </select>
      </div>

      {/* Table */}
      {isLoading ? (
        <div className="space-y-2">{[...Array(6)].map((_, i) => <div key={i} className="skeleton h-10 rounded" />)}</div>
      ) : iocs.length === 0 ? (
        <div className="card p-10 text-center flex flex-col items-center">
          <ShieldAlert className="h-10 w-10 text-gray-700 mb-3" />
          <p className="text-gray-400 font-medium">{(facets?.total ?? 0) === 0 ? 'No IOCs yet' : 'No matches for this filter'}</p>
          <p className="text-xs text-gray-500 mt-1">Add manually, bulk import, or sync from OpenCTI.</p>
        </div>
      ) : (
        <>
          <div className="overflow-auto max-h-[60vh] rounded-lg border border-gray-800">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-900 z-10">
                <tr className="border-b border-gray-800">
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Value</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Type</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Source</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Description</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Added</th>
                  <th className="px-3 py-2 w-10"></th>
                </tr>
              </thead>
              <tbody>
                {iocs.map((i: IOC) => (
                  <tr key={i.id} className="border-b border-gray-900 hover:bg-white/5 group">
                    <td className="px-3 py-1.5 font-mono text-gray-200 break-all max-w-[360px]">{i.value}</td>
                    <td className="px-3 py-1.5"><span className={`text-[10px] font-mono px-1.5 py-0.5 rounded border ${TYPE_BADGE[i.type] ?? 'text-gray-400 border-slate-700'}`}>{i.type}</span></td>
                    <td className="px-3 py-1.5 text-gray-400 whitespace-nowrap">{i.source || '—'}</td>
                    <td className="px-3 py-1.5 text-gray-500 break-all max-w-[280px]">{i.description || '—'}</td>
                    <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap">{i.created_at ? safeFormat(i.created_at, 'MMM dd, HH:mm') : '—'}</td>
                    <td className="px-3 py-1.5 text-right">
                      <button onClick={() => { if (confirm(`Delete IOC ${i.value}?`)) deleteMut.mutate(i.id) }}
                        className="text-gray-600 hover:text-red-400 opacity-0 group-hover:opacity-100 transition"><Trash2 className="h-3.5 w-3.5" /></button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Pagination */}
          <div className="flex items-center justify-between text-xs text-gray-400">
            <span>{(offset + 1).toLocaleString()}–{Math.min(offset + iocs.length, total).toLocaleString()} of {total.toLocaleString()}</span>
            <div className="flex items-center gap-2">
              <button onClick={() => setPage((p) => Math.max(0, p - 1))} disabled={page === 0}
                className="flex items-center gap-1 px-2.5 py-1 rounded border border-gray-700 bg-gray-800 hover:bg-gray-700 disabled:opacity-40"><ChevronLeft className="h-3.5 w-3.5" /> Prev</button>
              <span>Page {page + 1} / {totalPages}</span>
              <button onClick={() => setPage((p) => (p + 1 < totalPages ? p + 1 : p))} disabled={page + 1 >= totalPages}
                className="flex items-center gap-1 px-2.5 py-1 rounded border border-gray-700 bg-gray-800 hover:bg-gray-700 disabled:opacity-40">Next <ChevronRight className="h-3.5 w-3.5" /></button>
            </div>
          </div>
        </>
      )}

      {adding && <AddIOCModal onClose={() => setAdding(false)} onDone={invalidate} />}
      {bulkOpen && <BulkImportModal onClose={() => setBulkOpen(false)} onDone={invalidate} />}
    </div>
  )
}

// ── Add single IOC ───────────────────────────────────────────────────────────
function AddIOCModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [value, setValue] = useState('')
  const [type, setType] = useState('IPv4-Addr')
  const [description, setDescription] = useState('')

  const mut = useMutation({
    mutationFn: () => openctiApi.addManualIOC({ value: value.trim(), type, description: description.trim() || undefined }),
    onSuccess: () => { toast.success('IOC added'); onDone(); onClose() },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  return (
    <Modal title="Add IOC" onClose={onClose}>
      <div className="space-y-3">
        <div>
          <label className="label text-xs">Value *</label>
          <input className="input font-mono" placeholder="1.2.3.4 / evil.com / <sha256>" value={value} onChange={(e) => setValue(e.target.value)} />
        </div>
        <div>
          <label className="label text-xs">Type</label>
          <select className="input" value={type} onChange={(e) => setType(e.target.value)}>
            {TYPE_OPTIONS.map((t) => <option key={t} value={t}>{t}</option>)}
          </select>
        </div>
        <div>
          <label className="label text-xs">Description</label>
          <input className="input" placeholder="optional context" value={description} onChange={(e) => setDescription(e.target.value)} />
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-secondary text-sm" onClick={onClose}>Cancel</button>
          <button className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50"
            disabled={!value.trim() || mut.isPending} onClick={() => mut.mutate()}>
            {mut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />} Add
          </button>
        </div>
      </div>
    </Modal>
  )
}

// ── Bulk import (paste or file) ──────────────────────────────────────────────
function BulkImportModal({ onClose, onDone }: { onClose: () => void; onDone: () => void }) {
  const [text, setText] = useState('')
  const [source, setSource] = useState('Import')

  const mut = useMutation({
    mutationFn: () => openctiApi.bulkCreateIOCs({ text, source: source.trim() || 'Import' }),
    onSuccess: (r) => {
      toast.success(`Imported: ${r.created} new, ${r.skipped} duplicate, ${r.unrecognized} unrecognized`, { duration: 6000 })
      onDone()
      if (r.created > 0) onClose()
    },
    onError: (e) => toast.error(getErrorMessage(e)),
  })

  const onFile = async (file?: File) => {
    if (!file) return
    const content = await file.text()
    setText((prev) => (prev ? prev + '\n' : '') + content)
    setSource(`File: ${file.name}`)
  }

  return (
    <Modal title="Bulk import IOCs" onClose={onClose}>
      <div className="space-y-3">
        <p className="text-xs text-gray-500">
          Dán danh sách (mỗi dòng / phẩy / space) hoặc tải file .txt/.csv. Loại được tự nhận diện (hỗ trợ defang <code className="bg-gray-800 px-1 rounded">1[.]2[.]3[.]4</code>, <code className="bg-gray-800 px-1 rounded">hxxp://</code>). Trùng sẽ bỏ qua.
        </p>
        <textarea className="input font-mono text-xs min-h-[160px]"
          placeholder={'45.77.12.34\nbad-c2[.]com\nhxxps://evil.com/x\n<sha256>\nattacker@mail.com'}
          value={text} onChange={(e) => setText(e.target.value)} />
        <div className="flex items-center gap-2">
          <label className="flex items-center gap-2 border border-dashed border-gray-700 rounded-lg px-3 py-1.5 cursor-pointer hover:border-emerald-500/50 text-xs text-gray-400">
            <FileUp className="h-4 w-4 text-gray-500" /> Load file
            <input type="file" accept=".txt,.csv,.ioc,.log" className="hidden" onChange={(e) => onFile(e.target.files?.[0])} />
          </label>
          <input className="input text-xs flex-1" placeholder="Source label" value={source} onChange={(e) => setSource(e.target.value)} />
        </div>
        <div className="flex justify-end gap-2 pt-1">
          <button className="btn-secondary text-sm" onClick={onClose}>Cancel</button>
          <button className="btn-primary text-sm flex items-center gap-1.5 disabled:opacity-50"
            disabled={!text.trim() || mut.isPending} onClick={() => mut.mutate()}>
            {mut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Upload className="h-4 w-4" />} Import
          </button>
        </div>
      </div>
    </Modal>
  )
}

function Modal({ title, onClose, children }: { title: string; onClose: () => void; children: React.ReactNode }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4" onClick={onClose}>
      <div className="bg-deep-900 border border-slate-700 rounded-xl w-full max-w-lg shadow-2xl" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-center gap-2 px-4 py-3 border-b border-slate-800">
          <Database className="h-4 w-4 text-emerald-400" />
          <h3 className="text-sm font-semibold text-gray-200">{title}</h3>
          <button onClick={onClose} className="ml-auto text-gray-500 hover:text-gray-300"><X className="h-4 w-4" /></button>
        </div>
        <div className="p-4">{children}</div>
      </div>
    </div>
  )
}
