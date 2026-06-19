import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { Paperclip, ImageIcon, FileText, LinkIcon, X, Upload, Plus } from 'lucide-react'
import toast from 'react-hot-toast'
import { evidenceApi, IMAGE_EXT, type CaseEvidence } from '@/api/evidence'
import { type TimelineAttachment } from '@/api/timeline'
import { getErrorMessage } from '@/lib/utils'

function isImage(label?: string) {
  return !!label && IMAGE_EXT.test(label)
}

// ── Display attachments on a node ───────────────────────────────────────────
export function AttachmentsView({ attachments }: { attachments: TimelineAttachment[] }) {
  if (!attachments.length) return null
  return (
    <div className="flex items-center gap-2 flex-wrap mt-2">
      {attachments.map((a, i) => {
        if (a.type === 'link') {
          return (
            <a key={i} href={a.url} target="_blank" rel="noreferrer"
              className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-blue-500/10 text-blue-300 border border-blue-500/20 hover:bg-blue-500/20 max-w-[180px] truncate">
              <LinkIcon className="h-3 w-3 shrink-0" /> <span className="truncate">{a.label || a.url}</span>
            </a>
          )
        }
        if (!a.evidence_id) return null
        if (a.is_image || isImage(a.label)) {
          return (
            <a key={i} href={evidenceApi.viewUrl(a.evidence_id)} target="_blank" rel="noreferrer" title={a.label}>
              <img src={evidenceApi.viewUrl(a.evidence_id)} alt={a.label || 'image'}
                className="h-14 w-14 object-cover rounded border border-gray-700 hover:border-emerald-500/50" />
            </a>
          )
        }
        return (
          <a key={i} href={evidenceApi.downloadUrl(a.evidence_id)} title={a.label}
            className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-gray-700/40 text-gray-300 border border-gray-700 hover:bg-gray-700 max-w-[180px]">
            <FileText className="h-3 w-3 shrink-0" /> <span className="truncate">{a.label || 'file'}</span>
          </a>
        )
      })}
    </div>
  )
}

// ── Edit attachments (map evidence / upload / link) ─────────────────────────
export function AttachmentsEditor({
  caseId, host, value, onChange,
}: {
  caseId: string
  host?: string
  value: TimelineAttachment[]
  onChange: (next: TimelineAttachment[]) => void
}) {
  const [linkUrl, setLinkUrl] = useState('')
  const [linkLabel, setLinkLabel] = useState('')
  const [uploading, setUploading] = useState(false)
  const [pickEvidence, setPickEvidence] = useState('')

  const { data: evidence = [] } = useQuery({ queryKey: ['case-evidence', caseId], queryFn: () => evidenceApi.list(caseId) })

  const usedIds = new Set(value.filter((a) => a.type === 'evidence').map((a) => a.evidence_id))
  const available = evidence.filter((e: CaseEvidence) => !usedIds.has(e.id))

  const add = (a: TimelineAttachment) => onChange([...value, a])
  const removeAt = (i: number) => onChange(value.filter((_, idx) => idx !== i))

  const addExisting = (id: string) => {
    const e = evidence.find((x: CaseEvidence) => x.id === id)
    if (!e) return
    add({ type: 'evidence', evidence_id: e.id, label: e.file_name, is_image: IMAGE_EXT.test(e.file_name) })
    setPickEvidence('')
  }

  const handleUpload = async (file: File) => {
    setUploading(true)
    try {
      const e = await evidenceApi.upload(caseId, file, (host && host.trim()) || 'unattributed', 'timeline attachment')
      add({ type: 'evidence', evidence_id: e.id, label: e.file_name, is_image: IMAGE_EXT.test(e.file_name) })
      toast.success('Attached')
    } catch (err) {
      toast.error(getErrorMessage(err))
    } finally {
      setUploading(false)
    }
  }

  const addLink = () => {
    if (!linkUrl.trim()) return
    add({ type: 'link', url: linkUrl.trim(), label: linkLabel.trim() || linkUrl.trim() })
    setLinkUrl(''); setLinkLabel('')
  }

  return (
    <div className="space-y-2 border border-gray-800 rounded-lg p-2.5 bg-gray-900/30">
      <div className="flex items-center gap-1.5 text-[11px] text-gray-400 font-medium">
        <Paperclip className="h-3 w-3" /> Đính kèm (evidence / ảnh / link)
      </div>

      {/* Current attachments */}
      {value.length > 0 && (
        <div className="flex items-center gap-1.5 flex-wrap">
          {value.map((a, i) => (
            <span key={i} className="inline-flex items-center gap-1 text-[10px] px-1.5 py-0.5 rounded bg-gray-800 border border-gray-700 text-gray-300 max-w-[180px]">
              {a.type === 'link' ? <LinkIcon className="h-2.5 w-2.5" /> : a.is_image ? <ImageIcon className="h-2.5 w-2.5" /> : <FileText className="h-2.5 w-2.5" />}
              <span className="truncate">{a.label}</span>
              <button onClick={() => removeAt(i)} className="text-gray-500 hover:text-red-400"><X className="h-2.5 w-2.5" /></button>
            </span>
          ))}
        </div>
      )}

      {/* Map existing evidence */}
      {available.length > 0 && (
        <select className="input text-xs py-1" value={pickEvidence}
          onChange={(e) => { if (e.target.value) addExisting(e.target.value) }}>
          <option value="">+ Map evidence có sẵn…</option>
          {available.map((e: CaseEvidence) => (
            <option key={e.id} value={e.id}>{e.host} · {e.file_name}</option>
          ))}
        </select>
      )}

      <div className="flex items-center gap-2">
        {/* Upload new */}
        <label className={`flex-1 flex items-center justify-center gap-1.5 border border-dashed border-gray-700 rounded px-2 py-1.5 cursor-pointer hover:border-emerald-500/50 text-[11px] text-gray-400 ${uploading ? 'opacity-60' : ''}`}>
          <Upload className="h-3 w-3" /> {uploading ? 'Đang tải…' : 'Upload file/ảnh'}
          <input type="file" className="hidden" disabled={uploading}
            onChange={(e) => { const f = e.target.files?.[0]; if (f) handleUpload(f); e.currentTarget.value = '' }} />
        </label>
      </div>

      {/* Add link */}
      <div className="flex items-center gap-1.5">
        <input className="input text-xs py-1 flex-1" placeholder="https://link…" value={linkUrl} onChange={(e) => setLinkUrl(e.target.value)} />
        <input className="input text-xs py-1 w-28" placeholder="nhãn" value={linkLabel} onChange={(e) => setLinkLabel(e.target.value)} />
        <button onClick={addLink} disabled={!linkUrl.trim()} className="btn-secondary text-xs py-1 px-2 disabled:opacity-40"><Plus className="h-3 w-3" /></button>
      </div>
    </div>
  )
}
