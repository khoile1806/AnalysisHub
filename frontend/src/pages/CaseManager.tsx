import { useState, type FormEvent } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { Plus, FolderOpen, Briefcase, Calendar, Pencil } from 'lucide-react'
import toast from 'react-hot-toast'
import { casesApi, type Case } from '@/api/cases'
import { getErrorMessage, safeDistanceToNow } from '@/lib/utils'
import {
  Dialog,
  DialogContent,
  DialogHeader,
  DialogTitle,
  DialogDescription,
  DialogFooter,
  DialogBody,
} from '@/components/ui/dialog'
import { useNavigate } from 'react-router-dom'

function NewCaseModal({ open, onClose }: { open: boolean; onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState('')
  const [description, setDescription] = useState('')

  const createMutation = useMutation({
    mutationFn: casesApi.create,
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      toast.success('Case created successfully')
      handleClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) { toast.error('Case name is required'); return }
    createMutation.mutate({ name: name.trim(), description })
  }

  const handleClose = () => { setName(''); setDescription(''); onClose() }

  return (
    <Dialog open={open} onOpenChange={(v) => { if (!v) handleClose() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Create New Case</DialogTitle>
          <DialogDescription>Create a new investigation case to group agents and track hunting activity.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div>
              <label className="label">Case Name *</label>
              <input
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                placeholder="e.g. IR-2026-001 Ransomware"
                required
              />
            </div>
            <div>
              <label className="label">Description</label>
              <textarea
                className="input resize-none"
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
                placeholder="Details about the incident"
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={handleClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={createMutation.isPending}>
              {createMutation.isPending ? 'Creating...' : 'Create Case'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

function EditCaseModal({ caseObj, onClose }: { caseObj: Case | null; onClose: () => void }) {
  const qc = useQueryClient()
  const [name, setName] = useState(caseObj?.name ?? '')
  const [description, setDescription] = useState(caseObj?.description ?? '')

  const updateMutation = useMutation({
    mutationFn: () => casesApi.update(caseObj!.id, { name: name.trim(), description }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['cases'] })
      qc.invalidateQueries({ queryKey: ['case-summary', caseObj!.id] })
      toast.success('Case updated')
      onClose()
    },
    onError: (err) => toast.error(getErrorMessage(err)),
  })

  const handleSubmit = (e: FormEvent) => {
    e.preventDefault()
    if (!name.trim()) { toast.error('Case name is required'); return }
    updateMutation.mutate()
  }

  if (!caseObj) return null

  return (
    <Dialog open={!!caseObj} onOpenChange={(v) => { if (!v) onClose() }}>
      <DialogContent className="max-w-md">
        <DialogHeader>
          <DialogTitle>Edit Case</DialogTitle>
          <DialogDescription>Update case name or description.</DialogDescription>
        </DialogHeader>
        <form onSubmit={handleSubmit}>
          <DialogBody className="space-y-4">
            <div>
              <label className="label">Case Name *</label>
              <input
                className="input"
                value={name}
                onChange={(e) => setName(e.target.value)}
                required
              />
            </div>
            <div>
              <label className="label">Description</label>
              <textarea
                className="input resize-none"
                rows={3}
                value={description}
                onChange={(e) => setDescription(e.target.value)}
              />
            </div>
          </DialogBody>
          <DialogFooter>
            <button type="button" className="btn-secondary" onClick={onClose}>Cancel</button>
            <button type="submit" className="btn-primary" disabled={updateMutation.isPending}>
              {updateMutation.isPending ? 'Saving...' : 'Save Changes'}
            </button>
          </DialogFooter>
        </form>
      </DialogContent>
    </Dialog>
  )
}

export default function CaseManagerPage() {
  const navigate = useNavigate()
  const [newOpen, setNewOpen] = useState(false)
  const [editCase, setEditCase] = useState<Case | null>(null)

  const { data: cases = [], isLoading } = useQuery({
    queryKey: ['cases'],
    queryFn: casesApi.list,
    refetchInterval: 5000,
  })

  return (
    <div className="space-y-5">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 flex items-center gap-2">
            <Briefcase className="h-5 w-5 text-emerald-400" />
            Case Manager
          </h1>
          <p className="text-sm text-gray-400 mt-0.5">
            Group your agents and track hunting activities by investigation cases
          </p>
        </div>
        <button className="btn-primary" onClick={() => setNewOpen(true)}>
          <Plus className="h-4 w-4" /> New Case
        </button>
      </div>

      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {isLoading ? (
          [...Array(3)].map((_, i) => <div key={i} className="skeleton h-32 rounded-lg" />)
        ) : cases.length === 0 ? (
          <div className="col-span-full flex flex-col items-center justify-center py-16 text-gray-500 bg-gray-900/20 border border-gray-800 rounded-lg">
            <FolderOpen className="h-10 w-10 mb-3 opacity-30" />
            <p className="text-sm">No cases created yet</p>
          </div>
        ) : (
          cases.map((c) => (
            <div
              key={c.id}
              className="card p-5 cursor-pointer hover:border-emerald-500/50 transition-colors flex flex-col h-full"
              onClick={() => navigate(`/cases/${c.id}`)}
            >
              <div className="flex items-start justify-between mb-2 gap-2">
                <h3 className="font-semibold text-gray-200 truncate flex-1">{c.name}</h3>
                <div className="flex items-center gap-1.5 shrink-0">
                  <span className={`text-[10px] uppercase font-bold px-2 py-0.5 rounded-full ${c.status === 'open' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-gray-700 text-gray-300'}`}>
                    {c.status}
                  </span>
                  <button
                    className="p-1 text-gray-500 hover:text-emerald-400 hover:bg-gray-800 rounded transition"
                    title="Edit case"
                    onClick={(e) => { e.stopPropagation(); setEditCase(c) }}
                  >
                    <Pencil className="h-3.5 w-3.5" />
                  </button>
                </div>
              </div>
              <p className="text-xs text-gray-400 flex-1 line-clamp-2 mb-4">
                {c.description || 'No description provided.'}
              </p>
              <div className="flex items-center justify-between text-[11px] text-gray-500 mt-auto pt-3 border-t border-gray-800/60">
                <div className="flex items-center gap-1.5">
                  <Calendar className="h-3.5 w-3.5" />
                  {safeDistanceToNow(c.created_at, { addSuffix: true })}
                </div>
              </div>
            </div>
          ))
        )}
      </div>

      <NewCaseModal open={newOpen} onClose={() => setNewOpen(false)} />
      <EditCaseModal caseObj={editCase} onClose={() => setEditCase(null)} />
    </div>
  )
}
