import { create } from 'zustand'
import { ChecklistBatch } from '@/api/checklist'

export type Platform = 'win' | 'linux'
export type ItemStatus = 'idle' | 'running' | 'done' | 'failed'

export interface ToolResult {
  jobId: string
  itemId: string
  toolName: string
  liveOutput: string
  liveStatus: 'pending' | 'downloading' | 'running' | 'done' | 'failed'
}

export interface ToolPick {
  toolId: string
  args: string
}

interface ChecklistState {
  platform: Platform
  selectedAgent: string
  collapsed: Record<string, boolean>
  checked: Set<string>
  tab: 'checklist' | 'results'
  running: boolean
  caseID: string
  analyst: string
  itemStatus: Record<string, ItemStatus>
  runIDs: string[]
  batchResults: (ChecklistBatch & { liveOutput?: string; liveStatus?: string })[]
  toolResults: ToolResult[]
  openPickerFor: string | null
  itemToolPick: Record<string, ToolPick>
  itemToolRunning: Record<string, boolean>

  // Actions
  setPlatform: (p: Platform) => void
  setSelectedAgent: (a: string) => void
  setCollapsed: (updater: Record<string, boolean> | ((prev: Record<string, boolean>) => Record<string, boolean>)) => void
  setChecked: (updater: Set<string> | ((prev: Set<string>) => Set<string>)) => void
  setTab: (t: 'checklist' | 'results') => void
  setRunning: (r: boolean) => void
  setCaseID: (c: string) => void
  setAnalyst: (a: string) => void
  setItemStatus: (updater: Record<string, ItemStatus> | ((prev: Record<string, ItemStatus>) => Record<string, ItemStatus>)) => void
  setRunIDs: (updater: string[] | ((prev: string[]) => string[])) => void
  setBatchResults: (updater: any[] | ((prev: any[]) => any[])) => void
  setToolResults: (updater: ToolResult[] | ((prev: ToolResult[]) => ToolResult[])) => void
  setOpenPickerFor: (id: string | null) => void
  setItemToolPick: (updater: Record<string, ToolPick> | ((prev: Record<string, ToolPick>) => Record<string, ToolPick>)) => void
  setItemToolRunning: (updater: Record<string, boolean> | ((prev: Record<string, boolean>) => Record<string, boolean>)) => void
  resetAgentState: (newAgent: string) => void
}

export const useChecklistStore = create<ChecklistState>((set) => ({
  platform: 'win',
  selectedAgent: '',
  collapsed: {},
  checked: new Set(),
  tab: 'checklist',
  running: false,
  caseID: '',
  analyst: '',
  itemStatus: {},
  runIDs: [],
  batchResults: [],
  toolResults: [],
  openPickerFor: null,
  itemToolPick: {},
  itemToolRunning: {},

  setPlatform: (p) => set({ platform: p }),
  setSelectedAgent: (a) => set({ selectedAgent: a }),
  setCollapsed: (updater) => set((state) => ({
    collapsed: typeof updater === 'function' ? updater(state.collapsed) : updater
  })),
  setChecked: (updater) => set((state) => ({
    checked: typeof updater === 'function' ? updater(state.checked) : updater
  })),
  setTab: (t) => set({ tab: t }),
  setRunning: (r) => set({ running: r }),
  setCaseID: (c) => set({ caseID: c }),
  setAnalyst: (a) => set({ analyst: a }),
  setItemStatus: (updater) => set((state) => ({
    itemStatus: typeof updater === 'function' ? updater(state.itemStatus) : updater
  })),
  setRunIDs: (updater) => set((state) => ({
    runIDs: typeof updater === 'function' ? updater(state.runIDs) : updater
  })),
  setBatchResults: (updater) => set((state) => ({
    batchResults: typeof updater === 'function' ? updater(state.batchResults) : updater
  })),
  setToolResults: (updater) => set((state) => ({
    toolResults: typeof updater === 'function' ? updater(state.toolResults) : updater
  })),
  setOpenPickerFor: (id) => set({ openPickerFor: id }),
  setItemToolPick: (updater) => set((state) => ({
    itemToolPick: typeof updater === 'function' ? updater(state.itemToolPick) : updater
  })),
  setItemToolRunning: (updater) => set((state) => ({
    itemToolRunning: typeof updater === 'function' ? updater(state.itemToolRunning) : updater
  })),
  resetAgentState: (newAgent) => set({
    selectedAgent: newAgent,
    batchResults: [],
    itemStatus: {},
    runIDs: [],
    toolResults: [],
    running: false,
  }),
}))
