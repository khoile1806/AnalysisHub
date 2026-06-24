import { create } from 'zustand'
import { persist } from 'zustand/middleware'
import { type Severity } from '@/api/cve'

interface CveFilters {
  severities: Set<Severity>
  onlyKev: boolean
  cvssMin: number
  epssPercentileMin: number
}

interface UiState {
  // CVE Page State
  cveInput: string
  cveVersionInput: string
  cveQuery: string
  cveVersion: string
  cveSelectedId: string | null
  cveFilters: CveFilters
  setCveState: (state: Partial<UiState>) => void

  // Memory Analysis Page State
  memorySidebarOpen: boolean
  setMemorySidebarOpen: (open: boolean) => void
}

export const useUiStore = create<UiState>()(
  persist(
    (set) => ({
      cveInput: '',
      cveVersionInput: '',
      cveQuery: '',
      cveVersion: '',
      cveSelectedId: null,
      cveFilters: {
        severities: new Set(),
        onlyKev: false,
        cvssMin: 0,
        epssPercentileMin: 0,
      },
      setCveState: (state) => set((prev) => ({ ...prev, ...state })),

      memorySidebarOpen: false,
      setMemorySidebarOpen: (open) => set({ memorySidebarOpen: open }),
    }),
    {
      name: 'forensic-ui-state',
      partialize: (state) => ({
        cveInput: state.cveInput,
        cveVersionInput: state.cveVersionInput,
        cveQuery: state.cveQuery,
        cveVersion: state.cveVersion,
        // Set cannot be natively JSON serialized, so we convert it
        cveFilters: { ...state.cveFilters, severities: Array.from(state.cveFilters.severities) as any },
        memorySidebarOpen: state.memorySidebarOpen,
      }),
      merge: (persistedState: any, currentState) => {
        if (!persistedState) return currentState
        return {
          ...currentState,
          ...persistedState,
          cveFilters: {
            ...currentState.cveFilters,
            ...persistedState.cveFilters,
            severities: new Set(persistedState.cveFilters?.severities || []),
          },
        }
      },
    }
  )
)
