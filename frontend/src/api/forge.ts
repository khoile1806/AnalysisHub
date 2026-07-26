import apiClient from './client'

// Transform workbench ("Forge"): a CyberChef-style recipe engine. The user
// pastes a value, stacks an ordered list of operations, and the backend runs
// them left-to-right. Mirrors backend/internal/api/handlers transform contract.

export type ForgeArgType = 'string' | 'int' | 'bool' | 'select'

export interface ForgeArg {
  key: string
  label: string
  type: ForgeArgType
  default?: string
  options?: string[]
  help?: string
}

export interface ForgeOp {
  name: string
  category: string
  description: string
  args?: ForgeArg[]
}

export interface ForgeRecipeStep {
  op: string
  args?: Record<string, string>
}

export interface ForgeStep {
  op: string
  output: string
  binary: boolean
  bytes: number
  error?: string
}

export interface ForgeResult {
  steps: ForgeStep[]
  output: string
  binary: boolean
  bytes: number
}

interface ApiResponse<T> {
  success: boolean
  error?: string
  data: T
}

export interface ForgeRunResult {
  success: boolean
  error?: string
  result: ForgeResult
}

export const forgeApi = {
  // The catalogue of available operations, grouped client-side by category.
  operations: async (): Promise<ForgeOp[]> => {
    const { data } = await apiClient.get<ApiResponse<ForgeOp[]>>('/tools/transform/operations')
    return data.data
  },

  // Run a recipe. A failing step still returns HTTP 200 with success:false, an
  // error, and a partial trace (steps up to the failure) — surface both.
  run: async (input: string, recipe: ForgeRecipeStep[]): Promise<ForgeRunResult> => {
    const { data } = await apiClient.post<ApiResponse<ForgeResult>>('/tools/transform', {
      input,
      recipe,
    })
    return { success: data.success, error: data.error, result: data.data }
  },
}
