import { useAuthStore } from '@/store/auth'

export interface GenerateBundleRequest {
  name: string
  tool_ids: string[]
  platform: 'windows' | 'linux' | 'both'
  case_id?: string
  case_name?: string
}

// generateOfflineBundle sends a POST and triggers a ZIP file download.
// Uses fetch() directly so we can stream the binary response as a blob.
export async function generateOfflineBundle(req: GenerateBundleRequest): Promise<void> {
  const token = useAuthStore.getState().token
  const baseURL = import.meta.env.VITE_API_URL ?? ''

  const response = await fetch(`${baseURL}/api/v1/offline-bundles/generate`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      ...(token ? { Authorization: `Bearer ${token}` } : {}),
    },
    body: JSON.stringify(req),
  })

  if (!response.ok) {
    const text = await response.text()
    throw new Error(text || `Server returned ${response.status}`)
  }

  // Extract filename from Content-Disposition header.
  const disposition = response.headers.get('Content-Disposition') ?? ''
  const match = disposition.match(/filename="?([^";\n]+)"?/)
  const filename = match ? match[1] : `offline-bundle-${Date.now()}.zip`

  const blob = await response.blob()
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(url)
}
