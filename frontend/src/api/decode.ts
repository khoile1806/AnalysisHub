import apiClient from './client'

// Smart multi-layer decoder (URL, Base64/32, Hex, HTML, Unicode, gzip/zlib, JWT).

export interface DecodeStep {
  codec: string
  label: string
  output: string
  binary?: boolean
  note?: string
}

export interface DecodeResult {
  input: string
  steps: DecodeStep[]
  final: string
  final_binary?: boolean
  layers: number
}

export const decodeApi = {
  analyze: (input: string) =>
    apiClient.post<{ data: DecodeResult }>('/osint/oob/decode', { input }).then(r => r.data.data),
}
