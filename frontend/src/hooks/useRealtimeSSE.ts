import { useEffect, useRef, useState } from 'react'
import { useAuthStore } from '@/store/auth'

export type RealtimeDataType = 'processes' | 'netstat' | 'sysinfo' | 'netconn'

// useRealtimeSSE subscribes to the agent's live telemetry stream (Server-Sent
// Events) for the given data type. The agent pushes a fresh snapshot every
// couple of seconds; the backend fans it out. Payloads are arrays (processes /
// netstat / netconn) or a single object (sysinfo, normalised to a 1-element
// array here).
export function useRealtimeSSE<T>(agentId: string, dataType: RealtimeDataType, enabled: boolean) {
  const [data, setData] = useState<T[] | null>(null)
  const [connected, setConnected] = useState(false)
  const esRef = useRef<EventSource | null>(null)
  const token = useAuthStore((s) => s.token)

  useEffect(() => {
    if (!enabled) {
      // Tear down any stream when disabled (e.g. live mode toggled off).
      esRef.current?.close()
      esRef.current = null
      setConnected(false)
      return
    }

    const base = (import.meta.env.VITE_API_URL as string | undefined) ?? ''
    const tokenParam = token ? `&token=${encodeURIComponent(token)}` : ''
    const url = `${base}/api/v1/agents/${agentId}/monitor?type=${dataType}${tokenParam}`
    const es = new EventSource(url)
    esRef.current = es

    es.onopen = () => setConnected(true)
    es.onmessage = (e) => {
      try {
        const parsed = JSON.parse(e.data)
        setData(Array.isArray(parsed) ? (parsed as T[]) : [parsed as T])
        setConnected(true)
      } catch {
        // ignore parse errors
      }
    }
    es.onerror = () => setConnected(false)

    return () => {
      es.close()
      esRef.current = null
    }
  }, [agentId, dataType, enabled, token])

  return { data, connected }
}
