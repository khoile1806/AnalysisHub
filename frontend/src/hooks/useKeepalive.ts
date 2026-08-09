import { useEffect } from 'react'
import { logsearchApi } from '@/api/logsearch'

// useKeepalive keeps a managed backend service (ELK or the volatility Sandbox)
// alive while the page is mounted, and auto-starts it on open. The backend
// reaper stops these RAM-heavy containers after they go idle; heartbeating here
// resets that timer and, when the container is stopped (and not admin-disabled),
// brings it back up. Fires immediately on mount, then every 60s (idle timeout is
// 3 min by default, so a 60s beat comfortably keeps it up while in use).
export function useKeepalive(svc: 'elk' | 'sandbox', enabled = true) {
  useEffect(() => {
    if (!enabled) return
    let stopped = false
    const beat = () => { logsearchApi.keepalive(svc).catch(() => {}) }
    beat()
    const id = window.setInterval(() => { if (!stopped) beat() }, 60_000)
    return () => { stopped = true; window.clearInterval(id) }
  }, [svc, enabled])
}
