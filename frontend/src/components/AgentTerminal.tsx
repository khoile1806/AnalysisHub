import { useEffect, useRef, useState } from 'react'
import { Terminal as XTerm } from 'xterm'
import { FitAddon } from '@xterm/addon-fit'
import 'xterm/css/xterm.css'
import { Terminal as TerminalIcon, Power, Loader2 } from 'lucide-react'
import { useAuthStore } from '@/store/auth'
import type { Agent } from '@/api/agents'

type Shell = 'cmd' | 'powershell' | 'bash' | 'zsh' | 'sh'

type ConnState = 'idle' | 'connecting' | 'open' | 'closed' | 'error'

function shellOptions(agentOS: string): Shell[] {
  const os = (agentOS || '').toLowerCase()
  if (os.includes('windows')) return ['powershell', 'cmd']
  if (os.includes('darwin') || os.includes('mac')) return ['zsh', 'bash', 'sh']
  return ['bash', 'zsh', 'sh']
}

function encodeUtf8(input: string): string {
  // Browser TextEncoder → Uint8Array → base64
  const bytes = new TextEncoder().encode(input)
  let binary = ''
  for (let i = 0; i < bytes.length; i++) binary += String.fromCharCode(bytes[i])
  return btoa(binary)
}

function decodeBase64ToUint8(b64: string): Uint8Array {
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

export function AgentTerminal({ agent }: { agent: Agent }) {
  const containerRef = useRef<HTMLDivElement | null>(null)
  const termRef = useRef<XTerm | null>(null)
  const fitRef = useRef<FitAddon | null>(null)
  const wsRef = useRef<WebSocket | null>(null)
  const resizeObserverRef = useRef<ResizeObserver | null>(null)

  const defaultShell = shellOptions(agent.os)[0]
  const [shell, setShell] = useState<Shell>(defaultShell)
  const [state, setState] = useState<ConnState>('idle')
  const [errorMsg, setErrorMsg] = useState<string | null>(null)

  const isOnline = agent.status === 'online'

  // Mount xterm once per component lifetime. Theme matches the dashboard dark look.
  useEffect(() => {
    if (!containerRef.current) return

    const term = new XTerm({
      convertEol: true,
      cursorBlink: true,
      fontFamily: '"JetBrains Mono", "Fira Code", ui-monospace, monospace',
      fontSize: 13,
      theme: {
        background: '#0b0f19',
        foreground: '#e5e7eb',
        cursor: '#34d399',
        selectionBackground: '#374151',
      },
      scrollback: 5000,
    })
    const fit = new FitAddon()
    term.loadAddon(fit)
    term.open(containerRef.current)
    try { fit.fit() } catch { /* container may have zero size during first paint */ }

    termRef.current = term
    fitRef.current = fit

    const ro = new ResizeObserver(() => {
      try {
        fit.fit()
        const ws = wsRef.current
        if (ws && ws.readyState === WebSocket.OPEN && termRef.current) {
          ws.send(JSON.stringify({ type: 'resize', cols: termRef.current.cols, rows: termRef.current.rows }))
        }
      } catch { /* ignore */ }
    })
    ro.observe(containerRef.current)
    resizeObserverRef.current = ro

    term.writeln('\x1b[90mForensicHub interactive terminal\x1b[0m')
    term.writeln('\x1b[90mClick "Connect" to open a shell on the target agent.\x1b[0m')

    return () => {
      ro.disconnect()
      wsRef.current?.close()
      term.dispose()
      termRef.current = null
      fitRef.current = null
    }
  }, [])

  const connect = () => {
    const term = termRef.current
    const fit = fitRef.current
    if (!term || !fit) return
    if (wsRef.current) {
      wsRef.current.close()
      wsRef.current = null
    }

    setErrorMsg(null)
    setState('connecting')

    try { fit.fit() } catch { /* ignore */ }
    const cols = term.cols
    const rows = term.rows

    const token = useAuthStore.getState().token ?? ''
    let base = import.meta.env.VITE_WS_URL as string | undefined;
    if (!base) {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      base = `${protocol}//${window.location.host}`;
    }
    const url = `${base}/ws/terminal?agent_id=${encodeURIComponent(agent.id)}`
      + `&shell=${encodeURIComponent(shell)}`
      + `&cols=${cols}&rows=${rows}`
      + `&token=${encodeURIComponent(token)}`

    const ws = new WebSocket(url)
    wsRef.current = ws

    ws.onopen = () => {
      setState('open')
      term.writeln(`\x1b[32m[connected to ${agent.name} — shell: ${shell}]\x1b[0m`)
      term.focus()
    }

    ws.onmessage = (ev) => {
      try {
        const msg = JSON.parse(ev.data)
        if (msg.type === 'output' && typeof msg.data === 'string') {
          term.write(decodeBase64ToUint8(msg.data))
        } else if (msg.type === 'closed') {
          if (msg.exit_code === -1) {
            term.writeln(`\r\n\x1b[31m[agent disconnected — click Connect to reopen]\x1b[0m`)
            setErrorMsg('Agent disconnected — click Connect to reopen')
            setState('error')
          } else {
            term.writeln(`\r\n\x1b[33m[shell exited — code ${msg.exit_code ?? 0}]\x1b[0m`)
            setState('closed')
          }
          ws.close()
        } else if (msg.type === 'error') {
          setErrorMsg(msg.message ?? 'terminal error')
          term.writeln(`\r\n\x1b[31m[error: ${msg.message ?? 'unknown'}]\x1b[0m`)
          setState('error')
        }
      } catch {
        /* ignore malformed frames */
      }
    }

    ws.onerror = () => {
      setErrorMsg('WebSocket error — check console')
      setState('error')
    }

    ws.onclose = (ev) => {
      setState((prev) => (prev === 'open' || prev === 'connecting' ? 'closed' : prev))
      if (ev.code !== 1000 && ev.code !== 1005) {
        term.writeln(`\r\n\x1b[90m[disconnected: ${ev.reason || ev.code}]\x1b[0m`)
      }
    }

    term.onData((data) => {
      const sock = wsRef.current
      if (sock && sock.readyState === WebSocket.OPEN) {
        sock.send(JSON.stringify({ type: 'input', data: encodeUtf8(data) }))
      }
    })

    term.onResize(({ cols, rows }) => {
      const sock = wsRef.current
      if (sock && sock.readyState === WebSocket.OPEN) {
        sock.send(JSON.stringify({ type: 'resize', cols, rows }))
      }
    })
  }

  const disconnect = () => {
    wsRef.current?.close()
    wsRef.current = null
    setState('closed')
  }

  if (!isOnline) {
    return (
      <div className="card flex flex-col items-center justify-center py-16 text-gray-500">
        <TerminalIcon className="h-10 w-10 mb-3 opacity-30" />
        <p className="text-sm">Agent is offline — the terminal requires an active connection.</p>
      </div>
    )
  }

  const shells = shellOptions(agent.os)
  const connected = state === 'open'

  return (
    <div className="space-y-3">
      <div className="flex items-center justify-between gap-3">
        <div className="flex items-center gap-2">
          <label className="text-xs text-gray-400">Shell</label>
          <select
            value={shell}
            onChange={(e) => setShell(e.target.value as Shell)}
            disabled={connected || state === 'connecting'}
            className="input text-xs py-1 disabled:opacity-50"
          >
            {shells.map((s) => (
              <option key={s} value={s}>{s}</option>
            ))}
          </select>
          <span className={`text-xs ${
            state === 'open' ? 'text-emerald-400'
            : state === 'connecting' ? 'text-amber-400'
            : state === 'error' ? 'text-red-400'
            : 'text-gray-500'
          }`}>
            {state === 'open' ? '● live' : state === 'connecting' ? '◌ connecting' : state === 'error' ? '✖ error' : '○ idle'}
          </span>
          {errorMsg && <span className="text-xs text-red-400 truncate max-w-xs" title={errorMsg}>{errorMsg}</span>}
        </div>
        <div className="flex items-center gap-2">
          {connected ? (
            <button className="btn-danger text-xs flex items-center gap-1.5" onClick={disconnect}>
              <Power className="h-3.5 w-3.5" /> Disconnect
            </button>
          ) : (
            <button
              className="btn-primary text-xs flex items-center gap-1.5"
              onClick={connect}
              disabled={state === 'connecting'}
            >
              {state === 'connecting'
                ? <Loader2 className="h-3.5 w-3.5 animate-spin" />
                : <TerminalIcon className="h-3.5 w-3.5" />}
              {state === 'connecting' ? 'Connecting…' : 'Connect'}
            </button>
          )}
        </div>
      </div>

      <div className="card p-2">
        <div
          ref={containerRef}
          className="h-[60vh] w-full bg-[#0b0f19] rounded"
        />
      </div>
      <p className="text-xs text-gray-600">
        Full interactive PTY · ctrl-C / tab completion / ANSI colours supported · window resizes are forwarded to the agent.
      </p>
    </div>
  )
}
