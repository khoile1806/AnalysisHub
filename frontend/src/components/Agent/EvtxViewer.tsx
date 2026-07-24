import { useState, useRef, useEffect, Fragment } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Search, Activity, AlertTriangle, ChevronRight, ShieldQuestion, Copy, Database, Save, ShieldAlert, ChevronDown, GitBranch,
} from 'lucide-react'
import { agentsApi, type Agent } from '@/api/agents'
import TraceOriginModal from '@/components/Agent/TraceOriginModal'
import { intelApi } from '@/api/intel'
import { timelineApi, type TimelineSeverity } from '@/api/timeline'
import { casesApi } from '@/api/cases'
import { huntingApi, type SigmaAlert, type SigmaSweepResult } from '@/api/hunting'
import { copyToClipboard, getErrorMessage } from '@/lib/utils'
import IntelLookupModal from '@/components/IntelLookupModal'
import toast from 'react-hot-toast'

// ── Structured event shape (matches the agent's new EVTX output) ──────────────
interface EvtEvent {
  time: string
  id: number
  level: string
  provider: string
  computer: string
  record_id: number
  message: string
  data: Record<string, string>
}
type LookupTarget = { indicator: string; type?: string }

// Curated high-value DFIR event presets, grouped by ATT&CK tactic.
// Selecting one fills log + IDs. All channels are real Windows logs the agent
// queries through Get-WinEvent — no backend change needed to add a preset.
const PRESETS: { key: string; group: string; label: string; log: string; ids: number[]; desc: string }[] = [
  // ── Authentication & Access ───────────────────────────────────────────────
  { key: 'logon', group: 'Authentication & Access', label: 'Logons (success / failed)', log: 'Security', ids: [4624, 4625, 4634, 4647, 4648], desc: 'Account logon / logoff activity' },
  { key: 'logon_priv', group: 'Authentication & Access', label: 'Privileged & RDP logons', log: 'Security', ids: [4672, 4778, 4779], desc: 'Admin logons + RDP reconnect/disconnect' },
  { key: 'lockout', group: 'Authentication & Access', label: 'Lockouts / password spraying', log: 'Security', ids: [4740, 4767, 4625], desc: 'Account locked/unlocked + failed logons (brute-force)' },
  { key: 'kerberos', group: 'Authentication & Access', label: 'Kerberos / NTLM auth', log: 'Security', ids: [4768, 4769, 4771, 4776], desc: 'Ticket requests + NTLM (lateral movement, kerberoasting)' },
  { key: 'rdp_session', group: 'Authentication & Access', label: 'RDP session detail (per session)', log: 'Microsoft-Windows-TerminalServices-LocalSessionManager/Operational', ids: [21, 22, 23, 24, 25], desc: 'RDP logon/shell/logoff/disconnect/reconnect' },
  { key: 'rdp_conn', group: 'Authentication & Access', label: 'RDP connection auth (source IP)', log: 'Microsoft-Windows-TerminalServices-RemoteConnectionManager/Operational', ids: [1149], desc: 'Remote desktop user authentication succeeded' },

  // ── Execution ─────────────────────────────────────────────────────────────
  { key: 'process', group: 'Execution', label: 'Process creation (4688)', log: 'Security', ids: [4688], desc: 'Process creation w/ command line (requires audit)' },
  { key: 'powershell', group: 'Execution', label: 'PowerShell script block / pipeline', log: 'Microsoft-Windows-PowerShell/Operational', ids: [4104, 4103], desc: 'Script-block / pipeline logging' },
  { key: 'ps_engine', group: 'Execution', label: 'PowerShell engine start (legacy)', log: 'Windows PowerShell', ids: [400, 403, 600], desc: 'Engine state + host start (downgrade / v2 abuse)' },
  { key: 'wmi_exec', group: 'Execution', label: 'WMI activity (lateral exec)', log: 'Microsoft-Windows-WMI-Activity/Operational', ids: [5857, 5858, 5860, 5861], desc: 'WMI provider load + temp/permanent consumers' },
  { key: 'task_exec', group: 'Execution', label: 'Scheduled task execution', log: 'Microsoft-Windows-TaskScheduler/Operational', ids: [106, 140, 141, 200, 201], desc: 'Task registered / updated / deleted / action run' },
  { key: 'applocker', group: 'Execution', label: 'AppLocker allow / block', log: 'Microsoft-Windows-AppLocker/EXE and DLL', ids: [8002, 8003, 8004], desc: 'Execution allowed / audited / blocked' },
  { key: 'wdac', group: 'Execution', label: 'Code Integrity (WDAC) block', log: 'Microsoft-Windows-CodeIntegrity/Operational', ids: [3076, 3077, 3033], desc: 'Unsigned / blocked image (audit & enforce)' },

  // ── Persistence ───────────────────────────────────────────────────────────
  { key: 'services', group: 'Persistence', label: 'Service installs / state', log: 'System', ids: [7045, 7036, 7040], desc: 'New / changed services + start-type change (persistence)' },
  { key: 'tasks', group: 'Persistence', label: 'Scheduled task create/delete', log: 'Security', ids: [4698, 4699, 4700, 4701, 4702], desc: 'Task create / delete / enable / disable / update' },
  { key: 'bits', group: 'Persistence', label: 'BITS transfer jobs', log: 'Microsoft-Windows-Bits-Client/Operational', ids: [3, 59, 60, 4], desc: 'BITS download jobs (stealth download / persistence)' },
  { key: 'wmi_persist', group: 'Persistence', label: 'WMI event subscription (Sysmon)', log: 'Microsoft-Windows-Sysmon/Operational', ids: [19, 20, 21], desc: 'WMI filter / consumer / binding (fileless persistence)' },

  // ── Privilege Escalation & Credential Access ──────────────────────────────
  { key: 'sensitive_priv', group: 'Priv-Esc & Credential Access', label: 'Sensitive privilege use', log: 'Security', ids: [4673, 4674, 4985], desc: 'Privileged service / object operation (token abuse)' },
  { key: 'cred_dump', group: 'Priv-Esc & Credential Access', label: 'LSASS access (Sysmon 10)', log: 'Microsoft-Windows-Sysmon/Operational', ids: [10], desc: 'Process access to lsass.exe (Mimikatz / cred dump)' },
  { key: 'backup_restore', group: 'Priv-Esc & Credential Access', label: 'Backup/restore + SAM access', log: 'Security', ids: [4661, 4662, 4663], desc: 'Handle to SAM / directory object (DCSync, secrets)' },

  // ── Lateral Movement ──────────────────────────────────────────────────────
  { key: 'shares', group: 'Lateral Movement', label: 'Network share access', log: 'Security', ids: [5140, 5145, 5142, 5143, 5144], desc: 'SMB share connect / object access / admin$ create' },
  { key: 'named_pipe', group: 'Lateral Movement', label: 'Named pipes (Sysmon 17/18)', log: 'Microsoft-Windows-Sysmon/Operational', ids: [17, 18], desc: 'Pipe create / connect (PsExec, Cobalt Strike SMB beacon)' },
  { key: 'remote_thread', group: 'Lateral Movement', label: 'Remote thread / raw read (Sysmon)', log: 'Microsoft-Windows-Sysmon/Operational', ids: [8, 9], desc: 'CreateRemoteThread + raw disk read (injection)' },
  { key: 'winrm', group: 'Lateral Movement', label: 'WinRM remote shell', log: 'Microsoft-Windows-WinRM/Operational', ids: [91, 168, 169], desc: 'WinRM session created + auth (remote PowerShell)' },

  // ── Defense Evasion & Anti-Forensics ──────────────────────────────────────
  { key: 'logclear', group: 'Defense Evasion & Anti-Forensics', label: 'Event log cleared', log: 'Security', ids: [1102, 104], desc: 'Security / other log wiped (log tampering)' },
  { key: 'time_change', group: 'Defense Evasion & Anti-Forensics', label: 'System time changed', log: 'Security', ids: [4616], desc: 'Clock tampering (timestomping / anti-forensics)' },
  { key: 'audit_change', group: 'Defense Evasion & Anti-Forensics', label: 'Audit policy tampering', log: 'Security', ids: [4719, 4817, 4907, 4908], desc: 'Audit policy / SACL / special-groups change' },
  { key: 'defender', group: 'Defense Evasion & Anti-Forensics', label: 'Defender detections', log: 'Microsoft-Windows-Windows Defender/Operational', ids: [1006, 1015, 1116, 1117], desc: 'Malware detected / behavior / action taken' },
  { key: 'defender_off', group: 'Defense Evasion & Anti-Forensics', label: 'Defender disabled / config change', log: 'Microsoft-Windows-Windows Defender/Operational', ids: [5001, 5004, 5007, 5010, 5012, 1009], desc: 'RTP / feature off, exclusions added, signatures rolled back' },
  { key: 'firewall', group: 'Defense Evasion & Anti-Forensics', label: 'Firewall rule changes', log: 'Microsoft-Windows-Windows Firewall With Advanced Security/Firewall', ids: [2004, 2005, 2006, 2033, 2009], desc: 'Firewall rule add / modify / delete / flush' },

  // ── System & Services ─────────────────────────────────────────────────────
  { key: 'accounts', group: 'System & Accounts', label: 'Account / group changes', log: 'Security', ids: [4720, 4722, 4725, 4726, 4738, 4728, 4732, 4756], desc: 'User create/enable/disable/delete + group membership' },
  { key: 'service_health', group: 'System & Accounts', label: 'Service crashes / failures', log: 'System', ids: [7034, 7031, 7000, 7009, 7011, 7023], desc: 'Service crashed / failed to start (tamper or instability)' },
  { key: 'boot', group: 'System & Accounts', label: 'Boot / shutdown / crash', log: 'System', ids: [6005, 6006, 6008, 6013, 1074, 41], desc: 'Log start/stop, dirty shutdown, uptime, forced reboot' },
  { key: 'driver', group: 'System & Accounts', label: 'Driver / device load', log: 'Microsoft-Windows-Kernel-PnP/Configuration', ids: [400, 410, 420, 430], desc: 'Device + driver install (USB, BYOVD rootkit)' },
  { key: 'usb_storage', group: 'System & Accounts', label: 'USB removable storage', log: 'Microsoft-Windows-Partition/Diagnostic', ids: [1006], desc: 'Removable media insert (exfil / bad-USB)' },

  // ── Sysmon (host must run Sysmon) ─────────────────────────────────────────
  { key: 'sysmon_proc', group: 'Sysmon (requires Sysmon)', label: 'Process create', log: 'Microsoft-Windows-Sysmon/Operational', ids: [1], desc: 'Full cmdline + parent + hashes' },
  { key: 'sysmon_net', group: 'Sysmon (requires Sysmon)', label: 'Network + DNS', log: 'Microsoft-Windows-Sysmon/Operational', ids: [3, 22], desc: 'Network connections + DNS queries' },
  { key: 'sysmon_persist', group: 'Sysmon (requires Sysmon)', label: 'File / registry / image load', log: 'Microsoft-Windows-Sysmon/Operational', ids: [11, 12, 13, 7], desc: 'File create / registry / image load' },
  { key: 'sysmon_inject', group: 'Sysmon (requires Sysmon)', label: 'Injection / tampering', log: 'Microsoft-Windows-Sysmon/Operational', ids: [8, 10, 25], desc: 'Remote thread + process access + process tampering' },
  { key: 'sysmon_filedel', group: 'Sysmon (requires Sysmon)', label: 'File delete (anti-forensics)', log: 'Microsoft-Windows-Sysmon/Operational', ids: [23, 26], desc: 'File deleted / delete detected (cleanup, ransomware)' },
]

const EVENT_NAMES: Record<number, string> = {
  4624: 'Logon', 4625: 'Failed Logon', 4634: 'Logoff', 4647: 'User-initiated Logoff', 4648: 'Explicit-cred Logon',
  4672: 'Special Privileges', 4688: 'Process Creation', 4689: 'Process Exit',
  4778: 'RDP Reconnect', 4779: 'RDP Disconnect', 4740: 'Account Lockout', 4767: 'Account Unlocked',
  4720: 'User Created', 4722: 'User Enabled', 4725: 'User Disabled', 4726: 'User Deleted', 4738: 'User Changed',
  4728: 'Member Added (Global)', 4732: 'Member Added (Local)', 4756: 'Member Added (Universal)',
  4697: 'Service Installed', 7045: 'Service Installed', 7036: 'Service State', 7040: 'Service Start-type Changed',
  7034: 'Service Crashed', 7031: 'Service Failed', 7000: 'Service Start Failed', 7009: 'Service Timeout', 7011: 'Service Timeout', 7023: 'Service Exit Error',
  4698: 'Task Created', 4699: 'Task Deleted', 4700: 'Task Enabled', 4701: 'Task Disabled', 4702: 'Task Updated',
  1102: 'Audit Log Cleared', 104: 'Event Log Cleared',
  4104: 'PowerShell Script Block', 4103: 'PowerShell Pipeline', 400: 'PS Engine Start', 403: 'PS Engine Stop', 600: 'PS Provider Start',
  4768: 'Kerberos TGT', 4769: 'Kerberos Service Ticket', 4771: 'Kerberos Pre-auth Failed', 4776: 'NTLM Auth',
  5140: 'Share Access', 5145: 'Share Object Access', 5142: 'Share Added', 5143: 'Share Modified', 5144: 'Share Deleted',
  1006: 'Defender: Malware Detected', 1015: 'Defender: Behavior Detected', 1116: 'Defender: Malware Detected', 1117: 'Defender: Action Taken',
  5001: 'Defender: RTP Disabled', 5004: 'Defender: RTP Config', 5007: 'Defender: Config Changed', 5010: 'Defender: Scan Disabled', 5012: 'Defender: AV Disabled', 1009: 'Defender: Restored from Quarantine',
  4673: 'Sensitive Privilege', 4674: 'Privileged Object Op', 4985: 'Transaction State',
  4661: 'Handle to Object', 4662: 'Directory Object Op', 4663: 'Object Access Attempt',
  4616: 'System Time Changed', 4719: 'Audit Policy Changed', 4817: 'Auditing Settings Changed', 4907: 'SACL Changed', 4908: 'Special Groups Changed',
  5857: 'WMI Provider Started', 5858: 'WMI Query Error', 5860: 'WMI Temp Consumer', 5861: 'WMI Permanent Consumer',
  106: 'Task Registered', 140: 'Task Updated', 141: 'Task Deleted', 200: 'Task Action Started', 201: 'Task Action Completed',
  8002: 'AppLocker: Allowed', 8003: 'AppLocker: Audited', 8004: 'AppLocker: Blocked',
  3076: 'CodeIntegrity: Audit Block', 3077: 'CodeIntegrity: Blocked', 3033: 'CodeIntegrity: Failed Validation',
  3: 'BITS Job Created', 4: 'BITS Job Completed', 59: 'BITS Transfer Started', 60: 'BITS Transfer Stopped',
  91: 'WinRM Session Created', 168: 'WinRM Auth', 169: 'WinRM User Auth',
  21: 'RDP Logon', 22: 'RDP Shell Start', 23: 'RDP Logoff', 24: 'RDP Disconnect', 25: 'RDP Reconnect', 1149: 'RDP Auth Succeeded',
  2004: 'Firewall Rule Added', 2005: 'Firewall Rule Modified', 2006: 'Firewall Rule Deleted', 2009: 'Firewall Rules Restored', 2033: 'Firewall Rules Flushed',
  6005: 'Event Log Started', 6006: 'Event Log Stopped', 6008: 'Unexpected Shutdown', 6013: 'System Uptime', 1074: 'Shutdown Initiated', 41: 'Kernel-Power Dirty Reboot',
  410: 'Device Started', 420: 'Device Configured', 430: 'Driver Loaded',
}
// Sysmon IDs (only meaningful when provider is Sysmon).
const SYSMON_NAMES: Record<number, string> = {
  1: 'Process Create', 3: 'Network Connect', 7: 'Image Load', 8: 'CreateRemoteThread', 9: 'RawAccessRead',
  10: 'Process Access', 11: 'File Create', 12: 'Registry Object', 13: 'Registry Set', 15: 'FileCreateStreamHash',
  17: 'Pipe Created', 18: 'Pipe Connected', 19: 'WMI Filter', 20: 'WMI Consumer', 21: 'WMI Binding',
  22: 'DNS Query', 23: 'File Delete', 25: 'Process Tampering', 26: 'File Delete Detected',
}

// evtxTarget extracts the process/file an event is about (NewProcessName, Image,
// …) as a basename, so it can be traced back to its origin. "" when none.
// evtxTarget picks the binary/executable an event references so Trace origin can
// reconstruct where it came from. Ordered by preference (the acting process
// first, then parents, then service/image-load binaries). Returns "" for events
// with no binary to trace — e.g. pure logon / audit records (4624/4625) carry an
// account, not a process, so no Trace button is shown for them.
function evtxTarget(e: EvtEvent): string {
  const want = [
    // Acting process / image (4688, Sysmon 1, most execution events)
    'newprocessname', 'image', 'processname', 'application',
    // Sysmon file / target / source images
    'targetimage', 'sourceimage', 'targetfilename', 'originalfilename', 'imageloaded',
    // Parent process (still a real binary to trace)
    'parentimage', 'parentprocessname',
    // Service install (7045: ImagePath) / other resolved paths
    'imagepath', 'servicefilename', 'callerprocessname',
  ]
  const d = e.data || {}
  // Build a case-insensitive lookup once so field-name casing never hides a match.
  const lower: Record<string, string> = {}
  for (const k of Object.keys(d)) lower[k.toLowerCase()] = d[k]
  for (const w of want) {
    const v = lower[w]
    if (v && v !== '-') {
      const t = String(v).trim()
      return t.split(/[\\/]/).pop() || t
    }
  }
  return ''
}

// bestTraceTarget always yields SOMETHING to trace so every event row shows a
// Trace button. It prefers a real binary (evtxTarget); for events that carry no
// process/image — pure logon, RDP session, share access — it falls back to the
// acting account (from EventData, or parsed out of the rendered message, e.g.
// "User: DOMAIN\name"). Tracing an account gives a thinner result than tracing a
// binary, but lets the analyst open the panel and pivot from there.
function bestTraceTarget(e: EvtEvent): string {
  const bin = evtxTarget(e)
  if (bin) return bin
  const d = e.data || {}
  const lower: Record<string, string> = {}
  for (const k of Object.keys(d)) lower[k.toLowerCase()] = d[k]
  for (const w of ['subjectusername', 'targetusername', 'user', 'accountname', 'sourceusername']) {
    const v = lower[w]
    if (v && v !== '-' && v !== '') return String(v).trim()
  }
  // TerminalServices / RDP events put the account in the message body only.
  const m = (e.message || '').match(/User:\s*([^\r\n]+)/i)
  if (m && m[1].trim()) return m[1].trim()
  return ''
}

function eventName(e: EvtEvent): string {
  if (e.provider?.toLowerCase().includes('sysmon')) return SYSMON_NAMES[e.id] ?? `Event ${e.id}`
  return EVENT_NAMES[e.id] ?? `Event ${e.id}`
}

// Fields surfaced in the one-line summary, in priority order.
const SUMMARY_KEYS = [
  'SubjectUserName', 'TargetUserName', 'User', 'AccountName',
  'NewProcessName', 'Image', 'ProcessName', 'ServiceName', 'TaskName',
  'ParentProcessName', 'ParentImage',
  'CommandLine', 'ImagePath',
  'IpAddress', 'SourceIp', 'DestinationIp', 'WorkstationName',
  'LogonType', 'ShareName', 'RelativeTargetName', 'QueryName',
]
function summarize(e: EvtEvent): { k: string; v: string }[] {
  const out: { k: string; v: string }[] = []
  for (const k of SUMMARY_KEYS) {
    const v = e.data?.[k]
    if (v && v !== '-' && v !== '' && out.length < 4) out.push({ k, v })
  }
  if (out.length === 0 && e.message) out.push({ k: 'msg', v: e.message.split('\n')[0].slice(0, 120) })
  return out
}

const ipRe = /^(?:\d{1,3}\.){3}\d{1,3}$/
const hashRe = /\b[a-fA-F0-9]{64}\b|\b[a-fA-F0-9]{40}\b|\b[a-fA-F0-9]{32}\b/g
// Pull IPs / hashes out of an event for IOC matching + VirusTotal.
function indicators(e: EvtEvent): { type: 'ip' | 'hash'; value: string }[] {
  const out: { type: 'ip' | 'hash'; value: string }[] = []
  const seen = new Set<string>()
  const push = (type: 'ip' | 'hash', v: string) => { const lv = v.toLowerCase(); if (!seen.has(lv)) { seen.add(lv); out.push({ type, value: v }) } }
  for (const [k, v] of Object.entries(e.data || {})) {
    if (!v) continue
    if ((k.toLowerCase().includes('ip') || k === 'ClientAddress') && ipRe.test(v) && v !== '0.0.0.0' && !v.startsWith('127.')) push('ip', v)
    if (k === 'Hashes' || k.toLowerCase().includes('hash')) {
      const m = v.match(hashRe); if (m) m.forEach(h => push('hash', h))
    }
  }
  return out
}

function fmtTime(iso?: string) {
  if (!iso) return '—'
  const d = new Date(iso); if (isNaN(d.getTime())) return iso
  return d.toLocaleString()
}
async function copy(label: string, v?: string) { if (!v) return; (await copyToClipboard(v)) ? toast.success(`${label} copied`) : toast.error('Copy failed') }

const levelStyle = (l: string) =>
  l === 'Error' || l === 'Critical' ? 'bg-red-500/10 text-red-400'
  : l === 'Warning' ? 'bg-yellow-500/10 text-yellow-400'
  : 'bg-gray-800 text-gray-400'

// PresetSelect is a dark-themed, height-capped, searchable replacement for the
// native <select> — 40 grouped presets render with readable contrast, scroll
// inside a fixed-height panel, and can be filtered by name / log / event ID.
function PresetSelect({ presetKey, onPick }: { presetKey: string; onPick: (k: string) => void }) {
  const [open, setOpen] = useState(false)
  const [q, setQ] = useState('')
  const ref = useRef<HTMLDivElement>(null)
  const current = PRESETS.find(p => p.key === presetKey)

  useEffect(() => {
    if (!open) return
    const onDoc = (e: MouseEvent) => { if (ref.current && !ref.current.contains(e.target as Node)) setOpen(false) }
    const onEsc = (e: KeyboardEvent) => { if (e.key === 'Escape') setOpen(false) }
    document.addEventListener('mousedown', onDoc)
    document.addEventListener('keydown', onEsc)
    return () => { document.removeEventListener('mousedown', onDoc); document.removeEventListener('keydown', onEsc) }
  }, [open])

  const ql = q.trim().toLowerCase()
  const match = (p: typeof PRESETS[number]) =>
    !ql || p.label.toLowerCase().includes(ql) || p.desc.toLowerCase().includes(ql) ||
    p.log.toLowerCase().includes(ql) || p.group.toLowerCase().includes(ql) || p.ids.join(',').includes(ql)
  const groups = Array.from(new Set(PRESETS.map(p => p.group)))
  const anyMatch = PRESETS.some(match)

  return (
    <div className="relative" ref={ref}>
      <button type="button" onClick={() => setOpen(o => !o)}
        className="h-9 w-full flex items-center justify-between gap-2 text-xs bg-gray-950/50 border border-gray-800 rounded-lg px-2.5 text-gray-200 hover:border-purple-500/50 focus:outline-none focus:border-purple-500/60">
        <span className="truncate">{current ? current.label : 'Custom (manual log / event IDs)'}</span>
        <ChevronDown className={`h-3.5 w-3.5 text-gray-500 shrink-0 transition-transform ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div className="absolute z-30 mt-1 w-full bg-gray-900 border border-gray-700 rounded-lg shadow-xl shadow-black/60 overflow-hidden">
          <div className="p-2 border-b border-gray-800">
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input autoFocus value={q} onChange={e => setQ(e.target.value)} placeholder="Search presets / log / event id…"
                className="w-full pl-8 pr-2 py-1.5 text-xs bg-gray-950 border border-gray-700 rounded text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
            </div>
          </div>
          <div className="max-h-72 overflow-y-auto py-1">
            {groups.map(g => {
              const items = PRESETS.filter(p => p.group === g && match(p))
              if (!items.length) return null
              return (
                <div key={g}>
                  <div className="px-3 py-1 text-[10px] uppercase tracking-wider text-purple-300/80 font-bold bg-gray-900/95 sticky top-0 backdrop-blur-sm">{g}</div>
                  {items.map(p => (
                    <button key={p.key} type="button" onClick={() => { onPick(p.key); setOpen(false); setQ('') }}
                      className={`w-full text-left px-3 py-1.5 flex flex-col gap-0.5 transition-colors ${p.key === presetKey ? 'bg-purple-500/15 text-purple-200' : 'text-gray-200 hover:bg-purple-500/10'}`}>
                      <span className="text-xs font-medium leading-tight">{p.label}</span>
                      <span className="text-[10px] text-gray-500 leading-tight truncate">{p.desc}</span>
                    </button>
                  ))}
                </div>
              )
            })}
            {!anyMatch && <div className="px-3 py-4 text-center text-xs text-gray-600">No preset matches “{q}”</div>}
          </div>
        </div>
      )}
    </div>
  )
}

// traceableFromEvent pulls the process identity out of a matched event so the
// analyst can pivot straight into an origin trace. Field names differ between
// Sysmon, Security 4688 and the Linux collector, so try each namespace.
function traceableFromEvent(ev: any): { target: string; pid: number } | null {
  if (!ev) return null
  const target = ev.Image || ev.NewProcessName || ev.Executable || ev.ProcessName || ev.ParentProcessName || ev.ParentImage
  if (!target) return null
  const raw = ev.NewProcessId ?? ev.ProcessId ?? ev.PID ?? ev.pid
  // 4688 reports the PID as a hex string ("0x1f4"); parseInt handles both forms.
  const pid = typeof raw === 'number' ? raw : parseInt(String(raw ?? ''), raw && String(raw).startsWith('0x') ? 16 : 10)
  return { target: String(target), pid: Number.isFinite(pid) ? pid : 0 }
}

// SigmaAlertRow shows one detection and, expanded, exactly why it fired: the
// rule's condition, every field comparison that satisfied it (what the rule
// asked for vs what the event actually held), and a pivot into the origin trace.
export function SigmaAlertRow({ alert, expanded, onToggle, onTrace }: {
  // onTrace is omitted for stored/offline logs: the origin trace queries a live
  // agent, and a dead-box log has no machine to ask.
  alert: SigmaAlert; expanded: boolean; onToggle: () => void; onTrace?: (target: string, pid: number) => void
}) {
  const traceable = onTrace ? traceableFromEvent(alert.event) : null
  return (
    <div className="text-xs bg-black/40 rounded border border-red-900/30">
      <div className="flex items-start gap-2 p-2">
        <button onClick={onToggle} className="text-gray-500 hover:text-gray-200 mt-0.5 shrink-0" title="Why did this fire?">
          <ChevronRight className={`h-3.5 w-3.5 transition-transform ${expanded ? 'rotate-90' : ''}`} />
        </button>
        <div className="min-w-0 flex-1">
          <span className={`font-bold ${alert.rule_level ? 'text-red-400' : 'text-gray-400'}`}>[{alert.rule_level?.toUpperCase() || 'UNRATED'}]</span> {alert.rule_title}
          {(alert.event_count ?? 0) > 1 && <span className="ml-1.5 text-amber-400">×{alert.event_count}</span>}
          {(alert.mitre_techniques?.length ?? 0) > 0 && (
            <span className="ml-2 text-[10px] text-purple-300">{alert.mitre_techniques!.join(' ')}</span>
          )}
          {(alert.mitre_tactics?.length ?? 0) > 0 && (
            <span className="ml-1.5 text-[10px] text-gray-500">{alert.mitre_tactics!.join(', ')}</span>
          )}
        </div>
        {traceable && (
          <button onClick={() => onTrace?.(traceable.target, traceable.pid)}
            className="shrink-0 inline-flex items-center gap-1 px-2 py-0.5 rounded border border-purple-600/40 bg-purple-600/10 text-purple-300 hover:bg-purple-600/20 text-[10px]"
            title={`Trace where ${traceable.target} came from`}>
            <GitBranch className="h-3 w-3" /> Trace origin
          </button>
        )}
      </div>

      {expanded && (
        <div className="border-t border-red-900/30 px-3 py-2 space-y-2">
          {alert.rule_description && <p className="text-[11px] text-gray-400">{alert.rule_description}</p>}
          {alert.condition && (
            <div className="text-[11px]">
              <span className="text-gray-500">Condition: </span>
              <span className="font-mono text-gray-300">{alert.condition}</span>
            </div>
          )}

          {alert.matches && alert.matches.length > 0 ? (
            <div>
              <div className="text-[10px] uppercase tracking-wider text-gray-500 font-bold mb-1">Why it matched</div>
              <div className="overflow-x-auto">
                <table className="w-full text-[11px]">
                  <thead>
                    <tr className="text-gray-600 border-b border-gray-800">
                      <th className="text-left pr-3 py-1 font-normal">SELECTION</th>
                      <th className="text-left pr-3 py-1 font-normal">FIELD</th>
                      <th className="text-left pr-3 py-1 font-normal">RULE EXPECTED</th>
                      <th className="text-left py-1 font-normal">EVENT CONTAINED</th>
                    </tr>
                  </thead>
                  <tbody>
                    {alert.matches.map((m, i) => (
                      <tr key={i} className="border-b border-gray-900/60 align-top">
                        <td className="pr-3 py-1 text-gray-500 font-mono whitespace-nowrap">{m.selection}</td>
                        <td className="pr-3 py-1 text-gray-300 font-mono whitespace-nowrap">
                          {m.field}{m.modifier && <span className="text-gray-600">|{m.modifier}</span>}
                        </td>
                        <td className="pr-3 py-1 text-amber-300 font-mono break-all">{m.expected}</td>
                        <td className="py-1 text-emerald-300 font-mono break-all">{m.actual}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          ) : (
            <p className="text-[11px] text-gray-500">No field-level explanation available for this alert.</p>
          )}

          <details>
            <summary className="text-[10px] uppercase tracking-wider text-gray-500 font-bold cursor-pointer hover:text-gray-300">Raw event</summary>
            <pre className="mt-1 max-h-52 overflow-auto text-[10px] text-gray-400 font-mono whitespace-pre-wrap break-all">
              {JSON.stringify(alert.event, null, 2)}
            </pre>
          </details>
        </div>
      )}
    </div>
  )
}

// sigmaSeverity maps a Sigma rule level onto the timeline's severity scale. An
// unrated rule becomes "info" rather than inheriting a high default.
function sigmaSeverity(level?: string): TimelineSeverity {
  switch ((level || '').toLowerCase()) {
    case 'critical': return 'critical'
    case 'high': return 'high'
    case 'medium': return 'medium'
    case 'low': return 'low'
    default: return 'info'
  }
}

export function EvtxViewer({ agent }: { agent: Agent }) {
  const [presetKey, setPresetKey] = useState('logon')
  const [logName, setLogName] = useState('Security')
  const [eventIds, setEventIds] = useState('4624, 4625')
  const [hours, setHours] = useState(24)
  const [maxEvents, setMaxEvents] = useState(500)
  const [keyword, setKeyword] = useState('')

  const [loading, setLoading] = useState(false)
  const [events, setEvents] = useState<EvtEvent[] | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [expanded, setExpanded] = useState<Set<number>>(new Set())
  const [filter, setFilter] = useState('')
  const [traceTarget, setTraceTarget] = useState<{ target: string; pid: number } | null>(null)

  const [iocMatches, setIocMatches] = useState<Set<string>>(new Set())
  const [lookup, setLookup] = useState<LookupTarget | null>(null)
  const [selected, setSelected] = useState<Set<number>>(new Set())
  const [saveCaseId, setSaveCaseId] = useState<string>(agent.case_id ?? '')
  const [saving, setSaving] = useState(false)

  const [scanningSigma, setScanningSigma] = useState(false)
  const [sigmaAlerts, setSigmaAlerts] = useState<SigmaAlert[]>([])
  const [sweeping, setSweeping] = useState(false)
  const [sweep, setSweep] = useState<SigmaSweepResult | null>(null)
  const [openAlerts, setOpenAlerts] = useState<Set<number>>(new Set())
  const toggleAlert = (i: number) => setOpenAlerts(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const { data: cases = [] } = useQuery({ queryKey: ['cases'], queryFn: casesApi.list })

  const applyPreset = (key: string) => {
    setPresetKey(key)
    const p = PRESETS.find(x => x.key === key)
    if (p) { setLogName(p.log); setEventIds(p.ids.join(', ')) }
  }

  const toggleExp = (i: number) => setExpanded(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })
  const toggleSel = (i: number) => setSelected(p => { const n = new Set(p); n.has(i) ? n.delete(i) : n.add(i); return n })

  const checkIOCs = async (evts: EvtEvent[]) => {
    const vals = Array.from(new Set(evts.flatMap(indicators).map(x => x.value.toLowerCase()))).slice(0, 5000)
    if (!vals.length) return
    try {
      const res = await intelApi.matchIOCs(vals)
      if (res.count > 0) { setIocMatches(new Set(Object.keys(res.matches))); toast.error(`${res.count} indicator(s) match your IOC database`, { icon: '🚨' }) }
    } catch { /* non-fatal */ }
  }

  const handleSearch = async () => {
    if (agent.status !== 'online') { toast.error('Agent is offline'); return }
    const ids = eventIds.split(',').map(s => parseInt(s.trim(), 10)).filter(n => !isNaN(n))
    setLoading(true); setError(null); setEvents(null); setSigmaAlerts([]); setSelected(new Set()); setIocMatches(new Set())
    try {
      const data = await agentsApi.parseEvtx(agent.id, { log_name: logName, event_ids: ids, hours, max: maxEvents, keyword })
      let parsed = data
      if (typeof data === 'string') { try { parsed = JSON.parse(data) } catch { parsed = [] } }
      const arr: EvtEvent[] = Array.isArray(parsed) ? parsed : (parsed && parsed.id !== undefined ? [parsed] : [])
      setEvents(arr)
      toast.success(`${arr.length} event(s) returned`)
      checkIOCs(arr)
    } catch (err: any) {
      const m = getErrorMessage(err)
      setError(m); toast.error(m)
    } finally { setLoading(false) }
  }

  // runSigmaSweep scans the WHOLE machine instead of only the events currently
  // on screen: the server derives which channels the loaded ruleset needs, pulls
  // each from the agent and evaluates them all in one pass.
  const runSigmaSweep = async () => {
    if (agent.status !== 'online') { toast.error('Agent is offline'); return }
    setSweeping(true); setSweep(null); setSigmaAlerts([])
    try {
      const res = await huntingApi.sigmaSweep(agent.id, { hours })
      setSweep(res)
      setSigmaAlerts(res.alerts || [])
      const n = res.alerts?.length ?? 0
      n > 0
        ? toast.error(`${n} Sigma alert(s) across ${res.events_scanned} event(s)`)
        : toast.success(`No Sigma alerts — ${res.events_scanned} event(s) scanned with ${res.rules_count} rule(s)`)
    } catch (err: any) {
      toast.error('Sigma sweep failed: ' + getErrorMessage(err))
    } finally { setSweeping(false) }
  }

  const runSigma = async () => {
    if (!events?.length) return
    setScanningSigma(true)
    try {
      // Flatten EventData to top level so Sigma rules can match field names.
      // The spread comes first: an EventData element named EventID/Provider/
      // Message must not overwrite the identity fields that logsource gating
      // and the rules themselves rely on.
      const sigmaEvents = events.map(e => ({ ...e.data, EventID: e.id, Provider: e.provider, Message: e.message }))
      const alerts = await huntingApi.scanSigma(sigmaEvents)
      setSigmaAlerts(alerts)
      alerts.length > 0 ? toast.error(`Found ${alerts.length} Sigma alert(s)!`) : toast.success('No Sigma alerts found.')
    } catch (err: any) {
      toast.error('Sigma scan failed: ' + getErrorMessage(err))
    } finally { setScanningSigma(false) }
  }

  const isKnownIOC = (e: EvtEvent) => indicators(e).some(x => iocMatches.has(x.value.toLowerCase()))

  const handleSaveToCase = async () => {
    if (!saveCaseId) { toast.error('Select a case first'); return }
    if (!events || selected.size === 0) { toast.error('Select at least one event'); return }
    setSaving(true)
    try {
      const items = Array.from(selected).map(i => events[i]).filter(Boolean).map(e => {
        const known = isKnownIOC(e)
        const summary = summarize(e).map(s => `${s.k}=${s.v}`).join('  ')
        const inds = indicators(e)
        const ip = inds.find(x => x.type === 'ip')
        const hash = inds.find(x => x.type === 'hash')
        return {
          title: `EVTX ${e.id} (${eventName(e)})${summary ? ' — ' + summary.slice(0, 80) : ''}`,
          detail: `Log: ${logName}\nProvider: ${e.provider}\nComputer: ${e.computer}\nRecord: ${e.record_id}\n\n${e.message}`,
          event_time: e.time,
          severity: (known ? 'critical' : e.level === 'Error' || e.level === 'Critical' ? 'high' : 'info') as TimelineSeverity,
          value: hash?.value || ip?.value,
          ioc_type: hash ? 'File-Hash' : ip ? 'IPv4-Addr' : undefined,
          promote_ioc: !!(hash || ip),
        }
      })
      const res = await timelineApi.importArtifacts(saveCaseId, { source: 'edge-forensics:evtx', host: agent.hostname || agent.name, items })
      toast.success(`Saved ${res.events_created} event(s) · ${res.iocs_promoted} new IOC(s)`)
      setSelected(new Set())
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setSaving(false) }
  }

  // Sigma alerts only lived in React state, so a refresh threw away the
  // detection work. Pushing them onto the case timeline keeps the ATT&CK
  // mapping the rules already carry, which is what the coverage view reads.
  const saveAlertsToCase = async () => {
    if (!saveCaseId || sigmaAlerts.length === 0) return
    setSaving(true)
    try {
      // Alerts are rolled up per rule: only the first row of each rule carries
      // event_count, the rest are extra samples. Saving one item per rule keeps
      // the timeline readable instead of repeating the same detection.
      const items = sigmaAlerts
        .filter(a => (a.event_count ?? 0) > 0)
        .map(a => {
          const ev = a.event || {}
          const when = ev.TimeCreated || ev.time
          return {
            title: `Sigma: ${a.rule_title}${(a.event_count ?? 0) > 1 ? ` (${a.event_count} events)` : ''}`,
            detail: [
              a.rule_description,
              a.rule_id ? `Rule ID: ${a.rule_id}` : '',
              a.mitre_techniques?.length ? `ATT&CK: ${a.mitre_techniques.join(', ')}` : '',
              a.mitre_tactics?.length ? `Tactics: ${a.mitre_tactics.join(', ')}` : '',
              `EventID: ${ev.EventID ?? '—'}  Provider: ${ev.Provider ?? '—'}`,
              ev.CommandLine || ev.ProcessCommandLine ? `CommandLine: ${ev.CommandLine || ev.ProcessCommandLine}` : '',
              ev.NewProcessName || ev.Image ? `Image: ${ev.NewProcessName || ev.Image}` : '',
            ].filter(Boolean).join('\n'),
            event_time: typeof when === 'string' ? when : undefined,
            severity: sigmaSeverity(a.rule_level),
            technique: a.mitre_techniques?.[0],
            tactic: a.mitre_tactics?.[0],
          }
        })
      const res = await timelineApi.importArtifacts(saveCaseId, {
        source: 'sigma', host: agent.hostname || agent.name, items,
      })
      toast.success(`Saved ${res.events_created} Sigma alert(s) to the case timeline`)
    } catch (err: any) {
      toast.error(getErrorMessage(err))
    } finally { setSaving(false) }
  }

  const shown = (events ?? []).map((e, i) => ({ e, i })).filter(({ e }) => {
    if (!filter) return true
    const f = filter.toLowerCase()
    return e.message.toLowerCase().includes(f) || String(e.id).includes(f) ||
      Object.values(e.data || {}).some(v => v?.toLowerCase().includes(f))
  })

  return (
    <div className="flex flex-col h-full min-h-[600px] gap-4">
      {/* Controls */}
      <div className="flex flex-col gap-3 p-4 bg-gray-900/50 rounded-xl border border-gray-800 shrink-0">
        <div className="flex items-center gap-3">
          <div className="p-2.5 bg-purple-500/10 rounded-lg border border-purple-500/20"><Activity className="h-5 w-5 text-purple-500" /></div>
          <div>
            <h1 className="text-lg font-bold text-gray-100">EVTX Log Forensics</h1>
            <p className="text-xs text-gray-400">Structured Windows Event Log query on {agent.name} — parsed fields, IOC match & VirusTotal.</p>
          </div>
        </div>

        <div className="grid grid-cols-1 lg:grid-cols-12 gap-3 pt-2 border-t border-gray-800/50">
          <div className="lg:col-span-4 flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Preset <span className="text-gray-600 normal-case font-normal">({PRESETS.length} checks)</span></label>
            <PresetSelect presetKey={presetKey} onPick={applyPreset} />
            {/* Editing the log or the ID list clears the preset, so the dropdown
                never claims to describe a query the operator has since changed. */}
            <p className="text-[10px] text-gray-500 leading-tight truncate" title={PRESETS.find(p => p.key === presetKey)?.desc}>
              {presetKey ? PRESETS.find(p => p.key === presetKey)?.desc : 'Custom query — edit Log Name and Event IDs freely'}
            </p>
          </div>
          <div className="lg:col-span-4 flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Log Name</label>
            <input value={logName} onChange={e => { setLogName(e.target.value); setPresetKey('') }} placeholder="Security" className="h-9 text-xs font-mono bg-gray-950/50 border border-gray-800 rounded-lg px-2 text-gray-200 focus:outline-none focus:border-purple-500/60" />
          </div>
          <div className="lg:col-span-4 flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">
              Event IDs <span className="text-gray-600 normal-case font-normal">— any IDs you want, comma separated; empty = all</span>
            </label>
            <input value={eventIds} onChange={e => { setEventIds(e.target.value); setPresetKey('') }} placeholder="e.g. 4688, 4104, 7045 — or leave empty" className="h-9 text-xs font-mono bg-gray-950/50 border border-gray-800 rounded-lg px-2 text-gray-200 focus:outline-none focus:border-purple-500/60" />
          </div>

          <div className="lg:col-span-3 flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Time window</label>
            <select value={hours} onChange={e => setHours(Number(e.target.value))} className="h-9 text-xs bg-gray-950/50 border border-gray-800 rounded-lg px-2 text-gray-200 focus:outline-none focus:border-purple-500/60">
              <option value={1}>Last 1 hour</option><option value={6}>Last 6 hours</option><option value={24}>Last 24 hours</option>
              <option value={72}>Last 3 days</option><option value={168}>Last 7 days</option><option value={720}>Last 30 days</option><option value={0}>All time</option>
            </select>
          </div>
          <div className="lg:col-span-2 flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Max events</label>
            <input type="number" min={10} max={5000} value={maxEvents} onChange={e => setMaxEvents(Number(e.target.value))} className="h-9 text-xs bg-gray-950/50 border border-gray-800 rounded-lg px-2 text-gray-200 focus:outline-none focus:border-purple-500/60" />
          </div>
          <div className="lg:col-span-4 flex flex-col gap-1">
            <label className="text-[10px] uppercase tracking-wider text-gray-500 font-bold">Keyword (in message)</label>
            <input value={keyword} onChange={e => setKeyword(e.target.value)} placeholder="optional — e.g. mimikatz, an IP, a user" className="h-9 text-xs bg-gray-950/50 border border-gray-800 rounded-lg px-2 text-gray-200 focus:outline-none focus:border-purple-500/60" />
          </div>
          <div className="lg:col-span-3 flex items-end gap-2">
            <button onClick={handleSearch} disabled={loading || agent.status !== 'online'} className="flex-1 h-9 flex items-center justify-center gap-2 px-4 rounded-lg bg-purple-600 hover:bg-purple-700 text-white text-sm font-medium disabled:opacity-50">
              {loading ? <span className="h-4 w-4 rounded-full border-2 border-white/30 border-t-white animate-spin" /> : <Search className="h-4 w-4" />}
              {loading ? 'Querying…' : 'Search'}
            </button>
            {!!events?.length && (
              <button onClick={runSigma} disabled={scanningSigma} className="h-9 flex items-center gap-1.5 px-3 rounded-lg bg-red-600/90 hover:bg-red-600 text-white text-xs font-medium disabled:opacity-50" title="Run the Sigma rule library against the events currently listed">
                <ShieldAlert className="h-3.5 w-3.5" /> {scanningSigma ? '…' : 'Sigma'}
              </button>
            )}
            <button onClick={runSigmaSweep} disabled={sweeping || agent.status !== 'online'}
              className="h-9 flex items-center gap-1.5 px-3 rounded-lg bg-red-700 hover:bg-red-600 text-white text-xs font-medium disabled:opacity-50 whitespace-nowrap"
              title="Scan the whole machine: pulls every log channel the rule library needs and evaluates all of them">
              {sweeping ? <span className="h-3.5 w-3.5 rounded-full border-2 border-white/30 border-t-white animate-spin" /> : <ShieldAlert className="h-3.5 w-3.5" />}
              {sweeping ? 'Sweeping…' : 'Scan machine'}
            </button>
          </div>
        </div>
        {agent.status !== 'online' && <p className="text-xs text-orange-300">Agent is offline — EVTX query unavailable.</p>}
      </div>

      {/* Results */}
      <div className="flex-1 bg-gray-900/50 rounded-xl border border-gray-800 overflow-hidden flex flex-col">
        {/* Save-to-case toolbar */}
        {selected.size > 0 && (
          <div className="flex flex-wrap items-center gap-3 px-4 py-2.5 border-b border-gray-800 bg-emerald-500/5">
            <span className="text-xs text-emerald-300 font-medium">{selected.size} selected</span>
            <select value={saveCaseId} onChange={e => setSaveCaseId(e.target.value)} className="text-xs bg-gray-900 border border-gray-700 rounded-lg px-2 py-1.5 text-gray-200">
              <option value="">Select case…</option>
              {cases.map((c: any) => <option key={c.id} value={c.id}>{c.name}</option>)}
            </select>
            <button onClick={handleSaveToCase} disabled={saving || !saveCaseId} className="inline-flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-50">
              {saving ? <span className="h-3.5 w-3.5 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="h-3.5 w-3.5" />} Save to Case + promote IOC
            </button>
            <button onClick={() => setSelected(new Set())} className="text-xs text-gray-500 hover:text-gray-300">Clear</button>
          </div>
        )}

        {sweep && (
          <div className="m-4 mb-0 rounded-lg border border-gray-800 bg-gray-950/40 p-3">
            <h4 className="text-xs font-bold text-gray-300 mb-2 flex items-center gap-2">
              <ShieldAlert className="h-4 w-4 text-red-400" />
              Machine sweep — {sweep.events_scanned} event(s) from {sweep.sources.length} channel(s), {sweep.rules_count} rule(s), {sweep.hours > 0 ? `last ${sweep.hours}h` : 'all time'}
            </h4>
            <div className="flex flex-col gap-1 text-[11px] font-mono">
              {sweep.sources.map((s, i) => (
                <div key={i} className="flex items-start gap-2">
                  <span className={`w-1.5 h-1.5 rounded-full mt-1.5 shrink-0 ${s.error ? 'bg-gray-600' : s.events > 0 ? 'bg-emerald-500' : 'bg-gray-700'}`} />
                  <span className="text-gray-300 min-w-0 flex-1 break-all">{s.log_name}</span>
                  <span className="text-gray-600 shrink-0">{s.event_ids?.length ? s.event_ids.join(',') : 'all ids'}</span>
                  {/* A channel that is absent on the host (no Sysmon, no PowerShell
                      operational logging) must not read the same as a clean one. */}
                  <span className={`shrink-0 ${s.error ? 'text-amber-500' : 'text-gray-400'}`}>
                    {s.error ? s.error : `${s.events} event(s)`}
                  </span>
                </div>
              ))}
            </div>
            {sweep.load_stats && sweep.load_stats.unsupported > 0 && (
              <p className="mt-2 text-[10px] text-amber-500">
                {sweep.load_stats.unsupported} rule(s) on disk could not be evaluated (aggregation or correlation conditions) and were not part of this sweep.
              </p>
            )}
          </div>
        )}

        {sigmaAlerts.length > 0 && (
          <div className="m-4 mb-0 rounded-lg border border-red-900/50 bg-red-950/20 p-3">
            <div className="flex items-center justify-between mb-2 gap-2">
              <h4 className="text-xs font-bold text-red-400 flex items-center gap-2"><AlertTriangle className="h-4 w-4" /> Sigma Alerts ({sigmaAlerts.length})</h4>
              <button onClick={saveAlertsToCase} disabled={saving || !saveCaseId}
                title={saveCaseId ? 'Save these detections onto the case timeline with their ATT&CK mapping' : 'Pick a case below first'}
                className="inline-flex items-center gap-1.5 px-2.5 py-1 text-[11px] font-medium bg-emerald-600 hover:bg-emerald-500 text-white rounded-lg disabled:opacity-40">
                {saving ? <span className="h-3 w-3 border-2 border-white/30 border-t-white rounded-full animate-spin" /> : <Save className="h-3 w-3" />}
                Save alerts to Case
              </button>
            </div>
            <div className="flex flex-col gap-1.5 max-h-[420px] overflow-auto">
              {/* Only the rolled-up row of each rule carries event_count, so the
                  duplicate sample rows render without a count badge. */}
              {sigmaAlerts.map((a, i) => (
                <SigmaAlertRow key={i} alert={a} expanded={openAlerts.has(i)} onToggle={() => toggleAlert(i)}
                  onTrace={(target, pid) => setTraceTarget({ target, pid })} />
              ))}
            </div>
          </div>
        )}

        {events && events.length > 0 && (
          <div className="px-4 pt-3">
            <div className="relative">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-gray-500" />
              <input value={filter} onChange={e => setFilter(e.target.value)} placeholder="Filter results (message / field / id)…" className="w-full pl-8 pr-3 py-1.5 text-xs bg-gray-950 border border-gray-700 rounded-lg text-gray-200 placeholder-gray-600 focus:outline-none focus:border-purple-500/60" />
            </div>
          </div>
        )}

        <div className="flex-1 p-4 overflow-y-auto">
          {loading ? (
            <div className="h-full flex items-center justify-center text-gray-500 flex-col gap-3"><span className="h-8 w-8 rounded-full border-2 border-purple-500/30 border-t-purple-500 animate-spin" /><p className="text-sm">Querying {logName}…</p></div>
          ) : error ? (
            <div className="rounded-lg border border-red-900/50 bg-red-950/20 p-4 flex items-start gap-3"><AlertTriangle className="h-5 w-5 text-red-500 shrink-0 mt-0.5" /><div><h4 className="text-sm font-medium text-red-200">Error reading EVTX</h4><p className="text-xs text-red-300/80 mt-1">{error}</p></div></div>
          ) : !events ? (
            <div className="h-full flex items-center justify-center text-gray-500"><p className="text-sm">Pick a preset (or set log + IDs) and click Search.</p></div>
          ) : events.length === 0 ? (
            <div className="h-full flex items-center justify-center text-gray-500"><p className="text-sm">No events found. Note: 4688 command line & Sysmon require auditing/Sysmon enabled on the host.</p></div>
          ) : (
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-gray-900 z-10">
                <tr className="border-b border-gray-800">
                  <th className="px-2 py-2 w-6"></th>
                  <th className="px-2 py-2 w-6"></th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Time</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Event</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Summary</th>
                  <th className="px-3 py-2 text-left text-gray-500 font-medium">Indicators</th>
                </tr>
              </thead>
              <tbody>
                {shown.map(({ e, i }) => {
                  const known = isKnownIOC(e)
                  const isOpen = expanded.has(i)
                  const inds = indicators(e)
                  return (
                    <Fragment key={i}>
                      <tr className={`border-b border-gray-800/40 hover:bg-gray-800/30 ${known ? 'bg-red-950/30' : ''}`}>
                        <td className="px-2 py-1.5 text-center"><input type="checkbox" checked={selected.has(i)} onChange={() => toggleSel(i)} className="accent-emerald-500" /></td>
                        <td className="px-2 py-1.5 text-gray-600 cursor-pointer" onClick={() => toggleExp(i)}><ChevronRight className={`h-3.5 w-3.5 transition-transform ${isOpen ? 'rotate-90' : ''}`} /></td>
                        <td className="px-3 py-1.5 text-gray-500 whitespace-nowrap cursor-pointer" onClick={() => toggleExp(i)}>{fmtTime(e.time)}</td>
                        <td className="px-3 py-1.5 whitespace-nowrap cursor-pointer" onClick={() => toggleExp(i)}>
                          <span className="font-mono text-purple-400 font-semibold">{e.id}</span> <span className="text-gray-300">{eventName(e)}</span>
                          <span className={`ml-1.5 px-1.5 py-0.5 rounded text-[9px] uppercase ${levelStyle(e.level)}`}>{e.level || '—'}</span>
                        </td>
                        <td className="px-3 py-1.5 text-gray-300 max-w-md">
                          <div className="flex flex-wrap gap-x-3 gap-y-0.5">
                            {summarize(e).map((s, k) => <span key={k} className="truncate"><span className="text-gray-500">{s.k}:</span> <span className="font-mono">{s.v.length > 60 ? s.v.slice(0, 59) + '…' : s.v}</span></span>)}
                          </div>
                        </td>
                        <td className="px-3 py-1.5">
                          <div className="flex flex-wrap items-center gap-1">
                            {inds.slice(0, 3).map((ind, k) => {
                              const hit = iocMatches.has(ind.value.toLowerCase())
                              return (
                                <button key={k} onClick={(ev) => { ev.stopPropagation(); setLookup({ indicator: ind.value, type: ind.type }) }} title="Look up on VirusTotal"
                                  className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border ${hit ? 'bg-red-500/20 border-red-500/40 text-red-400' : 'bg-gray-800 border-gray-700 text-gray-300 hover:border-purple-500/40'}`}>
                                  {hit ? <Database className="h-2.5 w-2.5" /> : <ShieldQuestion className="h-2.5 w-2.5" />}
                                  {ind.value.length > 18 ? ind.value.slice(0, 8) + '…' + ind.value.slice(-6) : ind.value}
                                </button>
                              )
                            })}
                            {bestTraceTarget(e) && (
                              <button onClick={(ev) => { ev.stopPropagation(); setTraceTarget({ target: bestTraceTarget(e), pid: 0 }) }}
                                title={`Trace origin of ${bestTraceTarget(e)} (parent process / user, when)`}
                                className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-mono border bg-gray-800 border-gray-700 text-gray-300 hover:border-emerald-500/40 hover:text-emerald-300">
                                <GitBranch className="h-2.5 w-2.5" /> trace
                              </button>
                            )}
                          </div>
                        </td>
                      </tr>
                      {isOpen && (
                        <tr className="bg-gray-950/60">
                          <td colSpan={2}></td>
                          <td colSpan={4} className="px-4 py-3 space-y-2">
                            <div className="text-[11px] text-gray-500">Provider: <span className="text-gray-300">{e.provider}</span> · Computer: <span className="text-gray-300">{e.computer}</span> · Record: <span className="text-gray-300">{e.record_id}</span></div>
                            {Object.keys(e.data || {}).length > 0 && (
                              <div className="rounded-lg border border-gray-800 overflow-hidden">
                                <table className="w-full text-[11px]">
                                  <tbody>
                                    {Object.entries(e.data).filter(([, v]) => v && v !== '-').map(([k, v]) => (
                                      <tr key={k} className="border-b border-gray-800/40">
                                        <td className="px-2 py-1 text-gray-500 align-top w-44 font-medium">{k}</td>
                                        <td className="px-2 py-1 font-mono text-gray-300 break-all">{v}</td>
                                      </tr>
                                    ))}
                                  </tbody>
                                </table>
                              </div>
                            )}
                            <div className="flex items-start gap-2">
                              <pre className="flex-1 text-[11px] text-gray-400 font-mono whitespace-pre-wrap bg-black/30 p-2 rounded border border-gray-800/60 max-h-40 overflow-auto">{e.message}</pre>
                              <button onClick={() => copy('Message', e.message)} className="text-gray-600 hover:text-emerald-400 shrink-0"><Copy className="h-3.5 w-3.5" /></button>
                            </div>
                            {bestTraceTarget(e) && (
                              <div className="pt-1">
                                <button onClick={() => setTraceTarget({ target: bestTraceTarget(e), pid: 0 })} className="inline-flex items-center gap-1.5 px-2.5 py-1 rounded text-[11px] font-medium bg-emerald-700/80 hover:bg-emerald-700 text-white" title={`Trace the origin of ${bestTraceTarget(e)} (parent process / user, when)`}>
                                  <GitBranch className="h-3.5 w-3.5" /> Trace origin: {bestTraceTarget(e)}
                                </button>
                              </div>
                            )}
                          </td>
                        </tr>
                      )}
                    </Fragment>
                  )
                })}
              </tbody>
            </table>
          )}
        </div>
      </div>

      {lookup && <IntelLookupModal indicator={lookup.indicator} type={lookup.type} onClose={() => setLookup(null)} />}
      {traceTarget && <TraceOriginModal agent={agent} target={traceTarget.target} pid={traceTarget.pid} onClose={() => setTraceTarget(null)} />}
    </div>
  )
}
