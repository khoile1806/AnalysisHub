import { useState } from 'react'
import { ShieldQuestion } from 'lucide-react'
import IntelLookupModal from './IntelLookupModal'
import { isRoutableIP } from '@/lib/utils'

export type IntelKind = 'hash' | 'ip' | 'domain' | 'url'

// IntelButton — one-click threat-intel lookup (VirusTotal + OTX + AbuseIPDB) for a
// single indicator, plus a direct link into the VirusTotal GUI from the modal footer.
//
// It owns its own modal state on purpose. The malware and network views render
// indicators inside deeply nested tables and detail panels; threading an onLookup
// handler down through every one of those parents (the pattern EdgeForensics uses)
// would touch far more code than the feature is worth. Dropping a self-contained
// button next to a value costs one line at the call site.
export default function IntelButton({
  value,
  kind,
  className = '',
  size = 'sm',
  label,
}: {
  value?: string | null
  kind: IntelKind
  className?: string
  size?: 'xs' | 'sm'
  /** Render a text button instead of the bare icon. */
  label?: string
}) {
  const [open, setOpen] = useState(false)
  const v = (value ?? '').trim()
  if (!v) return null
  // A Host: header or a Zeek server_name is a domain most of the time and a bare
  // address the rest of the time. Correct the caller rather than query the wrong
  // endpoint: VirusTotal's domain and ip-address objects are not interchangeable.
  const k: IntelKind = kind === 'domain' && looksLikeIP(v) ? 'ip' : kind
  // Looking up an address that cannot appear in any public dataset wastes an API
  // call and shows the analyst a meaningless "no threat" verdict.
  if (k === 'ip' && !isRoutableIP(stripPort(v))) return null
  // A URL keeps its port; an ip/domain object is addressed by name alone.
  const target = k === 'url' ? v : stripPort(v)

  const icon = size === 'xs' ? 'h-3 w-3' : 'h-3.5 w-3.5'
  return (
    <>
      <button
        type="button"
        onClick={(e) => { e.stopPropagation(); e.preventDefault(); setOpen(true) }}
        title={`Check this ${k} on VirusTotal`}
        className={`shrink-0 inline-flex items-center gap-1 text-gray-500 hover:text-purple-400 transition-colors ${className}`}
      >
        <ShieldQuestion className={icon} />
        {label && <span className="text-[10px]">{label}</span>}
      </button>
      {open && <IntelLookupModal indicator={target} type={k} onClose={() => setOpen(false)} />}
    </>
  )
}

// looksLikeIP is deliberately loose: it only has to separate "1.2.3.4" and
// "[2001:db8::1]:443" from a hostname, not validate the address.
function looksLikeIP(v: string): boolean {
  const bare = stripPort(v)
  return /^\d{1,3}(\.\d{1,3}){3}$/.test(bare) || bare.includes(':')
}

// stripPort removes a trailing :port and IPv6 brackets, which Host headers carry
// and threat-intel APIs reject.
function stripPort(v: string): string {
  const m = /^\[(.+)\](?::\d+)?$/.exec(v)
  if (m) return m[1]
  if (/^\d{1,3}(\.\d{1,3}){3}:\d+$/.test(v)) return v.split(':')[0]
  if (/^[A-Za-z0-9.-]+:\d+$/.test(v)) return v.split(':')[0]
  return v
}
