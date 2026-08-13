"""Second-pass analysis for samples whose real content is hidden behind a layer.

Three cases the base pipeline could see but not read:

  .NET obfuscation — commodity RATs (AsyncRAT, njRAT, Quasar) ship packed by
      ConfuserEx and friends; the config, strings and C2 only appear after
      de4dot has undone it.
  shellcode      — a raw blob carved out of a document, a pcap or an overlay has
      no PE header, so the emulator never ran it and static analysis saw bytes.
  PowerShell     — `-EncodedCommand` is only the first layer; real droppers stack
      concat, format operators, char arithmetic, replace chains and Gzip.

Everything here is static or emulated; nothing is executed on the host.
"""
import base64
import binascii
import gzip
import hashlib
import os
import re
import shutil
import struct
import subprocess
import zlib

DE4DOT_PATHS = ("/opt/de4dot/de4dot.exe", "/opt/de4dot/de4dot-x64.exe")
DE4DOT_TIMEOUT = int(os.environ.get("DE4DOT_TIMEOUT", "180"))
SHELLCODE_TIMEOUT = int(os.environ.get("SHELLCODE_TIMEOUT", "60"))


# ── .NET deobfuscation ────────────────────────────────────────────────────────

def de4dot_available():
    if not shutil.which("mono"):
        return False
    return any(os.path.exists(p) for p in DE4DOT_PATHS)


def run_de4dot(path):
    """Deobfuscate a .NET assembly. Returns (out_path, detail) or (None, reason).

    The cleaned assembly is what the caller re-runs .NET metadata extraction and
    config parsing against — that is where the C2 actually shows up."""
    exe = next((p for p in DE4DOT_PATHS if os.path.exists(p)), None)
    if not exe or not shutil.which("mono"):
        return None, "de4dot/mono not installed"
    out = path + ".clean.exe"
    try:
        p = subprocess.run(["mono", exe, "-f", path, "-o", out],
                           capture_output=True, timeout=DE4DOT_TIMEOUT)
    except Exception as e:
        return None, "de4dot failed: %s" % e
    text = (p.stdout + p.stderr).decode("utf-8", "replace")
    if not os.path.exists(out) or os.path.getsize(out) == 0:
        return None, "de4dot produced no output: %s" % text.strip().splitlines()[-1:] or "unknown"
    detector = ""
    m = re.search(r"Detected\s+(.+?)\s*\(", text)
    if m:
        detector = m.group(1).strip()
    return out, detector or "deobfuscated"


# ── shellcode ─────────────────────────────────────────────────────────────────

# Byte patterns that mark a blob as likely shellcode rather than data. Kept short
# and specific: a false "this is shellcode" wastes a minute of emulation.
SHELLCODE_MARKERS = (
    (b"\xfc\x48\x83\xe4\xf0", "x64 stack-align prologue (Metasploit-style)"),
    (b"\xfc\xe8", "x86 call/pop GetPC prologue"),
    (b"\x64\x8b\x52\x30", "PEB access via fs:[0x30] (x86)"),
    (b"\x65\x48\x8b\x52\x60", "PEB access via gs:[0x60] (x64)"),
    (b"\x64\xa1\x30\x00\x00\x00", "PEB access (mov eax, fs:[0x30])"),
    (b"\xeb\x27\x5b", "jmp/call/pop decoder stub"),
)


def looks_like_shellcode(data):
    """Reasons this blob looks like position-independent code."""
    hits = []
    head = data[:4096]
    for sig, why in SHELLCODE_MARKERS:
        if sig in head:
            hits.append(why)
    # A hash-based API resolver (ror13) is the other classic tell.
    if b"\x0f\xb6" in head and b"\xc1\xcf\x0d" in head:
        hits.append("ROR13 API-hash resolver")
    return hits


def emulate_shellcode(data, arch="x86"):
    """Run a raw blob under speakeasy's shellcode mode and return the API trace.

    Real execution never happens: speakeasy emulates the instructions and stubs
    every Windows API, which is what makes a hostile blob safe to 'run' here."""
    try:
        import speakeasy
    except Exception as e:
        return {"error": "speakeasy not installed: %s" % e}
    try:
        se = speakeasy.Speakeasy()
        sc_addr = se.load_shellcode(None, arch, data=data)
        se.run_shellcode(sc_addr, offset=0)
        report = se.get_report()
    except Exception as e:
        return {"error": str(e), "arch": arch}
    return {"arch": arch, "report": report}


# ── PowerShell / script de-obfuscation ────────────────────────────────────────

RE_B64_LONG = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
RE_FORMAT_OP = re.compile(r"""\(\s*['"]([^'"]{0,400}?)['"]\s*-f\s*(.+?)\)""", re.I | re.S)
RE_CHAR_CODES = re.compile(r"\[char\]\s*(\d{1,3})", re.I)
RE_JOIN_CHARS = re.compile(r"\(\s*\[char\[\]\]\s*\(\s*([\d,\s]{6,})\)\s*-join\s*['\"]?['\"]?\s*\)", re.I)
RE_REPLACE = re.compile(r"""-replace\s*['"]([^'"]{1,40})['"]\s*,\s*['"]([^'"]{0,40})['"]""", re.I)
RE_CONCAT = re.compile(r"""['"]([^'"]{0,60})['"]\s*\+\s*['"]([^'"]{0,60})['"]""")
RE_BACKTICK = re.compile(r"`")


def _try_b64_payload(blob):
    """Decode a base64 blob and, if it is compressed, inflate it. Returns text."""
    try:
        raw = base64.b64decode(blob + "=" * (-len(blob) % 4), validate=False)
    except Exception:
        return ""
    # Gzip / raw-deflate are what IO.Compression produces in a PowerShell dropper.
    for inflate in (lambda b: gzip.decompress(b),
                    lambda b: zlib.decompress(b, -15),
                    lambda b: zlib.decompress(b)):
        try:
            raw = inflate(raw)
            break
        except Exception:
            continue
    for enc in ("utf-16le", "utf-8", "latin-1"):
        try:
            text = raw.decode(enc)
        except Exception:
            continue
        printable = sum(c.isprintable() or c in "\r\n\t" for c in text)
        if len(text) >= 8 and printable >= len(text) * 0.8:
            return text
    return ""


def _apply_format_operator(text):
    """Resolve PowerShell's -f operator: ('{1}{0}' -f 'b','a') → 'ab'."""
    def repl(m):
        fmt, args = m.group(1), m.group(2)
        parts = re.findall(r"""['"]([^'"]*)['"]""", args)
        if not parts:
            return m.group(0)
        try:
            return '"' + re.sub(r"\{(\d+)\}", lambda i: parts[int(i.group(1))] if int(i.group(1)) < len(parts) else "", fmt) + '"'
        except Exception:
            return m.group(0)
    return RE_FORMAT_OP.sub(repl, text)


def _apply_char_codes(text):
    text = RE_JOIN_CHARS.sub(
        lambda m: '"' + "".join(chr(int(n)) for n in re.findall(r"\d{1,3}", m.group(1)) if int(n) < 256) + '"', text)
    return RE_CHAR_CODES.sub(lambda m: '"%s"' % chr(int(m.group(1))) if int(m.group(1)) < 256 else m.group(0), text)


def deobfuscate_powershell(text, rounds=4):
    """Peel the layers a PowerShell dropper actually stacks, one round at a time.

    Returns (final_text, steps) where steps names each transformation that fired —
    the analyst needs to see HOW it was hidden, not just the result."""
    steps = []
    current = text
    for _ in range(rounds):
        before = current
        if RE_BACKTICK.search(current):
            current = RE_BACKTICK.sub("", current)
            steps.append("removed backtick escapes")
        new = _apply_format_operator(current)
        if new != current:
            current, _ = new, steps.append("resolved -f format operator")
        new = _apply_char_codes(current)
        if new != current:
            current, _ = new, steps.append("resolved [char] / char-array joins")
        new = RE_CONCAT.sub(lambda m: '"' + m.group(1) + m.group(2) + '"', current)
        if new != current:
            current, _ = new, steps.append("folded string concatenation")
        for pat, rep in RE_REPLACE.findall(current)[:8]:
            try:
                replaced = current.replace(pat, rep)
            except Exception:
                continue
            if replaced != current:
                current = replaced
                steps.append("applied -replace '%s'→'%s'" % (pat[:20], rep[:20]))
        # The payload itself is usually the longest base64 blob present.
        for blob in sorted(RE_B64_LONG.findall(current), key=len, reverse=True)[:2]:
            decoded = _try_b64_payload(blob)
            if len(decoded) >= 16:
                current = current.replace(blob, decoded)
                steps.append("decoded base64%s payload (%d chars)" %
                             (" + decompressed" if "compress" in current.lower() else "", len(decoded)))
                break
        if current == before:
            break
    return current[:200000], steps


def carve_pe_from_memory(blob, max_files=4, max_bytes=8 * 1024 * 1024):
    """Find PE images inside an emulated memory dump.

    This is the payoff of dynamic analysis on a packed sample: the stub decrypts
    the real executable into RAM, so the memory image contains a PE that never
    existed on disk. Each one is returned so the caller can analyse it as its own
    sample — imports, capabilities, config and all — instead of staring at a
    packer stub.
    """
    out = []
    total = 0
    start = 0
    while len(out) < max_files and total < max_bytes:
        i = blob.find(b"MZ", start)
        if i < 0:
            break
        start = i + 2
        try:
            e_lfanew = struct.unpack_from("<I", blob, i + 0x3C)[0]
        except Exception:
            continue
        if e_lfanew <= 0 or e_lfanew > 0x1000 or i + e_lfanew + 24 > len(blob):
            continue
        if blob[i + e_lfanew:i + e_lfanew + 4] != b"PE\x00\x00":
            continue
        # SizeOfImage tells us how much of the region belongs to this image.
        try:
            magic = struct.unpack_from("<H", blob, i + e_lfanew + 24)[0]
            size_off = i + e_lfanew + 24 + (56 if magic == 0x20B else 56)
            size_of_image = struct.unpack_from("<I", blob, size_off)[0]
        except Exception:
            size_of_image = 0
        size = size_of_image if 0x400 <= size_of_image <= 32 * 1024 * 1024 else 0x100000
        size = min(size, len(blob) - i, max_bytes - total)
        if size < 0x400:
            continue
        data = bytes(blob[i:i + size])
        out.append({
            "offset": i,
            "size": len(data),
            "sha256": hashlib.sha256(data).hexdigest(),
            "b64": base64.b64encode(data).decode("ascii"),
        })
        total += len(data)
        start = i + size
    return out


def hex_escape_decode(text):
    """\\xNN and 0x-comma arrays, the other two ways scripts hide a payload."""
    out = []
    for m in re.findall(r"(?:\\x[0-9A-Fa-f]{2}){8,}", text)[:20]:
        try:
            out.append(bytes(int(b, 16) for b in re.findall(r"[0-9A-Fa-f]{2}", m)).decode("utf-8", "ignore"))
        except Exception:
            continue
    for m in re.findall(r"(?:0x[0-9A-Fa-f]{2}\s*,\s*){8,}0x[0-9A-Fa-f]{2}", text)[:10]:
        try:
            out.append(binascii.unhexlify("".join(re.findall(r"0x([0-9A-Fa-f]{2})", m))).decode("utf-8", "ignore"))
        except Exception:
            continue
    return [s for s in out if len(s.strip()) >= 8][:20]
