"""Triage extractors for the malware sidecar.

Everything here is STATIC and LOCAL: the sample is never executed, no tool
reaches the network. Each extractor is best-effort — a missing binary or a
crafted file yields an empty/partial result instead of failing the request, the
same contract the rest of the sidecar follows.

Covers the classic first-pass analyst toolbox:
  file(1) magic · exiftool metadata · ssdeep fuzzy hash · binwalk carving ·
  sliding-window entropy map · chi-square randomness · ClamAV (when a DB is
  present) · deep PE structure (rich header, version info, exports, resources,
  icon hash, TLS callbacks, PDB path, authentihash, checksum/timestamp anomalies).
"""
import hashlib
import math
import os
import re
import shutil
import struct
import subprocess

# Bounds: triage runs on every sample, so every step is cheap and capped.
TOOL_TIMEOUT = int(os.environ.get("TRIAGE_TOOL_TIMEOUT", "60"))
ENTROPY_BUCKETS = 192          # data points in the entropy map (UI chart width)
ENTROPY_MIN_WINDOW = 256       # never compute entropy over a window smaller than this
CLAMAV_TIMEOUT = int(os.environ.get("CLAMAV_TIMEOUT", "120"))


# ── generic helpers ───────────────────────────────────────────────────────────

def _run(argv, timeout=TOOL_TIMEOUT):
    """Run a tool, returning combined stdout+stderr text, or "" on any failure."""
    exe = shutil.which(argv[0])
    if not exe:
        return ""
    try:
        p = subprocess.run([exe] + argv[1:], capture_output=True, timeout=timeout)
    except Exception:
        return ""
    return (p.stdout + p.stderr).decode("utf-8", "replace")


def shannon(buf):
    """Byte-wise Shannon entropy in bits/byte (0-8)."""
    if not buf:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    n = float(len(buf))
    e = 0.0
    for c in counts:
        if c:
            p = c / n
            e -= p * math.log(p, 2)
    return e


def chi_square(buf):
    """Chi-square statistic against a uniform byte distribution. Encrypted or
    well-compressed data sits near 256 (uniform); structured data is far higher.
    Used to tell 'this file is encrypted' from 'this file is merely packed'."""
    if len(buf) < 256:
        return 0.0
    counts = [0] * 256
    for b in buf:
        counts[b] += 1
    expected = len(buf) / 256.0
    return sum((c - expected) ** 2 / expected for c in counts)


# ── external tools ────────────────────────────────────────────────────────────

def run_file_magic(path):
    """file(1)/libmagic type string — far broader than magic-byte heuristics
    (RTF, LNK, MSI, ISO, OneNote, Mach-O, dumps, …)."""
    out = _run(["file", "-b", "--", path], 30).strip()
    return out.splitlines()[0][:400] if out else ""


def run_file_mime(path):
    out = _run(["file", "-b", "--mime-type", "--", path], 30).strip()
    return out.splitlines()[0][:120] if out else ""


# exiftool keys worth keeping: authorship/toolchain/timestamps drive campaign
# clustering and attribution. The full dump is huge and mostly noise.
EXIF_KEYS = (
    "FileType", "FileTypeExtension", "MIMEType", "Author", "Creator", "Producer",
    "Company", "LastModifiedBy", "LastPrinted", "CreateDate", "ModifyDate",
    "Title", "Subject", "Keywords", "Comments", "Template", "Application",
    "AppVersion", "Software", "OriginalFilename", "InternalName", "ProductName",
    "ProductVersion", "FileVersion", "CompanyName", "FileDescription",
    "LegalCopyright", "PEType", "Subsystem", "TimeStamp", "MachineType",
    "CharacterSet", "LanguageCode", "Revision", "TotalEditTime", "Words",
    "GPSLatitude", "GPSLongitude", "Make", "Model", "CodeSize", "LinkerVersion",
)


def run_exiftool(path):
    """exiftool metadata, filtered to the investigative keys."""
    raw = _run(["exiftool", "-j", "-n", "-q", "--", path], 45)
    if not raw.strip():
        return {}
    try:
        import json as _json
        data = _json.loads(raw)
    except Exception:
        return {}
    if not isinstance(data, list) or not data:
        return {}
    src = data[0]
    out = {}
    for k in EXIF_KEYS:
        v = src.get(k)
        if v not in (None, "", []):
            out[k] = str(v)[:300]
    return out


def run_ssdeep(path):
    """ssdeep fuzzy hash — complements TLSH (which needs >=50 bytes of varied
    input, so small scripts and ransom notes often have no TLSH at all)."""
    out = _run(["ssdeep", "-b", "-s", "--", path], 45)
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("ssdeep,"):
            continue
        # format: blocksize:hash1:hash2,"filename"
        if re.match(r"^\d+:", line):
            return line.split(',"')[0].strip()[:200]
    return ""


BINWALK_SKIP = ("Unix path", "Copyright text", "HTML document", "XML document",
                "Base64 standard", "SHA256 hash constants", "AES S-Box",
                "AES Inverse S-Box", "CRC32 polynomial", "Neighborly text")
# Signatures worth surfacing: an embedded second stage is the point of carving.
BINWALK_KEEP_HINTS = ("executable", "archive", "compressed", "PDF", "PNG", "JPEG",
                      "Microsoft", "certificate", "PEM", "installer", "CAB",
                      "cpio", "squashfs", "ELF", "Zip", "gzip", "RAR", "7-zip")


def run_binwalk(data, path):
    """binwalk signature scan → embedded files/payloads at their offsets.
    Crypto-constant hits are kept separately: an AES S-Box or RSA constant in a
    binary tells you HOW it encrypts, which matters for ransomware triage."""
    out = _run(["binwalk", "--signature", "--term", "--", path], TOOL_TIMEOUT)
    embedded, crypto = [], []
    for line in out.splitlines():
        m = re.match(r"^\s*(\d+)\s+0x([0-9A-Fa-f]+)\s+(.+?)\s*$", line)
        if not m:
            continue
        off, desc = int(m.group(1)), m.group(3).strip()
        if off == 0:
            continue  # the file's own header
        low = desc.lower()
        if "s-box" in low or "constant" in low or "polynomial" in low or "sbox" in low:
            if desc not in crypto:
                crypto.append("0x%X: %s" % (off, desc))
            continue
        if any(s.lower() in low for s in BINWALK_SKIP):
            continue
        if any(h.lower() in low for h in BINWALK_KEEP_HINTS):
            embedded.append("0x%X: %s" % (off, desc))
        if len(embedded) >= 40 and len(crypto) >= 20:
            break
    # Fallback for images without binwalk: raw magic scan for an embedded PE/ZIP.
    if not embedded and not shutil.which("binwalk"):
        for magic, label in ((b"MZ\x90\x00", "PE/MZ executable"), (b"PK\x03\x04", "Zip archive"),
                             (b"\x1f\x8b\x08", "gzip compressed data"), (b"7z\xbc\xaf\x27\x1c", "7-zip archive")):
            start = 1
            while len(embedded) < 20:
                i = data.find(magic, start)
                if i < 0:
                    break
                embedded.append("0x%X: %s (raw magic scan)" % (i, label))
                start = i + 1
    return embedded[:40], crypto[:20]


def clamav_db_dirs():
    """Where signatures may live, in priority order."""
    return [d for d in (os.environ.get("CLAMAV_DB"), "/var/lib/clamav", "/usr/share/clamav") if d]


def clamav_db_dir():
    """The first directory that actually holds signature files, or ""."""
    for d in clamav_db_dirs():
        try:
            if any(f.endswith((".cvd", ".cld", ".cud", ".hdb", ".ndb", ".ldb")) for f in os.listdir(d)):
                return d
        except OSError:
            continue
    return ""


def clamav_db_present():
    """True only when signature files are actually installed. `clamscan` being on
    PATH proves nothing — without a database it exits 2 and scans nothing."""
    return clamav_db_dir() != ""


def run_clamav(path):
    """ClamAV scan — a second, fully offline detection engine. Only meaningful
    when a virus DB is present (freshclam is never run at build time: it would
    breach the no-egress guarantee).

    The exit code decides, not the text: 0 = clean, 1 = infected, anything else =
    the scan did not happen. Reporting "no detection" when ClamAV never loaded a
    database would be a false all-clear — the worst possible answer here."""
    exe = shutil.which("clamscan")
    if not exe or not clamav_db_present():
        return None
    cmd = [exe, "--no-summary", "--stdout", "--infected"]
    # Point clamscan at the same directory the in-product update writes to. Without
    # this it reads only its compiled-in default, so a database fetched into
    # CLAMAV_DB would be present on disk and still never used.
    db = clamav_db_dir()
    if db:
        cmd.append("--database=" + db)
    cmd += ["--", path]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=CLAMAV_TIMEOUT)
    except Exception:
        return None
    out = (p.stdout + p.stderr).decode("utf-8", "replace")
    if p.returncode == 1:
        m = re.search(r":\s*(.+?)\s+FOUND\s*$", out, re.M)
        return {"scanned": True, "infected": True,
                "signature": (m.group(1).strip()[:200] if m else "ClamAV detection")}
    if p.returncode == 0:
        return {"scanned": True, "infected": False, "signature": ""}
    return None  # rc 2 (or anything else): the scan failed — say nothing, not "clean"


# ── entropy map ───────────────────────────────────────────────────────────────

def entropy_map(data):
    """Sliding-window entropy across the file. This is what makes packing,
    embedded keys and appended payloads VISIBLE: a flat 6.5 with one 7.9 plateau
    at 60% offset is an encrypted blob inside an otherwise normal binary."""
    n = len(data)
    if n < ENTROPY_MIN_WINDOW:
        return {"window": n, "values": [round(shannon(data), 3)], "high_regions": []}
    window = max(ENTROPY_MIN_WINDOW, n // ENTROPY_BUCKETS)
    values, offsets = [], []
    off = 0
    while off < n and len(values) < ENTROPY_BUCKETS * 2:
        chunk = data[off:off + window]
        if len(chunk) < ENTROPY_MIN_WINDOW and values:
            break
        values.append(round(shannon(chunk), 3))
        offsets.append(off)
        off += window
    # Contiguous runs above 7.2 bits/byte = compressed/encrypted/packed regions.
    high, run = [], None
    for i, v in enumerate(values):
        if v >= 7.2:
            if run is None:
                run = [offsets[i], offsets[i] + window, v]
            else:
                run[1] = offsets[i] + window
                run[2] = max(run[2], v)
        elif run is not None:
            high.append({"offset": run[0], "size": run[1] - run[0], "entropy": round(run[2], 2)})
            run = None
    if run is not None:
        high.append({"offset": run[0], "size": min(run[1], n) - run[0], "entropy": round(run[2], 2)})
    return {"window": window, "values": values, "high_regions": high[:20]}


# ── deep PE structure (pefile) ────────────────────────────────────────────────

def _res_name(entry):
    try:
        if entry.name is not None:
            return str(entry.name)
        import pefile
        return pefile.RESOURCE_TYPE.get(entry.id, "ID_%s" % entry.id)
    except Exception:
        return "?"


def _walk_resources(pe, data):
    """Resource inventory + icon hash. A high-entropy resource is where droppers
    hide their payload; the icon hash clusters phishing lures that reuse an icon."""
    out, icon_hash = [], ""
    try:
        rsrc = pe.DIRECTORY_ENTRY_RESOURCE
    except Exception:
        return out, icon_hash
    for rtype in getattr(rsrc, "entries", [])[:24]:
        tname = _res_name(rtype)
        for rid in getattr(getattr(rtype, "directory", None), "entries", [])[:24]:
            for lang in getattr(getattr(rid, "directory", None), "entries", [])[:4]:
                try:
                    d = lang.data.struct
                    blob = pe.get_data(d.OffsetToData, d.Size)
                except Exception:
                    continue
                if not blob:
                    continue
                ent = shannon(blob[:65536])
                out.append({"type": tname, "id": str(getattr(rid, "id", "") or _res_name(rid)),
                            "size": len(blob), "entropy": round(ent, 2)})
                if tname in ("RT_ICON", "RT_GROUP_ICON") and not icon_hash:
                    icon_hash = hashlib.md5(blob).hexdigest()
                if len(out) >= 60:
                    return out, icon_hash
    return out, icon_hash


def _version_info(pe):
    """VersionInfo strings (CompanyName/OriginalFilename/…). Malware impersonating
    a legitimate product is one of the strongest single tells there is."""
    out = {}
    try:
        for fi in getattr(pe, "FileInfo", []) or []:
            entries = fi if isinstance(fi, list) else [fi]
            for e in entries:
                for st in getattr(e, "StringTable", []) or []:
                    for k, v in (st.entries or {}).items():
                        key = k.decode("utf-8", "ignore") if isinstance(k, bytes) else str(k)
                        val = v.decode("utf-8", "ignore") if isinstance(v, bytes) else str(v)
                        if key and val:
                            out[key[:60]] = val.strip()[:200]
    except Exception:
        pass
    return out


def _rich_header(pe):
    """Rich header hash — a fingerprint of the exact compiler/linker toolchain and
    object counts. Two samples built on the same dev box share it, which clusters
    authorship far more tightly than imphash."""
    try:
        rich = pe.parse_rich_header()
    except Exception:
        return "", []
    if not rich:
        return "", []
    clear = rich.get("clear_data") or b""
    rhash = hashlib.md5(clear).hexdigest() if clear else ""
    ids = []
    vals = rich.get("values") or []
    for i in range(0, len(vals) - 1, 2):
        comp_id, count = vals[i], vals[i + 1]
        ids.append("%d.%d x%d" % (comp_id >> 16, comp_id & 0xFFFF, count))
    return rhash, ids[:30]


def _tls_callbacks(pe):
    """TLS callbacks run BEFORE the entry point — a classic anti-debug / early
    execution trick that a naive 'analyse from the entrypoint' pass misses."""
    out = []
    try:
        tls = pe.DIRECTORY_ENTRY_TLS.struct
        addr = tls.AddressOfCallBacks
        if not addr:
            return out
        base = pe.OPTIONAL_HEADER.ImageBase
        size = 8 if pe.OPTIONAL_HEADER.Magic == 0x20B else 4
        rva = addr - base
        for _ in range(16):
            raw = pe.get_data(rva, size)
            if not raw or len(raw) < size:
                break
            val = struct.unpack("<Q" if size == 8 else "<I", raw)[0]
            if not val:
                break
            out.append(hex(val))
            rva += size
    except Exception:
        pass
    return out


def _pdb_path(pe):
    """Debug PDB path — frequently leaks the author's username, project name and
    build directory (e.g. C:\\Users\\admin\\source\\repos\\Stealer\\…)."""
    try:
        for dbg in getattr(pe, "DIRECTORY_ENTRY_DEBUG", []) or []:
            ent = getattr(dbg, "entry", None)
            name = getattr(ent, "PdbFileName", None)
            if name:
                return name.decode("utf-8", "ignore").rstrip("\x00")[:300]
    except Exception:
        pass
    return ""


def _authentihash(pe, data):
    """Authenticode hash: SHA256 of the file with the checksum field, the security
    data directory entry and the certificate table excluded. Lets you match a
    tampered/re-signed binary against the hash the publisher actually signed."""
    try:
        opt_off = pe.DOS_HEADER.e_lfanew + 24
        cks_off = opt_off + 64
        magic = pe.OPTIONAL_HEADER.Magic
        dd_off = opt_off + (112 if magic == 0x20B else 96)
        sec_off = dd_off + 4 * 8  # IMAGE_DIRECTORY_ENTRY_SECURITY is index 4
        cert_rva = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].VirtualAddress
        cert_size = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size
        h = hashlib.sha256()
        h.update(data[:cks_off])
        h.update(data[cks_off + 4:sec_off])
        end = len(data)
        if cert_rva and cert_size and cert_rva + cert_size <= len(data):
            end = cert_rva
        h.update(data[sec_off + 8:end])
        return h.hexdigest()
    except Exception:
        return ""


def pe_extended(data):
    """Deep PE structure the Go parser does not cover."""
    try:
        import pefile
    except Exception:
        return None
    try:
        pe = pefile.PE(data=data)
    except Exception:
        return None
    out = {}
    try:
        out["rich_hash"], out["rich_ids"] = _rich_header(pe)
        out["version_info"] = _version_info(pe)
        out["pdb_path"] = _pdb_path(pe)
        out["tls_callbacks"] = _tls_callbacks(pe)
        out["authentihash"] = _authentihash(pe, data)
        out["resources"], out["icon_hash"] = _walk_resources(pe, data)

        exports = []
        try:
            for exp in (pe.DIRECTORY_ENTRY_EXPORT.symbols or [])[:120]:
                nm = exp.name.decode("utf-8", "ignore") if exp.name else "#%s" % exp.ordinal
                exports.append(nm)
            out["export_dll_name"] = (pe.DIRECTORY_ENTRY_EXPORT.name or b"").decode("utf-8", "ignore")
        except Exception:
            pass
        out["exports"] = exports

        anomalies = []
        try:
            stored = pe.OPTIONAL_HEADER.CheckSum
            real = pe.generate_checksum()
            if stored and stored != real:
                anomalies.append("PE checksum mismatch (stored 0x%X, actual 0x%X) — file modified after build" % (stored, real))
        except Exception:
            pass
        try:
            import datetime
            ts = pe.FILE_HEADER.TimeDateStamp
            now = int(datetime.datetime.utcnow().timestamp())
            if ts == 0:
                anomalies.append("compile timestamp zeroed (deliberately stripped)")
            elif ts > now + 86400:
                anomalies.append("compile timestamp is in the FUTURE (%s) — faked" %
                                 datetime.datetime.utcfromtimestamp(min(ts, 2 ** 31 - 1)).isoformat())
            elif ts < 788918400:  # 1995-01-01
                anomalies.append("compile timestamp implausibly old — faked")
        except Exception:
            pass
        try:
            dc = pe.OPTIONAL_HEADER.DllCharacteristics
            missing = []
            if not dc & 0x0040:
                missing.append("ASLR")
            if not dc & 0x0100:
                missing.append("DEP/NX")
            if not dc & 0x4000:
                missing.append("CFG")
            if missing:
                anomalies.append("mitigations disabled: " + ", ".join(missing))
        except Exception:
            pass
        try:
            if pe.is_driver():
                anomalies.append("kernel driver (.sys) — runs in ring 0")
            out["subsystem"] = pefile.SUBSYSTEM_TYPE.get(pe.OPTIONAL_HEADER.Subsystem, "")
        except Exception:
            pass
        if out.get("pdb_path") and re.search(r"[Uu]sers\\|/home/", out["pdb_path"]):
            anomalies.append("debug PDB path leaks the build environment: " + out["pdb_path"])
        vi = out.get("version_info") or {}
        orig = vi.get("OriginalFilename", "")
        company = vi.get("CompanyName", "")
        if company and re.search(r"microsoft|google|adobe|oracle|intel|nvidia", company, re.I):
            anomalies.append("claims to be published by %r — verify against the Authenticode result (impersonation is common)" % company)
        if orig:
            out["original_filename"] = orig
        out["anomalies"] = anomalies
    finally:
        try:
            pe.close()
        except Exception:
            pass
    return out


# ── entry point ───────────────────────────────────────────────────────────────

def triage(path, data, filename="", skip=()):
    """Full first-pass triage of one sample. Never executes anything.

    `skip` holds the tool ids the operator switched off in the UI, so an admin's
    choice is honoured here and not merely filtered out after the fact."""
    off = set(skip or ())
    out = {
        "magic": run_file_magic(path) if "magic" not in off else "",
        "mime": run_file_mime(path) if "magic" not in off else "",
        "exiftool": run_exiftool(path) if "exiftool" not in off else {},
        "ssdeep": run_ssdeep(path) if "ssdeep" not in off else "",
        "entropy_map": entropy_map(data),
        "chi_square": round(chi_square(data[:1 << 20]), 1),
    }
    if "binwalk" not in off:
        embedded, crypto = run_binwalk(data, path)
        out["embedded"] = embedded
        out["crypto_constants"] = crypto
    if "clamav" not in off:
        clam = run_clamav(path)
        if clam:
            out["clamav"] = clam
    if data[:2] == b"MZ" and "pe_deep" not in off:
        pex = pe_extended(data)
        if pex:
            out["pe"] = pex
    if off:
        out["skipped"] = sorted(off)
    out["tools"] = {
        "file": bool(shutil.which("file")),
        "exiftool": bool(shutil.which("exiftool")),
        "ssdeep": bool(shutil.which("ssdeep")),
        "binwalk": bool(shutil.which("binwalk")),
        # Usable, not merely installed: without signatures ClamAV scans nothing.
        "clamav": bool(shutil.which("clamscan")) and clamav_db_present(),
    }
    return out
