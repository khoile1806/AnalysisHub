"""Extended document/lure analysis for the malware sidecar.

Covers the delivery formats that replaced VBA macros after Office started
blocking them by default, and which the base `/document` analyser did not touch:

  RTF          — embedded OLE objects, Equation Editor exploits (CVE-2017-11882)
  DDE          — Office fields that spawn a shell without any macro
  OLE          — oleid risk indicators, oleobj embedded payloads
  LNK          — the shortcut's hidden command line (post-macro era favourite)
  OneNote      — embedded file attachments (FileDataStoreObject)
  PDF          — object-stream aware keyword/JS extraction
  HTML         — HTML smuggling (blob + msSaveOrOpenBlob / data: download)

All parsing is static; nothing is opened by its host application.
"""
import binascii
import io
import re
import struct
import zlib

MAX_ITEMS = 40
SNIPPET = 4000


# ── RTF ───────────────────────────────────────────────────────────────────────

# CLSIDs abused by RTF droppers (Equation Editor / packager).
RTF_BAD_CLSID = {
    "0002ce02": "Microsoft Equation 3.0 (CVE-2017-11882 / CVE-2018-0802 exploit vector)",
    "00020906": "Word.Document.8 embedded document",
    "0003000c": "OLE Package (arbitrary embedded file — classic dropper)",
    "44f9a03b": "Adobe Acrobat document",
}


def analyze_rtf(path, data):
    out = {"objects": [], "suspicious": [], "iocs": []}
    text = data.decode("latin-1", "ignore")
    for clsid, label in RTF_BAD_CLSID.items():
        if clsid in text.lower().replace(" ", ""):
            out["suspicious"].append("embedded object CLSID %s — %s" % (clsid, label))
    if re.search(r"\\objupdate", text, re.I):
        out["suspicious"].append(r"\objupdate — the embedded object executes on open without user interaction")
    if re.search(r"equation|eqnedt32", text, re.I):
        out["suspicious"].append("references the Equation Editor (eqnedt32.exe) — exploit delivery")
    # Obfuscation tells: RTF parsers are lenient, so droppers pad control words.
    if re.search(r"\\bin[0-9]{4,}", text):
        out["suspicious"].append(r"\bin with a huge length — RTF obfuscation to hide the object payload")
    try:
        from oletools.rtfobj import RtfObjParser
        parser = RtfObjParser(data)
        parser.parse()
        for obj in parser.objects[:MAX_ITEMS]:
            entry = {
                "index": getattr(obj, "start", 0),
                "class_name": (getattr(obj, "class_name", b"") or b"").decode("utf-8", "ignore"),
                "filename": (getattr(obj, "filename", b"") or b"").decode("utf-8", "ignore"),
                "src_path": (getattr(obj, "src_path", b"") or b"").decode("utf-8", "ignore"),
                "size": len(getattr(obj, "oledata", b"") or b""),
            }
            out["objects"].append(entry)
            if entry["filename"]:
                out["iocs"].append("embedded file: " + entry["filename"])
            if entry["src_path"]:
                out["iocs"].append("source path: " + entry["src_path"])
            if entry["class_name"].lower() in ("equation.3", "package"):
                out["suspicious"].append("OLE class %r — used to drop/execute an embedded file" % entry["class_name"])
    except Exception as e:
        out.setdefault("notes", []).append("rtfobj unavailable: %s" % e)
    return out


# ── DDE ───────────────────────────────────────────────────────────────────────

def analyze_dde(path):
    """msodde: DDE/DDEAUTO fields execute commands with no macro involved."""
    try:
        from oletools import msodde
    except Exception:
        return []
    try:
        res = msodde.process_file(path, msodde.FIELD_FILTER_DEFAULT)
    except Exception:
        return []
    lines = [l.strip() for l in (res or "").splitlines() if l.strip()]
    return lines[:MAX_ITEMS]


# ── OLE indicators ────────────────────────────────────────────────────────────

def analyze_oleid(path):
    """oleid: quick risk indicators for any OLE/OOXML container."""
    out = []
    try:
        from oletools.oleid import OleID
    except Exception:
        return out
    try:
        oid = OleID(path)
        for ind in oid.check():
            risk = str(getattr(ind, "risk", "") or "")
            value = getattr(ind, "value", "")
            if risk.lower() in ("high", "medium") or value in (True, "True"):
                out.append("%s: %s (%s)" % (getattr(ind, "name", "?"), value, risk or "info"))
    except Exception:
        pass
    return out[:MAX_ITEMS]


def analyze_oleobj(path):
    """oleobj: embedded OLE objects / external relationship links (template
    injection pulls the real payload from a remote URL at open time)."""
    out = {"embedded": [], "external_links": []}
    try:
        from oletools import oleobj
    except Exception:
        return out
    try:
        for rel_type, target in oleobj.find_external_relationships(open(path, "rb").read()) or []:
            out["external_links"].append("%s → %s" % (rel_type, target))
    except Exception:
        pass
    return out


# ── LNK ───────────────────────────────────────────────────────────────────────

LNK_MAGIC = b"\x4c\x00\x00\x00\x01\x14\x02\x00"


def analyze_lnk(data):
    """Windows shortcut: the payload lives in the (usually hidden) command-line
    arguments — `powershell -enc …`, `cmd /c curl …`, an .iso-relative path."""
    out = {"target": "", "arguments": "", "working_dir": "", "icon": "",
           "suspicious": [], "strings": []}
    try:
        import LnkParse3
        import io
        lnk = LnkParse3.lnk_file(io.BytesIO(data))
        info = lnk.get_json()
        d = info.get("data", {}) or {}
        out["target"] = str(d.get("relative_path") or "")[:500]
        out["arguments"] = str(d.get("command_line_arguments") or "")[:4000]
        out["working_dir"] = str(d.get("working_directory") or "")[:500]
        out["icon"] = str(d.get("icon_location") or "")[:500]
    except Exception:
        # Fallback: LNK StringData is UTF-16LE; pull the readable runs directly.
        try:
            txt = data.decode("utf-16-le", "ignore")
            runs = [r for r in re.findall(r"[\x20-\x7e]{6,}", txt)]
            out["strings"] = runs[:60]
            for r in runs:
                low = r.lower()
                if any(k in low for k in ("powershell", "cmd.exe", "-enc", "mshta", "rundll32",
                                          "curl", "certutil", "wscript", "http://", "https://")):
                    out["arguments"] = (out["arguments"] + " " + r).strip()[:4000]
        except Exception:
            pass
    blob = " ".join([out["target"], out["arguments"], out["working_dir"], out["icon"]] + out["strings"]).lower()
    for marker, why in (
        ("powershell", "launches PowerShell"),
        ("-enc", "base64-encoded PowerShell command"),
        ("-w hidden", "hidden window"),
        ("-nop", "bypasses the PowerShell profile"),
        ("mshta", "launches mshta (proxy execution)"),
        ("rundll32", "launches rundll32 (proxy execution)"),
        ("regsvr32", "launches regsvr32 (proxy execution)"),
        ("certutil", "uses certutil to download/decode"),
        ("curl", "downloads with curl"),
        ("bitsadmin", "downloads with bitsadmin"),
        ("cmd.exe", "launches a command shell"),
        ("wscript", "launches Windows Script Host"),
        ("http://", "contains an HTTP URL"),
        ("https://", "contains an HTTPS URL"),
        ("\\appdata\\", "references the user AppData directory"),
        ("%temp%", "references the TEMP directory"),
    ):
        if marker in blob:
            out["suspicious"].append("%s — %s" % (marker, why))
    return out


# ── OneNote ───────────────────────────────────────────────────────────────────

# FileDataStoreObject GUID that wraps every embedded attachment in a .one file.
ONENOTE_GUID = binascii.unhexlify("e716e3bd65254511a4c48d4d0b7a9eac")


def analyze_onenote(data):
    """OneNote sections carry embedded files verbatim; attackers ship a .one with
    a hidden .hta/.cmd behind a 'Double-click to open' image."""
    out = {"embedded": []}
    start = 0
    while True:
        i = data.find(ONENOTE_GUID, start)
        if i < 0 or len(out["embedded"]) >= 20:
            break
        try:
            size = struct.unpack("<Q", data[i + 16:i + 24])[0]
        except Exception:
            break
        blob = data[i + 36:i + 36 + min(size, 32 * 1024 * 1024)]
        kind = "unknown"
        if blob[:2] == b"MZ":
            kind = "PE executable"
        elif blob[:4] == b"PK\x03\x04":
            kind = "ZIP archive"
        elif blob[:5] == b"%PDF-":
            kind = "PDF"
        elif re.match(rb"^\s*(<\s*(html|script)|@echo|powershell|cscript|wscript|set )", blob[:200], re.I):
            kind = "script"
        preview = blob[:600].decode("utf-8", "ignore")
        out["embedded"].append({"offset": i, "size": int(size), "kind": kind,
                                "preview": re.sub(r"[^\x20-\x7e\n]", ".", preview)})
        start = i + 16
    return out


# ── PDF (object-stream aware) ─────────────────────────────────────────────────

PDF_KEYWORDS = ("/JS", "/JavaScript", "/OpenAction", "/AA", "/Launch", "/EmbeddedFile",
                "/URI", "/SubmitForm", "/RichMedia", "/AcroForm", "/XFA", "/GoToE",
                "/GoToR", "/ObjStm", "/Encrypt")


def analyze_pdf_deep(data):
    """pdfid-style keyword census PLUS decompressed stream contents, so JS hidden
    inside a FlateDecode object stream is actually seen."""
    out = {"keywords": {}, "scripts": [], "urls": [], "suspicious": []}
    text = data.decode("latin-1", "ignore")
    for kw in PDF_KEYWORDS:
        n = text.count(kw)
        if n:
            out["keywords"][kw] = n
    for kw, why in (("/OpenAction", "runs an action as soon as the document opens"),
                    ("/AA", "additional-action trigger (open/close/page events)"),
                    ("/Launch", "launches an external program"),
                    ("/EmbeddedFile", "carries an embedded file"),
                    ("/JS", "contains JavaScript"),
                    ("/JavaScript", "contains JavaScript"),
                    ("/XFA", "XFA form (used to smuggle script)"),
                    ("/GoToE", "jumps into an embedded file"),
                    ("/RichMedia", "embeds Flash/rich media")):
        if out["keywords"].get(kw):
            out["suspicious"].append("%s x%d — %s" % (kw, out["keywords"][kw], why))
    # Decompress every FlateDecode stream and look inside.
    for m in re.finditer(rb"stream\r?\n", data):
        start = m.end()
        end = data.find(b"endstream", start)
        if end < 0:
            continue
        raw = data[start:end]
        if len(raw) > 8 << 20:
            continue
        try:
            dec = zlib.decompress(raw)
        except Exception:
            continue
        txt = dec.decode("utf-8", "ignore")
        if re.search(r"\b(eval|unescape|String\.fromCharCode|app\.launchURL|this\.exportDataObject|util\.print[dfx])\b", txt):
            out["scripts"].append(txt[:SNIPPET])
        for u in re.findall(r"https?://[^\s<>\)\"']{4,500}", txt):
            if u not in out["urls"]:
                out["urls"].append(u)
        if len(out["scripts"]) >= 10 and len(out["urls"]) >= 50:
            break
    for u in re.findall(r"/URI\s*\(([^)]{4,500})\)", text):
        if u not in out["urls"]:
            out["urls"].append(u.strip())
    out["urls"] = out["urls"][:80]
    return out


# ── HTML smuggling ────────────────────────────────────────────────────────────

SMUGGLE_MARKERS = (
    ("msSaveOrOpenBlob", "writes a Blob straight to disk (classic HTML smuggling)"),
    ("msSaveBlob", "writes a Blob straight to disk"),
    ("createObjectURL", "builds a download URL from in-page data"),
    ("download=", "anchor with a forced download attribute"),
    ("atob(", "base64-decodes an embedded payload in the browser"),
    ("Uint8Array", "reconstructs binary content from an array"),
    ("charCodeAt", "byte-level payload reconstruction"),
    ("data:application/octet-stream", "inline binary data URI"),
    ("window.location.replace", "auto-redirect"),
    ("<meta http-equiv=\"refresh\"", "meta-refresh redirect"),
    ("document.write(unescape", "obfuscated document writer"),
)


def analyze_html(data):
    """HTML attachment: smuggling markers + embedded payload sizes + forms."""
    text = data.decode("utf-8", "ignore")
    low = text.lower()
    out = {"markers": [], "urls": [], "embedded_blobs": [], "forms": []}
    for marker, why in SMUGGLE_MARKERS:
        if marker.lower() in low:
            out["markers"].append("%s — %s" % (marker, why))
    for m in re.finditer(r"['\"]([A-Za-z0-9+/]{512,}={0,2})['\"]", text):
        blob = m.group(1)
        kind = ""
        try:
            import base64
            head = base64.b64decode(blob[:64] + "==", validate=False)
            if head[:2] == b"MZ":
                kind = "PE executable"
            elif head[:4] == b"PK\x03\x04":
                kind = "ZIP archive"
            elif head[:5] == b"%PDF-":
                kind = "PDF"
        except Exception:
            pass
        out["embedded_blobs"].append({"length": len(blob), "kind": kind or "unknown"})
        if len(out["embedded_blobs"]) >= 10:
            break
    for m in re.finditer(r"<form[^>]*action\s*=\s*[\"']([^\"']+)", text, re.I):
        out["forms"].append(m.group(1)[:300])
    if re.search(r"type\s*=\s*[\"']password[\"']", text, re.I):
        out["markers"].append("password input field — credential harvesting page")
    out["urls"] = list(dict.fromkeys(re.findall(r"https?://[^\s\"'<>]{4,500}", text)))[:60]
    return out


# ── modern Office exploit chains ──────────────────────────────────────────────
# The 2017 Equation Editor bug is handled above; these are the ones that replaced
# it and are still the two most common "document that needs no macro" chains.
EXPLOIT_MARKERS = (
    # CVE-2022-30190 (Follina): a document fetches an HTML file that invokes the
    # ms-msdt: protocol handler, which runs a PowerShell command line.
    (re.compile(rb"ms-msdt:", re.I), "CVE-2022-30190 (Follina) — ms-msdt: protocol handler invocation"),
    (re.compile(rb"IT_BrowseForFile\s*=", re.I), "CVE-2022-30190 (Follina) — MSDT IT_BrowseForFile payload parameter"),
    (re.compile(rb"ms-search:|ms-officecmd:|search-ms:", re.I), "URI-handler abuse (ms-search / ms-officecmd)"),
    # CVE-2021-40444: an OOXML relationship pulls a remote HTML which loads a CAB
    # or an ActiveX/mhtml object.
    (re.compile(rb"mhtml:https?://", re.I), "CVE-2021-40444 — mhtml: remote object load"),
    (re.compile(rb"\.cab!", re.I), "CVE-2021-40444 — CAB path traversal payload reference"),
    (re.compile(rb"oleObject\d*\.bin", re.I), "embedded OLE object stream"),
    # Remote template injection: the payload is not in the file at all.
    (re.compile(rb"attachedTemplate[^>]{0,200}https?://", re.I), "remote template injection (attachedTemplate → URL)"),
    (re.compile(rb"frameset[^>]{0,200}https?://", re.I), "remote frame pulls external content"),
)


def scan_exploit_markers(data):
    """Byte-level scan for the modern document-exploit chains. Runs over the RAW
    file (and, for OOXML, its unzipped parts) because the marker usually lives in
    a relationship or an embedded object rather than in visible text."""
    hits = []
    seen = set()

    def check(blob, where):
        for pat, label in EXPLOIT_MARKERS:
            if pat.search(blob) and label not in seen:
                seen.add(label)
                hits.append("%s%s" % (label, (" [in %s]" % where) if where else ""))

    check(data[: 8 << 20], "")
    # OOXML is a ZIP: the interesting parts are the relationship files.
    if data[:2] == b"PK":
        try:
            import zipfile
            with zipfile.ZipFile(io.BytesIO(data)) as z:
                for name in z.namelist()[:200]:
                    low = name.lower()
                    if not (low.endswith(".rels") or low.endswith(".xml") or "embeddings" in low):
                        continue
                    try:
                        part = z.read(name)
                    except Exception:
                        continue
                    check(part[: 2 << 20], name)
                    for m in re.finditer(rb"""Target="(https?://[^"]{4,400})"[^>]*TargetMode="External""", part):
                        url = m.group(1).decode("utf-8", "ignore")
                        label = "external relationship in %s → %s" % (name, url)
                        if label not in seen:
                            seen.add(label)
                            hits.append(label)
        except Exception:
            pass
    return hits[:40]


# ── dispatcher ────────────────────────────────────────────────────────────────

def extended(path, data, ext, doc_type, skip=()):
    """Run whichever extended analysers apply. Returns a dict merged into the
    /document response by the caller (empty when nothing applies). `skip` holds
    the tool ids the operator switched off in the UI."""
    out = {}
    off = set(skip or ())
    low_ext = (ext or "").lower()
    head = data[:8]

    if "rtfobj" not in off and (low_ext == ".rtf" or data[:5] == b"{\\rtf"):
        out["rtf"] = analyze_rtf(path, data)
    if "lnk" not in off and (low_ext == ".lnk" or head == LNK_MAGIC):
        out["lnk"] = analyze_lnk(data)
    if "onenote" not in off and (low_ext == ".one" or ONENOTE_GUID in data[:4096]):
        out["onenote"] = analyze_onenote(data)
    if "html_smuggling" not in off and (
            low_ext in (".html", ".htm", ".hta", ".mht", ".mhtml")
            or re.match(rb"^\s*<(!doctype html|html|head|script)", data[:200], re.I)):
        out["html"] = analyze_html(data)
    if "pdf_deep" not in off and (doc_type == "pdf" or data[:5] == b"%PDF-"):
        out["pdf_deep"] = analyze_pdf_deep(data)
    # The modern chains hide in relationships and embedded objects rather than in
    # visible text, so the byte scan runs for every document type.
    marks = scan_exploit_markers(data)
    if marks:
        out["exploit_markers"] = marks
    if doc_type == "office" or head[:4] == b"\xd0\xcf\x11\xe0" or head[:2] == b"PK":
        if "oleid" not in off:
            ole = analyze_oleid(path)
            if ole:
                out["oleid"] = ole
            rels = analyze_oleobj(path)
            if rels.get("external_links"):
                out["external_links"] = rels["external_links"]
        if "msodde" not in off:
            dde = analyze_dde(path)
            if dde:
                out["dde"] = dde
    return out


def summarize(ext_result):
    """Flatten the extended results into (suspicious[], iocs[], scripts[]) so the
    existing DocAnalysis contract (and the AI prompt) picks them up unchanged."""
    suspicious, iocs, scripts = [], [], []
    rtf = ext_result.get("rtf") or {}
    suspicious += rtf.get("suspicious", [])
    iocs += rtf.get("iocs", [])
    lnk = ext_result.get("lnk") or {}
    if lnk.get("arguments"):
        scripts.append("LNK command line: " + lnk["arguments"])
    suspicious += ["LNK: " + s for s in lnk.get("suspicious", [])]
    if lnk.get("target"):
        iocs.append("LNK target: " + lnk["target"])
    one = ext_result.get("onenote") or {}
    for e in one.get("embedded", []):
        suspicious.append("OneNote embedded %s (%d bytes at offset %d)" % (e["kind"], e["size"], e["offset"]))
    html = ext_result.get("html") or {}
    suspicious += ["HTML: " + m for m in html.get("markers", [])]
    for b in html.get("embedded_blobs", []):
        suspicious.append("HTML carries a %d-char base64 blob (%s) — HTML smuggling" % (b["length"], b["kind"]))
    iocs += html.get("urls", [])[:30]
    iocs += ["form posts to " + f for f in html.get("forms", [])[:10]]
    pdf = ext_result.get("pdf_deep") or {}
    suspicious += pdf.get("suspicious", [])
    scripts += pdf.get("scripts", [])
    iocs += pdf.get("urls", [])[:30]
    suspicious += ["exploit: " + s for s in ext_result.get("exploit_markers", [])]
    suspicious += ["oleid: " + s for s in ext_result.get("oleid", [])]
    suspicious += ["DDE field: " + s for s in ext_result.get("dde", [])]
    suspicious += ["external relationship (template injection?): " + s
                   for s in ext_result.get("external_links", [])]
    dedup = lambda xs: list(dict.fromkeys([x for x in xs if x]))  # noqa: E731
    return dedup(suspicious)[:80], dedup(iocs)[:80], dedup(scripts)[:12]
