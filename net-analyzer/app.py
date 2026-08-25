"""Network-analysis sidecar — runs Suricata over an uploaded pcap and distils its
eve.json into a compact, typed summary the backend reasons over: connection flows
(for the graph), DNS/TLS(JA3)/HTTP metadata, file transfers, and — most valuable —
ET-Open signature ALERTS (C2 / malware detection). Nothing is executed; Suricata
only reads the packet file.

POST /analyze  (multipart: file)  -> distilled network JSON
GET  /health                       -> {"ok": true, "suricata": bool, "rules": int}
"""
import base64
import bisect
import csv
import hashlib
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import tempfile

from flask import Flask, request, jsonify

app = Flask(__name__)

ANALYZE_TIMEOUT = int(os.environ.get("NET_ANALYZE_TIMEOUT", "600"))
RULES = os.environ.get("SURICATA_RULES", "/var/lib/suricata/rules/suricata.rules")
YARA_RULES = os.environ.get("YARA_RULES", "/rules/analysishub_malware.yar")

# Per-list caps so a huge pcap can't blow the response / DB.
CAP_FLOWS = 4000
CAP_ALERTS = 2000
CAP_DNS = 2000
CAP_TLS = 1500
CAP_HTTP = 2000
CAP_FILES = 500

# File carving: Suricata writes reconstructed files to <out>/filestore. We return
# the small ones inline (base64) so the backend can move them into the Evidence
# Store. Bounded so a pcap full of large downloads can't blow the response.
CARVE_MAX_FILE = int(os.environ.get("NET_CARVE_MAX_FILE", str(16 * 1024 * 1024)))  # 16 MB/file
CARVE_MAX_FILES = int(os.environ.get("NET_CARVE_MAX_FILES", "20"))
CARVE_MAX_TOTAL = int(os.environ.get("NET_CARVE_MAX_TOTAL", str(48 * 1024 * 1024)))  # 48 MB total


# Suricata's own engine events describe the CAPTURE and the parser's view of it,
# not the traffic's intent. They are emitted by the decoder/stream/app-layer
# machinery rather than by a detection ruleset, and they fire constantly on
# perfectly ordinary evidence:
#
#   invalid checksum      — any NIC with TX offload (every Docker veth, every VM)
#   3way handshake …      — a capture that started mid-conversation, or one side
#                           of an asymmetric path
#   unable to match …     — a truncated capture, or a filter that kept one direction
#
# Measured on real files: an hping3 flood produced 191 alerts, ALL of them stream
# events and none from a ruleset — while the capture's actual attack went
# unreported. Counting these buries genuine detections and drives the verdict off
# artifacts of how the pcap was taken.
#
# Only events prefixed "SURICATA " are engine events; every ruleset signature
# (ET/…) keeps its own prefix and is never touched by this.
_ENGINE_EVENT_MARKERS = (
    "invalid checksum", "checksum invalid",
    "3way handshake", "invalid ack", "wrong seq", "wrong thread",
    "shutdown rst", "pkt seen on wrong thread",
    "applayer detect protocol", "applayer protocol detection skipped",
    "applayer wrong direction first data", "applayer mismatch protocol",
    "unable to match response to request", "unable to match request to response",
    "reassembly", "segment before base seq", "retransmission",
    "excessive retransmissions", "packet with broken ack",
    "data on stream", "suspected data injection",
)


def _is_capture_artifact(signature):
    """True for a Suricata ENGINE event, as opposed to a ruleset detection."""
    sig = (signature or "").lower()
    if not sig.startswith("suricata "):
        return False  # a real ruleset detection, whatever it says
    return any(m in sig for m in _ENGINE_EVENT_MARKERS)


def run_suricata(pcap_path, out_dir):
    """Run Suricata in offline mode over the pcap. Returns True on a run that
    produced eve.json (even with warnings). File carving (file-store) is enabled
    so payloads/malware transferred over the wire can be pulled out of the pcap."""
    exe = shutil.which("suricata")
    if not exe:
        return False
    cmd = [exe, "-r", pcap_path, "-l", out_dir, "-k", "none",
           "--set", "app-layer.protocols.tls.ja3-fingerprints=yes",
           # Reconstruct transferred files into <out>/filestore for carving.
           "--set", "file-store.version=2",
           "--set", "file-store.enabled=yes",
           "--set", "file-store.force-filestore=yes",
           "--set", "file-store.dir=filestore"]
    if os.path.exists(RULES):
        cmd += ["-S", RULES]
    try:
        subprocess.run(cmd, capture_output=True, timeout=ANALYZE_TIMEOUT)
    except Exception:
        pass
    return os.path.exists(os.path.join(out_dir, "eve.json"))


def collect_carved(out_dir, wanted_sha):
    """Read reconstructed files from Suricata's filestore (indexed by sha256) and
    return the small ones as {sha256, size, b64}. Bounded by the CARVE_* caps."""
    store = os.path.join(out_dir, "filestore")
    if not os.path.isdir(store):
        return []
    carved, total = [], 0
    seen = set()
    for root, _dirs, fnames in os.walk(store):
        for name in fnames:
            sha = name.lower()
            if sha in seen or (wanted_sha and sha not in wanted_sha):
                continue
            fp = os.path.join(root, name)
            try:
                sz = os.path.getsize(fp)
            except OSError:
                continue
            if sz == 0 or sz > CARVE_MAX_FILE or total + sz > CARVE_MAX_TOTAL:
                continue
            try:
                with open(fp, "rb") as fh:
                    data = fh.read()
            except OSError:
                continue
            seen.add(sha)
            total += sz
            carved.append({"sha256": sha, "size": sz, "yara": yara_scan(fp),
                           "b64": base64.b64encode(data).decode("ascii")})
            if len(carved) >= CARVE_MAX_FILES:
                return carved
    return carved


def yara_scan(path):
    """Scan a carved file with the bundled YARA ruleset; return matched rule
    names. Best-effort: missing binary/rules or a timeout → no matches."""
    if not os.path.exists(YARA_RULES) or not shutil.which("yara"):
        return []
    try:
        p = subprocess.run(["yara", "-w", YARA_RULES, path],
                           capture_output=True, timeout=30, text=True)
    except Exception:
        return []
    rules = []
    for ln in (p.stdout or "").splitlines():
        parts = ln.split()
        if parts and parts[0] and parts[0] not in rules:
            rules.append(parts[0])
    return rules[:20]


def proto_hierarchy(pcap):
    """tshark protocol-hierarchy stats (io,phs) → a flat, indented tree of
    {name, level, frames, bytes} so the UI can show what protocols the capture
    actually contains and their share of traffic."""
    if not shutil.which("tshark"):
        return []
    try:
        p = subprocess.run(["tshark", "-r", pcap, "-q", "-z", "io,phs"],
                           capture_output=True, timeout=120, text=True)
    except Exception:
        return []
    out, started = [], False
    for ln in (p.stdout or "").splitlines():
        if "Protocol Hierarchy Statistics" in ln:
            started = True
            continue
        if not started or not ln.strip() or ln.strip().startswith("==="):
            continue
        m = re.match(r"^(\s*)(\S+)\s+frames:(\d+)\s+bytes:(\d+)", ln)
        if m:
            out.append({"name": m.group(2), "level": len(m.group(1)) // 2,
                        "frames": int(m.group(3)), "bytes": int(m.group(4))})
        if len(out) >= 60:
            break
    return out


# ── GeoIP / ASN (offline, sapics/ip-location-db CSV ranges) ──────────────────
_GEO = None


def _ip4_to_int(s):
    try:
        return struct.unpack("!I", socket.inet_aton(s))[0]
    except OSError:
        return None


def _load_ranges_csv(path, valfn):
    """Load an IP-range CSV (start,end,...) into (starts[], rows[]) sorted by
    start, where each row is (start_int, end_int, value=valfn(record))."""
    rows = []
    if path and os.path.exists(path):
        try:
            with open(path, newline="", errors="replace") as fh:
                for rec in csv.reader(fh):
                    if len(rec) < 3:
                        continue
                    s = _ip4_to_int(rec[0])
                    e = _ip4_to_int(rec[1])
                    if s is None or e is None:
                        continue
                    rows.append((s, e, valfn(rec)))
        except OSError:
            pass
    rows.sort(key=lambda r: r[0])
    return [r[0] for r in rows], rows


def _load_geo():
    global _GEO
    if _GEO is not None:
        return _GEO
    asn_starts, asn_rows = _load_ranges_csv(
        os.environ.get("GEOIP_ASN", "/data/asn-ipv4.csv"),
        lambda r: (r[2], r[3] if len(r) > 3 else ""))
    cc_starts, cc_rows = _load_ranges_csv(
        os.environ.get("GEOIP_COUNTRY", "/data/country-ipv4.csv"),
        lambda r: r[2])
    _GEO = {"asn_starts": asn_starts, "asn_rows": asn_rows,
            "cc_starts": cc_starts, "cc_rows": cc_rows}
    return _GEO


def _range_lookup(starts, rows, v):
    if not rows:
        return None
    i = bisect.bisect_right(starts, v) - 1
    if i < 0:
        return None
    s, e, val = rows[i]
    return val if s <= v <= e else None


def geo_lookup(ip):
    """Return {asn, cc, org} for an IPv4 address, or None (private/unknown)."""
    v = _ip4_to_int(ip)
    if v is None:
        return None
    g = _load_geo()
    asn = _range_lookup(g["asn_starts"], g["asn_rows"], v)
    cc = _range_lookup(g["cc_starts"], g["cc_rows"], v)
    if not asn and not cc:
        return None
    out = {"asn": (asn[0] if asn else ""), "org": (asn[1] if asn else ""), "cc": cc or ""}
    if out["asn"] in ("", "0") and not out["cc"]:
        return None
    return out


def geo_enrich(ips):
    """Build {ip: {asn, cc, org}} for up to 400 external addresses."""
    out = {}
    for ip in ips[:400]:
        g = geo_lookup(ip)
        if g:
            out[ip] = g
    return out


# ── Zeek — deep protocol logs (best-effort; disabled if zeek isn't installed) ─
def run_zeek(pcap):
    """Run Zeek offline over the pcap (JSON logs) and return the output dir, or
    None when Zeek is unavailable."""
    zeek = shutil.which("zeek") or ("/opt/zeek/bin/zeek" if os.path.exists("/opt/zeek/bin/zeek") else None)
    if not zeek:
        return None
    d = tempfile.mkdtemp(prefix="zeek-")
    try:
        # extract-all-files reconstructs transferred files for EVERY protocol Zeek
        # parses, which is the point: measured on a real capture, Suricata produced
        # no fileinfo event at all for a binary sent over FTP-data — it could not
        # tie the data channel to its control channel (app_proto "failed") — while
        # Zeek identified the same file by name and size. Carving only from
        # Suricata's filestore therefore loses every SMB, FTP and SMTP transfer,
        # which is most of what matters in a lateral-movement or phishing capture.
        subprocess.run([zeek, "-C", "-r", pcap, "LogAscii::use_json=T",
                        "policy/frameworks/files/extract-all-files",
                        "FileExtract::default_limit=%d" % CARVE_MAX_FILE],
                       cwd=d, capture_output=True, timeout=ANALYZE_TIMEOUT)
    except Exception:
        pass
    return d


# Zeek names an extracted file extract-<ts>-<protocol>-<fuid>.<ext>; the protocol
# is the only part worth keeping, since it says HOW the file crossed the wire.
_ZEEK_EXTRACT_RE = re.compile(r"^extract-[^-]*-(?P<proto>[A-Za-z0-9_]+)-")


def collect_zeek_carved(zdir, have_sha, budget):
    """Read files Zeek reconstructed and return (carved, file_records) for the ones
    not already carved by Suricata. `budget` is the remaining byte allowance."""
    if not zdir:
        return [], []
    store = os.path.join(zdir, "extract_files")
    if not os.path.isdir(store):
        return [], []
    carved, records, total = [], [], 0
    for name in sorted(os.listdir(store)):
        if len(carved) >= CARVE_MAX_FILES:
            break
        fp = os.path.join(store, name)
        try:
            sz = os.path.getsize(fp)
        except OSError:
            continue
        if sz == 0 or sz > CARVE_MAX_FILE or total + sz > budget:
            continue
        try:
            with open(fp, "rb") as fh:
                data = fh.read()
        except OSError:
            continue
        sha = hashlib.sha256(data).hexdigest()
        if sha in have_sha:
            continue
        have_sha.add(sha)
        total += sz
        m = _ZEEK_EXTRACT_RE.match(name)
        proto = (m.group("proto") if m else "zeek").upper()
        carved.append({"sha256": sha, "size": sz, "yara": yara_scan(fp),
                       "b64": base64.b64encode(data).decode("ascii")})
        records.append({"filename": name, "magic": "", "size": sz, "sha256": sha,
                        "md5": "", "src": "", "dst": "", "source": proto, "carved_by": "zeek"})
    return carved, records


def _read_ndjson(path, cap):
    out = []
    if not os.path.exists(path):
        return out
    try:
        with open(path, errors="replace") as fh:
            for ln in fh:
                ln = ln.strip()
                if not ln:
                    continue
                try:
                    out.append(json.loads(ln))
                except Exception:
                    continue
                if len(out) >= cap:
                    break
    except OSError:
        pass
    return out


def _first(v):
    return v[0] if isinstance(v, list) and v else (v if isinstance(v, str) else "")


def distil_zeek(d):
    """Distil the Zeek logs we care about: notices, file provenance, TLS
    validation, and lateral-movement/auth events (SMB/Kerberos/NTLM/SSH)."""
    if not d:
        return {}
    z = {}
    notices = []
    for e in _read_ndjson(os.path.join(d, "notice.log"), 300):
        notices.append({"note": e.get("note", ""), "msg": e.get("msg", ""), "sub": e.get("sub", ""),
                        "src": e.get("src") or e.get("id.orig_h", ""), "dst": e.get("dst") or e.get("id.resp_h", "")})
    if notices:
        z["notices"] = notices

    files = []
    for e in _read_ndjson(os.path.join(d, "files.log"), 500):
        files.append({"tx": _first(e.get("tx_hosts")), "rx": _first(e.get("rx_hosts")),
                      "source": e.get("source", ""), "mime": e.get("mime_type", ""),
                      "filename": e.get("filename", ""), "sha256": e.get("sha256", ""),
                      "md5": e.get("md5", ""), "bytes": e.get("total_bytes") or e.get("seen_bytes") or 0})
    if files:
        z["files"] = files

    ssl = []
    for e in _read_ndjson(os.path.join(d, "ssl.log"), 500):
        ssl.append({"server_name": e.get("server_name", ""), "version": e.get("version", ""),
                    "ja3": e.get("ja3", ""), "ja3s": e.get("ja3s", ""), "subject": e.get("subject", ""),
                    "issuer": e.get("issuer", ""), "validation": e.get("validation_status", ""),
                    "dst": e.get("id.resp_h", "")})
    if ssl:
        z["ssl"] = ssl

    kerb = [{"client": e.get("client", ""), "service": e.get("service", ""), "success": e.get("success"),
             "src": e.get("id.orig_h", ""), "dst": e.get("id.resp_h", "")}
            for e in _read_ndjson(os.path.join(d, "kerberos.log"), 200)]
    if kerb:
        z["kerberos"] = kerb
    ntlm = [{"user": e.get("username", ""), "host": e.get("hostname", ""), "domain": e.get("domainname", ""),
             "src": e.get("id.orig_h", ""), "dst": e.get("id.resp_h", "")}
            for e in _read_ndjson(os.path.join(d, "ntlm.log"), 200)]
    if ntlm:
        z["ntlm"] = ntlm
    smb = [{"action": e.get("action", ""), "path": e.get("path", ""), "name": e.get("name", ""),
            "src": e.get("id.orig_h", ""), "dst": e.get("id.resp_h", "")}
           for e in _read_ndjson(os.path.join(d, "smb_files.log"), 200)]
    if smb:
        z["smb"] = smb
    ssh = [{"success": e.get("auth_success"), "client": e.get("client", ""), "server": e.get("server", ""),
            "src": e.get("id.orig_h", ""), "dst": e.get("id.resp_h", "")}
           for e in _read_ndjson(os.path.join(d, "ssh.log"), 200)]
    if ssh:
        z["ssh"] = ssh
    return z


# ── TLS decryption (SSLKEYLOG) ───────────────────────────────────────────────
def sniff_mime(b):
    """Very small magic sniff for a mime-ish label used on decrypted objects."""
    if b[:2] == b"MZ":
        return "application/x-dosexec"
    if b[:4] == b"\x7fELF":
        return "application/x-elf"
    if b[:4] == b"%PDF":
        return "application/pdf"
    if b[:4] == b"PK\x03\x04":
        return "application/zip"
    if b[:3] == b"\x1f\x8b":
        return "application/gzip"
    if b[:4] == b"\x89PNG":
        return "image/png"
    if b[:3] == b"\xff\xd8\xff":
        return "image/jpeg"
    return "application/octet-stream"


def _tshark_fields(pcap, keylog, disp, fields, cap=300):
    """Run tshark with keylog decryption and a display filter, returning rows of
    the requested fields (tab-separated)."""
    cmd = ["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keylog, "-Y", disp,
           "-T", "fields", "-E", "separator=\t"]
    for f in fields:
        cmd += ["-e", f]
    try:
        p = subprocess.run(cmd, capture_output=True, timeout=180, text=True)
    except Exception:
        return []
    rows = []
    for ln in (p.stdout or "").splitlines():
        if ln.strip():
            rows.append(ln.split("\t"))
        if len(rows) >= cap:
            break
    return rows


def tls_decrypt(pcap, keylog):
    """Decrypt TLS with the provided SSLKEYLOG and pull out (1) reconstructed
    HTTP objects (files transferred over HTTPS), (2) the decrypted HTTP requests,
    and (3) domain-fronting cases (TLS SNI ≠ HTTP Host on the same stream)."""
    if not shutil.which("tshark"):
        return {"files": [], "http": [], "fronting": []}
    d = tempfile.mkdtemp(prefix="tlsdec-")
    files = []
    try:
        objdir = os.path.join(d, "obj")
        os.makedirs(objdir, exist_ok=True)
        try:
            subprocess.run(["tshark", "-r", pcap, "-o", "tls.keylog_file:" + keylog,
                            "--export-objects", "http," + objdir],
                           capture_output=True, timeout=ANALYZE_TIMEOUT)
        except Exception:
            pass
        total = 0
        for root, _dirs, fnames in os.walk(objdir):
            for name in fnames:
                fp = os.path.join(root, name)
                try:
                    sz = os.path.getsize(fp)
                except OSError:
                    continue
                if sz == 0 or sz > CARVE_MAX_FILE or total + sz > CARVE_MAX_TOTAL:
                    continue
                try:
                    data = open(fp, "rb").read()
                except OSError:
                    continue
                total += sz
                files.append({"filename": name, "sha256": hashlib.sha256(data).hexdigest(),
                              "size": sz, "mime": sniff_mime(data), "yara": yara_scan(fp),
                              "b64": base64.b64encode(data).decode("ascii")})
                if len(files) >= CARVE_MAX_FILES:
                    break

        # Decrypted HTTP requests — HTTP/1.1 AND HTTP/2 (HTTPS is usually h2).
        http = []
        for c in _tshark_fields(pcap, keylog, "http.request or http2.headers.method",
                                ["ip.src", "ip.dst", "tcp.dstport", "http.request.method",
                                 "http.host", "http.request.uri", "http.user_agent",
                                 "http2.headers.method", "http2.headers.authority", "http2.headers.path"]):
            c = (c + [""] * 10)[:10]
            method = c[3] or c[7]
            host = c[4] or c[8]
            url = c[5] or c[9]
            if not method and not host:
                continue
            http.append({"src": c[0], "dst": c[1], "dport": c[2], "method": method,
                         "host": host, "url": url, "ua": c[6]})

        # Domain fronting: join SNI (per TCP stream) with the decrypted HTTP Host.
        sni = {}
        for r in _tshark_fields(pcap, keylog, "tls.handshake.extensions_server_name",
                                ["tcp.stream", "tls.handshake.extensions_server_name", "ip.dst"]):
            if len(r) >= 2 and r[0] and r[1]:
                sni[r[0]] = (r[1], r[2] if len(r) > 2 else "")
        fronting = []
        seen_front = set()
        for r in _tshark_fields(pcap, keylog, "http.host or http2.headers.authority",
                                ["tcp.stream", "http.host", "http2.headers.authority", "ip.src", "ip.dst"]):
            r = (r + [""] * 5)[:5]
            host = (r[1] or r[2]).lower()
            if not r[0] or r[0] not in sni or not host:
                continue
            s = sni[r[0]][0].lower()
            if s and host and s != host and not host.endswith("." + s) and not s.endswith("." + host):
                key = s + "|" + host
                if key in seen_front:
                    continue
                seen_front.add(key)
                fronting.append({"sni": sni[r[0]][0], "host": (r[1] or r[2]),
                                 "src": r[3], "dst": r[4]})
        return {"files": files, "http": http[:300], "fronting": fronting[:50]}
    finally:
        shutil.rmtree(d, ignore_errors=True)


def distil_eve(path):
    """Parse eve.json (NDJSON) into a compact summary + a host-flow graph."""
    flows, alerts, dns, tls, http, files = [], [], [], [], [], []
    stats = {"packets": 0, "flows": 0, "alerts": 0, "bytes": 0}
    ioc_ips, ioc_domains = set(), set()
    wanted_sha = set()  # sha256 of files seen in fileinfo, for carving
    # graph aggregation: (src,dst) -> {proto, bytes, flows, ports}
    edges = {}
    nodes = set()
    max_sev = 0

    def add_edge(src, dst, proto, bytes_, dport):
        if not src or not dst:
            return
        nodes.add(src)
        nodes.add(dst)
        k = (src, dst)
        e = edges.get(k)
        if e is None:
            e = {"src": src, "dst": dst, "proto": proto or "", "bytes": 0, "flows": 0, "ports": set()}
            edges[k] = e
        e["bytes"] += int(bytes_ or 0)
        e["flows"] += 1
        if dport:
            e["ports"].add(str(dport))

    try:
        with open(path, "r", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                et = ev.get("event_type")
                src, dst = ev.get("src_ip"), ev.get("dest_ip")
                dport = ev.get("dest_port")

                if et == "flow":
                    stats["flows"] += 1
                    fl = ev.get("flow") or {}
                    to_server = int(fl.get("bytes_toserver", 0))
                    to_client = int(fl.get("bytes_toclient", 0))
                    b = to_server + to_client
                    pkts = int(fl.get("pkts_toserver", 0)) + int(fl.get("pkts_toclient", 0))
                    stats["bytes"] += b
                    stats["packets"] += pkts
                    add_edge(src, dst, ev.get("proto"), b, dport)
                    if dst:
                        ioc_ips.add(dst)
                    if len(flows) < CAP_FLOWS:
                        # start/end + directional bytes let the backend detect real
                        # beaconing (periodicity) and exfiltration (upload ratio).
                        flows.append({"src": src, "sport": ev.get("src_port"), "dst": dst,
                                      "dport": dport, "proto": ev.get("proto"),
                                      "app": ev.get("app_proto"), "bytes": b,
                                      "to_server": to_server, "to_client": to_client,
                                      "pkts": pkts, "start": fl.get("start", ""),
                                      "end": fl.get("end", ""),
                                      "state": (fl.get("state") or "")})
                elif et == "alert":
                    a = ev.get("alert") or {}
                    # Decoder events about checksums are an artifact of how the
                    # capture was taken, not a property of the traffic. Any NIC
                    # with TX checksum offload — every Docker veth, every VM
                    # vNIC, most modern hardware — hands the packet to the
                    # capture before the checksum is computed, so Suricata sees
                    # thousands of "invalid checksum" events. Counting them
                    # drowned one real ET detection under eight artifacts and
                    # pushed max_severity around. (-k none already stops these
                    # from affecting packet ACCEPTANCE; the decoder-event rules
                    # still fire independently.)
                    if _is_capture_artifact(a.get("signature")):
                        continue
                    stats["alerts"] += 1
                    sev = int(a.get("severity", 3))
                    if 4 - sev > max_sev:
                        max_sev = 4 - sev
                    if len(alerts) < CAP_ALERTS:
                        alerts.append({"signature": a.get("signature"), "category": a.get("category"),
                                       "severity": sev, "sid": a.get("signature_id"),
                                       "src": src, "dst": dst, "dport": dport,
                                       "proto": ev.get("proto")})
                    if dst:
                        ioc_ips.add(dst)
                elif et == "dns":
                    d = ev.get("dns") or {}
                    q = d.get("rrname")
                    if not q and isinstance(d.get("query"), list) and d["query"]:
                        q = d["query"][0].get("rrname")
                    # Answer IP addresses (fast-flux) + rcode (NXDOMAIN → DGA signal).
                    answers = []
                    for a in (d.get("answers") or []):
                        rd = a.get("rdata")
                        if rd and a.get("rrtype") in ("A", "AAAA"):
                            answers.append(rd)
                    rcode = d.get("rcode") or ""
                    if q:
                        ioc_domains.add(q.rstrip("."))
                        if len(dns) < CAP_DNS:
                            dns.append({"query": q, "type": d.get("rrtype"), "src": src,
                                        "rcode": rcode, "answers": answers[:12]})
                elif et == "tls":
                    t = ev.get("tls") or {}
                    ja3 = (t.get("ja3") or {}).get("hash")
                    ja3s = (t.get("ja3s") or {}).get("hash")
                    sni = t.get("sni")
                    if sni:
                        ioc_domains.add(sni.rstrip("."))
                    if len(tls) < CAP_TLS:
                        tls.append({"sni": sni, "ja3": ja3, "ja3s": ja3s,
                                    "subject": t.get("subject"), "issuer": t.get("issuerdn"),
                                    "version": t.get("version"), "dst": dst})
                elif et == "http":
                    h = ev.get("http") or {}
                    host = h.get("hostname")
                    if host:
                        ioc_domains.add(host.rstrip("."))
                    if len(http) < CAP_HTTP:
                        http.append({"host": host, "url": h.get("url"), "method": h.get("http_method"),
                                     "ua": h.get("http_user_agent"), "status": h.get("status"),
                                     "dst": dst})
                elif et == "fileinfo":
                    f = ev.get("fileinfo") or {}
                    sha = (f.get("sha256") or "").lower()
                    if sha:
                        wanted_sha.add(sha)
                    if len(files) < CAP_FILES:
                        files.append({"filename": f.get("filename"), "magic": f.get("magic"),
                                      "size": f.get("size"), "sha256": f.get("sha256"),
                                      "md5": f.get("md5"), "src": src, "dst": dst})
    except OSError:
        pass

    # Finalise the graph.
    graph_nodes = [{"id": n, "kind": "host"} for n in list(nodes)[:800]]
    graph_edges = []
    for e in sorted(edges.values(), key=lambda x: x["bytes"], reverse=True)[:1500]:
        graph_edges.append({"src": e["src"], "dst": e["dst"], "proto": e["proto"],
                            "bytes": e["bytes"], "flows": e["flows"],
                            "ports": sorted(e["ports"])[:8]})

    return {
        "stats": stats,
        "flows": flows,
        "alerts": alerts,
        "dns": dns,
        "tls": tls,
        "http": http,
        "files": files,
        "graph": {"nodes": graph_nodes, "edges": graph_edges},
        "iocs": {"ips": sorted(ioc_ips)[:500], "domains": sorted(ioc_domains)[:500]},
        "max_severity": max_sev,
    }, wanted_sha


@app.post("/analyze")
def analyze():
    f = request.files.get("file")
    if f is None:
        return jsonify(error="file is required"), 400
    tmp = tempfile.mkdtemp(prefix="netan-")
    pcap = os.path.join(tmp, "capture.pcap")
    out = os.path.join(tmp, "out")
    os.makedirs(out, exist_ok=True)
    # Optional SSLKEYLOG for decrypting TLS.
    keylog = None
    kf = request.files.get("keylog")
    if kf is not None:
        keylog = os.path.join(tmp, "keys.log")
        kf.save(keylog)
    try:
        f.save(pcap)
        if os.path.getsize(pcap) == 0:
            return jsonify(error="empty file"), 400
        if not run_suricata(pcap, out):
            return jsonify(error="suricata did not produce output (not installed or bad pcap)",
                           stats={}, flows=[], alerts=[], dns=[], tls=[], http=[], files=[],
                           graph={"nodes": [], "edges": []}, iocs={"ips": [], "domains": []}), 200
        result, wanted_sha = distil_eve(os.path.join(out, "eve.json"))
        result["carved"] = collect_carved(out, wanted_sha)
        result["protocols"] = proto_hierarchy(pcap)
        # Deep protocol logs (Zeek) + offline GeoIP/ASN on external endpoints.
        zdir = run_zeek(pcap)
        result["zeek"] = distil_zeek(zdir)
        if zdir:
            # Merge Zeek's reconstructions in before the directory goes away. A file
            # Suricata already carved keeps its entry; the rest are what SMB/FTP/SMTP
            # transfers contribute, and they are the ones that used to be lost.
            have = {c["sha256"] for c in result["carved"]}
            spent = sum(c["size"] for c in result["carved"])
            zcarved, zrecords = collect_zeek_carved(zdir, have, max(0, CARVE_MAX_TOTAL - spent))
            result["carved"].extend(zcarved)
            known = {f.get("sha256") for f in result.get("files", []) if f.get("sha256")}
            for r in zrecords:
                if r["sha256"] not in known:
                    result.setdefault("files", []).append(r)
            shutil.rmtree(zdir, ignore_errors=True)
        result["geo"] = geo_enrich(result.get("iocs", {}).get("ips", []))

        # TLS decryption (when a keylog was supplied): pull decrypted files into the
        # carve pipeline + surface decrypted HTTP and domain-fronting.
        if keylog and os.path.exists(keylog) and os.path.getsize(keylog) > 0:
            dec = tls_decrypt(pcap, keylog)
            result["decrypted_http"] = dec["http"]
            result["domain_fronting"] = dec["fronting"]
            have = {c["sha256"] for c in result["carved"]}
            for df in dec["files"]:
                if df["sha256"] in have:
                    continue
                have.add(df["sha256"])
                result["carved"].append({"sha256": df["sha256"], "size": df["size"],
                                         "yara": df["yara"], "b64": df["b64"]})
                result["files"].append({"filename": df["filename"], "magic": df["mime"],
                                        "size": df["size"], "sha256": df["sha256"], "md5": "",
                                        "src": "", "dst": "", "decrypted": True})
        return jsonify(result)
    except Exception as e:
        return jsonify(error=str(e)), 200
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.post("/rules/validate")
def rules_validate():
    """Compile-check an operator-supplied Suricata ruleset WITHOUT running it.

    A rule that does not parse is silently dropped by Suricata — the run still
    succeeds and reports nothing, which reads exactly like "the traffic is clean".
    So a ruleset is checked here first, and refused with the parser's own message."""
    src = request.form.get("rules") or ""
    if not src.strip():
        return jsonify(ok=False, error="empty ruleset"), 400
    exe = shutil.which("suricata")
    if not exe:
        return jsonify(ok=False, error="suricata is not installed in this sidecar"), 200
    tmp = tempfile.mkdtemp(prefix="netrules-")
    try:
        path = os.path.join(tmp, "custom.rules")
        with open(path, "w", errors="replace") as fh:
            fh.write(src)
        p = subprocess.run([exe, "-T", "-S", path, "-l", tmp],
                           capture_output=True, timeout=120)
        detail = (p.stderr or p.stdout or b"").decode("utf-8", "replace")
        if p.returncode != 0:
            return jsonify(ok=False, error=_first_error(detail)), 200
        return jsonify(ok=True, sids=_rule_sids(src), msgs=_rule_msgs(src))
    except Exception as e:
        return jsonify(ok=False, error=str(e)), 200
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


@app.post("/retrohunt")
def retrohunt():
    """Replay ONE stored pcap against an operator ruleset only (`-S` replaces the
    bundled rules rather than adding to them), so the answer is "did THIS rule
    fire", not "what does the whole rule set say about this capture again"."""
    f = request.files.get("file")
    src = request.form.get("rules") or ""
    if f is None:
        return jsonify(error="file is required"), 400
    if not src.strip():
        return jsonify(error="rules are required"), 400
    exe = shutil.which("suricata")
    if not exe:
        return jsonify(error="suricata is not installed in this sidecar"), 200
    tmp = tempfile.mkdtemp(prefix="netretro-")
    out = os.path.join(tmp, "out")
    os.makedirs(out, exist_ok=True)
    try:
        pcap = os.path.join(tmp, "capture.pcap")
        f.save(pcap)
        if os.path.getsize(pcap) == 0:
            return jsonify(error="empty file"), 400
        rules = os.path.join(tmp, "custom.rules")
        with open(rules, "w", errors="replace") as fh:
            fh.write(src)
        p = subprocess.run([exe, "-r", pcap, "-l", out, "-k", "none", "-S", rules],
                           capture_output=True, timeout=ANALYZE_TIMEOUT)
        eve = os.path.join(out, "eve.json")
        if not os.path.exists(eve):
            detail = (p.stderr or b"").decode("utf-8", "replace")
            return jsonify(error=_first_error(detail) or "suricata produced no output"), 200
        hits = []
        with open(eve, "r", errors="replace") as fh:
            for line in fh:
                try:
                    ev = json.loads(line)
                except Exception:
                    continue
                if ev.get("event_type") != "alert":
                    continue
                a = ev.get("alert") or {}
                hits.append({"signature": a.get("signature"), "sid": a.get("signature_id"),
                             "category": a.get("category"), "severity": a.get("severity"),
                             "src": ev.get("src_ip"), "dst": ev.get("dest_ip"),
                             "dport": ev.get("dest_port"), "proto": ev.get("proto"),
                             "timestamp": ev.get("timestamp")})
                if len(hits) >= 200:
                    break
        return jsonify(alerts=hits, matched=bool(hits))
    except Exception as e:
        return jsonify(error=str(e)), 200
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _first_error(text):
    """The first line Suricata flagged as an error — the rest is startup noise."""
    for line in (text or "").splitlines():
        s = line.strip()
        if s.startswith("E:") or "error" in s.lower():
            return s[:400]
    return ""


RE_SID = re.compile(r"\bsid\s*:\s*(\d+)")
RE_MSG = re.compile(r'\bmsg\s*:\s*"([^"]{1,200})"')


def _rule_sids(src):
    return list(dict.fromkeys(RE_SID.findall(src or "")))[:200]


def _rule_msgs(src):
    return list(dict.fromkeys(RE_MSG.findall(src or "")))[:200]


@app.get("/health")
def health():
    rules = 0
    try:
        if os.path.exists(RULES):
            with open(RULES, "r", errors="replace") as fh:
                rules = sum(1 for ln in fh if ln.strip() and not ln.startswith("#"))
    except OSError:
        pass
    return jsonify(ok=True, suricata=shutil.which("suricata") is not None, rules=rules)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8092")), threaded=True)
