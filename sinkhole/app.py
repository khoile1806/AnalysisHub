#!/usr/bin/env python3
"""sinkhole — the fake Internet the script sandbox runs against.

A sample that cannot resolve its C2 stops at the first beacon and the run tells
you nothing beyond "it tried". This service answers everything: every DNS query
resolves here, every HTTP/HTTPS request gets a plausible 200, every other TCP port
accepts and reads. The sample proceeds through its whole routine — registration,
task poll, exfil attempt — and each step is recorded with the detail a detection
engineer actually needs: the URI, the User-Agent, the SNI, the request body.

It runs on an `internal: true` Docker network, so "answers everything" is bounded
by a network that has no route off the host.

Ports: 53/udp DNS · 80 HTTP · 443 HTTPS · a catch-all TCP list · 8095 control API.
"""

import base64
import json
import os
import re
import shutil
import socket
import socketserver
import ssl
import struct
import subprocess
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

SELF_IP = os.environ.get("SINKHOLE_IP", "10.99.0.5")
CONTROL_PORT = int(os.environ.get("CONTROL_PORT", "8095"))
# Ports that speak HTTP. 8080/8000/8081 carry as much commodity C2 as 80 does, and
# answering them with the raw TCP catch-all threw away the method, URI and body —
# the request line is the detection content, so these get a real HTTP server.
HTTP_PORTS = [int(p) for p in os.environ.get("HTTP_PORTS", "80,8000,8080,8081,8888").split(",") if p.strip()]
HTTPS_PORTS = [int(p) for p in os.environ.get("HTTPS_PORTS", "443,8443,4443").split(",") if p.strip()]
# Everything else: accept, read the opening bytes, log. A protocol we do not speak
# still reveals its port and its first frame.
SMTP_PORTS = [int(p) for p in os.environ.get("SMTP_PORTS", "25,587,2525").split(",") if p.strip()]
CATCH_PORTS = [int(p) for p in os.environ.get(
    "CATCH_PORTS",
    "21,22,23,110,143,445,993,1080,1337,3333,4444,5555,6379,6667,9001,9050,50050"
).split(",") if p.strip()]
MAX_BODY = 512 * 1024
MAX_RECORDS = 5000

# Captured traffic, bucketed per analysis run. Runs are serialised by the
# backend's dynamic-concurrency bound, so a single "current" bucket is enough;
# with parallel runs the records would need to be keyed by source IP instead.
LOCK = threading.Lock()
SESSIONS = {}
CURRENT = [None]

# ── Packet capture ─────────────────────────────────────────────────────────
# The sinkhole is the one host every sandbox packet reaches — DNS resolves every
# name here and the network has no other destination — so capturing on this
# container's interface yields 100% of the sample's traffic without giving the
# container that RUNS the malware any capture privilege.
#
# A separate tap container would not work: a Docker bridge is a switch, not a hub,
# so a third container never sees unicast traffic between two others. Capturing at
# an endpoint is what makes this reliable.
PCAP_DIR = "/tmp/pcap"
# The container's own interface on sandbox_net. Overridable in case the runtime
# names it differently.
CAPTURE_IFACE = os.environ.get("CAPTURE_IFACE", "eth0")
CAPTURE = {}  # session -> subprocess.Popen


def _pcap_path(session):
    safe = re.sub(r"[^A-Za-z0-9_-]", "", session or "")[:64] or "session"
    return os.path.join(PCAP_DIR, safe + ".pcap")


def start_capture(session):
    """Begin writing a pcap for this run. Best-effort: a missing tcpdump or a
    denied capability disables the feature rather than failing the detonation."""
    stop_capture(session)
    if not shutil.which("tcpdump"):
        return
    try:
        os.makedirs(PCAP_DIR, exist_ok=True)
    except OSError:
        return
    path = _pcap_path(session)
    try:
        os.remove(path)
    except OSError:
        pass
    try:
        # -U writes each packet through immediately, so a run killed on timeout
        # still leaves a readable capture. The control API's own port is excluded:
        # the backend polling this service is not the sample's behaviour.
        p = subprocess.Popen(
            # A REAL interface, not "any".
            #
            # "-i any" writes LINUX_SLL2 (Linux cooked v2) encapsulation, and
            # Suricata 7.0.3 reads zero packets from it — the capture looked fine
            # in tshark while the whole IDS stage silently produced nothing.
            # Capturing eth0 yields ordinary Ethernet frames, which every tool in
            # the pipeline handles natively.
            #
            # -p: no promiscuous mode. We capture at an ENDPOINT, so every packet
            # is addressed to this host anyway.
            ["tcpdump", "-i", CAPTURE_IFACE, "-p", "-U", "-s", "0", "-w", path,
             "not port %d" % CONTROL_PORT],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        print("[sinkhole] capture unavailable: %s" % e, file=sys.stderr)
        return

    # Wait until tcpdump is actually capturing before letting the run start.
    #
    # Popen returns as soon as the process is forked, but tcpdump needs a few
    # hundred milliseconds to open its socket and create the file. Returning
    # immediately meant the sample's first packets — the DNS lookups and the
    # opening request, which is exactly the beacon a responder wants — were
    # missed: a run that captured 65 packets by hand yielded 15 through the API.
    # tcpdump writes the pcap header as soon as it is live, so the file appearing
    # with a header in it is the signal that capture has begun.
    deadline = time.time() + 3.0
    while time.time() < deadline:
        if p.poll() is not None:
            print("[sinkhole] tcpdump exited immediately (rc=%s)" % p.returncode, file=sys.stderr)
            return
        try:
            if os.path.getsize(path) >= 24:  # pcap file header written
                break
        except OSError:
            pass
        time.sleep(0.05)

    with LOCK:
        CAPTURE[session] = p


def stop_capture(session):
    with LOCK:
        p = CAPTURE.pop(session, None)
    if not p:
        return
    try:
        p.terminate()
        p.wait(timeout=5)
    except Exception:
        try:
            p.kill()
        except Exception:
            pass


def record(kind, **fields):
    entry = {"t": round(time.time(), 3), "kind": kind}
    entry.update(fields)
    with LOCK:
        sid = CURRENT[0]
        if sid is None:
            sid = "_unassigned"
            SESSIONS.setdefault(sid, [])
        bucket = SESSIONS.setdefault(sid, [])
        if len(bucket) < MAX_RECORDS:
            bucket.append(entry)
    return entry


def clip(v, n=4096):
    if isinstance(v, bytes):
        v = v.decode("latin1")
    v = str(v)
    return v if len(v) <= n else v[:n] + "…[+%d]" % (len(v) - n)


# ── DNS ────────────────────────────────────────────────────────────────────

# Query types worth naming in the record. A capture full of TXT or NULL lookups
# for long random labels is DNS tunnelling, and that is only visible if the type
# is recorded alongside the name.
DNS_QTYPE = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 10: "NULL", 12: "PTR",
             15: "MX", 16: "TXT", 28: "AAAA", 33: "SRV", 65: "HTTPS", 255: "ANY"}

# What a TXT query gets back. Deliberately inert: it must be well-formed enough to
# keep the implant running, and must never look like a real command, since anything
# here is fed straight into the sample's own parser.
DNS_TXT_REPLY = os.environ.get("DNS_TXT_REPLY", "v=spf1 -all")


def parse_qname(data, offset=12):
    """Read the QNAME labels out of a DNS query."""
    labels = []
    pos = offset
    while pos < len(data):
        ln = data[pos]
        if ln == 0:
            pos += 1
            break
        if ln & 0xC0:  # compression pointer — not expected in a query
            pos += 2
            break
        labels.append(data[pos + 1:pos + 1 + ln].decode("latin1", "replace"))
        pos += ln + 1
    return ".".join(labels), pos


class DNSHandler(socketserver.BaseRequestHandler):
    def handle(self):
        data, sock = self.request
        if len(data) < 12:
            return
        try:
            name, end = parse_qname(data)
            qtype, qclass = struct.unpack("!HH", data[end:end + 4])
        except Exception:
            return

        record("dns", host=name, qtype=qtype, qtype_name=DNS_QTYPE.get(qtype, str(qtype)),
               client=self.client_address[0], answer=SELF_IP)

        txid = data[:2]
        flags = b"\x81\x80"           # response, recursion available, no error
        counts = struct.pack("!HHHH", 1, 1, 0, 0)
        question = data[12:end + 4]
        # Answer: pointer to the question name, A/IN, 60s TTL, our address.
        answer = b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 60, 4) + socket.inet_aton(SELF_IP)
        if qtype == 28:  # AAAA — refuse so the client falls back to our A record
            counts = struct.pack("!HHHH", 1, 0, 0, 0)
            answer = b""
        elif qtype == 16:
            # TXT is a C2 channel in its own right: the implant asks for a name and
            # reads its next command out of the answer. Replying with an A record —
            # which is what this did — is a type mismatch, so the resolver discards
            # it and the sample stops there, taking the rest of its behaviour with
            # it. A well-formed TXT answer keeps it running to the next stage.
            txt = DNS_TXT_REPLY.encode("latin1")[:255]
            rdata = bytes([len(txt)]) + txt
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 16, 1, 60, len(rdata)) + rdata
        elif qtype == 15:
            # MX, so a sample that mails its collection out is pointed at our SMTP
            # listener instead of failing to resolve.
            host = b"\xc0\x0c"  # the queried name itself, which resolves to us
            rdata = struct.pack("!H", 10) + host
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 15, 1, 60, len(rdata)) + rdata
        elif qtype == 5:
            rdata = b"\xc0\x0c"
            answer = b"\xc0\x0c" + struct.pack("!HHIH", 5, 1, 60, len(rdata)) + rdata
        elif qtype not in (1, 255):
            # Any other type: NOERROR with no answer. Returning a wrong record type
            # is worse than returning none — it makes the client retry or crash
            # instead of moving on.
            counts = struct.pack("!HHHH", 1, 0, 0, 0)
            answer = b""
        try:
            sock.sendto(txid + flags + counts + question + answer, self.client_address)
        except Exception:
            pass


# ── HTTP / HTTPS ───────────────────────────────────────────────────────────

class SinkHTTP(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    server_version = "nginx/1.24.0"
    sys_version = ""

    def log_message(self, *a):
        pass  # the report is the log

    def _read_chunked(self):
        """Read a chunked-encoded body.

        Node's http.request sends Transfer-Encoding: chunked whenever the caller
        does not set Content-Length, which is the common case for a hand-rolled
        beacon. Reading only Content-Length bodies silently dropped exactly the
        payload that matters — the victim profile and the exfil blob."""
        body = b""
        while len(body) < MAX_BODY:
            line = self.rfile.readline(64)
            if not line:
                break
            try:
                size = int(line.strip().split(b";")[0], 16)
            except ValueError:
                break
            if size == 0:
                self.rfile.readline(4)  # trailing CRLF
                break
            body += self.rfile.read(size)
            self.rfile.readline(4)      # CRLF after each chunk
        return body

    def _capture(self, method):
        body = b""
        encoding = (self.headers.get("Transfer-Encoding") or "").lower()
        if "chunked" in encoding:
            try:
                body = self._read_chunked()
            except Exception:
                body = b""
        else:
            try:
                length = int(self.headers.get("Content-Length") or 0)
            except ValueError:
                length = 0
            if 0 < length <= MAX_BODY:
                try:
                    body = self.rfile.read(length)
                except Exception:
                    body = b""

        host = self.headers.get("Host", "")
        record(
            "http",
            scheme="https" if getattr(self.server, "is_tls", False) else "http",
            method=method,
            host=host,
            path=self.path,
            http_version=self.request_version,
            user_agent=self.headers.get("User-Agent", ""),
            headers={k: clip(v, 512) for k, v in self.headers.items()},
            body_len=len(body),
            body=clip(body, 16384),
            body_b64=base64.b64encode(body[:MAX_BODY]).decode() if body else "",
            client=self.client_address[0],
        )

        # A generic 200 keeps the sample in its routine. JSON is the safest shape:
        # most modern stagers parse their task list as JSON and abort on garbage,
        # while the ones expecting text tolerate it.
        payload = b'{"status":"ok","id":"1","data":[],"cmd":"","result":"success"}'
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Connection", "keep-alive")
        self.end_headers()
        try:
            self.wfile.write(payload)
        except Exception:
            pass

    def do_GET(self):
        self._capture("GET")

    def do_POST(self):
        self._capture("POST")

    def do_PUT(self):
        self._capture("PUT")

    def do_HEAD(self):
        self._capture("HEAD")

    def do_PATCH(self):
        self._capture("PATCH")

    def do_DELETE(self):
        self._capture("DELETE")

    def do_OPTIONS(self):
        self._capture("OPTIONS")

    def do_CONNECT(self):
        # Proxy-style CONNECT reveals the real destination even when the payload
        # itself is tunnelled.
        record("connect", target=self.path, client=self.client_address[0])
        self.send_response(200, "Connection Established")
        self.end_headers()


class ThreadedHTTP(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True
    is_tls = False


def make_cert(path_key, path_crt):
    """Self-signed leaf. The sandbox harness disables verification, and most
    samples never check anyway — an unverified TLS session still yields the SNI,
    the request line and the body, which is the whole point."""
    if os.path.exists(path_crt) and os.path.exists(path_key):
        return True
    try:
        subprocess.run(
            ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes",
             "-keyout", path_key, "-out", path_crt, "-days", "3650",
             "-subj", "/C=US/O=Microsoft Corporation/CN=*.com",
             "-addext", "subjectAltName=DNS:*.com,DNS:*.net,DNS:*.org,DNS:*"],
            check=True, capture_output=True, timeout=120)
        return True
    except Exception as e:
        print("[sinkhole] certificate generation failed: %s" % e, file=sys.stderr)
        return False


def serve_https(port=443):
    key, crt = "/tmp/sink.key", "/tmp/sink.crt"
    if not make_cert(key, crt):
        return
    httpd = ThreadedHTTP(("0.0.0.0", port), SinkHTTP)
    httpd.is_tls = True
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    # Old stagers negotiate TLS 1.0/1.1 and weak ciphers; refusing them would
    # silently lose exactly the samples most worth recording.
    ctx.minimum_version = ssl.TLSVersion.TLSv1
    try:
        ctx.set_ciphers("ALL:@SECLEVEL=0")
    except ssl.SSLError:
        pass
    ctx.load_cert_chain(crt, key)

    def on_sni(sock, name, context):
        if name:
            record("tls_sni", sni=name)

    ctx.sni_callback = on_sni
    httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)
    httpd.serve_forever()


# ── Generic TCP catch-all ──────────────────────────────────────────────────

class CatchAll(socketserver.BaseRequestHandler):
    def handle(self):
        port = self.server.server_address[1]
        self.request.settimeout(10)
        chunks = b""
        try:
            while len(chunks) < 65536:
                b = self.request.recv(8192)
                if not b:
                    break
                chunks += b
                if len(chunks) >= 4096:
                    break
        except Exception:
            pass
        record("tcp", port=port, client=self.client_address[0],
               bytes=len(chunks), data=clip(chunks, 8192),
               data_b64=base64.b64encode(chunks[:MAX_BODY]).decode() if chunks else "")
        try:
            # A generic ack keeps a protocol-speaking implant talking instead of
            # dropping the connection after its first frame.
            self.request.sendall(b"+OK\r\n")
        except Exception:
            pass


class ThreadedTCP(socketserver.ThreadingMixIn, socketserver.TCPServer):
    daemon_threads = True
    allow_reuse_address = True


# ── SMTP ───────────────────────────────────────────────────────────────────
# Mail is a first-class exfiltration channel — an infostealer that mails its
# collection out is at least as common as one that POSTs it. Until now ports 25
# and 587 fell to the catch-all, which answers "+OK": an SMTP client needs a
# "220" greeting and hangs up immediately, so the exfil never happened and the
# report showed a bare TCP connect with no content.
#
# The AUTH exchange is the part worth having. Malware that mails data out carries
# the mailbox credentials it will use, and they identify the attacker's
# infrastructure far better than the message body does.

def _decode_b64(s):
    try:
        return base64.b64decode(s + "=" * (-len(s) % 4)).decode("utf-8", "replace")
    except Exception:
        return ""


class SinkSMTP(socketserver.BaseRequestHandler):
    def handle(self):
        port = self.server.server_address[1]
        self.request.settimeout(20)
        f = self.request.makefile("rb")
        state = {"from": "", "rcpt": [], "auth": "", "helo": "", "sent": 0}

        def send(line):
            try:
                self.request.sendall(line.encode() + b"\r\n")
            except Exception:
                pass

        send("220 mail.local ESMTP Postfix (Debian/GNU)")
        expect_auth = None
        try:
            while True:
                raw = f.readline(2048)
                if not raw:
                    break
                line = raw.decode("latin1", "replace").rstrip("\r\n")
                up = line.upper()

                if expect_auth:
                    # Continuation of AUTH LOGIN: username then password, each base64.
                    state["auth"] += ("%s=%s " % (expect_auth, _decode_b64(line.strip())))
                    if expect_auth == "user":
                        expect_auth = "pass"
                        send("334 UGFzc3dvcmQ6")
                        continue
                    expect_auth = None
                    send("235 2.7.0 Authentication successful")
                    continue

                if up.startswith("EHLO") or up.startswith("HELO"):
                    state["helo"] = line[5:].strip()
                    if up.startswith("EHLO"):
                        for cap in ("250-mail.local", "250-SIZE 20480000", "250-8BITMIME",
                                    "250-AUTH PLAIN LOGIN", "250 HELP"):
                            send(cap)
                    else:
                        send("250 mail.local")
                elif up.startswith("AUTH LOGIN"):
                    arg = line[10:].strip()
                    if arg:
                        state["auth"] += "user=%s " % _decode_b64(arg)
                        expect_auth = "pass"
                        send("334 UGFzc3dvcmQ6")
                    else:
                        expect_auth = "user"
                        send("334 VXNlcm5hbWU6")
                elif up.startswith("AUTH PLAIN"):
                    arg = line[10:].strip()
                    if arg:
                        # AUTH PLAIN is authzid\0authcid\0password in one blob.
                        parts = _decode_b64(arg).split("\x00")
                        state["auth"] += "plain=%s " % ":".join(p for p in parts if p)
                        send("235 2.7.0 Authentication successful")
                    else:
                        send("334 ")
                elif up.startswith("MAIL FROM"):
                    state["from"] = line.split(":", 1)[-1].strip()
                    send("250 2.1.0 Ok")
                elif up.startswith("RCPT TO"):
                    if len(state["rcpt"]) < 50:
                        state["rcpt"].append(line.split(":", 1)[-1].strip())
                    send("250 2.1.5 Ok")
                elif up.startswith("DATA"):
                    send("354 End data with <CR><LF>.<CR><LF>")
                    body = b""
                    while len(body) < MAX_BODY:
                        chunk = f.readline(4096)
                        if not chunk or chunk.rstrip(b"\r\n") == b".":
                            break
                        body += chunk
                    record("smtp", port=port, client=self.client_address[0],
                           helo=state["helo"], mail_from=state["from"],
                           rcpt=",".join(state["rcpt"]), auth=state["auth"].strip(),
                           bytes=len(body), body=clip(body, 16384),
                           body_b64=base64.b64encode(body[:MAX_BODY]).decode() if body else "")
                    send("250 2.0.0 Ok: queued as 4XmPQ1")
                    state["sent"] += 1
                    state["from"], state["rcpt"] = "", []
                elif up.startswith("QUIT"):
                    send("221 2.0.0 Bye")
                    break
                elif up.startswith("RSET"):
                    state["from"], state["rcpt"] = "", []
                    send("250 2.0.0 Ok")
                elif up.startswith("STARTTLS"):
                    # Refused on purpose: staying in the clear keeps the message
                    # readable, and every client falls back rather than give up.
                    send("454 4.7.0 TLS not available due to temporary reason")
                elif up.startswith("NOOP"):
                    send("250 2.0.0 Ok")
                else:
                    send("250 2.0.0 Ok")
        except Exception:
            pass
        finally:
            # A session that authenticated but never sent DATA is still evidence:
            # it names the mailbox the sample was going to use. A session that DID
            # send is already recorded — do not log it twice.
            if state["auth"] and state["sent"] == 0:
                record("smtp", port=port, client=self.client_address[0],
                       helo=state["helo"], mail_from=state["from"], rcpt="",
                       auth=state["auth"].strip(), bytes=0, body="", body_b64="")
            try:
                f.close()
            except Exception:
                pass


# ── Control API ────────────────────────────────────────────────────────────

class Control(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, *a):
        pass

    def _json(self, code, obj):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _session(self):
        m = re.search(r"session=([^&]+)", self.path or "")
        return m.group(1) if m else None

    def do_GET(self):
        if self.path.startswith("/health"):
            return self._json(200, {"ok": True, "ip": SELF_IP, "catch_ports": CATCH_PORTS,
                                    "pcap": bool(shutil.which("tcpdump"))})
        if self.path.startswith("/pcap"):
            # Hands back the run's capture. Stopping first flushes tcpdump's last
            # packets, so the caller never reads a truncated file.
            sid = self._session()
            if not sid:
                return self._json(400, {"error": "session is required"})
            stop_capture(sid)
            path = _pcap_path(sid)
            try:
                with open(path, "rb") as fh:
                    blob = fh.read()
            except OSError:
                return self._json(404, {"error": "no capture for this session"})
            self.send_response(200)
            self.send_header("Content-Type", "application/vnd.tcpdump.pcap")
            self.send_header("Content-Length", str(len(blob)))
            self.end_headers()
            self.wfile.write(blob)
            return
        if self.path.startswith("/log"):
            sid = self._session()
            with LOCK:
                recs = list(SESSIONS.get(sid, [])) if sid else []
            return self._json(200, summarise(recs))
        self._json(404, {"error": "not found"})

    def do_POST(self):
        if self.path.startswith("/reset"):
            sid = self._session()
            # A run begins here, so the capture starts here: the pcap spans
            # exactly the window the JSON record set spans.
            if sid:
                start_capture(sid)
            with LOCK:
                CURRENT[0] = sid
                if sid:
                    SESSIONS[sid] = []
                # Keep the store bounded across a long-lived container.
                if len(SESSIONS) > 50:
                    for k in list(SESSIONS)[:-20]:
                        SESSIONS.pop(k, None)
            return self._json(200, {"ok": True, "session": sid})
        self._json(404, {"error": "not found"})


def summarise(recs):
    """Shape the capture the way the report renders it: the distinct hosts and
    URLs first (that is the blocklist), the full record list after."""
    hosts, urls, sni, ports = [], [], [], []
    for r in recs:
        if r["kind"] == "dns" and r.get("host") and r["host"] not in hosts:
            hosts.append(r["host"])
        elif r["kind"] == "http":
            u = "%s://%s%s" % (r.get("scheme", "http"), r.get("host", ""), r.get("path", ""))
            if u not in urls:
                urls.append(u)
        elif r["kind"] == "tls_sni" and r.get("sni") and r["sni"] not in sni:
            sni.append(r["sni"])
        elif r["kind"] == "tcp":
            p = r.get("port")
            if p and p not in ports:
                ports.append(p)
    return {
        "records": recs, "count": len(recs),
        "hosts": hosts, "urls": urls, "tls_sni": sni, "tcp_ports": ports,
    }


def main():
    threads = []

    def spawn(fn, name):
        t = threading.Thread(target=fn, name=name, daemon=True)
        t.start()
        threads.append(t)

    spawn(lambda: socketserver.ThreadingUDPServer(("0.0.0.0", 53), DNSHandler).serve_forever(), "dns")

    reserved = set(HTTP_PORTS) | set(HTTPS_PORTS) | set(SMTP_PORTS) | {53, CONTROL_PORT}

    for port in SMTP_PORTS:
        def run_smtp(p=port):
            try:
                ThreadedTCP(("0.0.0.0", p), SinkSMTP).serve_forever()
            except Exception as e:
                print("[sinkhole] smtp port %d unavailable: %s" % (p, e), file=sys.stderr)

        spawn(run_smtp, "smtp%d" % port)

    for port in HTTP_PORTS:
        if port == CONTROL_PORT:
            continue

        def run_http(p=port):
            try:
                ThreadedHTTP(("0.0.0.0", p), SinkHTTP).serve_forever()
            except Exception as e:
                print("[sinkhole] http port %d unavailable: %s" % (p, e), file=sys.stderr)

        spawn(run_http, "http%d" % port)

    for port in HTTPS_PORTS:
        def run_https(p=port):
            try:
                serve_https(p)
            except Exception as e:
                print("[sinkhole] https port %d unavailable: %s" % (p, e), file=sys.stderr)

        spawn(run_https, "https%d" % port)

    for port in CATCH_PORTS:
        if port in reserved:
            continue

        def run(p=port):
            try:
                ThreadedTCP(("0.0.0.0", p), CatchAll).serve_forever()
            except Exception as e:
                print("[sinkhole] port %d unavailable: %s" % (p, e), file=sys.stderr)

        spawn(run, "tcp%d" % port)

    print("[sinkhole] up on %s — dns/53 control/%d · http:%s · https:%s · smtp:%s · catch-all:%s"
          % (SELF_IP, CONTROL_PORT,
             ",".join(str(p) for p in HTTP_PORTS),
             ",".join(str(p) for p in HTTPS_PORTS),
             ",".join(str(p) for p in SMTP_PORTS),
             ",".join(str(p) for p in CATCH_PORTS)), flush=True)
    ThreadedHTTP(("0.0.0.0", CONTROL_PORT), Control).serve_forever()


if __name__ == "__main__":
    main()
