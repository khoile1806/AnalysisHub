"""Local malware emulation sidecar.

Emulates a Windows PE / shellcode sample with Mandiant speakeasy (CPU + Win32 API
emulation via Unicorn) and returns a NORMALISED behaviour summary. The sample is
never really executed on the host — every instruction is emulated and every API
call is intercepted/stubbed — so this is safe to run in a plain container with no
VM. Fully local: nothing leaves the box.

POST /emulate  (multipart: file)  -> normalised BehaviorSummary JSON
GET  /health                      -> {"ok": true, "speakeasy": bool}
"""
import json
import multiprocessing as mp
import os
import re
import shutil
import subprocess
import tempfile

from flask import Flask, request, jsonify

app = Flask(__name__)

EMULATION_TIMEOUT = int(os.environ.get("EMULATION_TIMEOUT", "90"))  # seconds

# Win32 APIs whose use is a behavioural tell, by lower-case base name.
SUSPICIOUS = {
    "virtualalloc", "virtualallocex", "virtualprotect", "writeprocessmemory",
    "readprocessmemory", "createremotethread", "ntcreatethreadex", "queueuserapc",
    "loadlibrarya", "loadlibraryw", "getprocaddress", "winexec", "createprocessa",
    "createprocessw", "shellexecutea", "shellexecutew", "urldownloadtofilea",
    "internetopena", "internetconnecta", "httpsendrequesta", "wsasocketa", "connect",
    "send", "recv", "regsetvalueexa", "regcreatekeyexa", "createservicea",
    "isdebuggerpresent", "checkremotedebuggerpresent", "cryptencrypt", "cryptdecrypt",
    "setwindowshookexa", "adjusttokenprivileges", "ntunmapviewofsection",
    "createtoolhelp32snapshot", "getasynckeystate", "createmutexa",
}
INJECT = {"virtualallocex", "writeprocessmemory", "createremotethread",
          "ntcreatethreadex", "queueuserapc", "ntunmapviewofsection"}

RE_IP = re.compile(r"\b\d{1,3}(?:\.\d{1,3}){3}\b")
RE_DOMAIN = re.compile(r"\b(?:[a-z0-9-]+\.)+[a-z]{2,}\b", re.I)
# File/module extensions that must NOT be mistaken for network hosts (e.g.
# LoadLibrary("kernel32.dll") — the arg is a DLL name, not a C2 domain).
NON_NET_EXT = (".dll", ".exe", ".sys", ".drv", ".ocx", ".nls", ".mui", ".cpl",
               ".scr", ".tmp", ".dat", ".bin", ".ini", ".log", ".db")
# APIs whose arguments legitimately carry a network host/URL. Network indicators
# are only pulled from THESE (plus the sandbox's network_events) so a DLL name in
# a LoadLibrary call can never be logged as a callback.
NET_APIS = {
    "internetopena", "internetopenw", "internetopenurla", "internetopenurlw",
    "internetconnecta", "internetconnectw", "httpopenrequesta", "httpopenrequestw",
    "httpsendrequesta", "httpsendrequestw", "urldownloadtofilea", "urldownloadtofilew",
    "winhttpconnect", "winhttpsendrequest", "connect", "wsaconnect", "gethostbyname",
    "getaddrinfo", "getaddrinfow", "send", "sendto", "dnsquery_a", "dnsquery_w",
}


def base_api(name):
    if not name:
        return ""
    return str(name).split(".")[-1].lower()


def looks_net(s):
    s = str(s).strip()
    low = s.lower()
    if low.endswith(NON_NET_EXT):
        return False
    return "http://" in low or "https://" in low or bool(RE_IP.search(s)) or bool(RE_DOMAIN.search(s))


_YARA_RULES = None  # compiled once, lazily


def load_yara_rules():
    """Compile the local YARA rules dir once. None if yara-python or rules absent."""
    try:
        import yara
    except Exception:
        return None
    rules_dir = os.environ.get("YARA_RULES", "/rules")
    files = {}
    if os.path.isdir(rules_dir):
        for root, _dirs, fs in os.walk(rules_dir):
            for fn in fs:
                if fn.lower().endswith((".yar", ".yara")):
                    p = os.path.join(root, fn)
                    files[p] = p
    if not files:
        return None
    try:
        return yara.compile(filepaths=files)
    except Exception:
        return None


def dump_memory(se):
    """Concatenate the emulated memory regions (bounded) — the UNPACKED image the
    sample built in RAM. Returns b'' if nothing could be read."""
    blob = bytearray()
    regions = []
    for getter in ("get_mem_regions", "get_mem_maps"):
        fn = getattr(se, getter, None)
        if fn:
            try:
                regions = fn() or []
                break
            except Exception:
                continue
    for mm in regions:
        try:
            base = mm.get_base() if hasattr(mm, "get_base") else getattr(mm, "base", 0)
            size = mm.get_size() if hasattr(mm, "get_size") else getattr(mm, "size", 0)
            size = min(int(size), 4 * 1024 * 1024)
            if size <= 0:
                continue
            blob += bytes(se.mem_read(int(base), size))
            if len(blob) > 64 * 1024 * 1024:
                break
        except Exception:
            continue
    return bytes(blob)


def scan_memory_blob(blob):
    """YARA-scan an unpacked-memory blob — catches a payload the sample decoded in
    RAM that a scan of the packed file on disk would miss."""
    global _YARA_RULES
    if not blob:
        return []
    try:
        import yara  # noqa: F401
    except Exception:
        return []
    if _YARA_RULES is None:
        _YARA_RULES = load_yara_rules()
    if _YARA_RULES is None:
        return []
    try:
        seen, hits = set(), []
        for m in _YARA_RULES.match(data=blob):
            if m.rule not in seen:
                seen.add(m.rule)
                hits.append(m.rule)
        return hits[:50]
    except Exception:
        return []


def fmt_arg(v):
    """Format one API argument for the ordered call trace."""
    if isinstance(v, str):
        s = v.strip().replace("\n", " ")
        return ("'" + s[:80] + "'") if s else "''"
    if isinstance(v, bool):
        return str(v)
    if isinstance(v, int):
        return hex(v) if v > 9 else str(v)
    return str(v)[:80]


def reconstruct_flow(ordered):
    """Turn the ORDERED (name, args, ret) API sequence into a chronological,
    high-level behaviour flow — the malware's actual operational steps, not just a
    set of API names. Consecutive duplicates are collapsed."""
    steps = []

    def push(s):
        if not steps or steps[-1] != s:
            steps.append(s)

    for name, args, _ret in ordered:
        b = base_api(name)
        a0 = fmt_arg(args[0]) if args else ""
        a1 = fmt_arg(args[1]) if len(args) > 1 else ""
        if b in ("createfilea", "createfilew", "createfile2", "_lopen"):
            push("Open/create file %s" % a0)
        elif b in ("writefile", "_lwrite", "fwrite"):
            push("Write data to a file")
        elif b in ("copyfilea", "copyfilew", "movefilea", "movefilew", "movefileexa"):
            push("Copy/move file %s -> %s" % (a0, a1))
        elif b in ("deletefilea", "deletefilew"):
            push("Delete file %s" % a0)
        elif b in ("regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw", "regsetkeyvaluea", "regsetkeyvaluew"):
            push("Registry write (possible persistence) %s" % (a1 or a0))
        elif b in ("winexec", "createprocessa", "createprocessw", "createprocessinternalw", "shellexecutea", "shellexecutew", "shellexecuteexa"):
            push("Execute a child process %s" % a0)
        elif b in ("loadlibrarya", "loadlibraryw", "loadlibraryexa", "loadlibraryexw"):
            push("Dynamically load library %s" % a0)
        elif b in ("getprocaddress",):
            push("Resolve API by name %s (dynamic import)" % (a1 or a0))
        elif b in ("virtualalloc", "virtualallocex", "ntallocatevirtualmemory"):
            push("Allocate executable memory (unpacking or injection)")
        elif b in ("virtualprotect", "virtualprotectex"):
            push("Change memory protection to executable (RWX)")
        elif b in ("writeprocessmemory",):
            push("Write code into another process's memory")
        elif b in ("createremotethread", "ntcreatethreadex", "queueuserapc", "rtlcreateuserthread", "setthreadcontext"):
            push("Start execution in another process → PROCESS INJECTION")
        elif b in ("openprocess",):
            push("Open a handle to another process %s" % a0)
        elif b in ("internetopena", "internetopenw", "internetconnecta", "internetconnectw", "winhttpconnect", "connect", "wsaconnect"):
            push("Connect to a network host %s" % a0)
        elif b in ("httpsendrequesta", "httpsendrequestw", "httpopenrequesta", "httpopenrequestw", "urldownloadtofilea", "urldownloadtofilew", "send", "wsasend", "internetreadfile", "winhttpsendrequest"):
            push("Send/download over the network %s" % a0)
        elif b in ("cryptencrypt", "cryptdecrypt", "cryptcreatehash", "crypthashdata", "bcryptencrypt", "bcryptdecrypt"):
            push("Cryptographic operation (%s)" % b)
        elif b in ("isdebuggerpresent", "checkremotedebuggerpresent", "ntqueryinformationprocess", "outputdebugstringa"):
            push("Anti-debug / evasion check")
        elif b in ("sleep", "sleepex", "waitforsingleobject", "waitforsingleobjectex"):
            push("Sleep / stalling delay (evasion)")
        elif b in ("getasynckeystate", "getkeystate", "setwindowshookexa", "setwindowshookexw", "registerrawinputdevices"):
            push("Keylogging / input hooking")
        elif b in ("openclipboard", "getclipboarddata"):
            push("Read the clipboard")
        elif b in ("createmutexa", "createmutexw"):
            push("Create mutex %s (single-instance marker)" % a0)
        elif b in ("getcomputernamea", "getcomputernamew", "getusernamea", "getusernamew", "getsysteminfo", "gethostname", "getvolumeinformationa"):
            push("Collect host / system information")
        elif b in ("adjusttokenprivileges", "lookupprivilegevaluea"):
            push("Adjust token privileges (escalation)")
        elif b in ("createservicea", "createservicew", "startservicea", "openscmanagera"):
            push("Install/start a service (persistence)")
    return steps[:60]


def harvest_host_iocs(ordered):
    """Pull high-value HOST artifacts from API arguments — file paths written,
    registry keys/values set, mutex names, and child command lines. These are the
    IOCs a responder hunts for on an endpoint and were previously discarded."""
    out, seen = [], set()

    def push(label, val):
        val = str(val).strip()
        if not val or len(val) < 3:
            return
        line = "%s: %s" % (label, val[:200])
        if line not in seen and len(out) < 60:
            seen.add(line)
            out.append(line)

    for name, args, _ret in ordered:
        b = base_api(name)
        # API arg positions vary (mutex name is arg[2] on CreateMutex, path is arg[0]
        # on CreateFile), so pick the best STRING argument by category rather than a
        # fixed index.
        str_args = [a for a in args if isinstance(a, str) and a.strip()]
        if b in ("createfilea", "createfilew", "writefile", "copyfilea", "copyfilew",
                 "movefilea", "movefilew", "movefileexa", "deletefilea", "deletefilew"):
            for s in str_args:
                if "\\" in s or "/" in s:
                    push("file", s)
                    break
        elif b in ("regsetvalueexa", "regsetvalueexw", "regcreatekeyexa", "regcreatekeyexw",
                   "regsetkeyvaluea", "regsetkeyvaluew"):
            for s in str_args:
                if "\\" in s:
                    push("registry", s)
                    break
            else:
                if str_args:
                    push("registry", str_args[0])
        elif b in ("createmutexa", "createmutexw", "openmutexa", "openmutexw"):
            if str_args:
                push("mutex", str_args[0])
        elif b in ("createprocessa", "createprocessw", "createprocessinternalw", "winexec",
                   "shellexecutea", "shellexecutew", "shellexecuteexa"):
            if str_args:
                push("exec", str_args[0])
    return out


def distil(report):
    apis, api_seen = [], set()
    network, net_seen = [], set()
    dropped = []
    attck = set()
    sus_count = 0
    inject_hits = set()
    bases = set()  # every base API name seen (for combination signatures)

    ordered = []
    stop_reasons = []
    # A stalling/spraying sample can emit millions of API records; keeping them all
    # balloons this child process's RAM. Cap the retained ordered list — call_trace
    # slices [:250] and flow [:60] downstream, so nothing needs the full history.
    ORDERED_CAP = 20000
    ordered_capped = False
    for ep in (report.get("entry_points") or []):
        for a in (ep.get("apis") or []):
            name = a.get("api_name") or ""
            if not name:
                continue
            b = base_api(name)
            bases.add(b)
            if b in SUSPICIOUS:
                sus_count += 1
            if b in INJECT:
                inject_hits.add(b)
            if name not in api_seen and len(apis) < 80:
                api_seen.add(name)
                apis.append(name)
            if len(ordered) < ORDERED_CAP:
                ordered.append((name, a.get("args") or [], a.get("ret_val")))
            elif not ordered_capped:
                ordered_capped = True
                stop_reasons.append("API-call cap reached (%d) — probable looping/spraying sample" % ORDERED_CAP)
            # Only network APIs contribute network indicators from their args, so a
            # module name (LoadLibrary "kernel32.dll") is never logged as a callback.
            if b in NET_APIS:
                for arg in (a.get("args") or []):
                    s = str(arg)
                    if looks_net(s) and s not in net_seen and len(network) < 60:
                        net_seen.add(s)
                        network.append(s[:200])
        er = ep.get("error")
        if er:
            reason = (er.get("type") or er.get("desc") or str(er)) if isinstance(er, dict) else str(er)
            reason = str(reason)[:160]
            if reason and reason not in stop_reasons:
                stop_reasons.append(reason)
        ne = ep.get("network_events") or {}
        for d in (ne.get("dns") or []):
            q = d.get("query") or d.get("request")
            if q:
                line = "DNS " + str(q)
                if line not in net_seen and len(network) < 60:
                    net_seen.add(line)
                    network.append(line)
        for t in (ne.get("traffic") or []):
            srv = t.get("server") or t.get("host")
            if srv:
                line = "%s %s:%s" % (t.get("proto") or t.get("method") or "", srv, t.get("port") or "")
                line = line.strip()
                if line not in net_seen and len(network) < 60:
                    net_seen.add(line)
                    network.append(line)
        for df in (ep.get("dropped_files") or ep.get("files") or []):
            p = df.get("path") or df.get("name")
            if p and p not in dropped and len(dropped) < 40:
                dropped.append(str(p))

    signatures = []
    if len(inject_hits) >= 2:
        signatures.append("Process-injection APIs observed (" + ", ".join(sorted(inject_hits)) + ")")
        attck.add("T1055")
    if any(base_api(x).startswith(("urldownload", "internetopen", "internetconnect")) for x in apis):
        signatures.append("Network download / C2 capability")
        attck.add("T1105")
    if any(base_api(x) in ("winexec", "createprocessa", "createprocessw", "shellexecutea", "shellexecutew") for x in apis):
        signatures.append("Spawns child processes")
        attck.add("T1059")
    if any(base_api(x) in ("regsetvalueexa", "regcreatekeyexa") for x in apis):
        signatures.append("Modifies the registry")
        attck.add("T1112")
    if any(base_api(x) in ("isdebuggerpresent", "checkremotedebuggerpresent") for x in apis):
        signatures.append("Anti-debug checks")
        attck.add("T1622")

    # Ordered call trace (execution order + args) and the reconstructed behaviour
    # flow — the malware's actual step-by-step operation.
    call_trace = []
    for name, args, _ret in ordered[:250]:
        astr = ", ".join(fmt_arg(x) for x in args[:4])
        call_trace.append("%s(%s)" % (name, astr))
    behavior_flow = reconstruct_flow(ordered)

    # Flow-derived signatures (an ORDERED injection sequence is stronger evidence
    # than the API set alone).
    if any("PROCESS INJECTION" in s for s in behavior_flow):
        signatures.append("Executed a process-injection sequence (alloc → write → remote thread)")
        attck.add("T1055")
    if any("persistence" in s.lower() for s in behavior_flow):
        attck.add("T1547")

    # Process-hollowing: create a (suspended) process, unmap/allocate in it, write
    # code, then hijack its thread. Detect via the API combination.
    hollow = ({"ntunmapviewofsection"} & bases or {"virtualallocex"} & bases) and \
        {"writeprocessmemory"} & bases and \
        (bases & {"createprocessa", "createprocessw", "createprocessinternalw"}) and \
        (bases & {"setthreadcontext", "resumethread", "ntresumethread"})
    if hollow:
        signatures.append("Process-hollowing pattern (CreateProcess → unmap/alloc → WriteProcessMemory → hijack thread)")
        attck.add("T1055.012")

    host_iocs = harvest_host_iocs(ordered)

    # Heuristic 0-10 score derived from the reconstructed MALICIOUS behaviours in
    # the flow — NOT from raw API counts. Normal runtime activity (dynamic library
    # loading, API resolution, writing a log file) scores 0, so a benign program
    # like a Go agent is not falsely inflated. `sus_count` is intentionally ignored
    # here because common APIs (LoadLibrary/GetProcAddress/VirtualProtect) are used
    # by nearly every program.
    fs = " ".join(behavior_flow).lower()
    score = 0.0
    if "process injection" in fs:
        score += 5.0
    elif inject_hits:
        score += 2.0
    if "persistence" in fs or "install/start a service" in fs:
        score += 2.0
    if "connect to a network host" in fs or "send/download over the network" in fs:
        score += 2.0
    if "keylog" in fs or "read the clipboard" in fs:
        score += 2.0
    if "execute a child process" in fs:
        score += 1.5
    if "anti-debug" in fs or "evasion" in fs:
        score += 1.0
    if "cryptographic operation" in fs:
        score += 1.0
    if hollow:
        score += 3.0
    score = min(10.0, score)

    p = report.get("path") or report.get("module") or "sample"
    process_tree = [os.path.basename(str(p)) + " (emulated)"]

    out = {
        "score": round(score, 1),
        "signatures": signatures,
        "process_tree": process_tree,
        "api_calls": apis,
        "call_trace": call_trace,
        "behavior_flow": behavior_flow,
        "network": network,
        "dropped": dropped,
        "host_iocs": host_iocs,
        "attck": sorted(attck),
    }
    if stop_reasons:
        out["stop_reason"] = "; ".join(stop_reasons[:3])
    return out


def _empty_behavior(note):
    return {"score": 0, "signatures": [], "process_tree": [], "api_calls": [],
            "call_trace": [], "behavior_flow": [], "network": [], "dropped": [],
            "attck": [], "memory_yara": [], "api_count": 0, "note": note}


def _emulate_core(data):
    """Actual speakeasy emulation. Runs inside a CHILD PROCESS so it can be hard-
    killed on timeout — signal-based alarms don't work in Flask's worker threads
    ('signal only works in main thread of the main interpreter')."""
    import speakeasy

    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, data)
    os.close(fd)
    try:
        se = speakeasy.Speakeasy()
        try:
            module = se.load_module(path)
            # all_entrypoints follows exports/TLS callbacks too (more coverage on
            # samples whose real logic isn't at the module entry). Fall back if the
            # installed speakeasy doesn't accept the kwarg.
            try:
                se.run_module(module, all_entrypoints=True)
            except TypeError:
                se.run_module(module)
        except Exception:
            # Not a loadable PE — try as raw shellcode (x86, then x64).
            for arch in ("x86", "amd64"):
                try:
                    sc = se.load_shellcode(path, arch)
                    se.run_shellcode(sc, offset=0)
                    break
                except Exception:
                    continue
        result = distil(se.get_report())
        # Dump the unpacked memory image ONCE, then both YARA-scan it and run the
        # family config extractors over it — a packed CobaltStrike/Remcos/.NET
        # config lives in RAM after unpacking, not in the on-disk file.
        mem_blob = dump_memory(se)
        result["memory_yara"] = scan_memory_blob(mem_blob)  # YARA on the UNPACKED memory
        if mem_blob:
            try:
                mem_cfg = extract_config(mem_blob, analyze_dotnet(mem_blob))
            except Exception:
                mem_cfg = None
            if mem_cfg:
                result["memory_config"] = mem_cfg
        result["api_count"] = len(result.get("call_trace") or [])
        if result["api_count"] == 0 and not result.get("memory_yara"):
            note = (
                "The emulator observed no behaviour. The sample likely unpacks/relocates "
                "in a way speakeasy cannot follow, is .NET, or uses unsupported APIs. "
                "Absence of behaviour is NOT proof of benignity — rely on static analysis, "
                "Deep RE, or a full-VM sandbox (CAPE)."
            )
            if result.get("stop_reason"):
                note += " Emulation stopped: " + result["stop_reason"]
            result["note"] = note
        return result
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


def _emulate_worker(data, q):
    try:
        q.put(_emulate_core(data))
    except Exception as e:
        q.put(_empty_behavior("Emulation error: %s" % e))


def emulate_bytes(data):
    # Bound the emulation with a killable child process (thread-safe timeout).
    # "spawn" avoids the multithreaded-fork deadlock risk inside Flask's worker
    # threads (fork copies held locks; spawn starts a clean interpreter).
    try:
        ctx = mp.get_context("spawn")
    except ValueError:
        ctx = mp
    q = ctx.Queue()
    p = ctx.Process(target=_emulate_worker, args=(data, q))
    p.start()
    p.join(EMULATION_TIMEOUT + 30)
    if p.is_alive():
        p.terminate()
        p.join(5)
        return _empty_behavior(
            "Emulation timed out (%ss) — the sample is too complex or hung; rely on "
            "static analysis and Deep RE." % EMULATION_TIMEOUT)
    try:
        return q.get(timeout=5)
    except Exception:
        return _empty_behavior("The emulator engine produced no result (speakeasy may not be installed).")


# ── Deep static analysis (capa capabilities + FLOSS deobfuscated strings) ─────
# Both are standalone binaries on PATH (installed in the image). They analyse the
# file WITHOUT executing it, so they run safely and fully local.

def run_capa(path):
    """capa -> code capabilities (what the binary CAN do) + ATT&CK, no execution."""
    exe = shutil.which("capa")
    if not exe:
        return {"capabilities": [], "attck": []}
    try:
        p = subprocess.run([exe, "-j", path], capture_output=True, timeout=240)
        data = json.loads(p.stdout.decode("utf-8", "replace"))
    except Exception:
        return {"capabilities": [], "attck": []}
    caps, attck = [], set()
    for name, r in (data.get("rules") or {}).items():
        meta = r.get("meta") or {}
        ids = []
        for a in (meta.get("attack") or meta.get("att&ck") or []):
            i = a.get("id") if isinstance(a, dict) else None
            if i:
                ids.append(i)
                attck.add(i)
        caps.append({"rule": meta.get("name") or name, "namespace": meta.get("namespace") or "", "attck": ids})
        if len(caps) >= 120:
            break
    return {"capabilities": caps, "attck": sorted(attck)}


def run_floss(path):
    """FLOSS -> stack/tight/decoded strings that plain string extraction misses."""
    exe = shutil.which("floss")
    if not exe:
        return []
    try:
        p = subprocess.run([exe, "-j", path], capture_output=True, timeout=240)
        data = json.loads(p.stdout.decode("utf-8", "replace"))
    except Exception:
        return []
    out, seen = [], set()
    strings = data.get("strings") or {}
    for key in ("stack_strings", "tight_strings", "decoded_strings"):
        for s in (strings.get(key) or []):
            val = s.get("string") if isinstance(s, dict) else str(s)
            if val and val not in seen and len(out) < 200:
                seen.add(val)
                out.append(val)
    return out


# capa/FLOSS get impractically slow on very large binaries (e.g. an 80 MB Go
# agent can take 10+ minutes / time out). Above this size, skip deep static —
# the verdict still stands on structure + reputation + (optional) YARA.
DEEPSTATIC_MAX_BYTES = int(os.environ.get("DEEPSTATIC_MAX_BYTES", str(48 * 1024 * 1024)))


def run_authenticode(path):
    """Verify an Authenticode signature and qualify HOW trustworthy it is. A
    crypto-valid signature is only a strong BENIGN signal when it also chains to a
    real CA and is not self-signed/expired — otherwise an attacker can 'benign-wash'
    with a self-signed or expired cert that still verifies against its own leaf."""
    exe = shutil.which("osslsigncode")
    if not exe:
        return None
    try:
        p = subprocess.run([exe, "verify", path], capture_output=True, timeout=30)
        out = (p.stdout + p.stderr).decode("utf-8", "replace")
    except Exception:
        return None
    low = out.lower()
    if "no signature found" in low or "does not contain" in low:
        return {"signed": False, "valid": False, "publisher": ""}
    valid = "signature verification: ok" in low
    def _cn(field):
        m = re.search(field + r":.*?/CN=([^/\n]+)", out) or re.search(field + r":.*?/O=([^/\n]+)", out)
        return m.group(1).strip() if m else ""
    pub = _cn("Subject")
    issuer = _cn("Issuer")
    self_signed = bool(pub) and pub == issuer
    expired = "certificate has expired" in low or "certificate expired" in low or "has expired" in low
    # osslsigncode reports whether a trusted-chain CA file was used; without one
    # (our default), the chain to a real root is NOT proven, so treat "valid" as
    # leaf-only unless it is clearly a well-formed, timestamped, non-self-signed cert.
    timestamped = "signature is timestamped" in low or "the signature is timestamped" in low
    signed = ("signature verification" in low) or bool(pub)
    # trusted = a strong benign signal only when everything lines up.
    trusted = valid and not self_signed and not expired
    return {"signed": signed, "valid": valid, "trusted": trusted,
            "self_signed": self_signed, "expired": expired, "timestamped": timestamped,
            "publisher": pub, "issuer": issuer}


# ── Unpacking (UPX static unpack) ─────────────────────────────────────────────
# A UPX-packed binary hides its imports/strings/capabilities behind compression.
# Statically unpacking it (upx -d, no execution) exposes the real payload so capa
# / FLOSS / config-extraction see the true code. Other packers need a runtime
# dump — the emulator's memory-YARA pass already scans the UNPACKED memory image.

def maybe_unpack(path):
    """If UPX-packed, statically decompress to a sibling temp file. Returns
    (work_path, unpacked_label). No execution — upx -d only inflates."""
    try:
        with open(path, "rb") as fh:
            head = fh.read(8192)
    except OSError:
        return path, None
    tail = b""
    try:
        with open(path, "rb") as fh:
            fh.seek(max(0, os.path.getsize(path) - 8192))
            tail = fh.read(8192)
    except OSError:
        pass
    if b"UPX!" not in head and b"UPX0" not in head and b"UPX!" not in tail:
        return path, None
    exe = shutil.which("upx")
    if not exe:
        return path, None
    out = path + ".unp"
    try:
        shutil.copyfile(path, out)
        r = subprocess.run([exe, "-d", "-q", out], capture_output=True, timeout=90)
        if r.returncode == 0 and os.path.getsize(out) > 0:
            return out, "UPX"
    except Exception:
        pass
    try:
        os.remove(out)
    except OSError:
        pass
    return path, None


# ── Malware config / C2 extraction (family-specific parsers) ──────────────────
# A recovered config (C2 servers, keys, campaign id) is a near-certain malicious
# signal — benign software has no embedded C2 block. Parsers are purely static
# (byte parsing), extensible by adding to CONFIG_EXTRACTORS.

CS_MAGIC = b"\x00\x01\x00\x01\x00\x02"  # setting#1, type=short, len=2
CS_KEYS = (0x2e, 0x69)  # classic CobaltStrike XOR keys
CS_SETTINGS = {1: "BeaconType", 2: "Port", 3: "SleepTime", 8: "C2Server",
               9: "UserAgent", 11: "HttpPostUri", 37: "Watermark"}


def _cs_parse_tlv(blob):
    import struct
    out, i = {}, 0
    while i + 6 <= len(blob):
        idx, typ, ln = struct.unpack(">HHH", blob[i:i + 6])
        i += 6
        if idx == 0 or ln > 0x10000 or i + ln > len(blob):
            break
        val = blob[i:i + ln]
        i += ln
        if typ == 1 and ln == 2:
            out[idx] = struct.unpack(">H", val)[0]
        elif typ == 2 and ln == 4:
            out[idx] = struct.unpack(">I", val)[0]
        else:
            out[idx] = val
        if len(out) > 64:
            break
    return out


def extract_cobaltstrike(data):
    """Recover a CobaltStrike beacon config: XOR-decode the config block and parse
    its TLV settings (C2 servers, port, sleep, watermark)."""
    for key in CS_KEYS:
        magic = bytes(b ^ key for b in CS_MAGIC)
        pos = data.find(magic)
        if pos < 0:
            continue
        blob = bytes(b ^ key for b in data[pos:pos + 4096])
        settings = _cs_parse_tlv(blob)
        if not settings:
            continue
        c2, keys = [], {}
        raw_c2 = settings.get(8)
        if isinstance(raw_c2, (bytes, bytearray)):
            txt = raw_c2.split(b"\x00")[0].decode("latin-1", "ignore")
            for part in txt.split(","):
                part = part.strip()
                if part and not part.startswith("/") and "." in part:
                    c2.append(part)
        if settings.get(2):
            keys["port"] = str(settings[2])
        if settings.get(3):
            keys["sleep_ms"] = str(settings[3])
        ua = settings.get(9)
        if isinstance(ua, (bytes, bytearray)):
            uav = ua.split(b"\x00")[0].decode("latin-1", "ignore")
            if uav:
                keys["user_agent"] = uav[:200]
        wm = settings.get(37)
        campaign = str(wm) if isinstance(wm, int) and wm else ""
        # Require a real C2 host (a chance TLV parse yielding only a "port" is not a
        # config) plus a plausible port, so a random 6-byte magic hit can't emit a
        # false CobaltStrike attribution.
        port = int(settings.get(2) or 0)
        port_ok = port == 0 or 0 < port <= 65535
        if c2 and port_ok:
            return {"family": "CobaltStrike", "c2": c2, "keys": keys,
                    "campaign": campaign, "raw": "XOR key 0x%02x" % key}
    return None


def _rc4(key, data):
    if not key:
        return b""
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % len(key)]) & 0xff
        s[i], s[j] = s[j], s[i]
    out = bytearray()
    i = j = 0
    for c in data:
        i = (i + 1) & 0xff
        j = (j + s[i]) & 0xff
        s[i], s[j] = s[j], s[i]
        out.append(c ^ s[(s[i] + s[j]) & 0xff])
    return bytes(out)


def _find_pe_resource(data, name):
    """Return the bytes of a named PE resource (e.g. Remcos 'SETTINGS'), or None."""
    try:
        import pefile
    except Exception:
        return None
    try:
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE']])
    except Exception:
        return None
    if not hasattr(pe, "DIRECTORY_ENTRY_RESOURCE"):
        return None
    want = name.upper()
    for entry in pe.DIRECTORY_ENTRY_RESOURCE.entries:
        nm = getattr(entry, "name", None)
        if nm is None or str(nm).upper() != want:
            continue
        try:
            d = entry.directory.entries[0].directory.entries[0].data.struct
            return pe.get_data(d.OffsetToData, d.Size)
        except Exception:
            return None
    return None


def extract_remcos(data, dotnet=None):
    """Remcos RAT stores its config in an RC4-encrypted 'SETTINGS' resource:
    [1 byte key length][key][RC4(config)]. Config fields are \\x1e-separated;
    the first is host:port:password. Fail-closed (returns None) if it doesn't
    parse cleanly, so a wrong guess never produces a bogus config."""
    blob = _find_pe_resource(data, "SETTINGS")
    if not blob or len(blob) < 4:
        return None
    # A real Remcos config resource is small (&lt;64 KB). Cap before the O(n) pure-
    # Python RC4 so a crafted PE with a huge SETTINGS resource can't hang the worker.
    if len(blob) > 256 * 1024:
        return None
    keylen = blob[0]
    if keylen == 0 or keylen > 64 or 1 + keylen >= len(blob):
        return None
    key = blob[1:1 + keylen]
    pt = _rc4(key, blob[1 + keylen:])
    fields = pt.split(b"\x1e")
    if len(fields) < 2:
        return None
    first = fields[0].decode("latin-1", "ignore")
    c2 = []
    for host in first.split("|"):
        host = host.strip()
        if host and ":" in host and "." in host.split(":")[0]:
            c2.append(host)
    if not c2:
        return None
    keys = {}
    # A common layout: field[1] is the botnet/campaign group name.
    grp = fields[1].decode("latin-1", "ignore").strip() if len(fields) > 1 else ""
    if grp and grp.isprintable() and len(grp) < 64:
        keys["group"] = grp
    return {"family": "Remcos", "c2": c2, "keys": keys, "campaign": grp,
            "raw": "RC4 SETTINGS resource"}


# .NET RAT markers → family. AsyncRAT/Quasar/DcRat/Venom share code; RedLine and
# AgentTesla are info-stealers. Detection is by user-string markers (heuristic).
DOTNET_FAMILIES = {
    "AsyncRAT": ("asyncrat", "async rat"),
    "Quasar": ("quasar", "quasarrat"),
    "DcRat": ("dcrat", "dc rat"),
    "njRAT": ("njrat", "njq8", "im523"),
    "RedLine": ("redline", "redlinestealer"),
    "AgentTesla": ("agenttesla", "agent tesla"),
    "VenomRAT": ("venomrat", "venom rat"),
    "XWorm": ("xworm",),
}
RE_HOSTPORT = re.compile(r"\b((?:\d{1,3}\.){3}\d{1,3}|(?:[a-z0-9-]+\.)+[a-z]{2,}):\d{2,5}\b", re.I)
RE_URL = re.compile(r"https?://[^\s'\"<>]{6,200}", re.I)
RE_TG = re.compile(r"\b\d{8,10}:[A-Za-z0-9_-]{30,45}\b")  # Telegram bot token


def extract_dotnet_rat(data, dotnet=None):
    """Heuristic config from a .NET RAT's user strings: family guess + C2/URL/
    Telegram-token candidates. Lower confidence than a byte-exact parser, so it
    only fires when a family marker AND a C2-like indicator are both present."""
    if not dotnet or not dotnet.get("is_dotnet"):
        return None
    strings = dotnet.get("user_strings") or []
    blob = "\n".join(strings)
    low = blob.lower()
    family = ""
    for fam, marks in DOTNET_FAMILIES.items():
        if any(m in low for m in marks):
            family = fam
            break
    c2, seen = [], set()
    for m in RE_HOSTPORT.findall(blob) + RE_URL.findall(blob):
        if m not in seen and len(c2) < 20:
            seen.add(m)
            c2.append(m)
    keys = {}
    tg = RE_TG.findall(blob)
    if tg:
        keys["telegram_token"] = tg[0]
    # Fire ONLY on strong corroboration, to avoid mis-attributing a benign .NET app
    # that merely embeds a host:port string:
    #   (a) a known family marker AND a C2/URL indicator, or
    #   (b) a Telegram bot token (very high-signal exfil channel on its own).
    if family and (c2 or tg):
        return {"family": family, "c2": c2, "keys": keys, "campaign": "",
                "raw": "heuristic from .NET user strings (family marker + C2)"}
    if tg:
        return {"family": ".NET stealer (generic)", "c2": c2, "keys": keys, "campaign": "",
                "raw": "heuristic: Telegram exfil token in .NET user strings"}
    return None


def extract_njrat(data, dotnet=None):
    """njRAT stores its config PLAINTEXT in .NET user strings, fields joined by the
    signature splitter |'|'|  (host | port | version | campaign | install...)."""
    if not dotnet or not dotnet.get("is_dotnet"):
        return None
    for s in (dotnet.get("user_strings") or []):
        if "|'|'|" not in s:
            continue
        parts = [p.strip() for p in s.split("|'|'|") if p.strip()]
        host, port, camp = "", "", ""
        for p in parts:
            if p.isdigit() and 0 < int(p) <= 65535 and not port:
                port = p
            elif ("." in p or ":" in p) and not host and not p.isdigit():
                host = p
        if not host:
            continue
        c2 = host + (":" + port if port else "")
        keys = {}
        if len(parts) > 3:
            camp = parts[-1] if len(parts[-1]) < 40 else ""
            if camp:
                keys["campaign"] = camp
        return {"family": "njRAT", "c2": [c2], "keys": keys, "campaign": camp,
                "raw": "plaintext |'|'| config in .NET strings"}
    return None


# AsyncRAT / Quasar / DcRat / VenomRAT share the same AES-256-CBC config crypto:
# key = PBKDF2-SHA1(masterKey, salt, 50000, 32); each encrypted value is
# base64([32-byte HMAC][16-byte IV][ciphertext]). The masterKey is itself a
# base64 field in #US, so we try each base64 candidate as the key and keep the one
# that decrypts a plausible C2. Fail-closed.
ASYNCRAT_SALT = bytes.fromhex("BFEB1E56FBCD973BB219022430A57843003D5644D21E62B9D4F180E7E6C33941")


def _asyncrat_try_decrypt(master, blob):
    import hashlib
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    if len(blob) < 48:
        return None
    iv, ct = blob[32:48], blob[48:]
    if len(ct) == 0 or len(ct) % 16 != 0:
        return None
    key = hashlib.pbkdf2_hmac("sha1", master, ASYNCRAT_SALT, 50000, 32)
    try:
        dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
        pt = dec.update(ct) + dec.finalize()
        pad = pt[-1]
        if 1 <= pad <= 16:
            pt = pt[:-pad]
        return pt.decode("utf-8", "ignore")
    except Exception:
        return None


def extract_asyncrat(data, dotnet=None):
    import base64
    if not dotnet or not dotnet.get("is_dotnet"):
        return None
    fam = ""
    low = "\n".join(dotnet.get("user_strings") or []).lower()
    for f, marks in DOTNET_FAMILIES.items():
        if f in ("AsyncRAT", "Quasar", "DcRat", "VenomRAT") and any(m in low for m in marks):
            fam = f
            break
    # base64 candidates from the user strings.
    cands = []
    for s in (dotnet.get("user_strings") or []):
        s = s.strip()
        if 16 <= len(s) <= 4096 and re.fullmatch(r"[A-Za-z0-9+/=]+", s):
            try:
                cands.append((s, base64.b64decode(s + "=" * (-len(s) % 4))))
            except Exception:
                continue
    if len(cands) < 2:
        return None
    for _kstr, kbytes in cands[:60]:
        if not (16 <= len(kbytes) <= 64):
            continue
        c2, keys, hits = [], {}, 0
        for _vstr, vb in cands:
            if len(vb) < 48:
                continue
            pt = _asyncrat_try_decrypt(kbytes, vb)
            if not pt or not pt.isprintable() or len(pt) < 2:
                continue
            hits += 1
            for host in re.findall(r"(?:\d{1,3}(?:\.\d{1,3}){3}|(?:[a-z0-9-]+\.)+[a-z]{2,})", pt, re.I):
                if host not in c2 and len(c2) < 20:
                    c2.append(host)
            for p in re.findall(r"\b\d{2,5}\b", pt):
                if 0 < int(p) <= 65535 and "port" not in keys:
                    keys["port"] = p
        if c2 and hits >= 2:
            return {"family": fam or "AsyncRAT-family", "c2": c2, "keys": keys,
                    "campaign": "", "raw": "AES-256-CBC .NET config (PBKDF2 key)"}
    return None


CONFIG_EXTRACTORS = (extract_cobaltstrike, extract_remcos, extract_njrat,
                     extract_asyncrat, extract_dotnet_rat)


def extract_config(data, dotnet=None):
    """Run every family config extractor; return the first hit. Bounded scan
    (config blocks live in the first few MB) to stay fast on large files."""
    scan = data if len(data) <= 16 * 1024 * 1024 else data[:16 * 1024 * 1024]
    for fn in CONFIG_EXTRACTORS:
        try:
            cfg = fn(scan, dotnet)
        except TypeError:
            try:
                cfg = fn(scan)
            except Exception:
                cfg = None
        except Exception:
            cfg = None
        if cfg:
            return cfg
    return None


# ── Packer / protector / compiler identification (Detect-It-Easy-style) ───────
# Naming the packer is a first-class triage signal ("VMProtect → go dynamic, don't
# waste time on static RE"). Heuristic: section names + marker strings.
PACKER_SIGS = (
    ("UPX", ("UPX0", "UPX1", "UPX!")),
    ("Themida/WinLicense", (".themida", ".winlice", "themida")),
    ("VMProtect", (".vmp0", ".vmp1", ".vmp2", "vmprotect")),
    ("ASPack", (".aspack", ".adata")),
    ("MPRESS", (".mpress1", ".mpress2")),
    ("Enigma", (".enigma1", ".enigma2", "enigma protector")),
    ("PECompact", ("pec1", "pec2", "pecompact")),
    ("FSG", ("fsg!",)),
    ("Petite", (".petite",)),
    ("NsPack", (".nsp0", ".nsp1", ".nsp2")),
    ("Obsidium", ("obsidium",)),
    ("MoleBox", (".molebox",)),
    ("PELock", ("pelock",)),
    (".NET Reactor", ("reactor",)),
    ("ConfuserEx (.NET)", ("confuseddbyattribute", "confuser")),
    ("PyInstaller", ("pyi-", "_meipass", "pyinstaller")),
    ("Nuitka", ("nuitka",)),
    ("Inno Setup", ("inno setup", "innosetup")),
    ("NSIS installer", ("nullsoftinst",)),
)


def detect_packer(data):
    """Return the identified packer/protector/installer, or ''."""
    secnames = []
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        for s in pe.sections:
            secnames.append(s.Name.rstrip(b"\x00").decode("latin-1", "ignore").lower())
    except Exception:
        pass
    head = data[:16384]
    tail = data[-16384:] if len(data) > 16384 else b""
    blob = (bytes(head) + bytes(tail)).lower()
    for name, markers in PACKER_SIGS:
        for m in markers:
            mb = m.lower()
            if any(mb in sn for sn in secnames) or mb.encode("latin-1", "ignore") in blob:
                return name
    return ""


# ── .NET analysis (dnfile — metadata, user strings, refs, obfuscator) ─────────
# .NET assemblies hide their logic behind IL that speakeasy can't emulate; static
# metadata + the #US user-string heap (where RAT configs, C2 and commands live)
# is far more revealing than raw byte strings. Purely static, no execution.

DOTNET_SUSP_APIS = (
    "amsiscanbuffer", "amsi", "etweventwrite", "assembly.load", "loadlibrary",
    "getprocaddress", "virtualprotect", "virtualalloc", "createdecryptor",
    "rijndael", "aes", "rfc2898", "webclient", "downloadstring", "downloadfile",
    "httpwebrequest", "process.start", "registrykey", "setvalue", "getasynckeystate",
    "createmutex", "reflection.emit", "gzipstream", "deflatestream", "frombase64string",
)
DOTNET_OBFUSCATORS = {
    "ConfuserEx": ("confusedbyattribute", "confuser"),
    "SmartAssembly": ("smartassembly",),
    ".NET Reactor": ("reactor", "eazfuscator"),
    "Dotfuscator": ("dotfuscator",),
    "Babel": ("babelobfuscator", "babelattribute"),
    "Eazfuscator": ("eazfuscator",),
}


def _read_compressed_uint(raw, i):
    b0 = raw[i]
    if b0 & 0x80 == 0:
        return b0, i + 1
    if b0 & 0xC0 == 0x80:
        return ((b0 & 0x3f) << 8) | raw[i + 1], i + 2
    return ((b0 & 0x1f) << 24) | (raw[i + 1] << 16) | (raw[i + 2] << 8) | raw[i + 3], i + 4


def _parse_us_heap(raw):
    """Parse the .NET #US (user string) heap into a list of strings. Each blob is
    [compressed-length][UTF-16LE bytes][1 flag byte] per ECMA-335."""
    out, i = [], 1  # skip the leading 0 byte
    while i < len(raw) - 1:
        b0 = raw[i]
        if b0 == 0:
            i += 1
            continue
        try:
            ln, i = _read_compressed_uint(raw, i)
        except Exception:
            break
        if ln == 0 or i + ln > len(raw):
            break
        blob = raw[i:i + ln]
        i += ln
        try:
            s = blob[:-1].decode("utf-16le", "ignore") if len(blob) > 1 else ""
        except Exception:
            s = ""
        if s and any(0x20 <= ord(c) < 0x7f or ord(c) > 0x7f for c in s):
            out.append(s)
        if len(out) > 4000:
            break
    return out


def _is_dotnet(data):
    try:
        import pefile
        pe = pefile.PE(data=data, fast_load=True)
        pe.parse_data_directories(directories=[pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR']])
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[14]
        return d.VirtualAddress != 0 and d.Size != 0
    except Exception:
        return False


def analyze_dotnet(data):
    """Static .NET analysis: user strings, assembly refs, suspicious CLR APIs,
    obfuscator + AMSI/ETW bypass markers. Returns None for non-.NET files."""
    if not _is_dotnet(data):
        return None
    out = {"is_dotnet": True, "user_strings": [], "assembly_refs": [],
           "suspicious_apis": [], "obfuscator": "", "amsi_bypass": False}
    # A crafted/huge .NET assembly can make dnfile consume large time/memory in the
    # worker (no subprocess isolation here). Above the deep-static cap, report the
    # .NET flag only and skip full metadata parsing.
    if len(data) > DEEPSTATIC_MAX_BYTES:
        out["note"] = "large .NET assembly — metadata parsing skipped"
        return out
    try:
        import dnfile
    except Exception:
        return out  # detected .NET but no dnfile → minimal report
    try:
        pe = dnfile.dnPE(data=data, fast_load=False)
    except Exception:
        return out
    # User strings via the raw #US heap (robust across dnfile versions).
    try:
        us = getattr(pe.net, "user_strings", None)
        raw = getattr(us, "__data__", None) if us is not None else None
        if raw:
            out["user_strings"] = _parse_us_heap(bytes(raw))[:1500]
    except Exception:
        pass
    # Assembly references + suspicious member/type names from metadata tables.
    names = []
    try:
        md = pe.net.mdtables
        for row in (getattr(md, "AssemblyRef", None).rows if getattr(md, "AssemblyRef", None) else []):
            n = getattr(row, "Name", None)
            if n:
                out["assembly_refs"].append(str(n))
        for tbl in ("MemberRef", "TypeRef"):
            t = getattr(md, tbl, None)
            if t:
                for row in t.rows:
                    n = getattr(row, "Name", None)
                    if n:
                        names.append(str(n).lower())
    except Exception:
        pass
    blob = "\n".join(out["user_strings"]).lower() + "\n" + "\n".join(names)
    out["suspicious_apis"] = sorted({a for a in DOTNET_SUSP_APIS if a in blob})[:40]
    if "amsiscanbuffer" in blob or "amsi" in blob:
        out["amsi_bypass"] = True
    for obf, marks in DOTNET_OBFUSCATORS.items():
        if any(m in blob for m in marks):
            out["obfuscator"] = obf
            break
    out["user_strings"] = [s for s in out["user_strings"] if len(s) > 3][:400]
    return out


@app.post("/analyze")
def analyze():
    f = request.files.get("file")
    if f is None:
        return jsonify(error="file is required"), 400
    data = f.read()
    if not data:
        return jsonify(error="empty file"), 400
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, data)
    os.close(fd)
    work_path = path
    try:
        sig = run_authenticode(path)  # fast (reads only the signature), run regardless of size
        # Statically unpack (UPX) so capa/FLOSS/config see the REAL payload.
        work_path, unpacked = maybe_unpack(path)
        try:
            with open(work_path, "rb") as fh:
                work = fh.read()
        except OSError:
            work, work_path = data, path
        dotnet = analyze_dotnet(work)
        config = extract_config(work, dotnet)
        packer = detect_packer(work)
        if len(work) > DEEPSTATIC_MAX_BYTES:
            return jsonify(capabilities=[], attck=[], floss_strings=[], signature=sig,
                           config=config, unpacked=unpacked, dotnet=dotnet, packer=packer,
                           note="file too large for capa/FLOSS (%d MB) — deep static skipped" % (len(work) // (1024 * 1024)))
        capa = run_capa(work_path)
        floss = run_floss(work_path)
        return jsonify(capabilities=capa["capabilities"], attck=capa["attck"],
                       floss_strings=floss, signature=sig, config=config,
                       unpacked=unpacked, dotnet=dotnet, packer=packer)
    except Exception as e:
        return jsonify(error=str(e), capabilities=[], attck=[], floss_strings=[]), 200
    finally:
        for p in {path, work_path}:
            try:
                os.remove(p)
            except OSError:
                pass


# ── Reverse engineering (radare2 — disassembly + pseudo-code) ─────────────────
# Selects the functions most worth decompiling — the entrypoint and the callers of
# suspicious imports (decrypt stubs, C2 beacons, injection loaders are usually
# SMALL, so "largest N" misses them) — and hands their pseudo-code to the AI.
# .NET assemblies are routed to IL metadata (radare2 only sees the CLR stub).

RE_MAX_BYTES = int(os.environ.get("RE_MAX_BYTES", str(64 * 1024 * 1024)))
# Import base-name substrings whose CALLERS are worth decompiling.
RE_SUSP_IMPORTS = (
    "virtualalloc", "virtualprotect", "writeprocessmemory", "createremotethread",
    "ntunmapviewofsection", "queueuserapc", "setthreadcontext", "resumethread",
    "loadlibrary", "getprocaddress", "winexec", "createprocess", "shellexecute",
    "urldownload", "internetopen", "internetconnect", "httpsendrequest", "httpopenrequest",
    "wsastartup", "crypt", "bcrypt", "regsetvalue", "regcreatekey", "createservice",
    "adjusttokenprivileges", "setwindowshook", "getasynckeystate", "createmutex",
    "isdebuggerpresent", "checkremotedebugger",
)


def _r2(r2, path, cmd, timeout):
    """Run one r2 command and return the last JSON line parsed, or None."""
    try:
        out = subprocess.run([r2, "-q", "-A", "-e", "scr.color=0", "-c", cmd, path],
                             capture_output=True, timeout=timeout).stdout.decode("utf-8", "replace")
    except Exception:
        return None
    for line in reversed(out.splitlines()):
        line = line.strip()
        if line.startswith("[") or line.startswith("{"):
            try:
                return json.loads(line)
            except Exception:
                continue
    return None


def _rank_re_functions(r2, path, funcs):
    """Rank candidate functions: entrypoint first, then callers of suspicious
    imports (by count), then remaining by size. Returns up to 12 functions."""
    by_addr = {f.get("offset", 0): f for f in funcs}
    score = {addr: 0 for addr in by_addr}
    # xrefs of every suspicious import → boost the caller function.
    imports = _r2(r2, path, "iij", 60) or _r2(r2, path, "iaj", 60) or []
    if isinstance(imports, dict):
        imports = imports.get("imports", [])
    sym_cmds = []
    for imp in imports:
        nm = str(imp.get("name") or "").lower()
        if any(s in nm for s in RE_SUSP_IMPORTS):
            sym_cmds.append("axtj sym.imp.%s" % imp.get("name"))
        if len(sym_cmds) >= 40:
            break
    for cmd in sym_cmds:
        xrefs = _r2(r2, path, cmd, 40)
        if not isinstance(xrefs, list):
            continue
        for x in xrefs:
            fa = x.get("fcn_addr")
            if fa in score:
                score[fa] += 1

    def is_entry(f):
        n = str(f.get("name") or "")
        return n in ("entry0", "main", "sym.main") or n.startswith("entry") or "main" in n

    ranked = sorted(
        (f for f in funcs if f.get("size", 0) >= 16 and not str(f.get("name", "")).startswith(("sym.imp", "fcn.0000"))),
        key=lambda f: (is_entry(f), score.get(f.get("offset", 0), 0), f.get("size", 0)),
        reverse=True,
    )
    sel, seen = [], set()
    # Always seed the entrypoint(s).
    for f in funcs:
        if is_entry(f) and f.get("offset") not in seen:
            sel.append(f)
            seen.add(f.get("offset"))
    for f in ranked:
        if f.get("offset") in seen:
            continue
        sel.append(f)
        seen.add(f.get("offset"))
        if len(sel) >= 12:
            break
    return sel[:12]


def run_radare(path):
    r2 = shutil.which("r2") or shutil.which("radare2")
    if not r2:
        return {"functions": [], "pseudocode": "", "error": "radare2 not installed"}
    try:
        size = os.path.getsize(path)
    except OSError:
        size = 0
    if size > RE_MAX_BYTES:
        return {"functions": [], "pseudocode": "",
                "note": "file too large for RE (%d MB) — analysis skipped" % (size // (1024 * 1024))}
    funcs = _r2(r2, path, "aflj", 220)
    if funcs is None:
        return {"functions": [], "pseudocode": "", "error": "radare2 analysis failed or timed out"}
    if not isinstance(funcs, list) or not funcs:
        return {"functions": [], "pseudocode": "", "note": "no functions recovered (packed or stripped binary?)"}
    cand = _rank_re_functions(r2, path, funcs)
    pseudo = ""
    if cand:
        cmds = ";".join("?e ===FUNC {}===;pdc @ {}".format(f.get("name"), f.get("offset")) for f in cand)
        try:
            out2 = subprocess.run([r2, "-q", "-A", "-e", "scr.color=0", "-c", cmds, path],
                                  capture_output=True, timeout=280).stdout.decode("utf-8", "replace")
            pseudo = out2[:48000]
        except Exception:
            pseudo = ""
    fnlist = [{"name": f.get("name"), "size": f.get("size", 0), "addr": hex(f.get("offset", 0))} for f in funcs[:100]]
    return {"functions": fnlist, "pseudocode": pseudo}


@app.post("/reverse")
def reverse():
    f = request.files.get("file")
    if f is None:
        return jsonify(error="file is required"), 400
    data = f.read()
    if not data:
        return jsonify(error="empty file"), 400
    # .NET: radare2 only sees the native CLR bootstrap — route to IL metadata so the
    # AI reads the real managed logic (methods / user strings / suspicious CLR APIs).
    if _is_dotnet(data):
        dn = analyze_dotnet(data) or {}
        lines = ["=== .NET ASSEMBLY (managed IL — radare2 disassembly is not meaningful) ==="]
        if dn.get("obfuscator"):
            lines.append("Obfuscator: %s" % dn["obfuscator"])
        if dn.get("amsi_bypass"):
            lines.append("References AMSI (likely AV/AMSI bypass)")
        if dn.get("assembly_refs"):
            lines.append("Assembly refs: " + ", ".join(dn["assembly_refs"][:30]))
        if dn.get("suspicious_apis"):
            lines.append("Suspicious CLR APIs: " + ", ".join(dn["suspicious_apis"]))
        if dn.get("user_strings"):
            lines.append("\n=== .NET USER STRINGS (config / C2 / commands often live here) ===")
            lines.extend(dn["user_strings"][:200])
        fns = [{"name": a, "size": 0, "addr": "il"} for a in (dn.get("suspicious_apis") or [])[:40]]
        return jsonify(functions=fns, pseudocode="\n".join(lines)[:48000], dotnet=True)
    fd, path = tempfile.mkstemp(suffix=".bin")
    os.write(fd, data)
    os.close(fd)
    try:
        res = run_radare(path)
        return jsonify(res)
    except Exception as e:
        return jsonify(error=str(e), functions=[], pseudocode=""), 200
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# ── Document / script deep analysis (macros, PDF JS, deobfuscation) ───────────
# Office VBA macros are the #1 phishing-doc payload vector; olevba (oletools)
# extracts the macro source AND flags AutoExec/Suspicious/IOC keywords without
# running anything. PDFs are checked for the /OpenAction, /Launch, /JS action
# keywords that drive drive-by execution. Scripts (ps1/js/vbs/bat/hta) are
# de-obfuscated (base64 / \xNN / char-code) so the AI reads the real payload.

# Extension → coarse document class. Office also detected by magic (OLE / ZIP).
OFFICE_EXT = (".doc", ".docm", ".dot", ".dotm", ".xls", ".xlsm", ".xlsb", ".xlt",
              ".xltm", ".ppt", ".pptm", ".pot", ".potm", ".xla", ".xlam", ".ppa",
              ".docx", ".xlsx", ".pptx", ".rtf", ".mht", ".mhtml")
SCRIPT_EXT = (".ps1", ".psm1", ".bat", ".cmd", ".vbs", ".vbe", ".js", ".jse",
              ".wsf", ".hta", ".sh", ".py", ".pl", ".php", ".lnk")

RE_B64 = re.compile(r"[A-Za-z0-9+/]{40,}={0,2}")
RE_HEXESC = re.compile(r"(?:\\x[0-9A-Fa-f]{2}){8,}")
# Script markers that signal downloaders / stagers / obfuscation.
SCRIPT_MARKERS = (
    "downloadstring", "downloadfile", "invoke-expression", "iex ", "iex(",
    "invoke-webrequest", "frombase64string", "-encodedcommand", "-enc ", "-e ",
    "webclient", "bitstransfer", "start-process", "shellexecute", "wscript.shell",
    "createobject", "powershell", "cmd.exe", "certutil", "bitsadmin", "mshta",
    "regsvr32", "rundll32", "createprocess", "virtualalloc", "getdelegatefortype",
    "reflection.assembly", "add-mppreference", "set-mppreference", "hidden",
    "bypass", "-nop", "-noprofile", "-w hidden", "char(", "chr(", "eval(",
    "unescape(", "atob(", "fromcharcode", "document.write",
)


# Bound the text fed to the de-obfuscation / keyword regexes so a large or
# adversarial document can't drive a long (near-pathological) scan in the worker.
DOC_MAX_TEXT = int(os.environ.get("DOC_MAX_TEXT", str(8 * 1024 * 1024)))


def _decode_layers(text):
    """Best-effort de-obfuscation: decode long base64 blobs and \\xNN escapes so
    hidden URLs/commands become visible. Returns a list of decoded snippets."""
    import base64
    if len(text) > DOC_MAX_TEXT:
        text = text[:DOC_MAX_TEXT]
    out, seen = [], set()
    for m in RE_B64.findall(text)[:20]:
        try:
            raw = base64.b64decode(m + "=" * (-len(m) % 4), validate=False)
        except Exception:
            continue
        # UTF-16LE (PowerShell -EncodedCommand) or ASCII
        for dec in (raw.decode("utf-16le", "ignore"), raw.decode("utf-8", "ignore")):
            dec = dec.strip()
            printable = sum(c.isprintable() for c in dec)
            if len(dec) >= 8 and printable >= len(dec) * 0.8 and dec not in seen:
                seen.add(dec)
                out.append(dec[:600])
                break
    for m in RE_HEXESC.findall(text)[:20]:
        try:
            dec = bytes(int(b, 16) for b in re.findall(r"[0-9A-Fa-f]{2}", m)).decode("utf-8", "ignore").strip()
        except Exception:
            continue
        if len(dec) >= 8 and dec not in seen:
            seen.add(dec)
            out.append(dec[:600])
    return out[:30]


def _scan_markers(text):
    low = text.lower()
    return sorted({mk.strip() for mk in SCRIPT_MARKERS if mk in low})


def analyze_office(path):
    """olevba: extract VBA macros + AutoExec/Suspicious/IOC indicators."""
    out = {"macros": [], "suspicious": [], "iocs": []}
    try:
        from oletools.olevba import VBA_Parser
    except Exception as e:
        out["error"] = "oletools not installed: %s" % e
        return out
    try:
        vp = VBA_Parser(path)
        if vp.detect_vba_macros():
            for (_fn, _stream, vba_name, vba_code) in vp.extract_macros():
                if vba_code and vba_code.strip():
                    out["macros"].append({"name": str(vba_name), "code": vba_code[:8000]})
            try:
                for kw_type, keyword, desc in (vp.analyze_macros() or []):
                    t = str(kw_type)
                    if t in ("AutoExec", "Suspicious"):
                        line = "%s: %s" % (keyword, desc)
                        if line not in out["suspicious"]:
                            out["suspicious"].append(line[:200])
                    elif t == "IOC":
                        if keyword not in out["iocs"]:
                            out["iocs"].append(str(keyword)[:200])
            except Exception:
                pass
        vp.close()
    except Exception as e:
        out["error"] = str(e)
    return out


def analyze_pdf(data):
    """Flag the PDF action keywords that drive automatic/drive-by execution and
    surface any readable JavaScript. Purely lexical — no rendering, no JS engine."""
    out = {"suspicious": [], "scripts": []}
    flags = ((b"/OpenAction", "auto-run action on open"), (b"/AA", "additional (auto) actions"),
             (b"/Launch", "launch external program"), (b"/JavaScript", "embedded JavaScript"),
             (b"/JS", "embedded JavaScript"), (b"/EmbeddedFile", "embedded file"),
             (b"/RichMedia", "embedded rich media / Flash"), (b"/SubmitForm", "submits form data"),
             (b"/URI", "external URL"), (b"/GoToR", "remote go-to"))
    for kw, desc in flags:
        if kw in data:
            line = "%s (%s)" % (kw.decode(), desc)
            if line not in out["suspicious"]:
                out["suspicious"].append(line)
    text = data.decode("latin-1", "ignore")
    if len(text) > DOC_MAX_TEXT:
        text = text[:DOC_MAX_TEXT]
    for m in re.findall(r"/JS\s*\(((?:[^()\\]|\\.){8,2000})\)", text)[:10]:
        js = m.replace("\\(", "(").replace("\\)", ")").strip()
        if js and js not in out["scripts"]:
            out["scripts"].append(js[:2000])
    for dec in _decode_layers(text):
        if dec not in out["scripts"]:
            out["scripts"].append(dec)
    return out


def analyze_script(data):
    """Text script: surface downloader/stager markers + de-obfuscated layers."""
    text = data.decode("utf-8", "ignore") or data.decode("latin-1", "ignore")
    if len(text) > DOC_MAX_TEXT:
        text = text[:DOC_MAX_TEXT]
    return {"markers": _scan_markers(text), "decoded": _decode_layers(text),
            "preview": text[:4000]}


@app.post("/document")
def document():
    """Deep-analyse a document/script sample. `kind` hint (office|pdf|script) or
    the file extension/magic decides the analyser. Fully local, no execution."""
    f = request.files.get("file")
    if f is None:
        return jsonify(error="file is required"), 400
    data = f.read()
    if not data:
        return jsonify(error="empty file"), 400
    name = (f.filename or "").lower()
    kind = (request.form.get("kind") or "").lower()
    ext = os.path.splitext(name)[1]
    is_office = kind == "office" or ext in OFFICE_EXT or data[:2] == b"PK" or data[:4] == b"\xd0\xcf\x11\xe0"
    is_pdf = kind == "pdf" or ext == ".pdf" or data[:5] == b"%PDF-"
    is_script = kind == "script" or ext in SCRIPT_EXT
    result = {"doc_type": ""}
    try:
        if is_pdf:
            result["doc_type"] = "pdf"
            result.update(analyze_pdf(data))
        elif is_office:
            # olevba needs a path
            fd, path = tempfile.mkstemp(suffix=ext or ".bin")
            os.write(fd, data)
            os.close(fd)
            try:
                result["doc_type"] = "office"
                result.update(analyze_office(path))
            finally:
                try:
                    os.remove(path)
                except OSError:
                    pass
        elif is_script:
            result["doc_type"] = "script"
            result.update(analyze_script(data))
        else:
            result["doc_type"] = "unknown"
        return jsonify(result)
    except Exception as e:
        return jsonify(error=str(e), doc_type=result.get("doc_type", "")), 200


@app.get("/health")
def health():
    try:
        import speakeasy  # noqa: F401
        emu = True
    except Exception:
        emu = False
    try:
        import oletools  # noqa: F401
        ole = True
    except Exception:
        ole = False
    try:
        import dnfile  # noqa: F401
        dnet = True
    except Exception:
        dnet = False
    return jsonify(ok=True, speakeasy=emu,
                   capa=shutil.which("capa") is not None,
                   floss=shutil.which("floss") is not None,
                   radare2=(shutil.which("r2") or shutil.which("radare2")) is not None,
                   osslsigncode=shutil.which("osslsigncode") is not None,
                   oletools=ole,
                   upx=shutil.which("upx") is not None,
                   dotnet=dnet)


@app.post("/emulate")
def emulate():
    f = request.files.get("file")
    if f is None:
        return jsonify(error="file is required"), 400
    data = f.read()
    if not data:
        return jsonify(error="empty file"), 400
    try:
        return jsonify(emulate_bytes(data))
    except Exception as e:  # never fail hard — return an empty (but valid) summary
        note = "Emulation error: %s" % e
        try:
            import speakeasy  # noqa: F401
        except Exception:
            note = "The emulator engine (speakeasy) is not installed in the sidecar — dynamic emulation is unavailable."
        return jsonify(error=str(e), note=note, score=0, signatures=[], process_tree=[],
                       api_calls=[], network=[], dropped=[], attck=[], api_count=0), 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", "8091")), threaded=True)
