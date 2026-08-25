#!/usr/bin/env python3
"""pyharness.py — instrumentation wrapper for Python samples.

CPython's audit hooks (PEP 578) are the equivalent of the Node harness's two
channels in one mechanism: the interpreter itself reports every `exec`/`compile`,
every subprocess launch, every socket connect and every file open, from inside the
runtime, so obfuscation that hides these calls from a source-level scanner cannot
hide them here — the code still has to make the call to have the effect.

Dangerous operations are recorded and then defeated by replacing the module
entry points, the same policy the Node harness uses: the command line is the
finding, running it would be the compromise.
"""

import base64
import builtins
import hashlib
import json
import os
import runpy
import signal
import sys
import traceback

OUT = os.environ.get("AH_REPORT", "/tmp/ah-report.json")
MAX_EVENTS = int(os.environ.get("AH_MAX_EVENTS", "4000"))
MAX_BLOB = 256 * 1024
MAX_ARG = 2048

REPORT = {
    "events": [], "scripts": [], "dropped": [], "network": [], "decrypted": [],
    "requires": [], "env_read": [], "errors": [], "truncated": False,
}
_seq = [0]


def clip(v, n=MAX_ARG):
    try:
        s = v if isinstance(v, str) else repr(v)
    except Exception:
        s = "<unrepresentable>"
    s = "".join(ch if (ch == "\n" or ch == "\t" or 0x20 <= ord(ch) < 0x7F or ord(ch) > 0xA0) else "." for ch in s)
    return s if len(s) <= n else s[:n] + "…[+%d]" % (len(s) - n)


def rec(category, action, detail=""):
    if _seq[0] >= MAX_EVENTS:
        REPORT["truncated"] = True
        return
    _seq[0] += 1
    REPORT["events"].append({
        "seq": _seq[0], "t": 0, "category": category,
        "action": action, "detail": clip(detail),
    })


def sha256(b):
    if isinstance(b, str):
        b = b.encode("utf8", "replace")
    return hashlib.sha256(b).hexdigest()


# ── Audit hook: the interpreter reports on itself ──────────────────────────

# Events worth a line in the report, mapped to the category the UI groups by.
AUDIT_MAP = {
    "exec": ("code", "exec"),
    "compile": ("code", "compile"),
    "subprocess.Popen": ("process", "Popen"),
    "os.system": ("process", "os.system"),
    "os.exec": ("process", "os.exec"),
    "os.spawn": ("process", "os.spawn"),
    "socket.connect": ("network", "socket.connect"),
    "socket.getaddrinfo": ("network", "dns"),
    "urllib.Request": ("network", "urllib"),
    "http.client.connect": ("network", "http.connect"),
    "ftplib.connect": ("network", "ftp"),
    "open": ("filesystem", "open"),
    "os.remove": ("filesystem", "remove"),
    "os.rename": ("filesystem", "rename"),
    "os.chmod": ("filesystem", "chmod"),
    "shutil.copyfile": ("filesystem", "copy"),
    "importlib.import_module": ("require", "import"),
    "ctypes.dlopen": ("code", "ctypes.dlopen"),
    "ctypes.call_function": ("code", "ctypes.call"),
    "marshal.loads": ("code", "marshal.loads"),
    "pickle.find_class": ("code", "pickle.find_class"),
}

# `open` fires constantly during interpreter start-up; only writes are findings.
_WRITE_MODES = ("w", "a", "x", "+")


def _audit(event, args):
    mapped = AUDIT_MAP.get(event)
    if not mapped:
        return
    category, action = mapped

    try:
        if event == "open":
            path, mode = (list(args) + [None, None])[:2]
            if not mode or not any(m in str(mode) for m in _WRITE_MODES):
                return
            rec(category, "open(write)", "%s mode=%s" % (clip(path, 512), mode))
            return

        if event == "compile":
            src = args[0] if args else b""
            if isinstance(src, (bytes, bytearray)):
                src = bytes(src).decode("utf8", "replace")
            if isinstance(src, str) and len(src) >= 24:
                _add_script(src, dynamic=True)
            return

        if event == "exec":
            rec(category, action, "<code object>")
            return

        if event == "socket.connect":
            addr = args[1] if len(args) > 1 else args
            t = clip(addr, 256)
            rec(category, action, t)
            if t not in REPORT["network"]:
                REPORT["network"].append(t)
            return

        if event in ("socket.getaddrinfo", "urllib.Request", "http.client.connect"):
            t = clip(args[0] if args else "", 512)
            rec(category, action, t)
            if t and t not in REPORT["network"]:
                REPORT["network"].append(t)
            return

        if event == "importlib.import_module":
            name = clip(args[0] if args else "", 128)
            if not any(r["module"] == name for r in REPORT["requires"]) and len(REPORT["requires"]) < 500:
                REPORT["requires"].append({"module": name, "from": "?"})
            return

        rec(category, action, clip(args, 512))
    except Exception as e:  # a harness must never break the run it observes
        REPORT["errors"].append("audit(%s): %s" % (event, e))


def _add_script(src, dynamic):
    if len(REPORT["scripts"]) >= 400:
        REPORT["truncated"] = True
        return
    REPORT["scripts"].append({
        "url": "<runtime-generated>" if dynamic else "<file>",
        "dynamic": dynamic, "length": len(src), "sha256": sha256(src),
        "source": src[:512 * 1024], "truncated": len(src) > 512 * 1024,
    })
    if dynamic:
        rec("code", "runtime_code_compiled", "%d bytes, sha256=%s" % (len(src), sha256(src)[:16]))


# ── Neutering shims ────────────────────────────────────────────────────────

def _install_shims():
    import subprocess

    class _FakeProc:
        pid = 0
        returncode = 0

        def communicate(self, *a, **k):
            return (b"", b"")

        def wait(self, *a, **k):
            return 0

        def poll(self):
            return 0

        def kill(self):
            pass

        terminate = kill

    def _popen(*a, **k):
        rec("process", "subprocess.Popen", clip(a[0] if a else k.get("args"), 1024))
        return _FakeProc()

    subprocess.Popen = _popen
    subprocess.call = lambda *a, **k: (rec("process", "subprocess.call", clip(a[0] if a else "", 1024)), 0)[1]
    subprocess.run = lambda *a, **k: (rec("process", "subprocess.run", clip(a[0] if a else "", 1024)), _FakeProc())[1]
    subprocess.check_output = lambda *a, **k: (rec("process", "check_output", clip(a[0] if a else "", 1024)), b"")[1]
    os.system = lambda cmd: (rec("process", "os.system", clip(cmd, 1024)), 0)[1]

    # Writes are captured rather than performed: the bytes ARE the next stage.
    _real_open = builtins.open

    def _open(file, mode="r", *a, **k):
        if any(m in str(mode) for m in _WRITE_MODES):
            return _CaptureFile(file, mode)
        return _real_open(file, mode, *a, **k)

    builtins.open = _open


class _CaptureFile:
    """Stands in for a writable file object, keeping the bytes in the report."""

    def __init__(self, path, mode):
        self.path = str(path)
        self.mode = mode
        self.buf = bytearray()

    def write(self, data):
        if isinstance(data, str):
            data = data.encode("utf8", "replace")
        if len(self.buf) < MAX_BLOB:
            self.buf.extend(data)
        return len(data)

    def writelines(self, lines):
        for ln in lines:
            self.write(ln)

    def flush(self):
        pass

    def close(self):
        blob = bytes(self.buf)
        rec("filesystem", "write", "%s (%d bytes)" % (clip(self.path, 512), len(blob)))
        if len(REPORT["dropped"]) < 60:
            REPORT["dropped"].append({
                "path": clip(self.path, 512), "size": len(blob), "sha256": sha256(blob),
                "b64": base64.b64encode(blob).decode() if len(blob) <= MAX_BLOB else "",
                "preview": clip(blob[:512].decode("latin1"), 512),
            })

    def __enter__(self):
        return self

    def __exit__(self, *a):
        self.close()
        return False


# ── Result flushing ────────────────────────────────────────────────────────

_flushed = [False]


def flush(reason):
    REPORT["stop_reason"] = reason
    try:
        with open(OUT, "w", encoding="utf8") as fh:  # the REAL open, captured below
            json.dump(REPORT, fh)
        _flushed[0] = True
    except Exception as e:
        REPORT["errors"].append("flush failed: %s" % e)


def main():
    if len(sys.argv) < 2:
        print("usage: pyharness.py <script>", file=sys.stderr)
        return 2
    target = sys.argv[1]

    # Keep a pristine `open` for flushing before the shim replaces the builtin.
    real_open = builtins.open
    global flush

    def _flush(reason):
        REPORT["stop_reason"] = reason
        try:
            with real_open(OUT, "w", encoding="utf8") as fh:
                json.dump(REPORT, fh)
            _flushed[0] = True
        except Exception as e:
            REPORT["errors"].append("flush failed: %s" % e)

    flush = _flush

    def _on_signal(signum, frame):
        flush("killed:%d" % signum)
        os._exit(0)

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, _on_signal)
        except Exception:
            pass

    sys.addaudithook(_audit)
    _install_shims()
    rec("harness", "ready", "python " + sys.version.split()[0])

    sys.argv = [target]
    try:
        runpy.run_path(target, run_name="__main__")
        flush("completed")
    except SystemExit:
        flush("sys_exit")
    except BaseException as e:
        REPORT["errors"].append("uncaught: " + "".join(traceback.format_exception_only(type(e), e))[:2000])
        rec("error", "uncaught", str(e))
        flush("uncaught_exception")
    return 0


if __name__ == "__main__":
    sys.exit(main())
