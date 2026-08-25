'use strict';
// server.js — control plane for the script sandbox sidecar.
//
// The backend POSTs a script (or a zip of the whole dropped directory plus an
// entry point) and gets back a behaviour report. The sample runs in a throwaway
// working directory inside this container, which sits on an `internal: true`
// Docker network with the sinkhole as its only reachable host — so "run the
// malware" means "run it where its network goes to our fake C2 and nowhere else".
//
// Interface deliberately mirrors the other sidecars (multipart POST, JSON out) so
// the Go client and a curl test look the same as they do for /emulate and /triage.

const http = require('http');
const { spawn, execFileSync } = require('child_process');
const fs = require('fs');
const os = require('os');
const path = require('path');

const PORT = parseInt(process.env.PORT || '8094', 10);
const HARNESS = '/opt/harness/harness.js';
const PY_HARNESS = '/opt/harness/pyharness.py';
const PS_HARNESS = '/opt/harness/psharness.ps1';
const SINKHOLE = process.env.SINKHOLE_URL || 'http://sinkhole:8095';
const DEFAULT_TIMEOUT = parseInt(process.env.SANDBOX_TIMEOUT || '60', 10);
const MAX_TIMEOUT = parseInt(process.env.SANDBOX_MAX_TIMEOUT || '180', 10);
const MAX_BODY = parseInt(process.env.SANDBOX_MAX_BODY || String(256 * 1024 * 1024), 10);

// ── Minimal multipart/form-data reader ─────────────────────────────────────
// A dependency-free parser keeps the image small and the supply chain short: this
// container runs hostile code, so every npm package it does NOT have is one fewer
// thing to audit.

function parseMultipart(buf, boundary) {
  const out = { fields: {}, file: null, filename: '' };
  const delim = Buffer.from('--' + boundary);
  let pos = 0;
  while (pos < buf.length) {
    const start = buf.indexOf(delim, pos);
    if (start < 0) break;
    const headEnd = buf.indexOf('\r\n\r\n', start);
    if (headEnd < 0) break;
    const head = buf.slice(start + delim.length, headEnd).toString('utf8');
    let next = buf.indexOf(delim, headEnd);
    if (next < 0) next = buf.length;
    // Trailing CRLF belongs to the delimiter, not the payload.
    const body = buf.slice(headEnd + 4, Math.max(headEnd + 4, next - 2));
    const nameMatch = /name="([^"]*)"/.exec(head);
    const fileMatch = /filename="([^"]*)"/.exec(head);
    if (nameMatch) {
      if (fileMatch) {
        out.file = body;
        out.filename = fileMatch[1];
      } else {
        out.fields[nameMatch[1]] = body.toString('utf8').trim();
      }
    }
    pos = next;
  }
  return out;
}

function readBody(req, cb) {
  const chunks = [];
  let size = 0;
  req.on('data', (c) => {
    size += c.length;
    if (size > MAX_BODY) {
      req.destroy();
      return;
    }
    chunks.push(c);
  });
  req.on('end', () => cb(null, Buffer.concat(chunks)));
  req.on('error', (e) => cb(e));
}

// ── Language routing ───────────────────────────────────────────────────────

function detectLang(filename, data) {
  const low = (filename || '').toLowerCase();
  if (/\.(js|cjs|mjs|jsx|node)$/.test(low)) return 'node';
  if (/\.(py|pyw)$/.test(low)) return 'python';
  if (/\.(ps1|psm1)$/.test(low)) return 'powershell';
  if (/\.(vbs|vbe|wsf|js\.txt)$/.test(low)) return 'unsupported-wsh';
  // Content sniff for extension-less drops.
  const head = data.slice(0, 4096).toString('latin1');
  if (/\brequire\s*\(|module\.exports|=>|\bconst\s+\w+\s*=/.test(head)) return 'node';
  if (/^\s*(import|from|def|print\()/m.test(head)) return 'python';
  if (/\$\w+\s*=|Invoke-|Write-Host/.test(head)) return 'powershell';
  return 'node';
}

// isZip recognises the container case: the caller shipped a whole dropped folder
// so the entry script can reach the payload files it loads at runtime. Analysing
// the loader without its payload is how a sandbox reports "nothing happened".
function isZip(data) {
  return data.length > 4 && data[0] === 0x50 && data[1] === 0x4b &&
    (data[2] === 3 || data[2] === 5 || data[2] === 7);
}

// pickEntry chooses what to execute out of an unpacked directory. Order matters:
// an explicit caller choice wins, then the manifest's own declaration, then the
// conventional names, then the largest script — because a bundler's output is
// usually the biggest file in the drop.
function pickEntry(dir, hint) {
  if (hint) {
    const p = path.join(dir, hint);
    if (fs.existsSync(p) && fs.statSync(p).isFile()) return path.relative(dir, p);
  }
  const pkg = path.join(dir, 'package.json');
  if (fs.existsSync(pkg)) {
    try {
      const j = JSON.parse(fs.readFileSync(pkg, 'utf8'));
      const m = j.main || (j.scripts && j.scripts.start);
      if (m && fs.existsSync(path.join(dir, m))) return m;
    } catch (_) { /* a malformed manifest is itself unremarkable */ }
  }
  const files = [];
  (function walk(d, depth) {
    if (depth > 4) return;
    let entries = [];
    try { entries = fs.readdirSync(d, { withFileTypes: true }); } catch (_) { return; }
    for (const e of entries) {
      const full = path.join(d, e.name);
      if (e.isDirectory()) { if (e.name !== 'node_modules') walk(full, depth + 1); }
      else if (/\.(js|cjs|mjs|py)$/i.test(e.name)) {
        try { files.push({ rel: path.relative(dir, full), size: fs.statSync(full).size }); } catch (_) {}
      }
    }
  })(dir, 0);
  if (!files.length) return '';
  for (const name of ['preload.js', 'index.js', 'main.js', 'app.js', 'bootstrap.js']) {
    const hit = files.find((f) => path.basename(f.rel).toLowerCase() === name);
    if (hit) return hit.rel;
  }
  files.sort((a, b) => b.size - a.size);
  return files[0].rel;
}

// ── Run ────────────────────────────────────────────────────────────────────

// parseEnvSpec turns an operator-supplied newline-separated "NAME=value" block
// into variables for the sample's process.
//
// This is what completes an analysis of a loader keyed from OUTSIDE itself. Such a
// loader reads process.env.KEY, finds nothing, and exits in milliseconds — the
// sandbox can observe the miss but cannot invent the value. Once an analyst
// recovers it from the infected host (the parent process command line, Sysmon
// EID 1), supplying it here lets the sample decrypt its own payload for us.
function parseEnvSpec(spec) {
  const out = {};
  for (const line of String(spec || '').split(/[\r\n]+/)) {
    const t = line.trim();
    if (!t || t.startsWith('#')) continue;
    const eq = t.indexOf('=');
    if (eq <= 0) continue;
    const name = t.slice(0, eq).trim();
    // Never let a supplied variable redirect the harness itself.
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/.test(name) || name.startsWith('AH_')) continue;
    out[name] = t.slice(eq + 1);
  }
  return out;
}

// splitArgv accepts a simple quoted command line; many loaders take their key as
// an argument rather than an environment variable.
function splitArgv(spec) {
  const out = [];
  const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
  let m;
  while ((m = re.exec(String(spec || '')))) out.push(m[1] ?? m[2] ?? m[3]);
  return out.slice(0, 32);
}

function runSample(workdir, entry, lang, timeoutSec, done, extraEnv, extraArgv, preload) {
  const reportPath = path.join(workdir, '.ah-report.json');
  const env = {
    PATH: process.env.PATH,
    HOME: workdir,
    TMPDIR: workdir,
    AH_REPORT: reportPath,
    // A believable victim profile: a sample that fingerprints its host and finds
    // an obvious sandbox often exits before doing anything worth recording.
    USERNAME: 'jdoe', USER: 'jdoe', COMPUTERNAME: 'DESKTOP-4KQ81N',
    USERDOMAIN: 'WORKGROUP', NUMBER_OF_PROCESSORS: '8',
    APPDATA: 'C:\\Users\\jdoe\\AppData\\Roaming',
    LOCALAPPDATA: 'C:\\Users\\jdoe\\AppData\\Local',
    TEMP: 'C:\\Users\\jdoe\\AppData\\Local\\Temp',
    ProgramData: 'C:\\ProgramData',
    SystemRoot: 'C:\\Windows',
    NODE_OPTIONS: '',
  };
  // Operator-supplied variables win over the synthetic victim profile: they are
  // the real launcher's environment, recovered from the infected host.
  Object.assign(env, extraEnv || {});

  let cmd, args;
  if (lang === 'python') {
    cmd = 'python3';
    args = [PY_HARNESS, entry];
  } else if (lang === 'powershell') {
    cmd = 'pwsh';
    // -File runs the harness, which dot-sources the sample after installing its
    // proxies. -NonInteractive matters: a sample that calls Read-Host would
    // otherwise block until the timeout and report nothing.
    args = ['-NoProfile', '-NonInteractive', '-File', PS_HARNESS, entry];
  } else {
    cmd = 'node';
    // --require installs the harness before the sample's first statement.
    // The old-space cap stops a decompression bomb inside the sample from
    // OOM-killing the container before the report is flushed.
    // --tls-keylog dumps the session secrets. In a sandbox we control BOTH ends
    // of every TLS connection, so the captured traffic becomes decryptable —
    // something a real-world pcap almost never is. The net-analyzer already
    // accepts a keylog and decrypts with it; it simply never had one for
    // sandbox traffic.
    args = ['--require', HARNESS, '--max-old-space-size=1024',
      '--tls-keylog=' + path.join(workdir, 'tls-keys.log')];
    // A loader/payload pair is the standard shape for this family: the loader is
    // --require'd so it can install its module hook, and the payload is then the
    // entry it intercepts. Running either alone reaches nothing — the loader has
    // nothing to load, and the payload is unreadable bytecode without the hook.
    if (preload) args.push('--require', path.resolve(workdir, preload));
    args.push(entry);
  }
  if (extraArgv && extraArgv.length) args = args.concat(extraArgv);

  const started = Date.now();
  let child;
  try {
    child = spawn(cmd, args, { cwd: workdir, env, stdio: ['ignore', 'pipe', 'pipe'] });
  } catch (e) {
    return done({ error: 'spawn failed: ' + e.message });
  }

  let stdout = '', stderr = '';
  child.stdout.on('data', (d) => { if (stdout.length < 256 * 1024) stdout += d.toString('latin1'); });
  child.stderr.on('data', (d) => { if (stderr.length < 256 * 1024) stderr += d.toString('latin1'); });

  let timedOut = false;
  const killTimer = setTimeout(() => {
    timedOut = true;
    // SIGTERM first: the harness has a handler that flushes the report. SIGKILL
    // only if it does not go quietly — the periodic flush covers that case.
    try { child.kill('SIGTERM'); } catch (_) {}
    setTimeout(() => { try { child.kill('SIGKILL'); } catch (_) {} }, 3000);
  }, timeoutSec * 1000);

  child.on('close', (code, signal) => {
    clearTimeout(killTimer);
    let report = null;
    try { report = JSON.parse(fs.readFileSync(reportPath, 'utf8')); } catch (_) {}
    // Read the keylog before the workdir is cleaned up.
    let keylog = '';
    try {
      keylog = fs.readFileSync(path.join(workdir, 'tls-keys.log'), 'utf8').slice(0, 2 * 1024 * 1024);
    } catch (_) { /* no TLS in this run */ }
    if (!report) {
      report = { events: [], scripts: [], dropped: [], network: [], decrypted: [], requires: [], env_read: [], errors: ['no report produced'] };
    }
    report.entry = entry;
    report.language = lang;
    report.exit_code = code;
    report.signal = signal;
    report.timed_out = timedOut;
    report.wall_ms = Date.now() - started;
    report.tls_keylog = keylog;
    report.stdout = stdout.slice(0, 64 * 1024);
    report.stderr = stderr.slice(0, 64 * 1024);
    done(report);
  });
}

// ── Sinkhole correlation ───────────────────────────────────────────────────
// What the sample TRIED to send is only half the story; what actually reached the
// fake C2 (method, path, headers, body, TLS SNI) is the other half, and it is the
// half a detection engineer turns into a rule.

function fetchSinkhole(sessionId, cb) {
  const url = SINKHOLE + '/log?session=' + encodeURIComponent(sessionId);
  const req = http.get(url, { timeout: 5000 }, (res) => {
    let body = '';
    res.on('data', (d) => { if (body.length < 4 * 1024 * 1024) body += d; });
    res.on('end', () => {
      try { cb(JSON.parse(body)); } catch (_) { cb(null); }
    });
  });
  req.on('error', () => cb(null));
  req.on('timeout', () => { req.destroy(); cb(null); });
}

function resetSinkhole(sessionId, cb) {
  const req = http.request(SINKHOLE + '/reset?session=' + encodeURIComponent(sessionId),
    { method: 'POST', timeout: 5000 }, (res) => { res.resume(); res.on('end', cb); });
  req.on('error', () => cb());
  req.on('timeout', () => { req.destroy(); cb(); });
  req.end();
}

// ── HTTP surface ───────────────────────────────────────────────────────────

const server = http.createServer((req, res) => {
  const send = (code, obj) => {
    const body = JSON.stringify(obj);
    res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
    res.end(body);
  };

  if (req.method === 'GET' && req.url.startsWith('/health')) {
    return send(200, {
      ok: true,
      node: process.version,
      python: has('python3'),
      powershell: has('pwsh'),
      unzip: has('unzip'),
      sinkhole: SINKHOLE,
    });
  }

  if (req.method !== 'POST' || !req.url.startsWith('/run')) {
    return send(404, { error: 'not found' });
  }

  const ctype = req.headers['content-type'] || '';
  const m = /boundary=(?:"([^"]+)"|([^;]+))/.exec(ctype);
  if (!m) return send(400, { error: 'multipart/form-data with a boundary is required' });

  readBody(req, (err, buf) => {
    if (err || !buf || !buf.length) return send(400, { error: 'empty or unreadable body' });
    const parsed = parseMultipart(buf, m[1] || m[2]);
    if (!parsed.file || !parsed.file.length) return send(400, { error: 'file part is required' });

    const sessionId = (parsed.fields.session || '').replace(/[^A-Za-z0-9_-]/g, '') || String(Date.now());
    let timeout = parseInt(parsed.fields.timeout || '', 10);
    if (!Number.isFinite(timeout) || timeout <= 0) timeout = DEFAULT_TIMEOUT;
    if (timeout > MAX_TIMEOUT) timeout = MAX_TIMEOUT;

    let workdir;
    try {
      workdir = fs.mkdtempSync(path.join(os.tmpdir(), 'ah-box-'));
    } catch (e) {
      return send(500, { error: 'cannot create workdir: ' + e.message });
    }

    let entry = '';
    let lang = (parsed.fields.lang || 'auto').toLowerCase();
    try {
      if (isZip(parsed.file)) {
        const zipPath = path.join(workdir, '_bundle.zip');
        fs.writeFileSync(zipPath, parsed.file);
        // -o overwrite, -qq quiet; a zip-slip entry is neutralised by -j? No —
        // keep the tree (the loader needs its relative paths) and rely on the
        // throwaway workdir plus the unprivileged user for containment.
        try { execFileSync('unzip', ['-o', '-qq', zipPath, '-d', workdir], { timeout: 60000 }); }
        catch (e) { /* partial extraction still gives us something to run */ }
        fs.unlinkSync(zipPath);
        entry = pickEntry(workdir, parsed.fields.entry || '');
        if (!entry) { cleanup(workdir); return send(200, { error: 'no runnable script found in the bundle' }); }
        if (lang === 'auto') lang = detectLang(entry, safeHead(path.join(workdir, entry)));
      } else {
        const name = sanitizeName(parsed.filename || 'sample.js');
        entry = name;
        fs.writeFileSync(path.join(workdir, name), parsed.file);
        if (lang === 'auto') lang = detectLang(name, parsed.file);
      }
    } catch (e) {
      cleanup(workdir);
      return send(500, { error: 'staging failed: ' + e.message });
    }

    if (lang === 'unsupported-wsh') {
      cleanup(workdir);
      return send(200, {
        error: 'WSH/VBScript needs a Windows guest — use the CAPE backend for this sample',
        language: lang, entry,
      });
    }

    const extraEnv = parseEnvSpec(parsed.fields.env);
    const extraArgv = splitArgv(parsed.fields.argv);
    // Only a file that was actually staged may be preloaded.
    let preload = sanitizeRel(parsed.fields.preload);
    if (preload && !fs.existsSync(path.join(workdir, preload))) preload = '';
    resetSinkhole(sessionId, () => {
      runSample(workdir, entry, lang, timeout, (report) => {
        fetchSinkhole(sessionId, (sink) => {
          report.sinkhole = sink || { note: 'sinkhole unreachable — network capture unavailable' };
          report.session = sessionId;
          // Echo what was supplied (names only — a recovered key is sensitive and
          // belongs in the case notes, not in every report render).
          report.env_supplied = Object.keys(extraEnv);
          report.preload = preload;
          cleanup(workdir);
          send(200, report);
        });
      }, extraEnv, extraArgv, preload);
    });
  });
});

// sanitizeRel keeps a caller-supplied relative path inside the working directory.
function sanitizeRel(n) {
  const raw = String(n || '').split('\\').join('/').trim();
  if (!raw) return '';
  const norm = path.posix.normalize(raw);
  if (norm.startsWith('/') || norm.startsWith('..')) return '';
  return norm;
}

function sanitizeName(n) {
  const base = path.basename(String(n).replace(/\\/g, '/'));
  const clean = base.replace(/[^A-Za-z0-9._-]/g, '_');
  return clean && clean !== '.' && clean !== '..' ? clean : 'sample.js';
}

function safeHead(p) {
  try { return fs.readFileSync(p).slice(0, 8192); } catch (_) { return Buffer.alloc(0); }
}

function cleanup(dir) {
  try { fs.rmSync(dir, { recursive: true, force: true }); } catch (_) {}
}

function has(bin) {
  try { execFileSync('sh', ['-c', 'command -v ' + bin], { stdio: 'ignore' }); return true; }
  catch (_) { return false; }
}

server.headersTimeout = (MAX_TIMEOUT + 120) * 1000;
server.requestTimeout = (MAX_TIMEOUT + 120) * 1000;
server.listen(PORT, '0.0.0.0', () => {
  console.log('[script-sandbox] listening on ' + PORT + ', sinkhole=' + SINKHOLE);
});
