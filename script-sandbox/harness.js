'use strict';
// harness.js — instrumentation preloaded into the sample's Node process via
// `--require`. It runs BEFORE the sample, so every hook is in place by the time
// the first line of untrusted code executes.
//
// Two independent recovery channels, because each defeats a different trick:
//
//   1. V8 Inspector (`Debugger.scriptParsed`). Monkey-patching cannot intercept a
//      direct `eval()` — the language forbids it. The inspector sees every script
//      V8 compiles, including the ones eval/`new Function`/`vm` produce, so a
//      loader that decrypts its payload and evals it hands us the plaintext by
//      running normally. This is what makes an obfuscated stager readable without
//      un-obfuscating anything by hand.
//   2. API hooks. The inspector says what code EXISTS; the hooks say what it DID —
//      which command it spawned, which host it dialled, what it wrote to disk, and
//      what came out of a decipher.
//
// Dangerous calls are logged and neutered, never performed: exec returns a
// plausible empty result instead of running, writes go to the capture store
// instead of the filesystem. The sample keeps running (a stager that thinks its
// drop failed usually retries or reveals a fallback C2), but nothing escapes.

const inspector = require('inspector');
const Module = require('module');
const path = require('path');
const fs = require('fs');

const OUT = process.env.AH_REPORT || '/tmp/ah-report.json';
const MAX_EVENTS = intEnv('AH_MAX_EVENTS', 4000);
const MAX_SCRIPTS = intEnv('AH_MAX_SCRIPTS', 400);
const MAX_SCRIPT_BYTES = intEnv('AH_MAX_SCRIPT_BYTES', 512 * 1024);
const MAX_ARG = 2048;
const MAX_BLOB = 256 * 1024;

function intEnv(name, def) {
  const v = parseInt(process.env[name] || '', 10);
  return Number.isFinite(v) && v > 0 ? v : def;
}

const REPORT = {
  events: [],        // ordered behaviour log
  scripts: [],       // recovered source (incl. eval/Function/vm)
  dropped: [],       // files the sample tried to write
  network: [],       // connect/request targets
  decrypted: [],     // cipher output — the packed payload in the clear
  requires: [],      // module graph the sample pulled in
  env_read: [],      // environment recon
  env_missing: [],   // read but NOT SET — the launcher's secrets the drop needs
  argv: [],          // command line the sample was given
  errors: [],
  truncated: false,
};

// ── Recording primitives ───────────────────────────────────────────────────

let eventCount = 0;
function rec(category, action, detail) {
  if (eventCount >= MAX_EVENTS) {
    REPORT.truncated = true;
    return;
  }
  eventCount++;
  REPORT.events.push({
    seq: eventCount,
    t: Math.round(process.uptime() * 1000),
    category,
    action,
    detail: detail === undefined ? '' : clip(detail, MAX_ARG),
  });
}

// clip renders any argument as a bounded, JSON-safe string. Untrusted values are
// frequently huge Buffers or objects with circular references, and a harness that
// throws while logging would hide the very call it was there to record.
function clip(v, max) {
  let s;
  try {
    if (typeof v === 'string') s = v;
    else if (Buffer.isBuffer(v)) s = '<Buffer ' + v.length + '> ' + v.toString('latin1');
    else if (v instanceof Error) s = v.name + ': ' + v.message;
    else if (typeof v === 'function') s = '<function ' + (v.name || 'anonymous') + '>';
    else s = JSON.stringify(v, safeReplacer());
  } catch (e) {
    try { s = String(v); } catch (_) { s = '<unrepresentable>'; }
  }
  if (s === undefined) s = String(v);
  // Control characters make the report unreadable and can break downstream
  // renderers; keep the bytes visible but inert.
  s = s.replace(/[\x00-\x1f\x7f]/g, '.');
  return s.length > max ? s.slice(0, max) + '…[+' + (s.length - max) + ']' : s;
}

function safeReplacer() {
  const seen = new WeakSet();
  return function (key, value) {
    if (typeof value === 'object' && value !== null) {
      if (seen.has(value)) return '<circular>';
      seen.add(value);
    }
    if (Buffer.isBuffer(value)) return '<Buffer ' + value.length + '>';
    return value;
  };
}

function argList(args) {
  return Array.prototype.slice.call(args, 0, 4).map((a) => clip(a, 512)).join(', ');
}

// override installs a hook as an OWN property of the shim.
//
// Plain assignment is not safe here: several built-ins expose non-writable
// members (`crypto.createDecipher` is one), and under 'use strict' assigning
// through the prototype chain throws — which killed the whole run at the first
// hooked module instead of losing one hook. defineProperty sets an own property
// regardless of the prototype's descriptor, and the try/catch means a member that
// still refuses is skipped with a note rather than aborting instrumentation.
function override(obj, name, fn) {
  try {
    Object.defineProperty(obj, name, {
      value: fn, writable: true, configurable: true, enumerable: true,
    });
    return true;
  } catch (e) {
    REPORT.errors.push('cannot hook ' + name + ': ' + e.message);
    return false;
  }
}

// ── Channel 1: V8 Inspector — recover every compiled script ─────────────────
// A loader that decrypts its payload and hands it to eval() has, at that moment,
// produced plaintext inside V8. scriptParsed fires for it exactly like it does
// for a file on disk, so the payload arrives here already decrypted.

function startInspector() {
  let session;
  try {
    session = new inspector.Session();
    session.connect();
  } catch (e) {
    REPORT.errors.push('inspector unavailable: ' + e.message);
    return;
  }

  session.on('Debugger.scriptParsed', ({ params }) => {
    const url = params.url || '';
    // node: internals and the harness itself are not findings.
    if (url.startsWith('node:') || url.includes('/opt/harness/')) return;
    if (REPORT.scripts.length >= MAX_SCRIPTS) {
      REPORT.truncated = true;
      return;
    }
    // A script with no URL was produced at runtime — eval, `new Function`, or a
    // vm compile. That is the interesting case, so mark it as such.
    const dynamic = !url;
    session.post('Debugger.getScriptSource', { scriptId: params.scriptId }, (err, res) => {
      if (err || !res || typeof res.scriptSource !== 'string') return;
      const src = res.scriptSource;
      // Trivial fragments are wrappers, not payloads.
      if (dynamic && src.length < 24) return;
      REPORT.scripts.push({
        url: url || '<runtime-generated>',
        dynamic,
        length: src.length,
        sha256: sha256(src),
        source: src.length > MAX_SCRIPT_BYTES ? src.slice(0, MAX_SCRIPT_BYTES) : src,
        truncated: src.length > MAX_SCRIPT_BYTES,
      });
      if (dynamic) rec('code', 'runtime_code_compiled', src.length + ' bytes, sha256=' + sha256(src).slice(0, 16));
    });
  });

  try {
    session.post('Debugger.enable');
    // Runtime domain surfaces console output the sample produces, which stagers
    // often leave enabled by accident.
    session.post('Runtime.enable');
    session.on('Runtime.consoleAPICalled', ({ params }) => {
      const text = (params.args || []).map((a) => a.value !== undefined ? a.value : a.description).join(' ');
      rec('console', params.type || 'log', text);
    });
  } catch (e) {
    REPORT.errors.push('inspector enable failed: ' + e.message);
  }
}

function sha256(s) {
  // Use the real crypto module captured before hooks are installed.
  return realCrypto.createHash('sha256').update(s).digest('hex');
}

// Captured up-front: the hooks below replace what `require('crypto')` returns,
// and the harness must keep a clean reference for its own hashing.
const realCrypto = require('crypto');

// ── Channel 2: API hooks ───────────────────────────────────────────────────

const realLoad = Module._load;

Module._load = function (request, parent, isMain) {
  const from = parent && parent.filename ? path.basename(parent.filename) : '?';
  if (REPORT.requires.length < 500 && !REPORT.requires.some((r) => r.module === request)) {
    REPORT.requires.push({ module: request, from });
  }
  rec('require', request, 'from ' + from);

  const real = realLoad.apply(this, arguments);
  switch (request) {
    case 'child_process': return wrapChildProcess(real);
    case 'fs': return wrapFs(real);
    case 'fs/promises': return wrapFsPromises(real);
    case 'net': return wrapNet(real);
    case 'dns': return wrapDns(real);
    case 'http': case 'https': return wrapHttp(real, request);
    case 'crypto': return wrapCrypto(real);
    case 'vm': return wrapVm(real);
    default: return real;
  }
};

// child_process: the single most consequential module a stager touches. Every
// entry point is logged with its full command line and then NOT run — the command
// is the finding, executing it would be the compromise.
function wrapChildProcess(real) {
  const shim = Object.create(real);
  const fakeResult = { pid: 0, stdout: '', stderr: '', status: 0, signal: null, output: ['', '', ''] };

  for (const name of ['exec', 'execFile', 'spawn', 'fork']) {
    override(shim, name, function (...args) {
      rec('process', name, argList(args));
      const cb = args.find((a) => typeof a === 'function');
      if (cb) setImmediate(() => cb(null, '', ''));
      return fakeChild();
    });
  }
  for (const name of ['execSync', 'execFileSync', 'spawnSync']) {
    override(shim, name, function (...args) {
      rec('process', name, argList(args));
      return name === 'spawnSync' ? fakeResult : Buffer.from('');
    });
  }
  return shim;
}

function fakeChild() {
  const { EventEmitter } = require('events');
  const child = new EventEmitter();
  child.pid = 0;
  child.stdout = new EventEmitter();
  child.stderr = new EventEmitter();
  child.stdin = { write() {}, end() {}, on() {} };
  child.kill = () => true;
  child.unref = () => child;
  setImmediate(() => { child.emit('close', 0); child.emit('exit', 0); });
  return child;
}

// fs: reads pass through (a loader must be able to read its own payload — that is
// how we reach the interesting code), writes are captured instead of performed.
function wrapFs(real) {
  const shim = Object.create(real);

  const captureWrite = (fnName) => function (file, data, ...rest) {
    recordDrop(file, data, fnName);
    const cb = rest.find((a) => typeof a === 'function');
    if (cb) setImmediate(() => cb(null));
    return undefined;
  };
  for (const name of ['writeFile', 'writeFileSync', 'appendFile', 'appendFileSync']) {
    override(shim, name, captureWrite(name));
  }
  for (const name of ['unlink', 'unlinkSync', 'rm', 'rmSync', 'rename', 'renameSync', 'chmod', 'chmodSync']) {
    override(shim, name, function (...args) {
      rec('filesystem', name, argList(args));
      const cb = args.find((a) => typeof a === 'function');
      if (cb) setImmediate(() => cb(null));
    });
  }
  for (const name of ['readFile', 'readFileSync', 'createReadStream', 'readdir', 'readdirSync', 'existsSync', 'statSync']) {
    if (typeof real[name] !== 'function') continue;
    override(shim, name, function (...args) {
      rec('filesystem', name, clip(args[0], 512));
      return real[name].apply(real, args);
    });
  }
  return shim;
}

function wrapFsPromises(real) {
  const shim = Object.create(real);
  for (const name of ['writeFile', 'appendFile']) {
    override(shim, name, async function (file, data) { recordDrop(file, data, name); });
  }
  for (const name of ['unlink', 'rm', 'rename', 'chmod']) {
    override(shim, name, async function (...args) { rec('filesystem', name, argList(args)); });
  }
  return shim;
}

function recordDrop(file, data, via) {
  const name = clip(file, 512);
  const buf = Buffer.isBuffer(data) ? data : Buffer.from(String(data == null ? '' : data), 'utf8');
  rec('filesystem', via, name + ' (' + buf.length + ' bytes)');
  if (REPORT.dropped.length >= 60) { REPORT.truncated = true; return; }
  REPORT.dropped.push({
    path: name,
    size: buf.length,
    sha256: realCrypto.createHash('sha256').update(buf).digest('hex'),
    // The dropped bytes ARE the next stage; ship them back so the platform can
    // analyse them as their own sample.
    b64: buf.length <= MAX_BLOB ? buf.toString('base64') : '',
    preview: clip(buf.slice(0, 512).toString('latin1'), 512),
  });
}

function wrapNet(real) {
  const shim = Object.create(real);
  const hook = function (...args) {
    rec('network', 'tcp_connect', argList(args));
    noteTarget(args[0]);
    return real.createConnection.apply(real, args);
  };
  override(shim, 'connect', hook);
  override(shim, 'createConnection', hook);
  return shim;
}

function wrapDns(real) {
  const shim = Object.create(real);
  for (const name of ['lookup', 'resolve', 'resolve4', 'resolveTxt']) {
    if (typeof real[name] !== 'function') continue;
    override(shim, name, function (...args) {
      rec('network', 'dns_' + name, clip(args[0], 256));
      noteTarget(args[0]);
      return real[name].apply(real, args);
    });
  }
  return shim;
}

function wrapHttp(real, scheme) {
  const shim = Object.create(real);
  for (const name of ['request', 'get']) {
    if (typeof real[name] !== 'function') continue;
    override(shim, name, function (...args) {
      rec('network', scheme + '_' + name, argList(args));
      noteTarget(args[0]);
      // The sinkhole answers with a self-signed certificate. Refusing it would
      // hide the request body and the beacon cadence, which are the evidence.
      if (args[0] && typeof args[0] === 'object') args[0].rejectUnauthorized = false;
      return real[name].apply(real, args);
    });
  }
  return shim;
}

function noteTarget(t) {
  let s = '';
  if (typeof t === 'string') s = t;
  else if (t && typeof t === 'object') {
    s = (t.protocol || '') + (t.hostname || t.host || '') + (t.port ? ':' + t.port : '') + (t.path || '');
  }
  s = clip(s, 512);
  if (s && !REPORT.network.includes(s)) REPORT.network.push(s);
}

// crypto: a packer's decipher output is the unpacked payload. Capturing it turns
// "high entropy blob" into readable code without touching the packer's algorithm.
function wrapCrypto(real) {
  const shim = Object.create(real);
  for (const name of ['createDecipheriv', 'createDecipher', 'createCipheriv']) {
    if (typeof real[name] !== 'function') continue;
    override(shim, name, function (algo, key, iv) {
      rec('crypto', name, 'algo=' + clip(algo, 64) + ' key=' + keyPreview(key) + ' iv=' + keyPreview(iv));
      const c = real[name].apply(real, arguments);
      return captureCipherStream(c, String(algo), name);
    });
  }
  return shim;
}

function keyPreview(k) {
  if (k == null) return '-';
  const b = Buffer.isBuffer(k) ? k : Buffer.from(String(k), 'utf8');
  return b.toString('hex').slice(0, 64) + (b.length > 32 ? '…' : '') + ' (' + b.length + 'B)';
}

// captureCipherStream tees a cipher's output. `update`/`final` are the only ways
// bytes leave it, so wrapping both catches the whole plaintext regardless of how
// the caller chunks it.
function captureCipherStream(cipher, algo, via) {
  const chunks = [];
  let total = 0;
  const take = (out) => {
    if (!out || total >= MAX_BLOB) return out;
    const b = Buffer.isBuffer(out) ? out : Buffer.from(String(out), 'utf8');
    chunks.push(b);
    total += b.length;
    return out;
  };
  const realUpdate = cipher.update.bind(cipher);
  const realFinal = cipher.final.bind(cipher);
  override(cipher, 'update', function (...a) { return take(realUpdate(...a)); });
  override(cipher, 'final', function (...a) {
    const out = take(realFinal(...a));
    flushCipher(chunks, total, algo, via);
    return out;
  });
  return cipher;
}

function flushCipher(chunks, total, algo, via) {
  if (!chunks.length || REPORT.decrypted.length >= 30) return;
  const buf = Buffer.concat(chunks).slice(0, MAX_BLOB);
  REPORT.decrypted.push({
    via,
    algorithm: algo,
    size: total,
    sha256: realCrypto.createHash('sha256').update(buf).digest('hex'),
    b64: buf.toString('base64'),
    preview: clip(buf.slice(0, 1024).toString('latin1'), 1024),
  });
  rec('crypto', 'plaintext_recovered', total + ' bytes via ' + via + ' (' + algo + ')');
}

function wrapVm(real) {
  const shim = Object.create(real);
  for (const name of ['runInThisContext', 'runInNewContext', 'runInContext', 'compileFunction']) {
    if (typeof real[name] !== 'function') continue;
    override(shim, name, function (code, ...rest) {
      rec('code', 'vm.' + name, clip(code, 1024));
      return real[name].apply(real, [code, ...rest]);
    });
  }
  return shim;
}

// `new Function(body)` is the other runtime-compile path. The inspector already
// records the compiled source; this hook records the CALL, so the report shows the
// sample chose to build code at runtime rather than merely that code existed.
const RealFunction = global.Function;
function HookedFunction(...args) {
  if (args.length) rec('code', 'new Function', clip(args[args.length - 1], 1024));
  return RealFunction.apply(this, args);
}
HookedFunction.prototype = RealFunction.prototype;
try {
  global.Function = new Proxy(RealFunction, {
    apply: (t, thisArg, args) => HookedFunction.apply(thisArg, args),
    construct: (t, args) => {
      if (args.length) rec('code', 'new Function', clip(args[args.length - 1], 1024));
      return Reflect.construct(t, args);
    },
  });
} catch (e) {
  REPORT.errors.push('Function hook failed: ' + e.message);
}

// ── Victim profile ─────────────────────────────────────────────────────────
// Windows malware written in Node routinely opens with `if (process.platform !==
// 'win32') return`. On a Linux sandbox that check ends the run in milliseconds
// with a clean exit code, which reads as "the sample did nothing" when what
// actually happened is "the sample noticed". Presenting a Windows host is what
// gets the payload to unpack itself.
//
// Order matters: `fs` and `path` were required at the top of this file, so their
// internal path handling is already bound to POSIX semantics and the harness can
// still write its own report. Only code loaded AFTER this point sees Windows.
const FAKE_PLATFORM = process.env.AH_PLATFORM || 'win32';
if (FAKE_PLATFORM !== 'off') {
  const spoofed = {
    platform: FAKE_PLATFORM,
    arch: process.env.AH_ARCH || 'x64',
  };
  for (const [k, v] of Object.entries(spoofed)) {
    try {
      Object.defineProperty(process, k, { value: v, writable: false, configurable: true });
    } catch (e) {
      REPORT.errors.push('cannot spoof process.' + k + ': ' + e.message);
    }
  }
  const osReal = require('os');
  const osFake = {
    platform: () => FAKE_PLATFORM,
    type: () => 'Windows_NT',
    release: () => '10.0.19045',
    arch: () => spoofed.arch,
    hostname: () => process.env.COMPUTERNAME || 'DESKTOP-4KQ81N',
    homedir: () => 'C:\\Users\\jdoe',
    tmpdir: () => 'C:\\Users\\jdoe\\AppData\\Local\\Temp',
    userInfo: () => ({ username: 'jdoe', uid: -1, gid: -1, shell: null, homedir: 'C:\\Users\\jdoe' }),
    totalmem: () => 17179869184,
    cpus: () => new Array(8).fill({ model: 'AMD Ryzen 7 5800X 8-Core Processor', speed: 3800 }),
  };
  for (const [k, fn] of Object.entries(osFake)) {
    override(osReal, k, function (...a) {
      rec('recon', 'os.' + k, '');
      return fn(...a);
    });
  }
}

// Environment recon: which secrets/paths the sample went looking for — and,
// crucially, which of them were NOT SET.
//
// A loader keyed from outside itself (`Buffer.from(process.env.KEY,'hex')`) is a
// dead end in any sandbox that does not have the launcher: the read returns
// undefined, the decrypt throws or yields garbage, and the run ends in
// milliseconds looking like "the sample did nothing". Recording the MISS turns
// that dead end into an actionable instruction — name the variable, and an
// analyst can recover it from the infected host (parent process command line,
// Sysmon EID 1) and re-detonate with it supplied.
try {
  const realEnv = process.env;
  process.env = new Proxy(realEnv, {
    get(target, prop) {
      if (typeof prop === 'string' && !prop.startsWith('AH_')) {
        if (!REPORT.env_read.includes(prop)) REPORT.env_read.push(prop);
        const val = target[prop];
        if ((val === undefined || val === '') && !REPORT.env_missing.includes(prop)) {
          REPORT.env_missing.push(prop);
          rec('recon', 'env_miss', prop + ' was read but is not set in this environment');
        }
      }
      return target[prop];
    },
  });
} catch (e) {
  REPORT.errors.push('env hook failed: ' + e.message);
}

// ── Result flushing ────────────────────────────────────────────────────────
// The report must survive a timeout kill and a crash: a sample that hangs after
// beaconing has already produced the evidence, and losing it to SIGTERM would
// throw away the whole run.

let flushed = false;
function flush(reason) {
  try {
    REPORT.stop_reason = reason;
    REPORT.duration_ms = Math.round(process.uptime() * 1000);
    fs.writeFileSync(OUT, JSON.stringify(REPORT));
    flushed = true;
  } catch (e) {
    try { fs.writeFileSync(OUT, JSON.stringify({ errors: ['flush failed: ' + e.message], events: [] })); } catch (_) {}
  }
}

process.on('exit', () => { if (!flushed) flush('exited'); });
for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) {
  process.on(sig, () => { flush('killed:' + sig); process.exit(0); });
}
// A stager that throws early (a missing native module, a failed probe) still has
// its real behaviour further down: swallowing the exception and letting the loop
// continue is what turns "crashed at line 3" into a complete behaviour trace.
// Bounded, so a sample that throws in a tight loop cannot spin for the whole
// timeout budget producing nothing.
const MAX_UNCAUGHT = intEnv('AH_MAX_UNCAUGHT', 25);
let uncaught = 0;
process.on('uncaughtException', (e) => {
  uncaught++;
  REPORT.errors.push('uncaught: ' + (e && e.stack ? e.stack : String(e)).slice(0, 2000));
  rec('error', 'uncaughtException', e && e.message);
  if (uncaught >= MAX_UNCAUGHT) {
    flush('uncaught_exception_limit');
    process.exit(0);
  }
});
process.on('unhandledRejection', (e) => {
  REPORT.errors.push('unhandled rejection: ' + clip(e, 1000));
});

// A periodic flush means even a hard SIGKILL (out-of-memory, container stop)
// leaves the evidence gathered so far on disk.
const timer = setInterval(() => flush('running'), 2000);
if (timer.unref) timer.unref();

startInspector();
REPORT.argv = process.argv.slice(1);
rec('harness', 'ready', 'node ' + process.version);
