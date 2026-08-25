# psharness.ps1 — instrumentation for PowerShell samples.
#
# Same contract as harness.js and pyharness.py: run the sample for real, record
# what it does, write the report to $env:AH_REPORT as JSON with the identical
# schema, so the Go side needs no language-specific parsing.
#
# PowerShell needs its own recovery channel for the same reason JavaScript did.
# The dominant obfuscation shape here is not a string array — it is
#   IEX ([Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($blob)))
# where the file on disk contains no readable command at all. Proxying
# Invoke-Expression means the decoded stage is recorded *as it is handed to the
# engine*, which is the exact analogue of catching Debugger.scriptParsed in V8:
# the sample deobfuscates itself and we read the result.
#
# Deliberate limit: a .NET method called on an object the sample constructed
# ([Net.WebClient]::DownloadString, [Convert]::FromBase64String) cannot be
# intercepted from inside the session. Those are covered from the other side —
# every request lands on the sinkhole, which records it. There is no fake hook
# here claiming coverage the harness does not have.
#
# Everything is defined in the global scope on purpose. A proxy function is
# invoked from the sample's scope, and `$script:` inside a global function means
# the global scope anyway; mixing the two is how state silently splits in twain.

$ErrorActionPreference = 'Continue'
$ProgressPreference    = 'SilentlyContinue'

$global:AH_MAX_EVENTS = 4000
$global:AH_MAX_ARG    = 4000
$global:AH_EVENTS     = 0
$global:AH_STARTED    = Get-Date
$global:AH_FLUSHED    = $false

$global:AH_REPORT = [ordered]@{
  events      = [System.Collections.ArrayList]::new()
  scripts     = [System.Collections.ArrayList]::new()
  dropped     = [System.Collections.ArrayList]::new()
  network     = [System.Collections.ArrayList]::new()
  decrypted   = [System.Collections.ArrayList]::new()
  requires    = [System.Collections.ArrayList]::new()
  env_read    = [System.Collections.ArrayList]::new()
  env_missing = [System.Collections.ArrayList]::new()
  argv        = [System.Collections.ArrayList]::new()
  errors      = [System.Collections.ArrayList]::new()
  truncated   = $false
}

function global:AhClip([object]$v, [int]$n) {
  if ($null -eq $v) { return '' }
  $s = try { [string]$v } catch { '<unprintable>' }
  # Control bytes in a JSON string break downstream consumers more often than
  # they carry meaning.
  $s = ($s -replace '[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]', '.')
  if ($s.Length -gt $n) { $global:AH_REPORT.truncated = $true; return $s.Substring(0, $n) + '...' }
  return $s
}

function global:AhRec([string]$category, [string]$action, [object]$detail) {
  if ($global:AH_EVENTS -ge $global:AH_MAX_EVENTS) { $global:AH_REPORT.truncated = $true; return }
  $global:AH_EVENTS++
  [void]$global:AH_REPORT.events.Add([ordered]@{
    seq      = $global:AH_EVENTS
    t        = [int]((Get-Date) - $global:AH_STARTED).TotalMilliseconds
    category = $category
    action   = $action
    detail   = (AhClip $detail $global:AH_MAX_ARG)
  })
}

function global:AhSha256([byte[]]$bytes) {
  $sha = [System.Security.Cryptography.SHA256]::Create()
  try { return (-join ($sha.ComputeHash($bytes) | ForEach-Object { $_.ToString('x2') })) }
  finally { $sha.Dispose() }
}

# AhScript stores recovered source. dynamic=$true marks code that did not exist
# on disk — the thing static review cannot see.
function global:AhScript([string]$code, [bool]$dynamic, [string]$origin) {
  if ([string]::IsNullOrEmpty($code)) { return }
  if ($global:AH_REPORT.scripts.Count -ge 400) { $global:AH_REPORT.truncated = $true; return }
  $bytes = [Text.Encoding]::UTF8.GetBytes($code)
  [void]$global:AH_REPORT.scripts.Add([ordered]@{
    url     = $origin
    dynamic = $dynamic
    length  = $bytes.Length
    sha256  = (AhSha256 $bytes)
    source  = (AhClip $code 65536)
  })
}

function global:AhNet([string]$target) {
  if ([string]::IsNullOrWhiteSpace($target)) { return }
  if ($global:AH_REPORT.network.Count -ge 500) { return }
  if ($global:AH_REPORT.network -notcontains $target) { [void]$global:AH_REPORT.network.Add($target) }
}

function global:AhDrop([string]$p, [object]$content) {
  if ($global:AH_REPORT.dropped.Count -ge 60) { $global:AH_REPORT.truncated = $true; return }
  $s = if ($null -eq $content) { '' } else { [string]$content }
  $bytes = [Text.Encoding]::UTF8.GetBytes($s)
  $text  = AhClip $s 4096
  [void]$global:AH_REPORT.dropped.Add([ordered]@{
    path    = $p
    size    = $bytes.Length
    sha256  = (AhSha256 $bytes)
    preview = $text.Substring(0, [Math]::Min(200, $text.Length))
  })
}

# AhUrls pulls anything URL-shaped out of an argument list, so a proxy records the
# target even when it was passed positionally or inside a larger string.
function global:AhUrls([object[]]$items) {
  foreach ($i in $items) {
    $s = [string]$i
    foreach ($m in [regex]::Matches($s, '(?i)\b(?:https?|ftp)://[^\s"'']+')) { AhNet $m.Value }
  }
}

# ── Base64 recovery ─────────────────────────────────────────────────────────
# Every base64 blob the sample carries or builds is a candidate payload. Decoding
# is cheap and turns an opaque string into evidence; a blob that does not decode
# to text is still reported by size and hash rather than discarded.
function global:AhTryB64([string]$s, [string]$origin) {
  if ([string]::IsNullOrEmpty($s) -or $s.Length -lt 24) { return }
  if ($s -notmatch '^[A-Za-z0-9+/=\s]+$') { return }
  $compact = ($s -replace '\s', '')
  if ($compact.Length -lt 24 -or ($compact.Length % 4) -ne 0) { return }
  $raw = try { [Convert]::FromBase64String($compact) } catch { $null }
  if ($null -eq $raw -or $raw.Length -lt 16) { return }
  if ($global:AH_REPORT.decrypted.Count -ge 30) { return }
  # UTF-16LE is what -EncodedCommand uses; try it before UTF-8.
  $text = $null
  foreach ($enc in @([Text.Encoding]::Unicode, [Text.Encoding]::UTF8)) {
    $t = try { $enc.GetString($raw) } catch { $null }
    if ($t -and $t.Length -gt 0) {
      $junk = ($t -replace '[\x20-\x7e\r\n\t]', '').Length
      if ($junk -lt ($t.Length * 0.15)) { $text = $t; break }
    }
  }
  [void]$global:AH_REPORT.decrypted.Add([ordered]@{
    via       = $origin
    algorithm = 'base64'
    size      = $raw.Length
    sha256    = (AhSha256 $raw)
    preview   = (AhClip $(if ($text) { $text } else { '<binary>' }) 2000)
  })
  if ($text) { AhScript $text $true "base64:$origin" }
}

# ── Static AST pass ─────────────────────────────────────────────────────────
# Runs before the sample does, so a Windows-only sample that dies on its first
# line under Linux pwsh still yields its command surface — which is most of what
# an analyst needs from it.
function global:AhScanAst([string]$file) {
  $tokens = $null; $errs = $null
  $ast = try {
    [System.Management.Automation.Language.Parser]::ParseFile($file, [ref]$tokens, [ref]$errs)
  } catch { $null }
  if ($null -eq $ast) { [void]$global:AH_REPORT.errors.Add('AST parse failed'); return }
  if ($errs -and $errs.Count -gt 0) {
    AhRec 'code' 'parse_errors' "$($errs.Count) parse error(s) — the file may be partly obfuscated"
  }

  $cmds = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.CommandAst] }, $true)
  $seen = @{}
  foreach ($c in $cmds) {
    $name = try { $c.GetCommandName() } catch { $null }
    if ($name -and -not $seen.ContainsKey($name)) {
      $seen[$name] = $true
      if ($global:AH_REPORT.requires.Count -lt 500) {
        [void]$global:AH_REPORT.requires.Add([ordered]@{ module = $name; from = 'static' })
      }
    }
  }
  if ($seen.Count -gt 0) { AhRec 'code' 'static_commands' (($seen.Keys | Sort-Object) -join ', ') }

  $strs = $ast.FindAll({ param($n) $n -is [System.Management.Automation.Language.StringConstantExpressionAst] }, $true)
  foreach ($s in $strs) {
    AhTryB64 $s.Value 'static-literal'
    AhUrls @($s.Value)
  }
}

# ── Proxy functions ─────────────────────────────────────────────────────────
# A function shadows a cmdlet of the same name, so defining these globally
# instruments the sample without touching it. Each records, then forwards to the
# real cmdlet by its fully qualified name so behaviour stays real.
#
# None of them declare [CmdletBinding()] or a param block: that would disable
# $args, and `@args` is the only pass-through that preserves the caller's named
# parameters exactly as written.

function global:Invoke-Expression {
  $code = if ($args.Count -gt 0) { [string]$args[0] } else { ($input | Out-String) }
  AhRec 'code' 'invoke-expression' $code
  AhScript $code $true 'Invoke-Expression'
  AhTryB64 $code 'iex-argument'
  AhUrls @($code)
  Microsoft.PowerShell.Utility\Invoke-Expression $code
}

function global:Invoke-WebRequest {
  AhRec 'network' 'invoke-webrequest' ($args -join ' ')
  AhUrls $args
  Microsoft.PowerShell.Utility\Invoke-WebRequest @args
}

function global:Invoke-RestMethod {
  AhRec 'network' 'invoke-restmethod' ($args -join ' ')
  AhUrls $args
  Microsoft.PowerShell.Utility\Invoke-RestMethod @args
}

function global:Start-BitsTransfer {
  AhRec 'network' 'start-bitstransfer' ($args -join ' ')
  AhUrls $args
}

function global:Start-Process {
  AhRec 'process' 'start-process' ($args -join ' ')
  AhUrls $args
  # Not forwarded: the target is a Windows path that does not exist on this
  # image, and spawning it would hand the sample a second, uninstrumented process.
}

function global:New-Object {
  $t = [string]$args[0]
  $cat = if ($t -match '(?i)webclient|httpclient|socket|webrequest|smtp') { 'network' }
         elseif ($t -match '(?i)crypto|aes|rijndael|tripledes|rc2|md5|sha') { 'crypto' }
         elseif ($t -match '(?i)comobject|wscript|shell.application|schedule') { 'process' }
         else { 'code' }
  AhRec $cat 'new-object' ($args -join ' ')
  AhUrls $args
  Microsoft.PowerShell.Utility\New-Object @args
}

function global:Add-Type {
  # Inline C# is how a script reaches a Win32 API it has no cmdlet for, so the
  # source passed here IS the payload.
  $src = (@($args) | Where-Object { $_ -is [string] -and $_.Length -gt 40 }) -join "`n"
  AhRec 'code' 'add-type' $src
  if ($src) { AhScript $src $true 'Add-Type' }
}

# AhPathArg finds the destination in a writer cmdlet's arguments: -Path/-LiteralPath
# if named, otherwise the first positional value.
function global:AhPathArg([object[]]$a) {
  for ($i = 0; $i -lt $a.Count; $i++) {
    $s = [string]$a[$i]
    if ($s -match '(?i)^-(Path|LiteralPath|FilePath)$' -and ($i + 1) -lt $a.Count) { return [string]$a[$i + 1] }
  }
  foreach ($x in $a) { $s = [string]$x; if ($s -and -not $s.StartsWith('-')) { return $s } }
  return '<unknown>'
}

# AhValueArg returns the content a writer cmdlet was given by name (-Value or
# -InputObject). Without it a drop written as `Out-File -InputObject $payload`
# records a path with zero bytes, which reads as "wrote nothing".
function global:AhValueArg([object[]]$a) {
  for ($i = 0; $i -lt $a.Count; $i++) {
    $s = [string]$a[$i]
    if ($s -match '(?i)^-(Value|InputObject|Encoding)$' -and ($i + 1) -lt $a.Count) {
      if ($s -match '(?i)^-Encoding$') { continue }
      return $a[$i + 1]
    }
  }
  return $null
}

function global:Out-File {
  $p = AhPathArg $args
  $v = AhValueArg $args
  if ($null -eq $v) { $v = ($input | Out-String) }
  AhRec 'filesystem' 'out-file' $p
  AhDrop $p $v
}
function global:Set-Content {
  $p = AhPathArg $args
  $v = AhValueArg $args
  if ($null -eq $v) { $v = ($input | Out-String) }
  AhRec 'filesystem' 'set-content' ($args -join ' ')
  AhDrop $p $v
}
function global:Add-Content {
  $p = AhPathArg $args
  $v = AhValueArg $args
  if ($null -eq $v) { $v = ($input | Out-String) }
  AhRec 'filesystem' 'add-content' ($args -join ' ')
  AhDrop $p $v
}

function global:Set-ItemProperty   { AhRec 'filesystem' 'set-itemproperty' ($args -join ' ') }
function global:New-ItemProperty   { AhRec 'filesystem' 'new-itemproperty' ($args -join ' ') }
function global:Remove-Item        { AhRec 'filesystem' 'remove-item' ($args -join ' ') }
function global:Register-ScheduledTask { AhRec 'process' 'register-scheduledtask' ($args -join ' ') }
function global:New-ScheduledTask      { AhRec 'process' 'new-scheduledtask' ($args -join ' ') }
function global:Get-WmiObject      { AhRec 'recon' 'get-wmiobject' ($args -join ' ') }
function global:Get-CimInstance    { AhRec 'recon' 'get-ciminstance' ($args -join ' ') }
function global:Get-ComputerInfo   { AhRec 'recon' 'get-computerinfo' ($args -join ' ') }
function global:Set-MpPreference   { AhRec 'process' 'set-mppreference' ($args -join ' ') }
function global:Add-MpPreference   { AhRec 'process' 'add-mppreference' ($args -join ' ') }

# ── Victim profile ──────────────────────────────────────────────────────────
# A sample that checks where it landed must see a plausible Windows host, or it
# exits before doing anything worth recording.
if (-not $env:COMPUTERNAME) { $env:COMPUTERNAME = 'DESKTOP-7K2M4XQ' }
if (-not $env:USERNAME)     { $env:USERNAME     = 'jdoe' }
if (-not $env:USERDOMAIN)   { $env:USERDOMAIN   = 'WORKGROUP' }
if (-not $env:APPDATA)      { $env:APPDATA      = 'C:\Users\jdoe\AppData\Roaming' }
if (-not $env:LOCALAPPDATA) { $env:LOCALAPPDATA = 'C:\Users\jdoe\AppData\Local' }
if (-not $env:TEMP)         { $env:TEMP         = 'C:\Users\jdoe\AppData\Local\Temp' }

# ── Report writing ──────────────────────────────────────────────────────────
# WriteReport is callable at any time. It is called once the static pass is done
# so that even a hard kill leaves the file inventory behind, and again when the
# sample finishes.
function global:AhWriteReport() {
  $out = $env:AH_REPORT
  if (-not $out) { return }
  try {
    $json = $global:AH_REPORT | ConvertTo-Json -Depth 8 -Compress
    [IO.File]::WriteAllText($out, $json, [Text.UTF8Encoding]::new($false))
  } catch {
    try { [IO.File]::WriteAllText($out, '{"errors":["report serialisation failed"],"events":[]}') } catch {}
  }
}

function global:AhFlush([string]$reason) {
  if ($global:AH_FLUSHED) { return }
  $global:AH_FLUSHED = $true
  $global:AH_REPORT['stop_reason'] = $reason
  $global:AH_REPORT['duration_ms'] = [int]((Get-Date) - $global:AH_STARTED).TotalMilliseconds
  AhWriteReport
}

# The server sends SIGTERM before SIGKILL on timeout. Catching it is what turns a
# timed-out run from "no report produced" into a partial report, which for a
# sample that deliberately sleeps is the only report there will ever be.
try {
  $null = [System.Runtime.InteropServices.PosixSignalRegistration]::Create(
    [System.Runtime.InteropServices.PosixSignal]::SIGTERM,
    { param($ctx) $ctx.Cancel = $true; AhFlush 'sigterm'; [Environment]::Exit(143) })
} catch {
  [void]$global:AH_REPORT.errors.Add('SIGTERM handler unavailable: ' + $_.Exception.Message)
}

# ── Run ─────────────────────────────────────────────────────────────────────
$entry = if ($args.Count -gt 0) { [string]$args[0] } else { $env:AH_ENTRY }
foreach ($a in $args) { [void]$global:AH_REPORT.argv.Add([string]$a) }

if (-not $entry -or -not (Test-Path -LiteralPath $entry)) {
  [void]$global:AH_REPORT.errors.Add("entry not found: $entry")
  AhFlush 'no-entry'
  exit 2
}
# Dot-sourcing a bare file name makes PowerShell look for a *command* by that
# name, not a script in the current directory, and the sample dies before its
# first statement. The path has to be absolute.
$entry = (Resolve-Path -LiteralPath $entry).Path

AhScanAst $entry
AhWriteReport

try {
  . $entry
  AhFlush 'completed'
} catch {
  [void]$global:AH_REPORT.errors.Add('uncaught: ' + (AhClip $_.Exception.Message 2000))
  AhRec 'code' 'terminated' $_.Exception.Message
  AhFlush 'exception'
}
