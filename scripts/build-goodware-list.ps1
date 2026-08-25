<#
.SYNOPSIS
  Build the known-good hash list that MALWARE_GOODWARE_LIST points at.

.DESCRIPTION
  The static heuristics fire on legitimate software as readily as on malware: an
  installer is packed, a game launcher has RWX sections, a system DLL imports
  every API on the "suspicious" list. Without a known-good set the engine has no
  way to say so, and the analyst pays for it in false positives on every batch.

  The obvious source for such a list is a directory of system files — and the
  obvious objection is that a compromised machine would poison it. This script
  answers that by refusing to record any file that does not carry a *valid*
  Authenticode signature from a trusted publisher. A trojanised system binary
  fails that check, so the list stays sound even when built on a live host.

  Signature verification is the slow part (a few minutes for System32). That is
  the whole point of the script; do not "optimise" it away.

.PARAMETER Path
  Directories to walk. Defaults to the Windows system directories.

.PARAMETER OutFile
  Where to write the list. Point MALWARE_GOODWARE_LIST at this file.

.PARAMETER Publisher
  Regex the signing subject must match. Defaults to Microsoft.

.EXAMPLE
  # Writes to backend\data, which compose mounts at /app/data in the backend.
  .\build-goodware-list.ps1

.EXAMPLE
  # A vendor's golden image mounted read-only, any signer accepted:
  .\build-goodware-list.ps1 -Path 'E:\Image\Program Files' -Publisher '.' -OutFile .\backend\data\gold.txt
#>
[CmdletBinding()]
param(
  [string[]]$Path = @("$env:SystemRoot\System32", "$env:SystemRoot\SysWOW64"),
  [string]$OutFile = "$PSScriptRoot\..\backend\data\goodware-hashes.txt",
  [string]$Publisher = 'Microsoft',
  [string[]]$Include = @('*.exe', '*.dll', '*.sys', '*.ocx', '*.cpl', '*.scr'),
  [int]$MaxFileMB = 128
)

$ErrorActionPreference = 'Stop'

$outDir = Split-Path -Parent $OutFile
if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
  New-Item -ItemType Directory -Force -Path $outDir | Out-Null
}

$maxBytes = $MaxFileMB * 1MB
$hashes = [System.Collections.Generic.HashSet[string]]::new()
$scanned = 0
$rejected = 0

foreach ($root in $Path) {
  if (-not (Test-Path -LiteralPath $root)) {
    Write-Warning "skipping missing path: $root"
    continue
  }
  Write-Host "walking $root ..."
  Get-ChildItem -LiteralPath $root -Recurse -File -Include $Include -ErrorAction SilentlyContinue |
    ForEach-Object {
      $scanned++
      if ($scanned % 250 -eq 0) { Write-Host "  $scanned files, $($hashes.Count) accepted" }
      if ($_.Length -eq 0 -or $_.Length -gt $maxBytes) { return }

      $sig = try { Get-AuthenticodeSignature -LiteralPath $_.FullName -ErrorAction Stop } catch { $null }
      # Valid means the digest matches AND the chain verifies. Anything else — an
      # unsigned file, a broken digest, an untrusted root — is not evidence of
      # anything and must not enter the list.
      if ($null -eq $sig -or $sig.Status -ne 'Valid') { $rejected++; return }
      if ($sig.SignerCertificate.Subject -notmatch $Publisher) { $rejected++; return }

      $h = try { Get-FileHash -LiteralPath $_.FullName -Algorithm SHA256 -ErrorAction Stop } catch { $null }
      if ($h) { [void]$hashes.Add($h.Hash.ToLowerInvariant()) }
    }
}

$header = @(
  "# AnalysisHub goodware allowlist",
  "# generated $(Get-Date -Format o) on $env:COMPUTERNAME",
  "# sources: $($Path -join '; ')",
  "# rule: SHA256 of files with a VALID Authenticode signature matching /$Publisher/",
  "# scanned $scanned file(s), accepted $($hashes.Count), rejected $rejected",
  "#",
  "# One hash per line. MD5/SHA1/SHA256 and '<hash>  <name>' lines are also accepted",
  "# by the loader, so an NSRL RDS export can be concatenated onto this file."
)

# WriteAllLines rather than Set-Content: Windows PowerShell's -Encoding utf8 emits
# a BOM, and a BOM on the first line means the loader sees "﻿#" instead of a
# comment. Harmless here, but not once an NSRL export is concatenated onto it.
[IO.File]::WriteAllLines(
  (Join-Path (Resolve-Path (Split-Path -Parent $OutFile)) (Split-Path -Leaf $OutFile)),
  ($header + ($hashes | Sort-Object)),
  [Text.UTF8Encoding]::new($false))

Write-Host ""
Write-Host "wrote $($hashes.Count) hashes to $OutFile"
Write-Host "scanned $scanned, rejected $rejected (unsigned / untrusted / wrong publisher)"
Write-Host ""
Write-Host "Now set in .env:  MALWARE_GOODWARE_LIST=/app/data/$(Split-Path -Leaf $OutFile)"
