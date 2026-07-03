/*
  Scenario: POWERSHELL / FILELESS
  Detects offensive PowerShell: encoded commands, download cradles, AMSI / logging
  bypass, in-memory (reflective) loading, and obfuscation.

  Author: AnalysisHub   Updated: 2026-06-26
*/

rule PS_Encoded_Command
{
    meta:
        author      = "AnalysisHub"
        description = "PowerShell -EncodedCommand with hidden/bypass flags"
        severity    = "high"
        category    = "powershell"
        reference   = "MITRE T1059.001 / T1027 obfuscation"
    strings:
        $enc1 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{60,}={0,2}/ nocase
        $enc2 = /-encodedcommand\s+/ nocase
        $hidden = /-w(indowstyle)?\s+hidden/ nocase
        $nop    = /-nop(rofile)?\b/ nocase
        $bypass = /-ep\s+bypass|-executionpolicy\s+bypass/ nocase
        $ps     = /powershell(\.exe)?|pwsh(\.exe)?/ nocase
    condition:
        filesize < 4MB and $ps and ($enc1 or ($enc2 and 1 of ($hidden,$nop,$bypass)))
}

rule PS_Download_Cradle
{
    meta:
        author      = "AnalysisHub"
        description = "In-memory download-and-execute cradle"
        severity    = "high"
        category    = "powershell"
        reference   = "MITRE T1059.001 / T1105 Ingress Tool Transfer"
    strings:
        $iex  = /IEX\s*\(|Invoke-Expression/ nocase
        $dl1  = /New-Object\s+(System\.)?Net\.WebClient/ nocase
        $dl2  = /\.DownloadString\s*\(/ nocase
        $dl3  = /\.DownloadFile\s*\(/ nocase
        $dl4  = /Invoke-WebRequest|Invoke-RestMethod|\biwr\b|\bcurl\b|\bwget\b/ nocase
        $dl5  = /Net\.WebRequest|Start-BitsTransfer/ nocase
    condition:
        filesize < 4MB and $iex and (2 of ($dl*) or $dl2 or $dl3)
}

rule PS_AMSI_Logging_Bypass
{
    meta:
        author      = "AnalysisHub"
        description = "AMSI / script-block logging bypass patterns"
        severity    = "critical"
        category    = "powershell"
        reference   = "MITRE T1562.001 Impair Defenses"
    strings:
        $a1 = "amsiInitFailed" nocase
        $a2 = "AmsiUtils" nocase
        $a3 = "AmsiScanBuffer" nocase
        $a4 = /\[Ref\]\.Assembly\.GetType\(/ nocase
        $a5 = "System.Management.Automation.AmsiUtils" nocase
        $l1 = "EnableScriptBlockLogging" nocase
        $l2 = "ScriptBlockLogging" nocase
    condition:
        filesize < 4MB and (
            (1 of ($a1,$a2,$a3,$a5) and ($a4 or 1 of ($a1,$a2,$a3,$a5))) or
            ($a4 and 1 of ($a1,$a2,$a3,$l1,$l2))
        )
}

rule PS_Reflective_InMemory
{
    meta:
        author      = "AnalysisHub"
        description = "Reflective / in-memory assembly loading and shellcode execution"
        severity    = "high"
        category    = "powershell"
        reference   = "MITRE T1620 Reflective Code Loading"
    strings:
        $r1 = /\[System\.Reflection\.Assembly\]::Load\s*\(/ nocase
        $r2 = "[Reflection.Assembly]::Load" nocase
        $api1 = "VirtualAlloc" nocase
        $api2 = "CreateThread" nocase
        $api3 = "memset" nocase
        $api4 = "WriteProcessMemory" nocase
        $marshal = /\[Runtime\.InteropServices\.Marshal\]::Copy/ nocase
        $addtype = /Add-Type\b.{0,200}(kernel32|VirtualAlloc|CreateThread)/ nocase
    condition:
        filesize < 4MB and (
            (1 of ($r*) and 1 of ($api*)) or
            ($addtype) or
            ($marshal and 1 of ($api1,$api2,$api4))
        )
}

rule PS_Obfuscation_Heavy
{
    meta:
        author      = "AnalysisHub"
        description = "Heavy PowerShell obfuscation (format/reorder, char arrays, -join, backticks)"
        severity    = "medium"
        category    = "powershell"
        reference   = "Invoke-Obfuscation patterns"
    strings:
        $o1 = /\(\s*'[^']{0,5}'\s*,\s*'[^']{0,5}'\s*\)\s*-f/ nocase   // ('{0}{1}' -f ...) style
        $o2 = /\[char\]\s*(\d{1,3}\s*\+?\s*){5,}/ nocase
        $o3 = /-join\s*\(/ nocase
        $o4 = /\[string\]::Join\(/ nocase
        $o5 = /\$\{.{0,30}\}\s*=\s*/ nocase
        $o6 = "[Convert]::FromBase64String" nocase
        $o7 = /\.replace\(['"][^'"]{1,4}['"]\s*,\s*['"]['"]\)/ nocase
    condition:
        filesize < 4MB and 3 of them
}
