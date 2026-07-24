/*
  Scenario: POWERSHELL / FILELESS
  Encoded commands, download cradles, AMSI / logging bypass, reflective loading
  and obfuscation.

  Precision notes:
   * The YARA engine has no per-language routing, so without a content gate
     these rules are evaluated against every .php, .js and .py file that quotes
     a Windows command line. Everything here is gated on ah_is_powershell.
   * "IEX somewhere in the file" plus "Invoke-WebRequest somewhere in the file"
     describes a large share of legitimate deployment scripts. The cradle and
     the encoded command are therefore matched as one expression, both
     directions, inside a single line.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_powershell
{
    // Shape test, not a parser: a Verb-Noun cmdlet, a .NET type literal, an
    // explicit interpreter invocation, a PowerShell automatic variable or a
    // typed param() block.
    strings:
        $v = /\b(Get|Set|New|Add|Remove|Invoke|Start|Stop|Register|Unregister|Import|Export|Write|Select|ForEach|ConvertTo|ConvertFrom|Enter|Exit|Copy|Move|Test|Enable|Disable|Out|Join|Split|Compare)-[A-Z][A-Za-z]{2,}\b/
        $t = /\[[A-Za-z][A-Za-z0-9_.]{2,60}\]\s*::\s*[A-Za-z]/
        $x = /\b(powershell|pwsh)(\.exe)?\b/ nocase
        $a = /\$(PSVersionTable|ExecutionContext|PSHome|MyInvocation|env:|null\b|true\b|false\b)/ nocase
        $i = /\b(IEX|Invoke-Expression)\b/ nocase
        $p = /\bparam\s*\(\s*\[/ nocase
        $r = /\[(Ref|System\.[A-Za-z][A-Za-z0-9_.]{2,40})\]\s*\./ nocase
    condition:
        any of them
}

rule PS_Encoded_Command
{
    meta:
        author      = "AnalysisHub"
        description = "PowerShell -EncodedCommand with hidden/bypass flags"
        severity    = "high"
        category    = "powershell"
        reference   = "MITRE T1059.001 / T1027 obfuscation"
    strings:
        // The interpreter and the blob must be the same command line; "the word
        // powershell appears in this file" is not a constraint.
        $enc1 = /(powershell|pwsh)(\.exe)?[^\n]{0,120}\s-e(nc|ncodedcommand|ncoded)?\s+[A-Za-z0-9+\/]{50,}={0,2}/ nocase
        $enc2 = /(powershell|pwsh)(\.exe)?[^\n]{0,120}-encodedcommand\s/ nocase
        $enc3 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{120,}={0,2}/ nocase
        $hidden = /-w(indowstyle)?\s+hidden/ nocase
        $nop    = /-nop(rofile)?\b/ nocase
        $bypass = /-ep\s+bypass|-executionpolicy\s+bypass/ nocase
    condition:
        ah_is_powershell and filesize < 4MB and (
            $enc1 or $enc3 or ($enc2 and 1 of ($hidden,$nop,$bypass))
        )
}

rule PS_Suspicious_Invocation_Flags
{
    meta:
        author      = "AnalysisHub"
        description = "PowerShell launched with a stacked evasion flag set (hidden window + no profile / bypass)"
        severity    = "medium"
        category    = "powershell"
        reference   = "MITRE T1059.001"
    strings:
        $a = /(powershell|pwsh)(\.exe)?[^\n]{0,200}-w(indowstyle)?\s+h(idden)?\b[^\n]{0,200}(-nop(rofile)?|-ep\s+bypass|-executionpolicy\s+bypass|-noni|-noninteractive|-e(nc|ncodedcommand)?\s)/ nocase
        $b = /(powershell|pwsh)(\.exe)?[^\n]{0,200}(-nop(rofile)?|-executionpolicy\s+bypass)[^\n]{0,200}-w(indowstyle)?\s+h(idden)?\b/ nocase
    condition:
        // A single -ExecutionPolicy Bypass is ordinary (it is in the header
        // comment of half the deployment scripts ever written); a hidden window
        // stacked on top of it is not.
        ah_is_powershell and filesize < 4MB and any of them
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
        $fwd = /\b(IEX|Invoke-Expression)\b[^\n]{0,160}(DownloadString|DownloadData|DownloadFile|Net\.WebClient|Invoke-WebRequest|Invoke-RestMethod|\biwr\b|Net\.WebRequest|Start-BitsTransfer)/ nocase
        $rev = /(DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|\biwr\b)[^\n]{0,200}\|\s*(IEX|Invoke-Expression|&)/ nocase
        $amp = /&\s*\(\s*['"]?(IEX|Invoke-Expression)['"]?\s*\)[^\n]{0,160}(DownloadString|Net\.WebClient)/ nocase
    condition:
        ah_is_powershell and filesize < 4MB and any of them
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
        $a5 = "System.Management.Automation.AmsiUtils" nocase
        // The tamper primitive: private reflection or a memory patch. Without it
        // the AMSI names are just what a defensive script greps for.
        $t1 = /\[Ref\]\.Assembly\.GetType\(/ nocase
        $t2 = /(GetField|GetProperty)\s*\(\s*['"]amsi/ nocase
        $t3 = /NonPublic\s*,?\s*Static/ nocase
        $t4 = /SetValue\s*\(\s*\$?null\s*,\s*\$?(true|1)/ nocase
        $t5 = "VirtualProtect" nocase
        $t6 = /GetProcAddress[^\n]{0,60}Amsi/ nocase
        $l1 = "EnableScriptBlockLogging" nocase
        $l2 = "ScriptBlockLogging" nocase
    condition:
        ah_is_powershell and filesize < 4MB and (
            (1 of ($a*) and 1 of ($t*)) or
            (1 of ($l*) and 1 of ($t3,$t4) )
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
        $r3 = /\[AppDomain\]::CurrentDomain\.Load\s*\(/ nocase
        // "memset" was dropped from this set: it is a plain C library name and
        // contributed nothing the other three do not.
        $api1 = "VirtualAlloc" nocase
        $api2 = "CreateThread" nocase
        $api4 = "WriteProcessMemory" nocase
        $api5 = "NtCreateThreadEx" nocase
        $marshal = /\[Runtime\.InteropServices\.Marshal\]::Copy/ nocase
        $addtype = /Add-Type\b[^\n]{0,200}(kernel32|VirtualAlloc|CreateThread|NtCreateThreadEx)/ nocase
    condition:
        ah_is_powershell and filesize < 4MB and (
            (1 of ($r*) and 1 of ($api*)) or
            $addtype or
            ($marshal and 1 of ($api*))
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
        // $s* are shapes a human does not write; $w* are ordinary language
        // features that only mean something as company. Three of the weak ones
        // alone used to be enough, which flagged any script using -join,
        // [string]::Join and a ${braced} variable.
        // Format-operator reordering: '{0}{2}{1}' -f 'IE','X','...'. The old
        // pattern had the operands the wrong way round and never matched.
        $s1 = /["']\{\d\}[^"'\n]{0,40}["']\s*-f\s*["']/ nocase
        $s2 = /(\[char\]\s*\d{1,3}\s*\+\s*){4,}/ nocase
        $s3 = /(\$\w+\[\s*\d+\s*\]\s*\+\s*){4,}/
        $s4 = /['"]\s*\+\s*['"]\s*\)?\s*\|\s*(IEX|Invoke-Expression)/ nocase
        $s5 = /\$\{[^}\n]{0,20}[^A-Za-z0-9_}\n][^}\n]{0,20}\}/     // ${w`eird} style names
        $w1 = /-join\s*\(/ nocase
        $w2 = /\[string\]::Join\(/ nocase
        $w3 = "[Convert]::FromBase64String" nocase
        $w4 = /\.replace\(['"][^'"]{1,4}['"]\s*,\s*['"]['"]\)/ nocase
        $w5 = /\[Text\.Encoding\]::(UTF8|ASCII|Unicode)\.GetString/ nocase
    condition:
        ah_is_powershell and filesize < 4MB and (
            (1 of ($s*) and 2 of ($w*)) or
            2 of ($s*)
        )
}
