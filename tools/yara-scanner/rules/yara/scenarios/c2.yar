/*
  Scenario: C2 FRAMEWORKS / IMPLANTS
  Cobalt Strike, Meterpreter, Sliver, Empire, Covenant, Havoc.

  Two constraints drive the precision of this file:

   1. Implants are compiled artefacts. The binary rules are gated on the
      PE/ELF/Mach-O magic (uint16(0)/uint32(0)) — the cheapest and strongest
      filter available — so a framework name quoted in source code, a blog post
      or a detection script cannot score critical on its own.

   2. Several framework tokens are also ordinary words or product names
      ("Covenant", "sleep", ".sliver", "$AES_IV"). They never fire alone; each
      needs either an unambiguous marker or a second independent indicator.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_pe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

private rule ah_is_elf
{
    condition:
        uint32(0) == 0x464C457F
}

private rule ah_is_macho
{
    condition:
        uint32(0) == 0xFEEDFACE or uint32(0) == 0xFEEDFACF or
        uint32(0) == 0xCEFAEDFE or uint32(0) == 0xCFFAEDFE
}

private rule ah_is_native_image
{
    condition:
        ah_is_pe or ah_is_elf or ah_is_macho
}

private rule ah_is_powershell
{
    // Shape test, not a parser: a Verb-Noun cmdlet, a .NET type literal, an
    // explicit interpreter invocation, or a PowerShell automatic variable.
    // Without it a PowerShell stager rule is evaluated against every .php/.js
    // file that happens to quote a Windows command line.
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

rule C2_CobaltStrike_Beacon
{
    meta:
        author      = "AnalysisHub"
        description = "Cobalt Strike beacon — reflective loader + beacon artifacts / default pipes"
        severity    = "critical"
        category    = "c2"
        reference   = "MITRE S0154 Cobalt Strike"
    strings:
        $rl   = "ReflectiveLoader" ascii
        $b1   = "beacon.dll" ascii nocase
        $b2   = "beacon.x64.dll" ascii nocase
        $b3   = "%s as %s\\%s: %d" ascii
        $b4   = "%d is an x86 process (can't inject x64 content)" ascii
        $b5   = "Could not open process token: %d (%u)" ascii
        // The default post-ex pipe names carry a hex suffix; requiring it keeps
        // the pattern out of ordinary named-pipe code and makes it strong
        // enough to report from a text artefact (script, config, memory strings).
        $pipe = /\\\\\.\\pipe\\(MSSE-|msagent_|status_|postex_)[0-9a-f]{2,}/ nocase
        $spawn = "%windir%\\sysnative\\rundll32.exe" ascii
    condition:
        filesize < 8MB and (
            $pipe or
            (ah_is_pe and filesize > 1KB and (
                ($rl and 1 of ($b*)) or
                2 of ($b*) or
                ($spawn and $rl)
            ))
        )
}

rule C2_CobaltStrike_MalleableProfile
{
    meta:
        author      = "AnalysisHub"
        description = "Cobalt Strike malleable C2 profile — beacon transport configuration"
        severity    = "high"
        category    = "c2"
        reference   = "Cobalt Strike malleable-c2 profile grammar"
    strings:
        $p1 = /set\s+sleeptime\s+"[0-9]+"/ nocase
        $p2 = /set\s+jitter\s+"[0-9]+"/ nocase
        $p3 = /http-(get|post|stager)\s*\{/ nocase
        $p4 = /set\s+useragent\s+"/ nocase
        $p5 = /set\s+uri\s+"/ nocase
        $p6 = /(header|parameter)\s+"[^"\n]{1,40}"\s+"[^"\n]{0,60}";/ nocase
    condition:
        // Profile grammar only — three of these directives together are not a
        // shape any other configuration format produces.
        filesize < 512KB and 3 of them
}

rule C2_Meterpreter
{
    meta:
        author      = "AnalysisHub"
        description = "Metasploit Meterpreter stager / stdapi extension markers"
        severity    = "critical"
        category    = "c2"
        reference   = "Metasploit Meterpreter (MITRE S0419)"
    strings:
        $m1 = "metsrv.dll" ascii nocase
        $m2 = "metsrv.x64.dll" ascii nocase
        $m3 = "core_channel_open" ascii
        $m4 = "stdapi_sys_process_execute" ascii
        $m5 = "ReflectiveLoader" ascii
        $m6 = "PACKET_TYPE_RESPONSE" ascii
    condition:
        filesize < 8MB and (
            2 of ($m3,$m4,$m6) or
            // A bare "metsrv.dll" is also what every detection article writes,
            // so it needs the file to actually be an implant or a second marker.
            (1 of ($m1,$m2) and (ah_is_native_image or 1 of ($m3,$m4,$m5,$m6)))
        )
}

rule C2_Sliver_Implant
{
    meta:
        author      = "AnalysisHub"
        description = "Sliver C2 implant markers"
        severity    = "critical"
        category    = "c2"
        reference   = "BishopFox Sliver"
    strings:
        // ".sliver" was dropped: it matches any word ending in that substring
        // and carried no information the protobuf package names do not.
        $s1 = "sliverpb" ascii
        $s2 = "SliverRPC" ascii
        $s4 = "bishopfox/sliver" ascii
        $s5 = "tunnelpb" ascii
    condition:
        filesize < 30MB and ($s4 or 2 of ($s1,$s2,$s5))
}

rule C2_Havoc_Demon
{
    meta:
        author      = "AnalysisHub"
        description = "Havoc C2 Demon agent / KaynLdr loader artefacts"
        severity    = "high"
        category    = "c2"
        reference   = "HavocFramework/Havoc"
    strings:
        $h1 = "KaynLdr" ascii
        $h2 = "havocframework" nocase
        $h3 = "Demon.x64.bin" ascii nocase
        $h4 = "DEMON_COMMAND" ascii
        $h5 = "DemonInit" ascii
    condition:
        filesize < 12MB and (1 of ($h1,$h2,$h3) or 2 of them)
}

rule C2_PowerShell_Empire
{
    meta:
        author      = "AnalysisHub"
        description = "PowerShell Empire / Starkiller agent + staging markers"
        severity    = "high"
        category    = "c2"
        reference   = "MITRE S0363 Empire"
    strings:
        $e1 = "Invoke-Empire" nocase
        $e7 = "Start-Negotiate" nocase
        // Weak on their own: "$AES_IV" and "$ser = 'https://" are both perfectly
        // ordinary variable names in other languages, which is why the whole
        // rule is gated on PowerShell content and these need a second hit.
        $e2 = "$AES_IV" ascii
        $e3 = /\$ser\s*=\s*['"]https?:\/\// nocase
        $e4 = "ReferenceSet" ascii
        $e5 = "/admin/get.php" nocase
        $e6 = "/login/process.php" nocase
    condition:
        ah_is_powershell and filesize < 4MB and (
            1 of ($e1,$e7) or
            2 of ($e2,$e3,$e4,$e5,$e6)
        )
}

rule C2_Covenant_Grunt
{
    meta:
        author      = "AnalysisHub"
        description = "Covenant Grunt implant markers"
        severity    = "high"
        category    = "c2"
        reference   = "Covenant C2"
    strings:
        $g1 = "GruntStager" ascii
        $g2 = "GruntExecutor" ascii
        $g3 = "Covenant" ascii
        $g4 = "ProfileHttpHeaders" ascii
    condition:
        // "Covenant" alone is an English word and a product name — it can only
        // corroborate, never trigger.
        filesize < 8MB and (1 of ($g1,$g2) or ($g3 and $g4))
}

rule C2_Generic_Beacon_Behavior
{
    meta:
        author      = "AnalysisHub"
        description = "Generic implant heuristic — HTTP C2 + sleep jitter + command dispatch in one binary"
        severity    = "medium"
        category    = "c2"
    strings:
        $h1 = "User-Agent:" ascii
        $h2 = "checkin" nocase
        $j1 = "jitter" nocase
        $j2 = "sleep" nocase
        $c1 = "cmd.exe /c" nocase
        $c2 = "/bin/sh -c" ascii
    condition:
        // Every token here occurs in ordinary networking code; the rule is only
        // meaningful for the compiled-implant case it was written for, so it is
        // restricted to native images.
        ah_is_native_image and filesize > 1KB and filesize < 8MB and
        $h1 and ($h2 or $j1) and $j2 and 1 of ($c1,$c2)
}
