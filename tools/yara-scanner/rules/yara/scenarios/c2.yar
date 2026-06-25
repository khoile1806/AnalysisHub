/*
  Scenario: C2 FRAMEWORKS / IMPLANTS
  Detects post-exploitation implants and beacons: Cobalt Strike, Meterpreter,
  Sliver, PowerShell Empire, and Covenant Grunt. Binary rules gate on PE magic.

  Author: ForensicHub   Updated: 2026-06-26
*/

rule C2_CobaltStrike_Beacon
{
    meta:
        author      = "ForensicHub"
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
        $pipe = /\\\\\.\\pipe\\(MSSE-|msagent_|status_|postex_)/ nocase
        $spawn = "%windir%\\sysnative\\rundll32.exe" ascii
    condition:
        uint16(0) == 0x5A4D and filesize < 8MB and (
            ($rl and 1 of ($b*)) or
            (2 of ($b*)) or
            $pipe or
            ($spawn and $rl)
        )
}

rule C2_Meterpreter
{
    meta:
        author      = "ForensicHub"
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
        filesize < 8MB and (1 of ($m1,$m2) or 2 of ($m3,$m4,$m6) or ($m5 and 1 of ($m3,$m4,$m6)))
}

rule C2_Sliver_Implant
{
    meta:
        author      = "ForensicHub"
        description = "Sliver C2 implant markers"
        severity    = "critical"
        category    = "c2"
        reference   = "BishopFox Sliver"
    strings:
        $s1 = "sliverpb" ascii
        $s2 = "SliverRPC" ascii
        $s3 = ".sliver" ascii
        $s4 = "bishopfox/sliver" ascii
        $s5 = "tunnelpb" ascii
    condition:
        filesize < 30MB and 2 of them
}

rule C2_PowerShell_Empire
{
    meta:
        author      = "ForensicHub"
        description = "PowerShell Empire / Starkiller agent + staging markers"
        severity    = "high"
        category    = "c2"
        reference   = "MITRE S0363 Empire"
    strings:
        $e1 = "Invoke-Empire" nocase
        $e2 = "$AES_IV" ascii
        $e3 = /\$ser\s*=\s*['"]https?:\/\// nocase
        $e4 = "ReferenceSet" ascii
        $e5 = "/admin/get.php" nocase
        $e6 = "/login/process.php" nocase
        $e7 = "function Start-Negotiate" nocase
    condition:
        filesize < 4MB and (2 of them)
}

rule C2_Covenant_Grunt
{
    meta:
        author      = "ForensicHub"
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
        filesize < 8MB and 2 of them
}

rule C2_Generic_Beacon_Behavior
{
    meta:
        author      = "ForensicHub"
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
        filesize < 8MB and $h1 and ($h2 or $j1) and ($j2) and 1 of ($c1,$c2)
}
