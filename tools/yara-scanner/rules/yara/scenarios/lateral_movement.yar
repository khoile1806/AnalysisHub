/*
  Scenario: LATERAL MOVEMENT
  PsExec and clones, WMI remote process creation, WinRM/PSRemoting, the Impacket
  suite, remote service creation and SSH key implantation.

  Precision notes:
   * Remote execution is expressed as a command line, and a command line lives
     on one line. Every "X near Y" requirement is therefore a single regex with
     [^\n] bounds — an AND of two strings would only mean "both appear somewhere
     in this file", which is how `sc create` in a build script met `binpath=`
     from an unrelated service definition 200 lines away.
   * Remoting cmdlets are the daily work of Windows administrators, so they only
     report when the payload they carry is itself suspicious.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_pe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

private rule ah_is_windows_admin_context
{
    // Keeps the Windows remote-exec rules from being evaluated against .js/.py
    // content that merely contains a tool name in a string table or a comment.
    strings:
        $c = /\b(cmd\.exe|powershell|pwsh|wmic|wmiexec|psexec|paexec|winrs|schtasks|sc\.exe|rundll32|mshta|impacket|Invoke-Command|New-PSSession|Enter-PSSession|New-Service|Invoke-WmiMethod|Invoke-CimMethod)\b/ nocase
        $u = /\\\\[A-Za-z0-9_.\-]{1,60}\\(ADMIN\$|C\$|IPC\$)/
        $p = /HK(LM|CU|EY_LOCAL_MACHINE|EY_CURRENT_USER)\\/ nocase
        $n = /\bnet\s+use\s+\\\\/ nocase
        $s = /\bsc(\.exe)?\s+(\\\\|create\b|config\b)/ nocase
    condition:
        ah_is_pe or any of them
}

rule LATERAL_PsExec
{
    meta:
        author      = "AnalysisHub"
        description = "Sysinternals PsExec / clones (service-based remote exec)"
        severity    = "high"
        category    = "lateral-movement"
        reference   = "MITRE T1570 / T1021.002; PsExec PSEXESVC"
    strings:
        $banner = "Sysinternals PsExec" nocase
        $cmd = /(psexec|paexec)(\.exe)?\s+\\\\/ nocase
        $art1 = "PSEXESVC" ascii wide
        $art2 = "psexesvc.exe" nocase
        $art3 = "PAExec" ascii wide
        // "RemCom" alone also matches identifiers such as RemComputerName;
        // the service/binary name is the artefact worth reporting.
        $art4 = /RemCom(Svc)?\.exe/ nocase
        $art5 = "RemComSvc" ascii
        $install = /(sc(\.exe)?\s+create|CreateService[AW]?|OpenSCManager)/ nocase
    condition:
        // A tool name in isolation is what an IR note or an allow-list contains.
        // It reports when the file is the service binary itself, when a remote
        // invocation is spelled out, or when a second artefact corroborates.
        ah_is_windows_admin_context and filesize < 10MB and (
            $banner or $cmd or
            (1 of ($art*) and (ah_is_pe or $install or 2 of ($art*)))
        )
}

rule LATERAL_WMIC_Remote_Exec
{
    meta:
        author      = "AnalysisHub"
        description = "Remote process creation via WMIC / WMI"
        severity    = "high"
        category    = "lateral-movement"
        reference   = "MITRE T1047 WMI"
    strings:
        $wmic = /wmic(\.exe)?\s+\/node:[^\s\n]{1,80}[^\n]{0,120}process\s+call\s+create/ nocase
        $ps1  = /Invoke-WmiMethod[^\n]{0,160}Win32_Process[^\n]{0,160}(-Name\s+Create|Create)/ nocase
        $ps2  = /Invoke-CimMethod[^\n]{0,160}Win32_Process[^\n]{0,160}-MethodName\s+Create/ nocase
        $rmt  = /-Compute[rR]Name\s+[^\s\n]{1,60}/ nocase
        $sus  = /(powershell|cmd\.exe|mshta|rundll32|regsvr32|certutil|-enc\b|FromBase64String)/ nocase
    condition:
        ah_is_windows_admin_context and filesize < 6MB and (
            $wmic or
            (1 of ($ps*) and $rmt and $sus)
        )
}

rule LATERAL_WinRM_PSRemoting
{
    meta:
        author      = "AnalysisHub"
        description = "PowerShell remoting / WinRM carrying an obfuscated or downloaded payload"
        severity    = "medium"
        category    = "lateral-movement"
        reference   = "MITRE T1021.006 WinRM"
    strings:
        $i  = /(Invoke-Command|New-PSSession|Enter-PSSession)[^\n]{0,80}-Compute[rR]Name/ nocase
        $w  = /winrs(\.exe)?\s+-r:/ nocase
        // Invoke-Command -ComputerName ... -ScriptBlock { Get-Service } is what
        // an administrator types all day. Only the payload distinguishes it.
        $sus1 = /\b(IEX|Invoke-Expression)\b/ nocase
        $sus2 = /-e(nc|ncodedcommand)?\s+[A-Za-z0-9+\/]{40,}={0,2}/ nocase
        $sus3 = /(DownloadString|DownloadFile|FromBase64String)/ nocase
        $sus4 = /-w(indowstyle)?\s+hidden/ nocase
        $sus5 = /New-Object\s+(System\.)?Net\.WebClient/ nocase
    condition:
        ah_is_windows_admin_context and filesize < 4MB and ($i or $w) and 1 of ($sus*)
}

rule LATERAL_Impacket_Suite
{
    meta:
        author      = "AnalysisHub"
        description = "Impacket remote-exec / secrets tools (wmiexec/smbexec/atexec/psexec/secretsdump)"
        severity    = "critical"
        category    = "lateral-movement"
        reference   = "Impacket examples"
    strings:
        $i1 = "wmiexec" nocase
        $i2 = "smbexec" nocase
        $i3 = "atexec" nocase
        $i4 = "dcomexec" nocase
        $i5 = "secretsdump" nocase
        $i6 = "Impacket" ascii
        $imp = /from\s+impacket(\.[a-z]+)*\s+import/ nocase
        $svc = "SMBEXEC" ascii
        $share = "\\\\127.0.0.1\\ADMIN$" nocase
    condition:
        filesize < 12MB and (
            $imp or $svc or
            2 of ($i1,$i2,$i3,$i4,$i5) or
            ($i6 and 1 of ($i1,$i2,$i3,$i4,$i5)) or
            ($share and 1 of ($i1,$i2,$i3,$i4,$i5))
        )
}

rule LATERAL_Remote_Service_Create
{
    meta:
        author      = "AnalysisHub"
        description = "Remote service created on another host (sc \\\\host create ... binpath=)"
        severity    = "high"
        category    = "lateral-movement"
        reference   = "MITRE T1021.002 / T1543.003"
    strings:
        $sc = /sc(\.exe)?\s+\\\\[^\s\n]{1,60}\s+create\s[^\n]{0,200}binpath\s*=/ nocase
        $ps = /New-Service[^\n]{0,200}-BinaryPathName[^\n]{0,120}\\\\[^\s\n]{1,60}\\/ nocase
    condition:
        ah_is_windows_admin_context and filesize < 4MB and any of them
}

rule LATERAL_SSH_Key_Implant
{
    meta:
        author      = "AnalysisHub"
        description = "Attacker public key appended to an authorized_keys file (remote or local)"
        severity    = "high"
        category    = "lateral-movement"
        reference   = "MITRE T1098.004 SSH Authorized Keys"
    strings:
        // Both halves live in one regex: the key material and the append into
        // authorized_keys have to be the same statement, otherwise a script that
        // merely reads authorized_keys and separately prints a key matches.
        $a = /(echo|printf|cat|tee)[^\n]{0,240}ssh-(rsa|ed25519|dss)\s[^\n]{0,400}>>?\s*[^\n]{0,80}authorized_keys/ nocase
        $b = /ssh\s+[^\n]{0,60}@[^\n]{0,80}(echo|cat|tee)[^\n]{0,200}authorized_keys/ nocase
        $c = /(scp|rsync)\s+[^\n]{0,80}\s[^\n]{0,60}@[^\n]{0,60}:[^\n]{0,60}\.ssh\/authorized_keys/ nocase
    condition:
        // No language gate: the regexes are specific enough on their own and the
        // technique shows up in shell, Python and PHP payloads alike.
        filesize < 4MB and any of them
}
