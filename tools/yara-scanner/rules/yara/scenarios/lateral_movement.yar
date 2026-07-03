/*
  Scenario: LATERAL MOVEMENT
  Detects remote-execution tooling and techniques: PsExec, WMI remote process
  creation, WinRM/PSRemoting, Impacket suite, and pass-the-hash utilities.

  Author: AnalysisHub   Updated: 2026-06-26
*/

rule LATERAL_PsExec
{
    meta:
        author      = "AnalysisHub"
        description = "Sysinternals PsExec / clones (service-based remote exec)"
        severity    = "high"
        category    = "lateral-movement"
        reference   = "MITRE T1570 / T1021.002; PsExec PSEXESVC"
    strings:
        $svc1 = "PSEXESVC" ascii wide
        $svc2 = "psexesvc.exe" nocase
        $banner = "Sysinternals PsExec" nocase
        $paexec = "PAExec" ascii wide
        $remcom = "RemCom" ascii
        $cmd = /psexec(\.exe)?\s+\\\\/ nocase
    condition:
        filesize < 10MB and (1 of ($svc*) or $banner or $paexec or $remcom or $cmd)
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
        $w1 = /wmic\s+\/node:/ nocase
        $w2 = /process\s+call\s+create/ nocase
        $w3 = "Invoke-WmiMethod" nocase
        $w4 = "Win32_Process" nocase
        $sus = /(powershell|cmd|mshta|rundll32|regsvr32|certutil)/ nocase
    condition:
        filesize < 6MB and (
            ($w1 and $w2) or
            (($w3 or $w4) and $w2 and $sus)
        )
}

rule LATERAL_WinRM_PSRemoting
{
    meta:
        author      = "AnalysisHub"
        description = "PowerShell remoting / WinRM used for remote execution"
        severity    = "medium"
        category    = "lateral-movement"
        reference   = "MITRE T1021.006 WinRM"
    strings:
        $i1 = /Invoke-Command\s+-ComputerName/ nocase
        $i2 = /Enter-PSSession\s+-ComputerName/ nocase
        $i3 = /New-PSSession\s+-ComputerName/ nocase
        $w  = /winrs(\.exe)?\s+-r:/ nocase
        $sb = "-ScriptBlock" nocase
    condition:
        filesize < 4MB and (1 of ($i*) or $w) and ($sb or $w)
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
        $svc = "SMBEXEC" ascii
        $share = "\\\\127.0.0.1\\ADMIN$" nocase
    condition:
        filesize < 12MB and (2 of ($i*) or ($i6 and 1 of ($i1,$i2,$i3,$i4,$i5)) or $svc or ($share and 1 of ($i*)))
}

rule LATERAL_Remote_Service_Create
{
    meta:
        author      = "AnalysisHub"
        description = "Remote service created on another host (sc \\\\host create)"
        severity    = "high"
        category    = "lateral-movement"
        reference   = "MITRE T1021.002 / T1543.003"
    strings:
        $sc = /sc(\.exe)?\s+\\\\[^\s]+\s+create/ nocase
        $bp = /binpath=/ nocase
    condition:
        filesize < 4MB and $sc and $bp
}
