/*
  Scenario: WINDOWS PERSISTENCE
  Detects autostart / persistence mechanisms in scripts and binaries:
  Run keys, scheduled tasks, services, WMI event subscriptions, IFEO /
  accessibility backdoors, and Winlogon tampering.

  Author: AnalysisHub   Updated: 2026-06-26
*/

rule PERSIST_Registry_RunKey
{
    meta:
        author      = "AnalysisHub"
        description = "Autostart Run/RunOnce key written via reg.exe or PowerShell"
        severity    = "high"
        category    = "persistence"
        reference   = "MITRE T1547.001 Registry Run Keys"
    strings:
        $run1 = /CurrentVersion\\Run(Once)?\b/ nocase
        $run2 = /CurrentVersion\\RunServices(Once)?\b/ nocase
        $add  = /reg(\.exe)?\s+add/ nocase
        $ps   = /(Set|New)-ItemProperty/ nocase
        $sus  = /(powershell|cmd|wscript|cscript|mshta|rundll32|regsvr32)/ nocase
    condition:
        filesize < 4MB and 1 of ($run*) and (1 of ($add,$ps)) and $sus
}

rule PERSIST_Scheduled_Task
{
    meta:
        author      = "AnalysisHub"
        description = "Suspicious scheduled-task creation (schtasks / Register-ScheduledTask)"
        severity    = "high"
        category    = "persistence"
        reference   = "MITRE T1053.005 Scheduled Task"
    strings:
        $s1 = /schtasks(\.exe)?\s+\/create/ nocase
        $s2 = "Register-ScheduledTask" nocase
        $hi = /\/ru\s+(system|"nt authority\\system")/ nocase
        $tr = /\/tr\s+["']?.{0,80}(powershell|cmd|mshta|wscript|cscript|rundll32|regsvr32|\.bat|\.vbs|\.ps1)/ nocase
        $sc = /\/sc\s+(minute|hourly|onlogon|onstart)/ nocase
    condition:
        filesize < 4MB and 1 of ($s1,$s2) and ($tr or ($hi and $sc))
}

rule PERSIST_Service_Install
{
    meta:
        author      = "AnalysisHub"
        description = "Service created with an interpreter/script binPath — service persistence"
        severity    = "high"
        category    = "persistence"
        reference   = "MITRE T1543.003 Windows Service"
    strings:
        $sc1 = /sc(\.exe)?\s+create/ nocase
        $sc2 = "New-Service" nocase
        $bp  = /binpath=.{0,80}(cmd|powershell|mshta|wscript|cscript|rundll32|\.bat|\.vbs|\.ps1)/ nocase
        $bp2 = /-BinaryPathName.{0,80}(cmd|powershell|mshta)/ nocase
    condition:
        filesize < 4MB and 1 of ($sc*) and 1 of ($bp*)
}

rule PERSIST_WMI_Event_Subscription
{
    meta:
        author      = "AnalysisHub"
        description = "WMI permanent event subscription persistence"
        severity    = "high"
        category    = "persistence"
        reference   = "MITRE T1546.003 WMI Event Subscription"
    strings:
        $f = "__EventFilter" ascii nocase
        $c1 = "CommandLineEventConsumer" ascii nocase
        $c2 = "ActiveScriptEventConsumer" ascii nocase
        $b = "__FilterToConsumerBinding" ascii nocase
        $q = /SELECT\s+\*\s+FROM\s+__InstanceModificationEvent/ nocase
    condition:
        filesize < 4MB and $f and (1 of ($c*)) and ($b or $q)
}

rule PERSIST_IFEO_Accessibility_Backdoor
{
    meta:
        author      = "AnalysisHub"
        description = "Image File Execution Options debugger hijack / accessibility (sticky keys) backdoor"
        severity    = "critical"
        category    = "persistence"
        reference   = "MITRE T1546.008 / T1546.012"
    strings:
        $ifeo = /Image File Execution Options\\(sethc|utilman|osk|magnify|narrator|displayswitch)\.exe/ nocase
        $dbg  = "Debugger" nocase
        $acc1 = /sethc\.exe/ nocase
        $acc2 = /utilman\.exe/ nocase
        $cmd  = /(cmd\.exe|powershell\.exe)/ nocase
        $copy = /copy\s+.{0,40}(cmd|powershell)\.exe\s+.{0,40}(sethc|utilman)\.exe/ nocase
    condition:
        filesize < 4MB and (
            ($ifeo and $dbg) or
            $copy or
            (1 of ($acc1,$acc2) and $dbg and $cmd)
        )
}

rule PERSIST_Winlogon_Tamper
{
    meta:
        author      = "AnalysisHub"
        description = "Winlogon Userinit/Shell value tampering for persistence"
        severity    = "high"
        category    = "persistence"
        reference   = "MITRE T1547.004 Winlogon Helper DLL"
    strings:
        $wl = /Winlogon\b/ nocase
        $u  = "Userinit" nocase
        $s  = /\bShell\b/ nocase
        $set = /(reg(\.exe)?\s+add|Set-ItemProperty)/ nocase
        $sus = /(powershell|cmd|wscript|cscript|mshta|\.exe,)/ nocase
    condition:
        filesize < 4MB and $wl and (1 of ($u,$s)) and $set and $sus
}

rule PERSIST_Startup_Folder_Drop
{
    meta:
        author      = "AnalysisHub"
        description = "Payload dropped into a Startup folder via script"
        severity    = "medium"
        category    = "persistence"
        reference   = "MITRE T1547.001 Startup Folder"
    strings:
        $p = /Start Menu\\Programs\\Startup/ nocase
        $w = /(copy|move|Copy-Item|Move-Item|file_put_contents|WriteAllText)/ nocase
        $e = /\.(exe|bat|vbs|ps1|lnk|hta|js|scr)\b/ nocase
    condition:
        filesize < 4MB and $p and $w and $e
}
