/*
  Scenario: WINDOWS PERSISTENCE
  Run keys, scheduled tasks, services, WMI event subscriptions, IFEO /
  accessibility backdoors, Winlogon tampering and Startup-folder drops.

  Precision notes:
   * Every technique here is a single command line or a single cmdlet call, so
     the autostart location and the payload it points at are matched by one
     regex with [^\n] bounds. The previous shape — "$run_key and $reg_add and
     $interpreter" — meant nothing more than "this file mentions a Run key
     somewhere and the word powershell somewhere", which any deployment script
     satisfies.
   * A file that names an autostart location without writing to it is inventory
     or detection content, not persistence.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_pe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

private rule ah_is_windows_script
{
    strings:
        $ps  = /\b(Get|Set|New|Add|Remove|Register|Start|Copy|Move|Enable)-[A-Z][A-Za-z]{2,}\b/
        $cmd = /\b(cmd\.exe|powershell|pwsh|wscript|cscript|mshta|rundll32|regsvr32|schtasks|wmic)\b/ nocase
        $reg = /\b(reg(\.exe)?\s+add|RegWrite|HK(LM|CU|CR|EY_LOCAL_MACHINE|EY_CURRENT_USER)\\)/ nocase
        $sc  = /\bsc(\.exe)?\s+create\b/ nocase
        $wmi = /(__EventFilter|__FilterToConsumerBinding|root\\(cimv2|subscription))/ nocase
        $env = /%(windir|systemroot|appdata|temp|programdata)%/ nocase
        $pth = /([A-Za-z]:\\(Windows|Users|ProgramData|Program Files)\\|\\AppData\\|Start Menu\\Programs)/ nocase
    condition:
        ah_is_pe or any of them
}

rule PERSIST_Registry_RunKey
{
    meta:
        author      = "AnalysisHub"
        description = "Autostart Run/RunOnce key pointed at an interpreter or script"
        severity    = "high"
        category    = "persistence"
        reference   = "MITRE T1547.001 Registry Run Keys"
    strings:
        $regadd = /reg(\.exe)?\s+add\s[^\n]{0,140}CurrentVersion\\Run(Once|Services|ServicesOnce)?[^\n]{0,200}(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|certutil|\.vbs|\.bat|\.hta|\.scr|-enc)/ nocase
        $psprop = /(Set|New)-ItemProperty[^\n]{0,200}CurrentVersion\\Run(Once)?[^\n]{0,240}(powershell|pwsh|cmd\.exe|wscript|cscript|mshta|rundll32|regsvr32|\.vbs|\.bat|\.hta|-enc)/ nocase
        $regwrite = /RegWrite[^\n]{0,140}CurrentVersion\\Run(Once)?[^\n]{0,200}(powershell|cmd\.exe|wscript|cscript|mshta|\.vbs|\.bat|\.hta)/ nocase
    condition:
        ah_is_windows_script and filesize < 4MB and any of them
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
        $st  = /schtasks(\.exe)?\s+\/create[^\n]{0,240}\/tr\s+["']?[^\n]{0,120}(powershell|pwsh|cmd(\.exe)?\s*\/c|mshta|wscript|cscript|rundll32|regsvr32|certutil|\.bat|\.vbs|\.ps1|\.hta|-enc)/ nocase
        $sys = /schtasks(\.exe)?\s+\/create[^\n]{0,240}\/ru\s+["']?(system|"?nt authority\\system)/ nocase
        $psact = /New-ScheduledTaskAction[^\n]{0,200}-Execute\s+["']?[^\n]{0,60}(powershell|pwsh|cmd|mshta|wscript|cscript|rundll32)/ nocase
        $psreg = "Register-ScheduledTask" nocase
    condition:
        ah_is_windows_script and filesize < 4MB and (
            $st or $sys or ($psreg and $psact)
        )
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
        $sc = /sc(\.exe)?\s+(\\\\[^\s\n]{1,60}\s+)?create\s[^\n]{0,160}binpath\s*=\s*["']?[^\n]{0,140}(cmd(\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|\.bat|\.vbs|\.ps1|-enc)/ nocase
        $ps = /New-Service[^\n]{0,200}-BinaryPathName\s+["']?[^\n]{0,140}(cmd(\.exe)?|powershell|pwsh|mshta|wscript|cscript|rundll32|\.bat|\.vbs|\.ps1)/ nocase
    condition:
        ah_is_windows_script and filesize < 4MB and any of them
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
        $f  = "__EventFilter" ascii nocase
        $c1 = "CommandLineEventConsumer" ascii nocase
        $c2 = "ActiveScriptEventConsumer" ascii nocase
        $b  = "__FilterToConsumerBinding" ascii nocase
        // A hunting script enumerates the same three class names, so a creation
        // verb (or the payload property itself) has to be present.
        $mk1 = /(Set-WmiInstance|New-CimInstance|Register-WmiEvent|PutInstance|\.Put_?\s*\(|instance\s+of\s+__)/ nocase
        $mk2 = /(CommandLineTemplate|ScriptText)\s*=/ nocase
    condition:
        ah_is_windows_script and filesize < 4MB and $f and 1 of ($c*) and $b and 1 of ($mk*)
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
        $ifeo1 = /Image File Execution Options\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe[^\n]{0,200}Debugger/ nocase
        $ifeo2 = /Debugger[^\n]{0,140}Image File Execution Options\\(sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe/ nocase
        $copy  = /(copy|xcopy|Copy-Item)[^\n]{0,100}(cmd|powershell)\.exe[^\n]{0,100}(sethc|utilman|osk|magnify)\.exe/ nocase
    condition:
        // The old third branch ("sethc.exe" and "Debugger" and "cmd.exe"
        // anywhere in the file) fired on the detection scripts written for this
        // technique; the registry value and its target are now one match.
        ah_is_windows_script and filesize < 4MB and any of them
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
        $a = /(reg(\.exe)?\s+add|Set-ItemProperty|New-ItemProperty|RegWrite)[^\n]{0,200}Winlogon[^\n]{0,240}(Userinit|Shell)[^\n]{0,200}(\.exe|\.dll|powershell|cmd|wscript|cscript|mshta)/ nocase
        $b = /Winlogon[^\n]{0,120}(Userinit|Shell)\s*=\s*["'][^"'\n]{0,140}(\.exe|\.dll|powershell)/ nocase
    condition:
        // \bShell\b matches far too much English to be ANDed across a file, so
        // the value name is bound to the Winlogon key and the value data.
        ah_is_windows_script and filesize < 4MB and any of them
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
        $a = /(copy|xcopy|move|Copy-Item|Move-Item|Out-File|WriteAllText|file_put_contents)[^\n]{0,180}Start Menu\\Programs\\Startup/ nocase
        $b = /Start Menu\\Programs\\Startup[^\n]{0,140}\.(exe|bat|vbs|ps1|lnk|hta|js|scr)\b/ nocase
    condition:
        ah_is_windows_script and filesize < 4MB and any of them
}
