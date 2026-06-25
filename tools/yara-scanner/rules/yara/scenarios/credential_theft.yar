/*
  Scenario: CREDENTIAL THEFT
  Detects credential-dumping tooling and techniques: Mimikatz, LSASS dumping,
  registry-hive theft, NTDS extraction, Kerberos abuse, and credential stealers.

  Author: ForensicHub   Updated: 2026-06-26
*/

rule CRED_Mimikatz_Commands
{
    meta:
        author      = "ForensicHub"
        description = "Mimikatz module/command strings — sekurlsa / lsadump / kerberos"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.001 LSASS Memory; gentilkiwi/mimikatz"
    strings:
        $m1 = "sekurlsa::logonpasswords" nocase
        $m2 = "sekurlsa::wdigest" nocase
        $m3 = "sekurlsa::tickets" nocase
        $m4 = "lsadump::sam" nocase
        $m5 = "lsadump::lsa" nocase
        $m6 = "lsadump::dcsync" nocase
        $m7 = "kerberos::golden" nocase
        $m8 = "privilege::debug" nocase
        $m9 = "crypto::capi" nocase
        $brand1 = "gentilkiwi" nocase
        $brand2 = "mimikatz" nocase
        $brand3 = "Benjamin Delpy" nocase
    condition:
        filesize < 15MB and (2 of ($m*) or (1 of ($brand*) and 1 of ($m*)))
}

rule CRED_LSASS_Dumping
{
    meta:
        author      = "ForensicHub"
        description = "LSASS memory dump via comsvcs MiniDump, procdump, or direct API"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.001"
    strings:
        $comsvcs = /rundll32(\.exe)?.{0,40}comsvcs\.dll.{0,20}MiniDump/ nocase
        $minidmp = "MiniDumpWriteDump" ascii
        $pd1     = /procdump(64)?(\.exe)?\s+.{0,40}lsass/ nocase
        $pd2     = /-ma\s+lsass/ nocase
        $lsass   = "lsass.exe" nocase
        $lsass2  = "lsass.dmp" nocase
        $silent  = "-accepteula" nocase
    condition:
        filesize < 20MB and (
            $comsvcs or
            ($minidmp and ($lsass or $lsass2)) or
            (1 of ($pd*) and ($lsass or $lsass2 or $silent))
        )
}

rule CRED_Registry_Hive_Theft
{
    meta:
        author      = "ForensicHub"
        description = "Theft of SAM/SYSTEM/SECURITY registry hives for offline cracking"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.002 Security Account Manager"
    strings:
        $r1 = /reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\sam/ nocase
        $r2 = /reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\system/ nocase
        $r3 = /reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\security/ nocase
        $r4 = /esentutl.{0,40}\\config\\SAM/ nocase
        $shadow = "\\\\.\\C:\\Windows\\System32\\config\\SAM" nocase
    condition:
        filesize < 8MB and (2 of ($r*) or $r4 or $shadow)
}

rule CRED_NTDS_Extraction
{
    meta:
        author      = "ForensicHub"
        description = "Active Directory NTDS.dit extraction (DCSync / ntdsutil / vss)"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.003 NTDS"
    strings:
        $n1 = "ntds.dit" nocase
        $n2 = /ntdsutil.{0,60}ifm/ nocase
        $n3 = "create full" nocase
        $n4 = /vssadmin\s+create\s+shadow/ nocase
        $n5 = "ac i ntds" nocase
        $dcsync = "DsGetNCChanges" ascii
    condition:
        filesize < 10MB and ($dcsync or ($n1 and 1 of ($n2,$n3,$n4,$n5)))
}

rule CRED_Kerberoast_Rubeus
{
    meta:
        author      = "ForensicHub"
        description = "Rubeus / Kerberoasting / AS-REP roasting tooling"
        severity    = "high"
        category    = "credential-theft"
        reference   = "MITRE T1558.003 Kerberoasting"
    strings:
        $r1 = "Rubeus" ascii wide
        $r2 = "kerberoast" nocase
        $r3 = "asreproast" nocase
        $r4 = "[*] Action: Kerberoasting" ascii
        $r5 = "$krb5tgs$" nocase
        $r6 = "$krb5asrep$" nocase
    condition:
        filesize < 10MB and 2 of them
}

rule CRED_Stealer_Tooling
{
    meta:
        author      = "ForensicHub"
        description = "Known credential-stealer utilities (LaZagne / WCE / pwdump / SharpWeb)"
        severity    = "high"
        category    = "credential-theft"
    strings:
        $lz1 = "LaZagne" ascii wide
        $lz2 = "lazagne.config" nocase
        $wce = "Windows Credentials Editor" nocase
        $pw  = "pwdump" nocase
        $sw  = "SharpWeb" ascii
        $chrome = "Login Data" ascii
        $dpapi  = "CryptUnprotectData" ascii
        $vault  = "VaultGetItem" ascii
    condition:
        filesize < 15MB and (
            1 of ($lz*) or $wce or $pw or $sw or
            ($chrome and ($dpapi or $vault))
        )
}
