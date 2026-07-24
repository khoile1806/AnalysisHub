/*
  Scenario: CREDENTIAL THEFT
  Mimikatz, LSASS dumping, registry-hive theft, NTDS extraction, Kerberos abuse
  and credential stealers.

  Precision notes:
   * Tool names and file names ("ntds.dit", "lsass.exe", "mimikatz") are written
     down by defenders at least as often as by attackers, so a bare name never
     fires — the rule wants the *operation* performed on it, expressed as one
     regex rather than two independently matched strings.
   * `.` never crosses a newline in YARA, so [^\n] bounds keep a command-line
     pattern inside a single command line instead of spanning a whole file.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_pe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule CRED_Mimikatz_Commands
{
    meta:
        author      = "AnalysisHub"
        description = "Mimikatz module/command strings — sekurlsa / lsadump / kerberos"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.001 LSASS Memory; gentilkiwi/mimikatz"
    strings:
        // $u* are module::command pairs with no meaning outside mimikatz, so
        // one is enough. $m* are weaker (privilege::debug and crypto::capi are
        // quoted in a lot of defensive material) and need a second indicator.
        $u1 = "sekurlsa::logonpasswords" nocase
        $u2 = "lsadump::dcsync" nocase
        $u3 = "kerberos::golden" nocase
        $u4 = "lsadump::sam" nocase
        $u5 = "sekurlsa::pth" nocase
        $m1 = "sekurlsa::wdigest" nocase
        $m2 = "sekurlsa::tickets" nocase
        $m3 = "lsadump::lsa" nocase
        $m4 = "privilege::debug" nocase
        $m5 = "crypto::capi" nocase
        $m6 = "token::elevate" nocase
        $m7 = "misc::skeleton" nocase
        // The bare word "mimikatz" is written far more often by defenders than
        // by attackers; the binary name and the banner are the artefacts.
        $brand1 = "gentilkiwi" nocase
        $brand2 = /mimikatz(\.exe|\s+\d+\.\d+|\s*#\s*)/ nocase
        $brand3 = "Benjamin Delpy" nocase
    condition:
        filesize < 15MB and (
            1 of ($u*) or
            2 of ($m*) or
            (1 of ($brand*) and 1 of ($m*))
        )
}

rule CRED_LSASS_Dumping
{
    meta:
        author      = "AnalysisHub"
        description = "LSASS memory dump via comsvcs MiniDump, procdump, or direct API"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.001"
    strings:
        $comsvcs = /rundll32(\.exe)?[^\n]{0,60}comsvcs\.dll[^\n]{0,30}(MiniDump|#\+?24)/ nocase
        $pd1     = /procdump(64)?(\.exe)?[^\n]{0,60}lsass/ nocase
        $pd2     = /-ma\s+lsass(\.exe)?/ nocase
        $nano    = "nanodump" nocase
        $minidmp = "MiniDumpWriteDump" ascii
        $lsass   = "lsass.exe" nocase
        $lsass2  = "lsass.dmp" nocase
    condition:
        // "-accepteula" was dropped as a corroborator: it is a Sysinternals
        // flag, not evidence, and it made any procdump reference sufficient.
        filesize < 20MB and (
            $comsvcs or $pd1 or $pd2 or $nano or
            ($minidmp and ($lsass or $lsass2))
        )
}

rule CRED_Registry_Hive_Theft
{
    meta:
        author      = "AnalysisHub"
        description = "Theft of SAM/SYSTEM/SECURITY registry hives for offline cracking"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.002 Security Account Manager"
    strings:
        $r1 = /reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\sam\b/ nocase
        $r3 = /reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\security\b/ nocase
        $r4 = /esentutl[^\n]{0,40}\\config\\SAM/ nocase
        // Saving SYSTEM alone has legitimate uses (driver/boot troubleshooting),
        // so it only counts next to SAM or SECURITY.
        $r2 = /reg(\.exe)?\s+save\s+hk(lm|ey_local_machine)\\system\b/ nocase
        $shadow = "\\\\.\\C:\\Windows\\System32\\config\\SAM" nocase
    condition:
        filesize < 8MB and (
            $r1 or $r3 or $r4 or $shadow or
            ($r2 and 1 of ($r1,$r3,$r4))
        )
}

rule CRED_NTDS_Extraction
{
    meta:
        author      = "AnalysisHub"
        description = "Active Directory NTDS.dit extraction (DCSync / ntdsutil IFM / shadow copy)"
        severity    = "critical"
        category    = "credential-theft"
        reference   = "MITRE T1003.003 NTDS"
    strings:
        $dcsync = "DsGetNCChanges" ascii
        // "create full" and "ac i ntds" only mean something as ntdsutil syntax,
        // so they are bound to the tool inside one regex instead of being ANDed
        // with a loose "ntds.dit" mention somewhere else in the file.
        $ifm    = /ntdsutil(\.exe)?[^\n]{0,120}(ifm|create\s+full|ac\s+i\s+ntds)/ nocase
        $acintds = "ac i ntds" nocase
        $ntds   = "ntds.dit" nocase
        $vss    = /vssadmin(\.exe)?\s+create\s+shadow/ nocase
        $copy   = /(copy|xcopy|Copy-Item)[^\n]{0,120}ntds\.dit/ nocase
    condition:
        filesize < 10MB and (
            $dcsync or $ifm or $acintds or
            ($ntds and ($vss or $copy))
        )
}

rule CRED_Kerberoast_Rubeus
{
    meta:
        author      = "AnalysisHub"
        description = "Rubeus / Kerberoasting / AS-REP roasting tooling"
        severity    = "high"
        category    = "credential-theft"
        reference   = "MITRE T1558.003 Kerberoasting"
    strings:
        $h1 = "$krb5tgs$" nocase
        $h2 = "$krb5asrep$" nocase
        $h3 = "[*] Action: Kerberoasting" ascii
        $r1 = "Rubeus" ascii wide
        $r2 = "kerberoast" nocase
        $r3 = "asreproast" nocase
        $r4 = "Invoke-Kerberoast" nocase
    condition:
        // The hashcat-format prefixes are extracted material, not a tool name —
        // one is already an incident.
        filesize < 10MB and (1 of ($h*) or 2 of ($r*))
}

rule CRED_Stealer_Tooling
{
    meta:
        author      = "AnalysisHub"
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
            // "Login Data" is two English words; the DPAPI/Vault pairing is only
            // credible inside a compiled binary, where it is the stealer profile.
            (ah_is_pe and $chrome and ($dpapi or $vault))
        )
}

rule CRED_Browser_Credential_Theft
{
    meta:
        author      = "AnalysisHub"
        description = "Script reads a browser credential store and decrypts it — infostealer behaviour"
        severity    = "high"
        category    = "credential-theft"
        reference   = "MITRE T1555.003 Credentials from Web Browsers"
    strings:
        $store1 = /(Google\\Chrome|Microsoft\\Edge|BraveSoftware|Mozilla\\Firefox)\\+User Data/ nocase
        $store2 = /Login Data/ ascii
        $store3 = "logins.json" nocase
        $store4 = "key4.db" nocase
        $decrypt1 = "CryptUnprotectData" ascii
        $decrypt2 = "win32crypt" nocase
        $decrypt3 = "os_crypt" nocase
        $decrypt4 = /AES\s*GCM|AESGCM|encrypted_key/ nocase
        $query = /SELECT[^\n]{0,60}(password_value|encryptedUsername)/ nocase
    condition:
        // Reading the store is not enough — legitimate backup and migration
        // tooling does that. Decrypting the secret is the theft.
        filesize < 4MB and (
            ($query and 1 of ($decrypt*)) or
            (1 of ($store*) and 2 of ($decrypt*))
        )
}
