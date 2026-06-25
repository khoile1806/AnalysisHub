/*
  Scenario: RANSOMWARE
  Detects ransomware binaries, ransom notes, and the recovery-destruction
  behaviour that precedes encryption. Rules favour multi-string combinations
  and filesize/magic gating to keep false positives low.

  Author: ForensicHub   Updated: 2026-06-26
*/

rule RANSOM_Note_Generic
{
    meta:
        author      = "ForensicHub"
        description = "Generic ransom note — extortion wording plus a payment/contact channel"
        severity    = "high"
        category    = "ransomware"
        reference   = "Common ransom-note linguistics across families"
    strings:
        $enc1 = "your files have been encrypted" nocase
        $enc2 = "your files are encrypted" nocase
        $enc3 = "all your files have been encrypted" nocase
        $enc4 = "files has been encrypted" nocase
        $enc5 = "have been locked" nocase

        $pay1 = "bitcoin" nocase
        $pay2 = ".onion" nocase
        $pay3 = "decryptor" nocase
        $pay4 = "decrypt your files" nocase
        $pay5 = "private key" nocase
        $pay6 = "pay the ransom" nocase
        $pay7 = "tox id" nocase
        $pay8 = /[a-z0-9._%+\-]+@(protonmail|tutanota|cock\.li|onionmail|airmail)/ nocase
    condition:
        filesize < 150KB and any of ($enc*) and 2 of ($pay*)
}

rule RANSOM_Recovery_Destruction
{
    meta:
        author      = "ForensicHub"
        description = "Shadow-copy / backup / recovery destruction — pre-encryption sabotage"
        severity    = "critical"
        category    = "ransomware"
        reference   = "MITRE T1490 Inhibit System Recovery"
    strings:
        $vss1 = /vssadmin(\.exe)?\s+delete\s+shadows/ nocase
        $vss2 = /wmic\s+shadowcopy\s+delete/ nocase
        $vss3 = "Win32_ShadowCopy" nocase
        $wb   = /wbadmin\s+delete\s+(catalog|systemstatebackup|backup)/ nocase
        $bcd1 = /bcdedit.{0,40}recoveryenabled\s+no/ nocase
        $bcd2 = /bcdedit.{0,40}bootstatuspolicy\s+ignoreallfailures/ nocase
        $cat  = /wbadmin\s+delete\s+catalog\s+-quiet/ nocase
        $rstr = /Disable-ComputerRestore|SRRemoveRestorePoint/ nocase
    condition:
        filesize < 8MB and 2 of them
}

rule RANSOM_Mass_Encryption_API
{
    meta:
        author      = "ForensicHub"
        description = "PE combining crypto APIs, enumeration and recovery sabotage — encryptor profile"
        severity    = "critical"
        category    = "ransomware"
    strings:
        $c1 = "CryptEncrypt" ascii
        $c2 = "CryptGenKey" ascii
        $c3 = "CryptAcquireContext" ascii
        $c4 = "BCryptEncrypt" ascii
        $e1 = "FindFirstFileW" ascii
        $e2 = "FindNextFileW" ascii
        $e3 = "GetLogicalDriveStringsW" ascii
        $r1 = "vssadmin" nocase
        $r2 = "delete shadows" nocase
        $note = /README|HOW.?TO.?DECRYPT|RECOVER.?FILES|_readme\.txt/ nocase
    condition:
        uint16(0) == 0x5A4D and filesize < 12MB and
        1 of ($c*) and 1 of ($e*) and (1 of ($r*) or $note)
}

rule RANSOM_Family_Markers
{
    meta:
        author      = "ForensicHub"
        description = "Distinctive strings of well-known ransomware families"
        severity    = "critical"
        category    = "ransomware"
        reference   = "LockBit / Conti / BlackCat / REvil / Ryuk / Hive / Phobos / STOP-Djvu"
    strings:
        $lockbit1 = "LockBit" ascii wide
        $lockbit2 = "Restore-My-Files.txt" nocase
        $lockbit3 = ".lockbit" nocase
        $conti1   = "CONTI_LOG" ascii
        $conti2   = "R3ADM3.txt" nocase
        $conti3   = "conti_readme.txt" nocase
        $alphv1   = "RECOVER-" ascii
        $alphv2   = "-FILES.txt" ascii
        $alphv3   = "bcdedit /set {default}" nocase
        $revil1   = "sodinokibi" nocase
        $revil2   = "revil" nocase
        $ryuk1    = "RyukReadMe" nocase
        $ryuk2    = "UNIQUE_ID_DO_NOT_REMOVE" ascii
        $hive1    = "HOW_TO_DECRYPT.txt" nocase
        $phobos1  = "info.hta" nocase
        $stop1    = "_readme.txt" ascii
        $stop2    = "personal ID" nocase
    condition:
        filesize < 12MB and (
            ($lockbit1 and ($lockbit2 or $lockbit3)) or
            (any of ($conti*)) or
            (all of ($alphv*)) or
            (any of ($revil*)) or
            (any of ($ryuk*)) or
            $hive1 or
            ($stop1 and $stop2) or
            $phobos1
        )
}

rule RANSOM_Encrypted_Extension_Marker
{
    meta:
        author      = "ForensicHub"
        description = "Script/binary appends a known ransomware extension to victim files"
        severity    = "high"
        category    = "ransomware"
    strings:
        $a = /\.(locked|crypted|encrypted|enc|crypt|ezz|exx|zzz|micro|locky|cerber|wallet|onion|globe|wncry|wcry)\b/ nocase
        $b = "rename" nocase
        $c = "MoveFile" nocase
        $d = /\.(locked|encrypted|crypt)["']/ nocase
    condition:
        filesize < 4MB and #a > 3 and (1 of ($b, $c) or $d)
}
