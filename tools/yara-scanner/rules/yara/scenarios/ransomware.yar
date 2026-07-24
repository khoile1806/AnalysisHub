/*
  Scenario: RANSOMWARE
  Ransom notes, the recovery-destruction that precedes encryption, encryptor
  binaries, family markers and renamed-file extensions.

  Precision notes:
   * The destruction commands are unambiguous verbs, not nouns: "vssadmin delete
     shadows" is never a backup script, whereas "vssadmin list shadows" and
     "Win32_ShadowCopy" are exactly what a backup script contains. Requiring two
     of a mixed set meant a real single-command wipe was missed while a pair of
     harmless mentions scored critical; each destructive command now stands on
     its own and the harmless mentions can no longer trigger at all.
   * Bare "README" was removed from the encryptor note pattern — it matched every
     source tree on disk.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_pe
{
    condition:
        uint16(0) == 0x5A4D and uint32(uint32(0x3C)) == 0x00004550
}

rule RANSOM_Note_Generic
{
    meta:
        author      = "AnalysisHub"
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
        $enc6 = "your network has been breached" nocase

        $pay1 = "bitcoin" nocase
        $pay2 = ".onion" nocase
        $pay3 = "decryptor" nocase
        $pay4 = "decrypt your files" nocase
        $pay5 = "private key" nocase
        $pay6 = "pay the ransom" nocase
        $pay7 = "tox id" nocase
        $pay8 = /[a-z0-9._%+\-]+@(protonmail|tutanota|cock\.li|onionmail|airmail)/ nocase
    condition:
        filesize > 100 and filesize < 150KB and any of ($enc*) and 2 of ($pay*)
}

rule RANSOM_Recovery_Destruction
{
    meta:
        author      = "AnalysisHub"
        description = "Shadow-copy / backup / recovery destruction — pre-encryption sabotage"
        severity    = "critical"
        category    = "ransomware"
        reference   = "MITRE T1490 Inhibit System Recovery"
    strings:
        $vss1 = /vssadmin(\.exe)?(\s+\/?\w+)?\s+delete\s+shadows/ nocase
        $vss2 = /wmic(\.exe)?\s+shadowcopy\s+delete/ nocase
        // Win32_ShadowCopy on its own is the class every backup tool queries;
        // only the removal call counts.
        $vss3 = /Win32_Shadowcopy[^\n]{0,140}(Remove-WmiObject|Remove-CimInstance|\.Delete\s*\(|Delete\(\))/ nocase
        $wb1  = /wbadmin(\.exe)?\s+delete\s+(catalog|systemstatebackup|backup)/ nocase
        $bcd1 = /bcdedit[^\n]{0,60}recoveryenabled\s+no/ nocase
        $bcd2 = /bcdedit[^\n]{0,60}bootstatuspolicy\s+ignoreallfailures/ nocase
        $rstr = /(Disable-ComputerRestore|SRRemoveRestorePoint|vssadmin(\.exe)?\s+resize\s+shadowstorage)/ nocase
    condition:
        filesize < 8MB and (
            1 of ($vss*) or $wb1 or 1 of ($bcd*) or
            // Restore-point tampering is also a (rare) tuning step, so it needs
            // company before it counts.
            ($rstr and 1 of ($vss*, $wb1, $bcd*))
        )
}

rule RANSOM_Mass_Encryption_API
{
    meta:
        author      = "AnalysisHub"
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
        $note = /(HOW.{0,3}TO.{0,3}DECRYPT|RECOVER.{0,3}(YOUR.{0,3})?FILES|DECRYPT.{0,3}(MY|YOUR).{0,3}FILES|_readme\.txt|RESTORE.{0,3}FILES)/ nocase
    condition:
        ah_is_pe and filesize > 1KB and filesize < 12MB and
        1 of ($c*) and 1 of ($e*) and (1 of ($r*) or $note)
}

rule RANSOM_Family_Markers
{
    meta:
        author      = "AnalysisHub"
        description = "Distinctive strings of well-known ransomware families"
        severity    = "critical"
        category    = "ransomware"
        reference   = "LockBit / Conti / BlackCat / REvil / Ryuk / Hive / Phobos / STOP-Djvu / Akira / Black Basta / Clop"
    strings:
        $lockbit1 = "LockBit" ascii wide
        $lockbit2 = "Restore-My-Files.txt" nocase
        $lockbit3 = ".lockbit" nocase
        $lockbit4 = "LockBit_Ransomware.hta" nocase
        $conti1   = "CONTI_LOG" ascii
        $conti2   = "R3ADM3.txt" nocase
        $conti3   = "conti_readme.txt" nocase
        $alphv1   = "RECOVER-" ascii
        $alphv2   = "-FILES.txt" ascii
        $alphv3   = "bcdedit /set {default}" nocase
        $revil1   = "sodinokibi" nocase
        $revil2   = /\bREvil\b/
        $revil3   = "-DECRYPT.txt" ascii
        $ryuk1    = "RyukReadMe" nocase
        $ryuk2    = "UNIQUE_ID_DO_NOT_REMOVE" ascii
        $hive1    = "HOW_TO_DECRYPT.txt" nocase
        $phobos1  = "info.hta" nocase
        $stop1    = "_readme.txt" ascii
        $stop2    = "personal ID" nocase
        $akira1   = "akira_readme.txt" nocase
        $basta1   = "instructions_read_me.txt" nocase
        $clop1    = "ClopReadMe.txt" nocase
        $medusa1  = "!!!READ_ME_MEDUSA!!!.txt" nocase
    condition:
        filesize < 12MB and (
            ($lockbit1 and 1 of ($lockbit2,$lockbit3,$lockbit4)) or
            any of ($conti*) or
            all of ($alphv*) or
            // "REvil" as a word appears in every threat-intel write-up, so it
            // needs the note extension next to it; sodinokibi does not.
            $revil1 or ($revil2 and $revil3) or
            any of ($ryuk*) or
            $hive1 or $akira1 or $basta1 or $clop1 or $medusa1 or
            ($stop1 and $stop2) or
            $phobos1
        )
}

rule RANSOM_Encrypted_Extension_Marker
{
    meta:
        author      = "AnalysisHub"
        description = "Script/binary appends a known ransomware extension to victim files"
        severity    = "high"
        category    = "ransomware"
    strings:
        // .enc/.crypt/.onion/.wallet were removed from the counted set: they are
        // ordinary file suffixes in crypto, Tor and wallet tooling and a handful
        // of occurrences plus the word "rename" was not evidence of anything.
        $a = /\.(locked|crypted|encrypted|cerber|locky|wncry|wcry|micro|ezz|exx|zzz|globe|djvu|lockbit|conti|basta|akira|phobos|makop|mallox|ryuk|crysis|dharma)\b/ nocase
        $b = /(rename|MoveFile|Move-Item|os\.rename|\.rename\s*\()/ nocase
        $c = /\.(locked|encrypted|crypted|wncry|lockbit)["'`]/ nocase
    condition:
        filesize < 4MB and #a > 3 and ($b or $c)
}
