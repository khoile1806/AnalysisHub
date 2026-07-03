/*
  Scenario: LINUX THREATS
  Detects Linux reverse shells, crypto-miners, persistence, rootkits and
  common ELF backdoors. Binary rules are gated on the ELF magic to cut FPs.

  Author: AnalysisHub   Updated: 2026-06-26
*/

rule LIN_Reverse_Shell
{
    meta:
        author      = "AnalysisHub"
        description = "Interactive reverse shell one-liners (bash/python/perl/nc)"
        severity    = "critical"
        category    = "linux"
        reference   = "MITRE T1059.004 Unix Shell"
    strings:
        $b1 = /bash\s+-i\s+>&?\s*\/dev\/tcp\// nocase
        $b2 = /\/dev\/(tcp|udp)\/[0-9]{1,3}(\.[0-9]{1,3}){3}\// nocase
        $nc = /nc(\.traditional)?\s+(-[a-z]*e[a-z]*\s+)?.{0,40}\/bin\/(sh|bash)/ nocase
        $py = /python[0-9.]*\s+-c\s+.{0,120}(pty\.spawn|socket\.socket).{0,120}(\/bin\/(sh|bash))/ nocase
        $pl = /perl\s+-e\s+.{0,120}(socket|exec).{0,40}(\/bin\/(sh|bash))/ nocase
        $fifo = /mkfifo\s+.{0,40};.{0,40}(nc|\/bin\/(sh|bash))/ nocase
        $php = /php\s+-r\s+.{0,120}fsockopen.{0,120}(\/bin\/(sh|bash))/ nocase
    condition:
        filesize < 4MB and any of them
}

rule LIN_CryptoMiner
{
    meta:
        author      = "AnalysisHub"
        description = "Cryptocurrency miner (XMRig / stratum config) — coin-mining payload"
        severity    = "high"
        category    = "linux"
        reference   = "MITRE T1496 Resource Hijacking"
    strings:
        $x1 = "xmrig" nocase
        $x2 = "stratum+tcp://" nocase
        $x3 = "stratum+ssl://" nocase
        $x4 = "--donate-level" nocase
        $x5 = "cryptonight" nocase
        $x6 = "randomx" nocase
        $x7 = "minerd" nocase
        $x8 = "\"algo\":" ascii
        $pool = /(pool|xmr)\.[a-z0-9.\-]+:[0-9]{2,5}/ nocase
    condition:
        filesize < 30MB and (2 of ($x*) or ($x2 and $pool))
}

rule LIN_Persistence
{
    meta:
        author      = "AnalysisHub"
        description = "Linux persistence via cron, ld.so.preload, rc.local, or SSH authorized_keys"
        severity    = "high"
        category    = "linux"
        reference   = "MITRE T1053.003 / T1574.006 / T1037"
    strings:
        $cron1 = /\/(etc\/cron\.(d|daily|hourly)|var\/spool\/cron)/ nocase
        $cron2 = /\*\s+\*\s+\*\s+\*\s+\*\s+.{0,80}(curl|wget|bash\s+-i|\/dev\/tcp)/ nocase
        $pre   = "/etc/ld.so.preload" nocase
        $rc    = "/etc/rc.local" nocase
        $ak1   = "authorized_keys" nocase
        $ak2   = /echo\s+.{0,80}ssh-(rsa|ed25519).{0,120}>>\s*.{0,40}authorized_keys/ nocase
        $dl    = /(curl|wget)\s+.{0,120}(\||;|&&)\s*(sh|bash)/ nocase
    condition:
        filesize < 4MB and (
            ($cron1 and ($cron2 or $dl)) or
            ($pre) or
            ($rc and $dl) or
            $ak2 or
            ($ak1 and $dl)
        )
}

rule LIN_ELF_Backdoor_Strings
{
    meta:
        author      = "AnalysisHub"
        description = "Known Linux DDoS/IoT botnet & backdoor family strings (Mirai/Tsunami/Gafgyt/BillGates)"
        severity    = "critical"
        category    = "linux"
    strings:
        $mirai1 = "/bin/busybox" ascii
        $mirai2 = "MIRAI" ascii
        $mirai3 = "/dev/watchdog" ascii
        $mirai4 = "TSource Engine Query" ascii
        $gafgyt = "gayfgt" ascii
        $tsunami = "PRIVMSG" ascii          // IRC C2 (Tsunami/Kaiten)
        $bill   = "BillGates" ascii
        $kaiten = "NICK %s" ascii
    condition:
        uint32(0) == 0x464c457f and filesize < 8MB and (
            ($mirai1 and 1 of ($mirai2,$mirai3,$mirai4)) or
            $gafgyt or
            ($tsunami and $kaiten) or
            $bill
        )
}

rule LIN_Rootkit_LD_PRELOAD
{
    meta:
        author      = "AnalysisHub"
        description = "Userland LD_PRELOAD rootkit (process/file hiding) — libprocesshider / Diamorphine markers"
        severity    = "critical"
        category    = "linux"
        reference   = "MITRE T1014 Rootkit"
    strings:
        $h1 = "libprocesshider" nocase
        $h2 = "process_to_filter" ascii
        $hook1 = "readdir" ascii
        $hook2 = "readdir64" ascii
        $dlsym = "dlsym" ascii
        $orig  = "RTLD_NEXT" ascii
        $diam  = "diamorphine" nocase
        $magic = "give_root" ascii
    condition:
        filesize < 4MB and (
            $h1 or $diam or $magic or
            ($dlsym and $orig and 1 of ($hook1,$hook2) and $h2)
        )
}
