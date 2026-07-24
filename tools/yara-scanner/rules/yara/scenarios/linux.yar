/*
  Scenario: LINUX THREATS
  Reverse shells, coin miners, persistence primitives, ELF botnets and userland
  rootkits.

  Precision notes:
   * Compiled payloads are gated on the ELF magic (uint32(0)). That matters most
     for the rootkit rule: rkhunter/chkrootkit-style audit scripts name every
     rootkit they look for, and a bare "diamorphine" string used to score
     critical on the very scripts written to find it.
   * Persistence is a *write* to an autostart location. Mentioning
     /etc/ld.so.preload or /etc/cron.d is what hardening and inventory scripts
     do; the redirection into it is what an implant does. Each pattern binds the
     write and the target into one regex.

  Author: AnalysisHub   Updated: 2026-07-24
*/

private rule ah_is_elf
{
    condition:
        uint32(0) == 0x464C457F
}

private rule ah_is_unix_script
{
    strings:
        $shebang = /#!\s*\/(usr\/)?(local\/)?s?bin\/[a-z]/
        $sh1 = /\/bin\/(sh|bash|zsh|dash|ksh)\b/
        $sh2 = /\b(crontab|systemctl|chmod|chattr|iptables|useradd|nohup|mkfifo|socat|ncat|export|umask)\b/
        $sh3 = /\/(etc|tmp|var|dev|proc|opt|home)\//
        $py  = /\b(import\s+(os|sys|socket|subprocess|pty)|python[0-9.]{0,3}\s+-c)\b/
        $pl  = /\bperl\s+-e\b/
    condition:
        any of them
}

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
        // \b on nc: without it the pattern also started inside "sync", "func"…
        $nc = /\bnc(\.traditional)?\b\s+(-[a-z]*e[a-z]*\s+)?[^\n]{0,40}\/bin\/(sh|bash)/ nocase
        $py = /python[0-9.]{0,3}\s+-c\s+[^\n]{0,120}(pty\.spawn|socket\.socket)[^\n]{0,120}\/bin\/(sh|bash)/ nocase
        $pl = /perl\s+-e\s+[^\n]{0,120}(socket|exec)[^\n]{0,40}\/bin\/(sh|bash)/ nocase
        $fifo = /mkfifo\s+[^\n]{0,40};[^\n]{0,40}(\bnc\b|\/bin\/(sh|bash))/ nocase
        $php = /php\s+-r\s+[^\n]{0,120}fsockopen[^\n]{0,120}\/bin\/(sh|bash)/ nocase
        $socat = /socat\s+[^\n]{0,60}exec:\s*['"]?\/bin\/(sh|bash)/ nocase
    condition:
        ah_is_unix_script and filesize < 4MB and any of them
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
        // $s* name the miner or its pool protocol; $w* are algorithm names and
        // config keys that also appear in benchmarking and blockchain code, so
        // they can only corroborate.
        $s1 = "xmrig" nocase
        $s2 = "stratum+tcp://" nocase
        $s3 = "stratum+ssl://" nocase
        $s4 = "--donate-level" nocase
        $s5 = "minerd" nocase
        $s6 = "nicehash" nocase
        $w1 = "cryptonight" nocase
        $w2 = "randomx" nocase
        $w3 = "\"algo\":" ascii
        $w4 = /(pool|xmr)\.[a-z0-9.\-]{3,40}:[0-9]{2,5}/ nocase
        $w5 = "--cpu-priority" nocase
    condition:
        filesize < 30MB and (
            2 of ($s*) or
            (1 of ($s*) and 1 of ($w*)) or
            (ah_is_elf and 1 of ($s1,$s4,$s5))
        )
}

rule LIN_Persistence
{
    meta:
        author      = "AnalysisHub"
        description = "Linux persistence — write into cron, ld.so.preload, rc.local, systemd or authorized_keys"
        severity    = "high"
        category    = "linux"
        reference   = "MITRE T1053.003 / T1574.006 / T1037 / T1098.004"
    strings:
        $cron_write = /(echo|printf|cat|tee)[^\n]{0,200}>>?\s*\/(etc\/cron\.(d|daily|hourly|weekly)|var\/spool\/cron)/ nocase
        $cron_pipe  = /(echo|printf)[^\n]{0,200}\|\s*crontab\s+-/ nocase
        $cron_job   = /(\*|[0-9]{1,2})\s+\*\s+\*\s+\*\s+\*\s+[^\n]{0,120}(curl|wget|bash\s+-i|\/dev\/tcp|base64\s+-d|nc\s)/ nocase
        // Mentioning /etc/ld.so.preload is an audit; writing to it is a rootkit.
        $ld_write   = /(echo|printf|cat|tee)[^\n]{0,160}>>?\s*\/etc\/ld\.so\.preload/ nocase
        $rc_write   = /(echo|printf|cat|tee)[^\n]{0,200}>>?\s*\/etc\/rc\.local/ nocase
        $ak_write   = /(echo|printf|cat|tee)[^\n]{0,240}ssh-(rsa|ed25519|dss)\s[^\n]{0,400}>>?\s*[^\n]{0,80}authorized_keys/ nocase
        $unit_write = /(>|tee\s+(-a\s+)?)\/(etc|usr\/lib|lib)\/systemd\/system\/[^\s\n]{1,60}\.service/ nocase
        $unit_exec  = /ExecStart\s*=[^\n]{0,160}(\/tmp\/|\/dev\/shm\/|curl|wget|base64\s+-d|bash\s+-c|nc\s+-)/ nocase
    condition:
        ah_is_unix_script and filesize < 4MB and (
            1 of ($cron_write, $cron_pipe, $cron_job, $ld_write, $rc_write, $ak_write) or
            ($unit_write and $unit_exec)
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
        ah_is_elf and filesize > 1KB and filesize < 8MB and (
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
        $diam  = "diamorphine" nocase
        $magic = "give_root" ascii
        $hook1 = "readdir" ascii
        $hook2 = "readdir64" ascii
        $dlsym = "dlsym" ascii
        $orig  = "RTLD_NEXT" ascii
    condition:
        // A family name on its own is exactly what a rootkit *hunting* script
        // contains, so it only reports from a shared object / executable. In any
        // other file the full interposition profile has to be present.
        filesize < 4MB and (
            (ah_is_elf and 1 of ($h1,$diam,$magic)) or
            ($dlsym and $orig and 1 of ($hook1,$hook2) and 1 of ($h1,$h2,$diam,$magic))
        )
}
