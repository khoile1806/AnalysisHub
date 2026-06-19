# Playbook: Security Assessment & Threat Hunting (Evidence Collection)

> **Loại:** Proactive hunting / Security assessment · **Nền tảng:** Windows + Linux

---

## 1. Mục tiêu & Mục đích
**Mục đích:** Thu thập có hệ thống các bằng chứng cấu hình, tiến trình, mạng, cơ chế persistence và log kiểm toán trên Windows + Linux để **chủ động săn tìm dấu hiệu xâm nhập** và đánh giá an toàn hệ thống — trước khi xảy ra sự cố hoặc để xác nhận một nghi ngờ.

**Đạt được:**
- Ảnh chụp toàn diện trạng thái hệ thống (snapshot).
- Phát hiện tiến trình lạ, kết nối C2, tài khoản trái phép, backdoor persistence.
- Bằng chứng có mốc thời gian để dựng timeline.
- IOC để hunt rộng trên SIEM.

## 2. Khi nào dùng
- Rà soát an toàn định kỳ (proactive hunting).
- Xác minh một nghi ngờ chưa rõ (alert mơ hồ, hành vi lạ).
- Bước thu thập đầu tiên trước khi chuyển sang playbook chuyên sâu (Webshell/Ransomware).

## 3. Kết quả cần đạt
- [ ] Thu thập đủ 5 nhóm bằng chứng (System, Identity, Process/Network, Persistence, Logs) trên mỗi máy.
- [ ] Đánh dấu các bất thường (process không path, kết nối lạ, account UID=0, authorized_keys lạ…).
- [ ] IOC + timeline ban đầu.

## 4. Cần Hunt Những Gì (5 nhóm bằng chứng)

| Nhóm | Mục tiêu hunt | Dấu hiệu bất thường |
|---|---|---|
| **System & Patches** | Môi trường + bản vá | Thiếu patch quan trọng → CVE khai thác được |
| **Identity & Access** | Tài khoản & quyền | Account lạ, admin trái phép, UID=0, session ngoài giờ |
| **Process & Network** | Tiến trình & kết nối | Process không path, parent lạ, C2 beaconing |
| **Persistence** | Cơ chế tự khởi động | Task/cron/service/Run key/authorized_keys lạ |
| **Logs & Audit** | Dòng thời gian sự cố | Brute-force, cài service mới, script PS đáng ngờ |

## 5. Các bước thực hiện

> Trong ForensicHub: dùng **Evidence & Compliance → profile Forensic Collection** (đã có sẵn các check bên dưới, mỗi check kèm note "Phục vụ" + tool gợi ý). Chọn agent → Run theo nhóm.

### PHẦN A — WINDOWS

**A1. System & Patches** — *xác định môi trường + lỗ hổng chưa vá*
```cmd
systeminfo
wmic qfe list brief /format:table
```
```powershell
Get-HotFix | Sort-Object InstalledOn -Descending | Select-Object HotFixID,Description,InstalledOn -First 20
```

**A2. Identity & Access** — *phát hiện tài khoản lạ / admin trái phép*
```cmd
net user
net localgroup administrators
query user
```

**A3. Process & Network** — *tiến trình độc hại / C2 beaconing*
```powershell
Get-Process | Where-Object {$_.Path -ne $null} | Select-Object Id,Name,Path,Company | Format-Table -AutoSize
Get-NetTCPConnection -State Established | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,OwningProcess,@{N="Proc";E={(Get-Process -Id $_.OwningProcess).Name}} | Format-Table -AutoSize
```
```cmd
netstat -ano
```
> 🔎 Chú ý: process **không có Path**, **parent bất thường** (web process spawn cmd/powershell), kết nối tới IP lạ lặp lại (beaconing).

**A4. Persistence** — *mã độc tự khởi động*
```cmd
schtasks /query /fo LIST /v
```
```powershell
Get-ScheduledTask | Where-Object {$_.TaskPath -notlike "\Microsoft*"} | Select TaskName,TaskPath,State
Get-ItemProperty HKLM:\Software\Microsoft\Windows\CurrentVersion\Run
Get-ItemProperty HKCU:\Software\Microsoft\Windows\CurrentVersion\Run
```

**A5. Event Logs (hunting nhanh + export)** — *dựng timeline*
```powershell
# Đăng nhập thành/bại
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625} -MaxEvents 50
# Cài service mới (backdoor / leo quyền)
Get-WinEvent -FilterHashtable @{LogName='System'; ID=4697} -EA SilentlyContinue
# Script PowerShell đáng ngờ
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4104} -EA SilentlyContinue -MaxEvents 20
```
> Event ID quan trọng: **4624** logon thành công · **4625** logon thất bại · **4697** service install · **4104** PS script block.

### PHẦN B — LINUX

**B1. System & Network/Firewall**
```bash
uname -a ; cat /etc/os-release
sudo iptables -L -n -v   # hoặc: sudo ufw status verbose
grep -E "^(PermitRootLogin|PasswordAuthentication|PubkeyAuthentication)" /etc/ssh/sshd_config
```
> 🔎 `PermitRootLogin yes` / `PasswordAuthentication yes` = cấu hình lỏng, cửa brute-force.

**B2. Identity & Logins**
```bash
cat /etc/passwd | grep -E "/bin/bash|/bin/sh"
grep -Po '^sudo.+:\K.*' /etc/group   # hoặc 'wheel' trên RHEL
last -n 20 ; sudo lastb -n 20
```
> 🔎 Tài khoản **UID=0** ngoài root, **lastb** bùng nổ = brute-force.

**B3. Process & Network**
```bash
ps auxef ; pstree -ap
sudo ss -antup   # hoặc: sudo netstat -pant
```
> 🔎 Reverse shell: process con của web/sshd kết nối ra ngoài.

**B4. Persistence**
```bash
crontab -l ; cat /etc/crontab ; ls -la /etc/cron.*
systemctl list-unit-files --type=service --state=enabled
cat /root/.ssh/authorized_keys 2>/dev/null
cat /home/*/.ssh/authorized_keys 2>/dev/null
```
> 🔎 authorized_keys lạ = backdoor SSH; cron/systemd lạ = persistence.

**B5. Audit Logs**
```bash
tail -n 100 /var/log/auth.log    # Ubuntu/Debian
tail -n 100 /var/log/secure      # CentOS/RHEL
cat ~/.bash_history | tail -n 50
cat /home/*/.bash_history 2>/dev/null
```

## 6. Công cụ trong ForensicHub
- **Evidence & Compliance** (Forensic Collection) — toàn bộ check A1–A5, B1–B5 đã có sẵn.
- **AI Analysis** — tóm tắt phát hiện, đánh giá bất thường.
- **ELK Threat Hunting** — hunt IOC trên log tập trung.
- **Attack Timeline** (AI Extract/Rebuild) — dựng dòng thời gian.
- **Offline Bundle** — chạy trên máy không có mạng.

## 7. Công cụ / nền tảng bên ngoài gợi ý

### Tự động hoá thu thập (single host)
| Nền tảng | Công cụ |
|---|---|
| Windows | **KAPE** (Event logs, Registry, Prefetch, MFT), **CyLR** |
| Linux | **UAC** (Unix Artifact Collector) |

### Phân tích chuyên sâu
| Nhu cầu | Công cụ |
|---|---|
| Phân tích event log nhanh | **Hayabusa**, **DeepBlueCLI**, Chainsaw |
| Artifact Windows | Eric Zimmerman tools (MFTECmd, RECmd…) |
| Timeline đa nguồn | **Plaso/log2timeline**, Timesketch |
| Kiểm tra hardening | **Lynis** (Linux), **ssh-audit**, CIS-CAT |

### Quy mô lớn (Enterprise / Live Response)
- **Velociraptor (khuyên dùng):** agent Windows + Linux, viết **VQL** để săn tìm & thu thập bằng chứng từ hàng ngàn máy qua web console tập trung.
- **OSQuery / Wazuh:** truy vấn trạng thái endpoint dạng SQL trên toàn fleet.

## 8. IOC cần thu thập
IP/domain C2 · Hash binary · Path process lạ · Tài khoản bất thường (UID=0) · authorized_keys lạ · cron/task/service lạ · Event quanh thời điểm sự cố.

## 9. Lưu ý
- Tuân thủ **Order of Volatility** (RAM → network → disk) nếu nghi malware in-memory → dump RAM trước.
- Bảo toàn **chain of custody** (timestamp + hostname + hash).
- Đây là bước **hunting/triage** — khi xác định loại tấn công, chuyển playbook chuyên sâu tương ứng.
