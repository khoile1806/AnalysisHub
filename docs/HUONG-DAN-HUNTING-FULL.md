# Hướng dẫn HUNTING FULL — Case SeaView Hotel (runbook thực hành)

> Runbook cầm-tay-chỉ-việc để điều tra **toàn bộ** vụ xâm nhập SeaView trên VM `velociraptor`
> (`192.168.200.156`) bằng AnalysisHub. Mỗi bước ghi **thao tác cụ thể + kết quả kỳ vọng (khớp
> ground truth thật)**. Chi tiết kỹ thuật đầy đủ xem [DEMO-HUNTING-LINUX-DETAILED.md](DEMO-HUNTING-LINUX-DETAILED.md).
>
> Nguyên tắc: **hunt tới đâu điền Timeline tới đó** (3 vòng) — xem [DEMO-HUNTING-TIMELINE-WORKFLOW.md](DEMO-HUNTING-TIMELINE-WORKFLOW.md).

---

## PHẦN 0 — CHUẨN BỊ (làm 1 lần, trước demo)

**0.1. Bật lab (trên VM sau khi mở server):**
```bash
sudo bash /home/khoi/restore_lab.sh      # start web + re-stage file volatile
```

**0.2. AnalysisHub server chạy + đăng nhập console.** (`docker compose up -d` nếu chưa chạy).

**0.3. Cấu hình AI provider** *(bắt buộc để dùng AI Analysis cho webshell Tier-3):*
- **AI Analysis → AI Providers → Add** → chọn preset (OpenAI/Anthropic/Google/DeepSeek) → điền API key → Save.

**0.4. Nạp IOC mồi** *(để mọi kết quả scan tự tô đậm dòng khớp):*
- **Threat Intelligence → IOC Store → Bulk import**:
  ```
  185.220.101.55
  evil-update[.]com
  d450c5072492292af47159d32db91b87cd3dbe690e6bc7826448ce16e8897f40   # room_247.php
  aa8bdb66a5fcbd4ac679a65b7105f97a0b55156ffe9d2a5f7616b4a651175270   # functions.php
  ```

**0.5. Upload tool hunting** *(nếu chưa có):*
- `yarascan`: chạy `tools/yara-scanner/upload_scanner.ps1`.
- `LinPEAS` + `Hayabusa`: chạy `upload_tools.ps1 -BaseUrl http://<SERVER>:3000/api/v1 -Email <email> -Password <pass>`.

**0.6. Cài agent lên VM Linux:**
- **Endpoints & Tools → Agents → New Agent** → copy lệnh `install.sh`.
- Trên VM chạy bằng **sudo** → agent hiện **Online**.
> ⚠️ Cần `PUBLIC_URL` server đúng địa chỉ VM truy cập được. (Đây là bước duy nhất cần server URL — nếu bạn cho tôi URL, tôi cài hộ qua SSH.)

**0.7. Tạo Case + gán agent:**
- **Case Manager → New Case** → tên `IR-2026-B — SeaView Hotel Compromise`.
- Mở case → gán agent `velociraptor`.

---

## PHẦN 1 — TIẾP NHẬN SỰ CỐ (Timeline Node #1)

Mở case → tab **Attack Timeline** → **Add event**:
| Trường | Giá trị |
|---|---|
| event_time | `2026-07-22 02:47` |
| host | `velociraptor` · severity `medium` · source `manual` |
| title | `NOC alert: outbound spike + CPU cao rạng sáng` |
| detail | DevOps báo file room_247.php lạ + Search Console spam (#OPS-2290) |

→ Timeline có mốc "lúc phát hiện". Giờ đi tìm "lúc xâm nhập thật".

---

## PHẦN 2 — VÒNG 1: DỰNG KHUNG XƯƠNG (ELK web-log hunting)

Đây là mảng mạnh nhất cho vụ này (tấn công qua web).

**2.1. Đẩy log vào ELK:** **ELK → Log Ingest** → ingest `/var/log/apache2/access.log` + `/var/log/auth.log` (qua agent).

**2.2. Hunt dấu hiệu web-attack** (tạo query lần lượt):
| Query | Bắt được gì | Kết quả kỳ vọng |
|---|---|---|
| `UNION SELECT` | khai thác SQLi | hit **21:24** dump bảng users |
| `%27` hoặc `'` | probe SQLi | hit **21:22** (`search.php?q='`) |
| `sqlmap` (user_agent) | công cụ tấn công | 2 hit UA sqlmap |
| `POST` + `/admin/login.php` | đăng nhập admin | hit **21:31** (302) |
| `room_247.php` | webshell RCE | hit **21:36** `?cmd=id` |

**2.3. Điền timeline:** với mỗi result → **Import ELK** (chọn case) → mỗi hit thành event có `@timestamp` thật.
→ Timeline giờ có chuỗi **21:22 → 21:24 → 21:31 → 21:34 → 21:36**.

**✔ Trả lời được:** *điểm vào = SQLi (T1190)*, *attacker dump creds*, *upload webshell*. Gán tactic `initial-access`.

---

## PHẦN 3 — VÒNG 2: HUNT WEB ROOT + HỆ THỐNG (gắn thịt vào timeline)

### 3.1. yarascan — webshell trong web root ⭐
**Agents → [velociraptor] → Scanner** (hoặc Jobs → tool `yarascan`), args:
```
scan /var/www --scenario linux -o {{OUTDIR}}
```
**Kết quả kỳ vọng — 2 hit:**
- `uploads/rooms/room_247.php` — rule `php_dynamic_exec_super` (score 90, **critical**)
- `includes/functions.php` — rule `php_eval_base64` (score 80, **high**) · *mtime 21:40 lệch app 07-10 → file bị sửa*
- `includes/db.php` **KHÔNG ra hit** → sang 3.2.

→ Tick từng dòng → **Save to Case + promote IOC**. Gán `persistence / T1505.003`.

### 3.2. AI Analysis — bắt webshell EVASIVE (Tier-3) ⭐ *điểm nhấn AI*
- **Evidence Store / Files** → tải `includes/db.php` → nút **🧠 AI**.
- **Kết quả kỳ vọng:** AI chỉ ra tên hàm ghép runtime `"sy"."st"."em"` + `base64_decode($_GET['ref'])` gọi qua biến → **webshell** dù không khớp signature.
- → **AI triage → timeline**, promote IOC `77ea45ab…`. **Thông điệp demo:** signature bắt cái đã biết, **AI phủ cái né tránh**.

### 3.3. yarascan — reverse shell + miner + persistence (ngoài web root)
```
scan /tmp /dev/shm /var/tmp /etc/cron.d /etc/systemd/system --scenario linux --all-files -o {{OUTDIR}}
```
**Kỳ vọng:** `/dev/shm/.x` (`LIN_Reverse_Shell`) · `/etc/cron.d/apache-update` (`LIN_Persistence`) · `/var/tmp/.cache/kworker` (`LIN_CryptoMiner`). → Save to Case.

### 3.4. Edge Forensics (native)
**Agents → [velociraptor] → Edge Forensics** → Run Scan từng tab:
| Tab | Kỳ vọng |
|---|---|
| **Autoruns** | `sysupdate.service` (systemd, cờ `exec-from-world-writable`) · cron `apache-update` · `profile.d/00-update.sh` |
| **Processes** | tiến trình chạy từ `/dev/shm`,`/var/tmp` (nếu còn chạy) |
| **Network** | kết nối tới `185.220.101.55:4444` (nếu còn) |
→ Tick → **Save to Case + promote IOC**. Gán `persistence / T1543.002, T1053.003, T1546.004`.

### 3.5. LinPEAS — điểm mù của yarascan & Autoruns ⭐
**Jobs → tool `LinPEAS`**, args `-a` (kết quả ở Process Output → AI đọc qua nguồn `job`).
**Kỳ vọng LinPEAS nêu bật:**
- **SUID lạ:** `/tmp/.bd`, `/var/tmp/.cache/.bd`, `/var/tmp/.cache/kworker` (T1548.001)
- **SSH key lạ** trong `/root/.ssh/authorized_keys` (T1098.004)
- **User `support`** uid 1001 trong nhóm **sudo** (T1136.001)
→ **Add event** (manual) cho từng cái, event_time = mtime (22:20 / 22:12 / 22:25).

### 3.6. Terminal + Files — xác minh & đọc bằng chứng gốc
**Agents → [velociraptor] → Terminal:**
```
sqlite3 /var/www/html/data/seaview.db "SELECT username,password,role FROM users;"   # creds bị dump
find / -perm -4000 -type f 2>/dev/null            # SUID: /tmp/.bd, /var/tmp/.cache/*
cat /root/.ssh/authorized_keys ; getent group sudo # ssh key + user support
cat /home/support/.bash_history                    # wget miner -> cat shadow -> tar loot -> curl C2
```
→ Đọc `.bash_history` = kịch bản exfil: mỗi lệnh → **Add event** (tải miner 22:02, đọc shadow 22:30, exfil 03:00). Gán `collection/T1074`, `exfiltration/T1041`.

---

## PHẦN 4 — VÒNG 3: DỰNG CHUYỆN & BÁO CÁO

**4.1. Analyze Evidence** (đầu Case) → AI quét **mọi job/scan trong case** → vá finding còn thiếu vào timeline.

**4.2. AI Rebuild** (tab Attack Timeline → **AI Rebuild → Append**) → chuẩn hoá tiêu đề + gắn tactic còn trống.

**4.3. Kiểm tra ATT&CK Matrix** → phải đủ cột:
`Initial Access (SQLi) → Execution → Persistence → Privilege Escalation → Credential Access → Collection → Command & Control → Exfiltration`. Cột nào trống → hunt bù rồi Add event.

**4.4. AI Summary** → tường thuật chuỗi tấn công tự động.

**4.5. Incident Report** (Case → Incident Report) → xuất HTML/PDF.

**4.6. Export STIX** → xuất IOC (hash webshell, IP C2, cron/systemd/ssh/SUID, user support).

---

## BẢNG TRA NHANH — hunt gì, ở đâu, ra gì

| Câu hỏi IR | Công cụ | Vị trí | Bằng chứng kỳ vọng |
|---|---|---|---|
| Điểm vào? | **ELK** | access.log | SQLi `UNION SELECT` @21:24 |
| Lấy creds gì? | ELK + Terminal | log / seaview.db | `admin:Summer2026!`, `reception:welcome1` |
| Webshell ở đâu (mấy cái)? | **yarascan** + **AI** | /var/www | room_247.php · functions.php · **db.php (AI)** |
| Leo root chưa? | LinPEAS | SUID scan | `/tmp/.bd`, `/var/tmp/.cache/.bd` |
| Persistence? | Edge Forensics + LinPEAS | autoruns | cron · systemd · ssh key · profile.d · SUID |
| Tài khoản lạ? | LinPEAS / Terminal | /etc/passwd | user `support` (sudo) |
| Dữ liệu bị lấy? | Terminal | .bash_history | tar `/etc/shadow` → curl C2 @03:00 |

---

## CHECKLIST "ĐÃ HUNT FULL"
- [ ] Node #1 (NOC alert) đã điền
- [ ] ELK: SQLi + admin login + upload + RCE → Import ELK vào timeline
- [ ] yarascan /var/www → 2 hit (Tier-1, Tier-2) → Save to Case
- [ ] AI Analysis db.php → phát hiện Tier-3 evasive
- [ ] yarascan /tmp,/dev/shm,/var/tmp → reverse shell + cron + miner
- [ ] Edge Forensics Autoruns → systemd/cron/profile
- [ ] LinPEAS → SUID + ssh key + user support
- [ ] Terminal → dump creds DB + đọc bash_history (exfil)
- [ ] Analyze Evidence → AI Rebuild → ATT&CK matrix đủ cột
- [ ] AI Summary → Incident Report → Export STIX

> **Kết quả cuối:** timeline ~16 mốc từ 21:22 (SQLi) → 03:00 (exfil), dwell time ~5h45, ma trận ATT&CK đủ
> 8 giai đoạn, báo cáo sự cố + STIX xuất ra. **Đây là "hunting full" cho case SeaView.**
