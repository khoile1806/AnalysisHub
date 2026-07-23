# AnalysisHub — Kịch bản điều tra chi tiết (Intake → Giả thuyết → Target → Hunting)

> Tài liệu này làm cho demo có **mạch điều tra như thật**: sự cố được **báo cáo từ đâu**
> (node đầu tiên của timeline) → từ **mô tả của người report** lập **giả thuyết** và xác định
> **TARGET hunt** → rồi mới hunting sâu theo [DEMO-HUNTING-TIMELINE-WORKFLOW.md](DEMO-HUNTING-TIMELINE-WORKFLOW.md).
>
> Cặp với 2 kịch bản kỹ thuật trong [DEMO-HUNTING-SCENARIOS.md](DEMO-HUNTING-SCENARIOS.md).
> Mốc thời gian dùng ngày demo **2026-07-22** (đổi tuỳ buổi). Giờ = giờ máy nạn nhân.

---

## 0. Khung điều tra chung (áp dụng cho cả 2 kịch bản)

Mọi cuộc điều tra đi theo 5 bước — và **timeline được điền ngay từ bước 1**:

```
1. INTAKE (Tiếp nhận)   → Ai/đâu báo? báo gì? lúc nào?  ⇒ TIMELINE NODE #1 (manual, "Incident reported")
2. TRIAGE (Phân loại)   → Trích "cái đã biết / chưa biết" từ lời report ⇒ NODE #2 "Investigation opened"
3. HYPOTHESIS (Giả thuyết)→ Từ triệu chứng suy ra chuỗi tấn công khả dĩ
4. TARGET & SCOPE       → Chốt host / artifact / IOC / thời gian cần hunt + câu hỏi phải trả lời
5. HUNT sâu             → Chạy Edge Forensics/YARA/ELK… → điền timeline dần (vòng 2 & 3)
```

> **Nguyên tắc:** node #1 **không phải** dấu vết tấn công, mà là *"lúc SOC biết chuyện"*.
> Nó neo mốc "thời điểm phát hiện" để sau này so với "thời điểm xâm nhập thật" (dwell time).

---

# KỊCH BẢN A — Windows: "Máy kế toán có hành vi lạ sau khi mở email"

## A.0. Bối cảnh tổ chức
- Công ty **ACME Corp**, phòng Kế toán. Máy trạm Windows domain-joined.
- Máy nạn nhân: **`WS-ACC-07`**, người dùng **`acme\acc-lan`** (nhân viên kế toán, không rành IT).
- Có SOC nội bộ dùng AnalysisHub; endpoint đã cài agent.

## A.1. INTAKE — Sự cố được báo cáo từ đâu (⇒ Timeline Node #1)
> **Kênh: Helpdesk ticket do người dùng cuối tạo** (không phải alert máy) — sát thực tế nhất.

**Ticket #HD-4821 — 2026-07-22 08:12**
> *Người báo:* chị Lan (acc-lan), phòng Kế toán — gọi tổng đài IT.
> *Nội dung (nguyên văn):* "Sáng nay bật máy thấy **một cửa sổ màu đen nhấp nháy rồi tắt** lúc mới đăng nhập.
> Máy **chạy chậm hẳn**. Tôi thấy trong **Documents có một file .zip lạ** tên `loot.zip` tôi không tạo.
> **Outlook cứ bắt đăng nhập lại** suốt. Tối qua tôi có mở **file đính kèm trong email 'Hóa đơn tháng 7.docx'**
> gửi từ một địa chỉ lạ, mở xong nó báo lỗi không xem được."

Helpdesk phân loại **Security** → chuyển SOC lúc **08:20**. SOC mở điều tra.

**→ Điền Timeline (Add event — thao tác đầu tiên trên console):**
| Trường | Giá trị |
|---|---|
| event_time | `2026-07-22 08:12` |
| source | `manual` |
| host | `WS-ACC-07` |
| severity | `info` |
| tactic / technique | *(để trống — đây là mốc phát hiện, không phải kỹ thuật)* |
| title | `Sự cố được báo cáo qua Helpdesk (#HD-4821)` |
| detail | Trích nguyên văn triệu chứng của người dùng + tên email nghi phishing |

*(Tuỳ chọn Node #2, 08:20, `manual`, "SOC opened investigation — assigned analyst").*

## A.2. TRIAGE — Trích thông tin từ lời report
| Triệu chứng người dùng nói | Suy luận kỹ thuật (giả thuyết mắt xích) |
|---|---|
| Mở "Hóa đơn tháng 7.docx" từ email lạ tối qua | **Initial Access** — Phishing Attachment (T1566.001) |
| Cửa sổ đen nhấp nháy lúc đăng nhập | **Persistence** chạy lúc boot/logon → PowerShell hidden (T1547.001 / T1053.005 + T1059.001) |
| Outlook đăng nhập lại liên tục | Nghi **Credential Access** — token/creds bị đụng (T1003 / T1539) |
| File `loot.zip` lạ trong Documents | **Collection/Staging** — gom dữ liệu chờ exfil (T1560) |
| Máy chậm | Tiến trình lạ chạy nền (execution/C2) |

**Cái ĐÃ biết:** host, user, email mồi, ~thời điểm bắt đầu (tối qua), 4 triệu chứng.
**Cái CHƯA biết:** payload là gì, có mất credential thật không, persistence chính xác ở đâu, dữ liệu gì trong loot.zip, đã lan sang máy khác chưa, C2 nào.

## A.3. HYPOTHESIS (giả thuyết điều tra)
> "Người dùng mở tài liệu phishing tối 21/07 → macro/loader chạy **PowerShell** kéo payload
> (`updater.exe`) → **dump credential** (giải thích Outlook logout) → cài **persistence** chạy lúc logon
> (giải thích cửa sổ đen) → **gom dữ liệu** vào `loot.zip` để **exfil** ra C2."

## A.4. TARGET & SCOPE — hunt có mục tiêu
| Hạng mục | Target cụ thể |
|---|---|
| **Target host** | `WS-ACC-07` (mở rộng nếu thấy lateral movement) |
| **Time window** | **2026-07-21 18:00 → 2026-07-22 08:12** (tối qua → lúc báo) |
| **Target artifacts** | Prefetch (POWERSHELL, updater.exe) · Autoruns (Run key/Task chạy lúc logon) · MFT (`loot.zip`, `updater.exe` + hash/mtime) · YARA credential_theft · EVTX 4104/4625/4697 · Network (C2) |
| **Target IOC** | file `updater.exe`, `creds.txt`, `loot.zip`; Run key `WinUpdater`; task `MicrosoftEdgeUpdateSvc`; IP `185.220.101.55` |
| **Câu hỏi phải trả lời (IR objectives)** | 1) Điểm xâm nhập ban đầu & giờ chính xác? 2) Credential có bị dump không? 3) Cơ chế persistence nào? 4) `loot.zip` chứa gì, đã exfil chưa? 5) Có lan sang máy khác không? |

## A.5. Dẫn vào HUNT sâu
Từ đây chạy đúng **bảng END-TO-END Scenario A** trong
[DEMO-HUNTING-TIMELINE-WORKFLOW.md §3](DEMO-HUNTING-TIMELINE-WORKFLOW.md). Trình tự khớp câu hỏi A.4:
1. **Super-timeline** (MFT+Prefetch+Processes) → khung xương giờ thật → thấy `updater.exe` chạy **21/07 22:14**, `loot.zip` tạo **22:31** → **trả lời Q1 & Q4 (một phần)**.
2. **YARA credential_theft** + **Autoruns** → creds dump + Run key/Task → **Q2 & Q3**.
3. **Network** (IP C2) + **EVTX** → **Q4 (exfil) & Q5 (lateral)**.
Mỗi phát hiện → *Save to Case / AI triage / Add event* (gắn tactic+technique) → timeline đầy dần.
Chốt: **Analyze Evidence → AI Rebuild → ATT&CK matrix → AI Summary → Incident Report**.

**Kết luận điều tra mẫu (đọc khi demo):** dwell time ~10h (xâm nhập 21/07 22:14, phát hiện 22/07 08:12);
initial access = phishing doc; credential bị dump; persistence = Run key + Scheduled Task; `loot.zip` gom Documents,
outbound tới 185.220.101.55 (chặn ở firewall); chưa thấy lateral movement.

---

# KỊCH BẢN B — Linux: "Web server có file lạ và outbound bất thường ban đêm"

## B.0. Bối cảnh tổ chức
- **ACME Corp** vận hành website công khai trên **`websrv-01`** (Ubuntu, Apache + PHP).
- Có form upload (khách gửi hồ sơ). Server đẩy log về **ELK** của SOC. Đã cài agent.

## B.1. INTAKE — Sự cố được báo cáo từ đâu (⇒ Timeline Node #1)
> **Kênh: 2 nguồn hội tụ** — NOC (monitoring) + Quản trị web. Đây là cách sự cố Linux hay lộ.

**Cảnh báo NOC — 2026-07-22 02:47**
> Hệ thống giám sát (Zabbix) bắn cảnh báo: `websrv-01` **outbound bandwidth spike** +
> **CPU load cao bất thường** lúc rạng sáng. Trực NOC ghi nhận, chưa rõ nguyên nhân.

**Báo cáo Quản trị web — 2026-07-22 09:05 (ticket #OPS-2290)**
> *Người báo:* anh Minh (DevOps).
> *Nội dung:* "Sáng nay soát thư mục website thấy **`/var/www/html/uploads/up.php`** — team **không hề deploy** file này.
> **Google Search Console** cảnh báo site chứa **nội dung spam/redirect lạ**. NOC cũng bảo đêm qua server
> **gửi traffic ra ngoài nhiều** lúc ~3h sáng. Nghi website bị chèn shell qua form upload."

SOC gộp 2 sự kiện thành 1 điều tra lúc **09:10**.

**→ Điền Timeline (Add event):**
| Trường | Giá trị |
|---|---|
| event_time | `2026-07-22 02:47` |
| source | `manual` |
| host | `websrv-01` |
| severity | `medium` |
| tactic/technique | *(trống — mốc phát hiện)* |
| title | `NOC alert: outbound spike + CPU cao bất thường` |
| detail | Cảnh báo Zabbix rạng sáng; sau đó DevOps báo file up.php lạ + Search Console flag spam (#OPS-2290) |

## B.2. TRIAGE — Trích thông tin từ lời report
| Dấu hiệu được báo | Suy luận kỹ thuật |
|---|---|
| `up.php` lạ trong thư mục uploads | **Initial Access + Web Shell** (T1190 + T1505.003) |
| Site bị chèn spam/redirect | Web bị kiểm soát qua shell |
| Outbound spike ~3h sáng | **C2 / Exfil** (T1071 / T1041) |
| CPU cao rạng sáng | Tiến trình lạ chạy (reverse shell / miner / beacon) |

**ĐÃ biết:** host, đường vào nghi ngờ (form upload), file `up.php`, cửa sổ thời gian outbound (~03:00), site bị spam.
**CHƯA biết:** shell vào lúc nào & qua request nào, attacker chạy gì, persistence gì, có leo thang **root** không, dữ liệu gì bị lấy, IP C2.

## B.3. HYPOTHESIS
> "Attacker khai thác **form upload** của web app → đặt **webshell `up.php`** → từ shell chạy lệnh,
> mở **reverse shell/C2** (giải thích outbound 03:00) → cài **persistence** (cron/systemd/ssh key) để trụ lại
> → thử **leo thang root** (SUID) → **gom & exfil** dữ liệu."

## B.4. TARGET & SCOPE
| Hạng mục | Target cụ thể |
|---|---|
| **Target host** | `websrv-01` |
| **Time window** | **2026-07-21 20:00 → 2026-07-22 03:30** (tối qua → sau outbound spike) |
| **Target artifacts** | ELK access log (`/uploads/up.php?cmd=`) · ELK auth.log (`Failed password`) · Files/YARA trên `/var/www`,`/tmp`,`/dev/shm` · Autoruns (cron `apache-update`, systemd `sysupdate.service`) · Processes (chạy từ `/dev/shm`) · `/root/.ssh/authorized_keys` · SUID (`/tmp/.bd`) · `/tmp/.loot.tgz` |
| **Target IOC** | path `up.php`; `/dev/shm/.x`; cron `apache-update`; unit `sysupdate.service`; SSH key `attacker@evil`; SUID `/tmp/.bd`; C2 `185.220.101.55` / `evil-update.com` |
| **Câu hỏi phải trả lời** | 1) Webshell vào **lúc nào & qua request nào**? 2) Attacker chạy lệnh gì? 3) Persistence nào? 4) Có lên **root** không? 5) Dữ liệu gì bị gom/exfil, C2 nào? |

## B.5. Dẫn vào HUNT sâu
Chạy đúng **bảng END-TO-END Scenario B** trong
[DEMO-HUNTING-TIMELINE-WORKFLOW.md §4](DEMO-HUNTING-TIMELINE-WORKFLOW.md). Trình tự khớp câu hỏi B.4:
1. **ELK access log** → tìm `POST /uploads/up.php` + `?cmd=` → **Import ELK** → thấy shell dùng lần đầu **21/07 21:38** → **Q1**.
2. **Files/YARA** xác nhận `up.php`; **Processes/Autoruns** → reverse shell + cron/systemd → **Q2 & Q3**.
3. **Terminal**: `authorized_keys`, `find -perm -4000` → SSH backdoor + SUID → **Q3 & Q4**.
4. **ELK/Terminal**: `/tmp/.loot.tgz`, outbound tới C2 → **Q5**.
Mỗi phát hiện → *Import ELK / Save to Case / AI triage / Add event* (gắn tactic+technique).
Chốt: **Analyze Evidence → AI Rebuild → ATT&CK matrix → AI Summary → Incident Report + STIX**.

**Kết luận điều tra mẫu:** webshell `up.php` upload & dùng lần đầu 21/07 21:38 qua form upload;
attacker mở reverse shell tới 185.220.101.55; persistence cron + systemd + SSH key root;
leo thang qua SUID `/tmp/.bd`; gom `/etc/passwd` vào `/tmp/.loot.tgz`, exfil rạng sáng (outbound 03:00 NOC thấy).

---

## 2. So sánh 2 kịch bản (slide tổng kết demo)

| | Kịch bản A (Windows) | Kịch bản B (Linux) |
|---|---|---|
| **Nguồn báo cáo** | End-user qua Helpdesk (#HD-4821) | NOC alert + DevOps report (#OPS-2290) |
| **Node #1 timeline** | 22/07 08:12 "Sự cố được báo cáo" | 22/07 02:47 "NOC alert outbound spike" |
| **Target host** | WS-ACC-07 | websrv-01 |
| **Đường vào** | Phishing attachment (T1566) | Web upload → webshell (T1190/T1505.003) |
| **Khung xương timeline** | Super-timeline (MFT/Prefetch) | Import ELK (log) |
| **Trọng tâm hunt** | cred theft + persistence + staging | webshell + persistence + privesc + exfil |
| **Dwell time (mẫu)** | ~10 giờ | ~5–6 giờ |

## 3. Checklist "kể chuyện" khi quay demo
- [ ] Mở đầu bằng **ticket/alert thật** (đọc nguyên văn lời người báo) — tạo Node #1 **trước** khi đụng tới forensic.
- [ ] Chỉ ra **cái đã biết vs chưa biết** → nêu **giả thuyết** → chốt **target + câu hỏi**.
- [ ] Mỗi lần hunt ra dấu vết, nói rõ nó **trả lời câu hỏi nào** rồi mới điền timeline.
- [ ] Kết bằng **ATT&CK matrix + dwell time** (khoảng cách Node #1 "phát hiện" và node "xâm nhập thật").
- [ ] Xuất **Incident Report + STIX** → đóng case.
