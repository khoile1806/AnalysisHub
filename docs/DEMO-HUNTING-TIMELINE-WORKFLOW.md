# AnalysisHub — Quy trình Hunting + Điền Attack Timeline (kịch bản demo)

> Tài liệu này trả lời: **vừa hunt vừa dựng Attack Timeline như thế nào cho cả hành trình**,
> để cuối buổi có một timeline hoàn chỉnh (chronological + ATT&CK matrix) → AI Summary → Incident Report.
>
> Đi kèm 2 kịch bản trong [DEMO-HUNTING-SCENARIOS.md](DEMO-HUNTING-SCENARIOS.md) (A: Windows, B: Linux).
> Tên nút dưới đây khớp đúng với UI (tab **Attack Timeline** trong Case Detail).

---

## 1. Hiểu Attack Timeline trước khi điền

**Điểm mấu chốt:** mỗi event mang **`event_time` = thời điểm hoạt động THẬT của attacker**
(trích từ bằng chứng), **không phải** lúc ta thu thập. Nhờ vậy timeline sắp xếp lại đúng chuỗi tấn công.

**Trường của một event** (`models.TimelineEvent`):
| Trường | Ý nghĩa | Ai điền |
|---|---|---|
| `event_time` | Giờ hoạt động thật (sắp xếp theo cái này) | Bắt buộc |
| `source` | Nguồn: `manual` · `elk` · `ai` · `edge:*` · `edge-forensics:*`/`import` · `trace*` · `job` | Tự gán theo nút |
| `host` | Endpoint quan sát được (WS-01 / websrv-01) | Theo agent |
| `tactic` | ATT&CK tactic (`initial-access`, `persistence`…) → dựng **ma trận** | Nên điền |
| `technique` | ATT&CK technique (`T1059.001`) | Nên điền |
| `severity` | `critical/high/medium/low/info` | Nên điền |
| `title` / `detail` | Mô tả ngắn / chi tiết | Bắt buộc title |
| `attachments` | Link evidence/ảnh đính kèm node | Tùy chọn |

### 1.1. 6 nguồn điền timeline ↔ nút trên UI
| Nút (tab Attack Timeline / nơi khác) | Cơ chế | `source` | Có timestamp thật? | Có Tactic/Technique? |
|---|---|---|---|---|
| **Super-timeline** (Layers) | Chạy MFT/Prefetch/Processes/Shimcache trên agent online → nổ thành event time-anchored | `edge:mft`… | ✅ (timestamp NTFS/prefetch) | ✗ (điền tay sau) |
| **Import ELK** (Search) | Promote hit của ELK hunt result (mỗi hit `@timestamp`) | `elk` | ✅ (log time) | ✗ |
| **Save to Case + promote IOC** (ở **Edge Forensics** / **EVTX Viewer**) | Import dòng đã tick → event + IOC | `edge-forensics:<tab>` / `import` | ⚠️ tùy artifact | ✗ |
| **AI triage → timeline** (ở **Edge Forensics**) / **AI Extract** / **AI Rebuild** | AI đọc dữ liệu → rút event có MITRE | `ai` | ✅ AI suy ra từ nội dung | ✅ (AI gắn) |
| **Analyze Evidence** (nút ở đầu Case) | AI quét **mọi job/scan trong case** → findings → timeline | `ai` | ✅ | ✅ |
| **Add event** (Add timeline event) | Nhập tay: có ô **MITRE Tactic** + **Technique** | `manual` | ✅ (tự nhập) | ✅ |
| *(Trace entity → Add to timeline)* | Lineage 1 process/file | `trace*` | ✅ | ✗ |

> **Dedupe:** các nguồn tự động (super, elk, import, trace) idempotent theo
> `case_id + source + event_time + host + title + technique` → chạy lại **không nhân đôi**.
> Riêng **manual** không dedupe (luôn cố ý). ELK promote cap 200 hit/lần, super cap 2000/nguồn.

### 1.2. Hai chế độ AI hay nhầm
- **AI Rebuild** = *tinh chỉnh timeline đang có*: `Replace` (xoá + dựng lại sạch, nội dung cũ được nạp cho AI trước nên không mất) hoặc `Append` (giữ cũ, thêm mới). Dùng **cuối buổi** để chuẩn hoá.
- **AI Extract / AI triage / Analyze Evidence** = *rút event MỚI* từ bằng chứng.

---

## 2. Nguyên tắc vàng: "Hunt tới đâu, điền tới đó" — quy trình 3 vòng

Đừng để cuối buổi mới điền. Làm theo 3 vòng, timeline lớn dần cùng quá trình hunt:

```
VÒNG 1 — DỰNG KHUNG XƯƠNG (timestamp thật, tự động)
   Windows → Super-timeline (MFT+Prefetch+Processes+Shimcache, Only suspicious ✓)
   Linux   → ELK hunt (auth/web/syslog) → Import ELK
   ⇒ Timeline có sẵn các mốc thời gian THẬT (execution, file tạo, logon…)

VÒNG 2 — GẮN THỊT KHI HUNT (mỗi dấu vết → 1 event, kèm Tactic/Technique)
   Mỗi lần Edge Forensics / YARA / Checklist / Terminal ra một dấu vết:
     • Bằng chứng máy móc rõ ràng → "Save to Case + promote IOC"
     • Cần AI diễn giải / gắn MITRE → "AI triage → timeline"
     • Mốc không có timestamp máy (containment, quyết định IR) → "Add event" (manual)

VÒNG 3 — CHUẨN HOÁ & KỂ CHUYỆN (cuối buổi)
   • Analyze Evidence (quét toàn case, vá lỗ hổng còn thiếu)
   • AI Rebuild (Append) → dedupe, chuẩn hoá tiêu đề, bổ sung tactic còn trống
   • Xem ATT&CK matrix (event nhóm theo tactic kill-chain) → kiểm tra đủ giai đoạn
   • AI Summary → tường thuật → Incident Report + Export STIX
```

> **Mẹo 2 VM / 1 case:** nếu gộp cả Windows & Linux vào 1 case, dùng bộ lọc **host** trên
> toolbar timeline để tách theo máy khi trình bày; hoặc tạo 2 case riêng rồi ghép ở báo cáo.

---

## 3. Bảng END-TO-END — SCENARIO A (Windows)

Mỗi hàng = một mắt xích tấn công → **hunt ở đâu** → **điền timeline bằng nút nào** → metadata điền kèm.

| # | Kỹ thuật (ATT&CK) | Hunt ở đâu (thao tác) | Điền timeline | source | tactic / technique | severity |
|---|---|---|---|---|---|---|
| 1 | Execution — PowerShell (T1059.001) | Edge Forensics → **Prefetch** (POWERSHELL run_count cao) | **Super-timeline** (Prefetch) + tick dòng → *Save to Case* | edge:prefetch | execution / T1059.001 | high |
| 2 | Ingress Tool (T1105) | Edge Forensics → **MFT** (`updater.exe` mới tạo) | **Super-timeline** (MFT) | edge:mft | command-and-control / T1105 | high |
| 3 | Cred Dumping (T1003.001) | **YARA Scanner** rule `credential_theft` (hit `creds.txt`) + **Sigma** mimikatz | **AI triage → timeline** (từ dòng scanner) hoặc *Add event* | ai / manual | credential-access / T1003.001 | critical |
| 4 | Persistence Run key (T1547.001) | Edge Forensics → **Autoruns** (`WinUpdater`) / **Registry Viewer** | **Save to Case + promote IOC** (promote value = đường dẫn) | edge-forensics:autoruns | persistence / T1547.001 | high |
| 5 | Persistence Task (T1053.005) | Edge Forensics → **Autoruns** (task `MicrosoftEdgeUpdateSvc`) | **Save to Case** | edge-forensics:autoruns | persistence / T1053.005 | high |
| 6 | Discovery (T1018/T1135) | **Prefetch**/**Processes** (net.exe, arp.exe) hoặc Playbook HUNT_WIN | **Add event** (manual) | manual | discovery / T1018 | medium |
| 7 | Failed logons (T1110/auth) | **EVTX Viewer** lọc **4625** → tick | **Save to Case + promote IOC** (EVTX Viewer có nút này) | import | credential-access / T1110 | medium |
| 8 | Collection/Staging (T1560) | Edge Forensics → **MFT** (`loot.zip`) | **Super-timeline** (MFT) hoặc *Save to Case* | edge:mft | collection / T1560 | high |
| 9 | C2 (T1071) | Edge Forensics → **Network** (IP mồi 185.220.101.55, khớp IOC → tô đậm) | **Save to Case + promote IOC** | edge-forensics:netconn | command-and-control / T1071 | high |

**Chốt vòng 3 (A):** `Analyze Evidence` → `AI Rebuild (Append)` → xem **ATT&CK matrix** đủ cột
Execution→Persistence→Cred Access→Discovery→Collection→C2 → `AI Summary` → Report.

---

## 4. Bảng END-TO-END — SCENARIO B (Linux)

> Lưu ý: Linux **không có** MFT/Prefetch/Shimcache → khung xương thời gian dựa vào **ELK** (log)
> + **event_time nhập tay/AI** cho artifact hệ thống.

| # | Kỹ thuật (ATT&CK) | Hunt ở đâu (thao tác) | Điền timeline | source | tactic / technique | severity |
|---|---|---|---|---|---|---|
| 1 | Exploit web app (T1190) | **ELK** hunt access log: request `/uploads/up.php?cmd=` | **Import ELK** (promote hit) | elk | initial-access / T1190 | high |
| 2 | Web Shell (T1505.003) | **Files** duyệt `/var/www/html/uploads` + **YARA** `webshell_base` | **Save to Case + promote IOC** (path `up.php`) | edge-forensics:yara / import | persistence / T1505.003 | critical |
| 3 | Reverse shell (T1059.004) | Edge Forensics → **Processes** (con của web server, chạy từ `/dev/shm`) | **AI triage → timeline** | ai | execution / T1059.004 | high |
| 4 | Cron persistence (T1053.003) | Edge Forensics → **Autoruns** (cron `apache-update`, cờ `suspicious-command`) | **Save to Case + promote IOC** | edge-forensics:autoruns | persistence / T1053.003 | high |
| 5 | systemd persistence (T1543.002) | Edge Forensics → **Autoruns** (`sysupdate.service`, ExecStart `/dev/shm/.x`) | **Save to Case** | edge-forensics:autoruns | persistence / T1543.002 | high |
| 6 | SSH key backdoor (T1098.004) | **Terminal**: `cat /root/.ssh/authorized_keys` | **Add event** (manual, event_time = mtime file) | manual | persistence / T1098.004 | high |
| 7 | SUID privesc (T1548.001) | **Terminal**: `find / -perm -4000` (thấy `/tmp/.bd`) | **Add event** (manual) | manual | privilege-escalation / T1548.001 | high |
| 8 | Auth brute (auth log) | **ELK** hunt: `Failed password` | **Import ELK** | elk | credential-access / T1110 | medium |
| 9 | Staging/Exfil (T1074/T1041) | **Terminal**/Checklist: `/tmp/.loot.tgz`, `/dev/shm` | **Add event** hoặc *AI triage* | manual / ai | collection / T1074 | medium |

**Chốt vòng 3 (B):** `Analyze Evidence` (nạp thêm output checklist/YARA) → `AI Rebuild (Append)` →
ATT&CK matrix đủ Initial Access→Execution→Persistence→PrivEsc→Collection → `AI Summary` → Report.

---

## 5. Cách thức thực hiện DEMO (click-by-click)

### 5.1. Trình tự thao tác chuẩn (áp dụng mỗi VM)
1. **Case Manager → New Case** → mở case → gán agent (VM). Mở tab **Attack Timeline** để trống → "No events yet".
2. **(Vòng 1) Dựng khung xương:**
   - *Windows:* tab Attack Timeline → **Super-timeline** → chọn agent → tick **MFT + Prefetch + Processes** + **Only suspicious** → **Build**. Toast: "Super-timeline built: N event(s)". Timeline hiện loạt mốc có giờ thật.
   - *Linux:* ELK → Log Ingest (đẩy log) → chạy hunt (IOC/từ khoá) → mở result → **Promote timeline** (hoặc tab Timeline → **Import ELK**) → chọn case.
3. **(Vòng 2) Hunt & gắn thịt** — làm lần lượt theo bảng mục 3/4. Với **mỗi** dấu vết:
   - Vào **Agents → [VM] → Edge Forensics → [tab]** → **Run Scan** → tick dòng nghi ngờ.
   - Bấm **Save to Case + promote IOC** (bằng chứng máy) **hoặc** **AI triage → timeline** (cần MITRE).
   - Quay lại tab **Attack Timeline** của case → thấy event mới xuất hiện. Nếu là `manual`, bấm **Add event**, nhập **event_time**, **Tactic**, **Technique**, **Severity**, **Title/Detail**.
   - (Tuỳ chọn, đẹp cho báo cáo) bấm biểu tượng **attachments** trên event → đính kèm file evidence/ảnh (snapshot Edge Forensics đã tự lưu ở Evidence Store).
4. **(Vòng 3) Chuẩn hoá & kể chuyện:**
   - Đầu Case → **Analyze Evidence** (AI quét toàn bộ job/scan → bổ sung finding còn thiếu vào timeline).
   - Tab Attack Timeline → **AI Rebuild** → chọn provider → **Append** → **Rebuild timeline** (chuẩn hoá tiêu đề, vá tactic trống, khử trùng).
   - Xem **ATT&CK matrix** (event nhóm theo tactic kill-chain trái→phải) → xác nhận đủ giai đoạn; cột nào trống thì hunt bù rồi Add event.
   - Case → **AI Summary** → tường thuật.
   - Case → **Incident Report** (HTML/PDF) — timeline + matrix + findings đã nằm trong báo cáo.
   - Case → **Export STIX** — xuất IOC đã promote.

### 5.2. Điều "khán giả" nhìn thấy timeline lớn dần (điểm nhấn demo)
- Sau **Super-timeline/Import ELK**: timeline nhảy từ 0 → ~10–30 mốc có giờ thật → "đây là khung thời gian khách quan từ artifact".
- Sau mỗi **Save to Case / AI triage**: 1 event mới có **màu severity** + **nhãn tactic** xuất hiện đúng vị trí thời gian → "chúng ta đang khớp từng hành vi vào dòng thời gian".
- Sau **AI Rebuild + matrix**: các event xếp thành **chuỗi kill-chain** hoàn chỉnh → chốt câu chuyện tấn công.

### 5.3. Thời lượng gợi ý
| Phút | Vòng | Hành động |
|---|---|---|
| 0–2 | — | Tạo case, gán agent, mở timeline trống |
| 2–5 | 1 | Super-timeline (Win) / Import ELK (Linux) → khung xương |
| 5–13 | 2 | Hunt từng mắt xích + điền event (theo bảng) |
| 13–17 | 3 | Analyze Evidence → AI Rebuild → matrix |
| 17–20 | 3 | AI Summary → Incident Report → STIX |

---

## 6. Mẹo & lỗi thường gặp khi điền timeline

| Vấn đề | Nguyên nhân / cách xử lý |
|---|---|
| Event dồn về "hôm nay" thay vì đúng giờ tấn công | Artifact không có timestamp → `import-artifacts` mặc định `now`. Ưu tiên **Super-timeline/ELK** (có giờ thật); hoặc **Add event** rồi nhập `event_time` = mtime file (xem ở MFT/Files). |
| ATT&CK matrix trống cột | Event thiếu `tactic`. Mở event → **Edit** điền Tactic/Technique, hoặc chạy **AI Rebuild** để AI gắn. |
| Chạy Super-timeline 2 lần bị nhân đôi? | Không — dedupe theo key. Nhưng **manual** thì có (cố ý), tránh Add trùng. |
| Timeline quá nhiều dòng "info" nhiễu | Bật **Only suspicious** khi Super-timeline; lọc theo **severity** trên toolbar khi trình bày. |
| Linux mà Super-timeline không ra gì | Đúng — MFT/Prefetch/Shimcache Windows-only. Linux dùng **ELK + AI triage + manual**. |
| Muốn gộp 2 VM | Dùng bộ lọc **host** trên timeline, hoặc 2 case rồi ghép ở Incident Report. |
| Cần chứng minh chain-of-custody trong timeline | Đính **attachments** = evidence (mỗi Edge Forensics scan tự lưu snapshot có SHA-256 vào Evidence Store) vào node tương ứng. |

---

## 7. Tóm tắt 1 dòng cho người vận hành
**Vòng 1** dựng khung thời gian bằng Super-timeline/ELK → **Vòng 2** hunt tới đâu bấm *Save to Case* / *AI triage* / *Add event* (nhớ gắn Tactic+Technique) tới đó → **Vòng 3** Analyze Evidence + AI Rebuild + xem ATT&CK matrix + AI Summary → **Incident Report + STIX**.
