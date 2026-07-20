# AnalysisHub — Hướng dẫn sử dụng

> Tài liệu dành cho người mới: đọc xong bạn sẽ biết **dự án này làm gì**, **hoạt động ra sao**, và **dùng từng tính năng thế nào**.

---

## 1. AnalysisHub là gì?

**AnalysisHub là nền tảng DFIR (Digital Forensics & Incident Response) + Threat Hunting tập trung.**

Nói đơn giản: khi bạn nghi ngờ một (hoặc hàng loạt) máy trong hệ thống bị xâm nhập, AnalysisHub giúp bạn — từ **một màn hình duy nhất**:

1. **Đưa công cụ forensic xuống máy nghi ngờ** (Loki, YARA, Redline, DumpIt, KAPE…) và chạy từ xa.
2. **Tự động thu kết quả scan về server**, tự parse dữ liệu thô thành dạng đọc được.
3. **Điều tra trực tiếp trên máy đó** (tiến trình, autoruns, prefetch, registry, EVTX, network, file…) mà không cần remote desktop.
4. **Dùng AI phân tích** đống dữ liệu đó, tự rút ra *findings* có cấu trúc và **dựng timeline tấn công**.
5. **Quản lý theo case (vụ việc)**, gom bằng chứng, IOC, timeline → **xuất báo cáo sự cố**.

### Ai dùng?
- **Analyst / IR responder**: điều tra máy bị nghi nhiễm, dựng lại chuỗi tấn công.
- **Threat hunter**: quét chủ động hàng loạt endpoint theo kịch bản/IOC.
- **SOC / quản lý**: theo dõi tình trạng hệ thống, đọc báo cáo sự cố.

### Điểm khác biệt
- **Không cần cài agent thường trực nặng nề**: agent nhẹ, và có **chế độ offline** (bundle) cho máy air-gapped / policy chặt không cho agent kết nối mạng.
- **AI được tích hợp sâu**, không phải chatbot rời rạc: AI đọc kết quả tool → sinh finding có cấu trúc → **đổ thẳng vào timeline của case** kèm IOC.

---

## 2. Kiến trúc tổng quan

```
┌───────────────┐        WebSocket (lệnh + telemetry)      ┌──────────────────┐
│   Frontend    │◄──────── REST / SSE ─────────────────────│                  │
│ React + Vite  │                                          │   Backend (Go)   │
└───────────────┘                                          │  Gin + GORM      │
                                                           │                  │
                            ┌──────────────────────────────│  PostgreSQL      │
                            │        HTTP upload           │  Redis           │
                            ▼        (kết quả scan)        │  Local Storage   │
                    ┌───────────────┐                      └──────────────────┘
                    │  Agent (Go)   │  ◄── WebSocket ──►
                    │  trên endpoint│
                    └───────────────┘
                            │
                    (hoặc)  ▼
                    ┌───────────────┐
                    │ Offline Bundle│  máy air-gapped → xuất report → mang về import
                    └───────────────┘
```

| Thành phần | Công nghệ | Vai trò |
|---|---|---|
| **Backend** | Go, Gin, GORM, PostgreSQL, Redis, gorilla/websocket | API, điều phối agent, xử lý dữ liệu, AI, lưu trữ |
| **Frontend** | React 18, Vite, TailwindCSS, zustand, react-query | Giao diện điều tra |
| **Agent** | Go (Windows/Linux) | Chạy trên endpoint: nhận lệnh, chạy tool, thu kết quả, forensic tại chỗ |
| **Offline Bundle** | Go (self-contained .exe) | Bản đóng gói chạy độc lập, không cần mạng |
| **Storage** | Filesystem | `tools/`, `artifacts/`, `tool-results/`, `case-evidence/`, `log-uploads/` |

**Cách agent kết nối:** agent giữ **WebSocket** thường trực tới server để nhận lệnh (chạy tool, forensic scan…) và gửi telemetry (CPU/RAM/Disk mỗi 30s). Riêng **file kết quả** thì upload qua **HTTP** (nén gzip, có retry + spool).

---

## 3. Bắt đầu nhanh

### 3.1. Khởi chạy hệ thống

```bash
# Tại thư mục dự án
cp .env.example .env        # rồi sửa các giá trị bên dưới
docker compose up -d --build
```

**Biến môi trường quan trọng** (`.env`):

| Biến | Ý nghĩa | Ghi chú |
|---|---|---|
| `POSTGRES_DSN` | Kết nối Postgres | |
| `JWT_SECRET` | Ký token đăng nhập | Đổi khi lên production |
| `AES_ENCRYPTION_KEY` | Mã hoá API key (AI provider…) | **Độ dài tuỳ ý** (hệ thống tự hash về 32 byte) |
| `PUBLIC_URL` | URL công khai của server | **Để trống** nếu agent kết nối qua LAN/IP nội bộ |
| `STORAGE_PATH` | Thư mục lưu file | Mặc định `/app/storage` |
| `DEFAULTS_PATH` | Nơi chứa binary agent dựng sẵn | Mặc định `/app/defaults` |

> ⚠️ `PUBLIC_URL`: nếu đặt domain mà agent không truy cập được domain đó, agent sẽ **không tải tool xuống được**. Để trống → hệ thống tự nhận diện host mà agent đang kết nối.

### 3.2. Triển khai agent lên máy cần điều tra

1. Vào **Agents → Add Agent / Download Installer**.
2. Chạy installer trên máy đích (**nên chạy Administrator** để đủ quyền forensic).
3. Agent tự kết nối về server → hiện **Online** trong danh sách.

### 3.3. Luồng điều tra chuẩn (nên đi theo thứ tự này)

```
1. Tạo Case            → Case Manager
2. Gán Agent vào Case  → Agent detail → Case
3. Upload Tool         → Tools (khai báo output spec để tự thu kết quả)
4. Chạy tool / forensic→ Agent detail → Jobs / Edge Forensics
5. Kết quả tự thu về   → Evidence Store + Collected Results
6. AI phân tích        → findings tự đổ vào Timeline của case
7. Đọc Timeline, bổ sung → Case Manager
8. Xuất báo cáo        → Incident Report / STIX
```

---

## 4. Chi tiết từng tính năng

### 4.1. Dashboard *(Overview)*
Màn hình tổng quan: số agent online, job đang chạy, case mở, cảnh báo mới nhất. Dùng để nắm nhanh tình hình đầu ca trực.

---

### 4.2. Case Manager *(Overview → Case Manager)*

**Là gì:** đơn vị tổ chức công việc. Mọi bằng chứng, timeline, IOC, agent đều gắn vào một **case**.

**Cách dùng:**
1. **New Case** → đặt tên, mô tả.
2. Mở case → gán **Agent** liên quan (hoặc gán từ trang Agent).
3. Trong case bạn có:
   - **Evidence**: file bằng chứng upload thủ công hoặc tự động đổ vào.
   - **Attack Timeline**: dòng thời gian tấn công (nguồn: AI, trace, import artifact, nhập tay).
   - **Findings / IOC**: chỉ dấu thu được.
4. **Nút hành động quan trọng** (theo đúng thứ tự nên bấm):

| Nút | Làm gì |
|---|---|
| **Analyze Evidence** | AI quét **mọi job trong case** (mọi host) → rút findings → đổ vào **một timeline chung** |
| **AI Summary** | AI viết tường thuật từ timeline đã có |
| **Incident Report** | Xuất báo cáo HTML/PDF |
| **Export STIX** | Xuất IOC chuẩn STIX |

> 💡 Thứ tự đúng: **Analyze Evidence** (rút finding) → **AI Summary** (tường thuật) → **Report**.

---

### 4.3. Agents *(Endpoints & Tools → Agents)*

Danh sách máy đã cài agent, kèm trạng thái online/offline và **CPU/RAM/Disk realtime**.

Mở một agent, bạn có các tab:

| Tab | Dùng để làm gì |
|---|---|
| **Jobs** | Tạo & theo dõi job chạy tool trên máy này |
| **System Info** | Thông tin hệ thống, phần cứng |
| **Network** | Kết nối TCP/UDP đang mở, DNS cache |
| **Processes** | Tiến trình đang chạy (có thể kill) |
| **Terminal** | Shell tương tác trực tiếp trên endpoint |
| **Files** | Duyệt / tải file từ máy đích (admin) |
| **Scanner** | YARA Scanner: quét webshell/malware theo kịch bản |
| **Registry Viewer** | Đọc registry từ xa |
| **EVTX Logs** | Đọc Windows Event Log |
| **Edge Forensics** | ⭐ Bộ forensic tại chỗ (xem dưới) |

#### Edge Forensics — điều tra tại chỗ (quan trọng nhất)

Chạy **trực tiếp trên endpoint**, không cần copy file về. Mỗi tab là một nguồn bằng chứng:

| Scan | Thu được gì |
|---|---|
| **File Forensics (MFT)** | Metadata file + hash MD5/SHA1/SHA256, timestamp NTFS |
| **Prefetch** | Bằng chứng thực thi: chương trình nào đã chạy, bao nhiêu lần, lần cuối khi nào |
| **Processes** | Cây tiến trình + user + command line + hash |
| **Autoruns** | Persistence: Run keys, service, scheduled task, WMI, IFEO… |
| **Loaded DLLs** | DLL đang nạp, cờ nghi ngờ DLL-hijack/injection |
| **Shimcache** | Bằng chứng thực thi bổ sung |
| **Browser** | Lịch sử duyệt web mọi profile |
| **Network** | Kết nối mạng + reverse DNS |
| **Triage Collection** | Gom trọn bộ artifact trong **một lượt elevated (1 UAC)** |

**Cách dùng:**
1. Chọn tab → **Run Scan** (cần agent Online + quyền Admin).
2. Kết quả tự **đối chiếu IOC store** — dòng khớp IOC được tô đậm.
3. Tick chọn dòng nghi ngờ → hai lựa chọn:
   - **Save to Case + promote IOC** → đẩy thẳng vào timeline + IOC store.
   - **AI triage → timeline** → để AI đọc các dòng đó, tự rút finding vào timeline.
4. Mỗi lần scan đều **tự lưu một bản snapshot vào Evidence Store** (dấu vết điều tra).

---

### 4.4. Tools *(Endpoints & Tools → Tools)* ⭐

**Là gì:** kho công cụ forensic. Bạn upload tool lên đây một lần, sau đó **đẩy xuống bất kỳ agent nào**.

**Upload tool — các trường cần khai báo:**

| Trường | Ý nghĩa |
|---|---|
| Name / Category / Platform | Phân loại (windows/linux/both) |
| File | File `.exe` hoặc `.zip` (zip sẽ được giải nén) |
| **Executable path** | Với zip: đường dẫn tới file chạy bên trong, vd `Redline\Windows\RunRedlineAudit.bat` |
| Args | Tham số mặc định |

**Phần "Result collection" — đây là thứ làm nên tự động hoá:**

| Trường | Ý nghĩa |
|---|---|
| **Collect result** | Bật = tự thu file kết quả sau khi chạy xong |
| **Output globs** | Mẫu tên file cần lấy, vd `*.csv,*.json,*.log` |
| **Output scope** | Tìm ở `outdir` (thư mục kết quả riêng), `tooldir`, hay `both` |
| **Result processor** | Bộ parse: `auto`, `text`, `csv`, `json`, `loki`, `redline`, `kape`, `evtx`, `pcap`, `sqlite`, `registry` |
| **Send to AI by default** | Kết quả tự đánh dấu để AI phân tích |
| **Auto-analyze on finish** | ⚡ Job xong → **tự chạy AI** rút finding vào timeline (không cần bấm) |
| **Max result MB** | Giới hạn dung lượng mỗi file |

> 💡 Dùng `{{OUTDIR}}` trong Args để tool ghi kết quả vào thư mục riêng của job — hệ thống tự thu đúng chỗ.
> Ví dụ Loki: `--noindicator --dontwait --csv -l {{OUTDIR}}\loki`

---

### 4.5. Jobs — chạy tool trên endpoint

**Cách dùng:** Agent detail → **Jobs → New Job** → chọn tool + args (có thể giới hạn CPU/RAM/priority) → **Run**.

**Điều gì xảy ra bên trong:**
1. Server gửi lệnh `job_start` qua WebSocket kèm URL tải tool.
2. Agent tải tool (có cache — lần sau không tải lại), giải nén nếu là zip.
3. Agent chạy tool **từ đúng thư mục của tool** (quan trọng với tool nhiều file như Redline/KAPE).
4. Output stream realtime về giao diện.
5. Xong → agent **tự thu file kết quả** theo output spec.

**Trên trang Job Detail:**
- **Process Output**: log realtime.
- **Report Viewer**: xem report HTML tool sinh ra.
- **Collected Results**: danh sách file đã thu, kèm trạng thái parse, `Use for AI`, Download, và **Extract findings → timeline**.
- **AI Narrative Report**: mở bản tường thuật AI dạng văn xuôi.

---

### 4.6. Cơ chế tự thu kết quả (Auto Result Collection) ⭐

Đây là "xương sống" tự động hoá — chạy ngầm, bạn không phải thao tác:

```
Tool chạy xong
   → Agent quét file theo glob + thời gian sửa đổi (chỉ file mới sinh)
   → Chờ file ghi xong (settle) → tính SHA-256
   → Hỏi server: đã có file trùng hash chưa? (nếu có → link, KHÔNG truyền lại)
   → Nếu chưa: nén gzip → upload (retry 3 lần, tối đa 3 file song song)
   → Upload fail hẳn → lưu vào spool trên đĩa, tự gửi lại khi kết nối lại
   → Server giải nén, verify SHA-256, xếp hàng xử lý
   → Worker parse (csv/json/loki/redline/kape/evtx/pcap/sqlite/registry)
   → Ghi vào Evidence Store + đánh dấu for-AI
   → (nếu tool bật Auto-analyze) → AI rút finding → Timeline + IOC
```

**Đảm bảo toàn vẹn & truy vết:** mỗi file lưu kèm **SHA-256**, **command line đã chạy**, **exit code**, **phiên bản tool** → đủ chuẩn chain-of-custody.

---

### 4.7. Evidence Store *(Threat Intelligence → IOC Store → tab Evidence Store)* ⭐

**Là gì:** kho bằng chứng tập trung của toàn hệ thống.

**Tự động nhận file từ 4 nguồn:**
| Nguồn (`kind`) | Khi nào |
|---|---|
| `tool-result` | Tool chạy xong, file kết quả tự thu |
| `checklist` | Mỗi lần chạy Evidence & Compliance checklist |
| `edge-forensics` | **Mỗi lần** scan Edge Forensics |
| `artifact` | Report/artifact tool sinh ra (vd report.html của YARA) |
| `upload` | Bạn upload tay |

**Cách dùng:**
- Lọc theo **kind / host / từ khoá** (phân trang server-side, chịu được kho lớn).
- Mỗi file: **View** (xem inline) · **Download** · **Delete** · **🧠 AI** (mở AI Analysis phân tích chi tiết file đó).

---

### 4.8. AI Analysis *(Analysis → AI Analysis)* ⭐

#### Bước 1 — Cấu hình provider
**AI Providers** → Add: chọn preset (**OpenAI / Anthropic / Google / DeepSeek**) → điền API key → Save.
API key được **mã hoá AES-256** trước khi lưu DB.

> DeepSeek: base URL `https://api.deepseek.com/v1`, model `deepseek-chat` hoặc `deepseek-reasoner`.

#### Bước 2 — Hai kiểu phân tích (đừng nhầm)

| Kiểu | Vào từ đâu | Cho ra gì |
|---|---|---|
| **Findings có cấu trúc** | "Extract findings → timeline" (Job), "Analyze Evidence" (Case), "AI triage" (Edge Forensics) | Finding chuẩn → **đổ vào Timeline + IOC store** |
| **Tường thuật (narrative)** | Trang **AI Analysis** | Báo cáo văn xuôi chi tiết, có streaming + chain-of-work |

#### Nguồn cho AI Analysis
`job` · `checklist_run` · `elk_result` · `upload` (file bất kỳ) · `offline_report` · `evidence` (từ Evidence Store).

#### Cách AI xử lý dữ liệu lớn
- File nhỏ → phân tích 1 lần.
- **File lớn → tự chia chunk → tóm tắt song song (MAP) → tổng hợp theo lô (REDUCE) → gộp + khử trùng** → không bỏ sót phần đuôi.
- Mỗi finding có: thời điểm, mức độ, **độ tin cậy**, kỹ thuật MITRE ATT&CK, bằng chứng, chỉ dấu.

---

### 4.9. Offline Bundles *(Endpoints & Tools → Offline Bundles)*

**Dùng khi:** máy đích **không được phép** nhận agent kết nối mạng (air-gapped, policy chặt).

**Ba giai đoạn:**

1. **Tạo bundle** (trên console): chọn tool + platform (+ case, checklist/playbook kèm theo) → server đóng gói **1 file .exe tự chứa** (manifest + tool + agent offline).
2. **Chạy trên máy đích** (không cần mạng):
   - Copy file sang, **chạy** → hệ thống **tự xin quyền Administrator (1 lần UAC)**.
   - Mở **UI cục bộ ngay trên máy đó** → chạy từng tool hoặc **Collect Everything**.
   - Chế độ CLI (`--cli`) cho môi trường SSH/headless: lệnh `run`, `status`, `output <job>`, `report`.
   - Xong → xuất **report.html** (đọc) + **report.json** (để import).
3. **Mang về import**: Case Manager → **Import Offline Report** → mỗi tool thành một Job trong case; AI phân tích qua nguồn `offline_report`.

> Kiểm tra tool đã chạy chưa: `status` (done/failed) · `output <job-id>` (log) · và **file kết quả thực tế** (vd DumpIt ra file `.raw`/`.dmp`, Redline ra thư mục `.mans`).

---

### 4.10. Collection & Hunting

#### Scenario Hunting *(+ Sigma)*
Chọn **kịch bản săn** (ransomware, credential theft, persistence, lateral movement…) → deploy xuống **nhiều agent cùng lúc** → kết quả gom về theo case. Hỗ trợ **Sigma rule** để quét log theo luật.

#### Evidence & Compliance *(Collection Checklist)*
Bộ **checklist thu thập bằng chứng** chuẩn IR: chọn các mục cần thu (theo nhóm: network state, process, persistence…) → dispatch **song song** xuống agent → mỗi nhóm là một batch có output riêng.
Chạy xong: **toàn bộ run được lưu thành 1 file evidence** trong Evidence Store.

#### Playbooks
Quy trình xử lý sự cố dạng từng bước (hướng dẫn cho responder).

---

### 4.11. Threat Intelligence

| Mục | Dùng để |
|---|---|
| **IOC Store** | Kho chỉ dấu tập trung: thêm tay, **bulk import** (hỗ trợ defang `1[.]2[.]3[.]4`, `hxxp://`), sync OpenCTI. Dùng cho IOC Sweep + tự đối chiếu mọi kết quả scan |
| **Vulnerability Search** | Tra cứu CVE |
| **Threat Intelligence** | Tin tức/threat feed (gồm dark web news) |
| **OSINT** | Điều tra nguồn mở theo mục tiêu |

---

### 4.12. Analysis khác

- **Sandbox Analysis**: phân tích file nghi ngờ trong môi trường cách ly.
- **ELK**: kết nối Elasticsearch/Kibana để hunt trên log tập trung; kết quả hunt có thể đưa cho AI (`elk_result`).

---

### 4.13. System Health *(System → System Health)* ⭐

**Theo dõi sức khoẻ hệ thống:**
- Trạng thái **PostgreSQL / Redis / Storage / WebSocket Hub**, DB pool, goroutine, RAM/Disk server.
- **Agent Resources**: CPU/RAM/Disk từng agent online (agent gửi mỗi 30s).
- **Auto-update**: các nguồn dữ liệu tự cập nhật (nuclei templates, retire.js, CISA KEV, cdncheck, WPScan) — trạng thái `ok` / `idle` / `failed` / **`↻ retrying`**.
- **Self-Heal Events**: lịch sử lỗi hệ thống **và những gì hệ thống đã tự sửa**.

**Hệ thống tự chữa lỗi (chạy ngầm):**
| Cơ chế | Hành vi |
|---|---|
| Updater retry | Nguồn cập nhật lỗi → tự thử lại backoff 1m → 3m → 9m → 27m (thay vì chờ trọn chu kỳ 24h/7d) |
| Stuck-job watcher | Job "running" quá 6h, hoặc agent rớt >5 phút → tự đánh dấu failed |
| Worker watchdog | Worker ngừng nhịp → ghi cảnh báo |
| Panic recovery | Lỗi trong 1 nhịp worker/agent không làm sập tiến trình |

---

### 4.14. Proxy Manager *(System)*
Quản lý proxy cho các tác vụ ra ngoài Internet (OSINT, feed…): thêm profile, kiểm tra sức khoẻ, xoay proxy.

---

## 5. Vận hành

### Backup
```bash
# Database
docker compose exec -T postgres pg_dump -U analysishub analysishub > backup-$(date +%F).sql
# Storage (tool, artifact, evidence)
tar czf storage-$(date +%F).tar.gz ./storage
```

### Cập nhật hệ thống
```bash
docker compose up -d --build backend frontend
```

### Cập nhật agent
Agent **không tự cập nhật**. Khi có thay đổi phía agent:
```bash
cd agent && go build ./cmd/agent            # agent online
make build-offline-windows                  # agent offline (cho bundle)
```
Với **offline bundle**: copy binary mới vào `DEFAULTS_PATH` của backend (`/app/defaults/agent-offline.exe`) rồi **tạo lại bundle** — vì binary được nhúng sẵn trong bundle.

---

## 6. Xử lý sự cố thường gặp

| Triệu chứng | Nguyên nhân & cách xử lý |
|---|---|
| **"encryption failed"** khi thêm AI provider | `AES_ENCRYPTION_KEY` có vấn đề. Bản mới tự hash key về 32 byte nên **độ dài nào cũng chạy** — chỉ cần **không để rỗng** rồi restart backend |
| **Agent không tải được tool** (401 / sai domain) | `PUBLIC_URL` trỏ tới domain agent không truy cập được → **để trống** `PUBLIC_URL`; agent cũng tự đổi host về server nó đang kết nối |
| **Agent online chập chờn, không nhận lệnh** | Agent bản cũ có thể crash. **Cập nhật binary agent mới** (đã có panic-recovery) |
| **Tool chạy nháy rồi tắt, không ra kết quả** | (1) Chưa chạy **Administrator** — DumpIt/Redline bắt buộc admin; (2) tool nhiều file cần chạy đúng thư mục của nó — bản mới đã sửa. Kiểm tra: `output <job-id>` và xem file kết quả có sinh ra không |
| **Report Viewer không hiển thị** | Trình duyệt chặn iframe. Bản mới đã sửa header sandbox — cập nhật backend |
| **AI trả về 0 finding** | Có thể dữ liệu thật sự sạch. Xem log backend `grep ai-findings` — nếu có dòng `unparseable` thì do model trả sai định dạng, đổi model hoặc bật lại JSON mode |
| **Job kẹt "running"** | Watchdog tự dọn sau 6h (hoặc 5 phút nếu agent offline). Muốn ngay: Stop job |

---

## 7. Bảng tra nhanh — "Tôi muốn… thì vào đâu?"

| Tôi muốn… | Vào |
|---|---|
| Bắt đầu một vụ điều tra | **Case Manager → New Case** |
| Xem máy nào đang online | **Agents** |
| Chạy Loki/YARA quét một máy | **Agents → [máy] → Jobs → New Job** |
| Xem tiến trình / autoruns / prefetch của máy | **Agents → [máy] → Edge Forensics** |
| Gõ lệnh trực tiếp trên máy đích | **Agents → [máy] → Terminal** |
| Thêm công cụ mới vào kho | **Tools → Upload** |
| Điều tra máy air-gapped | **Offline Bundles** |
| Xem toàn bộ bằng chứng đã thu | **IOC Store → tab Evidence Store** |
| Cho AI phân tích một file | **Evidence Store → 🧠** hoặc **AI Analysis** |
| Dựng timeline tấn công | **Case → Analyze Evidence** |
| Xuất báo cáo sự cố | **Case → Incident Report** |
| Quét hàng loạt máy theo kịch bản | **Scenario Hunting** |
| Kiểm tra hệ thống có khoẻ không | **System Health** |

---

## 8. Nguyên tắc bảo mật khi dùng

- Chỉ dùng trên **hệ thống bạn được phép điều tra**.
- Agent có quyền rất cao (đọc file, kill process, chạy lệnh) → **giới hạn tài khoản admin**, bật audit log.
- File evidence là dữ liệu nhạy cảm → phân quyền truy cập, có backup, cân nhắc bật retention để không phình đĩa.
- API key AI được mã hoá trong DB; **đừng commit `.env`** lên git.
