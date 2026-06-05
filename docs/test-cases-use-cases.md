# ForensicHub-v2 — Test Cases & Use Cases

> **Phiên bản:** 1.0 | **Cập nhật:** 2026-06-06  
> **Phạm vi:** Forensic & Hunting modules  
> **Loại trừ:** Threat Intelligence (CVE, CVE Collection, OpenCTI, IOC, News)

---

## Quy ước ký hiệu

| Ký hiệu | Ý nghĩa |
|---------|---------|
| `UC-XX-YY` | Use Case (XX = module code, YY = số thứ tự) |
| `TC-XX-YY` | Test Case (XX = module code, YY = số thứ tự) |
| **P** | Positive test (happy path) |
| **N** | Negative test (error / invalid input) |
| **E** | Edge case (boundary / race condition / large data) |
| **S** | Security test |

### Module codes

| Code | Module |
|------|--------|
| AUTH | Authentication & User |
| AGT | Agent Management |
| FSB | Filesystem Browser |
| TOOL | Tools Management |
| JOB | Jobs / Tool Execution |
| CCL | Evidence Collection Checklist |
| HNT | Hunting Scenarios & Deployments |
| ELK | ELK Threat Hunting |
| CASE | Case Management |
| AI | AI Analysis & Providers |
| SYS | System Health Monitoring |
| WS | WebSocket / Real-time |

---

## 1. Authentication & User Management (AUTH)

### 1.1 Use Cases

#### UC-AUTH-01 — Đăng nhập hệ thống

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst / Admin |
| **Precondition** | Tài khoản đã được tạo trong DB |
| **Main Flow** | 1. Người dùng nhập email + password → 2. Backend xác thực bcrypt → 3. Trả về JWT → 4. Frontend lưu token, redirect sang Dashboard |
| **Postcondition** | Session JWT hợp lệ, người dùng có thể truy cập các route được bảo vệ |
| **Alt Flow A** | Sai mật khẩu → trả về 401, hiển thị thông báo lỗi |
| **Alt Flow B** | Tài khoản không tồn tại → trả về 401 (không tiết lộ lý do cụ thể) |

#### UC-AUTH-02 — Xem thông tin tài khoản hiện tại

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst / Admin đã đăng nhập |
| **Precondition** | JWT hợp lệ trong header |
| **Main Flow** | 1. Frontend gọi `GET /api/v1/auth/me` → 2. Backend decode JWT → 3. Query user từ DB → 4. Trả về `{id, email, name, role}` |
| **Postcondition** | Frontend hiển thị thông tin user trong header/sidebar |
| **Alt Flow A** | JWT hết hạn → 401, frontend redirect sang login |

### 1.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-AUTH-01 | Đăng nhập thành công | User `admin@forensichub.local` tồn tại | `{email: "admin@forensichub.local", password: "Admin@123456"}` | HTTP 200, response có `token` (JWT), `user.role = "admin"` | P |
| TC-AUTH-02 | Đăng nhập sai mật khẩu | User tồn tại | `{email: "admin@forensichub.local", password: "WrongPass"}` | HTTP 401, `{success: false, error: "..."}` | N |
| TC-AUTH-03 | Đăng nhập email không tồn tại | — | `{email: "notexist@x.com", password: "any"}` | HTTP 401 (không tiết lộ "email not found" vs "wrong password") | N/S |
| TC-AUTH-04 | Đăng nhập thiếu trường email | — | `{password: "Admin@123456"}` | HTTP 400, validation error | N |
| TC-AUTH-05 | Gọi `/auth/me` với JWT hợp lệ | Đã có JWT | Header `Authorization: Bearer <valid_jwt>` | HTTP 200, `{id, email, name, role}` | P |
| TC-AUTH-06 | Gọi `/auth/me` với JWT hết hạn | JWT đã expire | Header `Authorization: Bearer <expired_jwt>` | HTTP 401 | N |
| TC-AUTH-07 | Gọi `/auth/me` không có header | — | Không có Authorization header | HTTP 401 | N |
| TC-AUTH-08 | Gọi `/auth/me` với JWT giả mạo | — | Header với JWT ký sai secret | HTTP 401 | S |
| TC-AUTH-09 | SQL Injection trong email | — | `{email: "' OR 1=1 --", password: "x"}` | HTTP 401, không crash, không bypass auth | S |
| TC-AUTH-10 | Brute force giới hạn | — | 20 lần đăng nhập sai liên tiếp | Không bị rate-limit crash, consistent 401 | E |

---

## 2. Agent Management (AGT)

### 2.1 Use Cases

#### UC-AGT-01 — Tạo và đăng ký agent mới

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Đã đăng nhập, có quyền admin |
| **Main Flow** | 1. Admin tạo agent qua UI (name, description) → 2. Backend tạo record, sinh token 32-byte hex → 3. Hiển thị install script → 4. Admin chạy script trên endpoint → 5. Agent kết nối WebSocket với token → 6. Backend cập nhật hostname/OS/IP, status=online |
| **Postcondition** | Agent hiển thị online trong danh sách, có thể nhận job |
| **Alt Flow A** | Endpoint không thể kết nối ra Internet → agent không thể đăng ký, status vẫn offline |

#### UC-AGT-02 — Theo dõi trạng thái agent

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Có ít nhất 1 agent đã đăng ký |
| **Main Flow** | 1. Analyst mở trang Agents → 2. Xem danh sách với status badge (online/offline) → 3. Click agent để xem detail (hostname, IP, OS, last seen, CPU/RAM/Disk) |
| **Postcondition** | Analyst biết endpoint nào đang hoạt động |
| **Alt Flow A** | Agent mất kết nối → status tự động chuyển offline sau timeout |

#### UC-AGT-03 — Xóa agent

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Agent không có job đang running |
| **Main Flow** | 1. Admin chọn agent → Delete → 2. Confirm dialog → 3. Backend xóa record, hủy WebSocket connection → 4. Agent biến mất khỏi danh sách |
| **Postcondition** | Token cũ không còn hợp lệ, agent không thể kết nối lại với token đó |
| **Alt Flow A** | Agent có job đang running → hiển thị warning, yêu cầu stop jobs trước |

#### UC-AGT-04 — Lấy install script

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Agent đã được tạo (có token) |
| **Main Flow** | 1. Mở Agent Detail → tab Installer → 2. Chọn platform (Windows/Linux) → 3. Copy hoặc download script → 4. Script chứa token, server URL, agent binary URL |
| **Postcondition** | Admin có script sẵn sàng chạy trên endpoint |

#### UC-AGT-05 — Cleanup agent cache

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Agent đang online, có tool cache trên disk |
| **Main Flow** | 1. Admin click Cleanup trên agent → 2. Backend gửi `cleanup` message qua WebSocket → 3. Agent xóa workdir/tools/* → 4. Trả về kết quả |
| **Postcondition** | Disk agent giảm, các job tiếp theo sẽ download tool lại từ đầu |

### 2.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-AGT-01 | Tạo agent với tên hợp lệ | Đã đăng nhập admin | `{name: "HOST-01", description: "Web server"}` | HTTP 201, `{id, name, token}`, token 64 hex chars | P |
| TC-AGT-02 | Tạo agent tên trùng | Agent "HOST-01" đã tồn tại | `{name: "HOST-01"}` | HTTP 409 hoặc tên được phép trùng (token khác nhau) | P/N |
| TC-AGT-03 | Tạo agent tên chứa ký tự đặc biệt hợp lệ | — | `{name: "HOST_01.web-server"}` | HTTP 201 (chấp nhận letters, digits, space, dot, underscore, hyphen) | P |
| TC-AGT-04 | Tạo agent tên chứa ký tự không hợp lệ | — | `{name: "HOST<>01"}` | HTTP 400, validation error | N |
| TC-AGT-05 | Tạo agent tên rỗng | — | `{name: ""}` | HTTP 400 | N |
| TC-AGT-06 | Lấy danh sách agent | Có 3 agent đã tạo | GET /agents | HTTP 200, array có đúng số agents với các trường cần thiết | P |
| TC-AGT-07 | Xem detail agent | Agent tồn tại | GET /agents/:id | HTTP 200, có `hostname`, `os`, `ip_address`, `status`, `last_seen` | P |
| TC-AGT-08 | Xem detail agent không tồn tại | — | GET /agents/00000000-0000-0000-0000-000000000000 | HTTP 404 | N |
| TC-AGT-09 | Update tên agent | Agent tồn tại | PATCH /agents/:id `{name: "HOST-01-renamed"}` | HTTP 200, tên được cập nhật | P |
| TC-AGT-10 | Assign agent vào case | Agent + Case tồn tại | PATCH /agents/:id `{case_id: "<uuid>"}` | HTTP 200, `agent.case_id` được set | P |
| TC-AGT-11 | Unassign agent khỏi case | Agent đang trong case | PATCH /agents/:id `{case_id: null}` | HTTP 200, `agent.case_id = null` | P |
| TC-AGT-12 | Xóa agent | Agent tồn tại, không có running job | DELETE /agents/:id | HTTP 200, agent không còn trong danh sách | P |
| TC-AGT-13 | Lấy PowerShell install script | Agent tồn tại | GET /agents/:id/install.ps1 | HTTP 200, content-type text/plain, script chứa token và server URL | P |
| TC-AGT-14 | Lấy Bash install script | Agent tồn tại | GET /agents/:id/install.sh | HTTP 200, script Linux hợp lệ | P |
| TC-AGT-15 | Download binary Windows | — | GET /agents/binary/windows | HTTP 200 hoặc redirect, file .exe | P |
| TC-AGT-16 | Download binary platform không hợp lệ | — | GET /agents/binary/macos | HTTP 400 | N |
| TC-AGT-17 | Agent online — kiểm tra resource telemetry | Agent online, gửi resource_report | Xem GET /agents/:id | `cpu_percent`, `mem_used_mb`, `disk_used_gb` được cập nhật | P |
| TC-AGT-18 | Cleanup khi agent offline | Agent offline | POST /agents/:id/cleanup | HTTP 400 hoặc 503 "agent offline" | N |
| TC-AGT-19 | Token không được trả về khi list agents | — | GET /agents | Response không chứa `token` field trong array items | S |
| TC-AGT-20 | Tạo agent khi không phải admin | Đăng nhập với role analyst | POST /agents | HTTP 403 | S |

---

## 3. Filesystem Browser (FSB)

### 3.1 Use Cases

#### UC-FSB-01 — Duyệt thư mục trên agent

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Agent đang online |
| **Main Flow** | 1. Mở Agent Detail → tab Files → 2. Nhập path (VD: `C:\Windows\System32`) → 3. Backend gửi `fs_request {op: "list"}` qua WebSocket → 4. Agent trả về danh sách file/folder → 5. Hiển thị trong FileBrowser component |
| **Postcondition** | Analyst thấy danh sách entries với name, size, type, modified time |
| **Alt Flow A** | Path không tồn tại → hiển thị error message |
| **Alt Flow B** | Permission denied trên agent → hiển thị error |

#### UC-FSB-02 — Download file từ agent

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Agent online, file tồn tại trên agent |
| **Main Flow** | 1. Browse đến file → click Download → 2. Backend gửi `fs_request {op: "read_file"}` → 3. Agent stream file qua WebSocket (base64 chunks) → 4. Backend reassemble, gửi về browser → 5. Browser download file, thêm vào DownloadedFilesPanel |
| **Postcondition** | File lưu trong thư mục download của browser, entry xuất hiện trong lịch sử |
| **Alt Flow A** | File > 100MB → truncated, hiển thị warning |

#### UC-FSB-03 — Download bundle (nhiều file)

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Agent online, nhiều file cần thu thập |
| **Main Flow** | 1. Select nhiều files → Download Bundle → 2. Backend gửi `fs_request {op: "read_bundle"}` → 3. Agent đóng gói ZIP → 4. Backend stream ZIP về browser |
| **Postcondition** | Browser download 1 file ZIP chứa tất cả files đã chọn |

#### UC-FSB-04 — Xem lịch sử download

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Đã download ít nhất 1 file từ agent |
| **Main Flow** | 1. Mở Agent Detail → DownloadedFilesPanel → 2. Xem danh sách với filename, size, source path, thời gian → 3. Click Re-download để fetch lại file từ agent |
| **Postcondition** | Lịch sử được lưu trong localStorage, không mất khi reload trang |

### 3.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-FSB-01 | List thư mục hợp lệ | Agent online | `GET /agents/:id/fs?path=C:\Windows` | HTTP 200, array entries với name, size, is_dir, modified | P |
| TC-FSB-02 | List root thư mục | Agent online | `GET /agents/:id/fs?path=C:\` | HTTP 200, danh sách drives/folders | P |
| TC-FSB-03 | List path không tồn tại | Agent online | `GET /agents/:id/fs?path=C:\NonExistentPath` | HTTP 404 hoặc error từ agent | N |
| TC-FSB-04 | List khi agent offline | Agent offline | GET /agents/:id/fs?path=C:\ | HTTP 503 "agent offline" | N |
| TC-FSB-05 | Download file nhỏ (<1MB) | Agent online, file tồn tại | `GET /agents/:id/fs/download?path=C:\test.txt` | HTTP 200, file content đúng, Content-Disposition header | P |
| TC-FSB-06 | Download file lớn (>50MB) | Agent online, file lớn | Download file 100MB | File được stream thành công, không timeout | E |
| TC-FSB-07 | Download file không tồn tại | Agent online | path không tồn tại trên agent | HTTP 404 | N |
| TC-FSB-08 | Path traversal trong download | Agent online | `path=../../etc/passwd` | HTTP 400, bị chặn | S |
| TC-FSB-09 | Download bundle nhiều files | Agent online | POST /agents/:id/fs/download-bundle với array paths | HTTP 200, ZIP file, chứa đúng số files | P |
| TC-FSB-10 | Bundle với 1 file không tồn tại | Agent online | Bundle path array có 1 path invalid | ZIP download thành công với files hợp lệ, error cho file không tồn tại | E |
| TC-FSB-11 | Re-download từ lịch sử khi agent offline | Agent offline | Click re-download trong DownloadedFilesPanel | Toast "Agent is offline", không crash | N |
| TC-FSB-12 | Clear lịch sử download | Có entries trong panel | Click "Clear all" | Confirm dialog, xóa hết, panel hiển thị empty state | P |

---

## 4. Tools Management (TOOL)

### 4.1 Use Cases

#### UC-TOOL-01 — Upload tool mới

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Đã đăng nhập admin |
| **Main Flow** | 1. Mở trang Tools → Upload → 2. Điền metadata (name, category, platform, version, description, args) → 3. Upload file binary/ZIP → 4. Nếu ZIP: nhập executable_path → 5. Backend lưu file vào storage, tạo DB record |
| **Postcondition** | Tool xuất hiện trong catalog, agents có thể download và execute |
| **Alt Flow A** | File quá lớn → thông báo lỗi |
| **Alt Flow B** | executable_path không match file trong ZIP → validate error |

#### UC-TOOL-02 — Tìm và filter tools

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Có ít nhất 5 tools trong catalog |
| **Main Flow** | 1. Mở trang Tools → 2. Filter theo category (memory/triage/process/network/disk/log) → 3. Filter theo platform (windows/linux/both) → 4. Tìm kiếm theo tên |
| **Postcondition** | Danh sách tools được lọc theo tiêu chí |

#### UC-TOOL-03 — Xóa tool không còn cần thiết

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Tool không có job đang running |
| **Main Flow** | 1. Chọn tool → Delete → 2. Confirm → 3. Backend xóa file khỏi storage, xóa DB record |
| **Postcondition** | Tool không xuất hiện trong catalog, các job cũ vẫn giữ metadata nhưng không thể chạy lại |

### 4.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-TOOL-01 | Upload tool binary đơn (non-ZIP) | Admin logged in | multipart: name="netstat-tool", category=network, platform=windows, file=netstat.exe | HTTP 201, `{id, name, file_size, ...}` | P |
| TC-TOOL-02 | Upload tool dạng ZIP | Admin logged in | multipart: file=toolbundle.zip, executable_path=bin/tool.exe | HTTP 201, executable_path được lưu | P |
| TC-TOOL-03 | Upload với executable_path trỏ ra ngoài ZIP | — | executable_path=../../etc/passwd | HTTP 400, path traversal blocked | S |
| TC-TOOL-04 | Upload file rỗng | — | file size = 0 bytes | HTTP 400 | N |
| TC-TOOL-05 | Upload thiếu trường bắt buộc (name) | — | multipart không có name | HTTP 400 | N |
| TC-TOOL-06 | Category không hợp lệ | — | category="invalid_cat" | HTTP 400 | N |
| TC-TOOL-07 | Platform không hợp lệ | — | platform="macos" | HTTP 400 | N |
| TC-TOOL-08 | Lấy danh sách tools, filter by category | Có tools nhiều category | GET /tools?category=memory | HTTP 200, chỉ trả về tools có category=memory | P |
| TC-TOOL-09 | Lấy danh sách tools, filter by platform | — | GET /tools?platform=linux | HTTP 200, chỉ tools platform=linux hoặc both | P |
| TC-TOOL-10 | Update tool metadata | Tool tồn tại | PUT /tools/:id `{description: "updated desc", args: "-v --json"}` | HTTP 200, metadata được cập nhật | P |
| TC-TOOL-11 | Xóa tool | Tool tồn tại | DELETE /tools/:id | HTTP 200, tool không còn trong GET /tools | P |
| TC-TOOL-12 | Download tool binary | Tool tồn tại | GET /tools/:id/download | HTTP 200, file content đúng, Content-Disposition header | P |
| TC-TOOL-13 | Upload file >8GB | — | Rất lớn file | HTTP 413 hoặc streaming error | E |
| TC-TOOL-14 | Upload tool khi không phải admin | Analyst role | POST /tools | HTTP 403 | S |
| TC-TOOL-15 | Xem tool detail | Tool tồn tại | GET /tools/:id | HTTP 200, đầy đủ fields, không lộ server file path | P/S |

---

## 5. Jobs — Tool Execution (JOB)

### 5.1 Use Cases

#### UC-JOB-01 — Tạo và chạy job trên agent

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Agent online, tool đã upload |
| **Main Flow** | 1. Mở Jobs → New Job → 2. Chọn agent, tool, nhập args → 3. POST /jobs → status=pending → 4. Backend gửi `job_start` WebSocket → agent download tool (status=ready) → 5. Click Run → `job_run` WebSocket → agent execute → 6. Output stream theo thời gian thực → 7. Job kết thúc → status=done, artifact upload (nếu có) |
| **Postcondition** | Output hiển thị trên màn hình, artifact có thể download |
| **Alt Flow A** | Tool không tương thích với OS của agent → job fail với error message |
| **Alt Flow B** | Agent disconnect giữa chừng → job chuyển sang failed |

#### UC-JOB-02 — Dừng job đang chạy

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Job đang ở trạng thái running |
| **Main Flow** | 1. Mở JobDetail → click Stop → 2. Backend gửi `job_stop` WebSocket → agent kill process → 3. Status chuyển sang stopped |
| **Postcondition** | Output tới thời điểm dừng được lưu, artifact (nếu đã upload một phần) được giữ |

#### UC-JOB-03 — Xem lại output job cũ

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Job đã done/failed |
| **Main Flow** | 1. Mở Jobs list → click vào job → 2. Xem output đã lưu trong DB → 3. Nếu có artifact: download file |
| **Postcondition** | Output vẫn hiển thị đầy đủ dù job đã kết thúc lâu |

#### UC-JOB-04 — Filter và tìm kiếm jobs

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Có nhiều jobs từ nhiều agents |
| **Main Flow** | 1. Mở Jobs → filter by agent, status, date range → 2. Kết quả được cập nhật ngay |
| **Postcondition** | Analyst có thể tìm job cụ thể nhanh chóng |

### 5.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-JOB-01 | Tạo job hợp lệ | Agent online, tool tồn tại | POST /jobs `{agent_id, tool_id, args: "-v"}` | HTTP 201, `status="pending"`, job_id trả về | P |
| TC-JOB-02 | Tạo job với agent offline | Agent offline | POST /jobs với agent offline | HTTP 400 "agent offline" hoặc job tạo nhưng không gửi được | N/E |
| TC-JOB-03 | Tạo job với tool không tồn tại | — | POST /jobs `{tool_id: "nonexistent-uuid"}` | HTTP 404 | N |
| TC-JOB-04 | Tạo job với agent không tồn tại | — | POST /jobs `{agent_id: "nonexistent-uuid"}` | HTTP 404 | N |
| TC-JOB-05 | Run job sau khi ready | Job status=ready | POST /jobs/:id/run | HTTP 200, `status` chuyển sang running, output stream bắt đầu | P |
| TC-JOB-06 | Run job chưa ready (status=pending) | Job status=pending | POST /jobs/:id/run | HTTP 400 "job not ready" | N |
| TC-JOB-07 | Run job đã done | Job status=done | POST /jobs/:id/run | HTTP 400 | N |
| TC-JOB-08 | Stop job đang running | Job status=running | POST /jobs/:id/stop | HTTP 200, `status` chuyển sang stopped | P |
| TC-JOB-09 | Stop job đã done | Job status=done | POST /jobs/:id/stop | HTTP 400 | N |
| TC-JOB-10 | Stream output khi job running | Job status=running | GET /jobs/:id/output (SSE) | SSE stream nhận được output lines, `event: done` khi job kết thúc | P |
| TC-JOB-11 | Download artifact sau khi job done | Job có artifact | GET /jobs/:id/artifact/download | HTTP 200, file download đúng | P |
| TC-JOB-12 | Xem artifact content | Job có artifact text | GET /jobs/:id/artifact/content | HTTP 200, text content | P |
| TC-JOB-13 | Download artifact khi job không có artifact | Job không có artifact | GET /jobs/:id/artifact/download | HTTP 404 | N |
| TC-JOB-14 | Xóa job | Job tồn tại | DELETE /jobs/:id | HTTP 200, job không còn trong GET /jobs | P |
| TC-JOB-15 | Filter jobs by agent | Có 10 jobs từ 3 agents | GET /jobs?agent_id=:id | Chỉ trả về jobs của agent đó | P |
| TC-JOB-16 | Filter jobs by status | — | GET /jobs?status=done | Chỉ trả về done jobs | P |
| TC-JOB-17 | Job với args chứa command injection | — | args: `; rm -rf /` | Agent execute đúng tool với args đó; tool executor không eval shell (chạy qua exec, không shell) | S |
| TC-JOB-18 | Job disconnect giữa chừng | Job running, agent disconnects | Agent WS disconnect khi job chạy | Job chuyển failed hoặc có error log, không hang indefinitely | E |
| TC-JOB-19 | Nhiều jobs song song trên cùng agent | — | Tạo 5 jobs cho 1 agent | Tất cả có thể download tool song song, execution tuần tự theo lệnh run | E |
| TC-JOB-20 | Job output rất dài (>1MB) | — | Tool sinh output 5MB | Output được stream đầy đủ, không truncate im lặng, hoặc truncate với warning | E |

---

## 6. Evidence Collection Checklist (CCL)

### 6.1 Use Cases

#### UC-CCL-01 — Chạy evidence collection trên Windows endpoint

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Agent Windows đang online |
| **Main Flow** | 1. Mở Evidence Checklist → chọn agent Windows → nhập label/analyst → 2. POST /checklist/run → 3. Backend tạo ChecklistRun với nhiều ChecklistBatch → 4. Gửi `job_start` cho từng batch → 5. Mỗi batch chạy nhóm lệnh thu thập (netstat, process list, logs...) → 6. Output từng batch hiển thị real-time → 7. Khi tất cả batch done: status=done |
| **Postcondition** | Đầy đủ evidence từ endpoint được thu thập và lưu trữ, có thể download từng batch |
| **Alt Flow A** | Một batch fail → batch đó status=failed, các batch khác tiếp tục |

#### UC-CCL-02 — Thu thập trên Linux endpoint

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Agent Linux online |
| **Main Flow** | Tương tự UC-CCL-01 nhưng với platform=linux (các lệnh khác: `/proc`, `journalctl`, `ss`, etc.) |
| **Postcondition** | Linux-specific evidence được thu thập |

#### UC-CCL-03 — Xem lại kết quả checklist run

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | ChecklistRun đã done |
| **Main Flow** | 1. Mở danh sách Checklist Runs → click run → 2. Xem từng batch với output → 3. Download output của batch cụ thể → 4. Nếu muốn AI phân tích: click "Analyze with AI" |
| **Postcondition** | Analyst có thể review evidence mọi lúc |

### 6.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-CCL-01 | Tạo checklist run Windows | Agent Windows online | POST /checklist/run `{agent_id, platform: "win", label: "Initial Triage HOST01", analyst: "Alice"}` | HTTP 201, `{run_id, batches: [...], status: "running"}` | P |
| TC-CCL-02 | Tạo checklist run Linux | Agent Linux online | POST /checklist/run `{platform: "linux", ...}` | HTTP 201, batches chứa Linux-specific batch keys | P |
| TC-CCL-03 | Tạo checklist với platform sai | — | `{platform: "macos"}` | HTTP 400 | N |
| TC-CCL-04 | Tạo checklist với agent offline | Agent offline | POST /checklist/run | HTTP 400 hoặc 503 | N |
| TC-CCL-05 | Lấy danh sách checklist runs | Có 5 runs | GET /checklist/runs | HTTP 200, array với status, label, agent info | P |
| TC-CCL-06 | Lấy detail checklist run | Run tồn tại | GET /checklist/runs/:id | HTTP 200, có `batches` array với từng batch và status | P |
| TC-CCL-07 | Stream batch output | Batch đang running | GET /checklist/batches/:id/output (SSE) | SSE stream output lines, done event khi kết thúc | P |
| TC-CCL-08 | Download batch output | Batch đã done | GET /checklist/batches/:id/download | HTTP 200, text file với output | P |
| TC-CCL-09 | Batch fail không ảnh hưởng batch khác | Giả lập 1 batch fail | Run với agent có lỗi trên 1 batch | batch_status=failed, các batch khác vẫn done | E |
| TC-CCL-10 | Checklist run trên agent không đúng platform | Linux agent, platform=win | POST /checklist/run | Run tạo nhưng lệnh Windows fail trên Linux agent | E |
| TC-CCL-11 | Multiple concurrent runs cùng agent | — | Tạo 2 runs cùng 1 agent cùng lúc | Cả 2 runs được tạo, chạy song song (agent xử lý song song) | E |
| TC-CCL-12 | Xem run detail không tồn tại | — | GET /checklist/runs/nonexistent-id | HTTP 404 | N |

---

## 7. Hunting Scenarios & Deployments (HNT)

### 7.1 Use Cases

#### UC-HNT-01 — Tạo hunting scenario

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Có ít nhất 2 tools đã upload |
| **Main Flow** | 1. Mở Hunting → New Scenario → 2. Đặt tên, mô tả, chọn icon/color → 3. Add tools theo thứ tự muốn chạy → 4. Save → Scenario xuất hiện trong danh sách |
| **Postcondition** | Scenario là template có thể deploy nhiều lần lên nhiều agents |

#### UC-HNT-02 — Deploy scenario lên agent

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Scenario đã tạo (có ít nhất 1 tool), Agent online |
| **Main Flow** | 1. Chọn scenario → Deploy → 2. Chọn agent (optionally chọn case) → 3. Confirm → 4. Backend tạo N jobs (N = số tool trong scenario), 1 deployment record → 5. Jobs được dispatch: agent download tất cả tools → 6. Analyst vào Deployments tab, click Run lần lượt từng job |
| **Postcondition** | N jobs được tạo và liên kết với deployment, analyst có thể chạy từng tool |
| **Alt Flow A** | Agent offline → không thể deploy |
| **Alt Flow B** | Scenario không có tool → không thể deploy |

#### UC-HNT-03 — Xem deployment và jobs liên quan

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Ít nhất 1 deployment đã tạo |
| **Main Flow** | 1. Mở Hunting → Deployments tab → 2. Click deployment → 3. Xem danh sách jobs (status, tool name, artifact) → 4. Click vào job để xem output chi tiết |
| **Postcondition** | Analyst có overview đầy đủ về tiến trình của 1 hunting campaign |

#### UC-HNT-04 — Quản lý tools trong scenario

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Scenario đã tạo |
| **Main Flow** | 1. Mở scenario → 2. Add tool mới hoặc Remove tool → 3. Reorder tools (sort_order) → 4. Save |
| **Postcondition** | Scenario được cập nhật cho deployments tương lai |

### 7.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-HNT-01 | Tạo scenario hợp lệ | — | POST /hunting/scenarios `{name: "Initial Triage", description: "...", icon: "Search", color: "blue"}` | HTTP 201, `{id, name, slug, tools: []}` | P |
| TC-HNT-02 | Tạo scenario tên rỗng | — | `{name: ""}` | HTTP 400 | N |
| TC-HNT-03 | Add tool vào scenario | Scenario + Tool tồn tại | POST /hunting/scenarios/:id/tools `{tool_id: "...", sort_order: 1}` | HTTP 200/201, tools array được cập nhật | P |
| TC-HNT-04 | Add tool đã có trong scenario | Tool đã được add | POST lại với cùng tool_id | HTTP 409 hoặc idempotent | N/E |
| TC-HNT-05 | Remove tool khỏi scenario | Tool trong scenario | DELETE /hunting/scenarios/:id/tools/:toolId | HTTP 200, tool không còn trong scenario.tools | P |
| TC-HNT-06 | Deploy scenario với agent online | Scenario có 3 tools, agent online | POST /hunting/scenarios/:id/deploy `{agent_id: "..."}` | HTTP 201, tạo 1 deployment + 3 jobs (status=pending) | P |
| TC-HNT-07 | Deploy scenario không có tool | Scenario không có tool | POST /hunting/scenarios/:id/deploy | HTTP 400 "scenario has no tools" | N |
| TC-HNT-08 | Deploy khi agent offline | Agent offline | POST /hunting/scenarios/:id/deploy | HTTP 400 "agent offline" | N |
| TC-HNT-09 | Lấy deployment detail | Deployment tồn tại | GET /hunting/deployments/:id | HTTP 200, có `scenario`, `agent`, `jobs` array | P |
| TC-HNT-10 | Xóa deployment | Deployment tồn tại | DELETE /hunting/deployments/:id | HTTP 200, deployment và jobs liên kết bị xóa | P |
| TC-HNT-11 | Update scenario | Scenario tồn tại | PUT /hunting/scenarios/:id `{name: "Renamed", color: "red"}` | HTTP 200, metadata được cập nhật | P |
| TC-HNT-12 | Xóa scenario đang có deployment | — | DELETE /hunting/scenarios/:id | HTTP 400 hoặc cascade xóa deployments | E |
| TC-HNT-13 | Deploy cùng scenario 2 lần lên 2 agents | 2 agents online | Deploy scenario 2x | 2 deployments độc lập, mỗi cái 3 jobs riêng | P |
| TC-HNT-14 | Sort order tools trong scenario | — | Add 3 tools với sort_order 3, 1, 2 | GET scenario trả về tools theo đúng thứ tự sort_order | P |
| TC-HNT-15 | Deploy với case_id | Case tồn tại | POST /deploy `{agent_id, case_id}` | Jobs được liên kết với case | P |
| TC-HNT-16 | Xem danh sách deployments | — | GET /hunting/deployments | HTTP 200, có pagination/filter | P |

---

## 8. ELK Threat Hunting (ELK)

### 8.1 Use Cases

#### UC-ELK-01 — Cấu hình kết nối ELK cluster

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | ELK cluster đang hoạt động |
| **Main Flow** | 1. Mở ELK Hunt → Config tab → 2. Tạo config mới (name, URL, username, password/API key) → 3. Set active → 4. Test connection ngầm định |
| **Postcondition** | Config được lưu với credentials encrypted, sẵn sàng hunt |

#### UC-ELK-02 — Hunt với IOC từ database

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | ELK config active, IOC database có entries |
| **Main Flow** | 1. Chọn IOC source = database → Chọn IOC types (IPv4, Domain, Hash) → 2. POST /elk/hunt → 3. Backend batch IOCs (500/batch) → 4. Với mỗi batch: query Elasticsearch → 5. SSE stream kết quả → 6. Hunt hoàn tất: lưu ELKHuntResult |
| **Postcondition** | Kết quả hunt được persist, có thể xem lại và analyze với AI |
| **Alt Flow A** | Elasticsearch không phản hồi → error stream, hunt status=failed |

#### UC-ELK-03 — Hunt với file IOC tải lên

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | ELK config active |
| **Main Flow** | 1. Chọn IOC source = upload file → Upload CSV/JSON → 2. POST /elk/iocs/parse → preview IOCs → 3. Confirm hunt → streaming kết quả tương tự UC-ELK-02 |
| **Postcondition** | Hunt với IOC từ bên ngoài, kết quả được lưu |

#### UC-ELK-04 — Xem lại kết quả hunt cũ

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Có ít nhất 1 ELKHuntResult đã completed |
| **Main Flow** | 1. Mở ELK Hunt → Results tab → 2. Click result → xem hits list → 3. Click "Analyze with AI" nếu muốn phân tích sâu |
| **Postcondition** | Kết quả hunt vẫn accessible sau nhiều ngày |

### 8.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-ELK-01 | Tạo ELK config | — | POST /elk/configs `{name: "SIEM-Prod", url: "https://elk:9200", username: "elastic", password: "pass"}` | HTTP 201, password không được lưu plaintext trong DB | P/S |
| TC-ELK-02 | Set active config | 2 configs tồn tại | POST /elk/configs/:id/activate | HTTP 200, chỉ config này là active, config cũ deactivated | P |
| TC-ELK-03 | Tạo config thiếu URL | — | POST /elk/configs `{name: "test"}` | HTTP 400 | N |
| TC-ELK-04 | Lấy active config | Config active tồn tại | GET /elk/config | HTTP 200, không trả về password plaintext | P/S |
| TC-ELK-05 | Hunt với IOC database | ELK config active, IOCs trong DB | POST /elk/hunt `{ioc_types: ["IPv4-Addr", "Domain-Name"]}` | HTTP 200, SSE stream bắt đầu với `event: batch_start`, `event: hits`, `event: done` | P |
| TC-ELK-06 | Hunt không có active config | Không có config active | POST /elk/hunt | HTTP 400 "no active ELK config" | N |
| TC-ELK-07 | Hunt không có IOC | ELK active, IOC DB rỗng | POST /elk/hunt | HTTP 400 "no IOCs found" | N |
| TC-ELK-08 | Parse file IOC — CSV format | — | POST /elk/iocs/parse với CSV file | HTTP 200, array of `{value, type}` parsed correctly | P |
| TC-ELK-09 | Parse file IOC — JSON format | — | POST /elk/iocs/parse với JSON file | HTTP 200, parsed correctly | P |
| TC-ELK-10 | Parse file IOC format sai | — | Upload .txt file với nội dung random | HTTP 400 hoặc empty parse result | N |
| TC-ELK-11 | File-based hunt | ELK active | POST /elk/hunt/file-stream + GET SSE | Giống UC-ELK-03, stream kết quả | P |
| TC-ELK-12 | Lấy danh sách hunt results | Có 3 completed hunts | GET /elk/hunt/results | HTTP 200, array với id, title, iocs_used, total_hits, status | P |
| TC-ELK-13 | Lấy detail hunt result | Result tồn tại | GET /elk/hunt/results/:id | HTTP 200, full JSON results | P |
| TC-ELK-14 | Xóa hunt result | Result tồn tại | DELETE /elk/hunt/results/:id | HTTP 200, result không còn trong list | P |
| TC-ELK-15 | Hunt với 10,000 IOCs | — | POST /elk/hunt với 10k IOCs | Batching đúng (500/batch), progress stream chính xác, không timeout | E |
| TC-ELK-16 | ELK unreachable giữa hunt | ELK ngắt kết nối mid-hunt | Simulate timeout sau batch 3 | Stream `event: error`, hunt result status=failed | E |

---

## 9. Case Management (CASE)

### 9.1 Use Cases

#### UC-CASE-01 — Tạo case cho incident mới

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst / Admin |
| **Precondition** | Đã đăng nhập |
| **Main Flow** | 1. Mở Cases → New Case → 2. Nhập tên, mô tả → 3. Save → 4. Assign agents cho case → 5. Tất cả activities (jobs, checklists, hunting) liên kết với case |
| **Postcondition** | Case tạo với status=open, sẵn sàng nhận agents và activities |

#### UC-CASE-02 — Theo dõi tiến trình điều tra qua case timeline

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Case có agents, jobs, checklists |
| **Main Flow** | 1. Mở Case Detail → 2. Xem Case Summary: danh sách agents trong case, tổng số jobs, trạng thái → 3. Timeline hiển thị hoạt động theo thời gian |
| **Postcondition** | Analyst có bức tranh tổng thể về incident |

#### UC-CASE-03 — Đóng case

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Case đang open |
| **Main Flow** | 1. Mở Case → Edit → 2. Đổi status = closed → 3. Save |
| **Postcondition** | Case status=closed, vẫn có thể xem lại nhưng không thêm activity mới |

### 9.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-CASE-01 | Tạo case hợp lệ | — | POST /cases `{name: "Incident 2026-06-01", description: "Ransomware on HOST01"}` | HTTP 201, `{id, name, status: "open", created_at}` | P |
| TC-CASE-02 | Tạo case tên rỗng | — | POST /cases `{name: ""}` | HTTP 400 | N |
| TC-CASE-03 | Lấy danh sách cases | Có 5 cases | GET /cases | HTTP 200, array với status, name, agent count | P |
| TC-CASE-04 | Update case name | Case tồn tại | PATCH /cases/:id `{name: "Renamed"}` | HTTP 200, name được cập nhật | P |
| TC-CASE-05 | Đóng case | Case status=open | PATCH /cases/:id `{status: "closed"}` | HTTP 200, `status = "closed"` | P |
| TC-CASE-06 | Case summary với agents và jobs | Case có 2 agents, 5 jobs | GET /cases/:id/summary | HTTP 200, `{agents: [...], job_count, ...}` | P |
| TC-CASE-07 | Assign agent vào case qua case update | — | PATCH /cases/:id với agent_ids | HTTP 200, agents được liên kết | P |
| TC-CASE-08 | Lấy detail case không tồn tại | — | GET /cases/nonexistent-id | HTTP 404 | N |
| TC-CASE-09 | Tạo nhiều cases | — | Tạo 20 cases liên tiếp | Tất cả 20 được tạo thành công, không conflict | E |
| TC-CASE-10 | Case với tên Unicode (tiếng Việt) | — | `{name: "Sự cố tấn công APT"}` | HTTP 201, name được lưu đúng UTF-8 | P |
| TC-CASE-11 | Xóa case | Case tồn tại | Nếu có endpoint xóa | HTTP 200 hoặc 400 nếu có jobs liên kết | E |

---

## 10. AI Analysis & Providers (AI)

### 10.1 Use Cases

#### UC-AI-01 — Cấu hình AI provider

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Có API key từ provider |
| **Main Flow** | 1. Mở AI Provider Settings → Add Provider → 2. Chọn loại (openai/anthropic/google) → 3. Nhập name, base URL (cho OpenAI-compatible), API key, model, max tokens → 4. Click "Test Connection" → 5. Save |
| **Postcondition** | Provider được lưu với API key encrypted, sẵn sàng dùng cho analysis sessions |
| **Alt Flow A** | Test connection fail → hiển thị error, cho phép sửa trước khi save |

#### UC-AI-02 — Phân tích job output bằng AI

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Job đã done, AI provider đã cấu hình |
| **Main Flow** | 1. Mở JobDetail → click "Analyze with AI" → 2. Chọn provider → 3. POST /ai/sessions `{source_type: "job", source_id: jobId, provider_id}` → 4. Redirect sang AIAnalysis page → 5. Chain steps hiển thị: collect → parse → context → analyze → save → 6. Token stream output real-time → 7. Khi done: markdown report được lưu |
| **Postcondition** | Session có `result` là markdown report đầy đủ, `status=done` |
| **Alt Flow A** | API key hết quota → session status=failed, error message hiển thị |

#### UC-AI-03 — Phân tích checklist run

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | ChecklistRun đã done, AI provider configured |
| **Main Flow** | 1. Mở Checklist Run → click "Analyze Run" → 2. Tạo session `{source_type: "checklist_run"}` → 3. Chain: collect (aggregate all batches) → context → analyze → save |
| **Postcondition** | Report tổng hợp từ toàn bộ evidence collection |

#### UC-AI-04 — Upload file để phân tích

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | AI provider configured |
| **Main Flow** | 1. Mở AIAnalysis → New Analysis → Upload File → 2. Drag-drop file (.txt/.csv/.json/.xml/.raw/.dmp) → 3. Tạo session `{source_type: "upload"}` → 4. Chain: upload → parse (binary: extract strings) → context → analyze → save |
| **Postcondition** | Report phân tích nội dung file |

#### UC-AI-05 — Xem lại session phân tích cũ

| Trường | Nội dung |
|--------|---------|
| **Actor** | Analyst |
| **Precondition** | Có session đã done |
| **Main Flow** | 1. Mở AI Analysis → Sidebar → chọn session cũ → 2. Xem chain steps đã complete → 3. Xem markdown report đã lưu (không stream lại) |
| **Postcondition** | Report accessible offline |

### 10.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-AI-01 | Tạo OpenAI-compatible provider | — | POST /ai/providers `{name: "Groq", provider_type: "openai", base_url: "https://api.groq.com/openai/v1", api_key: "gsk_...", model: "llama-3.3-70b-versatile"}` | HTTP 201, api_key không được trả về plaintext | P/S |
| TC-AI-02 | Tạo Anthropic provider | — | POST /ai/providers `{provider_type: "anthropic", api_key: "sk-ant-..."}` | HTTP 201 | P |
| TC-AI-03 | Tạo Google provider | — | POST /ai/providers `{provider_type: "google", api_key: "AIza..."}` | HTTP 201 | P |
| TC-AI-04 | Test connection thành công | Provider tồn tại, API key hợp lệ | POST /ai/providers/:id/test | HTTP 200, `{success: true, message: "Connection successful"}` | P |
| TC-AI-05 | Test connection API key sai | — | POST /ai/providers/:id/test với key không hợp lệ | HTTP 200 `{success: false, error: "Unauthorized"}` hoặc propagated error | N |
| TC-AI-06 | Tạo session từ job | Job done tồn tại | POST /ai/sessions `{source_type: "job", source_id: jobId, provider_id}` | HTTP 201, session với status=pending, steps array khởi tạo | P |
| TC-AI-07 | Tạo session từ job chưa done | Job status=running | POST /ai/sessions `{source_type: "job", ...}` | HTTP 400 "job not completed" | N |
| TC-AI-08 | Stream session | Session tồn tại (status=pending) | GET /ai/sessions/:id/stream (SSE) | SSE: `event: step` cho từng bước, `event: token` cho AI output, `event: done` | P |
| TC-AI-09 | Session stream với provider sai | Provider API key invalid | GET /ai/sessions/:id/stream | SSE: steps collect/parse done, analyze step fail, `event: error` | N |
| TC-AI-10 | Tạo session upload file text | — | POST /ai/sessions multipart với source_type=upload, file=.txt | HTTP 201, UploadPath được set | P |
| TC-AI-11 | Tạo session upload file binary | — | multipart với file=memdump.raw | HTTP 201, chain steps sẽ có `extract_strings` | P |
| TC-AI-12 | Upload file >100MB | — | file 200MB | HTTP 413 hoặc error theo ANALYSIS_UPLOAD_MAX_MB | E |
| TC-AI-13 | Session từ ELK result | ELKHuntResult exists | POST /ai/sessions `{source_type: "elk_result", source_id}` | HTTP 201, chain: collect → context → analyze → save | P |
| TC-AI-14 | Xem session đã done | Session status=done | GET /ai/sessions/:id | HTTP 200, `result` field có markdown report | P |
| TC-AI-15 | Xóa session | Session tồn tại | DELETE /ai/sessions/:id | HTTP 200, session + upload file (nếu có) bị xóa | P |
| TC-AI-16 | Token counting | Session done | GET /ai/sessions/:id | `tokens_used` > 0, phản ánh đúng usage | P |
| TC-AI-17 | API key được encrypt trong DB | — | Query DB trực tiếp: `SELECT api_key FROM ai_providers` | Không phải plaintext key | S |
| TC-AI-18 | Tạo provider thiếu provider_type | — | POST /ai/providers `{name: "test", api_key: "key"}` | HTTP 400 | N |
| TC-AI-19 | Xem tất cả sessions | — | GET /ai/sessions | HTTP 200, chỉ sessions của user hiện tại (nếu user-scoped) | P |
| TC-AI-20 | Session stream cancel giữa chừng | Session đang running | Client đóng SSE kết nối | Backend cancel AI API request, session status=failed hoặc partial | E |

---

## 11. System Health Monitoring (SYS)

### 11.1 Use Cases

#### UC-SYS-01 — Kiểm tra sức khỏe hệ thống

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin / Analyst |
| **Precondition** | Đã đăng nhập |
| **Main Flow** | 1. Mở System Health → Health Check tab → 2. Xem trạng thái: PostgreSQL, Redis, Storage, WebSocket Hub → 3. Xem server RAM/CPU/Disk metrics → 4. Xem resource usage của từng agent online |
| **Postcondition** | Admin biết hệ thống có hoạt động bình thường không |
| **Alt Flow A** | PostgreSQL down → status=error, hiển thị đỏ |

#### UC-SYS-02 — Xem thống kê token AI

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Có ít nhất 1 AI analysis session đã done |
| **Main Flow** | 1. Mở System Health → Token Usage tab → 2. Xem chart token by provider → 3. Xem tổng token theo model và session |
| **Postcondition** | Admin biết chi phí AI đang sử dụng bao nhiêu |

### 11.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-SYS-01 | Health check — all services up | All services running | GET /system/health | HTTP 200, `{postgres: "ok", redis: "ok", storage: "ok", ws_hub: "ok"}` | P |
| TC-SYS-02 | Health check có server resources | Linux server | GET /system/health | Response có `server.cpu_percent`, `server.ram_used_mb`, `server.disk_used_gb` | P |
| TC-SYS-03 | Health check có agent resources | Ít nhất 1 agent online | GET /system/health | Response có `agent_resources` array với cpu/mem/disk per agent | P |
| TC-SYS-04 | Health check khi Redis down | Redis stopped | GET /system/health | HTTP 200, `redis: "error"`, không crash toàn bộ endpoint | N/E |
| TC-SYS-05 | Health check khi PostgreSQL down | PostgreSQL stopped | GET /system/health | HTTP 500 hoặc `{postgres: "error"}` | N/E |
| TC-SYS-06 | Token stats | Có AI sessions với tokens | GET /system/token-stats | HTTP 200, `{by_provider: [...], total_tokens}` | P |
| TC-SYS-07 | Token stats không có session | Không có session nào | GET /system/token-stats | HTTP 200, `{by_provider: [], total_tokens: 0}` | E |
| TC-SYS-08 | Health check không yêu cầu auth | — | GET /system/health không có token | HTTP 401 | S |
| TC-SYS-09 | Server RAM display | — | Frontend System Health tab | ResourceGauge hiển thị đúng %, màu đúng (emerald/amber/red theo ngưỡng) | P |
| TC-SYS-10 | CPU percent tính delta | — | 2 request liên tiếp đến /system/health | cpu_percent thứ 2 phản ánh delta thực tế (không phải 0 hoặc 100) | P |

---

## 12. WebSocket & Real-time Communication (WS)

### 12.1 Use Cases

#### UC-WS-01 — Agent kết nối và xác thực qua WebSocket

| Trường | Nội dung |
|--------|---------|
| **Actor** | Agent binary |
| **Precondition** | Agent đã được tạo, token hợp lệ |
| **Main Flow** | 1. Agent gửi WebSocket upgrade request đến `/ws/agent` với header `X-Agent-Token: <token>` → 2. Backend xác thực token → 3. Upgrade connection → 4. Agent gửi registration message (hostname, OS, IP) → 5. Backend cập nhật Agent record, status=online → 6. Frontend nhận cập nhật trạng thái |
| **Postcondition** | Agent kết nối ổn định, heartbeat ping định kỳ |

#### UC-WS-02 — Interactive terminal session

| Trường | Nội dung |
|--------|---------|
| **Actor** | Admin |
| **Precondition** | Agent online, admin đã đăng nhập |
| **Main Flow** | 1. Mở Agent Detail → Terminal tab → 2. Frontend kết nối `/ws/terminal` với JWT → 3. Gửi `shell_open` → agent spawn bash/cmd.exe PTY → 4. Admin gõ lệnh → `shell_input` (base64) → agent execute → output stream về → 5. Admin đổi kích thước terminal → `shell_resize` → PTY resize |
| **Postcondition** | Admin có interactive shell trên endpoint |
| **Alt Flow A** | Shell session idle quá lâu → timeout, `shell_close` |

#### UC-WS-03 — Agent disconnect và reconnect

| Trường | Nội dung |
|--------|---------|
| **Actor** | Agent (system) |
| **Precondition** | Agent đang online |
| **Main Flow** | 1. Network interrupt → WebSocket đóng → 2. Backend cập nhật status=offline → 3. Agent thử reconnect với backoff → 4. Kết nối lại thành công → status=online lại |
| **Postcondition** | Jobs pending được tiếp tục dispatch sau khi agent online |

### 12.2 Test Cases

| ID | Mô tả | Precondition | Input | Expected Result | Type |
|----|-------|-------------|-------|----------------|------|
| TC-WS-01 | Agent connect với token hợp lệ | Agent tạo trong DB | WS connect `/ws/agent` với header token đúng | Connection upgrade success (101), agent status=online | P |
| TC-WS-02 | Agent connect với token sai | — | WS connect với token không đúng | Connection bị từ chối (401 trước upgrade) | N/S |
| TC-WS-03 | Agent connect không có token | — | WS connect không có header | 401 | N/S |
| TC-WS-04 | Admin terminal connect với JWT hợp lệ | Admin đăng nhập | WS connect `/ws/terminal` với JWT trong query hoặc header | 101 upgrade | P |
| TC-WS-05 | Admin terminal connect với JWT hết hạn | — | WS connect với expired JWT | 401 | N |
| TC-WS-06 | Shell open — bash | Agent Linux online | Gửi `{type: "shell_open"}` | Agent spawn bash, frontend nhận output stream | P |
| TC-WS-07 | Shell input — lệnh thông thường | Shell session open | Gửi `{type: "shell_input", data: base64("ls -la\n")}` | Output từ `ls -la` stream về frontend | P |
| TC-WS-08 | Shell resize | Shell open | Gửi `{type: "shell_resize", cols: 120, rows: 40}` | PTY resize, output wrap đúng | P |
| TC-WS-09 | Agent disconnect giữa job | Job running, agent disconnect | Simulate network drop | Job chuyển status=failed, hub xóa client | E |
| TC-WS-10 | Multiple agents kết nối cùng lúc | — | 10 agents connect đồng thời | Tất cả được handle, không race condition | E |
| TC-WS-11 | Multiple admin terminals cùng 1 agent | 2 admins | 2 admins cùng mở terminal đến 1 agent | Mỗi admin có session shell độc lập | E |
| TC-WS-12 | Agent gửi resource_report | Agent online | Agent gửi `{type: "resource_report", cpu_percent: 45.2, mem_used_mb: 1024, ...}` | Backend persist vào DB, /agents/:id phản ánh giá trị mới | P |
| TC-WS-13 | Ping heartbeat | Agent connected | Agent gửi `{type: "ping"}` mỗi 30s | Backend respond `{type: "pong"}`, last_seen được cập nhật | P |
| TC-WS-14 | Message injection qua WebSocket | — | Agent gửi JSON với type không hợp lệ | Backend bỏ qua gracefully, không crash | S/E |

---

## 13. Luồng tích hợp (Integration Flows)

### 13.1 Flow: Incident Response toàn trình

| Bước | Actor | Action | Test Points |
|------|-------|--------|------------|
| 1 | Admin | Tạo Case "Ransomware HOST01" | Case status=open |
| 2 | Admin | Tạo Agent, chạy install.ps1 trên HOST01 | Agent status=online |
| 3 | Admin | Assign agent vào case | agent.case_id = case.id |
| 4 | Analyst | Chạy Evidence Checklist (Windows) | N batch runs, output saved |
| 5 | Analyst | Chạy Webshell Scanner scenario | Deployment + jobs created |
| 6 | Analyst | Chờ jobs done, download artifacts | Artifacts accessible |
| 7 | Analyst | AI Analysis trên checklist run | Session done, report generated |
| 8 | Analyst | ELK Hunt với IOC từ AI report | Hunt result saved |
| 9 | Admin | Đóng Case | Case status=closed |

**Test Case tích hợp TC-INT-01**: Thực hiện toàn bộ flow từ bước 1 đến 9, kiểm tra mỗi bước tạo đúng records và liên kết đúng với case.

---

### 13.2 Flow: Threat Hunting Campaign

| Bước | Action | Expected |
|------|--------|----------|
| 1 | Tạo Scenario "Memory Forensics" với 3 tools | Scenario có 3 tools |
| 2 | Deploy lên 5 agents cùng lúc | 5 deployments × 3 jobs = 15 jobs |
| 3 | Run tất cả jobs | 15 jobs chạy tuần tự/song song |
| 4 | Collect artifacts | 15 artifacts downloaded |
| 5 | AI Analysis từng job | 15 sessions hoặc 5 sessions (per agent) |

**Test Case tích hợp TC-INT-02**: Deploy 1 scenario có 3 tools lên 3 agents. Kiểm tra tổng 9 jobs được tạo, deployment_id đúng, artifacts có thể download.

---

### 13.3 Flow: AI-assisted ELK Hunt

| Bước | Action | Expected |
|------|--------|----------|
| 1 | Cấu hình ELK + Groq provider | Cả hai active |
| 2 | ELK Hunt với 500 IOC từ DB | Hunt result saved, total_hits > 0 |
| 3 | Click "Analyze with AI" trên hunt result | Session `{source_type: "elk_result"}` tạo |
| 4 | AI stream phân tích hits | Chain steps done, report generated |

**Test Case tích hợp TC-INT-03**: Chạy ELK hunt với IOCs, sau đó tạo AI session từ hunt result. Kiểm tra `source_id` đúng, AI nhận được nội dung hits từ hunt result.

---

## 14. Security Test Summary (Cross-cutting)

| ID | Category | Test | Expected |
|----|---------|------|---------|
| TC-SEC-01 | Auth Bypass | Truy cập `/api/v1/agents` không có JWT | HTTP 401 |
| TC-SEC-02 | Auth Bypass | Truy cập agent WS với fake token | WS rejected |
| TC-SEC-03 | IDOR | Analyst A xem artifact của Analyst B | HTTP 403 hoặc 404 (nếu user-scoped) |
| TC-SEC-04 | Path Traversal | fs download với `../../etc/passwd` | HTTP 400, blocked |
| TC-SEC-05 | Path Traversal | tool executable_path = `../../../bin/bash` | HTTP 400 |
| TC-SEC-06 | Secrets in Response | GET /ai/providers — check api_key field | `has_key: true` only, no plaintext |
| TC-SEC-07 | Secrets in Response | GET /elk/configs — check password/api_key | Encrypted or masked |
| TC-SEC-08 | Secrets in Response | GET /agents — check token field | Token không xuất hiện trong list response |
| TC-SEC-09 | SQL Injection | Search params với SQL injection payload | GORM parameterized, no bypass |
| TC-SEC-10 | XSS | Tên agent chứa `<script>alert(1)</script>` | Stored but escaped on render |
| TC-SEC-11 | Command Injection | Job args với `; curl evil.com` | Tool exec không dùng shell; args được pass trực tiếp |
| TC-SEC-12 | Role Privilege | Analyst tạo agent (admin-only) | HTTP 403 |
| TC-SEC-13 | Audit Log | Tạo job, upload tool, delete agent | AuditLog entries tạo với action, user, IP |

---

## 15. Performance & Edge Case Tests

| ID | Test | Setup | Expected |
|----|------|-------|---------|
| TC-PERF-01 | 50 agents online đồng thời | 50 agents kết nối WS | Tất cả online, hub không drop |
| TC-PERF-02 | Job output >10MB | Tool sinh output lớn | Stream đầy đủ hoặc truncate với warning |
| TC-PERF-03 | 100 jobs cùng lúc | 100 jobs trên 10 agents | DB không dead-lock, jobs processed |
| TC-PERF-04 | Upload tool 4GB | Tool ZIP 4GB | Upload thành công (streaming to disk, không OOM) |
| TC-PERF-05 | ELK hunt 50,000 IOC | 50k IOC trong DB | 100 batches × 500 IOCs, không timeout |
| TC-PERF-06 | AI stream timeout | AI API slow response | Frontend hiển thị loading, không white screen |
| TC-PERF-07 | Agent reconnect liên tục | Agent flapping on/off 10 lần | Status cập nhật đúng, không memory leak trong hub |
| TC-PERF-08 | 10 admin terminals cùng lúc | 10 admins mở terminal | 10 PTY sessions độc lập, không cross-contamination |
