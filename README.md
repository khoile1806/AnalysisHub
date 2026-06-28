# ForensicHub v2

Nền tảng điều phối DFIR (Digital Forensics & Incident Response) tập trung — Backend (Go), Frontend (React), Agent (Go) và các công cụ tích hợp, triển khai bằng Docker Compose.

> Tài liệu này **chỉ hướng dẫn cấu hình và khởi động** dự án.

---

## 1. Yêu cầu hệ thống

- **Docker Engine ≥ 24** và **Docker Compose v2** (`docker compose`).
- RAM tối thiểu **4 GB** (khuyến nghị 8 GB).
- Cổng trống trên máy host: **3000** (giao diện), **43888** (backend/canary), **7681** (volatility sandbox).
- `git` để clone mã nguồn.

---

## 2. Lấy mã nguồn & tạo file cấu hình

```bash
git clone <repo-url> ForensicHub-v2
cd ForensicHub-v2
cp .env.example .env
```

Mọi cấu hình nằm trong file **`.env`**. Mở ra và chỉnh trước khi khởi động.

---

## 3. Cấu hình `.env`

### 3.1. BẮT BUỘC đổi trước khi chạy production

| Biến | Ý nghĩa | Lưu ý |
|------|---------|-------|
| `POSTGRES_PASSWORD` | Mật khẩu PostgreSQL | Đặt mật khẩu mạnh |
| `REDIS_PASSWORD` | Mật khẩu Redis | Đặt mật khẩu mạnh |
| `JWT_SECRET` | Khóa ký token đăng nhập | **Tối thiểu 32 ký tự** |
| `AES_ENCRYPTION_KEY` | Khóa mã hóa thông tin tích hợp (OpenCTI…) | **Phải dài đúng 32 byte** |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | Tài khoản quản trị khởi tạo lần đầu | Đổi mật khẩu sau khi đăng nhập |

> ⚠️ `AES_ENCRYPTION_KEY` sai độ dài (khác 32 byte) sẽ khiến backend báo lỗi khi lưu cấu hình tích hợp.

### 3.2. Mạng & truy cập

| Biến | Mặc định | Ý nghĩa |
|------|----------|---------|
| `FRONTEND_PORT` | `3000` | Cổng truy cập giao diện web |
| `CANARY_PORT` | `43888` | Cổng publish backend (phục vụ canary link `/c/<slug>`) |
| `PUBLIC_URL` | *(trống)* | URL công khai của server để **Agent** kết nối về và sinh script cài đặt. VD: `http://192.168.1.10:8080` hoặc `https://hub.example.com`. Để trống → tự suy ra từ request. |
| `ALLOWED_ORIGINS` | localhost | Danh sách origin được phép (CORS + WebSocket), phân tách bằng dấu phẩy. **Phải chứa mọi URL dùng để mở frontend.** |
| `USE_HTTPS` | `false` | Đặt `true` nếu chạy sau proxy SSL không gửi `X-Forwarded-Proto`. |

> `VITE_API_URL` / `VITE_WS_URL`: nên **để trống** để bundle frontend chạy được cả qua LAN lẫn domain mà không cần build lại (nginx của frontend tự proxy `/api`, `/ws`, `/catch` về backend). Nếu đặt giá trị cụ thể thì phải **build lại frontend** khi đổi.

### 3.3. Tùy chọn (có thể để trống lúc đầu)

- **CVE Intel:** `NVD_API_KEY`, `GITHUB_TOKEN` — nâng giới hạn tần suất tra cứu CVE.
- **Threat Intel / OSINT:** `VIRUSTOTAL_1..4`, `SHODAN`, `ABUSEIPDB`, `ALIENVAULT`, `ABUSE_CH_API_KEY`, `PULSEDIVE_API_KEY`… — **mỗi key đều tùy chọn**, thiếu key chỉ bỏ qua đúng nguồn đó (nhiều nguồn chạy không cần key).
- **Canary alerts:** `NOTIFY_WEBHOOK_URL`, `NOTIFY_TELEGRAM_TOKEN`, `NOTIFY_TELEGRAM_CHAT_ID` — gửi cảnh báo khi canary token bị mở.
- **Cloudflare Tunnel:** `CLOUDFLARE_TUNNEL_TOKEN`, `CANARY_BASE_URL` — che IP thật cho canary link (xem mục 7).
- **Reporting:** `PDF_RENDERER_URL` — bộ render HTML→PDF ngoài (vd Gotenberg); để trống thì xuất HTML + in-PDF của trình duyệt.

*(Xem chú thích chi tiết từng biến ngay trong `.env.example`.)*

---

## 4. Khởi động

```bash
docker compose up -d --build
```

- Lần build đầu mất khoảng **5–10 phút**.
- Các service: `postgres`, `redis`, `tor`, `backend`, `frontend`, `volatility_sandbox`.
- DB migration + tạo tài khoản admin chạy tự động khi backend khởi động lần đầu.

Kiểm tra trạng thái:
```bash
docker compose ps
docker compose logs -f backend
```

---

## 5. Truy cập hệ thống

- **Giao diện:** `http://localhost:3000` (hoặc `http://<IP-máy-host>:3000`).
- **Đăng nhập:** dùng `ADMIN_EMAIL` / `ADMIN_PASSWORD` đã đặt trong `.env`.
- Sau khi đăng nhập, **đổi mật khẩu admin** ngay.

---

## 6. Cài Agent lên máy cần điều tra

Agent được tạo và lấy script cài đặt **từ trong giao diện** (không cần build tay):

1. Đặt `PUBLIC_URL` trong `.env` thành địa chỉ server mà máy endpoint truy cập tới được, rồi khởi động lại backend.
2. Vào **Endpoints & Tools → Agents → New Agent**.
3. Sao chép lệnh cài đặt (`install.ps1` cho Windows / `install.sh` cho Linux) và chạy trên máy đích.
4. Agent tự kết nối về server và hiện trạng thái **online**.

> Nếu cần build agent thủ công: `cd agent && GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o forensichub-agent.exe ./cmd/agent` (đổi `GOOS=linux` cho Linux).

---

## 7. Tùy chọn: Cloudflare Tunnel (ẩn IP cho canary link)

1. Tạo tunnel ở Cloudflare Zero Trust → Networks → Tunnels, lấy token.
2. Điền vào `.env`: `CLOUDFLARE_TUNNEL_TOKEN=...` và `CANARY_BASE_URL=https://<hostname-tunnel>`.
3. Trên dashboard tunnel, map Public Hostname → Service `HTTP → backend:8080`, Path `/c/*`.
4. Khởi động kèm profile:
   ```bash
   docker compose --profile tunnel up -d
   ```

---

## 8. Vận hành

```bash
# Xem log
docker compose logs -f backend
docker compose logs -f frontend

# Dừng (giữ dữ liệu)
docker compose down

# Khởi động lại
docker compose up -d

# Cập nhật mã nguồn rồi build lại
git pull
docker compose up -d --build

# XÓA TOÀN BỘ dữ liệu (DB, Redis, storage) — KHÔNG THỂ KHÔI PHỤC
docker compose down -v
```

---

## 9. Chạy ở chế độ phát triển (không Docker, tùy chọn)

Cần **Go ≥ 1.22** và **Node ≥ 20**. Vẫn cần PostgreSQL + Redis (có thể chạy riêng bằng `docker compose up -d postgres redis`).

```bash
# Backend
cd backend
go run ./cmd/server         # đọc cấu hình từ ../.env hoặc biến môi trường

# Frontend
cd frontend
npm install
npm run dev                 # mặc định http://localhost:5173
```

---

## 10. Khắc phục sự cố thường gặp

| Triệu chứng | Cách xử lý |
|-------------|-----------|
| Không đăng nhập được | Kiểm tra `JWT_SECRET` (≥32 ký tự) và xem log `backend`. |
| Lỗi khi lưu tích hợp (OpenCTI…) | `AES_ENCRYPTION_KEY` phải **đúng 32 byte**. |
| Trình duyệt báo lỗi CORS / WebSocket | Thêm URL frontend vào `ALLOWED_ORIGINS`. |
| Agent không online | Kiểm tra `PUBLIC_URL` đúng địa chỉ endpoint truy cập được; cổng không bị firewall chặn. |
| Cổng bị trùng | Đổi `FRONTEND_PORT` / `CANARY_PORT` trong `.env`. |
| Backend không khởi động | `docker compose logs backend`; thường do `.env` thiếu/sai biến bắt buộc. |
