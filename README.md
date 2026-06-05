# ForensicHub v2

Nền tảng Điều phối DFIR (Digital Forensics and Incident Response) tập trung. Hệ thống bao gồm Backend (Go), Frontend (React), Agent (Go) và công cụ Webshell Scanner tích hợp sẵn. Tất cả được triển khai dễ dàng qua Docker Compose.

---

## 🚀 Cài đặt & Khởi chạy nhanh (Local)

**Yêu cầu hệ thống:**
- Docker Engine ≥ 24 và Docker Compose v2.
- RAM tối thiểu 4GB.

**Các bước thực hiện:**

1. **Clone dự án và tạo cấu hình môi trường:**
   ```bash
   git clone <repo-url> ForensicHub
   cd ForensicHub
   cp .env.example .env
   ```

2. **Khởi chạy hệ thống bằng Docker Compose:**
   ```bash
   docker compose up -d --build
   ```
   *Lưu ý: Lần build đầu tiên có thể mất 5-10 phút.*

3. **Truy cập hệ thống:**
   - **URL:** `http://localhost:3000`
   - **Tài khoản mặc định:** `admin@forensichub.local`
   - **Mật khẩu mặc định:** `Admin@123456`

---

## ⚙️ Cấu hình cần thiết (`.env`)

Mọi cấu hình hệ thống nằm trong file `.env`. Dưới đây là các biến môi trường quan trọng nhất cần thiết lập (đặc biệt khi triển khai lên môi trường thực tế):

| Biến môi trường | Giải thích | Mặc định (Local) |
|---|---|---|
| `JWT_SECRET` | Khóa bí mật mã hóa token. **Bắt buộc thay đổi ở Production** (>= 32 ký tự). | `change_this_jwt_secret...` |
| `POSTGRES_PASSWORD` | Mật khẩu cho cơ sở dữ liệu PostgreSQL. | `forensic_secret` |
| `REDIS_PASSWORD` | Mật khẩu cho Redis cache. | `redis_secret` |
| `PUBLIC_URL` | URL công khai của Backend (VD: `https://hub.example.com`). Bắt buộc cấu hình để Agent có thể kết nối tới Backend. | *(trống)* |
| `VITE_API_URL` | URL API cho Frontend. Nếu thay đổi biến này, bạn bắt buộc phải build lại Frontend. | `http://localhost:8080` |
| `VITE_WS_URL` | URL WebSocket cho Frontend. | `ws://localhost:8080` |
| `ALLOWED_ORIGINS` | Các URL Frontend được phép gọi API (CORS). | *(trống)* |

---

## 🛠 Hướng dẫn Build Agent và Tools

### 1. Build Agent (Go)
Agent là phần mềm chạy trên máy đích để nhận lệnh từ hệ thống.
```bash
cd agent
# Build cho Windows
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o forensichub-agent.exe ./cmd/agent

# Build cho Linux
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o forensichub-agent-linux ./cmd/agent
```
*(Mẹo: Trên giao diện Dashboard -> mục Agents sẽ cung cấp sẵn đoạn script lệnh tải và cài đặt tự động cho từng hệ điều hành).*

### 2. Build Webshell Scanner (Windows .exe)
Công cụ tích hợp dùng để dò quét mã độc trên máy chủ mục tiêu. Bạn có thể tự build file `.exe` bằng 1 dòng lệnh PowerShell sau (yêu cầu máy có cài sẵn Python):

```powershell
cd tools\webshell-scanner ; python -m venv .venv ; .\.venv\Scripts\python.exe -m pip install -e ".[dev]" ; .\.venv\Scripts\python.exe -m PyInstaller build.spec --clean --noconfirm --distpath dist\windows
```
File thực thi sau khi hoàn tất sẽ nằm tại: `tools\webshell-scanner\dist\windows\webshell-scanner.exe`.
