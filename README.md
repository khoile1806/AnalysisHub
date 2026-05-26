# ForensicHub — Setup Guide

DFIR platform: Go backend + React frontend + Go agent + integrated Webshell Scanner. Orchestrated via Docker Compose.

---

## Table of Contents

1. [Requirements](#requirements)
2. [Quick Start (local)](#quick-start-local)
3. [Environment Variables](#environment-variables)
4. [Public / Production Deployment](#public--production-deployment)
5. [Deploying Agents to Endpoints](#deploying-agents-to-endpoints)
6. [Webshell Scanner Usage](#webshell-scanner-usage)
7. [Rebuilding Components](#rebuilding-components)
8. [Backup & Operations](#backup--operations)
9. [Troubleshooting](#troubleshooting)

---

## Requirements

**Server (host running ForensicHub):**
- Docker Engine ≥ 24 with Docker Compose v2 plugin
- 2 vCPU / 4 GB RAM minimum (4 vCPU / 8 GB recommended for production)
- 10 GB disk + storage for artifacts

**Endpoint (machines running the agent):**
- Windows 10 / Server 2016+ (PowerShell 5.1+) or Linux with glibc (kernel 4.x+)
- Outbound TCP access to the backend `PUBLIC_URL`. No inbound port required.

**For rebuilding the integrated Webshell Scanner:**
- Python 3.11
- Docker Desktop (to cross-build the Linux binary)
- Build host must be Windows (PyInstaller cannot cross-compile to `.exe`)

---

## Quick Start (local)

```bash
git clone <repo-url> ForensicHub
cd ForensicHub

# 1. Create .env from template
cp .env.example .env
#   At minimum, set ADMIN_PASSWORD and JWT_SECRET (see env table below)

# 2. Build & start the stack
docker compose up -d --build
```

First build takes 5–10 minutes. Subsequent builds are cached.

**Verify all services are healthy:**

```bash
docker compose ps
# Expected:
#   forensichub_postgres   Up (healthy)
#   forensichub_redis      Up (healthy)
#   forensichub_backend    Up
#   forensichub_frontend   Up
```

**Log in:**
- URL: `http://localhost:3000`
- Email: value of `ADMIN_EMAIL` (default `admin@forensichub.local`)
- Password: value of `ADMIN_PASSWORD` (default `Admin@123456`)

Change the admin password immediately after the first login on any shared environment.

---

## Environment Variables

All configuration lives in `.env` at the repository root.

### App & Database

| Variable | Default | Required for public? | Notes |
|---|---|---|---|
| `APP_ENV` | `development` | Set to `production` | Enables strict logging, hides verbose error traces. |
| `SERVER_PORT` | `8080` | Optional | Backend host port. |
| `FRONTEND_PORT` | `3000` | Optional | Frontend (nginx) host port. |
| `POSTGRES_DB` | `forensichub` | No | Database name. |
| `POSTGRES_USER` | `forensic` | No | Postgres user. |
| `POSTGRES_PASSWORD` | `forensic_secret` | **Yes** | Use a strong password in production. |
| `REDIS_PASSWORD` | `redis_secret` | **Yes** | Same — generate a strong value. |

### Auth & Admin

| Variable | Default | Required for public? | Notes |
|---|---|---|---|
| `JWT_SECRET` | `change_this_jwt_secret_in_production_min_32_chars` | **Yes** | Random ≥ 32 chars. Changing it invalidates all issued JWTs. |
| `ADMIN_EMAIL` | `admin@forensichub.local` | Optional | Seeded admin account (created on first boot only). |
| `ADMIN_PASSWORD` | `Admin@123456` | **Yes** | Change before exposing publicly. |

### Public-facing network

| Variable | Default | When public | Notes |
|---|---|---|---|
| `PUBLIC_URL` | _(empty)_ | **Must set** | Externally-reachable URL of the backend, e.g. `https://hub.example.com` or `http://203.0.113.10:8080`. If empty, the backend falls back to `c.Request.Host` (which may resolve to a container hostname) — agents will fail with 401 / connection refused. |
| `USE_HTTPS` | `false` | `true` if behind an SSL-terminating proxy that doesn't send `X-Forwarded-Proto` | Forces auto-detected URLs to use `https://`. |
| `ALLOWED_ORIGINS` | _(empty)_ | **Must set** | Comma-separated list of frontend origins permitted for CORS + WebSocket upgrades. Example: `https://hub.example.com,https://admin.example.com`. |
| `VITE_API_URL` | `http://localhost:8080` | Set to the public URL | Baked into the frontend JS bundle at build time — changing it requires rebuilding the frontend image. |
| `VITE_WS_URL` | `ws://localhost:8080` | `wss://hub.example.com` | Same — requires frontend rebuild. |

### Optional integrations

| Variable | Default | Notes |
|---|---|---|
| `AES_ENCRYPTION_KEY` | placeholder | Must be exactly **32 bytes** (256-bit). Used to encrypt third-party integration credentials (e.g. OpenCTI). |
| `NVD_API_KEY` | _(empty)_ | Raises NVD CVE rate limit (5 → 50 req / 30 s). |
| `GITHUB_TOKEN` | _(empty)_ | Raises GitHub Search rate limit (10 → 30 req/min). |
| `OSINT_VIRUSTOTAL_API_KEY` | _(empty)_ | OSINT module — VirusTotal domain-reputation collector. Falls back to `SUBFINDER_VIRUSTOTAL` when empty. |
| `OSINT_SHODAN_API_KEY` | _(empty)_ | OSINT module — full Shodan host collector for IP targets. Falls back to `SUBFINDER_SHODAN` when empty (a free-tier key returns 403 on the host API — the free Shodan InternetDB collector still runs regardless). |
| `OSINT_ABUSEIPDB_API_KEY` | _(empty)_ | OSINT module — unlocks the AbuseIPDB abuse-score collector for IP targets. |
| `OSINT_HIBP_API_KEY` | _(empty)_ | OSINT module — unlocks the Have I Been Pwned breach-check collector for email targets. |
| `OSINT_NUMVERIFY_API_KEY` | _(empty)_ | OSINT module — unlocks the NumVerify carrier / line-type collector for phone targets. |

### OSINT Footprinting

The **OSINT** module (sidebar → *Hacking → OSINT*) takes a single identifier —
an IP, domain, email, phone number, or username — auto-detects its type, and
passively collects the traces that identifier left across the internet,
streaming progress live and grouping findings by source. Each discovered
related identifier (a registrant email, an MX domain, a PTR hostname, a
probable username…) is a one-click **pivot** that starts a fresh investigation.

A **username** investigation checks ~17 platforms (GitHub, GitLab, Reddit,
Telegram, Keybase, npm…) by HTTP and lists JS-walled platforms (X, Instagram,
Facebook, TikTok, LinkedIn…) as candidate links to confirm by hand — note
that automated profile detection yields *candidates*, not proof, and an
email's local part is only a *probable* username. IP addresses cannot be
mapped to social-media accounts and the module does not attempt to.

It works with **zero configuration** using free no-key sources: RDAP/WHOIS,
DNS, crt.sh Certificate Transparency, the Wayback Machine, ip-api geolocation,
Shodan InternetDB, and Gravatar. It also cross-checks the target against the
local OpenCTI IOC store. The VirusTotal and Shodan collectors **reuse the
recon module's `SUBFINDER_VIRUSTOTAL` / `SUBFINDER_SHODAN` keys automatically**
— no extra setup. The remaining `OSINT_*` keys above each unlock one more
collector; an unset key simply marks that collector *skipped*. The module is
backend-native: it does **not** use the forensic agent.

---

## Public / Production Deployment

### 1. Put the stack behind a TLS reverse proxy

Recommended: Caddy (auto Let's Encrypt). Minimal `Caddyfile`:

```caddyfile
hub.example.com {
    encode gzip

    handle /api/* {
        reverse_proxy backend_host:8080
    }
    handle /ws/* {
        reverse_proxy backend_host:8080
    }
    handle {
        reverse_proxy frontend_host:3000
    }
}
```

If using nginx or Traefik, make sure WebSocket upgrade headers are forwarded:

```nginx
proxy_http_version 1.1;
proxy_set_header   Upgrade $http_upgrade;
proxy_set_header   Connection "upgrade";
```

### 2. Update `.env` for production

```env
APP_ENV=production
PUBLIC_URL=https://hub.example.com
USE_HTTPS=true
ALLOWED_ORIGINS=https://hub.example.com
VITE_API_URL=https://hub.example.com
VITE_WS_URL=wss://hub.example.com

# Generate strong random values — do NOT keep defaults
JWT_SECRET=$(openssl rand -hex 32)
POSTGRES_PASSWORD=$(openssl rand -base64 24)
REDIS_PASSWORD=$(openssl rand -base64 24)
ADMIN_PASSWORD=<set a strong password>

AES_ENCRYPTION_KEY=$(openssl rand -hex 16)   # 32 bytes hex
```

### 3. Rebuild the stack with the new config

```bash
docker compose down
docker compose up -d --build
```

> **Important:** `VITE_API_URL` and `VITE_WS_URL` are baked into the frontend JS bundle at build time. Changing them requires rebuilding the frontend image (`docker compose build frontend && docker compose up -d frontend`) — a simple restart is not enough.

### 4. Hardening

- **Close DB ports** — in `docker-compose.yml` remove the `ports:` mapping from `postgres` and `redis`. The default template exposes `5432` and `6379` to the host for development convenience; this MUST NOT be kept in production.
- **Backup volumes** — schedule `pg_dump` of `postgres_data` and `tar` snapshots of `storage_data` (see [Backup & Operations](#backup--operations)).
- **Rate-limit / WAF** — apply at the reverse-proxy or CDN layer (Cloudflare, fail2ban). The backend has no built-in rate limiting.
- **Audit log review** — the `audit_logs` table records every privileged action (login, tool upload/delete, agent create/delete, job dispatch). Export periodically.

### 5. Verify from outside the network

```bash
# Login page loads over HTTPS
curl -I https://hub.example.com

# Backend health
curl https://hub.example.com/api/v1/health

# Agent endpoint reachable (run from a machine that will host an agent)
curl -I https://hub.example.com/api/v1/agent/tools
# Expect 401 "agent token required" — endpoint is reachable
```

---

## Deploying Agents to Endpoints

1. In the dashboard, open the **Agents** page → click **+ New Agent**.
2. Enter a name (e.g. `web01-prod`) + description → **Create**.
3. The system generates an agent token and shows an install command:
   - **Windows (PowerShell):** `iwr -UseBasicParsing https://hub.example.com/api/v1/agents/<id>/install.ps1 | iex`
   - **Linux (bash):** `curl -fsSL https://hub.example.com/api/v1/agents/<id>/install.sh | bash`
4. Run the command on the target host with administrator/root privileges.

The installer:
- Downloads the platform-appropriate agent binary.
- Writes a `forensichub-agent.conf` next to the binary (`SERVER_URL`, `AGENT_TOKEN`, `AGENT_NAME`).
- Registers a Windows Service or systemd unit and starts it.
- Connects via WebSocket — the agent appears as **online** in the dashboard within a few seconds.

**Agent config (`forensichub-agent.conf`, KEY=VALUE format):**

| Variable | Required | Default | Notes |
|---|---|---|---|
| `SERVER_URL` | Yes | — | Backend URL, e.g. `https://hub.example.com`. |
| `AGENT_TOKEN` | Yes | — | 32-byte hex from the install script. |
| `AGENT_NAME` | Yes | — | Display name. |
| `WORK_DIR` | No | OS temp | Tool cache + artifact scratch dir. |
| `LOG_LEVEL` | No | `info` | `debug` / `info` / `warn` / `error`. |

---

## Webshell Scanner Usage

The backend auto-seeds the `Webshell Scanner` tool (multi-platform ZIP bundle) on first boot if it doesn't exist in the DB.

### How to scan

1. Install the agent on the web server you want to scan.
2. Open the dashboard → **Webshell Scanner** menu.
3. Select an online **Target Agent**.
4. The page automatically dispatches a `health` job to provision the scanner binary on the agent. Wait for the `Ready to scan!` toast. If it fails, click **Test Env** to retry.
5. Enter a **Scan Path** — a directory on the agent host:
   - Windows IIS: `C:\inetpub\wwwroot`
   - Linux Apache/nginx: `/var/www/html`
6. (Optional) Toggle **Debug Mode** for verbose logging (passes `--verbose`).
7. Click **Start Scan**.

### Output and reports

- **Process View** — terminal-style live stream of the scan output, color-coded by severity:
  - Green `[+]` — info / progress
  - Amber `[!]` — warning / detected shell
  - Red `Error` — runtime error
- The scan output ends with an `+--- Output ---+` block listing the report paths.
- The agent then automatically uploads `report.html` as a job artifact. Look for `[+] Report uploaded successfully` in the output.

### Viewing the report

- The **Report Viewer** tab unlocks once the job completes and the artifact is uploaded.
- An iframe renders the interactive HTML report — searchable, filterable by severity, with code-snippet previews of detected shells.
- The **Download** icon next to the tabs downloads the raw `report.html`.

### Notes

- The scanner exits with **code 1** when it finds a webshell of medium severity or higher (this is intentional, so CI/CD can detect findings via exit code). The job is still marked `done` and the artifact is uploaded normally.
- Exit code `0` = clean. Exit code `2` = invalid arguments.

---

## Rebuilding Components

### Backend or frontend (after editing source)

```bash
# Backend (Go)
docker compose build backend && docker compose up -d backend

# Frontend (React) — also required after changing VITE_* env vars
docker compose build frontend && docker compose up -d frontend

# Both
docker compose build && docker compose up -d
```

### Agent binaries

```bash
cd agent
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o forensichub-agent.exe ./cmd/agent
GOOS=linux   GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -o forensichub-agent-linux ./cmd/agent
```

Or, if `make` is available:

```bash
cd agent && make build-all     # both
cd agent && make build-windows # windows only
cd agent && make build-linux   # linux only
```

After rebuilding, **redeploy the binary to every agent host manually** (stop the service, copy the new binary, start the service). Agents do NOT self-update.

### Webshell Scanner (Python → standalone binaries)

Required when `tools/webshell-scanner/dist/{windows,linux}` files are missing or after editing scanner source / rules.

**Prerequisites:** Windows host + Docker Desktop running + Python 3.11.

```powershell
cd "<repo>\tools\webshell-scanner"

# 1. Create venv + install deps + PyInstaller
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -e ".[dev]"

# 2. Run the orchestrator
python bundle.py
```

`bundle.py` performs three steps automatically:

1. **Windows binary** — runs PyInstaller locally with `build.spec` → `dist/windows/webshell-scanner.exe`.
2. **Linux binary** — writes a temporary `Dockerfile.build` (`python:3.11-slim` + `binutils gcc libmagic1`), builds an image, and uses `docker cp` to extract → `dist/linux/webshell-scanner`.
3. **Bundle ZIP** — packs both binaries into `dist/webshell-scanner-bundle.zip` with a `windows/` + `linux/` layout.

**Result:**

```
tools/webshell-scanner/dist/
├── windows/webshell-scanner.exe       (~18 MB)
├── linux/webshell-scanner             (~20 MB)
└── webshell-scanner-bundle.zip        (~20 MB)
```

**Build only one piece:**

```powershell
# Windows only
.\.venv\Scripts\python.exe -m PyInstaller build.spec --clean --noconfirm --distpath dist/windows

# Linux only (requires Docker)
docker build -t webshell-scanner-build -f Dockerfile.build .
docker create --name temp_scanner_build webshell-scanner-build
docker cp temp_scanner_build:/app/dist/linux/. dist/linux/
docker rm temp_scanner_build

# Rebuild the bundle ZIP only (when both binaries already exist)
python -c "from bundle import create_bundle; create_bundle()"
```

**Deploying the new bundle to the backend:**

Option A — auto-seed (cleanest):

```bash
cp tools/webshell-scanner/dist/webshell-scanner-bundle.zip backend/defaults/webshell-scanner.zip

docker compose exec postgres psql -U forensic -d forensichub \
  -c "DELETE FROM jobs WHERE tool_id IN (SELECT id FROM tools WHERE name ILIKE '%webshell%');" \
  -c "DELETE FROM tools WHERE name ILIKE '%webshell%';"

docker compose restart backend
```

The backend's seed routine recreates the `Webshell Scanner` tool from the new bundle with the correct `{{OS}}/webshell-scanner{{EXT}}` entrypoint.

Option B — upload via the UI: open **Tools** → edit `Webshell Scanner` → upload the new file. You will also need to clear the cached tool dir on each agent host (`<WORK_DIR>/tools/<tool_id>/`).

---

## Backup & Operations

### Backup volumes

```bash
# Database
docker compose exec postgres pg_dump -U forensic forensichub > backup-$(date +%F).sql

# Storage (tool binaries + artifacts)
docker run --rm -v forensichub_storage_data:/data -v $(pwd)/backups:/backup alpine \
  tar czf /backup/storage-$(date +%F).tar.gz -C /data .
```

### Restore

```bash
# Database
cat backup.sql | docker compose exec -T postgres psql -U forensic -d forensichub

# Storage
docker run --rm -v forensichub_storage_data:/data -v $(pwd)/backups:/backup alpine \
  tar xzf /backup/storage-2026-05-02.tar.gz -C /data
```

### Logs

```bash
docker compose logs -f backend
docker compose logs -f frontend
docker compose logs -f --tail=200       # all services
```

### Upgrade

```bash
git pull
docker compose down
docker compose up -d --build
```

GORM `AutoMigrate` runs at every backend boot — it only ADDS columns, never drops, so older schemas remain compatible.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| Login fails with valid credentials | `JWT_SECRET` was changed after the user logged in previously | Log out, log in again. Old JWTs are no longer valid. |
| Agent install script returns 404 | Backend container predates the route | `docker compose build backend && docker compose up -d backend` |
| Agent registers but goes offline within minutes | Heartbeat fails — agent cannot reach backend over WS | Verify `PUBLIC_URL` is reachable from the agent host; check outbound firewall; tail the agent log file. |
| Agent download returns 401 | Frontend/backend uses a JWT route instead of the agent route | Path must be `/api/v1/agent/tools/<id>/download` (note the `/agent/` prefix). |
| Job stuck in `pending`, never reaches `ready` | Agent is offline or not receiving `job_start` over WS | Confirm the agent is online; tail `docker compose logs -f backend` for `dispatched job ...`. |
| `POST /jobs/:id/run` returns HTTP 409 | Caller fired `/run` while job was still `pending` | Wait for job status to transition to `ready` before calling `/run`. The Webshell Scanner page handles this via polling automatically. |
| Report Viewer tab is blank after a successful scan | Iframe hits `/artifact/content` without a JWT | Hard-refresh the browser (Ctrl+F5). The frontend now appends `?token=` to the iframe src. |
| Process View shows no output | EventSource missing the `?token=` param | Hard-refresh. The frontend already passes the token via query string for SSE. |
| `executor: executable_path required for ZIP tool` | ZIP tool has no `Executable Path` configured | Edit the tool → set `executable_path` (e.g. `{{OS}}/<binary>{{EXT}}`). |
| `No such option: --debug` from the scanner | Tool flag mismatch | The scanner expects `--verbose`. The frontend now sends `--verbose` when Debug Mode is on. |
| Browser CORS error | Frontend origin not in `ALLOWED_ORIGINS` | Add the origin to `.env` `ALLOWED_ORIGINS` and restart the backend. |
| WebSocket disconnects immediately (close code 1006) | Reverse proxy not forwarding `Upgrade` / `Connection` headers | Configure the proxy correctly (see [Public / Production Deployment](#public--production-deployment)). Caddy works out of the box; nginx and Traefik need explicit headers. |

---

© ForensicHub — DFIR Orchestration Platform
