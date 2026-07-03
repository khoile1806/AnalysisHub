# Stage 0: Build agent binaries (online + offline, Windows + Linux)
FROM golang:alpine AS agent-builder

RUN apk add --no-cache git ca-certificates

WORKDIR /agent
COPY ./agent .

RUN go mod tidy && go mod download

# ── Online agent ──────────────────────────────────────────────
# Cross-compile for Windows (amd64)
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o analysishub-agent.exe ./cmd/agent

# Cross-compile for Linux (amd64)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o analysishub-agent-linux ./cmd/agent

# ── Offline agent ─────────────────────────────────────────────
# Cross-compile for Windows (amd64) — includes embedded HTML UI
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o agent-offline.exe ./cmd/offline-agent

# Cross-compile for Linux (amd64)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o agent-offline-linux ./cmd/offline-agent

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1: Build backend binary
FROM golang:alpine AS builder

RUN apk add --no-cache git ca-certificates tzdata

WORKDIR /build

# Build context is the repo root — backend sources live in ./backend/
COPY ./backend .

RUN go mod tidy && go mod download

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags="-w -s -extldflags '-static'" \
    -o server \
    ./cmd/server

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1.5a: Build YARA Scanner (Linux)
FROM python:3.11-slim AS scanner-builder-linux

RUN apt-get update && apt-get install -y binutils gcc libmagic1

WORKDIR /scanner
COPY ./tools/yara-scanner .
RUN pip install . pyinstaller
RUN pyinstaller build.spec --clean --noconfirm --distpath dist/linux

# Stage 1.5b: Build YARA Scanner (Windows)
FROM tobix/pywine:3.11 AS scanner-builder-windows

WORKDIR /wine-scanner
COPY ./tools/yara-scanner .
RUN wine python -m pip install . pyinstaller
RUN wine pyinstaller build.spec --clean --noconfirm --distpath dist/windows

# Stage 1.5c: Bundle
FROM alpine:3.19 AS scanner-bundler
RUN apk add --no-cache zip
WORKDIR /app/defaults
RUN mkdir -p linux windows
COPY --from=scanner-builder-linux /scanner/dist/linux/yara-scanner linux/
COPY --from=scanner-builder-windows /wine-scanner/dist/windows/yara-scanner.exe windows/
RUN zip -r yara-scanner.zip linux/ windows/
RUN wget -qO winpmem.exe https://github.com/Velocidex/WinPmem/releases/download/v4.0.rc1/winpmem_mini_x64_rc2.exe

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1.6: Vulnerability scanner tools (httpx + nuclei) + nuclei templates.
# Pulls the latest ProjectDiscovery release binaries (linux/amd64) and a shallow
# clone of nuclei-templates. All best-effort: if a download fails the vuln-scan
# feature degrades (the tool reports "not installed") instead of breaking the
# image build.
FROM alpine:3.19 AS scanner-tools
RUN apk add --no-cache curl unzip git ca-certificates
RUN set -eux; mkdir -p /out; \
    for tool in httpx nuclei subfinder naabu dnsx katana cdncheck tlsx; do \
      url=$(curl -fsSL "https://api.github.com/repos/projectdiscovery/$tool/releases/latest" \
            | grep -o "https://[^\"]*_linux_amd64\.zip" | head -1); \
      if [ -n "$url" ]; then \
        curl -fsSL "$url" -o "/tmp/$tool.zip" && unzip -o "/tmp/$tool.zip" "$tool" -d /out || \
        echo "[build] $tool download failed — vuln-scan will report it missing"; \
      else echo "[build] could not resolve $tool release URL"; fi; \
    done; \
    chmod +x /out/* 2>/dev/null || true
# gau (lc/gau) lives outside ProjectDiscovery and ships a .tar.gz — install it
# best-effort for the deep/aggressive parameter-discovery stage.
RUN set -eux; \
    url=$(curl -fsSL "https://api.github.com/repos/lc/gau/releases/latest" \
          | grep -o "https://[^\"]*_linux_amd64\.tar\.gz" | head -1); \
    if [ -n "$url" ]; then \
      curl -fsSL "$url" -o /tmp/gau.tar.gz && tar -xzf /tmp/gau.tar.gz -C /out gau && chmod +x /out/gau || \
      echo "[build] gau download failed — deep/aggressive URL discovery will be skipped"; \
    else echo "[build] could not resolve gau release URL"; fi
# dalfox (hahwul/dalfox) — dedicated XSS engine for the deep/aggressive profiles.
RUN set -eux; \
    url=$(curl -fsSL "https://api.github.com/repos/hahwul/dalfox/releases/latest" \
          | grep -o "https://[^\"]*_linux_amd64\.tar\.gz" | head -1); \
    if [ -n "$url" ]; then \
      curl -fsSL "$url" -o /tmp/dalfox.tar.gz && tar -xzf /tmp/dalfox.tar.gz -C /out dalfox && chmod +x /out/dalfox || \
      echo "[build] dalfox download failed — XSS stage will be skipped"; \
    else echo "[build] could not resolve dalfox release URL"; fi
# ffuf (ffuf/ffuf) — content discovery for the full/aggressive profiles.
RUN set -eux; \
    url=$(curl -fsSL "https://api.github.com/repos/ffuf/ffuf/releases/latest" \
          | grep -o "https://[^\"]*_linux_amd64\.tar\.gz" | head -1); \
    if [ -n "$url" ]; then \
      curl -fsSL "$url" -o /tmp/ffuf.tar.gz && tar -xzf /tmp/ffuf.tar.gz -C /out ffuf && chmod +x /out/ffuf || \
      echo "[build] ffuf download failed — content-discovery stage will be skipped"; \
    else echo "[build] could not resolve ffuf release URL"; fi
# Content-discovery wordlist (SecLists common.txt) for ffuf. Best-effort.
RUN mkdir -p /wordlists && \
    (curl -fsSL "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
       -o /wordlists/content-discovery.txt \
     || echo "[build] wordlist download failed — ffuf content discovery will skip at runtime")
RUN git clone --depth 1 https://github.com/projectdiscovery/nuclei-templates /out/nuclei-templates \
    || echo "[build] nuclei-templates clone failed — nuclei will fall back to its own discovery"

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 2: Minimal runtime image
FROM alpine:3.19

# libpcap + gcompat: naabu's release binary is CGO/glibc-linked (libpcap), so it
# needs the glibc-compat shim to run on musl/alpine.
RUN apk add --no-cache ca-certificates tzdata libpcap gcompat && \
    addgroup -S appgroup && \
    adduser -S -h /home/appuser appuser -G appgroup

# Maigret (optional) — powers the OSINT username collector (3000+ sites). Uses
# apk-provided C-extension deps to avoid slow source builds. Best-effort: if the
# install fails the OSINT "maigret" collector simply skips and the rest works.
RUN apk add --no-cache python3 py3-pip py3-lxml py3-aiohttp py3-requests && \
    (pip install --no-cache-dir --break-system-packages maigret \
     || echo "[build] maigret install failed — OSINT maigret collector will skip at runtime")

# nmap (vuln-scan "aggressive" profile: NSE vuln/vulners over discovered ports).
# Best-effort — the nmap stage reports "not installed" if this fails.
RUN apk add --no-cache nmap nmap-scripts || echo "[build] nmap install failed — nmap stage will skip"

# wpscan (optional, "full/aggressive": WordPress core/plugin/theme vulns). Ruby +
# gem; best-effort so a failure never breaks the image — the stage just skips.
RUN apk add --no-cache ruby ruby-dev build-base libcurl && \
    (gem install --no-document wpscan \
     || echo "[build] wpscan install failed — wpscan stage will skip at runtime")

WORKDIR /app

# Backend server binary
COPY --from=builder /build/server /app/server

# Pre-compiled online agent binaries served for one-click install
COPY --from=agent-builder /agent/analysishub-agent.exe   /app/agent-bins/analysishub-agent.exe
COPY --from=agent-builder /agent/analysishub-agent-linux /app/agent-bins/analysishub-agent-linux

# Pre-compiled offline agent binaries — used by GenerateOfflineBundle to embed in ZIP
COPY --from=agent-builder /agent/agent-offline.exe      /app/defaults/agent-offline.exe
COPY --from=agent-builder /agent/agent-offline-linux    /app/defaults/agent-offline-linux

# Copy internal data like cve_collection.json
COPY --from=builder /build/data /app/data

# Default integrated tools (e.g. YARA Scanner bundle, WinPmem)
COPY --from=scanner-bundler /app/defaults/yara-scanner.zip /app/defaults/yara-scanner.zip
COPY --from=scanner-bundler /app/defaults/winpmem.exe      /app/defaults/winpmem.exe

# Vulnerability scanner binaries (httpx, nuclei) + nuclei templates. The COPY of
# the whole /out dir tolerates a partially-failed download stage (missing tools
# just won't be on PATH → the feature reports them as "not installed").
COPY --from=scanner-tools /out/ /usr/local/bin/
RUN mv /usr/local/bin/nuclei-templates /app/nuclei-templates 2>/dev/null || mkdir -p /app/nuclei-templates
# Content-discovery wordlist for the ffuf stage (path matches VULNSCAN_FFUF_WORDLIST).
COPY --from=scanner-tools /wordlists/ /app/wordlists/

# Create required directories and fix ownership
RUN mkdir -p /app/storage /app/agent-bins /app/defaults \
    && chown -R appuser:appgroup /app /home/appuser

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/server"]
