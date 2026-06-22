# Stage 0: Build agent binaries (online + offline, Windows + Linux)
FROM golang:1.23-alpine AS agent-builder

RUN apk add --no-cache git ca-certificates

WORKDIR /agent
COPY ./agent .

RUN go mod tidy && go mod download

# ── Online agent ──────────────────────────────────────────────
# Cross-compile for Windows (amd64)
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o forensichub-agent.exe ./cmd/agent

# Cross-compile for Linux (amd64)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o forensichub-agent-linux ./cmd/agent

# ── Offline agent ─────────────────────────────────────────────
# Cross-compile for Windows (amd64) — includes embedded HTML UI
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o agent-offline.exe ./cmd/offline-agent

# Cross-compile for Linux (amd64)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o agent-offline-linux ./cmd/offline-agent

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1: Build backend binary
FROM golang:1.23-alpine AS builder

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

# Stage 1.5a: Build Webshell Scanner (Linux)
FROM python:3.11-slim AS scanner-builder-linux

RUN apt-get update && apt-get install -y binutils gcc libmagic1

WORKDIR /scanner
COPY ./tools/webshell-scanner .
RUN pip install . pyinstaller
RUN pyinstaller build.spec --clean --noconfirm --distpath dist/linux

# Stage 1.5b: Build Webshell Scanner (Windows)
FROM tobix/pywine:3.11 AS scanner-builder-windows

WORKDIR /wine-scanner
COPY ./tools/webshell-scanner .
RUN wine python -m pip install . pyinstaller
RUN wine pyinstaller build.spec --clean --noconfirm --distpath dist/windows

# Stage 1.5c: Bundle
FROM alpine:3.19 AS scanner-bundler
RUN apk add --no-cache zip
WORKDIR /app/defaults
RUN mkdir -p linux windows
COPY --from=scanner-builder-linux /scanner/dist/linux/webshell-scanner linux/
COPY --from=scanner-builder-windows /wine-scanner/dist/windows/webshell-scanner.exe windows/
RUN zip -r webshell-scanner.zip linux/ windows/

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 2: Minimal runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S appgroup && \
    adduser -S -h /home/appuser appuser -G appgroup

# Maigret (optional) — powers the OSINT username collector (3000+ sites). Uses
# apk-provided C-extension deps to avoid slow source builds. Best-effort: if the
# install fails the OSINT "maigret" collector simply skips and the rest works.
RUN apk add --no-cache python3 py3-pip py3-lxml py3-aiohttp py3-requests && \
    (pip install --no-cache-dir --break-system-packages maigret \
     || echo "[build] maigret install failed — OSINT maigret collector will skip at runtime")

WORKDIR /app

# Backend server binary
COPY --from=builder /build/server /app/server

# Pre-compiled online agent binaries served for one-click install
COPY --from=agent-builder /agent/forensichub-agent.exe   /app/agent-bins/forensichub-agent.exe
COPY --from=agent-builder /agent/forensichub-agent-linux /app/agent-bins/forensichub-agent-linux

# Pre-compiled offline agent binaries — used by GenerateOfflineBundle to embed in ZIP
COPY --from=agent-builder /agent/agent-offline.exe      /app/defaults/agent-offline.exe
COPY --from=agent-builder /agent/agent-offline-linux    /app/defaults/agent-offline-linux

# Copy internal data like cve_collection.json
COPY --from=builder /build/data /app/data

# Copy documentation for playbooks
COPY ./docs /app/docs

# Integrated Tools
COPY --from=scanner-bundler /app/defaults/webshell-scanner.zip /app/defaults/webshell-scanner.zip

# Create required directories and fix ownership
RUN mkdir -p /app/storage /app/agent-bins /app/defaults \
    && chown -R appuser:appgroup /app /home/appuser

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/server"]
