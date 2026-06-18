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

# Stage 1.5: Build Webshell Scanner (Linux)
FROM python:3.11-slim AS scanner-builder

RUN apt-get update && apt-get install -y binutils gcc libmagic1 zip

WORKDIR /scanner
COPY ./tools/webshell-scanner .
RUN pip install . pyinstaller
# Build Linux binary
RUN pyinstaller build.spec --clean --noconfirm --distpath dist/linux

# Create a default bundle with Linux binary
WORKDIR /app/defaults
RUN mkdir -p linux
RUN cp /scanner/dist/linux/webshell-scanner linux/
# Note: Windows binary can only be added if pre-built on host, otherwise bundle is Linux-only
# We zip it so the backend can easily "upload" it to storage
RUN zip -r webshell-scanner-linux.zip linux/

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 2: Minimal runtime image
FROM alpine:3.19

RUN apk add --no-cache ca-certificates tzdata && \
    addgroup -S appgroup && \
    adduser -S -h /home/appuser appuser -G appgroup

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

# Integrated Tools
COPY --from=scanner-builder /app/defaults/webshell-scanner-linux.zip /app/defaults/webshell-scanner.zip

# Create required directories and fix ownership
RUN mkdir -p /app/storage /app/agent-bins /app/defaults \
    && chown -R appuser:appgroup /app /home/appuser

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/server"]
