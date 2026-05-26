# Stage 0: Build agent binaries (Windows + Linux) from the repo root context
FROM golang:1.23-alpine AS agent-builder

RUN apk add --no-cache git ca-certificates

WORKDIR /agent
COPY ./agent .

RUN go mod tidy && go mod download

# Cross-compile for Windows (amd64)
RUN GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o forensichub-agent.exe ./cmd/agent

# Cross-compile for Linux (amd64)
RUN GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
    go build -ldflags="-s -w" -o forensichub-agent-linux ./cmd/agent

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

# Stage 1.6: Download pre-built recon tool binaries from GitHub releases.
# Using pre-built binaries is faster and avoids CGO / module-proxy issues
# that occur when compiling inside Docker.
# To upgrade a tool: update the version variable in the matching RUN block.
FROM alpine:3.19 AS recon-tools-builder

RUN apk add --no-cache curl ca-certificates unzip tar

WORKDIR /tools

# subfinder (subdomain enumeration)
RUN SFVER=2.14.0 && \
    curl -fsSL "https://github.com/projectdiscovery/subfinder/releases/download/v${SFVER}/subfinder_${SFVER}_linux_amd64.zip" \
    -o sf.zip && unzip -q sf.zip subfinder && rm sf.zip

# httpx (HTTP probing)
RUN HXVER=1.6.8 && \
    curl -fsSL "https://github.com/projectdiscovery/httpx/releases/download/v${HXVER}/httpx_${HXVER}_linux_amd64.zip" \
    -o hx.zip && unzip -q hx.zip httpx && rm hx.zip

# nuclei (vulnerability scanning)
RUN NCVER=3.8.0 && \
    curl -fsSL "https://github.com/projectdiscovery/nuclei/releases/download/v${NCVER}/nuclei_${NCVER}_linux_amd64.zip" \
    -o nc.zip && unzip -q nc.zip nuclei && rm nc.zip

# ffuf (directory fuzzing)
RUN FFVER=2.1.0 && \
    curl -fsSL "https://github.com/ffuf/ffuf/releases/download/v${FFVER}/ffuf_${FFVER}_linux_amd64.tar.gz" \
    -o ffuf.tgz && tar xzf ffuf.tgz ffuf && rm ffuf.tgz

# gowitness (screenshots) — tag has no "v" prefix
RUN GWVER=3.1.1 && \
    curl -fsSL "https://github.com/sensepost/gowitness/releases/download/${GWVER}/gowitness-${GWVER}-linux-amd64" \
    -o gowitness

# dnsx (DNS resolver / subdomain validator)
RUN DXVER=1.2.3 && \
    curl -fsSL "https://github.com/projectdiscovery/dnsx/releases/download/v${DXVER}/dnsx_${DXVER}_linux_amd64.zip" \
    -o dx.zip && unzip -q dx.zip dnsx && rm dx.zip

# katana (web crawler — discovers endpoints and parameters)
RUN KTVER=1.6.1 && \
    curl -fsSL "https://github.com/projectdiscovery/katana/releases/download/v${KTVER}/katana_${KTVER}_linux_amd64.zip" \
    -o kt.zip && unzip -q kt.zip katana && rm kt.zip

# naabu (fast port scanner — SYN/connect, covers 3000 ports quickly)
RUN NBVER=2.3.3 && \
    curl -fsSL "https://github.com/projectdiscovery/naabu/releases/download/v${NBVER}/naabu_${NBVER}_linux_amd64.zip" \
    -o nb.zip && unzip -q nb.zip naabu && rm nb.zip

# amass (comprehensive subdomain enumeration — passive mode)
RUN AMVER=3.23.3 && \
    curl -fsSL "https://github.com/owasp-amass/amass/releases/download/v${AMVER}/amass_Linux_amd64.zip" \
    -o am.zip && unzip -q -j am.zip "*/amass" && rm am.zip

RUN chmod +x /tools/*

# Download SecLists wordlists. Two tiers:
#   - common.txt          (~37 KB, ~4.6k entries) — quick fallback
#   - raft-medium-words.txt (~340 KB, ~30k entries) — preferred for accuracy
# Each download falls back gracefully if its mirror is unavailable, so the
# image still builds offline (engine.go picks whichever exists at run time).
RUN mkdir -p /wordlists && \
    ( curl -fsSL \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/common.txt" \
    -o /wordlists/common.txt 2>/dev/null || \
    printf '%s\n' \
    admin login index.php wp-admin .git robots.txt sitemap.xml \
    api v1 v2 backup config uploads static assets js css \
    > /wordlists/common.txt ) && \
    curl -fsSL \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/raft-medium-words.txt" \
    -o /wordlists/raft-medium-words.txt 2>/dev/null || true && \
    curl -fsSL \
    "https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-20000.txt" \
    -o /wordlists/subdomain-medium.txt 2>/dev/null || true

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1.9: Build additional Go-based recon tools
#   gau     — passive URL discovery (Wayback Machine, URLScan, Common Crawl, OTX)
#   dalfox  — XSS scanner with JSONL output and pipe/file modes
#   jsluice — JavaScript AST-based endpoint and secret extraction (BishopFox)
FROM golang:1.24-alpine AS recon-extra-builder
RUN apk add --no-cache git ca-certificates
ENV CGO_ENABLED=0
# gau: passive URL discovery (Wayback/URLScan/OTX)
RUN go install github.com/lc/gau/v2/cmd/gau@latest
# dalfox: XSS scanner — v2.10.0 requires Go 1.24+
RUN go install github.com/hahwul/dalfox/v2@v2.10.0

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1.95: Pre-download nuclei templates so vuln scanning works without
# internet access at runtime. --depth 1 skips git history to keep layer small.
FROM alpine:3.19 AS nuclei-templates-builder
RUN apk add --no-cache git ca-certificates
RUN git clone --depth 1 \
    https://github.com/projectdiscovery/nuclei-templates.git \
    /nuclei-templates
# Fail the build if the clone produced no .yaml templates — at runtime the
# vuln step pre-flight check would skip every scan with "templates not seeded",
# which is worse to discover in production than at build time.
RUN test -n "$(find /nuclei-templates -maxdepth 3 -name '*.yaml' -print -quit)" \
    || (echo "FATAL: nuclei-templates clone produced no .yaml files" && exit 1)

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 1.96: Build WPScan (Ruby)
FROM alpine:3.19 AS wpscan-builder
RUN apk add --no-cache ruby ruby-dev build-base libffi-dev procps curl-dev zlib-dev && \
    gem install wpscan --no-document

# ─────────────────────────────────────────────────────────────────────────── #

# Stage 2: Minimal runtime image
FROM alpine:3.19

# nmap      — port scanning (TCP connect mode, no root needed)
# chromium  — headless browser for gowitness screenshots
# gettext   — provides `envsubst` for render-provider-configs.sh
# ruby, procps, curl — required for WPScan (curl provides libcurl.so)
# gcompat   — glibc compatibility shim so the upstream naabu binary
#             (glibc-linked) can run on Alpine (musl). Without this naabu
#             fails at exec with "Error loading shared library libresolv.so.2".
# libpcap   — naabu's runtime dependency (libpcap.so.0.8 → .1 via symlink).
RUN apk add --no-cache ca-certificates tzdata nmap chromium gettext ruby procps curl gcompat libpcap ffmpeg && \
    ln -sf /usr/lib/libpcap.so.1 /usr/lib/libpcap.so.0.8 && \
    addgroup -S appgroup && \
    adduser -S -h /home/appuser appuser -G appgroup

WORKDIR /app

# Copy WPScan gems and binary
COPY --from=wpscan-builder /usr/lib/ruby/gems /usr/lib/ruby/gems
COPY --from=wpscan-builder /usr/bin/wpscan /usr/local/bin/wpscan

# Backend server binary
COPY --from=builder /build/server /app/server

# Pre-compiled agent binaries served for one-click install
COPY --from=agent-builder /agent/forensichub-agent.exe   /app/agent-bins/forensichub-agent.exe
COPY --from=agent-builder /agent/forensichub-agent-linux /app/agent-bins/forensichub-agent-linux

# Copy internal data like cve_collection.json
COPY --from=builder /build/data /app/data

# Integrated Tools
COPY --from=scanner-builder /app/defaults/webshell-scanner-linux.zip /app/defaults/webshell-scanner.zip

# Recon tools (built from source above)
RUN mkdir -p /app/recon-tools
COPY --from=recon-tools-builder /tools/subfinder  /app/recon-tools/subfinder
COPY --from=recon-tools-builder /tools/dnsx       /app/recon-tools/dnsx
COPY --from=recon-tools-builder /tools/httpx      /app/recon-tools/httpx
COPY --from=recon-tools-builder /tools/katana     /app/recon-tools/katana
COPY --from=recon-tools-builder /tools/nuclei     /app/recon-tools/nuclei
COPY --from=recon-tools-builder /tools/ffuf       /app/recon-tools/ffuf
COPY --from=recon-tools-builder /tools/gowitness  /app/recon-tools/gowitness
COPY --from=recon-tools-builder /tools/naabu     /app/recon-tools/naabu
COPY --from=recon-tools-builder /tools/amass     /app/recon-tools/amass
# Extra Go-based recon tools
COPY --from=recon-extra-builder /go/bin/gau     /app/recon-tools/gau
COPY --from=recon-extra-builder /go/bin/dalfox  /app/recon-tools/dalfox
# nmap is in /usr/bin from apk — symlink into our tool dir for a uniform path
RUN ln -s /usr/bin/nmap /app/recon-tools/nmap && \
    chmod +x /app/recon-tools/*

# Wordlist for ffuf
COPY --from=recon-tools-builder /wordlists /app/wordlists

# Nuclei templates (pre-downloaded; path matches -t flag in engine.go buildArgs)
COPY --from=nuclei-templates-builder /nuclei-templates /home/appuser/nuclei-templates

# Subfinder provider-config template + render script.
# At container start, render-provider-configs.sh expands env vars
# (SUBFINDER_SHODAN, SUBFINDER_CENSYS, …) into the runtime config so API keys
# never need to be baked into the image.
# Build context is the repo root; recon-config/ lives next to backend/.
COPY ./recon-config /app/recon-config
RUN chmod +x /app/recon-config/render-provider-configs.sh

# Create required directories and fix ownership
RUN mkdir -p /app/storage /app/agent-bins /app/defaults /screenshots \
    /home/appuser/.config/subfinder && \
    chown -R appuser:appgroup /app /screenshots /home/appuser

USER appuser

EXPOSE 8080

ENTRYPOINT ["/app/recon-config/render-provider-configs.sh", "/app/server"]
