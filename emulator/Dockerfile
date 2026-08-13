# Local malware emulation sidecar — Mandiant speakeasy (CPU + Win32 API emulation
# via Unicorn). Debian base so the unicorn/capstone wheels install cleanly (they
# do not on Alpine/musl, which is why this is a separate service, not baked into
# the backend image). Emulation never really runs the sample — it is safe on-box.
FROM python:3.11-slim

# System deps (required for the unicorn/capstone wheels) + radare2 (AI-RE) in ONE
# apt transaction, so radare2 reuses the SAME successful `apt-get update` rather
# than a separate flakier one (the cause of radare2 silently missing before).
# apt-get update is retried against transient network. radare2 is best-effort
# (dynamic emulation still works without it) with two download fallbacks.
RUN set -eux; \
    for i in 1 2 3; do apt-get update && break || sleep 5; done; \
    apt-get install -y --no-install-recommends gcc build-essential libffi-dev curl unzip ca-certificates osslsigncode upx-ucl \
        file libimage-exiftool-perl ssdeep binwalk libzbar0; \
    # ClamAV is an OPTIONAL second (fully offline) detection engine. freshclam is
    # deliberately NOT run at build time — downloading signatures would break the
    # no-egress guarantee; mount /var/lib/clamav to enable it.
    apt-get install -y --no-install-recommends clamav || echo "[build] clamav unavailable — offline AV scan off"; \
    ( apt-get install -y --no-install-recommends radare2 \
      || ( curl -fsSL https://github.com/radareorg/radare2/releases/download/5.9.8/radare2_5.9.8_amd64.deb -o /tmp/r2.deb \
           && apt-get install -y --no-install-recommends /tmp/r2.deb ) \
      || ( u=$(curl -fsSL https://api.github.com/repos/radareorg/radare2/releases/latest | grep -o 'https://[^"]*_amd64\.deb' | head -1); \
           [ -n "$u" ] && curl -fsSL "$u" -o /tmp/r2.deb && apt-get install -y --no-install-recommends /tmp/r2.deb ) \
      || echo "[build] radare2 unavailable — AI-assisted RE disabled" ); \
    ( command -v r2 >/dev/null 2>&1 && r2 -v ) || true; \
    rm -f /tmp/r2.deb; rm -rf /var/lib/apt/lists/*

# de4dot — .NET deobfuscator. Commodity RATs (AsyncRAT, njRAT, Quasar, Remcos
# .NET builds) ship packed by ConfuserEx/SmartAssembly/Babel, and their config,
# strings and C2 only become readable after deobfuscation. Needs mono to run the
# .NET Framework build; both are best-effort, and .NET analysis degrades to raw
# metadata when they are missing.
RUN set -eux; \
    ( apt-get update && apt-get install -y --no-install-recommends mono-runtime libmono-system-windows-forms4.0-cil \
      || echo "[build] mono unavailable — de4dot disabled" ); \
    # de4dot-cex is the maintained community build; the original repo publishes no
    # binaries any more. Pinned URL first, "latest" as the fallback.
    ( curl -fsSL https://github.com/ViRb3/de4dot-cex/releases/download/v4.0.0/de4dot-cex.zip -o /tmp/de4dot.zip \
      || curl -fsSL "$(curl -fsSL https://api.github.com/repos/ViRb3/de4dot-cex/releases/latest | grep -o 'https://[^\"]*de4dot[^\"]*\.zip' | head -1)" -o /tmp/de4dot.zip ) \
      && mkdir -p /opt/de4dot && unzip -q -o /tmp/de4dot.zip -d /opt/de4dot \
      && ( [ -f /opt/de4dot/de4dot.exe ] || find /opt/de4dot -name 'de4dot*.exe' -exec cp {} /opt/de4dot/de4dot.exe \; ) \
      || echo "[build] de4dot unavailable — .NET deobfuscation off"; \
    rm -f /tmp/de4dot.zip; rm -rf /var/lib/apt/lists/*

# Deep static-analysis binaries (standalone, bundle their own rules) — capa
# (capabilities + ATT&CK) and FLOSS (deobfuscated strings). Pinned direct URLs
# FIRST (no GitHub API → immune to unauthenticated rate limits on a fresh clone),
# with the "latest" API as fallback. Retried; best-effort (static still works).
RUN set -eux; \
    dl() { for i in 1 2 3; do curl -fsSL "$1" -o "$2" && return 0; sleep 3; done; return 1; }; \
    ( dl https://github.com/mandiant/capa/releases/download/v7.4.0/capa-v7.4.0-linux.zip /tmp/capa.zip \
      || dl "$(curl -fsSL https://api.github.com/repos/mandiant/capa/releases/latest | grep -o 'https://[^"]*-linux\.zip' | head -1)" /tmp/capa.zip ) \
      && unzip -o /tmp/capa.zip -d /usr/local/bin && chmod +x /usr/local/bin/capa \
      || echo "[build] capa unavailable — capability detection off"; \
    ( dl https://github.com/mandiant/flare-floss/releases/download/v3.1.1/floss-v3.1.1-linux.zip /tmp/floss.zip \
      || dl "$(curl -fsSL https://api.github.com/repos/mandiant/flare-floss/releases/latest | grep -o 'https://[^"]*-linux\.zip' | head -1)" /tmp/floss.zip ) \
      && unzip -o /tmp/floss.zip -d /usr/local/bin && chmod +x /usr/local/bin/floss \
      || echo "[build] floss unavailable — deobfuscated strings off"; \
    rm -f /tmp/capa.zip /tmp/floss.zip

WORKDIR /app
COPY emulator/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Optional lure/e-mail parsers: Outlook .msg (extract-msg), Windows shortcuts
# (LnkParse3) and QR decoding in attached images (pillow + pyzbar). Best-effort —
# each analyser degrades to a fallback when its library is missing, so a wheel
# that fails to build must not fail the image.
RUN pip install --no-cache-dir extract-msg==0.48.5 LnkParse3==1.5.0 pillow==10.4.0 pyzbar==0.1.9 \
    || pip install --no-cache-dir extract-msg LnkParse3 pillow pyzbar \
    || echo "[build] optional lure/e-mail parsers unavailable"

COPY emulator/app.py emulator/triage.py emulator/mailparse.py emulator/docext.py emulator/deepen.py ./

# YARA rules for memory scanning (catches the payload unpacked in RAM) — the same
# bundled ruleset the backend uses on files. Operators can add more .yar here.
RUN mkdir -p /rules
COPY tools/malware-yara/ /rules/

# Run unprivileged.
RUN useradd -m -u 10001 emu
# The ClamAV signature store the admin update writes into. Created and owned here
# so the unprivileged user can write it: a named volume inherits the image's
# ownership of its mount point, and a root-owned one makes freshclam fail with a
# permissions error that looks nothing like the actual problem.
RUN mkdir -p /clamav-db && chown -R emu:emu /clamav-db
USER emu

EXPOSE 8091
ENV EMULATION_TIMEOUT=90
ENV YARA_RULES=/rules
CMD ["python", "app.py"]
