# Script sandbox — runs untrusted JS/Python under instrumentation.
#
# This is the one image in the stack that executes attacker code on purpose, so
# it carries nothing it does not need: no compiler, no package manager at runtime,
# no npm dependencies at all (the harness and the server use only Node built-ins).
# Containment is layered on top by compose: an `internal: true` network whose only
# other host is the sinkhole, a read-only root filesystem, all capabilities
# dropped, and a non-root user.
FROM node:20-bookworm-slim

# python3 gives the second supported language; unzip stages a dropped folder so a
# loader can reach the payload files it requires at runtime. No build toolchain.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends python3 python3-minimal unzip ca-certificates curl; \
    rm -rf /var/lib/apt/lists/*

# PowerShell is the third language, and for Windows samples it is the FIRST one
# that matters: most script malware in the wild is PowerShell, VBS, or a LNK that
# launches PowerShell, while Node samples are the minority. A sandbox that runs
# only Node and Python executes the uncommon case.
#
# Installed from Microsoft's own apt repository, so the packages are signature-
# verified by apt rather than trusted from a bare tarball. It costs ~180 MB —
# the price of executing the language the samples are actually written in.
RUN set -eux; \
    curl -fsSL -o /tmp/ms-prod.deb https://packages.microsoft.com/config/debian/12/packages-microsoft-prod.deb; \
    dpkg -i /tmp/ms-prod.deb; \
    rm -f /tmp/ms-prod.deb; \
    apt-get update; \
    apt-get install -y --no-install-recommends powershell; \
    apt-get purge -y --auto-remove curl; \
    rm -rf /var/lib/apt/lists/* /root/.cache; \
    pwsh -NoProfile -Command 'exit 0'

WORKDIR /opt/sandbox
COPY script-sandbox/server.js ./server.js
RUN mkdir -p /opt/harness
COPY script-sandbox/harness.js /opt/harness/harness.js
COPY script-sandbox/pyharness.py /opt/harness/pyharness.py
COPY script-sandbox/psharness.ps1 /opt/harness/psharness.ps1

# Fail the build rather than ship a harness that cannot parse — a syntax error
# here would surface at analysis time as "the sample did nothing".
RUN node --check /opt/harness/harness.js \
    && node --check /opt/sandbox/server.js \
    && python3 -m py_compile /opt/harness/pyharness.py \
    && pwsh -NoProfile -File /opt/harness/psharness.ps1 /nonexistent-entry-check; \
    test $? -eq 2

# Samples run as this user in a throwaway directory under /tmp (a tmpfs supplied
# by compose, so the read-only root filesystem still leaves them somewhere to work).
RUN useradd -m -u 10002 boxer && chown -R boxer:boxer /opt/sandbox
USER boxer

ENV PORT=8094 \
    SANDBOX_TIMEOUT=60 \
    SANDBOX_MAX_TIMEOUT=180 \
    NODE_ENV=production

EXPOSE 8094
CMD ["node", "/opt/sandbox/server.js"]
