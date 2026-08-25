# Sinkhole — the fake Internet the script sandbox talks to.
#
# It answers DNS, HTTP, HTTPS and a catch-all TCP list so a sample completes its
# beacon/task/exfil routine instead of dying at the first failed resolve. It lives
# on the same `internal: true` network as the sandbox, so nothing it "answers"
# can reach a real host.
FROM python:3.11-slim

# openssl generates the self-signed leaf at first start; libcap lets an
# unprivileged process bind 53/80/443 without running the service as root.
RUN set -eux; \
    apt-get update; \
    apt-get install -y --no-install-recommends openssl libcap2-bin tcpdump; \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY sinkhole/app.py ./app.py
RUN python -m py_compile app.py

# Grant the interpreter the one capability it needs, then drop to a normal user:
# compose can then keep cap_drop: [ALL] with only NET_BIND_SERVICE added back.
RUN setcap 'cap_net_bind_service=+ep' "$(readlink -f "$(command -v python3)")"
# tcpdump captures the run. It lives HERE rather than in the sandbox because a
# Docker bridge is a switch: only an endpoint sees unicast traffic, and the
# endpoint that does NOT execute malware is the safer place to hold NET_RAW.
RUN setcap 'cap_net_raw,cap_net_admin=+ep' "$(readlink -f "$(command -v tcpdump)")"
RUN useradd -m -u 10003 sink && chown -R sink:sink /app
USER sink

ENV CONTROL_PORT=8095 \
    PYTHONUNBUFFERED=1

EXPOSE 53/udp 80 443 8095
CMD ["python3", "app.py"]
