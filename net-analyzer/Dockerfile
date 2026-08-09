# Network-analysis sidecar — Suricata IDS run in OFFLINE (pcap) mode over an
# uploaded capture. It produces eve.json (flows, DNS, TLS/JA3, HTTP, file metadata)
# plus alert events from the Emerging Threats Open ruleset (thousands of C2 /
# malware signatures). Separate service (like the malware emulator) so the packet
# tooling never bloats the backend image. Reads a FILE — needs no raw-socket caps.
# Ubuntu base: suricata + python3-flask ship in universe (Debian slim lacks suricata).
FROM ubuntu:24.04

ENV DEBIAN_FRONTEND=noninteractive
# suricata bundles the `suricata-update` command. tshark adds protocol-hierarchy
# stats + object extraction; yara scans files carved out of the capture. Preseed
# wireshark-common so tshark installs non-interactively (no setuid dumpcap).
RUN set -eux; \
    echo "wireshark-common wireshark-common/install-setuid boolean false" | debconf-set-selections; \
    for i in 1 2 3 4 5; do apt-get update && break || sleep 5; done; \
    apt-get install -y --no-install-recommends suricata suricata-update jq ca-certificates curl gnupg python3 python3-flask tshark yara; \
    rm -rf /var/lib/apt/lists/*

# Zeek — deep protocol logging (conn/dns/http/ssl/x509/files/notice + SMB/
# Kerberos/NTLM/SSH). Complements Suricata's signatures with rich per-connection
# metadata and file provenance. Installed from the official OBS repo; best-effort
# so an offline build still yields a working image (Zeek analysis just disabled).
RUN set -eux; \
    ( echo 'deb http://download.opensuse.org/repositories/security:/zeek/xUbuntu_24.04/ /' > /etc/apt/sources.list.d/zeek.list; \
      curl -fsSL https://download.opensuse.org/repositories/security:zeek/xUbuntu_24.04/Release.key | gpg --dearmor -o /etc/apt/trusted.gpg.d/zeek.gpg; \
      for i in 1 2 3 4 5; do apt-get update && break || sleep 5; done; \
      apt-get install -y --no-install-recommends zeek ) \
      || echo "[build] zeek install failed — Zeek analysis will be disabled"; \
    rm -rf /var/lib/apt/lists/*
ENV PATH="/opt/zeek/bin:${PATH}"

# IP→ASN + country datasets (sapics/ip-location-db, CC0/PDDL public-domain,
# served over the jsdelivr CDN) for offline GeoIP/ASN enrichment of external
# endpoints. Best-effort at build; if it fails the feature simply reports no geo.
RUN set -eux; mkdir -p /data; \
    ( curl -fsSL "https://cdn.jsdelivr.net/npm/@ip-location-db/asn/asn-ipv4.csv" -o /data/asn-ipv4.csv \
        && curl -fsSL "https://cdn.jsdelivr.net/npm/@ip-location-db/geo-whois-asn-country/geo-whois-asn-country-ipv4.csv" -o /data/country-ipv4.csv ) \
      || echo "[build] geoip dataset download failed — GeoIP/ASN will be disabled"; \
    wc -l /data/asn-ipv4.csv /data/country-ipv4.csv 2>/dev/null || true
ENV GEOIP_ASN=/data/asn-ipv4.csv
ENV GEOIP_COUNTRY=/data/country-ipv4.csv

# Bundled YARA ruleset (same curated set the malware emulator uses) — scanned
# against files reconstructed from the capture so malware transferred over the
# wire is flagged directly.
COPY tools/malware-yara/ /rules/

# Pull the ET-Open ruleset at build so C2/malware signatures ship in the image.
# Best-effort: if the download fails (offline build), Suricata still runs and the
# flow/DNS/TLS analysis works — only signature alerts are reduced.
RUN set -eux; \
    ( suricata-update --no-test --no-reload 2>&1 | tail -5 ) \
      || echo "[build] suricata-update failed — ET rules will be limited"; \
    ls -la /var/lib/suricata/rules/ 2>/dev/null || true

# Enable JA3/JA3S TLS fingerprinting + file metadata hashing in the default config
# (a small, targeted edit; the rest of the distro config is left intact).
RUN set -eux; \
    sed -i 's/^\(\s*\)ja3-fingerprints:.*/\1ja3-fingerprints: yes/' /etc/suricata/suricata.yaml || true; \
    grep -q 'ja3-fingerprints' /etc/suricata/suricata.yaml || true

# Enable the file-store output so transferred files are reconstructed to disk.
# It lives inside the `outputs:` list (not a top-level key), so a --set flag can't
# reach it — patch the yaml block directly: flip enabled:no→yes and force storing
# of ALL files (no rule needed).
RUN python3 - <<'PY'
import re
p = "/etc/suricata/suricata.yaml"
s = open(p).read()
s2 = re.sub(r"(- file-store:\s*\n\s*version:\s*2\s*\n\s*enabled:\s*)no",
            r"\1yes\n      dir: filestore\n      force-filestore: yes", s, count=1)
open(p, "w").write(s2)
print("file-store patched:", s2 != s)
PY

WORKDIR /app
COPY net-analyzer/app.py .

EXPOSE 8092
ENV SURICATA_RULES=/var/lib/suricata/rules/suricata.rules
ENV YARA_RULES=/rules/analysishub_malware.yar
ENV NET_ANALYZE_TIMEOUT=600
CMD ["python3", "app.py"]
