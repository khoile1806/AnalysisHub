FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive

# Install Python 2, Python 3, and build dependencies
RUN apt-get update && apt-get install -y \
    kali-linux-core \
    kali-tools-top10 \
    net-tools \
    iputils-ping \
    nmap \
    sqlmap \
    proxychains4 \
    python2 \
    python2-dev \
    python3 \
    python3-pip \
    python3-dev \
    curl \
    git \
    wget \
    unzip \
    build-essential \
    libssl-dev \
    libffi-dev \
    libsnappy-dev \
    libcrypt-dev \
    && rm -rf /var/lib/apt/lists/*

# Download and install ttyd statically compiled binary
RUN curl -L https://github.com/tsl0922/ttyd/releases/download/1.7.7/ttyd.x86_64 -o /usr/local/bin/ttyd && \
    chmod +x /usr/local/bin/ttyd

# Install pip for Python 2
RUN curl https://bootstrap.pypa.io/pip/2.7/get-pip.py --output get-pip.py && \
    python2 get-pip.py && \
    rm get-pip.py

# Install dependencies for Volatility 2
RUN pip2 install distorm3 pycrypto pillow openpyxl ujson

# Install Volatility 2
WORKDIR /opt
RUN git clone https://github.com/volatilityfoundation/volatility.git && \
    cd volatility && \
    python2 setup.py install

# Install Volatility 3
RUN git clone https://github.com/volatilityfoundation/volatility3.git && \
    cd volatility3 && \
    pip3 install --break-system-packages .

# Setup quick aliases using wrapper scripts
RUN echo '#!/bin/bash\npython2 /opt/volatility/vol.py "$@"' > /usr/local/bin/vol2 && \
    chmod +x /usr/local/bin/vol2 && \
    echo '#!/bin/bash\npython3 /opt/volatility3/vol.py "$@"' > /usr/local/bin/vol3 && \
    chmod +x /usr/local/bin/vol3

# --- Anonymized egress for the offensive toolbox -----------------------------
# This sandbox doubles as a pentest console (nmap, sqlmap, curl, …). Route that
# tooling through the integrated Tor SOCKS proxy (the `tor` compose service) so
# scans never leak the host's real IP. proxychains forces TCP through Tor and,
# with proxy_dns, resolves names over Tor too (no DNS leak). The proxy address
# is the compose service name `tor:9050`, resolved by Docker's internal DNS.
RUN printf '%s\n' \
    'strict_chain' \
    'proxy_dns' \
    'remote_dns_subnet 224' \
    'tcp_read_time_out 15000' \
    'tcp_connect_time_out 8000' \
    '[ProxyList]' \
    'socks5 tor 9050' \
    > /etc/proxychains4.conf

# Tool wrappers + env. Only ttyd's interactive bash sources ~/.bashrc, so the
# proxy env here never reaches build-time apt. curl/wget/git honour *_PROXY
# automatically (socks5h = remote DNS); nmap/sqlmap go through proxychains.
# NOTE: SOCKS carries TCP connect() only — use connect scans (`nmap -sT -Pn`),
# not SYN/raw scans, when tunnelling through Tor.
RUN printf '%s\n' \
    'export ALL_PROXY=socks5h://tor:9050' \
    'export HTTP_PROXY=socks5h://tor:9050  HTTPS_PROXY=socks5h://tor:9050' \
    'export http_proxy=socks5h://tor:9050  https_proxy=socks5h://tor:9050' \
    'alias pc="proxychains4 -q"' \
    'alias tnmap="proxychains4 -q nmap -sT -Pn"' \
    'alias tsqlmap="proxychains4 -q sqlmap"' \
    'echo "[sandbox] Tool egress is routed through Tor (tor:9050)."' \
    'echo "[sandbox] Anonymized scan: pc nmap -sT -Pn <target>  |  tnmap <target>"' \
    'echo "[sandbox] curl/wget/git already use the proxy via *_PROXY."' \
    >> /root/.bashrc

# Set default workspace to the shared memory dumps folder
WORKDIR /app/storage/memory_dumps

EXPOSE 7681

# Serve the web terminal under the SAME base path the backend reverse-proxies to
# (/api/v1/sandbox/terminal), so ttyd's assets + WebSocket resolve correctly
# behind the proxy. The container is NOT published on the host; access is gated
# by the backend's admin JWT.
CMD ["ttyd", "-p", "7681", "-b", "/api/v1/sandbox/terminal", "-W", "/bin/bash"]
