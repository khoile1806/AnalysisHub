FROM ubuntu:20.04

ENV DEBIAN_FRONTEND=noninteractive

# Install Python 2, Python 3, and build dependencies
RUN apt-get update && apt-get install -y \
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
    pip3 install .

# Setup quick aliases using wrapper scripts
RUN echo '#!/bin/bash\npython2 /opt/volatility/vol.py "$@"' > /usr/local/bin/vol2 && \
    chmod +x /usr/local/bin/vol2 && \
    echo '#!/bin/bash\npython3 /opt/volatility3/vol.py "$@"' > /usr/local/bin/vol3 && \
    chmod +x /usr/local/bin/vol3

# Set default workspace to the shared memory dumps folder
WORKDIR /app/storage/memory_dumps

EXPOSE 7681

# Run ttyd to provide a web terminal to the bash shell
CMD ["ttyd", "-p", "7681", "-W", "/bin/bash"]
