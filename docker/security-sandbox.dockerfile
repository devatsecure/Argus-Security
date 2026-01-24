# Argus Security Sandbox
# Isolated environment for safe exploit validation

FROM ubuntu:22.04

LABEL description="Argus Security Sandbox for Safe Exploit Validation"
LABEL maintainer="Argus Security"

# Prevent interactive prompts during installation
ENV DEBIAN_FRONTEND=noninteractive

# Update and install base packages
RUN apt-get update && \
    apt-get install -y \
    wget curl git vim nano \
    build-essential \
    software-properties-common \
    ca-certificates \
    gnupg \
    lsb-release \
    sudo && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Create sandbox user
RUN useradd -m -s /bin/bash sandbox && \
    usermod -aG sudo sandbox && \
    echo "sandbox ALL=(ALL) NOPASSWD:ALL" >> /etc/sudoers

# Create workspace directory
RUN mkdir -p /workspace /app && \
    chown -R sandbox:sandbox /workspace /app

# Install Python and dependencies
RUN apt-get update && \
    apt-get install -y \
    python3 \
    python3-pip \
    python3-dev \
    python3-venv \
    python3-setuptools && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Node.js (LTS)
RUN curl -fsSL https://deb.nodesource.com/setup_20.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Java (OpenJDK)
RUN apt-get update && \
    apt-get install -y openjdk-17-jdk openjdk-17-jre && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Install Go
RUN wget -q https://go.dev/dl/go1.21.5.linux-amd64.tar.gz && \
    tar -C /usr/local -xzf go1.21.5.linux-amd64.tar.gz && \
    rm go1.21.5.linux-amd64.tar.gz

# Install useful tools for exploit validation
RUN apt-get update && \
    apt-get install -y \
    netcat-traditional \
    net-tools \
    dnsutils \
    curl \
    wget \
    jq \
    sqlite3 \
    postgresql-client \
    mysql-client \
    redis-tools \
    strace \
    ltrace \
    gdb \
    nmap \
    tcpdump && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set environment variables
ENV PATH="/usr/local/go/bin:/home/sandbox/.local/bin:$PATH"
ENV PYTHONUNBUFFERED=1
ENV SANDBOX_MODE=true

# Switch to sandbox user
USER sandbox
WORKDIR /workspace

# Install Python packages for common exploit testing
RUN pip3 install --user --no-cache-dir \
    requests \
    pycryptodome \
    paramiko \
    scapy \
    beautifulsoup4 \
    lxml \
    pillow \
    pyyaml \
    pytest \
    pytest-timeout

# Install Node.js packages for common exploit testing
RUN npm install -g \
    axios \
    cheerio \
    express \
    commander

# Create Python virtual environment for isolated testing
RUN python3 -m venv /home/sandbox/venv && \
    /home/sandbox/venv/bin/pip install --upgrade pip

# Setup bashrc
RUN echo 'export PS1="\[\033[01;32m\]sandbox\[\033[00m\]:\[\033[01;34m\]\w\[\033[00m\]\$ "' >> /home/sandbox/.bashrc && \
    echo 'export PATH="/usr/local/go/bin:/home/sandbox/.local/bin:$PATH"' >> /home/sandbox/.bashrc && \
    echo 'echo "Argus Security Sandbox - Safe Exploit Validation Environment"' >> /home/sandbox/.bashrc

# Set working directory
WORKDIR /workspace

# Default command
CMD ["/bin/bash"]
