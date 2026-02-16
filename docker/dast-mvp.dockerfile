# Dockerfile for DAST Phase 1 MVP
# Includes Nuclei, ZAP, and all dependencies for multi-agent scanning

FROM python:3.11-slim

LABEL maintainer="Argus Security <security@argus.io>"
LABEL description="DAST Phase 1 MVP - Multi-Agent Security Scanner"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    git \
    curl \
    wget \
    unzip \
    ca-certificates \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei — pinned with SHA256 verification
RUN NUCLEI_VERSION="3.1.0" && \
    NUCLEI_SHA256="0a8b27f6302e41b9daf9ebc7892f0c8fe6a893987d1fcb5313879dbc3e145d3c" && \
    curl -sSfL "https://github.com/projectdiscovery/nuclei/releases/download/v${NUCLEI_VERSION}/nuclei_${NUCLEI_VERSION}_linux_amd64.zip" \
        -o /tmp/nuclei.zip && \
    echo "${NUCLEI_SHA256}  /tmp/nuclei.zip" | sha256sum --check && \
    unzip /tmp/nuclei.zip -d /usr/local/bin && \
    rm /tmp/nuclei.zip && \
    chmod +x /usr/local/bin/nuclei

# Verify Nuclei installation
RUN nuclei -version

# Install Gitleaks (secret scanner) — pinned with SHA256 verification
RUN GITLEAKS_VERSION="8.18.4" && \
    GITLEAKS_SHA256="ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d" && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tar.gz && \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum --check && \
    tar xz -C /usr/local/bin gitleaks -f /tmp/gitleaks.tar.gz && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Install ZAP (will use Docker-in-Docker)
# ZAP will be pulled at runtime via Docker

# Set working directory
WORKDIR /app

# Copy requirements
COPY requirements.txt requirements-dev.txt ./

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt
RUN pip install --no-cache-dir -r requirements-dev.txt

# Copy application code
COPY scripts/ ./scripts/
COPY config/ ./config/
COPY examples/ ./examples/
COPY docs/ ./docs/

# Create output directory
RUN mkdir -p /output

# Set environment variables
ENV PYTHONPATH="/app"
ENV PYTHONUNBUFFERED=1

# Create non-root user for security
RUN groupadd -r dastuser && useradd -r -g dastuser -u 1000 -m dastuser && \
    chown -R dastuser:dastuser /app /output

USER dastuser

# Default command
ENTRYPOINT ["python", "/app/scripts/dast_orchestrator.py"]
CMD ["--help"]

# Example usage:
# docker build -f docker/dast-mvp.dockerfile -t argus-dast:mvp .
# docker run --rm -v /var/run/docker.sock:/var/run/docker.sock \
#     -v $(pwd)/dast-results:/output \
#     argus-dast:mvp \
#     https://example.com \
#     --agents nuclei,zap \
#     --profile balanced \
#     --output /output
