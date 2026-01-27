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
    golang-go \
    docker.io \
    && rm -rf /var/lib/apt/lists/*

# Install Nuclei
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
ENV PATH="/root/go/bin:${PATH}"

# Verify Nuclei installation
RUN nuclei -version

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
