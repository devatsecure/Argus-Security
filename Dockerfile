# Argus Security - Production Container
# Optimized for fast builds and minimal size

FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="Argus Security"
LABEL org.opencontainers.image.description="Enterprise-grade AI Security Platform with multi-agent analysis"
LABEL org.opencontainers.image.vendor="Argus Security"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/devatsecure/Argus-Security"

# Install uv for fast dependency resolution (10x faster than pip)
COPY --from=ghcr.io/astral-sh/uv:0.5.11@sha256:7e479fa39802632c25b4e5c14ddfab9c5f443cd7c89626a0408d31a0b7afc193 /uv /bin/uv

# Set environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_LINK_MODE=copy \
    UV_COMPILE_BYTECODE=1 \
    PYTHONPATH=/app \
    PATH="/app/.venv/bin:$PATH"

# Install system dependencies and security tools
RUN apt-get update && apt-get install -y --no-install-recommends \
    git \
    curl \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Install Gitleaks (secret scanner) — pinned with SHA256 verification
RUN GITLEAKS_VERSION="8.18.4" && \
    GITLEAKS_SHA256="ba6dbb656933921c775ee5a2d1c13a91046e7952e9d919f9bac4cec61d628e7d" && \
    curl -sSfL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        -o /tmp/gitleaks.tar.gz && \
    echo "${GITLEAKS_SHA256}  /tmp/gitleaks.tar.gz" | sha256sum --check && \
    tar xz -C /usr/local/bin gitleaks -f /tmp/gitleaks.tar.gz && \
    rm /tmp/gitleaks.tar.gz && \
    chmod +x /usr/local/bin/gitleaks

# Create non-root user for security
RUN groupadd -r agentuser && useradd -r -g agentuser -u 1000 agentuser

# Create app directory
WORKDIR /app

# Copy dependency files first (better caching)
COPY requirements.txt pyproject.toml setup.py ./

# Install Python dependencies using uv (much faster than pip)
RUN uv pip install --system --no-cache -r requirements.txt && \
    uv pip install --system --no-cache semgrep

# Copy application code
COPY scripts/ ./scripts/
COPY policy/ ./policy/
COPY profiles/ ./profiles/
COPY schemas/ ./schemas/

# Create necessary directories with proper permissions for non-root user
RUN mkdir -p /workspace /output && \
    chmod 755 /workspace /output && \
    chown -R agentuser:agentuser /app /workspace /output

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import scripts.run_ai_audit; print('healthy')" || exit 1

# Set working directory for analysis
WORKDIR /workspace

# Switch to non-root user
USER agentuser

# Default entrypoint
ENTRYPOINT ["python", "-m", "scripts.run_ai_audit"]

# Default command shows help
CMD ["--help"]
