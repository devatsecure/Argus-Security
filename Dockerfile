# Argus Security - Production Container
# Optimized for fast builds and minimal size

FROM python:3.11-slim-bookworm

LABEL org.opencontainers.image.title="Argus Security"
LABEL org.opencontainers.image.description="Enterprise-grade AI Security Platform with multi-agent analysis"
LABEL org.opencontainers.image.vendor="Argus Security"
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.source="https://github.com/devatsecure/Argus-Security"

# Install uv for fast dependency resolution (10x faster than pip)
COPY --from=ghcr.io/astral-sh/uv:0.5.11 /uv /bin/uv

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
