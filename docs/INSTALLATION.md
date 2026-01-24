# Argus Security Action - Installation Guide

**Version:** 1.1.0
**Updated:** 2026-01-15

This guide covers complete installation and setup of Argus Security Action, including all dependencies, external tools, and configuration.

## Table of Contents

- [Quick Start](#quick-start)
- [System Requirements](#system-requirements)
- [Installation Methods](#installation-methods)
  - [Automated Installation (Recommended)](#automated-installation-recommended)
  - [Manual Installation](#manual-installation)
  - [Docker Installation](#docker-installation)
- [Python Dependencies](#python-dependencies)
- [External Security Tools](#external-security-tools)
- [API Keys & Configuration](#api-keys--configuration)
- [Verification](#verification)
- [Troubleshooting](#troubleshooting)
- [Platform-Specific Notes](#platform-specific-notes)

---

## Quick Start

The fastest way to get started:

```bash
# Clone repository
git clone https://github.com/devatsecure/Argus-Security.git
cd argus-action

# Run automated installer (macOS/Linux)
./scripts/install_dependencies.sh

# Verify installation
python scripts/health_check.py

# Set API key (choose one)
export ANTHROPIC_API_KEY="your-key-here"
export OPENAI_API_KEY="your-key-here"

# Run your first audit
python scripts/run_ai_audit.py --project-type backend-api
```

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| **OS** | macOS 12+, Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS 8+ |
| **Python** | 3.9 or higher (3.11 recommended) |
| **Memory** | 4GB RAM (8GB recommended) |
| **Disk Space** | 10GB free (20GB recommended) |
| **CPU** | 2+ cores |
| **Network** | Internet access for API calls and tool downloads |

### Supported Platforms

- **macOS**: 12 (Monterey), 13 (Ventura), 14 (Sonoma)
- **Linux**: Ubuntu 20.04+, Debian 11+, RHEL 8+, CentOS 8+
- **Windows**: 10, 11 (limited support - some tools not available)

### Network Requirements

The following domains must be accessible:

- `api.anthropic.com` - Claude AI API
- `api.openai.com` - OpenAI GPT API
- `github.com` - Source code and tool downloads
- `pypi.org` - Python package installation
- `aquasecurity.github.io` - Trivy scanner
- `download.falco.org` - Falco runtime security (optional)

---

## Installation Methods

### Automated Installation (Recommended)

The automated installer handles all dependencies for macOS and Linux:

```bash
# Full installation
./scripts/install_dependencies.sh

# Skip optional tools (nuclei, falco, opa)
./scripts/install_dependencies.sh --skip-optional

# Preview what would be installed
./scripts/install_dependencies.sh --dry-run

# Skip Python packages (install tools only)
./scripts/install_dependencies.sh --skip-python
```

**What it installs:**
- All Python dependencies (production + development)
- Core security scanners (semgrep, trivy, trufflehog, gitleaks, checkov)
- Docker (if not already installed)
- Optional tools (nuclei, falco, opa) unless skipped

### Manual Installation

If you prefer manual control or the automated installer doesn't work:

#### Step 1: Install Python Dependencies

```bash
# Install production dependencies
pip install -r requirements.txt

# Install development dependencies (optional)
pip install -r requirements-dev.txt
```

#### Step 2: Install External Tools

See [External Security Tools](#external-security-tools) section for detailed instructions.

### Docker Installation

Run Argus in a container with all dependencies pre-installed:

```bash
# Build Docker image
docker build -t argus:latest .

# Run container
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY="your-key" \
  argus:latest \
  --project-type backend-api
```

**Using GitHub Actions:**

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    fail-on-blockers: true
```

---

## Python Dependencies

### Production Dependencies

All production dependencies are defined in `requirements.txt`:

| Package | Version | Purpose |
|---------|---------|---------|
| `anthropic` | >=0.40.0 | Claude AI integration |
| `openai` | >=1.56.0 | OpenAI GPT integration |
| `tenacity` | >=9.0.0 | Retry logic with exponential backoff |
| `semgrep` | >=1.100.0 | SAST scanning with 2,000+ rules |
| `pytm` | >=1.3.0 | Threat modeling (STRIDE analysis) |
| `psutil` | >=6.1.0 | System monitoring |
| `pyyaml` | >=6.0.2 | YAML parsing |
| `requests` | >=2.32.0 | HTTP requests |
| `urllib3` | >=2.0.0 | URL handling |
| `certifi` | >=2024.8.30 | Certificate validation |
| `cryptography` | >=44.0.0 | Cryptographic operations |
| `rich` | >=13.0.0 | Progress bars and terminal UI |
| `packaging` | >=24.0 | Version comparison |

### Development Dependencies

Development dependencies are in `requirements-dev.txt`:

| Package | Version | Purpose |
|---------|---------|---------|
| `pytest` | >=7.0.0 | Testing framework |
| `pytest-cov` | >=4.0.0 | Coverage reporting |
| `pytest-mock` | >=3.10.0 | Mocking support |
| `ruff` | >=0.8.0 | Fast linter/formatter |
| `mypy` | >=1.0.0 | Static type checking |
| `bandit` | >=1.7.0 | Security issue scanner |
| `sphinx` | >=7.0.0 | Documentation generator |
| `ipython` | >=8.12.0 | Interactive shell |
| `pre-commit` | >=3.5.0 | Git hooks |

### Installation

```bash
# Production only
pip install -r requirements.txt

# Production + Development
pip install -r requirements-dev.txt
```

---

## External Security Tools

### Core Scanners (Required)

#### Semgrep - SAST Scanner

Fast static analysis with 2,000+ security rules.

**Installation:**

```bash
# macOS
brew install semgrep

# Linux/Windows
pip install semgrep>=1.100.0
```

**Verification:**
```bash
semgrep --version
# Should output: 1.100.0 or higher
```

#### Trivy - Vulnerability Scanner

CVE and dependency vulnerability scanner.

**Installation:**

```bash
# macOS
brew install trivy

# Ubuntu/Debian
wget -qO - https://aquasecurity.github.io/trivy-repo/deb/public.key | sudo apt-key add -
echo "deb https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" | sudo tee -a /etc/apt/sources.list.d/trivy.list
sudo apt-get update
sudo apt-get install trivy

# RHEL/CentOS
wget https://github.com/aquasecurity/trivy/releases/latest/download/trivy_0.48.0_Linux-64bit.tar.gz
tar -xzf trivy_0.48.0_Linux-64bit.tar.gz
sudo mv trivy /usr/local/bin/
```

**Verification:**
```bash
trivy --version
# Should output: 0.48.0 or higher
```

#### TruffleHog - Secret Detection

Verified secret detection with high accuracy.

**Installation:**

```bash
# macOS
brew install trufflehog

# Linux
curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sudo sh -s -- -b /usr/local/bin

# Windows
choco install trufflehog
```

**Verification:**
```bash
trufflehog --version
# Should output: 3.60.0 or higher
```

#### Gitleaks - Secret Scanning

Pattern-based secret scanning.

**Installation:**

```bash
# macOS
brew install gitleaks

# Linux
wget https://github.com/gitleaks/gitleaks/releases/download/v8.18.0/gitleaks_8.18.0_linux_x64.tar.gz
tar -xzf gitleaks_8.18.0_linux_x64.tar.gz
sudo mv gitleaks /usr/local/bin/

# Windows
choco install gitleaks
```

**Verification:**
```bash
gitleaks version
# Should output: 8.18.0 or higher
```

#### Checkov - IaC Scanner

Infrastructure-as-Code security scanning (Terraform, K8s, Docker, etc.).

**Installation:**

```bash
# macOS
brew install checkov

# Linux/Windows
pip install checkov>=3.1.0
```

**Verification:**
```bash
checkov --version
# Should output: 3.1.0 or higher
```

#### Docker - Container Runtime

Required for sandbox validation.

**Installation:**

```bash
# macOS
brew install --cask docker

# Linux
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER

# Windows
choco install docker-desktop
```

**Verification:**
```bash
docker --version
# Should output: 20.10.0 or higher

docker ps
# Should list running containers
```

### Optional Tools

#### Nuclei - DAST Scanner

Dynamic application security testing with 4,000+ templates.

**Installation:**

```bash
# macOS
brew install nuclei

# Linux
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_3.6.0_linux_amd64.zip
unzip nuclei_3.6.0_linux_amd64.zip
sudo mv nuclei /usr/local/bin/

# Windows
choco install nuclei
```

**Verification:**
```bash
nuclei -version
# Should output: 3.6.0 or higher
```

#### Falco - Runtime Security

Container runtime security monitoring.

**Installation:**

```bash
# macOS
brew install falco
# Note: Limited support on macOS

# Ubuntu/Debian
curl -s https://falco.org/repo/falcosecurity-3672BA8F.asc | apt-key add -
echo "deb https://download.falco.org/packages/deb stable main" | tee -a /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y
apt-get install -y falco

# RHEL/CentOS
# Manual installation required. See: https://falco.org/docs/
```

**Verification:**
```bash
falco --version
# Should output: 0.37.0 or higher
```

#### OPA - Policy Agent

Open Policy Agent for policy enforcement.

**Installation:**

```bash
# macOS
brew install opa

# Linux
curl -L -o opa https://openpolicyagent.org/downloads/latest/opa_linux_amd64
chmod 755 ./opa
sudo mv opa /usr/local/bin/

# Windows
choco install opa
```

**Verification:**
```bash
opa version
# Should output: 0.60.0 or higher
```

---

## API Keys & Configuration

### Required API Keys

Argus requires at least one AI provider API key:

#### Anthropic Claude (Recommended)

1. Visit: https://console.anthropic.com/
2. Create an account or sign in
3. Navigate to API Keys
4. Create a new key
5. Set environment variable:

```bash
export ANTHROPIC_API_KEY="sk-ant-..."
```

**Or add to `~/.bashrc` / `~/.zshrc`:**

```bash
echo 'export ANTHROPIC_API_KEY="sk-ant-..."' >> ~/.bashrc
source ~/.bashrc
```

#### OpenAI GPT (Alternative)

1. Visit: https://platform.openai.com/api-keys
2. Create an account or sign in
3. Create a new API key
4. Set environment variable:

```bash
export OPENAI_API_KEY="sk-..."
```

#### Ollama (Local, Free)

For cost-free local development:

1. Install Ollama: https://ollama.ai/
2. Pull a model: `ollama pull llama2`
3. Use with `--ai-provider ollama`

### Optional Environment Variables

```bash
# GitHub token for SARIF upload
export GITHUB_TOKEN="ghp_..."

# Custom configuration paths
export ARGUS_CONFIG="/path/to/config.yml"
export ARGUS_POLICY="/path/to/policy.rego"
```

### Configuration Files

Create `.argus-config.yml` in your project root:

```yaml
# Argus Configuration
version: "1.1.0"

# AI Provider settings
ai_provider: "anthropic"  # anthropic, openai, ollama
model: "claude-3-5-sonnet-20241022"

# Scanner configuration
scanners:
  semgrep:
    enabled: true
    rules: ["auto"]
  trivy:
    enabled: true
    severity: ["HIGH", "CRITICAL"]
  trufflehog:
    enabled: true
    verified_only: true
  gitleaks:
    enabled: true
  checkov:
    enabled: true
    frameworks: ["terraform", "kubernetes", "dockerfile"]

# Policy enforcement
policy:
  fail_on_blockers: true
  max_critical: 0
  max_high: 5

# Reporting
output:
  formats: ["sarif", "json", "markdown"]
  destination: "./security-reports"
```

---

## Verification

### Health Check

Run the comprehensive health check to verify all dependencies:

```bash
python scripts/health_check.py
```

**Expected output:**

```
================================================================================
Argus Security Action - Health Check
================================================================================

Platform:       Darwin 25.2.0
Python:         3.11.7
Config:         external-tools.yml

================================================================================

[1/5] Checking Python dependencies...
  ✓ Python Dependencies: All 13 Python packages installed

[2/5] Checking external security tools...
  ✓ Tool: semgrep: semgrep 1.100.0 installed (>=1.100.0)
  ✓ Tool: trivy: trivy 0.48.0 installed (>=0.48.0)
  ✓ Tool: trufflehog: trufflehog 3.60.0 installed (>=3.60.0)
  ✓ Tool: gitleaks: gitleaks 8.18.0 installed (>=8.18.0)
  ✓ Tool: checkov: checkov 3.1.0 installed (>=3.1.0)
  ✓ Tool: docker: docker 20.10.0 installed (>=20.10.0)

[3/5] Checking API keys and environment variables...
  ✓ API Key: ANTHROPIC_API_KEY is set (sk-ant-...)

[4/5] Checking Docker...
  ✓ Docker: Docker 20.10.0 running (0 containers)

[5/5] Checking system requirements...
  ✓ System: Memory: 16.0GB RAM available (>= 4GB required)
  ✓ System: Disk Space: 100.5GB free (>= 10GB required)
  ✓ System: CPU: 8 CPU cores (>= 2 required)

================================================================================
SUMMARY
================================================================================
Total Checks:   20
Passed:         20
Failed:         0
Warnings:       0
Skipped:        0

Overall Status: PASSED
================================================================================

✅ Health check PASSED - all dependencies met
```

### Manual Verification

Test each component individually:

```bash
# Python
python --version
# Should be 3.9+

# Pip packages
pip list | grep anthropic
pip list | grep semgrep

# External tools
semgrep --version
trivy --version
trufflehog --version
gitleaks version
checkov --version
docker --version
docker ps

# API keys
echo $ANTHROPIC_API_KEY | head -c 20
# Should show first 20 chars of key
```

### Test Run

Try a simple audit on a test project:

```bash
# Create test directory
mkdir test-project
cd test-project

# Create test file with intentional issue
cat > test.py << 'EOF'
import os
# Hardcoded secret (test)
API_KEY = "sk-test-12345"
password = "admin123"
EOF

# Run audit
python ../scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file results.json

# Check results
cat results.json
```

---

## Troubleshooting

### Common Issues

#### Issue: "pip: command not found"

**Solution:**
```bash
# Install pip
python -m ensurepip --upgrade

# Or install Python with pip included
# macOS: brew install python@3.11
# Linux: sudo apt-get install python3-pip
```

#### Issue: "Docker daemon not running"

**Solution:**
```bash
# macOS: Start Docker Desktop from Applications

# Linux: Start Docker service
sudo systemctl start docker
sudo systemctl enable docker

# Verify
docker ps
```

#### Issue: "Permission denied" when running Docker

**Solution:**
```bash
# Add user to docker group (Linux)
sudo usermod -aG docker $USER

# Log out and back in, then verify
docker ps
```

#### Issue: "ANTHROPIC_API_KEY not set"

**Solution:**
```bash
# Set temporarily
export ANTHROPIC_API_KEY="your-key"

# Set permanently (add to ~/.bashrc or ~/.zshrc)
echo 'export ANTHROPIC_API_KEY="your-key"' >> ~/.bashrc
source ~/.bashrc
```

#### Issue: Tool version too old

**Solution:**
```bash
# Update Homebrew packages (macOS)
brew update
brew upgrade semgrep trivy trufflehog gitleaks checkov

# Update pip packages
pip install --upgrade semgrep checkov

# Re-run health check
python scripts/health_check.py
```

#### Issue: "ImportError: No module named 'anthropic'"

**Solution:**
```bash
# Reinstall Python dependencies
pip install -r requirements.txt

# Verify installation
pip list | grep anthropic
```

### Debug Mode

Enable verbose logging for troubleshooting:

```bash
# Run with debug flag
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --debug \
  --output-file results.json 2>&1 | tee debug.log
```

### Get Help

- **Documentation**: https://github.com/devatsecure/Argus-Security/tree/main/docs
- **Issues**: https://github.com/devatsecure/Argus-Security/issues
- **Discussions**: https://github.com/devatsecure/Argus-Security/discussions

---

## Platform-Specific Notes

### macOS

- Homebrew is strongly recommended for tool installation
- Docker Desktop requires manual start after installation
- Some tools (Falco) have limited macOS support

### Linux

- Ubuntu/Debian have the best tool support
- RHEL/CentOS require additional repositories
- Docker requires group membership (`docker` group)
- Falco requires kernel headers for eBPF

### Windows

- WSL2 (Windows Subsystem for Linux) recommended
- Some tools not available natively on Windows:
  - Falco (not supported)
  - TruffleHog (limited support)
- Docker Desktop requires WSL2 backend
- Use PowerShell or Git Bash for best compatibility

---

## Next Steps

After installation:

1. **Configure API Keys**: Set `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`
2. **Run Health Check**: `python scripts/health_check.py`
3. **Test Installation**: Run audit on sample project
4. **Review Documentation**:
   - [README.md](../README.md) - Overview and usage
   - [ARCHITECTURE.md](architecture/overview.md) - System architecture
   - [SCANNER_REFERENCE.md](references/scanner-reference.md) - Scanner details
5. **Set Up CI/CD**: Integrate with GitHub Actions (see [action.yml](../action.yml))

---

## Updates

To update Argus and all dependencies:

```bash
# Pull latest code
git pull origin main

# Update Python dependencies
pip install --upgrade -r requirements.txt
pip install --upgrade -r requirements-dev.txt

# Update external tools (macOS)
brew update && brew upgrade

# Update external tools (Linux)
./scripts/install_dependencies.sh

# Verify updates
python scripts/health_check.py
```

---

**Questions or issues?** Open an issue on [GitHub](https://github.com/devatsecure/Argus-Security/issues).
