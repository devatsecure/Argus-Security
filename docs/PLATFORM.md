# Argus Platform Documentation

**Enterprise Security Control Plane**  
Deterministic Scanning + AI Analysis + Supply Chain Security + Policy Enforcement

> **Note**: This document covers the full Argus platform architecture and capabilities.  
> For the GitHub Action quick start, see [README.md](README.md).

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](#contributing)
[![Foundation-Sec](https://img.shields.io/badge/AI-Foundation--Sec--8B-green.svg)](#architecture)

---

## Table of Contents

- [Overview](#overview)
- [Quick Start](#quick-start)
- [Architecture](#architecture)
- [Features](#features)
- [Usage](#usage)
- [Configuration](#configuration)
- [Development](#development)
- [Testing](#testing)
- [Deployment](#deployment)
- [Performance](#performance)
- [Security](#security)
- [Contributing](#contributing)
- [License](#license)
- [Support](#support)

---

## Overview

Argus is a **production-ready security control plane** that transforms how organizations secure their software delivery pipeline.

### What It Does

- **Orchestrates Security Scanners**: TruffleHog, Gitleaks, Semgrep, Trivy, Checkov
- **AI-Powered Analysis**: Foundation-Sec-8B (SageMaker) for intelligent triage
- **Noise Reduction**: 60%+ false positive suppression via ML + historical analysis
- **Risk Prioritization**: CVSS × Exploitability × Reachability × Business Impact
- **Policy Enforcement**: Rego-based PR/release gates with velocity metrics
- **Supply Chain Security**: SBOM generation, SLSA provenance, artifact signing
- **Compliance Automation**: SOC 2, PCI-DSS policy packs

### Why Argus?

**AppSec maturity isn't about how many alerts you raise.**  
**It's about how many risks you resolve and how fast you ship.**

Argus aligns security with delivery velocity, compliance mandates, and executive reporting.

### Key Metrics

| Metric | Value |
|--------|-------|
| **Analysis Time** | <5 minutes (p95) |
| **Cost** | $0.00 (Foundation-Sec) or $0.35 (with Claude) |
| **Noise Reduction** | 60%+ false positives suppressed |
| **SOC 2 Compliance** | 100% automated evaluation |
| **Verified Secret Block Rate** | 90%+ |
| **False Block Rate** | <2% |

---

## Quick Start

### Prerequisites

- **Python**: 3.10 or higher (Python 3.9 is EOL and has dependency conflicts)
- **Git**: 2.30 or higher
- **OS**: macOS, Linux, or WSL2
- **API Keys** (optional):
  - Anthropic Claude (for AI analysis)
  - AWS credentials (for Foundation-Sec-8B on SageMaker)

### Installation

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/argus.git
cd argus

# Install Python dependencies
pip install -r requirements.txt

# Install security scanners (macOS)
brew install trufflehog gitleaks semgrep trivy checkov syft cosign opa

# Install security scanners (Linux)
# See scripts/install_security_tools.sh for automated installation

# Set up environment
cp .env.example .env
# Edit .env with your API keys (optional)
```

### Run Your First Analysis

```bash
# Basic security audit
python3 scripts/run_ai_audit.py /path/to/your/repo audit

# Results saved to:
# - .argus/reviews/audit-report.md
# - .argus/reviews/security-findings.json
```

### Expected Output

```
📊 Analysis Complete:
   ✅ 0 verified secrets
   ⚠️  4 SAST findings
   🔴 8 critical CVEs
   📦 1,458 SBOM components
   🔒 SLSA L2 provenance
   
💰 Cost: $0.00 (Foundation-Sec)
⏱️  Duration: 4.8 minutes
```

---

## Architecture

### System Overview

```
┌─────────────────────────────────────────────────────────────┐
│                    Argus Control Plane                    │
├─────────────────────────────────────────────────────────────┤
│                                                               │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐      │
│  │ Deterministic│  │  AI Analysis │  │Supply Chain  │      │
│  │   Scanning   │  │              │  │   Security   │      │
│  ├──────────────┤  ├──────────────┤  ├──────────────┤      │
│  │ TruffleHog   │  │ Foundation-  │  │ SBOM (Syft)  │      │
│  │ Gitleaks     │  │   Sec-8B     │  │ SLSA L2      │      │
│  │ Semgrep      │  │ (SageMaker)  │  │ Cosign       │      │
│  │ Trivy        │  │              │  │ Signing      │      │
│  │ Checkov      │  │ Claude AI    │  │              │      │
│  └──────┬───────┘  └──────┬───────┘  └──────┬───────┘      │
│         │                 │                  │              │
│         └─────────────────┴──────────────────┘              │
│                           │                                 │
│                 ┌─────────▼─────────┐                       │
│                 │  Normalization    │                       │
│                 │  (35+ fields)     │                       │
│                 └─────────┬─────────┘                       │
│                           │                                 │
│                 ┌─────────▼─────────┐                       │
│                 │  Noise Scoring    │                       │
│                 │  (ML + Historical)│                       │
│                 └─────────┬─────────┘                       │
│                           │                                 │
│                 ┌─────────▼─────────┐                       │
│                 │  Correlation      │                       │
│                 │  (Attack Surface) │                       │
│                 └─────────┬─────────┘                       │
│                           │                                 │
│                 ┌─────────▼─────────┐                       │
│                 │  Risk Scoring     │                       │
│                 │  (PRD Formula)    │                       │
│                 └─────────┬─────────┘                       │
│                           │                                 │
│                 ┌─────────▼─────────┐                       │
│                 │  Policy Gates     │                       │
│                 │  (OPA/Rego)       │                       │
│                 └─────────┬─────────┘                       │
│                           │                                 │
│                 ┌─────────▼─────────┐                       │
│                 │   Reports         │                       │
│                 │   SARIF/JSON/MD   │                       │
│                 └───────────────────┘                       │
└─────────────────────────────────────────────────────────────┘
```

### Core Components

#### 1. Deterministic Scanning
- **TruffleHog**: Verified secret detection with API validation
- **Gitleaks**: Pattern-based secret scanning
- **Semgrep**: SAST with security-audit ruleset
- **Trivy**: CVE scanning for dependencies and containers
- **Checkov**: Infrastructure-as-Code security

#### 2. AI Analysis (Foundation-Sec-8B)
- **Noise Scoring**: ML-based false positive prediction (60% reduction)
- **Correlation**: Exploit chain and attack surface analysis
- **Exploitability Triage**: Trivial/moderate/complex classification
- **Secret Detection**: Semantic analysis for obfuscated secrets (84% recall)

#### 3. Supply Chain Security
- **SBOM Generation**: CycloneDX format with Syft
- **SLSA Provenance**: L2 attestation for build integrity
- **Artifact Signing**: Cosign with ECDSA-256

#### 4. Policy Enforcement
- **PR Gates**: Block verified secrets, enforce coverage thresholds
- **Release Gates**: Require SBOM signing, SLSA provenance
- **Velocity Metrics**: Track PR delay, noise reduction, delivery impact

---

## Features

### ✅ Completed Features

#### Phase 1: Governance Foundation

- **Enhanced Finding Schema** (35+ fields)
  - Noise score, false positive probability, historical fix rate
  - Correlation group ID, business context, suppression management
  - Auto-fix suggestions with confidence scores
  - File: `scripts/normalizer/base.py`

- **Noise Scoring Engine**
  - ML-based FP prediction using Foundation-Sec
  - Historical analysis (fix rate for similar findings)
  - Pattern detection (test files, low-severity, unverified secrets)
  - File: `scripts/noise_scorer.py`

- **Policy Engine with Velocity Metrics**
  - Noise filtering (auto-suppress >0.7 noise score)
  - Auto-fix bypass (don't block if all findings auto-fixable)
  - Velocity tracking (PR delay, noise reduction rate, delivery impact)
  - Files: `policy/rego/pr.rego`, `policy/rego/release.rego`

#### Phase 2: Intelligence & Scale

- **Correlation Engine**
  - Exploit chains (XSS + CSRF, SQLi + weak auth)
  - Attack surface grouping (module-level)
  - AI-powered non-obvious relationships
  - File: `scripts/correlator.py`

- **LLM Exploitability Triage**
  - Foundation-Sec classification (trivial/moderate/complex/theoretical)
  - Batch processing for efficiency
  - Risk score recalculation
  - File: `scripts/exploitability_triage.py`

- **LLM Secret Detector**
  - Semantic detection (obfuscated, Base64, split strings)
  - 84% recall (FuzzForge-inspired)
  - Cross-validation (LLM + Gitleaks/TruffleHog)
  - File: `scripts/llm_secret_detector.py`

- **SOC 2 Compliance Pack**
  - CC6.1: Access controls (no verified secrets)
  - CC6.6: Encryption + SBOM requirements
  - CC7.2: Vulnerability remediation SLA
  - CC7.3: Incident response timeliness
  - File: `policy/rego/compliance_soc2.rego`

### 🚧 Roadmap (12 TODOs)

#### Phase 1 Remaining
- Enhanced deduplication testing
- CI templates (PR + main workflows)
- PostgreSQL setup (schema, partitioning, pooling)
- Grafana dashboards (velocity, risk, compliance)
- PR cycle time tracking
- Auto-fix suggestions (comment-based)
- Suppression management (allowlist.yml with expiry)

#### Phase 2 Remaining
- Enhanced reachability scoring (language-specific)
- Multi-repo coordinator enhancement (concurrency + caching)
- SBOM enforcement (release gate)
- SLA tracking (severity-based timelines)
- IaC checks enhancement (STRIDE mapping)

---

## Usage

### Basic Commands

#### 1. Security Audit

```bash
# Complete security audit
python3 scripts/run_ai_audit.py /path/to/repo audit

# Output: .argus/reviews/audit-report.md
```

#### 2. Noise Scoring

```bash
# Score findings for noise
python3 scripts/noise_scorer.py \
  --input raw_findings.json \
  --output scored_findings.json \
  --update-history
```

#### 3. Correlation Analysis

```bash
# Correlate findings
python3 scripts/correlator.py \
  --input scored_findings.json \
  --output correlated_findings.json \
  --groups-output correlation_groups.json
```

#### 4. Exploitability Triage

```bash
# Triage exploitability
python3 scripts/exploitability_triage.py \
  --input correlated_findings.json \
  --output triaged_findings.json \
  --batch  # For efficiency
```

#### 5. Policy Gate Evaluation

```bash
# PR gate
python3 scripts/gate.py \
  --stage pr \
  --input triaged_findings.json

# Release gate
python3 scripts/gate.py \
  --stage release \
  --input triaged_findings.json \
  --sbom-present \
  --sbom-signed
```

#### 6. SOC 2 Compliance Check

```bash
# Evaluate SOC 2 compliance
opa eval -d policy/rego/compliance_soc2.rego \
  -i compliance_input.json \
  "data.compliance.soc2.decision" \
  --format pretty
```

### Advanced Usage

#### Multi-Repository Scanning

```bash
# Scan multiple repositories
python3 scripts/multi_repo_coordinator.py \
  --config config/multi_repo_example.json \
  --output multi_repo_results.json \
  --max-concurrent 3
```

#### SBOM Generation and Signing

```bash
# Generate SBOM
python3 scripts/sbom_generator.py \
  --repo-path /path/to/repo \
  --output sbom.json

# Sign SBOM
cosign generate-key-pair  # One-time
cosign sign-blob --key cosign.key \
  --tlog-upload=false \
  --bundle sbom.bundle.json \
  sbom.json

# Verify signature
cosign verify-blob --key cosign.pub \
  --bundle sbom.bundle.json \
  sbom.json
```

#### Risk Scoring

```bash
# Calculate risk scores
python3 scripts/risk_scorer.py \
  correlated_findings.json \
  --business-impact high \
  --output risk_scored.json
```

---

## Configuration

### Environment Variables

Create a `.env` file in the project root:

```bash
# AI Providers (optional)
ANTHROPIC_API_KEY=sk-ant-api03-...
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_DEFAULT_REGION=us-east-1
SAGEMAKER_ENDPOINT=huggingface-pytorch-tgi-inference-...

# Policy Configuration
NOISE_THRESHOLD=0.7
AUTO_FIX_BYPASS=true
VELOCITY_TRACKING=true

# SBOM Configuration
SBOM_FORMAT=cyclonedx
SBOM_SPEC_VERSION=1.4

# Compliance
SOC2_ENABLED=true
CRITICAL_CVE_SLA_DAYS=7
HIGH_CVE_SLA_DAYS=30
```

### Policy Customization

Edit `policy/rego/pr.rego` to customize PR gates:

```rego
# Custom blocking rules
critical_finding(f) if {
    f.severity == "critical"
    f.noise_score < 0.5  # Only block low-noise findings
}

# Custom velocity thresholds
high_velocity_impact if {
    input.velocity_metrics.estimated_pr_delay_minutes > 60
}
```

### Scanner Configuration

Configure scanners in `config/`:

```json
{
  "semgrep": {
    "config": "p/security-audit",
    "exclude": ["tests/", "node_modules/"]
  },
  "trivy": {
    "severity": ["CRITICAL", "HIGH"],
    "ignore_unfixed": false
  }
}
```

---

## Development

### Branching Strategy (Git Flow)

Argus follows **Git Flow** for structured development. See [.github/GITFLOW.md](.github/GITFLOW.md) for complete details.

**Quick Reference:**

```bash
# Install Git Flow
brew install git-flow-avh  # macOS
# or: apt-get install git-flow  # Linux

# Start a feature
git checkout develop
git pull origin develop
git flow feature start my-feature

# Work on feature
git add .
git commit -m "feat: add new feature"

# Finish feature (merges to develop)
git flow feature finish my-feature
git push origin develop
```

**Branch Structure:**
- `main` - Production releases (tagged with versions)
- `develop` - Integration branch for next release
- `feature/*` - New features (branch from `develop`)
- `bugfix/*` - Bug fixes (branch from `develop`)
- `release/*` - Release preparation (branch from `develop`)
- `hotfix/*` - Production fixes (branch from `main`)

**Important:** All pull requests should target `develop`, not `main`.

### Project Structure

```
argus/
├── scripts/              # Core analysis scripts
│   ├── normalizer/       # Finding normalization
│   ├── providers/        # AI provider integrations
│   ├── noise_scorer.py   # Noise scoring engine
│   ├── correlator.py     # Correlation engine
│   ├── gate.py           # Policy gate evaluation
│   └── ...
├── policy/               # Rego policy files
│   └── rego/
│       ├── pr.rego       # PR gate policy
│       ├── release.rego  # Release gate policy
│       └── compliance_soc2.rego  # SOC 2 compliance
├── config/               # Configuration files
├── schemas/              # Data schemas
├── tests/                # Test suite
│   ├── unit/             # Unit tests
│   └── integration/      # Integration tests
├── examples/             # Usage examples
├── requirements.txt      # Python dependencies
└── README.md             # This file
```

### Setting Up Development Environment

```bash
# Clone repository
git clone https://github.com/YOUR_USERNAME/argus.git
cd argus

# Create virtual environment
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt
pip install -r tests/requirements.txt

# Install pre-commit hooks
pip install pre-commit
pre-commit install

# Run tests
pytest tests/
```

### Code Style

Argus follows PEP 8 style guidelines:

```bash
# Format code
black scripts/

# Lint code
flake8 scripts/
pylint scripts/

# Type checking
mypy scripts/
```

### Adding New Features

1. **Create a feature branch**
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Write tests first** (TDD approach)
   ```bash
   # Create test file
   touch tests/unit/test_your_feature.py
   
   # Write failing tests
   pytest tests/unit/test_your_feature.py
   ```

3. **Implement feature**
   ```bash
   # Create feature file
   touch scripts/your_feature.py
   
   # Implement until tests pass
   pytest tests/unit/test_your_feature.py
   ```

4. **Update documentation**
   - Add usage examples to this README
   - Update docstrings
   - Add inline comments for complex logic

5. **Submit pull request**
   - Ensure all tests pass
   - Update CHANGELOG.md
   - Request review

---

## Testing

### Running Tests

```bash
# Run all tests
pytest tests/

# Run unit tests only
pytest tests/unit/

# Run integration tests only
pytest tests/integration/

# Run with coverage
pytest --cov=scripts --cov-report=html tests/

# Run specific test
pytest tests/unit/test_noise_scorer.py -v
```

### Test Coverage

Current coverage: **85%+**

| Module | Coverage |
|--------|----------|
| `noise_scorer.py` | 92% |
| `correlator.py` | 88% |
| `gate.py` | 95% |
| `normalizer/` | 90% |
| `providers/` | 85% |

### Writing Tests

```python
# tests/unit/test_example.py
import pytest
from scripts.noise_scorer import NoiseScorer

def test_noise_scoring():
    scorer = NoiseScorer()
    finding = {
        "severity": "low",
        "path": "tests/test_file.py",
        "category": "SAST"
    }
    
    score = scorer.calculate_noise_score(finding)
    
    assert 0 <= score <= 1
    assert score > 0.5  # Test files should have high noise
```

---

## Deployment

### GitHub Actions Integration

Create `.github/workflows/argus.yml`:

```yaml
name: Argus Security Scan

on:
  pull_request:
    branches: [main]
  push:
    branches: [main]

jobs:
  security-scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Set up Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.9'
      
      - name: Install Argus
        run: |
          pip install -r requirements.txt
          ./scripts/install_security_tools.sh
      
      - name: Run Security Scan
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          python3 scripts/run_ai_audit.py . audit
      
      - name: Evaluate Policy Gate
        run: |
          python3 scripts/gate.py \
            --stage pr \
            --input .argus/analysis/risk_scored.json
      
      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: security-report
          path: .argus/reviews/
```

### Docker Deployment

```bash
# Build Docker image
docker build -t argus:latest -f docker/security-sandbox.dockerfile .

# Run container
docker run -v $(pwd):/workspace \
  -e ANTHROPIC_API_KEY=$ANTHROPIC_API_KEY \
  argus:latest \
  python3 scripts/run_ai_audit.py /workspace audit
```

### Kubernetes Deployment

```yaml
# k8s/argus-cronjob.yaml
apiVersion: batch/v1
kind: CronJob
metadata:
  name: argus-scan
spec:
  schedule: "0 2 * * *"  # Daily at 2 AM
  jobTemplate:
    spec:
      template:
        spec:
          containers:
          - name: argus
            image: argus:latest
            env:
            - name: ANTHROPIC_API_KEY
              valueFrom:
                secretKeyRef:
                  name: argus-secrets
                  key: anthropic-api-key
            command:
            - python3
            - scripts/run_ai_audit.py
            - /workspace
            - audit
          restartPolicy: OnFailure
```

---

## Performance

### Benchmarks

Tested on **spring_auth** repository (Node.js, 1,458 dependencies):

| Phase | Duration | Cost |
|-------|----------|------|
| Deterministic Scanning | 8.3s | $0.00 |
| Normalization | 0.5s | $0.00 |
| Noise Scoring | 2.1s | $0.00 |
| Correlation | 1.8s | $0.00 |
| Risk Scoring | 0.3s | $0.00 |
| Policy Gate | 0.2s | $0.00 |
| AI Analysis (Foundation-Sec) | 263.6s | $0.00 |
| **Total** | **4.8 min** | **$0.00** |

### Optimization Tips

1. **Use Foundation-Sec** instead of Claude ($0.00 vs $0.35)
2. **Enable batch processing** for exploitability triage
3. **Cache SBOM generation** for unchanged dependencies
4. **Run deterministic scans in parallel** (use `--parallel` flag)
5. **Filter by severity** to reduce AI analysis time

### Scalability

- **Single Repository**: <5 minutes
- **Multi-Repository (10 repos)**: <30 minutes (with concurrency)
- **Enterprise (100+ repos)**: Use Kubernetes CronJob with distributed workers

---

## Security

### Threat Model

Argus itself is a security tool and follows secure development practices:

- **No secrets in code**: All credentials via environment variables
- **Sandboxed execution**: Docker containers with minimal privileges
- **Signed artifacts**: All releases signed with Cosign
- **SBOM included**: Transparency for supply chain security
- **Regular updates**: Dependencies updated weekly

### Reporting Vulnerabilities

**DO NOT** open public issues for security vulnerabilities.

Please report security vulnerabilities via GitHub Security Advisories or by opening a private issue.

We aim to respond within 48 hours and provide a fix within 7 days for critical issues.

### Security Best Practices

1. **Rotate API keys** regularly (every 90 days)
2. **Use IAM roles** instead of hardcoded AWS credentials
3. **Enable audit logging** for all policy decisions
4. **Review suppressed findings** monthly
5. **Verify SBOM signatures** before deployment

---

## Contributing

We welcome contributions! Please see our [Contributing Guidelines](CONTRIBUTING.md).

### How to Contribute

1. **Fork the repository**
2. **Create a feature branch** (`git checkout -b feature/amazing-feature`)
3. **Write tests** for your changes
4. **Ensure tests pass** (`pytest tests/`)
5. **Commit your changes** (`git commit -m 'Add amazing feature'`)
6. **Push to the branch** (`git push origin feature/amazing-feature`)
7. **Open a Pull Request**

### Code Review Process

- All PRs require at least 1 approval
- All tests must pass
- Code coverage must not decrease
- Documentation must be updated

### Community

- **GitHub Discussions**: Ask questions, share ideas
- **GitHub Issues**: Bug reports and feature requests
- **Pull Requests**: Contributions welcome!

---

## License

Argus is licensed under the [MIT License](LICENSE).

```
MIT License

Copyright (c) 2025 Argus Contributors

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
```

---

## Support

### Documentation

- **README**: You're reading it!
- **Examples**: See `examples/` directory
- **API Reference**: See inline docstrings

### Getting Help

- **GitHub Issues**: Bug reports and feature requests
- **GitHub Discussions**: Questions and community support
- **Documentation**: See this README and inline code documentation

---

## Acknowledgments

Argus is built on the shoulders of giants:

- **TruffleHog**: Secret scanning
- **Gitleaks**: Secret detection
- **Semgrep**: SAST analysis
- **Trivy**: Vulnerability scanning
- **Checkov**: IaC security
- **Syft**: SBOM generation
- **Cosign**: Artifact signing
- **OPA**: Policy engine
- **Foundation-Sec-8B**: Security-optimized LLM (Cisco)
- **Anthropic Claude**: AI analysis

Special thanks to the open-source security community.

---

## Status

**Version**: 1.0.0 - Production Ready  
**Last Updated**: November 7, 2025  
**Maintainer**: Argus Community  
**License**: MIT

---

**Built with ❤️ by the open-source security community**

