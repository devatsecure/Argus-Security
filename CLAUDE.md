# CLAUDE.md - Argus Security

> Enterprise-grade AI Security Platform for code security analysis.

## What This Does

Argus Security orchestrates 5 security scanners (TruffleHog, Gitleaks, Semgrep, Trivy, Checkov) with Claude AI-powered triage to find vulnerabilities and reduce false positives by 60-70%.

## Quick Start

```bash
# Install
git clone https://github.com/devatsecure/Argus-Security
cd Argus-Security && pip install -r requirements.txt
export ANTHROPIC_API_KEY="your-key"

# Run security audit
python scripts/run_ai_audit.py --project-type backend-api
```

## Essential Commands

| Command | Purpose |
|---------|---------|
| `python scripts/run_ai_audit.py --project-type backend-api` | Full security audit with AI triage |
| `./scripts/argus gate --stage pr --input findings.json` | Apply policy gate (pass/fail) |
| `./scripts/argus feedback record <id> --mark fp` | Mark finding as false positive |
| `pytest -v --cov=scripts` | Run tests |

## How Claude Code Can Use This

### 1. Run a Security Scan
```bash
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --output-file report.json
```

### 2. Check Specific Files for Injection Vulnerabilities
```bash
python scripts/run_ai_audit.py \
  --only-changed src/auth.py src/api.py \
  --output-file findings.json
```

### 3. Apply Policy Gates
```bash
# Check if findings pass security policy
./scripts/argus gate --stage pr --input findings.json
# Exit 0 = pass, Exit 1 = fail
```

### 4. Record Feedback to Improve Future Scans
```bash
./scripts/argus feedback record finding-123 --mark fp --reason "test file"
```

## Project Structure

```
Argus-Security/
├── scripts/
│   ├── run_ai_audit.py       # Main entry point
│   ├── hybrid_analyzer.py    # Multi-scanner orchestrator
│   ├── agent_personas.py     # 5 AI personas for analysis
│   ├── remediation_engine.py # Auto-fix generation
│   └── argus                 # CLI tool
├── policy/rego/              # OPA policies for gates
├── tests/                    # Test suite
└── action.yml                # GitHub Action definition
```

## Development

```bash
# Lint and format
ruff check scripts/ && ruff format scripts/

# Run tests with coverage
pytest -v --cov=scripts

# Type checking
mypy scripts/*.py
```

## GitHub Action Usage

```yaml
- uses: devatsecure/Argus-Security@v1
  with:
    anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
    review-type: security
    fail-on-blockers: true
```

## Docker

```bash
docker build -t argus .
docker run -v $(pwd):/workspace argus
```
