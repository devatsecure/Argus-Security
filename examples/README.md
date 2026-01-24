# Argus Examples

This directory contains example scripts and usage patterns for Argus Security Action.

## Examples

### 1. Threat Intelligence Integration (`threat_intel_integration.py`)

**NEW** - Demonstrates how to enrich security findings with real-time threat intelligence.

**Features:**
- Loads findings from Trivy and Semgrep scanners
- Enriches CVE findings with CISA KEV, EPSS, NVD, GitHub, and OSV data
- Generates prioritized security reports
- Alerts on actively exploited vulnerabilities (KEV catalog)

**Usage:**

```bash
# Run scanners first
trivy fs --format json --output trivy-results.json .
semgrep --config auto --json --output semgrep-results.json .

# Then run the integration example
python examples/threat_intel_integration.py
```

**Output:**
- Console report with critical findings
- Enriched findings JSON file (`enriched-findings.json`)
- KEV catalog alerts for actively exploited vulnerabilities

**See Also:**
- `/docs/threat-intelligence-integration.md` - Full documentation
- `/scripts/threat_intel_enricher.py` - Core enrichment module

### 2. Basic Workflow

Standard Argus security audit workflow:

```bash
# Run full security audit with AI triage
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --ai-provider anthropic \
  --output-file security-report.json
```

### 3. Scanner Orchestration

Using individual scanners:

```bash
# TruffleHog for secrets
python scripts/scanners/trufflehog_scanner.py --scan-path .

# Checkov for IaC
python scripts/scanners/checkov_scanner.py --scan-path .

# Semgrep for code issues
semgrep --config auto --json .
```

### 4. CLI Tools

Argus CLI (`argus`) examples:

```bash
# Normalize scanner outputs
./scripts/argus normalize \
  --inputs semgrep.sarif trivy.json \
  --output findings.json

# Apply policy gates
./scripts/argus gate \
  --stage pr \
  --input findings.json

# Record feedback
./scripts/argus feedback record abc-123 \
  --mark fp \
  --reason "Test file should be ignored"
```

## Running Examples

All examples assume you're in the repository root:

```bash
cd /path/to/argus-action
python examples/threat_intel_integration.py
```

## Requirements

Most examples use only standard dependencies from `requirements.txt`. Special cases:

- **threat_intel_integration.py**: No additional deps (uses stdlib)
- **AI triage examples**: Require `ANTHROPIC_API_KEY` or `OPENAI_API_KEY`
- **Scanner examples**: Require scanner tools installed (trivy, semgrep, etc.)

## Contributing Examples

When adding new examples:

1. Add executable Python script to this directory
2. Update this README with usage instructions
3. Add corresponding documentation to `/docs/` if complex
4. Test with sample data in repository

## See Also

- `/docs/` - Comprehensive documentation
- `/scripts/` - Core implementation modules
- `action.yml` - GitHub Action interface
