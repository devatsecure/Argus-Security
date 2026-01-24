# SAST-DAST Correlator Integration Guide

## Quick Start

The SAST-DAST Correlator is a standalone module that can be integrated into your security workflow to verify if SAST findings are exploitable.

## Integration with Argus Workflow

### Option 1: Standalone CLI Usage

```bash
# Run your SAST scans
python scripts/run_ai_audit.py \
  --project-type backend-api \
  --output-file sast-results.json

# Run your DAST scans (external tool)
# Example: OWASP ZAP, Burp Suite, Nuclei, etc.
# zap-cli quick-scan http://localhost:8000 --output dast-results.json

# Correlate findings
python scripts/sast_dast_correlator.py \
  --sast-file sast-results.json \
  --dast-file dast-results.json \
  --output-file correlation-results.json
```

### Option 2: Programmatic Integration

```python
#!/usr/bin/env python3
"""Example: Full security scan with SAST-DAST correlation"""

import json
from run_ai_audit import run_security_audit
from sast_dast_correlator import SASTDASTCorrelator, CorrelationStatus

# Step 1: Run SAST scans
print("Running SAST scans...")
sast_results = run_security_audit(
    project_type="backend-api",
    scanners=["semgrep", "trufflehog"],
    ai_triage=True
)

# Step 2: Run DAST scans (use external DAST tool)
print("Running DAST scans...")
# This would be your DAST tool integration
# dast_results = run_dast_scan(target="http://localhost:8000")

# For demo purposes, load from file
with open("dast-results.json") as f:
    dast_results = json.load(f)

# Step 3: Correlate findings
print("Correlating SAST and DAST findings...")
correlator = SASTDASTCorrelator()
correlations = correlator.correlate(
    sast_findings=sast_results.get("findings", []),
    dast_findings=dast_results.get("findings", []),
    use_ai=True  # Enable AI verification
)

# Step 4: Filter and prioritize
confirmed = [
    c for c in correlations
    if c.status == CorrelationStatus.CONFIRMED
    and c.confidence >= 0.8
]

print(f"\n{'='*60}")
print(f"Found {len(confirmed)} confirmed exploitable vulnerabilities")
print(f"{'='*60}")

for finding in confirmed:
    print(f"\n⚠️  {finding.sast_finding_id}")
    print(f"   Confidence: {finding.confidence:.2%}")
    print(f"   Exploitability: {finding.exploitability}")
    print(f"   Reasoning: {finding.reasoning}")
```

### Option 3: GitHub Actions Integration

```yaml
# .github/workflows/security-scan.yml
name: Security Scan with SAST-DAST Correlation

on: [pull_request]

jobs:
  security:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      # Run SAST scans
      - name: Run SAST
        uses: devatsecure/Argus-Security@v1
        with:
          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}
          review-type: security
          output-file: sast-results.json

      # Run DAST scans (example with ZAP)
      - name: Run DAST with ZAP
        run: |
          docker run -v $(pwd):/zap/wrk/:rw \
            -t ghcr.io/zaproxy/zaproxy:stable \
            zap-baseline.py -t http://localhost:8000 \
            -J dast-results.json

      # Correlate findings
      - name: Correlate SAST-DAST
        run: |
          python scripts/sast_dast_correlator.py \
            --sast-file sast-results.json \
            --dast-file dast-results.json \
            --output-file correlation-results.json

      # Check for blocking findings
      - name: Check Confirmed Exploitables
        run: |
          CONFIRMED=$(jq '[.correlations[] | select(.status == "confirmed" and .confidence >= 0.8)] | length' correlation-results.json)
          if [ "$CONFIRMED" -gt 0 ]; then
            echo "❌ Found $CONFIRMED confirmed exploitable vulnerabilities!"
            exit 1
          else
            echo "✅ No confirmed exploitable vulnerabilities"
          fi

      # Upload correlation report
      - name: Upload Correlation Report
        uses: actions/upload-artifact@v4
        if: always()
        with:
          name: correlation-report
          path: correlation-results.json
```

## Integration with DAST Tools

### OWASP ZAP

```bash
# Run ZAP baseline scan
docker run -v $(pwd):/zap/wrk/:rw \
  -t ghcr.io/zaproxy/zaproxy:stable \
  zap-baseline.py -t http://localhost:8000 \
  -J zap-results.json

# Convert ZAP results to normalized format
python scripts/normalizer/zap_normalizer.py \
  --input zap-results.json \
  --output dast-normalized.json

# Correlate with SAST
python scripts/sast_dast_correlator.py \
  --sast-file sast-results.json \
  --dast-file dast-normalized.json \
  --output-file correlation.json
```

### Burp Suite

```bash
# Export Burp findings as JSON
# (Use Burp's API or export feature)

# Convert Burp results to normalized format
python scripts/normalizer/burp_normalizer.py \
  --input burp-results.json \
  --output dast-normalized.json

# Correlate
python scripts/sast_dast_correlator.py \
  --sast-file sast-results.json \
  --dast-file dast-normalized.json \
  --output-file correlation.json
```

### Nuclei

```bash
# Run Nuclei scan
nuclei -u http://localhost:8000 \
  -json -o nuclei-results.json

# Convert Nuclei results to normalized format
python scripts/normalizer/nuclei_normalizer.py \
  --input nuclei-results.json \
  --output dast-normalized.json

# Correlate
python scripts/sast_dast_correlator.py \
  --sast-file sast-results.json \
  --dast-file dast-normalized.json \
  --output-file correlation.json
```

## Custom DAST Normalizer Template

If you need to integrate a custom DAST tool, create a normalizer:

```python
#!/usr/bin/env python3
"""Normalizer for Custom DAST Tool"""

import json
from normalizer.base import Normalizer, Finding

class CustomDASTNormalizer(Normalizer):
    """Normalize Custom DAST tool output to Argus format"""

    def normalize(self, raw_output: dict) -> list[Finding]:
        """Convert Custom DAST output to Finding objects"""
        findings = []
        git_ctx = self._get_git_context()

        for item in raw_output.get("vulnerabilities", []):
            finding = Finding(
                id=self._generate_id({
                    "repo": git_ctx["repo"],
                    "path": item.get("url", ""),
                    "rule_id": item.get("type", ""),
                    "line": 0  # DAST findings don't have line numbers
                }),
                origin="custom-dast",
                repo=git_ctx["repo"],
                commit_sha=git_ctx["commit_sha"],
                branch=git_ctx["branch"],
                path=item.get("url", ""),
                rule_id=item.get("type", ""),
                rule_name=item.get("name", ""),
                category="RUNTIME",  # DAST is runtime testing
                severity=self._map_severity(item.get("severity")),
                cwe=item.get("cwe"),
                evidence={
                    "url": item.get("url"),
                    "method": item.get("method"),
                    "message": item.get("description"),
                    "poc": item.get("proof_of_concept")
                }
            )
            findings.append(finding)

        return findings

    def _map_severity(self, severity: str) -> str:
        """Map tool severity to standard levels"""
        mapping = {
            "CRITICAL": "critical",
            "HIGH": "high",
            "MEDIUM": "medium",
            "LOW": "low",
            "INFO": "info"
        }
        return mapping.get(severity.upper(), "medium")

# Usage
if __name__ == "__main__":
    import sys
    normalizer = CustomDASTNormalizer()

    with open(sys.argv[1]) as f:
        raw_data = json.load(f)

    findings = normalizer.normalize(raw_data)
    normalized = {"findings": [f.to_dict() for f in findings]}

    with open(sys.argv[2], "w") as f:
        json.dump(normalized, f, indent=2)
```

## Best Practices

### 1. Run DAST Against Deployed Environments

```bash
# Development environment
python scripts/sast_dast_correlator.py \
  --sast-file sast-dev.json \
  --dast-file dast-dev.json \
  --output-file correlation-dev.json

# Staging environment (more complete DAST coverage)
python scripts/sast_dast_correlator.py \
  --sast-file sast-staging.json \
  --dast-file dast-staging.json \
  --output-file correlation-staging.json
```

### 2. Track Correlation Metrics Over Time

```bash
# Store correlation results with timestamps
TIMESTAMP=$(date +%Y%m%d-%H%M%S)
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file "correlations/correlation-${TIMESTAMP}.json"

# Analyze trends
python scripts/analyze_correlation_trends.py correlations/
```

### 3. Use AI Verification Selectively

```bash
# Heuristics only for quick triage
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file quick-triage.json \
  --no-ai

# AI verification for high-severity findings
jq '.correlations[] | select(.sast_summary.severity == "critical" or .sast_summary.severity == "high")' \
  quick-triage.json > high-severity.json

python scripts/sast_dast_correlator.py \
  --sast-file high-severity.json \
  --dast-file dast.json \
  --output-file verified.json
  # AI enabled by default
```

### 4. Integrate into Security Gates

```bash
#!/bin/bash
# security-gate.sh

set -e

# Run SAST
python scripts/run_ai_audit.py --output-file sast.json

# Run DAST
run_dast_tool --output dast.json

# Correlate
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file correlation.json

# Apply gates
CRITICAL=$(jq '[.correlations[] | select(.status == "confirmed" and .sast_summary.severity == "critical")] | length' correlation.json)
HIGH=$(jq '[.correlations[] | select(.status == "confirmed" and .sast_summary.severity == "high")] | length' correlation.json)

if [ "$CRITICAL" -gt 0 ]; then
  echo "❌ GATE FAILED: $CRITICAL critical exploitable vulnerabilities"
  exit 1
elif [ "$HIGH" -gt 5 ]; then
  echo "❌ GATE FAILED: $HIGH high exploitable vulnerabilities (threshold: 5)"
  exit 1
else
  echo "✅ GATE PASSED"
  exit 0
fi
```

## Troubleshooting

### Issue: Low correlation rates

**Solution:**
1. Verify DAST coverage includes SAST-identified endpoints
2. Check that DAST findings include CWE/vulnerability type
3. Enable debug logging: `--debug`
4. Review path mapping with `--debug` to see match scores

### Issue: Too many false correlations

**Solution:**
1. Enable AI verification for better accuracy
2. Increase confidence threshold when filtering results
3. Provide better context in SAST/DAST findings

### Issue: "No DAST coverage" for most findings

**Solution:**
1. Expand DAST test suite to cover more endpoints
2. Use correlation results to identify coverage gaps
3. Prioritize DAST testing for critical SAST findings

## See Also

- [SAST-DAST Correlation Documentation](./sast-dast-correlation.md)
- [Main Argus Documentation](../README.md)
- [Scanner Reference](./references/scanner-reference.md)
