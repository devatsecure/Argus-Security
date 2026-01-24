# DAST Scanner - Quick Start Guide

## 5-Minute Setup

### 1. Install Nuclei

```bash
# macOS/Linux
brew install nuclei

# Or download binary
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/

# Verify installation
nuclei -version
```

### 2. Run Your First Scan

```bash
# Scan a URL
python scripts/dast_scanner.py https://example.com

# Scan with severity filter
python scripts/dast_scanner.py https://example.com --severity critical,high
```

### 3. Scan from OpenAPI Spec

```bash
# If you have an OpenAPI/Swagger spec
python scripts/dast_scanner.py \
  --openapi openapi.yaml \
  --base-url https://api.example.com \
  --output findings.json
```

### 4. Authenticated Scanning

```bash
# Add authentication headers
python scripts/dast_scanner.py https://api.example.com \
  --header "Authorization: Bearer $TOKEN" \
  --header "X-API-Key: $API_KEY"
```

## Python API Usage

```python
from dast_scanner import DASTScanner

# Simple scan
scanner = DASTScanner(target_url="https://api.example.com")
result = scanner.scan()

# View findings
for finding in result.findings:
    print(f"[{finding.severity}] {finding.template_name}")
    print(f"  URL: {finding.matched_at}")
    print(f"  PoC: {finding.curl_command}\n")

# Normalize to Argus Finding format
normalized = scanner.normalize_to_findings(result)
```

## Common Use Cases

### Case 1: Pre-deployment Security Check

```bash
# Scan staging environment before production deploy
python scripts/dast_scanner.py \
  --openapi openapi.yaml \
  --base-url https://staging.api.example.com \
  --header "Authorization: Bearer $STAGING_TOKEN" \
  --severity critical,high \
  --output pre-deploy-findings.json

# Exit code 1 if critical/high findings found
if [ $? -eq 1 ]; then
  echo "⛔ Security issues found - blocking deployment"
  exit 1
fi
```

### Case 2: Continuous Security Testing

```yaml
# .github/workflows/dast.yml
name: DAST Security Scan

on:
  schedule:
    - cron: '0 2 * * *'  # Daily at 2am

jobs:
  dast:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Install Nuclei
        run: |
          wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
          unzip nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/

      - name: Run DAST Scan
        run: |
          python scripts/dast_scanner.py \
            --openapi openapi.yaml \
            --base-url ${{ secrets.STAGING_URL }} \
            --header "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
            --output dast-findings.json

      - name: Upload Findings
        uses: actions/upload-artifact@v4
        with:
          name: dast-findings
          path: dast-findings.json
```

### Case 3: Custom Template Scanning

```bash
# Create custom template for your app
cat > my-app-sqli.yaml << 'EOF'
id: my-app-sqli

info:
  name: My App SQL Injection
  author: security-team
  severity: critical
  tags: sqli,custom

http:
  - method: GET
    path:
      - "{{BaseURL}}/api/users?id={{injection}}"

    payloads:
      injection:
        - "1' OR '1'='1"
        - "1 UNION SELECT NULL--"

    matchers:
      - type: word
        words:
          - "SQL syntax"
          - "mysql_fetch"
        condition: or
EOF

# Run with custom template
python scripts/dast_scanner.py https://myapp.com \
  --templates ./my-app-sqli.yaml \
  --severity critical
```

## Performance Tuning

### High-Performance Scan (Fast)

```bash
python scripts/dast_scanner.py https://api.example.com \
  --concurrency 100 \
  --rate-limit 500 \
  --timeout 3
```

### Conservative Scan (Safe)

```bash
python scripts/dast_scanner.py https://api.example.com \
  --concurrency 10 \
  --rate-limit 50 \
  --timeout 10
```

## Integration with Argus

### Add to Hybrid Analyzer

```python
# In hybrid_analyzer.py
from dast_scanner import DASTScanner

class HybridAnalyzer:
    def __init__(self, ...):
        # ... existing scanners ...
        self.enable_dast = config.get('enable_dast', False)
        self.dast_config = config.get('dast_config', {})

    def analyze(self, target_path: str):
        findings = []

        # ... existing scanners (TruffleHog, Gitleaks, Semgrep, Trivy, Checkov) ...

        # Add DAST scanning
        if self.enable_dast and self.api_base_url:
            logger.info("Running DAST scan...")
            dast_scanner = DASTScanner(
                target_url=self.api_base_url,
                openapi_spec=self.openapi_spec,
                config=self.dast_config
            )
            dast_result = dast_scanner.scan()
            dast_findings = dast_scanner.normalize_to_findings(dast_result)
            findings.extend(dast_findings)

        return findings
```

### Enable in Configuration

```yaml
# .argus.yml
scanners:
  dast:
    enabled: true
    api_base_url: https://api.example.com
    openapi_spec: openapi.yaml
    config:
      severity: [critical, high, medium]
      headers:
        Authorization: ${API_TOKEN}
      rate_limit: 100
      concurrency: 25
```

## Troubleshooting

### "Nuclei not installed"

```bash
# Check installation
which nuclei

# If not found, install
brew install nuclei
# OR
python scripts/dast_scanner.py --install
```

### "No findings but vulnerabilities exist"

```bash
# Try lowering severity threshold
python scripts/dast_scanner.py https://example.com \
  --severity info,low,medium,high,critical

# Or enable verbose logging
python scripts/dast_scanner.py https://example.com --verbose
```

### "Scan too slow"

```bash
# Increase concurrency and rate limit
python scripts/dast_scanner.py https://example.com \
  --concurrency 50 \
  --rate-limit 200
```

### "Target overwhelmed"

```bash
# Reduce load on target
python scripts/dast_scanner.py https://example.com \
  --concurrency 10 \
  --rate-limit 50 \
  --timeout 15
```

## Next Steps

1. **Read the full documentation**: `/home/user/argus-action/docs/references/dast-scanner-reference.md`
2. **Try the examples**: `/home/user/argus-action/examples/dast_scanner_example.py`
3. **Create custom templates**: For your specific application vulnerabilities
4. **Integrate with CI/CD**: Add DAST scanning to your pipeline
5. **Monitor trends**: Track findings over time to measure security improvements

## Get Help

- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Nuclei Docs: https://docs.projectdiscovery.io/nuclei/
- Template Library: https://github.com/projectdiscovery/nuclei-templates

## Security Best Practices

1. **Only scan authorized targets** - Get permission before scanning
2. **Use staging environments** - Avoid production scans during peak hours
3. **Protect credentials** - Use environment variables, never hardcode
4. **Rate limit appropriately** - Don't overwhelm target systems
5. **Review findings manually** - DAST can have false positives
6. **Keep templates updated** - Run `nuclei -update-templates` regularly

---

**Happy scanning! 🔒**
