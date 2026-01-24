# DAST Scanner Reference

## Overview

The **DAST (Dynamic Application Security Testing) Scanner** integrates Nuclei to provide runtime vulnerability detection for Argus. It complements the existing static analysis tools (Semgrep, Checkov) with dynamic testing capabilities.

## Features

### Core Capabilities

- **Nuclei Integration**: Leverages 4000+ built-in Nuclei templates for comprehensive vulnerability coverage
- **OpenAPI/Swagger Support**: Automatically discovers and tests endpoints from API specifications
- **Authenticated Scanning**: Supports custom headers, cookies, and tokens for testing authenticated endpoints
- **Multi-Protocol Testing**: HTTP, DNS, network protocol testing support
- **PoC Generation**: Automatically generates curl commands to reproduce vulnerabilities

### Vulnerability Detection

The scanner tests for:
- **SQL Injection (SQLi)** - CWE-89
- **Cross-Site Scripting (XSS)** - CWE-79
- **Server-Side Request Forgery (SSRF)** - CWE-918
- **XML External Entity (XXE)** - CWE-611
- **Remote Code Execution (RCE)** - CWE-94
- **Local File Inclusion (LFI)** - CWE-98
- **Open Redirects** - CWE-601
- **Authentication Bypasses**
- **API Misconfigurations**
- **CVEs** - Known vulnerabilities from NVD

## Installation

### Install Nuclei

```bash
# macOS/Linux (Homebrew)
brew install nuclei

# Linux (Binary)
wget https://github.com/projectdiscovery/nuclei/releases/latest/download/nuclei_linux_amd64.zip
unzip nuclei_linux_amd64.zip && sudo mv nuclei /usr/local/bin/

# Go Install
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest

# Docker
docker pull projectdiscovery/nuclei:latest
```

### Verify Installation

```bash
nuclei -version
```

## Usage

### CLI Usage

#### Basic URL Scan

```bash
python scripts/dast_scanner.py https://api.example.com
```

#### OpenAPI-Based Scan

```bash
# Scan all endpoints from OpenAPI spec
python scripts/dast_scanner.py \
  --openapi openapi.yaml \
  --base-url https://api.example.com \
  --output findings.json
```

#### Authenticated Scan

```bash
# Scan with authentication headers
python scripts/dast_scanner.py https://api.example.com \
  --header "Authorization: Bearer token123" \
  --header "X-API-Key: your-key" \
  --severity critical,high
```

#### Custom Templates

```bash
# Use custom Nuclei templates
python scripts/dast_scanner.py https://example.com \
  --templates ~/nuclei-templates/custom/ \
  --templates ./my-templates/sqli.yaml \
  --concurrency 50
```

#### Rate Limiting

```bash
# Control scan rate to avoid overwhelming target
python scripts/dast_scanner.py https://api.example.com \
  --rate-limit 100 \
  --timeout 10 \
  --concurrency 25
```

### Python API Usage

#### Simple URL Scan

```python
from dast_scanner import DASTScanner

scanner = DASTScanner(
    target_url="https://api.example.com",
    config={
        "severity": ["critical", "high"],
        "rate_limit": 100,
    }
)

result = scanner.scan()
print(f"Found {result.total_findings} vulnerabilities")
```

#### OpenAPI Scan

```python
scanner = DASTScanner(
    openapi_spec="openapi.yaml",
    config={
        "severity": ["critical", "high", "medium"],
        "headers": {
            "Authorization": "Bearer token123"
        }
    }
)

result = scanner.scan(
    target="https://api.example.com",
    output_file="dast_findings.json"
)
```

#### Normalize to Finding Format

```python
# Convert DAST findings to unified Finding format
normalized_findings = scanner.normalize_to_findings(result)

# Integrate with Argus pipeline
for finding in normalized_findings:
    print(f"{finding['severity']}: {finding['rule_name']}")
    print(f"  PoC: {finding['evidence']['poc']}")
```

#### Generate PoC Exploits

```python
for finding in result.findings:
    poc = scanner.generate_poc_exploit(finding)
    print(f"Reproduce with: {poc}")
```

## Configuration

### Scanner Configuration

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `target_url` | str | None | Base URL to scan |
| `openapi_spec` | str | None | Path to OpenAPI/Swagger spec |
| `config.severity` | list[str] | `["critical", "high", "medium"]` | Severity levels to include |
| `config.templates` | list[str] | `[]` | Custom template paths (empty = use built-in) |
| `config.rate_limit` | int | 150 | Requests per second |
| `config.timeout` | int | 5 | Request timeout in seconds |
| `config.retries` | int | 1 | Number of retry attempts |
| `config.headers` | dict | `{}` | Custom HTTP headers |
| `config.concurrency` | int | 25 | Concurrent requests |

### Severity Levels

- **critical**: Critical vulnerabilities (CVSS 9.0-10.0)
- **high**: High severity issues (CVSS 7.0-8.9)
- **medium**: Medium severity issues (CVSS 4.0-6.9)
- **low**: Low severity issues (CVSS 0.1-3.9)
- **info**: Informational findings (CVSS 0.0)

## Output Format

### DASTScanResult

```json
{
  "scan_type": "openapi",
  "target": "https://api.example.com",
  "timestamp": "2026-01-15T10:00:00Z",
  "total_requests": 25,
  "total_findings": 3,
  "scan_duration_seconds": 45.2,
  "nuclei_version": "v3.1.0",
  "templates_used": ["built-in"],
  "authentication": {
    "headers": ["Authorization", "X-API-Key"]
  },
  "findings": [...]
}
```

### NucleiFinding

```json
{
  "template_id": "CVE-2021-1234",
  "template_name": "SQL Injection in Login",
  "severity": "critical",
  "matched_at": "https://api.example.com/login",
  "extracted_results": ["admin' OR '1'='1"],
  "curl_command": "curl -X GET https://api.example.com/login?user=admin",
  "matcher_name": "sql-error",
  "type": "http",
  "host": "api.example.com",
  "ip": "192.0.2.1",
  "timestamp": "2026-01-15T10:00:00Z",
  "tags": ["sqli", "injection", "cve"],
  "classification": {
    "cwe-id": "CWE-89",
    "cvss-score": "9.8"
  }
}
```

### Normalized Finding Format

The scanner normalizes Nuclei findings to the Argus unified `Finding` format:

```json
{
  "id": "abc123...",
  "origin": "nuclei",
  "repo": "https://github.com/org/repo",
  "commit_sha": "abc123",
  "branch": "main",
  "path": "https://api.example.com/login",
  "asset_type": "api",
  "rule_id": "CVE-2021-1234",
  "rule_name": "SQL Injection in Login",
  "category": "DAST",
  "severity": "critical",
  "cwe": "CWE-89",
  "cve": "CVE-2021-1234",
  "evidence": {
    "matched_at": "https://api.example.com/login",
    "template_id": "CVE-2021-1234",
    "matcher_name": "sql-error",
    "extracted_results": ["admin' OR '1'='1"],
    "tags": ["sqli", "injection"],
    "poc": "curl -X GET https://api.example.com/login?user=admin",
    "request": "GET /login?user=admin HTTP/1.1...",
    "response": "HTTP/1.1 200 OK..."
  },
  "references": [
    "https://github.com/projectdiscovery/nuclei-templates/tree/main/CVE-2021-1234"
  ],
  "exploitability": "trivial",
  "reachability": "yes"
}
```

## OpenAPI Integration

### Endpoint Discovery

The scanner automatically:
1. Parses OpenAPI 3.0+ specifications (JSON or YAML)
2. Extracts all paths and HTTP methods
3. Identifies path parameters and replaces with test values
4. Extracts query parameters and adds test values
5. Generates request bodies from schemas for POST/PUT/PATCH
6. Builds full target URLs for scanning

### Example OpenAPI Spec

```yaml
openapi: 3.0.0
info:
  title: Sample API
  version: 1.0.0
servers:
  - url: https://api.example.com
paths:
  /users:
    get:
      summary: List users
      parameters:
        - name: page
          in: query
          schema:
            type: integer
  /users/{id}:
    get:
      summary: Get user
      parameters:
        - name: id
          in: path
          required: true
          schema:
            type: integer
    post:
      summary: Create user
      requestBody:
        content:
          application/json:
            schema:
              type: object
              properties:
                name:
                  type: string
                email:
                  type: string
              required:
                - name
                - email
```

This spec generates:
- `GET https://api.example.com/users?page=test`
- `GET https://api.example.com/users/1`
- `POST https://api.example.com/users/{id}` with JSON body

## Integration with Argus

### In Hybrid Analyzer

Add DAST scanner to `hybrid_analyzer.py`:

```python
# In hybrid_analyzer.py

from dast_scanner import DASTScanner

class HybridAnalyzer:
    def analyze(self, target: str):
        # ... existing scanners ...

        # Add DAST scanning
        if self.enable_dast:
            dast_scanner = DASTScanner(
                target_url=self.api_base_url,
                openapi_spec=self.openapi_spec,
                config=self.dast_config
            )
            dast_result = dast_scanner.scan()
            dast_findings = dast_scanner.normalize_to_findings(dast_result)
            all_findings.extend(dast_findings)
```

### In GitHub Actions

```yaml
- name: Run DAST Scan
  run: |
    python scripts/dast_scanner.py \
      --openapi openapi.yaml \
      --base-url ${{ secrets.STAGING_URL }} \
      --header "Authorization: Bearer ${{ secrets.API_TOKEN }}" \
      --severity critical,high \
      --output dast-findings.json

- name: Upload Results
  uses: github/codeql-action/upload-sarif@v2
  with:
    sarif_file: dast-findings.json
```

## Best Practices

### Performance

1. **Rate Limiting**: Use `--rate-limit` to avoid overwhelming targets
   ```bash
   --rate-limit 100  # 100 requests/second
   ```

2. **Concurrency**: Adjust based on target capacity
   ```bash
   --concurrency 25  # 25 concurrent requests
   ```

3. **Timeouts**: Set appropriate timeouts for slow endpoints
   ```bash
   --timeout 10  # 10 second timeout
   ```

### Security

1. **Secrets**: Never hardcode API keys or tokens
   ```bash
   --header "Authorization: Bearer $API_TOKEN"
   ```

2. **Target Environment**: Only scan authorized environments
   - Use staging/dev environments
   - Get explicit permission for production scans
   - Follow responsible disclosure policies

3. **Scope**: Define clear testing boundaries
   ```bash
   # Only scan specific paths
   --templates ./templates/api-only/
   ```

### Accuracy

1. **Severity Filtering**: Focus on actionable findings
   ```bash
   --severity critical,high  # Skip low-severity noise
   ```

2. **Custom Templates**: Create templates for your tech stack
   ```yaml
   # templates/custom/django-sqli.yaml
   id: django-sqli
   info:
     name: Django ORM SQL Injection
     severity: critical
   http:
     - method: GET
       path:
         - "{{BaseURL}}/api/users?id={{injection}}"
       payloads:
         injection:
           - "1' OR '1'='1"
   ```

3. **False Positive Reduction**: Review and tune templates
   - Mark false positives
   - Create skip rules for known issues
   - Contribute improvements to nuclei-templates

## Troubleshooting

### Nuclei Not Found

```
Error: Nuclei not installed
```

**Solution**: Install Nuclei following the [installation instructions](#install-nuclei)

### Permission Denied

```
Error: Permission denied to scan target
```

**Solution**: Ensure you have authorization to scan the target. Add authentication headers.

### Timeout Errors

```
Error: Request timed out
```

**Solution**: Increase timeout or reduce rate limit:
```bash
--timeout 15 --rate-limit 50
```

### No Findings

If the scanner completes but finds nothing:

1. **Check target is accessible**: Verify URL is reachable
2. **Review severity filter**: Lower the threshold (`--severity low,medium,high,critical`)
3. **Check templates**: Ensure templates match your tech stack
4. **Enable verbose logging**: `--verbose` to see details

## Examples

See `/home/user/argus-action/examples/dast_scanner_example.py` for comprehensive examples:

1. Simple URL scan
2. OpenAPI-based scan
3. Authenticated scanning
4. Custom template usage
5. Finding normalization
6. PoC generation

## Limitations

1. **Requires Running Application**: Unlike SAST, DAST needs a deployed instance
2. **Network Access**: Scanner must reach target endpoints
3. **Authentication State**: Complex auth flows may require manual testing
4. **Coverage**: Only tests exposed endpoints (no code-level coverage)
5. **Performance Impact**: Intensive scanning can impact target performance

## Roadmap

Future enhancements:

- [ ] SARIF output format for GitHub Advanced Security
- [ ] Integration with Burp Suite for recorded traffic replay
- [ ] WebSocket and GraphQL protocol support
- [ ] Authenticated session management (login flows)
- [ ] Headless browser integration for JavaScript-heavy apps
- [ ] Regression testing mode (compare findings across scans)
- [ ] CI/CD quality gates (block deployment on critical findings)

## References

- [Nuclei Documentation](https://docs.projectdiscovery.io/nuclei/)
- [Nuclei Templates Repository](https://github.com/projectdiscovery/nuclei-templates)
- [OpenAPI Specification](https://swagger.io/specification/)
- [OWASP DAST Guide](https://owasp.org/www-community/Vulnerability_Scanning_Tools)
- [CWE Database](https://cwe.mitre.org/)

## Support

For issues or questions:
- GitHub Issues: `devatsecure/Argus-Security`
- Documentation: `/home/user/argus-action/docs/`
- Examples: `/home/user/argus-action/examples/dast_scanner_example.py`
