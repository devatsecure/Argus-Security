# SAST-DAST Correlation Engine

## Overview

The SAST-DAST Correlation Engine is an AI-powered tool that correlates static analysis (SAST) findings with dynamic analysis (DAST) results to verify if vulnerabilities are actually exploitable in a running application. This helps reduce false positives and prioritize security efforts on confirmed exploitable issues.

## Key Features

- **Multi-Criteria Matching**: Correlates findings based on:
  - File path → URL endpoint mapping
  - Vulnerability type (SQL injection, XSS, etc.)
  - CWE identifiers

- **Fuzzy Path Matching**: Intelligently maps source file paths to API endpoints
  - Example: `src/api/users.py` → `/api/users`

- **AI-Powered Verification**: Uses Claude/OpenAI/Ollama to determine if DAST results confirm SAST findings
  - Provides confidence scores (0.0-1.0)
  - Explains reasoning for each correlation
  - Assesses exploitability level

- **Correlation Statuses**:
  - `CONFIRMED`: DAST verified the SAST finding is exploitable
  - `PARTIAL`: DAST found similar issue but not exact match
  - `NOT_VERIFIED`: DAST couldn't verify (might be false positive)
  - `NO_DAST_COVERAGE`: No DAST test for this endpoint

- **Integration with LLMManager**: Leverages existing AI infrastructure for cost tracking and decision logging

## How It Works

### 1. Heuristic Matching

The correlator first performs heuristic matching to find DAST candidates for each SAST finding:

```python
# Match score calculation (0.0-1.0)
score = (
    path_similarity * 0.40 +       # File path → URL matching
    vuln_type_match * 0.35 +       # Vulnerability type matching
    cwe_match * 0.25               # CWE ID matching
)
```

**Example Path Matching:**
- SAST: `src/api/users.py` → Endpoint: `/api/users`
- DAST: `http://localhost:8000/api/users?id=1'`
- Path similarity: 0.95 (high match)

### 2. AI Verification

For candidates with match score > 0.3, the correlator uses AI to verify:

```
Prompt includes:
- SAST finding context (file, line, code snippet)
- DAST finding evidence (URL, method, PoC)
- Heuristic match score

AI provides:
- Confirmation status
- Confidence score
- Exploitability assessment
- Clear reasoning
```

### 3. Results Generation

Each correlation includes:
- Status (confirmed/partial/not_verified/no_coverage)
- Confidence score
- Exploitability level (trivial/moderate/complex/theoretical)
- Reasoning
- PoC exploit from DAST (if available)
- Match score
- Summaries of both findings

## Installation

The correlator is part of the Argus Security Action:

```bash
cd argus-action/scripts
pip install -r ../requirements.txt
```

## Usage

### CLI Usage

```bash
# Basic usage with AI verification
python scripts/sast_dast_correlator.py \
  --sast-file sast-findings.json \
  --dast-file dast-findings.json \
  --output-file correlation-results.json

# Without AI (heuristics only)
python scripts/sast_dast_correlator.py \
  --sast-file sast-findings.json \
  --dast-file dast-findings.json \
  --output-file correlation-results.json \
  --no-ai

# Export as Markdown report
python scripts/sast_dast_correlator.py \
  --sast-file sast-findings.json \
  --dast-file dast-findings.json \
  --output-file correlation-report.md \
  --format markdown

# Enable debug logging
python scripts/sast_dast_correlator.py \
  --sast-file sast-findings.json \
  --dast-file dast-findings.json \
  --output-file correlation-results.json \
  --debug
```

### Programmatic Usage

```python
from sast_dast_correlator import SASTDASTCorrelator, CorrelationStatus

# Initialize correlator
correlator = SASTDASTCorrelator()

# Load findings (normalized format)
sast_findings = [...]  # List of SAST findings
dast_findings = [...]  # List of DAST findings

# Run correlation
results = correlator.correlate(
    sast_findings=sast_findings,
    dast_findings=dast_findings,
    use_ai=True  # Enable AI verification
)

# Process results
for result in results:
    if result.status == CorrelationStatus.CONFIRMED:
        print(f"✓ Confirmed exploitable: {result.sast_finding_id}")
        print(f"  Confidence: {result.confidence:.2f}")
        print(f"  Exploitability: {result.exploitability}")
        print(f"  PoC: {result.poc_exploit}")

# Export results
correlator.export_results(results, "output.json", format="json")
```

### Integration with Argus Workflow

```python
from run_ai_audit import run_security_audit
from sast_dast_correlator import SASTDASTCorrelator

# 1. Run SAST scans
sast_results = run_security_audit(
    scanners=["semgrep", "trufflehog"],
    ai_triage=True
)

# 2. Run DAST scans (using external DAST tool)
# Example: ZAP, Burp Suite, Nuclei
dast_results = run_dast_scan(target="http://localhost:8000")

# 3. Correlate results
correlator = SASTDASTCorrelator()
correlations = correlator.correlate(
    sast_findings=sast_results["findings"],
    dast_findings=dast_results["findings"]
)

# 4. Filter to confirmed exploitable findings
confirmed = [
    c for c in correlations
    if c.status == CorrelationStatus.CONFIRMED
    and c.confidence >= 0.8
]

# 5. Prioritize remediation
print(f"Found {len(confirmed)} confirmed exploitable vulnerabilities")
```

## Input Format

### SAST Findings

Findings should be in the normalized Argus format:

```json
{
  "id": "sast-001",
  "path": "src/api/users.py",
  "line": 42,
  "rule_id": "python.django.security.injection.sql.sql-injection",
  "rule_name": "SQL Injection",
  "severity": "high",
  "cwe": "CWE-89",
  "evidence": {
    "message": "Potential SQL injection vulnerability",
    "snippet": "cursor.execute('SELECT * FROM users WHERE id = ' + user_id)"
  }
}
```

### DAST Findings

```json
{
  "id": "dast-001",
  "path": "/api/users",
  "rule_id": "sql-injection",
  "rule_name": "SQL Injection",
  "severity": "high",
  "cwe": "CWE-89",
  "evidence": {
    "url": "http://localhost:8000/api/users?id=1' OR '1'='1",
    "method": "GET",
    "message": "SQL injection vulnerability confirmed",
    "poc": "curl 'http://localhost:8000/api/users?id=1%27%20OR%20%271%27=%271'"
  }
}
```

## Output Format

### JSON Output

```json
{
  "metadata": {
    "total_findings": 10,
    "confirmed": 3,
    "partial": 2,
    "not_verified": 1,
    "no_coverage": 4
  },
  "correlations": [
    {
      "sast_finding_id": "sast-001",
      "dast_finding_id": "dast-001",
      "status": "confirmed",
      "confidence": 0.95,
      "exploitability": "trivial",
      "reasoning": "DAST successfully exploited SQL injection at /api/users endpoint...",
      "poc_exploit": "curl 'http://localhost:8000/api/users?id=1%27%20OR%20%271%27=%271'",
      "match_score": 0.98,
      "sast_summary": {
        "id": "sast-001",
        "type": "SQL Injection",
        "path": "src/api/users.py",
        "severity": "high",
        "cwe": "CWE-89"
      },
      "dast_summary": {
        "id": "dast-001",
        "type": "SQL Injection",
        "path": "/api/users",
        "severity": "high",
        "cwe": "CWE-89"
      }
    }
  ]
}
```

## Configuration

### AI Provider Configuration

The correlator uses the same AI provider configuration as the main Argus system:

```bash
# Anthropic (recommended for security analysis)
export ANTHROPIC_API_KEY="sk-ant-..."

# OpenAI
export OPENAI_API_KEY="sk-..."

# Ollama (local, free)
export OLLAMA_ENDPOINT="http://localhost:11434"
export AI_PROVIDER="ollama"
```

### Cost Considerations

- **With AI verification**: ~$0.02-0.05 per finding correlation (depends on provider)
- **Without AI (heuristics only)**: Free, but lower accuracy
- **Tip**: Use `--no-ai` for initial triage, then AI verify high-priority findings

## Use Cases

### 1. Prioritizing Remediation

```bash
# Find all confirmed exploitable findings
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file correlations.json

# Filter to high-confidence confirmed
jq '.correlations[] | select(.status == "confirmed" and .confidence >= 0.8)' \
  correlations.json > priority-fixes.json
```

### 2. Validating SAST Findings

```bash
# Check if SAST findings are exploitable
python scripts/sast_dast_correlator.py \
  --sast-file semgrep-results.json \
  --dast-file zap-results.json \
  --output-file validation.json

# Count false positives (no DAST confirmation)
jq '[.correlations[] | select(.status == "not_verified" or .status == "no_dast_coverage")] | length' \
  validation.json
```

### 3. DAST Coverage Analysis

```bash
# Identify SAST findings without DAST coverage
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file correlations.json

# Extract findings needing DAST tests
jq '.correlations[] | select(.status == "no_dast_coverage")' \
  correlations.json > need-dast-coverage.json
```

### 4. Security Metrics

```bash
# Generate correlation report
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file report.md \
  --format markdown

# Metrics to track:
# - Confirmation rate: (confirmed / total) %
# - DAST coverage: (total - no_coverage) / total %
# - Exploitability distribution
```

## Vulnerability Type Support

The correlator recognizes and normalizes these vulnerability types:

| Vulnerability Type | Aliases | CWE IDs |
|-------------------|---------|---------|
| SQL Injection | sqli, sql_injection | CWE-89 |
| Cross-Site Scripting (XSS) | cross-site-scripting | CWE-79 |
| Command Injection | os-command-injection | CWE-78, CWE-77 |
| Path Traversal | directory-traversal | CWE-22 |
| SSRF | server-side-request-forgery | CWE-918 |
| XXE | xml-external-entity | CWE-611 |
| CSRF | cross-site-request-forgery | CWE-352 |
| Open Redirect | url-redirection, unvalidated-redirect | CWE-601 |

## Limitations

1. **Path Mapping Accuracy**: Fuzzy matching may miss correlations if:
   - Application uses non-standard routing (e.g., catch-all routes)
   - File paths don't reflect URL structure
   - Complex framework routing (e.g., Django's `urls.py` patterns)

2. **AI Dependency**: Best results require AI verification
   - Heuristics alone may produce false correlations
   - Consider using AI for final validation even if using `--no-ai` for initial triage

3. **DAST Coverage**: Correlation quality depends on DAST test coverage
   - No DAST test = can't confirm exploitability
   - Incomplete DAST scans will show many "no_coverage" results

4. **Finding Format**: Both SAST and DAST findings must be in normalized format
   - Use Argus normalizers or convert findings manually
   - See `scripts/normalizer/` for examples

## Troubleshooting

### Issue: "No DAST candidates found for any SAST findings"

**Cause**: Path/URL mapping mismatch or different vulnerability types

**Solution**:
```bash
# Enable debug logging to see matching details
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file out.json \
  --debug

# Check that paths/URLs are compatible
# Example: src/api/users.py should match /api/users
```

### Issue: "LLM Manager initialization failed"

**Cause**: No AI provider configured or invalid API key

**Solution**:
```bash
# Set API key
export ANTHROPIC_API_KEY="sk-ant-..."

# Or use heuristics-only mode
python scripts/sast_dast_correlator.py \
  --sast-file sast.json \
  --dast-file dast.json \
  --output-file out.json \
  --no-ai
```

### Issue: "Low confidence correlations"

**Cause**: Insufficient evidence or ambiguous matching

**Solution**:
```bash
# Review match scores in debug output
# Improve DAST coverage for critical endpoints
# Ensure SAST and DAST findings have complete metadata (CWE, type, etc.)
```

## Best Practices

1. **Normalize Findings First**: Use Argus normalizers to ensure consistent format
2. **Run Comprehensive DAST**: Better DAST coverage = better correlation accuracy
3. **Use AI for High-Value Findings**: Enable AI verification for critical/high severity findings
4. **Track Metrics**: Monitor confirmation rates to improve SAST/DAST coverage over time
5. **Iterative Refinement**: Use "no_coverage" results to expand DAST test suites

## Contributing

To extend the correlator:

1. **Add Vulnerability Types**: Update `VULN_TYPE_ALIASES` and `CWE_TO_VULN_TYPE`
2. **Improve Path Mapping**: Enhance `_extract_endpoint_from_path()` for your framework
3. **Custom Matching Logic**: Override `_calculate_match_score()` for domain-specific needs
4. **AI Prompt Tuning**: Modify `_build_correlation_prompt()` to improve verification accuracy

## See Also

- [Argus Main Documentation](../README.md)
- [AI Triage Strategy](adrs/0003-ai-triage-strategy.md)
- [Multi-Scanner Architecture](adrs/0002-multi-scanner-architecture.md)
- [Scanner Reference](references/scanner-reference.md)
