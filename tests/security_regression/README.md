# CVE Validation Infrastructure for Deep Analysis

This directory contains a comprehensive CVE validation framework to measure the effectiveness of Argus Deep Analysis against real-world disclosed vulnerabilities.

## Overview

The validation infrastructure:
- Uses **8 real CVEs** from popular open-source projects
- Covers 5 vulnerability types: SQL Injection, Path Traversal, XSS, SSRF, Command Injection
- Automatically clones vulnerable versions, runs Deep Analysis, and measures detection accuracy
- Calculates industry-standard metrics: Precision, Recall, F1 Score, Detection Rate

## Quick Start

### Run Full Validation

```bash
# Validate all test cases with Deep Analysis in full mode
python scripts/validate_deep_analysis.py --mode full

# Run dry-run to see what would be tested (no actual cloning/analysis)
python scripts/validate_deep_analysis.py --dry-run

# Test a specific CVE
python scripts/validate_deep_analysis.py --test-case CVE-2024-23334 --mode full

# Use conservative mode (semantic + proactive only)
python scripts/validate_deep_analysis.py --mode conservative

# Enable verbose logging
python scripts/validate_deep_analysis.py --mode full --verbose
```

### Expected Runtime

- **Dry Run:** <1 second
- **Single CVE:** 2-5 minutes (clone + analysis)
- **Full Suite (6 testable CVEs):** 10-20 minutes
- Note: 2 CVEs are skipped due to large codebases (GitLab, CPython)

## Files Structure

```
tests/security_regression/
├── README.md                    # This file
├── cve_test_cases.json         # CVE metadata and expected findings
├── validation_report.md        # Template for validation reports
├── validation_results.json     # Generated: validation metrics (JSON)
├── validation_results.md       # Generated: validation report (Markdown)
└── latest_results.json         # Previous run results
```

## CVE Test Cases

### Testable CVEs (6)

| CVE ID | Project | Type | Severity | CVSS | Notes |
|--------|---------|------|----------|------|-------|
| CVE-2024-23334 | aiohttp | Path Traversal | High | 7.5 | Python async HTTP library |
| CVE-2024-22203 | whoogle-search | SSRF | High | 8.6 | Privacy-focused search engine |
| CVE-2024-22205 | whoogle-search | XSS | Medium | 6.1 | Same project, different vuln |
| CVE-2024-11831 | serialize-javascript | XSS | Medium | 5.4 | JavaScript serialization lib |
| CVE-2024-27956 | wp-automatic | SQL Injection | Critical | 9.8 | WordPress plugin |
| CVE-2024-32640 | mura-cms | SQL Injection | High | 8.1 | ColdFusion CMS |

### Skipped CVEs (2)

| CVE ID | Project | Reason |
|--------|---------|--------|
| CVE-2023-2825 | GitLab | Large codebase (>100 files) |
| CVE-2024-9287 | CPython | Large codebase (>100 files) |

## How It Works

### 1. Test Case Loading
Reads `cve_test_cases.json` which contains:
- Repository URL and vulnerable commit SHA
- Affected file paths and line numbers
- Expected detection patterns
- CWE, severity, CVSS score
- References to advisories and patches

### 2. Repository Cloning
For each CVE:
- Shallow clone the repository (`--depth 1` for speed)
- Checkout the specific vulnerable commit
- Clone timeout: 5 minutes (configurable)

### 3. Deep Analysis Execution
- Runs Deep Analysis on vulnerable files
- Uses pattern matching for vulnerability detection
- Detects: SQL injection, path traversal, XSS, SSRF, command injection
- Analysis timeout: 3 minutes per CVE (configurable)

### 4. Finding Evaluation
Compares findings against expected results:
- **True Positive (TP):** Correctly identified the CVE
- **False Negative (FN):** Missed the CVE
- **False Positive (FP):** Reported unrelated issues

### 5. Metrics Calculation
```
Precision = TP / (TP + FP)     # Accuracy of positive predictions
Recall = TP / (TP + FN)        # Coverage of actual positives
F1 Score = 2 * (P * R) / (P + R)  # Harmonic mean
Detection Rate = (TP / Total) * 100  # Percentage detected
```

### 6. Report Generation
Creates two reports:
- **JSON:** `validation_results.json` - Machine-readable metrics
- **Markdown:** `validation_results.md` - Human-readable analysis

## Configuration

### Environment Variables

```bash
# Deep Analysis mode (off, semantic-only, conservative, full)
export DEEP_ANALYSIS_MODE=full

# Maximum files to analyze per project
export DEEP_ANALYSIS_MAX_FILES=100

# Analysis timeout in seconds
export DEEP_ANALYSIS_TIMEOUT=180

# API cost ceiling in USD
export DEEP_ANALYSIS_COST_CEILING=5.0

# Enable dry run (no actual API calls)
export DEEP_ANALYSIS_DRY_RUN=false
```

### Test Case Configuration

Edit `cve_test_cases.json` > `validation_config`:

```json
{
  "validation_config": {
    "clone_timeout_seconds": 300,
    "analysis_timeout_seconds": 180,
    "temp_dir_prefix": "argus_cve_validation_",
    "exclude_large_repos": true,
    "max_repo_size_mb": 500,
    "focus_files_only": true,
    "skip_tests": ["CVE-2023-2825", "CVE-2024-9287"],
    "skip_reason": "Large codebase - exceeds 100 file limit"
  }
}
```

## Command Line Options

```
python scripts/validate_deep_analysis.py [OPTIONS]

Options:
  --test-cases PATH       Path to CVE test cases JSON
                         Default: tests/security_regression/cve_test_cases.json

  --mode {off,semantic-only,conservative,full}
                         Deep Analysis mode to test
                         Default: full

  --test-case CVE-ID     Run validation on specific CVE only
                         Example: --test-case CVE-2024-23334

  --output PATH          Output file for validation results
                         Default: tests/security_regression/validation_results.json

  --dry-run             Simulate validation without cloning/analysis

  --verbose             Enable verbose logging

  -h, --help            Show help message
```

## Interpreting Results

### Example Output

```
CVE VALIDATION SUMMARY
================================================================================
Total Cases:       8
Tested:            6
Skipped:           2
Errors:            0
--------------------------------------------------------------------------------
True Positives:    5  (CVEs detected)
False Negatives:   1  (CVEs missed)
False Positives:   3  (Wrong findings)
--------------------------------------------------------------------------------
Precision:         62.5%
Recall:            83.3%
F1 Score:          0.714
Detection Rate:    83.3%
Total Time:        623.5s
================================================================================
```

### Metrics Interpretation

**Precision (62.5%)**
- Out of 8 vulnerabilities reported (5 TP + 3 FP), 62.5% were correct
- Lower precision = more false alarms
- **Action:** Tighten detection patterns if <70%

**Recall (83.3%)**
- Out of 6 real CVEs, we detected 5 (83.3%)
- Lower recall = missing vulnerabilities
- **Action:** Expand detection coverage if <60%

**F1 Score (0.714)**
- Balanced measure: 0.714 is "Good" (0.0=worst, 1.0=perfect)
- Targets: >0.60 (Acceptable), >0.75 (Good), >0.85 (Excellent)

**Detection Rate (83.3%)**
- Found 5 out of 6 testable CVEs
- Target: >75% (3 out of 4 CVEs)

### Performance Targets

| Metric | Minimum | Target | Excellent |
|--------|---------|--------|-----------|
| Precision | 60% | 80% | 90% |
| Recall | 50% | 70% | 85% |
| F1 Score | 0.55 | 0.75 | 0.87 |
| Detection Rate | 60% | 75% | 90% |

## Adding New CVE Test Cases

### 1. Research CVE

Find CVEs with:
- Public GitHub repository
- Disclosed vulnerability with CVE ID
- Known vulnerable commit and fix commit
- Small codebase (<100 files preferred)
- Clear PoC or advisory

Good sources:
- GitHub Security Advisories: https://github.com/advisories
- CVE database: https://cve.mitre.org/
- Exploit-DB: https://www.exploit-db.com/
- Snyk Vulnerability DB: https://security.snyk.io/

### 2. Add to cve_test_cases.json

```json
{
  "id": "CVE-YYYY-XXXXX",
  "project": "project-name",
  "repo_url": "https://github.com/org/repo",
  "vulnerable_commit": "abc123def",
  "fixed_commit": "fix456ghi",
  "vulnerable_version": "1.2.3",
  "fixed_version": "1.2.4",
  "vuln_type": "sql_injection",
  "affected_file": "src/vulnerable.py",
  "affected_lines": [100, 150],
  "description": "Brief description of vulnerability",
  "cwe_id": "CWE-89",
  "severity": "high",
  "cvss_score": 8.5,
  "exploitation_difficulty": "low",
  "expected_finding": {
    "pattern": "regex.*pattern|alternate",
    "file_should_contain": "vulnerable.py",
    "severity_min": "medium"
  },
  "references": [
    "https://github.com/advisories/GHSA-xxxx-xxxx-xxxx"
  ],
  "notes": "Optional notes"
}
```

### 3. Update Metadata

```json
"metadata": {
  "version": "1.1",
  "created": "2026-01-29",
  "total_cases": 9
}
```

### 4. Test New Case

```bash
python scripts/validate_deep_analysis.py --test-case CVE-YYYY-XXXXX --verbose
```

## Troubleshooting

### Clone Failures

**Issue:** `Clone failed: Repository not found`
- **Solution:** Verify repo URL is correct and public
- **Solution:** Check if repo was moved/deleted
- **Solution:** Try manual clone: `git clone [url]`

**Issue:** `Clone timed out`
- **Solution:** Increase timeout in validation_config
- **Solution:** Check network connectivity
- **Solution:** Use `--verbose` to see git output

### Analysis Failures

**Issue:** `Affected file not found`
- **Solution:** Verify file path in test case
- **Solution:** File may have moved between versions
- **Solution:** Use glob pattern to find file: `affected_file_pattern`

**Issue:** `Deep analysis failed`
- **Solution:** Check ANTHROPIC_API_KEY is set
- **Solution:** Verify API quota/limits
- **Solution:** Enable `--verbose` for detailed errors

### Detection Issues

**Issue:** Too many False Positives
- **Solution:** Make detection patterns more specific
- **Solution:** Add context checks (e.g., function name)
- **Solution:** Increase confidence threshold

**Issue:** Too many False Negatives
- **Solution:** Expand detection patterns
- **Solution:** Add more vulnerability signatures
- **Solution:** Enable more Deep Analysis phases

## Continuous Validation

### CI/CD Integration

Add to GitHub Actions:

```yaml
name: Deep Analysis Validation

on:
  schedule:
    - cron: '0 0 * * 0'  # Weekly on Sunday
  workflow_dispatch:

jobs:
  validate:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3

      - name: Setup Python
        uses: actions/setup-python@v4
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -r requirements.txt

      - name: Run CVE Validation
        env:
          ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
        run: |
          python scripts/validate_deep_analysis.py --mode full

      - name: Upload Results
        uses: actions/upload-artifact@v3
        with:
          name: validation-results
          path: tests/security_regression/validation_results.*

      - name: Check Metrics
        run: |
          # Fail if detection rate < 70%
          python -c "
          import json
          with open('tests/security_regression/validation_results.json') as f:
              data = json.load(f)
              rate = data['metrics']['detection_rate']
              assert rate >= 70, f'Detection rate {rate}% < 70%'
          "
```

### Regression Tracking

Compare results over time:

```bash
# Save baseline
cp validation_results.json baseline_results.json

# After changes, compare
python scripts/compare_validations.py baseline_results.json validation_results.json
```

## Related Documentation

- [Deep Analysis Engine](../../scripts/argus_deep_analysis.py)
- [Hybrid Analyzer](../../scripts/hybrid_analyzer.py)
- [Security Testing Guide](../../docs/security-testing.md)
- [Contributing Guide](../../CONTRIBUTING.md)

## License

MIT License - See [LICENSE](../../LICENSE) file

## Support

For issues or questions:
- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Documentation: https://docs.argus-security.io
- Email: security@argus-security.io
