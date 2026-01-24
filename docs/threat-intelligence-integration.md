# Threat Intelligence Integration

## Overview

The Threat Intelligence Enricher (`scripts/threat_intel_enricher.py`) enriches security findings with real-time threat intelligence from multiple authoritative sources. It provides context-aware prioritization by correlating CVE findings with active exploitation data, EPSS scores, and public exploit availability.

## Features

### Multiple Intelligence Sources

1. **CISA KEV Catalog** - Known Exploited Vulnerabilities actively exploited in the wild
2. **EPSS API** - Exploit Prediction Scoring System (probability of exploitation in next 30 days)
3. **NVD API** - National Vulnerability Database (CVSS scores, CWE mappings, references)
4. **GitHub Advisory Database** - Security advisories with patch information
5. **OSV API** - Open Source Vulnerabilities database

### Enrichment Capabilities

- **CVE Lookup**: Automatic CVE extraction and enrichment
- **CVSS Scoring**: Base scores with severity levels (v3.1 preferred)
- **EPSS Scores**: Exploitation probability (0.0-1.0) with percentile rankings
- **KEV Membership**: Active exploitation status with remediation deadlines
- **Exploit Detection**: Public exploit availability from multiple sources
- **Patch Status**: Vendor patch availability and URLs
- **Trending Detection**: Recently exploited or high-risk vulnerabilities
- **Risk Scoring**: Composite risk score (0.0-10.0) factoring all intelligence

### Intelligent Prioritization

The enricher automatically adjusts finding priorities based on threat context:

**Priority Boosts:**
- ⚠️ **CRITICAL** - In CISA KEV catalog (actively exploited)
- ⚠️ **CRITICAL** - EPSS > 0.8 + public exploit available
- 🔴 **HIGH** - EPSS > 0.5 (50%+ exploitation probability)
- 🔴 **HIGH** - Multiple public exploits (2+)
- 🔴 **HIGH** - CVSS score ≥ 9.0 (CRITICAL severity)
- 🟡 **MEDIUM** - Single public exploit available
- 🟡 **MEDIUM** - CVSS score ≥ 7.0 (HIGH severity)

**Priority Downgrades:**
- 🔵 **LOW** - EPSS < 0.1 with no public exploits

### Performance Features

- **Intelligent Caching**: 24-hour TTL for all API responses
- **Rate Limiting**: Automatic rate limiting per API source
- **Graceful Degradation**: Continues enrichment even if some APIs fail
- **Progress Tracking**: Rich progress bars (when `rich` is available)
- **Batch Processing**: Efficient processing of large finding sets

## Installation

No additional dependencies beyond Argus requirements:

```bash
# Standard library only (urllib, json, dataclasses)
# Optional: rich for progress bars (already in requirements.txt)
pip install rich
```

## Usage

### Command Line

```bash
# Basic usage
python scripts/threat_intel_enricher.py \
  --findings trivy-results.json \
  --output enriched-findings.json

# With progress bar
python scripts/threat_intel_enricher.py \
  --findings findings.json \
  --output enriched.json \
  --progress

# Custom cache directory
python scripts/threat_intel_enricher.py \
  --findings findings.json \
  --output enriched.json \
  --cache-dir /tmp/threat-intel-cache

# Debug mode
python scripts/threat_intel_enricher.py \
  --findings findings.json \
  --output enriched.json \
  --debug
```

### Python API

```python
from pathlib import Path
from threat_intel_enricher import ThreatIntelEnricher

# Initialize enricher
enricher = ThreatIntelEnricher(
    cache_dir=Path(".argus-cache/threat-intel"),
    use_progress=True
)

# Load findings from scanner
findings = [
    {
        "id": "trivy-cve-2024-1234",
        "description": "CVE-2024-1234: Remote code execution in example-lib",
        "severity": "HIGH",
        "package": "example-lib@1.0.0"
    }
]

# Enrich with threat intelligence
enriched = enricher.enrich_findings(findings)

# Access enriched data
for finding in enriched:
    print(f"CVE: {finding.threat_context.cve_id}")
    print(f"Original Priority: {finding.original_priority}")
    print(f"Adjusted Priority: {finding.adjusted_priority}")
    print(f"Risk Score: {finding.risk_score:.2f}/10.0")
    print(f"Action: {finding.recommended_action}")
    print(f"Deadline: {finding.remediation_deadline}")

    if finding.threat_context.in_kev_catalog:
        print("⚠️  WARNING: Actively exploited in the wild!")

    if finding.threat_context.epss_score:
        print(f"Exploitation probability: {finding.threat_context.epss_score:.1%}")

# Export to file
enricher.export_enriched_findings(enriched, Path("enriched.json"))
```

### Integration with Argus Workflow

```python
from run_ai_audit import run_security_audit
from threat_intel_enricher import ThreatIntelEnricher

# 1. Run security scanners
findings = run_security_audit(
    project_type="backend-api",
    enable_trivy=True,
    enable_semgrep=True
)

# 2. Enrich with threat intelligence
enricher = ThreatIntelEnricher(use_progress=True)
enriched = enricher.enrich_findings(findings)

# 3. Filter for critical threats
critical_threats = [
    f for f in enriched
    if f.adjusted_priority == "CRITICAL" or f.threat_context.in_kev_catalog
]

# 4. Generate report
for threat in critical_threats:
    print(f"🚨 {threat.threat_context.cve_id}")
    print(f"   {threat.recommended_action}")
    for reason in threat.priority_boost_reasons:
        print(f"   - {reason}")
```

## Output Format

### Enriched Finding Structure

```json
{
  "finding": {
    "id": "trivy-cve-2024-1234",
    "description": "CVE-2024-1234: Remote code execution vulnerability",
    "severity": "HIGH",
    "scanner": "trivy"
  },
  "threat_context": {
    "cve_id": "CVE-2024-1234",
    "cvss_score": 9.8,
    "cvss_severity": "CRITICAL",
    "cvss_vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
    "epss_score": 0.89,
    "epss_percentile": 98.5,
    "in_kev_catalog": true,
    "kev_date_added": "2024-01-15",
    "kev_due_date": "2024-02-05",
    "kev_action_required": "Apply updates per vendor instructions",
    "public_exploit_available": true,
    "exploit_sources": [
      "https://www.exploit-db.com/exploits/51234",
      "https://github.com/attacker/cve-2024-1234-poc"
    ],
    "exploit_count": 2,
    "trending": true,
    "vendor_patch_available": true,
    "patch_url": "https://github.com/advisories/GHSA-xxxx-yyyy-zzzz",
    "github_advisories": [
      {
        "id": "GHSA-xxxx-yyyy-zzzz",
        "severity": "CRITICAL",
        "published_at": "2024-01-15T10:00:00Z",
        "patched_versions": ">=1.0.1"
      }
    ],
    "cwe_ids": ["CWE-787", "CWE-89"],
    "last_updated": "2024-01-15T12:00:00.000000",
    "confidence": 1.0
  },
  "priority": {
    "original": "HIGH",
    "adjusted": "CRITICAL",
    "boost_reasons": [
      "In CISA KEV catalog - exploited in wild since 2024-01-15",
      "EPSS score 0.890 (top 1.5%) - high exploitation risk",
      "2 public exploits available",
      "Trending vulnerability - recent active exploitation"
    ],
    "downgrade_reasons": []
  },
  "risk_score": 9.8,
  "remediation": {
    "action": "🚨 URGENT: Apply updates per vendor instructions",
    "deadline": "2024-02-05T00:00:00.000000"
  }
}
```

## Intelligence Sources

### CISA KEV Catalog

**URL**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog

**Purpose**: Authoritative list of CVEs actively exploited in the wild

**Update Frequency**: Daily

**What It Tells You**:
- CVE is being actively exploited by threat actors
- Remediation deadline (typically 21 days for federal agencies)
- Required action (patch, workaround, etc.)

**Weight in Prioritization**: HIGHEST - Automatic CRITICAL priority

### EPSS (Exploit Prediction Scoring System)

**URL**: https://www.first.org/epss/

**Purpose**: Machine learning-based probability of exploitation within 30 days

**Update Frequency**: Daily

**What It Tells You**:
- Probability score (0.0-1.0) of exploitation
- Percentile ranking vs all CVEs

**Weight in Prioritization**:
- EPSS > 0.8: CRITICAL (with exploit)
- EPSS > 0.5: HIGH
- EPSS < 0.1: Consider downgrade

### NVD (National Vulnerability Database)

**URL**: https://nvd.nist.gov/

**Purpose**: Comprehensive vulnerability database with CVSS scores

**Update Frequency**: Continuous

**What It Tells You**:
- CVSS base score (0.0-10.0)
- Severity level (LOW/MEDIUM/HIGH/CRITICAL)
- CWE (Common Weakness Enumeration) mappings
- Attack vector, complexity, privileges required
- References to exploits, patches, advisories

**Weight in Prioritization**:
- CVSS ≥ 9.0: HIGH boost
- CVSS ≥ 7.0: MEDIUM boost

### GitHub Advisory Database

**URL**: https://github.com/advisories

**Purpose**: Security advisories for open source projects

**Update Frequency**: Real-time

**What It Tells You**:
- Affected package versions
- Patched versions available
- Severity assessment
- Mitigation strategies

**Weight in Prioritization**: Indicates patch availability

### OSV (Open Source Vulnerabilities)

**URL**: https://osv.dev/

**Purpose**: Distributed vulnerability database for open source

**Update Frequency**: Real-time

**What It Tells You**:
- Affected versions across ecosystems (npm, PyPI, Go, etc.)
- Detailed references
- Severity scores

**Weight in Prioritization**: Supplementary context and references

## Caching Strategy

### Cache Directory Structure

```
.argus-cache/threat-intel/
├── kev_catalog.json           # CISA KEV catalog (24h TTL)
├── epss_CVE-2024-1234.json    # EPSS scores per CVE (24h TTL)
├── nvd_CVE-2024-1234.json     # NVD data per CVE (24h TTL)
├── github_CVE-2024-1234.json  # GitHub advisories (24h TTL)
└── osv_CVE-2024-1234.json     # OSV data per CVE (24h TTL)
```

### Cache Behavior

- **TTL**: 24 hours for all cached data
- **Storage**: JSON files with modification time tracking
- **Invalidation**: Automatic on age; manual via cache directory deletion
- **Hit Rate**: Typically 80-90% for repeated scans
- **Performance**: 10-100x faster for cached data

### Manual Cache Management

```bash
# Clear all threat intel cache
rm -rf .argus-cache/threat-intel/

# Clear only KEV catalog (force refresh)
rm .argus-cache/threat-intel/kev_catalog.json

# View cache size
du -sh .argus-cache/threat-intel/
```

## Rate Limiting

### Per-Source Limits

| Source | Rate Limit | Delay Between Calls |
|--------|-----------|---------------------|
| CISA KEV | None | 600ms (default) |
| EPSS API | ~100/min | 600ms |
| NVD API (no key) | 5 per 30 seconds | **6 seconds** |
| GitHub API | 60/hour (unauthenticated) | 600ms |
| OSV API | ~100/min | 600ms |

**Note**: NVD requires 6-second delays without an API key. With an API key (not implemented), this reduces to 50ms.

### Expected Performance

- **Small repos** (10 CVEs): ~1 minute (first run), ~5 seconds (cached)
- **Medium repos** (50 CVEs): ~5 minutes (first run), ~15 seconds (cached)
- **Large repos** (200 CVEs): ~20 minutes (first run), ~1 minute (cached)

## Statistics and Reporting

### Console Output Example

```
======================================================================
📊 Threat Intelligence Enrichment Summary
======================================================================
Total CVEs enriched:         47
In CISA KEV catalog:         3 (actively exploited)
High EPSS (>0.5):            12 (likely to be exploited)
Public exploits available:   8
GitHub advisories found:     15
OSV entries found:           23
Priority boosted:            18
Priority downgraded:         5
Average risk score:          6.73/10.0

Cache performance:
  Cache hits:                132
  Cache misses:              18
  API errors:                2
======================================================================
```

## Error Handling

The enricher is designed for resilient operation:

### Graceful Degradation

- **API Failures**: Continues with other sources if one fails
- **Network Issues**: Uses cached data when available
- **Missing Data**: Returns partial enrichment with confidence score
- **Rate Limits**: Automatically backs off and retries

### Confidence Scoring

Each enriched finding includes a confidence score (0.0-1.0):

```python
# Confidence calculation
data_sources_successful = 0
if kev_data: data_sources_successful += 1
if epss_data: data_sources_successful += 1
if nvd_data: data_sources_successful += 1
if github_data: data_sources_successful += 1
if osv_data: data_sources_successful += 1

confidence = data_sources_successful / 5.0
```

**Interpretation**:
- `1.0`: All sources successful
- `0.8`: 4 out of 5 sources
- `0.6`: 3 out of 5 sources (minimum for reliable data)
- `<0.6`: Limited data, treat with caution

## Best Practices

### 1. Run After Dependency Scanning

Threat intelligence is most valuable for CVE findings from Trivy, not code issues from Semgrep:

```bash
# First: Run Trivy to find CVEs
trivy fs --format json --output trivy.json .

# Then: Enrich CVE findings
python scripts/threat_intel_enricher.py \
  --findings trivy.json \
  --output enriched-trivy.json
```

### 2. Use Caching for CI/CD

Enable caching in CI pipelines to avoid rate limits:

```yaml
# GitHub Actions example
- name: Cache Threat Intel
  uses: actions/cache@v4
  with:
    path: .argus-cache/threat-intel
    key: threat-intel-${{ github.run_id }}
    restore-keys: threat-intel-

- name: Enrich Findings
  run: |
    python scripts/threat_intel_enricher.py \
      --findings trivy.json \
      --output enriched.json
```

### 3. Focus on Critical Threats

Filter for actionable intelligence:

```python
# Only act on KEV or high EPSS
actionable = [
    f for f in enriched
    if f.threat_context.in_kev_catalog
    or (f.threat_context.epss_score and f.threat_context.epss_score > 0.7)
]
```

### 4. Automate Deadline Tracking

Use remediation deadlines for SLA tracking:

```python
import json
from datetime import datetime

# Load enriched findings
with open("enriched.json") as f:
    findings = json.load(f)

# Group by deadline
for finding in findings:
    deadline = finding["remediation"]["deadline"]
    if deadline:
        deadline_dt = datetime.fromisoformat(deadline)
        days_until = (deadline_dt - datetime.utcnow()).days

        if days_until < 0:
            print(f"⚠️  OVERDUE: {finding['threat_context']['cve_id']}")
        elif days_until < 7:
            print(f"🔴 DUE SOON: {finding['threat_context']['cve_id']} ({days_until} days)")
```

### 5. Monitor Trending Threats

Track trending vulnerabilities for emerging risks:

```python
trending = [
    f for f in enriched
    if f.threat_context.trending
]

if trending:
    print(f"🔥 {len(trending)} trending vulnerabilities detected!")
    for f in trending:
        print(f"  - {f.threat_context.cve_id}: {f.recommended_action}")
```

## Troubleshooting

### Issue: API Errors (403 Forbidden)

**Cause**: Network restrictions or proxy issues

**Solution**:
```bash
# Check internet connectivity
curl -I https://www.cisa.gov/

# Use proxy if needed
export HTTP_PROXY=http://proxy.example.com:8080
export HTTPS_PROXY=http://proxy.example.com:8080
```

### Issue: High API Error Rate

**Cause**: Rate limiting or transient failures

**Solution**: API errors are tracked in stats. If >20% error rate:
1. Check cache directory exists and is writable
2. Increase delays in code if rate limited
3. Consider running during off-peak hours

### Issue: No CVEs Enriched

**Cause**: Findings don't contain CVE identifiers

**Solution**: Ensure findings include CVE IDs in description/title/cve fields:

```python
# Check if findings have CVEs
import re
cve_pattern = re.compile(r"CVE-\d{4}-\d{4,}")

for finding in findings:
    text = str(finding)
    if cve_pattern.search(text):
        print(f"✓ Has CVE: {finding['id']}")
    else:
        print(f"✗ No CVE: {finding['id']}")
```

### Issue: Slow Performance

**Cause**: NVD rate limiting (6 second delay per CVE)

**Solutions**:
1. Enable caching (automatic, but verify `.argus-cache/` is writable)
2. Process findings incrementally (new findings only)
3. Consider NVD API key (requires code modification)

## Future Enhancements

Potential improvements for future versions:

1. **NVD API Key Support**: Reduce rate limit from 6s to 50ms per request
2. **VulnDB Integration**: Commercial vulnerability intelligence
3. **Social Media Trending**: Twitter/Reddit mentions of CVEs
4. **Exploit-DB API**: Direct exploit availability checking
5. **CVSS Temporal Scoring**: Factor in exploit maturity and patch availability
6. **ML-Based Prioritization**: Train model on historical exploitation data
7. **Threat Actor Attribution**: Link CVEs to known threat actor TTPs
8. **Remediation Tracking**: Mark findings as patched/mitigated
9. **Email Alerts**: Notify on KEV additions or trending threats
10. **Dashboard Integration**: Real-time visualization of threat landscape

## References

- [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog)
- [EPSS Project](https://www.first.org/epss/)
- [NVD API Documentation](https://nvd.nist.gov/developers)
- [GitHub Advisory Database](https://github.com/advisories)
- [OSV Documentation](https://osv.dev/)
- [CVSS v3.1 Specification](https://www.first.org/cvss/v3.1/specification-document)
