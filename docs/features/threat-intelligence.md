# Threat Intelligence Enrichment

## Overview

The Threat Intelligence Enrichment feature enhances security findings with real-time threat context from multiple authoritative sources. It prioritizes vulnerabilities that are actively exploited in the wild, helping teams focus on real threats rather than theoretical vulnerabilities.

## How It Works

When Argus discovers a CVE, the threat intelligence enricher:

1. **Queries Multiple Sources**:
   - CVE/NVD database
   - CISA KEV (Known Exploited Vulnerabilities) catalog
   - EPSS (Exploit Prediction Scoring System)
   - GitHub Advisory Database
   - OSV (Open Source Vulnerabilities)
   - Exploit databases (Metasploit, Exploit-DB)

2. **Enriches Findings with Context**:
   - Exploit probability score (EPSS)
   - Active exploitation status (KEV catalog)
   - Public exploit availability
   - Exploit maturity (PoC vs weaponized)
   - Dark web exploit pricing (when available)

3. **Adjusts Priority**:
   - Escalates severity to "critical" if in KEV catalog
   - Adds exploit probability to description
   - Updates exploitability rating based on real-world data

## Usage

### CLI Usage

```bash
# Enrich findings with threat intelligence
./scripts/argus threat-intel enrich --findings findings.json --output enriched.json

# Threat intel is automatically applied during scans when enabled (default)
python scripts/run_ai_audit.py --enable-threat-intel
```

### Python API

```python
from hybrid_analyzer import HybridSecurityAnalyzer

# Create analyzer with threat intel enabled (default)
analyzer = HybridSecurityAnalyzer(
    enable_threat_intel=True  # Enabled by default
)

# Run analysis - threat intel automatically enriches findings
result = analyzer.analyze(target_path="/path/to/repo")
```

### Standalone Usage

```python
from threat_intel_enricher import ThreatIntelEnricher

enricher = ThreatIntelEnricher()

# Enrich a specific CVE
threat_context = enricher.enrich_cve("CVE-2021-44228")  # Log4Shell

print(f"In KEV catalog: {threat_context['in_kev_catalog']}")
print(f"EPSS score: {threat_context['epss_score']:.1%}")
print(f"Exploit available: {threat_context['exploit_available']}")
```

## Configuration

Threat intelligence enrichment is **enabled by default** and requires no configuration. To disable:

```bash
python scripts/run_ai_audit.py --enable-threat-intel=false
```

## Output Format

Enriched findings include additional metadata:

```json
{
  "finding_id": "trivy-CVE-2021-44228",
  "cve_id": "CVE-2021-44228",
  "severity": "critical",
  "exploitability": "trivial",
  "description": "[EPSS: 97.5% exploit probability] [Public exploit available] Apache Log4j2 RCE...",
  "threat_context": {
    "in_kev_catalog": true,
    "kev_date_added": "2021-12-10",
    "epss_score": 0.975,
    "exploit_available": true,
    "exploit_maturity": "weaponized",
    "references": [
      "https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
      "https://nvd.nist.gov/vuln/detail/CVE-2021-44228"
    ]
  }
}
```

## Integration

Threat intelligence enrichment runs automatically as part of the hybrid analyzer workflow:

1. **Phase 1**: Scanners detect CVEs (Trivy, etc.)
2. **Threat Intel Phase**: Enriches CVEs with real-time threat context
3. **AI Triage Phase**: AI considers threat intel when prioritizing findings
4. **Output**: Findings include threat intelligence metadata

## Best Practices

1. **Prioritize KEV-Listed CVEs**: Always fix vulnerabilities in the CISA KEV catalog first
2. **Consider EPSS Scores**: Focus on CVEs with EPSS > 0.5 (50%+ exploit probability)
3. **Monitor Exploit Availability**: Public exploits mean higher urgency
4. **Review References**: Check linked threat intel sources for detailed context
5. **Update Regularly**: Threat intelligence data refreshes automatically on each scan

## Sources

Argus threat intelligence integrates data from:

- **CISA KEV**: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- **NVD**: https://nvd.nist.gov/
- **EPSS**: https://www.first.org/epss/
- **GitHub Advisory**: https://github.com/advisories
- **OSV**: https://osv.dev/

## Troubleshooting

**Q: Why are some CVEs not enriched?**

A: Enrichment only applies to findings with CVE IDs. Non-CVE findings (SAST, secrets, etc.) are not enriched.

**Q: How fresh is the threat intelligence data?**

A: Data is fetched in real-time during scans. CISA KEV updates daily, EPSS updates weekly, NVD updates continuously.

**Q: Can I use my own threat intelligence feeds?**

A: Yes! Extend `ThreatIntelEnricher` class to add custom sources. See plugin documentation.

**Q: Does this send CVE data externally?**

A: Yes, CVE IDs are sent to public APIs (NVD, CISA, EPSS) to fetch threat context. No proprietary code is sent.

## Performance

- **Overhead**: ~0.5-2 seconds per unique CVE
- **Caching**: Threat intel data is cached for 24 hours
- **Rate Limiting**: Respects API rate limits with automatic backoff

## Example Output

```
🌐 Threat Intelligence Enrichment:
   Total findings: 47
   Enriched: 12 CVEs

   Priority Escalations:
   - CVE-2021-44228 (Log4Shell): Critical - In KEV catalog, 97.5% EPSS, public exploit
   - CVE-2022-0543 (Redis RCE): Critical - In KEV catalog, 89.2% EPSS, weaponized
   - CVE-2023-1234 (Example): High - 65.3% EPSS, PoC available
```

---

**Related Documentation:**
- [Hybrid Analyzer](../architecture/overview.md)
- [AI Triage Strategy](../adrs/0003-ai-triage-strategy.md)
- [Scanner Reference](../references/scanner-reference.md)
