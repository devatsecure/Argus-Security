# Responsible Disclosure Workflow - Example

This example demonstrates the complete responsible disclosure workflow for Argus Security.

## Scenario

You've discovered 3 security vulnerabilities in an open-source project during an Argus Security scan:
- 1 Critical: Hardcoded AWS credentials
- 1 Critical: SQL Injection
- 1 High: XSS vulnerability

## Step-by-Step Example

### 1. Find Security Contact

```bash
python scripts/responsible_disclosure.py \
  --repo https://github.com/example/vulnerable-app \
  --find-contact
```

**Output:**
```
Finding security contact for https://github.com/example/vulnerable-app
Found SECURITY.md with contact: security@example.com

Security Contact Found:
  Method: security.md
  Contact: security@example.com
```

### 2. Generate Disclosure Email

```bash
python scripts/responsible_disclosure.py \
  --repo https://github.com/example/vulnerable-app \
  --report examples/sample_vulnerability_report.json \
  --severity critical \
  --generate-email
```

**Output:**
```
Disclosure email generated: disclosure_email_20260129_163000.txt
================================================================================
Subject: Security Vulnerability Disclosure - example/vulnerable-app

Dear example/vulnerable-app Maintainers,

I am writing to responsibly disclose security vulnerabilities discovered in
your project during an automated security audit...

[Full email content from template]
================================================================================
```

### 3. Create Tracking Entry

```bash
python scripts/responsible_disclosure.py \
  --repo https://github.com/example/vulnerable-app \
  --report examples/sample_vulnerability_report.json \
  --severity critical \
  --create
```

**Output:**
```
Finding security contact for https://github.com/example/vulnerable-app
Found SECURITY.md with contact: security@example.com

Disclosure tracking created: ARGUS-20260129-001
  Severity: critical
  Contact: security@example.com
  Deadline: 2026-04-29 (90 days)
Tracking saved to .argus/disclosures.json

Next steps:
1. Review generated email in disclosure_email_*.txt
2. Send to: security@example.com
3. Update status with: python responsible_disclosure.py --update ARGUS-20260129-001 --status acknowledged
```

### 4. Send Email and Wait

Send the generated email through your secure email client. The email includes:
- Professional introduction
- Summary of findings (3 vulnerabilities, 2 critical, 1 high)
- Request for preferred disclosure method
- 90-day disclosure timeline
- Offer to assist with remediation

### 5. Update Status After Acknowledgment

When maintainer responds (e.g., 3 days later):

```bash
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status acknowledged \
  --notes "Maintainer confirmed receipt on 2026-02-01, will review this week"
```

### 6. Share Technical Details

After maintainer confirms preferred method, send detailed report:

```bash
# Generate detailed technical report (example)
python scripts/run_ai_audit.py --project-type backend-api --output detailed_report.json
```

Then share via:
- GitHub Private Security Advisory (recommended)
- PGP-encrypted email
- Secure file sharing

### 7. Monitor Progress

List active disclosures:

```bash
python scripts/responsible_disclosure.py --list
```

**Output:**
```
Responsible Disclosure Tracking
================================================================================

📧 ARGUS-20260129-001 - example/vulnerable-app
   Severity: CRITICAL
   Status: acknowledged
   Contact: security@example.com
   Deadline: 2026-04-29 (87 days remaining)
   Response: Maintainer confirmed receipt on 2026-02-01, will review this week

================================================================================
```

### 8. Update When Patch Released

When maintainer releases fix (e.g., 3 weeks later):

```bash
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status patched \
  --notes "Fix released in v2.1.0 on 2026-02-20. All vulnerabilities addressed."
```

### 9. Coordinate Public Disclosure

30 days before deadline, coordinate disclosure:

```bash
# Check for approaching deadlines
python scripts/responsible_disclosure.py --check-overdue
```

Email maintainer:
```
Subject: Coordinating Public Disclosure - ARGUS-20260129-001

Hi [Maintainer],

Thank you for the prompt fix in v2.1.0! We'd like to coordinate public
disclosure of the security advisory.

Our original 90-day deadline is 2026-04-29. Since patches are available,
we propose disclosing on 2026-03-01 to give users time to upgrade.

Would this timeline work for you?
```

### 10. Public Disclosure

On agreed date (e.g., 2026-03-01):

```bash
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status disclosed \
  --notes "Publicly disclosed on 2026-03-01 via GitHub Security Advisory"
```

Publish:
- GitHub Security Advisory (make public)
- Blog post crediting maintainer
- Update documentation

## Timeline Overview

```
Day 0  (2026-01-29): Vulnerability discovered, private contact sent
Day 3  (2026-02-01): Maintainer acknowledges receipt
Day 7  (2026-02-05): Detailed technical report shared
Day 21 (2026-02-20): Fix released in v2.1.0
Day 31 (2026-03-01): Public disclosure (coordinated early)
Day 90 (2026-04-29): Original deadline (not needed, already disclosed)
```

## Example Tracking File

`.argus/disclosures.json`:

```json
{
  "last_updated": "2026-03-01T10:00:00",
  "disclosures": [
    {
      "disclosure_id": "ARGUS-20260129-001",
      "repo_url": "https://github.com/example/vulnerable-app",
      "repo_name": "example/vulnerable-app",
      "vulnerability_summary": "3 security vulnerabilities found",
      "severity": "critical",
      "contact_date": "2026-01-29T16:30:00",
      "deadline_date": "2026-04-29T16:30:00",
      "status": "disclosed",
      "contact_method": "security.md",
      "contact_email": "security@example.com",
      "maintainer_response": "Confirmed receipt on 2026-02-01",
      "patch_url": "https://github.com/example/vulnerable-app/releases/tag/v2.1.0",
      "public_advisory_url": "https://github.com/example/vulnerable-app/security/advisories/GHSA-xxxx-xxxx-xxxx",
      "notes": [
        "Initial disclosure created on 2026-01-29",
        "[2026-02-01] Maintainer confirmed receipt, will review this week",
        "[2026-02-20] Fix released in v2.1.0. All vulnerabilities addressed.",
        "[2026-03-01] Publicly disclosed via GitHub Security Advisory"
      ]
    }
  ]
}
```

## Best Practices Demonstrated

1. **Private First**: Used security email, not public issues
2. **Professional**: Generated professional disclosure email
3. **Tracked Timeline**: Created tracking entry with 90-day deadline
4. **Coordinated**: Worked with maintainer throughout process
5. **Flexible**: Agreed to early disclosure after patch released
6. **Credited**: Publicly thanked maintainer in advisory
7. **Documented**: Maintained detailed notes throughout

## Common Scenarios

### Scenario: No Response After 30 Days

```bash
# Send follow-up email
Subject: FOLLOW-UP: Security Vulnerability Disclosure - example/vulnerable-app

Dear Maintainers,

This is a follow-up to my security disclosure sent on 2026-01-29 (30 days ago).

I have not yet received acknowledgment. Please confirm receipt so we can
coordinate disclosure timeline.

Original deadline: 2026-04-29 (60 days remaining)
```

### Scenario: Need Extension

Maintainer requests more time:

```bash
python scripts/responsible_disclosure.py \
  --update ARGUS-20260129-001 \
  --status acknowledged \
  --notes "Maintainer requests 30-day extension due to complexity. Agreed to extend to 2026-05-29."
```

Update tracking manually or extend in code.

### Scenario: Critical Actively Exploited

If vulnerability is being exploited in the wild:

```bash
python scripts/responsible_disclosure.py \
  --repo https://github.com/example/vulnerable-app \
  --report findings.json \
  --severity critical \
  --create

# Immediate contact via multiple channels
# Consider 30-45 day timeline instead of 90 days
# May require immediate public disclosure with mitigations
```

## References

- [Full Process Documentation](../docs/RESPONSIBLE_DISCLOSURE.md)
- [Email Template](../templates/security-disclosure-email.md)
- [CERT/CC Guidelines](https://vuls.cert.org/confluence/display/CVD)
