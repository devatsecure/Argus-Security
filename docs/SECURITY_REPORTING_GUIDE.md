# Security Reporting Guide

> Best practices for responsible security disclosure and high-quality vulnerability reporting

## Table of Contents

1. [Overview](#overview)
2. [Quality Standards](#quality-standards)
3. [Step-by-Step Reporting Process](#step-by-step-reporting-process)
4. [Responsible Disclosure Timeline](#responsible-disclosure-timeline)
5. [Contact Discovery Methods](#contact-discovery-methods)
6. [Good vs Bad Report Examples](#good-vs-bad-report-examples)
7. [Integration with Argus Workflow](#integration-with-argus-workflow)
8. [Legal and Ethical Considerations](#legal-and-ethical-considerations)

---

## Overview

Security research benefits everyone when done responsibly. This guide ensures your findings are:
- **Actionable** - Maintainers can quickly understand and fix issues
- **Accurate** - Findings include proper context and validation
- **Responsible** - Private disclosure gives projects time to respond
- **Professional** - Clear communication builds trust

---

## Quality Standards

### Required Fields for All Findings

Every security report MUST include:

| Field | Requirement | Example |
|-------|-------------|---------|
| **Title** | Specific vulnerability name | "SQL Injection in user search endpoint" |
| **Severity** | CVSS-based rating | Critical/High/Medium/Low |
| **File Path** | Absolute or relative path | `src/api/users.py` |
| **Line Number** | Exact location | Line 142 |
| **Description** | Clear explanation (≥50 chars) | "User input passed directly to SQL query without sanitization" |
| **Impact** | What attacker can achieve | "Full database read/write access" |
| **Recommendation** | How to fix | "Use parameterized queries or ORM methods" |

### Optional but Recommended

- **CWE ID** - Common Weakness Enumeration reference
- **CVE ID** - If publicly disclosed vulnerability exists
- **CVSS Score** - Numeric severity rating
- **Proof of Concept** - Exploit code or reproduction steps
- **References** - Links to documentation or similar issues

---

## Step-by-Step Reporting Process

### 1. Validate Your Finding

Before reporting, ensure it's a real vulnerability:

```bash
# Use Argus to validate findings
python scripts/run_ai_audit.py --project-type backend-api

# Review Phase 4 sandbox validation results
cat results/latest_audit/sandbox_results.json
```

**Checklist:**
- [ ] Finding is reproducible
- [ ] Impact is clearly understood
- [ ] Not a known/documented issue
- [ ] Affects current version
- [ ] File path and line number verified

### 2. Gather Context

Collect all necessary information:

```bash
# Get file hash for verification
sha256sum path/to/vulnerable/file.py

# Check version information
git log --oneline -1 path/to/file.py

# Identify dependencies if relevant
pip list | grep package-name
```

### 3. Find Security Contact

**Priority order:**

1. **SECURITY.md** file in repository root
2. **GitHub Security Advisories** (Private reporting enabled?)
3. **README.md** security section
4. **package.json** or **pyproject.toml** author email
5. **git log** for maintainer emails
6. **GitHub Issues** (last resort - use private mode if available)

```bash
# Check for security contact
cat SECURITY.md

# Find maintainer email
git log --format='%ae' | sort -u | head -5

# Check package metadata
cat package.json | jq '.author'
```

### 4. Draft Your Report

Use the standardized template (see `.github/SECURITY_REPORTING_TEMPLATE.md`):

**Key principles:**
- Be concise but complete
- Assume reader is busy but technical
- Provide reproduction steps
- Suggest concrete fixes
- Be respectful and professional

### 5. Submit Privately

**DO:**
- Use encrypted email (PGP) if available
- Submit via GitHub Security Advisory (preferred)
- Use HackerOne/Bugcrowd if program exists
- Follow project's documented process

**DON'T:**
- Post in public GitHub issues
- Tweet or blog about it immediately
- Share exploit code publicly
- Pressure maintainers aggressively

### 6. Follow Up

**Timeline:**
- **Day 0:** Submit report
- **Day 3:** Expect acknowledgment
- **Day 7:** Follow up if no response
- **Day 30:** Reassess if radio silence
- **Day 90:** Consider public disclosure (with redaction)

---

## Responsible Disclosure Timeline

### Standard Timeline

```
Day 0   : Private disclosure to maintainers
Day 1-7 : Maintainer acknowledgment expected
Day 7-30: Patch development and testing
Day 30-60: Release and deployment
Day 90  : Public disclosure (coordinated)
```

### Exceptions

**Accelerated disclosure** (7-14 days):
- Actively exploited in the wild
- Public exploit code already exists
- Critical infrastructure at risk

**Extended timeline** (120+ days):
- Complex fix requires architecture changes
- Multiple vendors affected (coordinated disclosure)
- Maintainer requests additional time with valid justification

---

## Contact Discovery Methods

### 1. Repository Security Files

```bash
# Check standard locations
cat SECURITY.md
cat .github/SECURITY.md
cat docs/SECURITY.md
```

**Example SECURITY.md:**
```markdown
## Reporting Security Issues

Email: security@example.com
PGP Key: https://example.com/pgp-key.asc
Response Time: 48 hours
```

### 2. GitHub Security Advisories

Look for "Report a vulnerability" button on Security tab:
```
https://github.com/owner/repo/security/advisories/new
```

### 3. Package Metadata

```bash
# Python
cat pyproject.toml | grep -A 5 '\[project\]'
pip show package-name

# Node.js
cat package.json | jq '.author, .maintainers'

# Ruby
cat gemspec | grep email

# Go
cat go.mod | head -3
```

### 4. Commit History

```bash
# Find active maintainers
git shortlog -sne --since="1 year ago" | head -10

# Recent committers to vulnerable file
git log --format='%an <%ae>' --follow path/to/file.py | head -5
```

### 5. Community Channels

- **Slack/Discord** - Many projects have private security channels
- **Mailing Lists** - Check archives for security@ addresses
- **Documentation** - Security sections often list contacts

---

## Good vs Bad Report Examples

### Example 1: SQL Injection

#### BAD REPORT

```
Subject: Security Issue

I found a SQL injection bug in your code.

File: users.py
```

**Problems:**
- No line number
- No description of vulnerability
- No impact statement
- No reproduction steps
- No severity rating

#### GOOD REPORT

```
Subject: [SECURITY] SQL Injection in User Search (High Severity)

## Security Finding: SQL Injection in User Search Endpoint

**Severity**: High
**CWE**: CWE-89 (SQL Injection)
**File**: `src/api/users.py:142`
**Affected Versions**: 2.0.0 - 2.3.4

### Description

The user search endpoint directly concatenates user input into a SQL query
without sanitization or parameterization, allowing arbitrary SQL execution.

### Impact

An attacker can:
- Read entire database contents (user credentials, PII)
- Modify or delete database records
- Execute system commands (if db user has elevated privileges)

### Proof of Concept

```bash
curl -X POST https://example.com/api/users/search \
  -d "query=' OR '1'='1' UNION SELECT * FROM admin_passwords--"
```

### Vulnerable Code

```python
# src/api/users.py:142
def search_users(query):
    sql = f"SELECT * FROM users WHERE name LIKE '%{query}%'"
    return db.execute(sql)  # VULNERABLE
```

### Recommendation

Use parameterized queries:

```python
def search_users(query):
    sql = "SELECT * FROM users WHERE name LIKE ?"
    return db.execute(sql, (f'%{query}%',))
```

### References
- OWASP SQL Injection: https://owasp.org/www-community/attacks/SQL_Injection
- CWE-89: https://cwe.mitre.org/data/definitions/89.html
```

**Why it's good:**
- Specific, actionable title
- All required fields present
- Clear impact statement
- Working proof of concept
- Concrete fix recommendation
- Professional tone

---

### Example 2: Secret Exposure

#### BAD REPORT

```
Your API key is public in config.py
```

**Problems:**
- No line number
- No severity
- No impact analysis
- No guidance on rotation

#### GOOD REPORT

```
Subject: [SECURITY] Hardcoded AWS Credentials (Critical Severity)

## Security Finding: Hardcoded AWS IAM Credentials

**Severity**: Critical
**CWE**: CWE-798 (Use of Hard-coded Credentials)
**File**: `config/settings.py:23-24`
**Commit**: a3f9d82 (committed 14 days ago)

### Description

AWS IAM access key and secret key are hardcoded in the configuration file
and committed to the public GitHub repository.

### Impact

These credentials provide:
- Full S3 bucket access (confirmed via IAM policy check)
- EC2 instance management
- Potential $XX,XXX/month in AWS charges if abused
- Access to customer data stored in S3

**IMMEDIATE ACTION REQUIRED**: Rotate these credentials.

### Evidence

```python
# config/settings.py:23-24
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
```

**Public exposure:**
- Commit: a3f9d82 (2024-01-15)
- Repository: Public since creation
- GitHub search indexed: Yes

### Immediate Remediation Steps

1. **Rotate credentials immediately** via AWS IAM console
2. **Revoke compromised keys**
3. **Check CloudTrail logs** for unauthorized usage
4. **Remove from git history**:
   ```bash
   git filter-branch --force --index-filter \
     "git rm --cached --ignore-unmatch config/settings.py" \
     --prune-empty --tag-name-filter cat -- --all
   ```

### Long-term Fix

Use environment variables:

```python
# config/settings.py
import os
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
```

Add to `.gitignore`:
```
.env
.env.local
config/secrets.py
```

### Validation

Scan with Argus to prevent future exposure:
```bash
python scripts/run_ai_audit.py --project-type backend-api
```

### References
- AWS Key Rotation: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html
```

**Why it's excellent:**
- Critical severity clearly stated
- Immediate action items highlighted
- Complete remediation guide
- Prevention measures included
- References AWS-specific documentation

---

## Integration with Argus Workflow

### 1. Pre-Report Validation

Run Argus to validate findings before reporting:

```bash
# Full 6-phase audit
python scripts/run_ai_audit.py --project-type backend-api

# Review results
cat results/latest_audit/enriched_findings.json
```

### 2. Export Findings for Reporting

```bash
# Generate SARIF format (for GitHub)
python scripts/run_ai_audit.py --output-format sarif

# Generate markdown summary
python scripts/run_ai_audit.py --output-format markdown

# Filter critical/high severity only
jq '.findings[] | select(.severity == "CRITICAL" or .severity == "HIGH")' \
  results/latest_audit/enriched_findings.json
```

### 3. Attach Argus Validation Results

Include Argus metadata in reports:

```json
{
  "finding_id": "trufflehog-aws-key-001",
  "scanner": "TruffleHog",
  "ai_confidence": 0.95,
  "false_positive_score": 0.05,
  "sandbox_validation": "NOT_VALIDATED",
  "multi_agent_consensus": "CONFIRMED_VULNERABILITY"
}
```

### 4. Track Disclosure Status

Use Argus feedback system:

```bash
# Record external disclosure
./scripts/argus feedback record finding-001 \
  --status disclosed \
  --disclosure-date 2024-01-29 \
  --vendor-response "acknowledged"

# Track remediation
./scripts/argus feedback record finding-001 \
  --status remediated \
  --fix-commit abc123
```

---

## Legal and Ethical Considerations

### Safe Harbor

Check if organization has safe harbor policy:

```markdown
## Safe Harbor

[Organization] commits to not pursue legal action against security
researchers who:

1. Report vulnerabilities privately
2. Avoid data exfiltration or destruction
3. Do not exploit findings maliciously
4. Follow responsible disclosure timeline
```

### Scope Limitations

**In Scope:**
- Public repositories (if license allows security research)
- Bug bounty programs
- Explicitly authorized testing

**Out of Scope:**
- Private repositories (unless authorized)
- Production systems (without permission)
- Social engineering / phishing
- Physical security testing
- Denial of service attacks

### Testing Guidelines

**DO:**
- Test locally cloned repositories
- Use sandbox environments
- Minimize system impact
- Document all testing steps

**DON'T:**
- Test production systems without permission
- Exfiltrate real user data
- Modify or delete data
- Share access with others

### Vulnerability Disclosure Laws

Be aware of regional regulations:

- **USA**: CFAA (Computer Fraud and Abuse Act)
- **EU**: GDPR implications for data handling
- **UK**: Computer Misuse Act
- **International**: Budapest Convention on Cybercrime

**Recommendation:** Consult legal counsel if uncertain about legality.

---

## Additional Resources

### Tools

- **Argus Security**: https://github.com/devatsecure/Argus-Security
- **GitHub Security Advisories**: https://docs.github.com/en/code-security/security-advisories
- **HackerOne**: https://www.hackerone.com
- **Bugcrowd**: https://www.bugcrowd.com

### Standards

- **CVSS Calculator**: https://www.first.org/cvss/calculator/3.1
- **CWE Database**: https://cwe.mitre.org
- **OWASP Top 10**: https://owasp.org/www-project-top-ten

### Guidelines

- **ISO 29147**: Vulnerability disclosure
- **ISO 30111**: Vulnerability handling processes
- **NIST CVD Guide**: https://vuls.cert.org/confluence/display/CVD

---

## Questions?

For questions about Argus Security reporting workflows:
- GitHub Issues: https://github.com/devatsecure/Argus-Security/issues
- Documentation: https://github.com/devatsecure/Argus-Security/docs

---

**Last Updated:** 2026-01-29
**Version:** 1.0.0
