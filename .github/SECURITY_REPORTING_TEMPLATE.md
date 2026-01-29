# Security Finding Report Template

> Use this template when reporting security vulnerabilities discovered by Argus Security or manual research

---

## Security Finding: [DESCRIPTIVE TITLE]

**Severity**: [Critical / High / Medium / Low]
**CWE**: [CWE-XXX - Description]
**File**: `file_path:line_number`
**Finding ID**: [Auto-generated or scanner ID]

---

## Description

[Clear, concise description of the vulnerability. Explain what the issue is, where it occurs, and why it's a security concern. Minimum 50 characters required.]

[Example: "The user authentication endpoint accepts passwords without length validation, allowing single-character passwords that are trivially brute-forceable."]

---

## Impact

[Describe what an attacker could achieve by exploiting this vulnerability. Focus on business impact, not just technical details.]

**An attacker could:**
- [Specific action 1, e.g., "Access any user account with minimal effort"]
- [Specific action 2, e.g., "Exfiltrate sensitive user data (PII, credentials)"]
- [Specific action 3, e.g., "Compromise administrator accounts"]

**Affected Assets:**
- [List specific systems, data types, or resources at risk]

**CVSS Score**: [Optional: Include calculated CVSS v3.1 score and vector]

---

## Proof of Concept

[Provide step-by-step reproduction instructions or exploit code. Make it easy for maintainers to verify the issue.]

### Steps to Reproduce

1. [Step 1]
2. [Step 2]
3. [Step 3]
4. [Expected vs actual result]

### Example Code

```[language]
# Paste exploit code or vulnerable code snippet here
# Include comments explaining what's happening

[Example request/response or function call]
```

### Environment

- **OS**: [e.g., Ubuntu 22.04, macOS 14]
- **Language/Runtime**: [e.g., Python 3.11, Node.js 20.x]
- **Framework Version**: [e.g., Django 4.2, Express 4.18]
- **Dependencies**: [Relevant package versions if applicable]

---

## Vulnerable Code

[Include the specific code segment that contains the vulnerability. Provide file path and line numbers.]

**File**: `path/to/vulnerable/file.py`
**Lines**: 142-148

```python
# Example vulnerable code
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and user.password == password:  # ❌ Plain text comparison
        return generate_token(user)
    return None
```

---

## Recommendation

[Provide specific, actionable guidance on how to fix the vulnerability. Include code examples if possible.]

### Immediate Fix

[Quick patch that addresses the immediate security risk]

```[language]
# Example fix code
def authenticate_user(username, password):
    user = User.query.filter_by(username=username).first()
    if user and bcrypt.checkpw(password.encode(), user.password_hash):  # ✅ Secure
        return generate_token(user)
    return None
```

### Long-Term Solution

[More comprehensive fix that addresses root cause and prevents similar issues]

- [Recommendation 1]
- [Recommendation 2]
- [Recommendation 3]

### Validation

[How to verify the fix works]

```bash
# Test command or validation steps
pytest tests/security/test_authentication.py
```

---

## References

[Include links to relevant documentation, security advisories, or research]

- **CWE Reference**: [https://cwe.mitre.org/data/definitions/XXX.html]
- **OWASP**: [Relevant OWASP article]
- **Documentation**: [Official docs for secure implementation]
- **Similar CVEs**: [Any related CVE IDs]

---

## Argus Metadata

[Optional: Include Argus-specific validation data if using Argus Security]

```json
{
  "finding_id": "[scanner-type]-[identifier]",
  "scanner": "[TruffleHog / Semgrep / Trivy / etc.]",
  "detection_date": "YYYY-MM-DD",
  "confidence_score": 0.XX,
  "false_positive_score": 0.XX,
  "multi_agent_consensus": "[CONFIRMED / NEEDS_REVIEW / LIKELY_FP]",
  "sandbox_validation": "[EXPLOITABLE / NOT_EXPLOITABLE / NOT_VALIDATED]",
  "ai_enrichment": {
    "risk_score": 0.XX,
    "exploitability": "[HIGH / MEDIUM / LOW]",
    "recommendation": "[AI-generated fix suggestion]"
  }
}
```

---

## Disclosure Information

[For maintainers: Track disclosure timeline]

- **Private Disclosure Date**: [YYYY-MM-DD]
- **Acknowledgment Date**: [YYYY-MM-DD or "Pending"]
- **Target Fix Date**: [YYYY-MM-DD or "TBD"]
- **Public Disclosure Date**: [YYYY-MM-DD or "After 90 days"]

---

## Checklist

[Ensure report completeness before submission]

- [ ] Severity rating assigned (Critical/High/Medium/Low)
- [ ] CWE ID identified
- [ ] File path and line number provided
- [ ] Description is clear and ≥50 characters
- [ ] Impact statement describes attacker capabilities
- [ ] Proof of concept includes reproduction steps
- [ ] Vulnerable code snippet included
- [ ] Fix recommendation provided with code example
- [ ] References to documentation/standards included
- [ ] Private disclosure attempted before public reporting
- [ ] No sensitive data (credentials, PII) exposed in report

---

## Contact Information

[Optional: Your contact details for follow-up questions]

- **Name**: [Your name or handle]
- **Email**: [your.email@example.com]
- **PGP Key**: [Fingerprint or keyserver link]
- **GitHub**: [@yourusername]
- **Preferred Contact Method**: [Email / GitHub / Other]

---

## Legal and Ethics Statement

[Include responsible disclosure statement]

This vulnerability was discovered during authorized security research in accordance with:

- [ ] Applicable safe harbor policies
- [ ] Responsible disclosure guidelines (ISO 29147)
- [ ] Bug bounty program terms (if applicable)
- [ ] Open source license terms

I have:

- [ ] Not exploited this vulnerability beyond proof-of-concept validation
- [ ] Not accessed, modified, or exfiltrated any user data
- [ ] Not shared this vulnerability with unauthorized parties
- [ ] Followed the project's security disclosure policy

---

## Additional Notes

[Any other context or information that might be helpful]

---

**Template Version**: 1.0.0
**Last Updated**: 2026-01-29
**Source**: Argus Security - https://github.com/devatsecure/Argus-Security

---

## Example Usage

For complete examples of good security reports, see:
- [docs/SECURITY_REPORTING_GUIDE.md](../docs/SECURITY_REPORTING_GUIDE.md#good-vs-bad-report-examples)
- [docs/LESSONS_LEARNED_PI_MONO.md](../docs/LESSONS_LEARNED_PI_MONO.md)
