# Responsible Disclosure Workflow

## Overview

This document defines Argus Security's responsible disclosure process for reporting security vulnerabilities to maintainers of open-source projects. We are committed to ethical security research and coordinated disclosure practices.

## Core Principles

1. **NEVER create public GitHub issues for security vulnerabilities**
2. **ALWAYS contact maintainers privately first**
3. **ALWAYS give 90 days minimum before public disclosure**
4. **ALWAYS coordinate with maintainers on disclosure timeline**
5. **ALWAYS offer to assist with remediation**

## Responsible Disclosure Process

### Step 1: Discovery and Validation

When Argus Security discovers potential vulnerabilities:

1. **Initial Analysis**: Automated scanning identifies potential issues
2. **AI Triage**: Multi-agent analysis filters false positives
3. **Validation**: Sandbox validation confirms exploitability (if safe to do so)
4. **Documentation**: Generate detailed technical report
5. **Severity Assessment**: Assign severity rating (Critical/High/Medium/Low)

**Do NOT proceed to disclosure if:**
- Finding is likely a false positive
- Finding is already publicly known (check CVE databases)
- Finding is in abandoned/archived projects (no maintainer to contact)

### Step 2: Find Security Contact

Use the `responsible_disclosure.py` tool to locate security contacts:

```bash
python scripts/responsible_disclosure.py --repo https://github.com/owner/repo --find-contact
```

**Contact Priority Order:**

1. **SECURITY.md file**: Check for `SECURITY.md` in repository root or `.github/` directory
2. **GitHub Security Advisories**: Use private security advisory feature (preferred for GitHub repos)
3. **security@domain email**: Try `security@<project-domain.com>`
4. **Maintainer Email**: Extract from git commit history (last resort)

**Red Flags:**
- No maintainer activity in 6+ months → Consider project abandoned
- Multiple unresponded security issues → Consider escalation path
- No clear contact method → Use GitHub Security Advisory

### Step 3: Prepare Disclosure

Generate disclosure email using the template:

```bash
python scripts/responsible_disclosure.py \
  --repo https://github.com/owner/repo \
  --report findings.json \
  --severity high \
  --generate-email
```

**Email Template Includes:**
- Professional greeting
- Vulnerability summary (no technical details yet)
- Impact assessment
- Responsible disclosure timeline (90 days)
- Request for preferred disclosure method
- Contact information

**Review Checklist:**
- [ ] Email is professional and respectful
- [ ] Does NOT include exploit code in initial contact
- [ ] Clearly states 90-day timeline
- [ ] Offers to help with remediation
- [ ] Provides multiple contact methods
- [ ] Mentions willingness to extend deadline if actively patching

### Step 4: Initial Contact

Send the disclosure email:

1. **Use Private Channels Only**:
   - GitHub Security Advisory (preferred)
   - Direct email to security contact
   - PGP-encrypted email if public key available
   - NEVER public GitHub issues
   - NEVER Twitter/social media
   - NEVER public mailing lists

2. **Create Tracking Entry**:
```bash
python scripts/responsible_disclosure.py \
  --repo https://github.com/owner/repo \
  --report findings.json \
  --severity high \
  --create
```

3. **Document Initial Contact**:
   - Date and time sent
   - Contact method used
   - Disclosure ID assigned
   - 90-day deadline calculated

### Step 5: Wait for Response

**Timeline Expectations:**

- **0-7 days**: Wait for initial acknowledgment
- **7-14 days**: If no response, send follow-up email
- **14-30 days**: If still no response, try alternative contact method
- **30-60 days**: Consider contacting additional maintainers or project sponsors
- **60-90 days**: Prepare public disclosure materials
- **90 days**: Public disclosure deadline (unless extended by mutual agreement)

**Update Tracking:**
```bash
# When maintainer acknowledges
python scripts/responsible_disclosure.py --update ARGUS-20260129-001 --status acknowledged --notes "Maintainer confirmed receipt"

# When patch is released
python scripts/responsible_disclosure.py --update ARGUS-20260129-001 --status patched --notes "Fix released in v2.1.0"
```

### Step 6: Share Technical Details

Once maintainer confirms receipt and preferred method:

1. **Prepare Detailed Report**:
   - Full technical description
   - Proof-of-concept code (if safe)
   - Suggested remediation steps
   - Affected versions
   - Proposed timeline

2. **Delivery Methods**:
   - **GitHub Security Advisory**: Create private advisory draft
   - **PGP Email**: Encrypt detailed report with maintainer's public key
   - **Private Repository**: Create private repo and invite maintainers
   - **Secure File Share**: Use encrypted file sharing service

3. **What to Include**:
   - Vulnerability type and CWE classification
   - Affected code locations (file:line references)
   - Step-by-step reproduction instructions
   - Impact analysis and attack scenarios
   - Suggested fix/patch (if known)
   - CVSS score if applicable

4. **What NOT to Include**:
   - Working exploit code for highly dangerous vulnerabilities
   - Information about other unpatched systems you've found
   - Details about how to weaponize the vulnerability

### Step 7: Coordinate Patching

**Active Coordination:**
- Answer maintainer questions promptly
- Review proposed patches if requested
- Test fixes in sandbox environment
- Provide additional details as needed

**Timeline Flexibility:**
- If maintainer is actively working: Extend deadline as reasonable
- If no progress after 60 days: Remind of approaching deadline
- If maintainer requests extension: Evaluate based on complexity and progress

**Update Tracking:**
```bash
python scripts/responsible_disclosure.py --update ARGUS-20260129-001 --status acknowledged --notes "Maintainer working on patch, ETA 2 weeks"
```

### Step 8: Public Disclosure

**90 Days After Initial Contact** (or coordinated date):

1. **Pre-Disclosure Checklist**:
   - [ ] 90 days have passed (or coordinated date reached)
   - [ ] Maintainer has been given ample time
   - [ ] Patch is available OR 90-day deadline requires disclosure
   - [ ] Public disclosure materials prepared

2. **Disclosure Content**:
   - **If Patched**: Credit maintainer for prompt response and fix
   - **If Unpatched**: State that maintainer was contacted, given 90 days, and vulnerability remains
   - Include CVE number if assigned
   - Provide remediation guidance for users
   - Link to patch if available

3. **Disclosure Channels**:
   - GitHub Security Advisory (make public)
   - Security mailing lists (oss-security@lists.openwall.com)
   - CVE database
   - Argus Security blog/changelog

4. **Example Disclosure Format**:
```markdown
# Security Advisory: [Vulnerability Name] in [Project]

**Severity**: High
**CVE**: CVE-2026-XXXXX
**Disclosure Date**: 2026-04-29
**Initial Contact**: 2026-01-29
**Fixed In**: v2.1.0 (or "Unfixed - users should...")

## Summary
[Brief description]

## Timeline
- 2026-01-29: Vulnerability discovered and privately reported to maintainers
- 2026-02-05: Maintainer acknowledged receipt
- 2026-03-15: Patch released in v2.1.0
- 2026-04-29: Public disclosure (90 days after initial contact)

## Credit
Thank you to [Maintainer Name] for the prompt response and fix.

## Remediation
Users should upgrade to version 2.1.0 or later immediately.
```

### Step 9: Post-Disclosure

1. **Update Tracking**:
```bash
python scripts/responsible_disclosure.py --update ARGUS-20260129-001 --status disclosed --notes "Publicly disclosed on blog and security advisory"
```

2. **Monitor Community**:
   - Watch for questions from users
   - Assist with remediation guidance
   - Correct any misinformation

3. **Lessons Learned**:
   - Document what went well
   - Note improvements for next time
   - Update disclosure templates if needed

## Escalation Procedures

### No Response After 30 Days

1. Try alternative contact methods:
   - Different email addresses
   - GitHub @ mentions in private advisory
   - Contact project sponsors/foundation

2. Send second email with subject: "SECOND NOTICE: Security Vulnerability Disclosure"

3. Document all contact attempts

### No Response After 60 Days

1. Send final notice with subject: "FINAL NOTICE: Public Disclosure in 30 Days"

2. State clearly:
   - Multiple contact attempts made
   - 90-day deadline approaching
   - Public disclosure will proceed on [date]

3. Consider contacting:
   - CERT/CC (https://www.kb.cert.org/vuls/report/)
   - Upstream dependencies or frameworks
   - Security community for alternative contacts

### Critical Vulnerabilities

For **CRITICAL** severity (active exploitation possible, severe impact):

- **Shorter timeline acceptable**: 30-45 days if actively exploited
- **Immediate contact**: Try multiple channels simultaneously
- **CERT/CC coordination**: Report to CERT/CC for assistance
- **Vendor coordination**: Loop in major downstream users if applicable

**However**, still NEVER:
- Make public GitHub issue
- Disclose on social media
- Share exploit code publicly before deadline

## Special Cases

### Abandoned Projects

If project appears abandoned (no commits in 6+ months, maintainers unresponsive):

1. Make good faith effort to contact (90-day timeline still applies)
2. Document abandonment status in disclosure
3. Consider:
   - Creating a fork with fixes
   - Contacting major users directly
   - Reporting to security databases (NVD, GitHub Advisory)

### Upstream Dependencies

If vulnerability is in upstream dependency:

1. Contact upstream maintainer first
2. Inform downstream projects after upstream is patched
3. Coordinate disclosure across ecosystem

### Already Exploited in the Wild

If vulnerability is being actively exploited:

1. Immediately contact maintainer (emergency contact)
2. Consider shorter timeline (30-45 days)
3. Contact CERT/CC for coordination
4. May require immediate public disclosure with mitigation guidance

## Tools and Commands

### Find Security Contact
```bash
python scripts/responsible_disclosure.py --repo <url> --find-contact
```

### Generate Disclosure Email
```bash
python scripts/responsible_disclosure.py --repo <url> --report <json> --generate-email
```

### Create Tracking Entry
```bash
python scripts/responsible_disclosure.py --repo <url> --report <json> --create
```

### Update Status
```bash
python scripts/responsible_disclosure.py --update <disclosure-id> --status <status> --notes "<notes>"
```

### List Active Disclosures
```bash
python scripts/responsible_disclosure.py --list
```

### Check for Overdue Disclosures
```bash
python scripts/responsible_disclosure.py --check-overdue
```

## Disclosure Status Values

- **contacted**: Initial disclosure email sent
- **acknowledged**: Maintainer confirmed receipt
- **patched**: Fix has been released
- **disclosed**: Public disclosure completed
- **overdue**: 90-day deadline passed, disclosure pending

## Communication Best Practices

### DO:
- Be professional and respectful
- Use clear, technical language
- Offer to help with remediation
- Give maintainers reasonable time
- Extend deadlines for active patching
- Credit maintainers publicly
- Follow security community norms

### DON'T:
- Use threatening language
- Demand bounties or payment
- Share vulnerabilities publicly before deadline
- Test against production systems without permission
- Disclose to media before maintainers
- Rush maintainers unnecessarily
- Ignore maintainer communication

## Legal and Ethical Considerations

1. **Good Faith Security Research**:
   - Conduct research on your own systems or with permission
   - Do not access/modify data you don't own
   - Stop testing if you find sensitive data

2. **No Exploitation**:
   - Proof-of-concept only, no data exfiltration
   - Minimal testing to confirm vulnerability
   - Sandbox/isolated environments only

3. **Respect for Maintainers**:
   - Remember most open-source is volunteer work
   - Be patient and understanding
   - Offer assistance, not criticism

4. **Coordinated Disclosure**:
   - Follow CERT/CC guidelines
   - Respect industry norms (90 days)
   - Balance security with responsible disclosure

## References and Resources

- **CERT/CC Coordinated Disclosure**: https://vuls.cert.org/confluence/display/CVD
- **ISO/IEC 29147**: Vulnerability disclosure standard
- **GitHub Security Advisories**: https://docs.github.com/en/code-security/security-advisories
- **FIRST Guidelines**: https://www.first.org/global/sigs/vulnerability-coordination
- **HackerOne Disclosure Guidelines**: https://www.hackerone.com/disclosure-guidelines

## Contact

For questions about Argus Security's responsible disclosure process:
- **Email**: security@argus-security.io
- **GitHub**: https://github.com/devatsecure/Argus-Security
- **Documentation**: https://github.com/devatsecure/Argus-Security/docs/RESPONSIBLE_DISCLOSURE.md

## Changelog

- **2026-01-29**: Initial responsible disclosure workflow created
