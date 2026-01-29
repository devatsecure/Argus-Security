Subject: Security Vulnerability Disclosure - {repo_name}

Dear {repo_name} Maintainers,

I am writing to responsibly disclose security vulnerabilities discovered in your project during an automated security audit using Argus Security, an open-source AI-powered security platform.

## Summary

Our automated security analysis has identified **{vuln_count} potential security vulnerabilities** in {repo_name}, including:
- {critical_count} CRITICAL severity issues
- {high_count} HIGH severity issues

We are committed to responsible disclosure and wish to work with you to address these findings before any public disclosure.

## Vulnerability Impact

The identified vulnerabilities may pose security risks to users of {repo_name}. We have conducted initial analysis but refrained from deeper exploitation testing to minimize any potential impact on your infrastructure.

## Our Responsible Disclosure Policy

We follow industry-standard coordinated disclosure practices:

1. **Private Initial Contact**: This is our first contact with you (sent {contact_date})
2. **90-Day Disclosure Timeline**: We plan to publicly disclose on **{deadline_date}** (90 days from today)
3. **Coordination**: We are happy to extend this deadline if you need more time and are actively working on patches
4. **Credit**: We will credit your team appropriately in any public disclosure
5. **Support**: We can provide detailed technical reports and assist with remediation

## Next Steps

We would like to:

1. **Confirm Receipt**: Please acknowledge this email so we know it reached the right team
2. **Share Technical Details**: Provide you with detailed vulnerability reports in your preferred format (email, private GitHub Security Advisory, encrypted file, etc.)
3. **Coordinate Timeline**: Discuss the 90-day disclosure timeline and any extensions needed
4. **Assist Remediation**: Offer technical assistance if helpful

## Preferred Disclosure Method

Please let us know your preferred method for receiving detailed vulnerability information:
- [ ] Private GitHub Security Advisory (recommended for GitHub projects)
- [ ] PGP-encrypted email
- [ ] Private issue tracker
- [ ] Direct email with detailed report attached
- [ ] Other: _______________

## Contact Information

**Primary Contact**: {contact_email}
**Project**: Argus Security (https://github.com/devatsecure/Argus-Security)
**Disclosure Policy**: We follow CERT/CC guidelines for coordinated disclosure

## Important Notes

- We have NOT created any public GitHub issues or disclosed these vulnerabilities publicly
- We have NOT shared this information with any third parties
- We have NOT attempted to exploit these vulnerabilities beyond initial proof-of-concept validation
- All findings were discovered through automated static analysis and dynamic testing in isolated environments

## Timeline

- **Today ({contact_date})**: Initial private contact
- **Within 7 days**: We hope to hear back regarding receipt and preferred disclosure method
- **Within 14 days**: Share detailed technical reports
- **{deadline_date}**: Planned public disclosure date (90 days from initial contact)

If you need more time beyond the 90-day window and are actively working on patches, please let us know and we can coordinate an appropriate timeline.

## About Argus Security

Argus Security is an open-source enterprise-grade AI security platform that combines traditional security scanners (Semgrep, Trivy, Checkov, TruffleHog) with AI-powered analysis to reduce false positives and discover novel vulnerabilities. This disclosure is part of our commitment to improving open-source security responsibly.

We look forward to working with you to improve the security of {repo_name}.

Best regards,

Argus Security Team
{contact_email}

---

**Repository**: {repo_url}
**Disclosure ID**: ARGUS-{contact_date}
**Initial Contact Date**: {contact_date}
**Public Disclosure Deadline**: {deadline_date}
