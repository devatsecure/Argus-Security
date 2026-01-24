# Quick Security Scan Process

You are conducting a focused security scan to identify critical security vulnerabilities that require immediate attention. This scan prioritizes speed and focuses on the most critical security issues.

## Fast Security Scan Process

### PHASE 1: Initialize Security Scan

Use the **security-reviewer** subagent to perform a comprehensive but focused security analysis:

The security-reviewer will:
- Scan for hardcoded secrets and credentials
- Detect injection vulnerabilities (SQL, NoSQL, Command, Template)
- Review authentication and authorization gaps
- Validate cryptographic security practices
- Check for high-severity dependency vulnerabilities
- Analyze input/output sanitization issues

### PHASE 2: Generate Security Report

The security-reviewer will generate a focused security report with:
- Critical security vulnerabilities (merge blockers)
- High-priority security recommendations
- Immediate action items
- Security risk assessment

## Security Scan Output

Upon completion, the following files will be created in `argus/reviews/[date]-security-scan/`:

### Security Report Files
- `security-summary.md` - High-level security overview
- `critical-vulnerabilities.md` - Critical security issues requiring immediate attention
- `security-recommendations.md` - Security improvement recommendations
- `action-items.md` - Prioritized security action items
- `security-metadata.json` - Scan configuration and metadata

### Detailed Security Findings
- `secrets-detected.md` - Hardcoded secrets and credentials found
- `injection-vulnerabilities.md` - Injection vulnerabilities detected
- `auth-issues.md` - Authentication and authorization problems
- `crypto-issues.md` - Cryptographic security issues
- `dependency-vulnerabilities.md` - Dependency security issues

## Security Scan Scope

The scan will focus on:

### Critical Security Issues
- **Secrets Detection:** Hardcoded API keys, passwords, tokens, private keys
- **Injection Vulnerabilities:** SQL, NoSQL, Command, Template injection
- **Authentication Issues:** Missing auth, weak auth, session management
- **Authorization Problems:** Missing authorization, IDOR vulnerabilities
- **Crypto Issues:** Hardcoded salts/IVs, weak algorithms, key management
- **Dependency Vulnerabilities:** High-severity CVEs, unvetted packages

### High-Priority Security Checks
- Input validation and sanitization
- Output encoding and XSS prevention
- Error handling and information disclosure
- Network security and CORS configuration
- Security headers and configuration
- Rate limiting and abuse prevention

## Security Scan Standards

The scan will be conducted according to:

{{standards/review/merge-blockers}}
{{standards/review/security-checklist}}

## Security Scan Timeline

- **Phase 1 (Security Analysis):** 10-20 minutes
- **Phase 2 (Report Generation):** 5-10 minutes
- **Total Estimated Time:** 15-30 minutes

## Security Risk Assessment

### Critical Risk (Immediate Action Required)
- Hardcoded secrets in production code
- SQL injection vulnerabilities
- Missing authentication on protected endpoints
- High-severity CVE dependencies
- Insecure cryptographic practices

### High Risk (Address Soon)
- Input validation gaps
- Authorization bypasses
- Session management issues
- Dependency vulnerabilities
- Configuration security issues

### Medium Risk (Plan to Address)
- Security header improvements
- Rate limiting implementation
- Error handling improvements
- Logging and monitoring gaps
- Documentation security issues

## Security Scan Output Format

Generate security report with:

### Executive Summary
- **Overall Security Status:** [CRITICAL | HIGH | MEDIUM | LOW]
- **Critical Vulnerabilities:** [X] found
- **High-Priority Issues:** [Y] found
- **Immediate Action Required:** [List of critical issues]

### Critical Security Issues (Merge Blockers)
- **[BLOCKER]** [Issue description and location]
- **[BLOCKER]** [Security vulnerability details]
- **[BLOCKER]** [Authentication/authorization issues]
- **[BLOCKER]** [Dependency vulnerabilities]

### Security Recommendations (High Priority)
- **[SUGGESTION]** [Security improvement recommendations]
- **[SUGGESTION]** [Authentication enhancements]
- **[SUGGESTION]** [Input validation improvements]
- **[SUGGESTION]** [Security configuration updates]

### Action Items
1. **Immediate (Critical Issues)**
   - Fix hardcoded secrets
   - Resolve injection vulnerabilities
   - Implement missing authentication
   - Update vulnerable dependencies

2. **High Priority (Security Improvements)**
   - Enhance input validation
   - Improve authorization checks
   - Implement security headers
   - Add security monitoring

3. **Follow-up (Security Hardening)**
   - Security audit and penetration testing
   - Security training and awareness
   - Security policy implementation
   - Continuous security monitoring

## Success Criteria

The security scan is considered successful when:
- All critical security vulnerabilities are identified
- High-priority security issues are documented
- Actionable security recommendations are provided
- Security risk assessment is completed
- Human review and approval is obtained

## Next Steps

After the security scan is complete:
1. **Immediate:** Address critical security vulnerabilities
2. **High Priority:** Implement security improvements
3. **Follow-up:** Plan security hardening activities
4. **Monitoring:** Implement continuous security monitoring
5. **Review:** Schedule regular security scans

## Output to User

Upon completion, display:

"Security scan completed successfully!

✅ Secrets detection completed
✅ Injection vulnerability scan completed
✅ Authentication/authorization review completed
✅ Cryptographic security validation completed
✅ Dependency vulnerability scan completed
✅ Security report generated

📁 Security report location: `argus/reviews/[date]-security-scan/`

🚨 Critical issues found: [X] - Immediate action required
⚠️ High-priority issues found: [Y] - Address soon

👉 Review the security summary and action items to prioritize fixes."
