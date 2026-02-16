# 🔒 Hybrid Security Analysis Report
**Generated**: 2026-02-16T10:36:00.423415
**Target**: /tmp/chrome-devtools-mcp
**Duration**: 73.4s
**Cost**: $0.00
**Tools**: Semgrep, Trivy, Checkov, API-Security, Supply-Chain, Threat-Intel, Remediation, Regression-Testing, Nuclei-Templates, ZAP-Baseline, Sandbox-Validator

---

## 📊 Summary

**Total Findings**: 1

### By Severity

- 🔴 **Critical**: 0
- 🟠 **High**: 0
- 🟡 **Medium**: 1
- 🟢 **Low**: 0

### By Tool

- **nuclei-template**: 1 findings

---

## Medium Issues (1)

### 1. Missing Security Headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options

**Source**: nuclei-template

**File**: `/tmp/chrome-devtools-mcp/tests/server.ts` (line 56)

**CWE**: CWE-693

**Description**: This file defines HTTP response handling but does not set the following security headers: Content-Security-Policy, Strict-Transport-Security, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection, Referrer-Policy, Permissions-Policy.  Missing headers can expose the application to clickjacking, MIME-sniffing, and XSS attacks.

**References**:
- Testing: ['Manual security testing required', 'Consult OWASP guidelines']

---

